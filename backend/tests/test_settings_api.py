"""Tests for the general/authentication/scanner settings and About endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.core import system_info
from app.core.config import get_settings
from app.core.crypto import MasterKeyError, reset_secret_cipher
from tests.test_auth import CSRF, USER_PW, setup_admin


def _make_viewer(client: TestClient, csrf: str, name: str = "viewer1") -> TestClient:
    """Create a viewer account and return a client logged in as them."""
    client.post(
        "/api/users",
        json={"username": name, "password": USER_PW, "role": "viewer"},
        headers={CSRF: csrf},
    )
    viewer = TestClient(client.app)
    viewer.post("/api/auth/login", json={"username": name, "password": USER_PW})
    return viewer


class TestGeneralSettings:
    def test_defaults_and_update(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        assert client.get("/api/settings/general").json()["instance_name"] == "Scrye"
        resp = client.put(
            "/api/settings/general",
            json={"instance_name": "Prod Scrye", "admin_note": "east cluster"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200
        assert client.get("/api/settings/general").json()["instance_name"] == "Prod Scrye"

    def test_viewer_can_read_but_not_write(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        viewer = _make_viewer(client, csrf)
        assert viewer.get("/api/settings/general").status_code == 200
        resp = viewer.get("/api/auth/me")
        vcsrf = viewer.cookies.get("scrye_csrf")
        assert resp.status_code == 200
        assert (
            viewer.put(
                "/api/settings/general",
                json={"instance_name": "hax"},
                headers={CSRF: vcsrf},
            ).status_code
            == 403
        )


class TestAuthenticationSettings:
    def test_cannot_disable_local_login_without_oidc(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.put(
            "/api/settings/authentication",
            json={"local_login_enabled": False, "mfa_policy": "optional"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 400

    def test_mfa_policy_persists(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.put(
            "/api/settings/authentication",
            json={"local_login_enabled": True, "mfa_policy": "required_admin"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200
        assert client.get("/api/settings/authentication").json()["mfa_policy"] == "required_admin"


class TestScannerSettings:
    def test_update_defaults(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.put(
            "/api/settings/scanners",
            json={
                "default_severities": ["HIGH", "CRITICAL"],
                "default_ignore_unfixed": True,
                "trivyignore": "CVE-2021-1234",
                "grype_ignore": "",
                "auto_update_db": False,
                "db_update_interval_hours": 12,
            },
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200
        body = client.get("/api/settings/scanners").json()
        assert body["default_severities"] == ["HIGH", "CRITICAL"]
        assert body["default_ignore_unfixed"] is True
        assert body["db_update_interval_hours"] == 12


class TestAbout:
    def test_about_reports_version_and_counts(self, client: TestClient) -> None:
        setup_admin(client)
        body = client.get("/api/settings/about").json()
        assert body["version"]
        assert body["user_count"] == 1
        assert body["oidc_enabled"] is False
        assert isinstance(body["scanners"], list) and len(body["scanners"]) == 3
        # Scanner probe never leaks anything secret and always returns a name.
        assert {s["name"] for s in body["scanners"]} == {"trivy", "grype", "syft"}

    def test_about_reports_the_master_key_source_to_admins(self, client: TestClient) -> None:
        # The durable channel for "which key is in force, and back it up" (chosen
        # over a per-boot log line). The test suite supplies a key file via
        # SCRYE_APP_SECRET_KEY_FILE, so the configured-secret source is what shows.
        setup_admin(client)
        master_key = client.get("/api/settings/about").json()["master_key"]
        assert master_key is not None
        assert master_key["source"] == "secret_file"
        assert master_key["path"].endswith("app_secret_key")

    def test_about_master_key_row_never_carries_key_material(self, client: TestClient) -> None:
        setup_admin(client)
        key_file = Path(get_settings().app_secret_key_file)
        secret = key_file.read_text(encoding="utf-8").strip()
        body = client.get("/api/settings/about").text
        assert secret not in body, "the About payload leaked master key material"
        # Nothing beyond the source and path — no key version, no other new field.
        assert set(client.get("/api/settings/about").json()["master_key"]) == {"source", "path"}

    def test_about_reports_auto_generated_source(
        self, client: TestClient, tmp_path: Path, monkeypatch
    ) -> None:
        # A deployment that let Scrye generate its key must see that, not the
        # secret-file wording. Point both settings at a clean tmp dir and clear the
        # cached resolution so the row reflects a first-launch generation.
        setup_admin(client)
        autogen = tmp_path / "data" / "app_secret_key"
        settings = get_settings()
        monkeypatch.setattr(settings, "app_secret_key_file", tmp_path / "absent", raising=False)
        monkeypatch.setattr(settings, "app_secret_key_autogen_file", autogen, raising=False)
        # monkeypatch restores attributes but not this set, so put it back by hand:
        # the cached Settings instance is process-wide.
        was_explicit = "app_secret_key_file" in settings.model_fields_set
        settings.model_fields_set.discard("app_secret_key_file")
        reset_secret_cipher()
        try:
            master_key = client.get("/api/settings/about").json()["master_key"]
            assert master_key == {"source": "auto_generated", "path": str(autogen)}
        finally:
            if was_explicit:
                settings.model_fields_set.add("app_secret_key_file")
            reset_secret_cipher()

    def test_about_omits_the_master_key_row_for_non_admins(self, client: TestClient) -> None:
        # The About endpoint is readable by any role; the key's path is deployment
        # layout an operator/viewer has no need for.
        csrf = setup_admin(client)
        viewer = _make_viewer(client, csrf)
        body = viewer.get("/api/settings/about").json()
        assert body["master_key"] is None
        assert body["version"], "the rest of the About payload is still served"

    def test_about_omits_the_master_key_row_for_a_role_capped_admin_token(
        self, client: TestClient
    ) -> None:
        # An admin's viewer-scoped API token must not see more than a viewer does.
        csrf = setup_admin(client)
        token = client.post(
            "/api/api-tokens",
            json={"name": "viewer-token", "role": "viewer"},
            headers={CSRF: csrf},
        ).json()["token"]
        bare = TestClient(client.app)
        body = bare.get("/api/settings/about", headers={"Authorization": f"Bearer {token}"}).json()
        assert body["master_key"] is None

    def test_about_omits_the_master_key_row_when_no_key_resolves(
        self, client: TestClient, monkeypatch
    ) -> None:
        # A dev instance can run without a key (the lifespan warns instead of
        # failing); the row is omitted rather than erroring the whole response.
        setup_admin(client)

        def _unresolvable() -> None:
            raise MasterKeyError("no key for this test")

        monkeypatch.setattr(system_info, "get_master_key_resolution", _unresolvable)
        resp = client.get("/api/settings/about")
        assert resp.status_code == 200
        assert resp.json()["master_key"] is None
