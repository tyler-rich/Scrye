"""Tests for Trivy VEX/ignore-rule management and materialization."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.app_settings import ScannerSettings, SettingsService
from app.core.timeutil import utcnow
from app.db.models import TrivyIgnoreRule, VexDocument, VexFormat
from app.scanners.trivy_policy import load_trivy_policy, materialize_trivy_policy
from tests.test_auth import CSRF, setup_admin
from tests.test_rbac_users_audit import login_as, make_user

VEX_BODY = json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "statements": []})


class TestVexApi:
    def test_create_and_list(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post(
            "/api/trivy/vex-documents",
            json={"name": "prod-vex", "format": "openvex", "content": VEX_BODY},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 201, resp.text
        assert client.get("/api/trivy/vex-documents").json()[0]["name"] == "prod-vex"

    def test_invalid_json_rejected(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post(
            "/api/trivy/vex-documents",
            json={"name": "bad", "format": "openvex", "content": "not json{"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 422

    def test_viewer_cannot_manage(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        make_user(client, csrf, "vera", "viewer")
        browser, vcsrf = login_as(client, "vera")
        # Viewer can read but not write.
        assert browser.get("/api/trivy/vex-documents").status_code == 200
        resp = browser.post(
            "/api/trivy/vex-documents",
            json={"name": "x", "format": "openvex", "content": VEX_BODY},
            headers={CSRF: vcsrf},
        )
        assert resp.status_code == 403


class TestIgnoreRuleApi:
    def test_crud(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        rid = client.post(
            "/api/trivy/ignore-rules",
            json={"vuln_id": "CVE-2026-1234", "reason": "false positive"},
            headers={CSRF: csrf},
        ).json()["id"]
        assert client.get("/api/trivy/ignore-rules").json()[0]["vuln_id"] == "CVE-2026-1234"
        assert (
            client.put(
                f"/api/trivy/ignore-rules/{rid}",
                json={"vuln_id": "CVE-2026-9999", "enabled": False},
                headers={CSRF: csrf},
            ).json()["vuln_id"]
            == "CVE-2026-9999"
        )
        assert (
            client.delete(f"/api/trivy/ignore-rules/{rid}", headers={CSRF: csrf}).status_code == 204
        )

    def test_aware_expires_at_normalized_to_utc(self, client: TestClient) -> None:
        """An offset-aware ``expires_at`` is stored on the correct UTC instant (APIR-1).

        ``2026-08-01T00:00:00+09:00`` is ``2026-07-31T15:00:00`` in UTC; without
        normalization the ``+09:00`` offset was silently dropped, suppressing the
        CVE for 9 extra hours.
        """
        csrf = setup_admin(client)
        rid = client.post(
            "/api/trivy/ignore-rules",
            json={"vuln_id": "CVE-2026-5555", "expires_at": "2026-08-01T00:00:00+09:00"},
            headers={CSRF: csrf},
        ).json()["id"]

        stored = client.get("/api/trivy/ignore-rules").json()[0]["expires_at"]
        assert stored.startswith("2026-07-31T15:00:00"), stored

        # A naive timestamp is assumed to already be UTC and passes through.
        client.put(
            f"/api/trivy/ignore-rules/{rid}",
            json={"vuln_id": "CVE-2026-5555", "expires_at": "2026-08-01T00:00:00"},
            headers={CSRF: csrf},
        )
        stored = client.get("/api/trivy/ignore-rules").json()[0]["expires_at"]
        assert stored.startswith("2026-08-01T00:00:00"), stored


class TestPolicyLoad:
    def test_load_combines_global_and_active_rules(self, db: Session) -> None:
        SettingsService(db).set_scanners(
            ScannerSettings(trivyignore="CVE-2020-0001"), username="admin"
        )
        db.add_all(
            [
                TrivyIgnoreRule(vuln_id="CVE-2026-1", reason="triaged", enabled=True),
                TrivyIgnoreRule(vuln_id="CVE-2026-2", enabled=False),  # disabled → excluded
                TrivyIgnoreRule(
                    vuln_id="CVE-2026-3",
                    enabled=True,
                    expires_at=utcnow() - timedelta(days=1),  # expired → excluded
                ),
                VexDocument(name="v", format=VexFormat.OPENVEX, content=VEX_BODY, enabled=True),
            ]
        )
        db.commit()

        policy = load_trivy_policy(db)
        assert "CVE-2020-0001" in policy.ignorefile_text
        assert "CVE-2026-1" in policy.ignorefile_text
        assert "triaged" in policy.ignorefile_text
        assert "CVE-2026-2" not in policy.ignorefile_text
        assert "CVE-2026-3" not in policy.ignorefile_text
        assert len(policy.vex_documents) == 1

    def test_materialize_sets_env_and_cleans_up(self, db: Session) -> None:
        db.add_all(
            [
                TrivyIgnoreRule(vuln_id="CVE-2026-1", enabled=True),
                VexDocument(name="v", format=VexFormat.OPENVEX, content=VEX_BODY, enabled=True),
            ]
        )
        db.commit()
        policy = load_trivy_policy(db)

        with materialize_trivy_policy(policy) as env:
            ignore_path = Path(env["TRIVY_IGNOREFILE"])
            vex_path = Path(env["TRIVY_VEX"])
            assert ignore_path.is_file()
            assert "CVE-2026-1" in ignore_path.read_text()
            assert vex_path.is_file()
            tmpdir = ignore_path.parent
        # Directory removed on exit.
        assert not tmpdir.exists()

    def test_empty_policy_yields_empty_overlay(self, db: Session) -> None:
        policy = load_trivy_policy(db)
        assert policy.is_empty
        with materialize_trivy_policy(policy) as env:
            assert env == {}
