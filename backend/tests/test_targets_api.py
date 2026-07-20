"""API tests for registries, git credentials, and Docker environments.

Focus: write-only secret masking (plaintext never returned), RBAC (admin
manages, operator reads), CSRF, and the test/enumerate actions.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.masking import SECRET_MASK

ADMIN_PW = "unit-test-admin-passphrase"
OPERATOR_PW = "unit-test-operator-passphrase"
CSRF = "x-csrf-token"
REGISTRY_SECRET = "sup3r-s3cret-registry-token"


def _setup_admin(client: TestClient) -> str:
    resp = client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    assert resp.status_code == 201, resp.text
    return resp.json()["csrf_token"]


def _make_operator(client: TestClient, admin_csrf: str) -> str:
    created = client.post(
        "/api/users",
        headers={CSRF: admin_csrf},
        json={"username": "operator", "password": OPERATOR_PW, "role": "operator"},
    )
    assert created.status_code == 201, created.text
    login = client.post("/api/auth/login", json={"username": "operator", "password": OPERATOR_PW})
    return login.json()["csrf_token"]


# --- Registries --------------------------------------------------------------


def test_registry_create_masks_secret_and_never_returns_plaintext(client: TestClient) -> None:
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/registries",
        headers={CSRF: csrf},
        json={
            "name": "ghcr",
            "registry_host": "ghcr.io",
            "auth_type": "username_password",
            "username": "alice",
            "secret": REGISTRY_SECRET,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["secret"]["is_set"] is True
    assert body["secret"]["value"] == SECRET_MASK
    # The plaintext (and any ciphertext token) must never appear in the response.
    assert REGISTRY_SECRET not in resp.text
    assert "scrye$" not in resp.text

    listed = client.get("/api/registries")
    assert listed.status_code == 200
    assert REGISTRY_SECRET not in listed.text
    assert listed.json()[0]["secret"]["value"] == SECRET_MASK


def test_registry_requires_secret_for_static_auth(client: TestClient) -> None:
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/registries",
        headers={CSRF: csrf},
        json={"name": "x", "registry_host": "ghcr.io", "auth_type": "token"},
    )
    assert resp.status_code == 422


def test_registry_credential_helper_takes_no_secret(client: TestClient) -> None:
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/registries",
        headers={CSRF: csrf},
        json={
            "name": "ecr",
            "registry_host": "123.dkr.ecr.us-east-1.amazonaws.com",
            "auth_type": "aws_ecr",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["secret"]["is_set"] is False


def test_registry_rbac_and_csrf(client: TestClient) -> None:
    admin_csrf = _setup_admin(client)
    # Seed a registry as admin so the operator has something to select.
    client.post(
        "/api/registries",
        headers={CSRF: admin_csrf},
        json={
            "name": "ghcr",
            "registry_host": "ghcr.io",
            "auth_type": "username_password",
            "username": "alice",
            "secret": REGISTRY_SECRET,
        },
    )
    op_csrf = _make_operator(client, admin_csrf)

    # Operators may NOT read the full metadata list (host/username are credential
    # material) and may not create.
    assert client.get("/api/registries").status_code == 403
    denied = client.post(
        "/api/registries",
        headers={CSRF: op_csrf},
        json={"name": "n", "registry_host": "h", "auth_type": "token", "secret": "s"},
    )
    assert denied.status_code == 403

    # Operators CAN read the minimal id/name selection list — and it exposes
    # nothing beyond id + name (no host, username, auth type, or secret).
    options = client.get("/api/registries/options")
    assert options.status_code == 200
    assert options.json() == [{"id": 1, "name": "ghcr"}]
    assert "ghcr.io" not in options.text
    assert "alice" not in options.text

    # Missing CSRF is rejected for admins too.
    no_csrf = client.post(
        "/api/registries",
        json={"name": "n", "registry_host": "h", "auth_type": "token", "secret": "s"},
    )
    assert no_csrf.status_code == 403


def test_registry_update_replaces_secret(client: TestClient) -> None:
    csrf = _setup_admin(client)
    created = client.post(
        "/api/registries",
        headers={CSRF: csrf},
        json={
            "name": "ghcr",
            "registry_host": "ghcr.io",
            "auth_type": "token",
            "secret": "first",
        },
    ).json()
    first_updated = created["secret"]["updated_at"]

    patched = client.patch(
        f"/api/registries/{created['id']}",
        headers={CSRF: csrf},
        json={"secret": "second"},
    )
    assert patched.status_code == 200
    assert "second" not in patched.text
    assert patched.json()["secret"]["updated_at"] != first_updated


def test_registry_update_cannot_blank_username_password_username(client: TestClient) -> None:
    """Create requires a username for username_password; update can't blank it (APIR-6)."""
    csrf = _setup_admin(client)
    created = client.post(
        "/api/registries",
        headers={CSRF: csrf},
        json={
            "name": "priv",
            "registry_host": "registry.test",
            "auth_type": "username_password",
            "username": "robot",
            "secret": "pw",
        },
    ).json()
    resp = client.patch(
        f"/api/registries/{created['id']}",
        headers={CSRF: csrf},
        json={"username": "   "},
    )
    assert resp.status_code == 422
    assert "username" in resp.json()["detail"].lower()


def test_registry_update_strips_name(client: TestClient) -> None:
    """Update strips name like create, so ' ghcr ' can't shadow 'ghcr' (APIR-6)."""
    csrf = _setup_admin(client)
    created = client.post(
        "/api/registries",
        headers={CSRF: csrf},
        json={"name": "ghcr", "registry_host": "ghcr.io", "auth_type": "token", "secret": "t"},
    ).json()
    patched = client.patch(
        f"/api/registries/{created['id']}",
        headers={CSRF: csrf},
        json={"name": "  ghcr-prod  "},
    )
    assert patched.status_code == 200
    assert patched.json()["name"] == "ghcr-prod"
    # A whitespace-only name is rejected, not stored blank.
    blank = client.patch(
        f"/api/registries/{created['id']}",
        headers={CSRF: csrf},
        json={"name": "   "},
    )
    assert blank.status_code == 422


def test_registry_test_endpoint(client: TestClient, monkeypatch) -> None:
    from app.api import registries
    from app.core.registry_check import RegistryCheck

    async def _fake_check(**kwargs):
        assert kwargs["secret"] == REGISTRY_SECRET  # decrypted at test time
        return RegistryCheck(ok=True, detail="ok")

    monkeypatch.setattr(registries, "check_registry", _fake_check)
    csrf = _setup_admin(client)
    created = client.post(
        "/api/registries",
        headers={CSRF: csrf},
        json={
            "name": "ghcr",
            "registry_host": "ghcr.io",
            "auth_type": "token",
            "secret": REGISTRY_SECRET,
        },
    ).json()
    resp = client.post(f"/api/registries/{created['id']}/test", headers={CSRF: csrf})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "detail": "ok"}


def test_registry_delete(client: TestClient) -> None:
    csrf = _setup_admin(client)
    created = client.post(
        "/api/registries",
        headers={CSRF: csrf},
        json={"name": "ghcr", "registry_host": "ghcr.io", "auth_type": "token", "secret": "s"},
    ).json()
    deleted = client.delete(f"/api/registries/{created['id']}", headers={CSRF: csrf})
    assert deleted.status_code == 204
    assert client.get("/api/registries").json() == []


# --- Git credentials ---------------------------------------------------------


def test_git_credential_masks_token(client: TestClient) -> None:
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/git-credentials",
        headers={CSRF: csrf},
        json={"name": "gh", "provider": "github", "token": "ghp_secret_value"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["token"]["value"] == SECRET_MASK
    assert "ghp_secret_value" not in resp.text
    assert "ghp_secret_value" not in client.get("/api/git-credentials").text


def test_git_credential_rbac(client: TestClient) -> None:
    admin_csrf = _setup_admin(client)
    client.post(
        "/api/git-credentials",
        headers={CSRF: admin_csrf},
        json={"name": "gh", "provider": "github", "username": "deploy", "token": "t0ken"},
    )
    op_csrf = _make_operator(client, admin_csrf)

    # Operators may NOT read the full metadata list, nor create.
    assert client.get("/api/git-credentials").status_code == 403
    denied = client.post(
        "/api/git-credentials",
        headers={CSRF: op_csrf},
        json={"name": "gh2", "provider": "github", "token": "t"},
    )
    assert denied.status_code == 403

    # Operators CAN read the minimal id/name selection list, and nothing more:
    # provider, username, and token are all absent.
    options = client.get("/api/git-credentials/options")
    assert options.status_code == 200
    assert options.json() == [{"id": 1, "name": "gh"}]
    assert "github" not in options.text
    assert "deploy" not in options.text


# --- Docker environments -----------------------------------------------------


def test_docker_environment_crud_and_enumeration(client: TestClient, monkeypatch) -> None:
    from app.api import docker_environments
    from app.core.docker_proxy import DockerImage

    async def _fake_list(proxy_url: str):
        assert proxy_url == "http://proxy:2375"
        return [DockerImage(id="sha256:x", tags=["alpine:3.19"], size_bytes=1)]

    monkeypatch.setattr(docker_environments, "list_images", _fake_list)
    csrf = _setup_admin(client)

    created = client.post(
        "/api/docker-environments",
        headers={CSRF: csrf},
        json={"name": "local", "proxy_url": "http://proxy:2375", "risk_acknowledged": False},
    )
    assert created.status_code == 201, created.text
    env_id = created.json()["id"]

    # Enumeration is refused until the residual risk is acknowledged.
    blocked = client.get(f"/api/docker-environments/{env_id}/images")
    assert blocked.status_code == 409

    client.patch(
        f"/api/docker-environments/{env_id}",
        headers={CSRF: csrf},
        json={"risk_acknowledged": True},
    )
    images = client.get(f"/api/docker-environments/{env_id}/images")
    assert images.status_code == 200
    assert images.json()[0]["tags"] == ["alpine:3.19"]


def test_docker_environment_enumeration_surfaces_proxy_error(
    client: TestClient, monkeypatch
) -> None:
    from app.api import docker_environments
    from app.core.docker_proxy import DockerProxyError

    async def _boom(proxy_url: str):
        raise DockerProxyError("unreachable")

    monkeypatch.setattr(docker_environments, "list_images", _boom)
    csrf = _setup_admin(client)
    created = client.post(
        "/api/docker-environments",
        headers={CSRF: csrf},
        json={"name": "local", "proxy_url": "http://proxy:2375", "risk_acknowledged": True},
    ).json()
    resp = client.get(f"/api/docker-environments/{created['id']}/images")
    assert resp.status_code == 502
