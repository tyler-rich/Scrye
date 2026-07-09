"""End-to-end tests for the scan API: launch, RBAC, CSRF, results, artifacts.

The scanner subprocess is replaced with a fake, so a POST flows through the real
worker and produces persisted findings + a stored artifact without any binaries.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core import config
from app.db.models import Severity
from app.scanners import NormalizedFinding, ScanExecution, ScannerError
from app.scanners.base import tally_severities
from app.scanners.syft import SbomResult
from app.workers import inprocess

ADMIN_PW = "unit-test-admin-passphrase"
VIEWER_PW = "unit-test-viewer-passphrase"
CSRF = "x-csrf-token"


def _setup_admin(client: TestClient) -> str:
    resp = client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    assert resp.status_code == 201, resp.text
    return resp.json()["csrf_token"]


def _fake_execution() -> ScanExecution:
    findings = [
        NormalizedFinding(
            finding_class="vulnerability",
            severity=Severity.HIGH,
            vuln_id="CVE-2024-9999",
            pkg_name="libfoo",
            installed_version="1.0",
            fixed_version="1.1",
            title="libfoo flaw",
        )
    ]
    return ScanExecution(
        raw_output=json.dumps({"Results": []}).encode(),
        findings=findings,
        severity_counts=tally_severities(findings),
        command=["trivy", "image", "alpine"],
    )


class _FakeScanner:
    async def scan_image(
        self, target: str, options: dict, *, env: dict | None = None
    ) -> ScanExecution:
        return _fake_execution()


class _FailingScanner:
    async def scan_image(
        self, target: str, options: dict, *, env: dict | None = None
    ) -> ScanExecution:
        raise ScannerError("Trivy exited with code 1: boom")


def _wait_for_status(client: TestClient, scan_id: int, terminal: set[str]) -> dict:
    """Poll a scan until it reaches a terminal status (worker runs async)."""
    for _ in range(100):
        body = client.get(f"/api/scans/{scan_id}").json()
        if body["status"] in terminal:
            return body
        time.sleep(0.02)
    raise AssertionError(f"Scan {scan_id} did not settle; last status {body['status']}.")


def test_create_scan_runs_and_persists(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    csrf = _setup_admin(client)

    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={"scanner": "trivy", "target": "alpine:3.19"},
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    assert scan["status"] == "queued"
    assert scan["created_by_username"] == "admin"
    scan_id = scan["id"]

    settled = _wait_for_status(client, scan_id, {"succeeded", "failed"})
    assert settled["status"] == "succeeded"
    assert settled["findings_count"] == 1
    assert settled["highest_severity"] == "high"
    assert settled["severity_counts"]["high"] == 1

    findings = client.get(f"/api/scans/{scan_id}/findings").json()
    assert findings["total"] == 1
    assert findings["items"][0]["vuln_id"] == "CVE-2024-9999"

    artifacts = client.get(f"/api/scans/{scan_id}/artifacts").json()
    assert len(artifacts) == 1
    assert artifacts[0]["filename"] == "trivy.json"

    download = client.get(f"/api/scans/{scan_id}/artifacts/{artifacts[0]['id']}/download")
    assert download.status_code == 200
    assert json.loads(download.content) == {"Results": []}


def test_failed_scan_records_error(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FailingScanner())
    csrf = _setup_admin(client)

    resp = client.post(
        "/api/scans", headers={CSRF: csrf}, json={"scanner": "trivy", "target": "bad:image"}
    )
    scan_id = resp.json()["id"]
    settled = _wait_for_status(client, scan_id, {"succeeded", "failed"})
    assert settled["status"] == "failed"
    assert "boom" in settled["error"]


def test_findings_filter_by_severity(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans", headers={CSRF: csrf}, json={"scanner": "grype", "target": "alpine"}
    )
    scan_id = resp.json()["id"]
    _wait_for_status(client, scan_id, {"succeeded", "failed"})

    high = client.get(f"/api/scans/{scan_id}/findings", params={"severity": "high"}).json()
    assert high["total"] == 1
    low = client.get(f"/api/scans/{scan_id}/findings", params={"severity": "low"}).json()
    assert low["total"] == 0


def test_create_requires_csrf(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    _setup_admin(client)
    resp = client.post("/api/scans", json={"scanner": "trivy", "target": "alpine"})
    assert resp.status_code == 403


def test_create_requires_authentication(client: TestClient) -> None:
    resp = client.post("/api/scans", json={"scanner": "trivy", "target": "alpine"})
    assert resp.status_code == 401


def test_viewer_cannot_launch_but_can_read(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    admin_csrf = _setup_admin(client)
    # Admin creates a viewer account.
    created = client.post(
        "/api/users",
        headers={CSRF: admin_csrf},
        json={"username": "viewer", "password": VIEWER_PW, "role": "viewer"},
    )
    assert created.status_code == 201, created.text

    # Switch to the viewer session.
    login = client.post("/api/auth/login", json={"username": "viewer", "password": VIEWER_PW})
    viewer_csrf = login.json()["csrf_token"]

    denied = client.post(
        "/api/scans", headers={CSRF: viewer_csrf}, json={"scanner": "trivy", "target": "alpine"}
    )
    assert denied.status_code == 403
    # But viewers can list scans.
    assert client.get("/api/scans").status_code == 200


def test_sbom_target_via_json_is_rejected(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    csrf = _setup_admin(client)
    # SBOM scans require the upload endpoint, not the JSON create body.
    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={"scanner": "grype", "target": "sbom.json", "target_type": "sbom"},
    )
    assert resp.status_code == 422


def test_unsupported_scanner_target_combo_rejected(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    csrf = _setup_admin(client)
    # Grype has no repository target; Trivy owns repo scans (docs/PLAN.md §4).
    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={"scanner": "grype", "target": "https://x/y.git", "target_type": "repository"},
    )
    assert resp.status_code == 422


def test_cancel_queued_scan(client: TestClient, monkeypatch) -> None:
    # A scanner that blocks so the scan we cancel stays queued behind it.
    import asyncio

    class _SlowScanner:
        async def scan_image(
            self, target: str, options: dict, *, env: dict | None = None
        ) -> ScanExecution:
            await asyncio.sleep(0.2)
            return _fake_execution()

    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _SlowScanner())
    # Force single-slot concurrency so the second scan waits as 'queued'.
    client.app.state.scan_worker._semaphore = asyncio.Semaphore(1)
    csrf = _setup_admin(client)

    first = client.post(
        "/api/scans", headers={CSRF: csrf}, json={"scanner": "trivy", "target": "a"}
    ).json()
    second = client.post(
        "/api/scans", headers={CSRF: csrf}, json={"scanner": "trivy", "target": "b"}
    ).json()

    cancel = client.post(f"/api/scans/{second['id']}/cancel", headers={CSRF: csrf})
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "canceled"
    # The first scan still completes.
    _wait_for_status(client, first["id"], {"succeeded", "failed"})


def test_scan_not_found(client: TestClient) -> None:
    _setup_admin(client)
    assert client.get("/api/scans/9999").status_code == 404


@pytest.mark.parametrize("scanner", ["trivy", "grype"])
def test_list_filters_by_scanner(client: TestClient, monkeypatch, scanner: str) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda s: _FakeScanner())
    csrf = _setup_admin(client)
    client.post("/api/scans", headers={CSRF: csrf}, json={"scanner": scanner, "target": "x"})
    listed = client.get("/api/scans", params={"scanner": scanner}).json()
    assert len(listed) == 1
    assert listed[0]["scanner"] == scanner


# --- Phase 3: repository, filesystem, SBOM, registry credentials -------------


class _MultiTargetScanner:
    """Records the target/env each scan method receives (image/repo/fs/sbom)."""

    def __init__(self) -> None:
        self.calls: dict[str, dict] = {}

    async def scan_image(self, target, options, *, env=None):
        call: dict = {"target": target, "env": env}
        if env and "DOCKER_CONFIG" in env:
            config_file = Path(env["DOCKER_CONFIG"]) / "config.json"
            call["docker_config"] = json.loads(config_file.read_text())
        self.calls["image"] = call
        return _fake_execution()

    async def scan_repo(self, target, options, *, env=None):
        self.calls["repo"] = {"target": target, "env": env or {}}
        return _fake_execution()

    async def scan_filesystem(self, target, options, *, env=None):
        self.calls["filesystem"] = {"target": target}
        return _fake_execution()

    async def scan_sbom(self, target, options, *, env=None):
        self.calls["sbom"] = {"target": target, "exists": Path(target).is_file()}
        return _fake_execution()


def _install_multitarget(client: TestClient, monkeypatch) -> _MultiTargetScanner:
    scanner = _MultiTargetScanner()
    monkeypatch.setattr(inprocess, "get_scanner", lambda s: scanner)
    return scanner


def test_repository_scan_runs(client: TestClient, monkeypatch) -> None:
    scanner = _install_multitarget(client, monkeypatch)
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={
            "scanner": "trivy",
            "target": "https://github.com/org/repo.git",
            "target_type": "repository",
            "branch": "main",
        },
    )
    assert resp.status_code == 201, resp.text
    settled = _wait_for_status(client, resp.json()["id"], {"succeeded", "failed"})
    assert settled["status"] == "succeeded"
    assert scanner.calls["repo"]["target"] == "https://github.com/org/repo.git"


def test_repository_scan_with_git_credential_injects_token(client: TestClient, monkeypatch) -> None:
    scanner = _install_multitarget(client, monkeypatch)
    csrf = _setup_admin(client)
    cred = client.post(
        "/api/git-credentials",
        headers={CSRF: csrf},
        json={"name": "gh", "provider": "github", "token": "ghp_worker_token"},
    )
    assert cred.status_code == 201, cred.text
    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={
            "scanner": "trivy",
            "target": "https://github.com/org/repo.git",
            "target_type": "repository",
            "git_credential_id": cred.json()["id"],
        },
    )
    _wait_for_status(client, resp.json()["id"], {"succeeded", "failed"})
    # GitHub tokens are supplied via env, never embedded in the clone URL.
    assert scanner.calls["repo"]["env"]["GITHUB_TOKEN"] == "ghp_worker_token"
    assert "ghp_worker_token" not in scanner.calls["repo"]["target"]


def test_image_scan_with_registry_materializes_docker_config(
    client: TestClient, monkeypatch
) -> None:
    scanner = _install_multitarget(client, monkeypatch)
    csrf = _setup_admin(client)
    reg = client.post(
        "/api/registries",
        headers={CSRF: csrf},
        json={
            "name": "ghcr",
            "registry_host": "ghcr.io",
            "auth_type": "username_password",
            "username": "alice",
            "secret": "regpass",
        },
    )
    assert reg.status_code == 201, reg.text
    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={"scanner": "trivy", "target": "ghcr.io/org/app:1", "registry_id": reg.json()["id"]},
    )
    _wait_for_status(client, resp.json()["id"], {"succeeded", "failed"})
    # The scanner saw a transient DOCKER_CONFIG with the expected auth blob.
    blob = scanner.calls["image"]["docker_config"]["auths"]["ghcr.io"]["auth"]
    assert base64.b64decode(blob).decode() == "alice:regpass"
    # The materialized directory was shredded after the scan finished.
    assert not Path(scanner.calls["image"]["env"]["DOCKER_CONFIG"]).exists()


def test_filesystem_scan_requires_configured_root(client: TestClient, monkeypatch) -> None:
    _install_multitarget(client, monkeypatch)
    csrf = _setup_admin(client)
    # No SCRYE_FILESYSTEM_SCAN_ROOTS configured (default): rejected at create.
    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={"scanner": "grype", "target": "/etc", "target_type": "filesystem"},
    )
    assert resp.status_code == 422


def test_filesystem_scan_runs_within_allowed_root(
    client: TestClient, monkeypatch, tmp_path
) -> None:
    from app.scanners import targets

    root = tmp_path / "scanroot"
    project = root / "project"
    project.mkdir(parents=True)
    monkeypatch.setattr(
        targets, "get_settings", lambda: config.Settings(filesystem_scan_roots=[str(root)])
    )
    scanner = _install_multitarget(client, monkeypatch)
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={"scanner": "grype", "target": str(project), "target_type": "filesystem"},
    )
    assert resp.status_code == 201, resp.text
    _wait_for_status(client, resp.json()["id"], {"succeeded", "failed"})
    assert scanner.calls["filesystem"]["target"] == str(project.resolve())


def test_sbom_upload_scan(client: TestClient, monkeypatch) -> None:
    scanner = _install_multitarget(client, monkeypatch)
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans/sbom",
        headers={CSRF: csrf},
        data={"scanner": "grype"},
        files={
            "file": ("app.cdx.json", json.dumps({"artifacts": []}).encode(), "application/json")
        },  # noqa: E501
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    assert scan["target_type"] == "sbom"
    assert scan["target"] == "app.cdx.json"
    _wait_for_status(client, scan["id"], {"succeeded", "failed"})
    assert scanner.calls["sbom"]["exists"] is True

    # The uploaded SBOM is stored as an input artifact alongside the raw output.
    artifacts = client.get(f"/api/scans/{scan['id']}/artifacts").json()
    kinds = {a["kind"] for a in artifacts}
    assert "sbom" in kinds and "raw_grype_json" in kinds


def test_sbom_upload_rejects_non_json(client: TestClient, monkeypatch) -> None:
    _install_multitarget(client, monkeypatch)
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans/sbom",
        headers={CSRF: csrf},
        data={"scanner": "grype"},
        files={"file": ("bad.json", b"not json", "application/json")},
    )
    assert resp.status_code == 422


def test_generate_sbom_stores_sbom_artifact(client: TestClient, monkeypatch) -> None:
    _install_multitarget(client, monkeypatch)

    async def _fake_sbom(source, fmt=None, *, env=None):
        return SbomResult(
            raw_output=b'{"bomFormat":"CycloneDX"}',
            sbom_format="cyclonedx-json",
            filename="sbom.cyclonedx.json",
        )

    monkeypatch.setattr(inprocess.syft, "generate_sbom", _fake_sbom)
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={"scanner": "trivy", "target": "alpine:3.19", "generate_sbom": True},
    )
    _wait_for_status(client, resp.json()["id"], {"succeeded", "failed"})
    artifacts = client.get(f"/api/scans/{resp.json()['id']}/artifacts").json()
    sbom_artifacts = [a for a in artifacts if a["kind"] == "sbom"]
    assert len(sbom_artifacts) == 1
    assert sbom_artifacts[0]["filename"] == "sbom.cyclonedx.json"


# --- Deletion: full cleanup + RBAC ------------------------------------------


def _count_findings(scan_id: int) -> int:
    """Count normalized findings still stored for a scan (direct DB read)."""
    from sqlalchemy import func, select

    from app.db.models import Finding
    from app.db.session import SessionLocal

    with SessionLocal() as session:
        return session.scalar(
            select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
        )


def _dashboard_open_high() -> int:
    """Compute the live dashboard open-high posture (bypassing the TTL cache)."""
    from app.core.dashboard import compute_dashboard
    from app.db.session import SessionLocal

    with SessionLocal() as session:
        return compute_dashboard(session).open_high


def _dashboard_total() -> int:
    """Compute the live dashboard total-scans aggregate (bypassing the cache)."""
    from app.core.dashboard import compute_dashboard
    from app.db.session import SessionLocal

    with SessionLocal() as session:
        return compute_dashboard(session).total_scans


def test_delete_scan_purges_findings_artifacts_and_aggregates(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans", headers={CSRF: csrf}, json={"scanner": "trivy", "target": "alpine:3.19"}
    )
    scan_id = resp.json()["id"]
    _wait_for_status(client, scan_id, {"succeeded", "failed"})

    # Precondition: the scan has findings, a stored artifact on disk, and counts
    # toward the dashboard aggregates.
    assert _count_findings(scan_id) == 1
    artifacts = client.get(f"/api/scans/{scan_id}/artifacts").json()
    assert len(artifacts) == 1
    artifact_dir = config.get_settings().artifacts_dir / str(scan_id)
    assert artifact_dir.is_dir()
    assert _dashboard_total() == 1
    assert _dashboard_open_high() == 1  # the fake scan reports one HIGH finding

    deleted = client.delete(f"/api/scans/{scan_id}", headers={CSRF: csrf})
    assert deleted.status_code == 204, deleted.text

    # The scan is gone from the API, its findings are gone from the DB, the raw
    # artifact directory is removed, and it no longer feeds the aggregates.
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    assert _count_findings(scan_id) == 0
    assert not artifact_dir.exists()
    assert _dashboard_total() == 0
    assert _dashboard_open_high() == 0
    # It also drops out of history.
    history = client.get("/api/scans/history").json()
    assert history["total"] == 0


def test_delete_requires_operator(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    admin_csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans", headers={CSRF: admin_csrf}, json={"scanner": "trivy", "target": "alpine"}
    )
    scan_id = resp.json()["id"]
    _wait_for_status(client, scan_id, {"succeeded", "failed"})

    created = client.post(
        "/api/users",
        headers={CSRF: admin_csrf},
        json={"username": "viewer", "password": VIEWER_PW, "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    login = client.post("/api/auth/login", json={"username": "viewer", "password": VIEWER_PW})
    viewer_csrf = login.json()["csrf_token"]

    denied = client.delete(f"/api/scans/{scan_id}", headers={CSRF: viewer_csrf})
    assert denied.status_code == 403
    # The scan survives the forbidden attempt.
    assert client.get(f"/api/scans/{scan_id}").status_code == 200


def test_delete_requires_csrf(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans", headers={CSRF: csrf}, json={"scanner": "trivy", "target": "alpine"}
    )
    scan_id = resp.json()["id"]
    _wait_for_status(client, scan_id, {"succeeded", "failed"})

    denied = client.delete(f"/api/scans/{scan_id}")  # no CSRF header
    assert denied.status_code == 403
    assert client.get(f"/api/scans/{scan_id}").status_code == 200


def test_delete_missing_scan_is_404(client: TestClient) -> None:
    csrf = _setup_admin(client)
    assert client.delete("/api/scans/9999", headers={CSRF: csrf}).status_code == 404


def test_delete_queued_scan_rejected(client: TestClient, monkeypatch) -> None:
    # A blocking scanner keeps a second scan queued so we can try to delete it.
    import asyncio

    class _SlowScanner:
        async def scan_image(
            self, target: str, options: dict, *, env: dict | None = None
        ) -> ScanExecution:
            await asyncio.sleep(0.2)
            return _fake_execution()

    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _SlowScanner())
    client.app.state.scan_worker._semaphore = asyncio.Semaphore(1)
    csrf = _setup_admin(client)

    first = client.post(
        "/api/scans", headers={CSRF: csrf}, json={"scanner": "trivy", "target": "a"}
    ).json()
    second = client.post(
        "/api/scans", headers={CSRF: csrf}, json={"scanner": "trivy", "target": "b"}
    ).json()

    # The queued scan cannot be deleted while it is still pending.
    rejected = client.delete(f"/api/scans/{second['id']}", headers={CSRF: csrf})
    assert rejected.status_code == 409
    # Once everything settles it can be deleted like any completed scan.
    _wait_for_status(client, first["id"], {"succeeded", "failed"})
    _wait_for_status(client, second["id"], {"succeeded", "failed"})
    assert client.delete(f"/api/scans/{second['id']}", headers={CSRF: csrf}).status_code == 204
