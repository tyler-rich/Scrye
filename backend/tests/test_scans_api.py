"""End-to-end tests for the scan API: launch, RBAC, CSRF, results, artifacts.

The scanner subprocess is replaced with a fake, so a POST flows through the real
worker and produces persisted findings + a stored artifact without any binaries.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from app.db.models import Severity
from app.scanners import NormalizedFinding, ScanExecution, ScannerError
from app.scanners.base import tally_severities
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
    async def scan_image(self, target: str, options: dict) -> ScanExecution:
        return _fake_execution()


class _FailingScanner:
    async def scan_image(self, target: str, options: dict) -> ScanExecution:
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


def test_unsupported_target_type_rejected(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner())
    csrf = _setup_admin(client)
    resp = client.post(
        "/api/scans",
        headers={CSRF: csrf},
        json={"scanner": "trivy", "target": "https://x/y.git", "target_type": "repository"},
    )
    assert resp.status_code == 422


def test_cancel_queued_scan(client: TestClient, monkeypatch) -> None:
    # A scanner that blocks so the scan we cancel stays queued behind it.
    import asyncio

    class _SlowScanner:
        async def scan_image(self, target: str, options: dict) -> ScanExecution:
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
