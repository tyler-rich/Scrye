"""End-to-end tests for the Phase 4 history, reports, exports, and presets APIs.

Scans are inserted directly (bypassing the worker) so filter/sort/pagination
behavior can be exercised against precise, controlled data.
"""

from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient

from app.db.models import (
    Finding,
    FindingClass,
    Scan,
    Scanner,
    ScanStatus,
    ScanTag,
    Severity,
    TargetType,
)
from app.db.session import SessionLocal

ADMIN_PW = "unit-test-admin-passphrase"
VIEWER_PW = "unit-test-viewer-passphrase"
CSRF = "x-csrf-token"


def _setup_admin(client: TestClient) -> str:
    resp = client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    assert resp.status_code == 201, resp.text
    return resp.json()["csrf_token"]


def _make_viewer(client: TestClient, admin_csrf: str) -> str:
    created = client.post(
        "/api/users",
        headers={CSRF: admin_csrf},
        json={"username": "viewer", "password": VIEWER_PW, "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    login = client.post("/api/auth/login", json={"username": "viewer", "password": VIEWER_PW})
    return login.json()["csrf_token"]


def _insert_scan(
    *,
    scanner: Scanner = Scanner.TRIVY,
    target_type: TargetType = TargetType.IMAGE,
    target: str = "alpine:3.19",
    status: ScanStatus = ScanStatus.SUCCEEDED,
    highest_severity: Severity | None = Severity.HIGH,
    findings_count: int = 0,
    severity_counts: dict | None = None,
    created_by_username: str = "admin",
    created_at: datetime | None = None,
    tags: list[str] | None = None,
    findings: list[dict] | None = None,
) -> int:
    """Insert one scan (plus optional findings/tags) directly and return its id."""
    session = SessionLocal()
    try:
        scan = Scan(
            scanner=scanner,
            target_type=target_type,
            target=target,
            status=status,
            options={},
            severity_counts=severity_counts or {},
            highest_severity=highest_severity,
            findings_count=findings_count,
            created_by_username=created_by_username,
        )
        if created_at is not None:
            scan.created_at = created_at
        session.add(scan)
        session.flush()
        for tag in tags or []:
            session.add(ScanTag(scan_id=scan.id, tag=tag))
        for f in findings or []:
            session.add(Finding(scan_id=scan.id, **f))
        session.commit()
        return scan.id
    finally:
        session.close()


# --- History listing & filters ----------------------------------------------


def test_history_returns_paginated_envelope(client: TestClient) -> None:
    _setup_admin(client)
    for i in range(3):
        _insert_scan(target=f"img:{i}", created_at=datetime(2026, 1, 1, 0, i))
    resp = client.get("/api/scans/history")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 3
    assert len(body["items"]) == 3
    # Default sort is newest-created first.
    assert body["items"][0]["target"] == "img:2"


def test_history_filters_by_scanner_and_status(client: TestClient) -> None:
    _setup_admin(client)
    _insert_scan(scanner=Scanner.TRIVY, status=ScanStatus.SUCCEEDED)
    _insert_scan(scanner=Scanner.GRYPE, status=ScanStatus.FAILED, highest_severity=None)
    grype = client.get("/api/scans/history", params={"scanner": "grype"}).json()
    assert grype["total"] == 1 and grype["items"][0]["scanner"] == "grype"
    failed = client.get("/api/scans/history", params={"status": "failed"}).json()
    assert failed["total"] == 1 and failed["items"][0]["status"] == "failed"


def test_history_full_text_target_search(client: TestClient) -> None:
    _setup_admin(client)
    _insert_scan(target="ghcr.io/org/api:1.2")
    _insert_scan(target="docker.io/library/nginx:1.27")
    hit = client.get("/api/scans/history", params={"q": "nginx"}).json()
    assert hit["total"] == 1 and "nginx" in hit["items"][0]["target"]


def test_history_filters_by_initiator(client: TestClient) -> None:
    _setup_admin(client)
    _insert_scan(created_by_username="alice")
    _insert_scan(created_by_username="bob")
    alice = client.get("/api/scans/history", params={"initiator": "alice"}).json()
    assert alice["total"] == 1 and alice["items"][0]["created_by_username"] == "alice"


def test_history_highest_severity_exact_vs_threshold(client: TestClient) -> None:
    _setup_admin(client)
    _insert_scan(target="crit", highest_severity=Severity.CRITICAL)
    _insert_scan(target="high", highest_severity=Severity.HIGH)
    _insert_scan(target="low", highest_severity=Severity.LOW)
    # Exact highest-severity match.
    exact = client.get("/api/scans/history", params={"highest_severity": "high"}).json()
    assert {s["target"] for s in exact["items"]} == {"high"}
    # Threshold presence: at or above HIGH → critical + high.
    threshold = client.get("/api/scans/history", params={"min_severity": "high"}).json()
    assert {s["target"] for s in threshold["items"]} == {"crit", "high"}


def test_history_date_range_filter(client: TestClient) -> None:
    _setup_admin(client)
    _insert_scan(target="old", created_at=datetime(2026, 1, 1))
    _insert_scan(target="new", created_at=datetime(2026, 6, 1))
    resp = client.get(
        "/api/scans/history",
        params={"created_from": "2026-03-01T00:00:00", "created_to": "2026-12-01T00:00:00"},
    ).json()
    assert {s["target"] for s in resp["items"]} == {"new"}


def test_history_tag_filter_is_conjunctive(client: TestClient) -> None:
    _setup_admin(client)
    _insert_scan(target="both", tags=["prod", "team-a"])
    _insert_scan(target="one", tags=["prod"])
    both = client.get("/api/scans/history", params=[("tags", "prod"), ("tags", "team-a")]).json()
    assert {s["target"] for s in both["items"]} == {"both"}
    prod = client.get("/api/scans/history", params={"tags": "prod"}).json()
    assert {s["target"] for s in prod["items"]} == {"both", "one"}


def test_history_sorting_and_pagination(client: TestClient) -> None:
    _setup_admin(client)
    _insert_scan(target="a", findings_count=5)
    _insert_scan(target="b", findings_count=50)
    _insert_scan(target="c", findings_count=1)
    asc = client.get("/api/scans/history", params={"sort": "findings_count", "order": "asc"}).json()
    assert [s["findings_count"] for s in asc["items"]] == [1, 5, 50]
    # Pagination reports the full total but returns only the page.
    page = client.get(
        "/api/scans/history",
        params={"sort": "findings_count", "order": "desc", "limit": 1, "offset": 0},
    ).json()
    assert page["total"] == 3
    assert len(page["items"]) == 1 and page["items"][0]["findings_count"] == 50


def test_history_rejects_unknown_sort(client: TestClient) -> None:
    _setup_admin(client)
    assert client.get("/api/scans/history", params={"sort": "bogus"}).status_code == 422


def test_filter_options_lists_distinct_initiators_and_tags(client: TestClient) -> None:
    _setup_admin(client)
    _insert_scan(created_by_username="alice", tags=["prod"])
    _insert_scan(created_by_username="bob", tags=["prod", "dev"])
    opts = client.get("/api/scans/filter-options").json()
    assert opts["initiators"] == ["alice", "bob"]
    assert opts["tags"] == ["dev", "prod"]


# --- Tags --------------------------------------------------------------------


def test_set_tags_requires_operator_and_csrf(client: TestClient) -> None:
    admin_csrf = _setup_admin(client)
    scan_id = _insert_scan()
    # Missing CSRF → 403.
    assert client.put(f"/api/scans/{scan_id}/tags", json={"tags": ["x"]}).status_code == 403
    # Viewer role → 403.
    viewer_csrf = _make_viewer(client, admin_csrf)
    denied = client.put(
        f"/api/scans/{scan_id}/tags", headers={CSRF: viewer_csrf}, json={"tags": ["x"]}
    )
    assert denied.status_code == 403


def test_set_tags_normalizes_and_persists(client: TestClient) -> None:
    csrf = _setup_admin(client)
    scan_id = _insert_scan()
    resp = client.put(
        f"/api/scans/{scan_id}/tags",
        headers={CSRF: csrf},
        json={"tags": ["Prod", "prod", " Team-A "]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["tags"] == ["prod", "team-a"]
    # Replacing with a new set removes the old tags.
    resp2 = client.put(f"/api/scans/{scan_id}/tags", headers={CSRF: csrf}, json={"tags": ["only"]})
    assert resp2.json()["tags"] == ["only"]


# --- Exports -----------------------------------------------------------------


def test_per_scan_export_formats(client: TestClient) -> None:
    _setup_admin(client)
    scan_id = _insert_scan(
        findings_count=1,
        severity_counts={"high": 1},
        findings=[
            {
                "finding_class": FindingClass.VULNERABILITY,
                "severity": Severity.HIGH,
                "vuln_id": "CVE-2024-1",
                "pkg_name": "libfoo",
            }
        ],
    )
    js = client.get(f"/api/scans/{scan_id}/export", params={"format": "json"})
    assert js.status_code == 200
    assert js.headers["content-type"].startswith("application/json")
    assert "attachment" in js.headers["content-disposition"]
    assert js.json()["findings"][0]["vuln_id"] == "CVE-2024-1"

    csv_resp = client.get(f"/api/scans/{scan_id}/export", params={"format": "csv"})
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert "CVE-2024-1" in csv_resp.text

    md = client.get(f"/api/scans/{scan_id}/export", params={"format": "markdown"})
    assert md.headers["content-type"].startswith("text/markdown")
    assert "# Scrye scan report" in md.text


def test_history_export_respects_filters(client: TestClient) -> None:
    _setup_admin(client)
    _insert_scan(target="keep", scanner=Scanner.GRYPE)
    _insert_scan(target="drop", scanner=Scanner.TRIVY)
    resp = client.get("/api/scans/export", params={"format": "csv", "scanner": "grype"})
    assert resp.status_code == 200
    assert "keep" in resp.text and "drop" not in resp.text
    assert resp.headers["content-disposition"].endswith('scrye-history.csv"')
    # No truncation signal when the full set fits under the cap.
    assert "x-scrye-truncated" not in resp.headers


def test_history_export_signals_truncation(client: TestClient, monkeypatch) -> None:
    """When the export cap fires, every format and the response header say so (APIR-4)."""
    _setup_admin(client)
    monkeypatch.setattr("app.api.scans._MAX_HISTORY_EXPORT_SCANS", 2)
    for i in range(3):
        _insert_scan(target=f"img:{i}")

    js = client.get("/api/scans/export", params={"format": "json"})
    assert js.headers["x-scrye-truncated"] == "true"
    assert js.headers["x-scrye-total"] == "3"
    body = js.json()
    assert body["truncated"] is True
    assert body["total"] == 3
    assert body["count"] == 2

    md = client.get("/api/scans/export", params={"format": "markdown"}).text
    assert "Truncated" in md and "of 3 matching scans" in md

    csv_text = client.get("/api/scans/export", params={"format": "csv"}).text
    assert csv_text.startswith("# Truncated: showing the newest 2 of 3")


# --- Diff --------------------------------------------------------------------


def _vuln(vuln_id: str, severity: Severity = Severity.HIGH) -> dict:
    return {
        "finding_class": FindingClass.VULNERABILITY,
        "severity": severity,
        "vuln_id": vuln_id,
        "pkg_name": "libfoo",
    }


def test_diff_two_scans_of_same_target(client: TestClient) -> None:
    _setup_admin(client)
    base = _insert_scan(target="app:1", findings=[_vuln("CVE-KEEP"), _vuln("CVE-FIXED")])
    compare = _insert_scan(target="app:1", findings=[_vuln("CVE-KEEP"), _vuln("CVE-NEW")])
    resp = client.get(f"/api/scans/{base}/diff/{compare}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [f["vuln_id"] for f in body["added"]] == ["CVE-NEW"]
    assert [f["vuln_id"] for f in body["removed"]] == ["CVE-FIXED"]
    assert body["unchanged_count"] == 1


def test_diff_payload_includes_location_for_non_vuln_findings(client: TestClient) -> None:
    """The same misconfig rule firing in two files must stay distinguishable (APIR-3).

    ``location`` is part of the diff identity for every non-vulnerability class,
    so the payload must carry it — otherwise a rule fixed in one file and newly
    firing in another serializes as two byte-identical rows.
    """
    _setup_admin(client)

    def _misconfig(location: str) -> dict:
        return {
            "finding_class": FindingClass.MISCONFIGURATION,
            "severity": Severity.HIGH,
            "vuln_id": "DS002",
            "title": "Image user should not be root",
            "location": location,
        }

    base = _insert_scan(
        scanner=Scanner.TRIVY,
        target_type=TargetType.REPOSITORY,
        target="repo",
        findings=[_misconfig("a/Dockerfile")],
    )
    compare = _insert_scan(
        scanner=Scanner.TRIVY,
        target_type=TargetType.REPOSITORY,
        target="repo",
        findings=[_misconfig("b/Dockerfile")],
    )
    body = client.get(f"/api/scans/{base}/diff/{compare}").json()
    assert [f["location"] for f in body["removed"]] == ["a/Dockerfile"]
    assert [f["location"] for f in body["added"]] == ["b/Dockerfile"]


def test_diff_rejects_different_targets(client: TestClient) -> None:
    _setup_admin(client)
    a = _insert_scan(target="app:1")
    b = _insert_scan(target="app:2")
    assert client.get(f"/api/scans/{a}/diff/{b}").status_code == 422


def test_diff_rejects_same_target_string_across_target_types(client: TestClient) -> None:
    """The same target string can name unrelated things across target types.

    E.g. a Grype image scan of ``app`` vs. a filesystem scan whose path prints
    as ``app`` — diffing them would compare unrelated scans, so the identity
    check must include the target type, not just scanner + target string.
    """
    _setup_admin(client)
    a = _insert_scan(scanner=Scanner.GRYPE, target_type=TargetType.IMAGE, target="app")
    b = _insert_scan(scanner=Scanner.GRYPE, target_type=TargetType.FILESYSTEM, target="app")
    resp = client.get(f"/api/scans/{a}/diff/{b}")
    assert resp.status_code == 422
    assert "target type" in resp.json()["detail"]


def test_diff_rejects_self(client: TestClient) -> None:
    _setup_admin(client)
    a = _insert_scan(target="app:1")
    assert client.get(f"/api/scans/{a}/diff/{a}").status_code == 422


# --- Filter presets ----------------------------------------------------------


def test_preset_crud_and_owner_isolation(client: TestClient) -> None:
    admin_csrf = _setup_admin(client)
    created = client.post(
        "/api/filter-presets",
        headers={CSRF: admin_csrf},
        json={"name": "Criticals", "filters": {"min_severity": "critical"}},
    )
    assert created.status_code == 201, created.text
    preset_id = created.json()["id"]
    assert created.json()["filters"] == {"min_severity": "critical"}

    listed = client.get("/api/filter-presets").json()
    assert len(listed) == 1 and listed[0]["name"] == "Criticals"

    updated = client.put(
        f"/api/filter-presets/{preset_id}",
        headers={CSRF: admin_csrf},
        json={"name": "Crit + High", "filters": {"min_severity": "high"}},
    )
    assert updated.json()["name"] == "Crit + High"

    # A different user cannot see or delete the admin's preset.
    viewer_csrf = _make_viewer(client, admin_csrf)
    assert client.get("/api/filter-presets").json() == []
    denied = client.delete(f"/api/filter-presets/{preset_id}", headers={CSRF: viewer_csrf})
    assert denied.status_code == 404


def test_preset_duplicate_name_conflicts(client: TestClient) -> None:
    csrf = _setup_admin(client)
    first = client.post(
        "/api/filter-presets", headers={CSRF: csrf}, json={"name": "dup", "filters": {}}
    )
    assert first.status_code == 201
    dup = client.post(
        "/api/filter-presets", headers={CSRF: csrf}, json={"name": "dup", "filters": {}}
    )
    assert dup.status_code == 409


def test_preset_create_requires_csrf(client: TestClient) -> None:
    _setup_admin(client)
    resp = client.post("/api/filter-presets", json={"name": "x", "filters": {}})
    assert resp.status_code == 403
