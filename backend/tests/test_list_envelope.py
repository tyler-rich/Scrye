"""The shared ``{total, items}`` list envelope and its deliberate exceptions.

Locks in the convention introduced for L13 / APIR-8 (see
:mod:`app.api.pagination` and ``CONTRIBUTING.md`` § API conventions):

* Every endpoint returning a **collection of persisted resources** answers with
  ``{"total": int, "items": [...]}`` — including the unpaginated admin lists.
* Four endpoints returning a **fixed enumeration** or **live, non-persisted
  data** deliberately keep their bare-array shape. They are asserted here so a
  later review reads them as a decision rather than as drift.
* ``GET /api/scans`` keeps its frozen bare-array contract and is only marked
  deprecated in OpenAPI.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "unit-test-admin-passphrase"
CSRF = "x-csrf-token"

#: Enveloped endpoints reachable by an admin with an empty database. The
#: remaining Tier-A routes need a parent resource and are covered in their own
#: modules (scan artifacts in ``test_scans_api``, sessions in ``test_auth``).
ENVELOPED_PATHS = [
    "/api/registries",
    "/api/git-credentials",
    "/api/users",
    "/api/notifications",
    "/api/scan-schedules",
    "/api/api-tokens",
    "/api/backups",
    "/api/filter-presets",
    "/api/docker-environments",
    "/api/trivy/vex-documents",
    "/api/trivy/ignore-rules",
    "/api/auth/sessions",
]

#: Deliberate bare-array exceptions: fixed enumerations and id/name value lists.
#: ``/docker-environments/{id}/images`` is the fourth exception but needs a live
#: proxy, so it is covered by its own test in ``test_targets_api``.
BARE_ARRAY_PATHS = [
    "/api/registries/options",
    "/api/git-credentials/options",
    "/api/notifications/events",
]


def _setup_admin(client: TestClient) -> str:
    """Seed the first admin and return its CSRF token."""
    resp = client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
    assert resp.status_code == 201, resp.text
    return resp.json()["csrf_token"]


@pytest.mark.parametrize("path", ENVELOPED_PATHS)
def test_resource_collections_use_the_shared_envelope(client: TestClient, path: str) -> None:
    """Each persisted-resource list returns ``{total, items}``, never a bare array."""
    _setup_admin(client)
    resp = client.get(path)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, dict), f"{path} returned a bare array"
    assert set(body) == {"total", "items"}, f"{path} envelope keys: {sorted(body)}"
    assert isinstance(body["total"], int)
    assert isinstance(body["items"], list)
    # Unpaginated endpoints return one complete page, so the two always agree.
    assert body["total"] == len(body["items"])


@pytest.mark.parametrize("path", BARE_ARRAY_PATHS)
def test_value_lists_stay_bare_arrays(client: TestClient, path: str) -> None:
    """Fixed enumerations and value lists are exempt from the envelope by design."""
    _setup_admin(client)
    resp = client.get(path)
    assert resp.status_code == 200, resp.text
    assert isinstance(resp.json(), list), f"{path} should stay a bare array"


def test_envelope_total_counts_every_row(client: TestClient) -> None:
    """``total`` tracks the collection as rows are added (not a hardcoded zero)."""
    csrf = _setup_admin(client)
    for name in ("alpha", "beta", "gamma"):
        created = client.post(
            "/api/users",
            headers={CSRF: csrf},
            json={"username": name, "password": "unit-test-user-passphrase", "role": "viewer"},
        )
        assert created.status_code == 201, created.text

    body = client.get("/api/users").json()
    assert body["total"] == 4  # the seeded admin plus the three created above
    assert len(body["items"]) == 4
    assert [u["username"] for u in body["items"]] == ["admin", "alpha", "beta", "gamma"]


def test_paginated_envelopes_report_the_full_match_count(client: TestClient) -> None:
    """On a paginated endpoint ``total`` exceeds ``len(items)`` past page one.

    This is the property the unpaginated lists inherit the *shape* of: a client
    can tell from one response whether more rows exist.
    """
    _setup_admin(client)
    body = client.get("/api/audit", params={"limit": 1}).json()
    assert set(body) == {"total", "items"}
    assert body["total"] >= 1
    assert len(body["items"]) == 1


def test_legacy_scan_list_stays_a_bare_array_and_is_deprecated(client: TestClient) -> None:
    """``GET /api/scans`` keeps its frozen shape; only the OpenAPI marker changed.

    The bare array is a documented Phase-P4 contract (docs/ARCHIVE.md §14), so
    APIR-8 is closed by deprecating it in favour of ``/api/scans/history``
    rather than by re-shaping it.
    """
    _setup_admin(client)
    assert isinstance(client.get("/api/scans").json(), list)

    spec = client.get("/openapi.json").json()
    operation = spec["paths"]["/api/scans"]["get"]
    assert operation["deprecated"] is True
    description = operation["description"]
    assert "/api/scans/history" in description, "the replacement must be named"
    assert "total" in description, "the reason must be stated, not just the flag"
