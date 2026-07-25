"""Tests for the explicit-UTC timestamp wire format (APIR-5).

Response models serialize naive-UTC timestamps with an explicit ``Z`` designator
(:data:`app.api.schema_types.UtcDatetime`) so a consumer can't parse them as
browser-local and shift every instant by its UTC offset.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.api.schema_types import UtcDatetime
from app.core.timeutil import utcnow
from tests.test_auth import CSRF, setup_admin


class _Model(BaseModel):
    at: UtcDatetime
    maybe: UtcDatetime | None = None


class TestUtcDatetime:
    def test_naive_serializes_with_z(self) -> None:
        dumped = _Model(at=datetime(2026, 7, 11, 4, 0, 0)).model_dump(mode="json")
        assert dumped["at"] == "2026-07-11T04:00:00Z"
        assert dumped["maybe"] is None

    def test_aware_is_converted_before_z(self) -> None:
        aware = datetime(2026, 7, 11, 13, 0, 0, tzinfo=UTC)
        dumped = _Model(at=aware).model_dump(mode="json")
        assert dumped["at"] == "2026-07-11T13:00:00Z"

    def test_python_mode_unchanged(self) -> None:
        # Internal (non-JSON) dumps keep the raw datetime for callers that need it.
        assert isinstance(_Model(at=utcnow()).model_dump()["at"], datetime)


class TestResponseTimestamps:
    def test_api_timestamp_carries_z(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        client.post(
            "/api/trivy/ignore-rules",
            json={"vuln_id": "CVE-2026-7777"},
            headers={CSRF: csrf},
        )
        created_at = client.get("/api/trivy/ignore-rules").json()["items"][0]["created_at"]
        assert created_at.endswith("Z"), created_at
