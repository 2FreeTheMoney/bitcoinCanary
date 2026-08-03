"""Status surface: keyless, snapshot-fed, honest about staleness."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew.snapshot import write_snapshot
from canaryew.web.app import create_app


@pytest.fixture
def client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("CANARYEW_HOME", str(tmp_path))
    return TestClient(create_app())


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def snapshot_payload(updated_at: datetime) -> dict:
    return {
        "locked": False,
        "boot_count": 3,
        "updated_at": _iso(updated_at),
        "degraded": False,
        "watches": 1,
        "outputs": 3,
        "unacknowledged_alerts": False,
        "last_block_height": 900_000,
        "heartbeat": {"seq": 12, "ts": _iso(updated_at), "mac": "ab" * 32,
                      "interval_seconds": 21_600},
    }


def test_health_needs_no_state(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200 and response.json()["ok"] is True


def test_status_without_snapshot_is_503_not_200(client: TestClient) -> None:
    """No data must read as 'unknown', never as 'fine'."""
    assert client.get("/api/status").status_code == 503
    assert client.get("/api/heartbeat/latest").status_code == 503


def test_status_serves_fresh_snapshot(client: TestClient, tmp_path: Path) -> None:
    write_snapshot(tmp_path / "status.json", snapshot_payload(datetime.now(timezone.utc)))
    payload = client.get("/api/status").json()
    assert payload["outputs"] == 3
    assert payload["snapshot_stale"] is False
    assert payload["snapshot_age_seconds"] < 60


def test_stale_snapshot_is_flagged(client: TestClient, tmp_path: Path) -> None:
    """A dead monitor must be visible through the still-running web process."""
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    write_snapshot(tmp_path / "status.json", snapshot_payload(old))
    payload = client.get("/api/status").json()
    assert payload["snapshot_stale"] is True


def test_heartbeat_endpoint_exposes_verifiable_fields(
    client: TestClient, tmp_path: Path
) -> None:
    write_snapshot(tmp_path / "status.json", snapshot_payload(datetime.now(timezone.utc)))
    payload = client.get("/api/heartbeat/latest").json()
    assert payload["seq"] == 12 and payload["mac"] == "ab" * 32


def test_corrupt_snapshot_reads_as_unavailable(client: TestClient, tmp_path: Path) -> None:
    (tmp_path / "status.json").write_text("{half a json")
    assert client.get("/api/status").status_code == 503
