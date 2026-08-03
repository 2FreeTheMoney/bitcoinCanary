"""Keyless status surface.

This process holds **nothing**: no passphrase, no keys, no control-socket
access, no RPC credentials. It reads the redacted snapshot file the monitor
writes and serves it read-only on 127.0.0.1 (nginx proxies a subpath if LAN
access is wanted).

Compromising this process therefore yields the same information the operator
would happily read out loud: counts, block heights, timestamps, and heartbeat
sequence/MAC values that already travel in notifications.

Run: ``uvicorn --factory canaryew.web.app:create_app --host 127.0.0.1``
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException

from canaryew.config import load_config
from canaryew.snapshot import read_snapshot


def _staleness_seconds(payload: dict[str, Any]) -> float | None:
    raw = payload.get("updated_at")
    if not raw:
        return None
    try:
        updated = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - updated).total_seconds()


def create_app() -> FastAPI:
    config = load_config()
    app = FastAPI(title="canaryEW status", docs_url=None, redoc_url=None)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        """Liveness of the web process itself. Touches no state at all."""
        return {"ok": True, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        payload = read_snapshot(config.snapshot_path)
        if payload is None:
            raise HTTPException(
                status_code=503,
                detail="No status snapshot. The monitor service has not written one.",
            )
        stale_after = config.poll_interval_seconds * 2
        staleness = _staleness_seconds(payload)
        payload["snapshot_age_seconds"] = staleness
        payload["snapshot_stale"] = staleness is None or staleness > stale_after
        return payload

    @app.get("/api/heartbeat/latest")
    def heartbeat_latest() -> dict[str, Any]:
        """Last heartbeat seq/ts/mac, for manual verification against the
        notification the operator received."""
        payload = read_snapshot(config.snapshot_path)
        if payload is None or "heartbeat" not in payload:
            raise HTTPException(status_code=503, detail="No heartbeat recorded yet.")
        return dict(payload["heartbeat"])

    return app
