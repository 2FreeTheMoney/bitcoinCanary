"""Redacted status snapshot, the only bridge to the keyless web process.

The monitor writes this file; the FastAPI status app only ever reads it. That
one-way, file-shaped interface is what lets the web surface run as a separate
process holding no keys, no passphrase, and no socket into the monitor.

Contents are redacted at the source: counts, block heights, timestamps, the
heartbeat seq/MAC (already public -- it travels in notifications), and the
locked flag. Never outpoints, never labels, never anything derived from a key.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_snapshot(path: str | Path, payload: dict[str, Any]) -> None:
    """Atomically replace the snapshot file (0640)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_path = tempfile.mkstemp(
        dir=str(target.parent), prefix=".canaryew-status-", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, separators=(",", ":"))
        os.chmod(temp_path, 0o640)
        os.replace(temp_path, target)
    except Exception:
        Path(temp_path).unlink(missing_ok=True)
        raise


def read_snapshot(path: str | Path) -> dict[str, Any] | None:
    """Read the snapshot, or ``None`` if absent/unreadable/corrupt.

    Corruption reads as "no data" rather than an exception: the web surface
    must report staleness, not crash on a half-written file it should never
    see anyway (writes are atomic).
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None
