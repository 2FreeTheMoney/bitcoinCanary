"""Unlock lifecycle and the control socket."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew.control import ControlError, ControlServer, send_command
from canaryew.secrets import SecretsError
from canaryew.store import StateStore
from canaryew.unlock import LockedError, UnlockManager

PASSPHRASE = "a-correct-horse-battery-staple-for-tests"


@pytest.fixture
def short_dir():
    """AF_UNIX socket paths are limited to ~104 bytes on macOS; pytest's
    tmp_path can exceed that, so sockets get a deliberately short directory."""
    path = Path(tempfile.mkdtemp(prefix="cew-"))
    yield path
    shutil.rmtree(path, ignore_errors=True)


# ------------------------------------------------------------------ unlock --- #

def test_lifecycle_locked_to_unlocked(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    store.initialize(PASSPHRASE)
    manager = UnlockManager(store, tmp_path / "boot.json")

    assert manager.locked
    with pytest.raises(LockedError):
        _ = manager.keys
    with pytest.raises(LockedError):
        _ = manager.state
    with pytest.raises(LockedError):
        manager.save()

    keys = manager.unlock(PASSPHRASE)
    assert not manager.locked
    assert manager.keys.verification_phrase == keys.verification_phrase
    manager.save()  # persists without error once unlocked


def test_wrong_passphrase_stays_locked(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    store.initialize(PASSPHRASE)
    manager = UnlockManager(store, tmp_path / "boot.json")

    with pytest.raises(SecretsError):
        manager.unlock("wrong")
    assert manager.locked


def test_boot_counter_increments_and_survives_corruption(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    store.initialize(PASSPHRASE)
    boot_path = tmp_path / "boot.json"
    manager = UnlockManager(store, boot_path)

    assert manager.record_boot().boot_count == 1
    assert manager.record_boot().boot_count == 2
    assert boot_path.stat().st_mode & 0o077 == 0

    boot_path.write_text("{corrupt")
    info = manager.record_boot()   # corruption resets, never crashes startup
    assert info.boot_count == 1
    assert json.loads(boot_path.read_text())["boot_count"] == 1


# ----------------------------------------------------------------- control --- #

def test_control_round_trip(short_dir: Path) -> None:
    def handler(request: dict) -> dict:
        if request.get("command") == "greet":
            return {"ok": True, "echo": request.get("payload")}
        return {"ok": False, "error": "unknown"}

    server = ControlServer(short_dir / "c.sock", handler)
    server.start()
    try:
        response = send_command(short_dir / "c.sock", {"command": "greet", "payload": "hi"})
        assert response == {"ok": True, "echo": "hi"}
        assert send_command(short_dir / "c.sock", {"command": "nope"})["ok"] is False
    finally:
        server.stop()


def test_socket_is_owner_only(short_dir: Path) -> None:
    server = ControlServer(short_dir / "c.sock", lambda r: {"ok": True})
    try:
        assert (short_dir / "c.sock").stat().st_mode & 0o077 == 0
    finally:
        server.stop()


def test_handler_exception_returns_terse_error(short_dir: Path) -> None:
    """A crash in a handler must not leak a traceback (or echoed passphrase)."""

    def handler(request: dict) -> dict:
        raise RuntimeError(f"boom with secret {request.get('passphrase')}")

    server = ControlServer(short_dir / "c.sock", handler)
    server.start()
    try:
        response = send_command(
            short_dir / "c.sock", {"command": "unlock", "passphrase": "hunter2"}
        )
        assert response["ok"] is False
        assert "hunter2" not in json.dumps(response)
    finally:
        server.stop()


def test_missing_socket_gives_actionable_error(short_dir: Path) -> None:
    with pytest.raises(ControlError, match="Is the canaryew service running"):
        send_command(short_dir / "absent.sock", {"command": "status"})


def test_malformed_request_is_rejected(short_dir: Path) -> None:
    import socket

    server = ControlServer(short_dir / "c.sock", lambda r: {"ok": True})
    server.start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5.0)
            client.connect(str(short_dir / "c.sock"))
            client.sendall(b"this is not json\n")
            reply = client.recv(4096)
        assert json.loads(reply)["ok"] is False
    finally:
        server.stop()
