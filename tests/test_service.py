"""Service integration: boot, unlock, detection-to-alert, heartbeat, snapshot."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from conftest import FakeRpc, RecordingChannel

from canaryew.config import load_config
from canaryew.dispatch import Dispatcher
from canaryew.monitor import Severity
from canaryew.service import Service
from canaryew.snapshot import read_snapshot
from canaryew.store import StateStore, Watch, WatchedOutput

PASSPHRASE = "a-correct-horse-battery-staple-for-tests"
TXIDS = [f"{i:064x}" for i in range(3)]


@pytest.fixture
def home():
    # Short path: the control socket lives here and AF_UNIX paths are capped.
    path = Path(tempfile.mkdtemp(prefix="cew-"))
    yield path
    shutil.rmtree(path, ignore_errors=True)


def make_service(home: Path, rpc: FakeRpc, **kwargs) -> tuple[Service, RecordingChannel]:
    config = load_config({"CANARYEW_HOME": str(home)})
    store = StateStore(config.state_path)
    keys, state = store.initialize(PASSPHRASE)
    state.watches = [
        Watch(
            watch_id="w1",
            label="vault-cosigner-a",
            outputs=[WatchedOutput(txid=t, vout=0, value_sat=100_000) for t in TXIDS],
        )
    ]
    store.save(keys, state)

    service = Service(config, rpc=rpc, **kwargs)
    service.startup()
    assert service.handle_command({"command": "unlock", "passphrase": PASSPHRASE})["ok"]

    recorder = RecordingChannel()
    service.dispatcher = Dispatcher([recorder])
    return service, recorder


# ----------------------------------------------------------------- lifecycle - #

def test_startup_announces_locked_state(home: Path) -> None:
    config = load_config({"CANARYEW_HOME": str(home)})
    StateStore(config.state_path).initialize(PASSPHRASE)
    service = Service(config, rpc=FakeRpc())
    try:
        service.startup()
        assert config.boot_state_path.exists()
        assert config.control_socket_path.exists()

        status = service.handle_command({"command": "status"})["status"]
        assert status["locked"] is True
        assert status["boot_count"] == 1
        # A locked snapshot must not leak monitored-state details.
        assert "watches" not in status
    finally:
        service.shutdown()


def test_unlock_via_command_and_wrong_passphrase(home: Path) -> None:
    config = load_config({"CANARYEW_HOME": str(home)})
    StateStore(config.state_path).initialize(PASSPHRASE)
    service = Service(config, rpc=FakeRpc())
    try:
        service.startup()
        bad = service.handle_command({"command": "unlock", "passphrase": "nope"})
        assert bad["ok"] is False and service.unlock_manager.locked

        good = service.handle_command({"command": "unlock", "passphrase": PASSPHRASE})
        assert good["ok"] and "verification_phrase" in good
        assert not service.unlock_manager.locked
        assert service.handle_command(
            {"command": "unlock", "passphrase": PASSPHRASE}
        ).get("already_unlocked")
    finally:
        service.shutdown()


# ----------------------------------------------------------- detection path - #

def test_spend_reaches_channel_with_verification_phrase(home: Path) -> None:
    rpc = FakeRpc(spent={f"{TXIDS[1]}:0"})
    service, recorder = make_service(home, rpc)
    try:
        service.run_once()
        criticals = [n for n in recorder.notifications if n.severity is Severity.CRITICAL]
        assert len(criticals) == 1
        alert = criticals[0]
        assert "vault-cosigner-a" in alert.body
        assert service.unlock_manager.keys.verification_phrase in alert.body
        # minimal redaction: no txids, no values
        assert TXIDS[1] not in alert.body
        assert "BTC" not in alert.body
    finally:
        service.shutdown()


def test_first_pass_emits_heartbeat_and_persists_before_send(home: Path) -> None:
    service, recorder = make_service(home, FakeRpc())
    try:
        service.run_once()
        beats = [n for n in recorder.notifications if n.severity is Severity.INFO]
        assert len(beats) == 1

        # Persisted seq must match the sent one (save-before-send ordering).
        keys, state = StateStore(service.config.state_path).unlock(PASSPHRASE)
        assert state.heartbeat_seq == 1
        assert state.last_heartbeat_at is not None
    finally:
        service.shutdown()


def test_heartbeat_respects_interval(home: Path) -> None:
    service, recorder = make_service(home, FakeRpc())
    try:
        now = datetime.now(timezone.utc)
        service.run_once(now=now)
        service.run_once(now=now + timedelta(minutes=10))   # poll, not due
        assert len([n for n in recorder.notifications if n.severity is Severity.INFO]) == 1

        service.run_once(now=now + timedelta(hours=7))      # past 6h default
        assert len([n for n in recorder.notifications if n.severity is Severity.INFO]) == 2
    finally:
        service.shutdown()


def test_no_heartbeat_while_blind(home: Path) -> None:
    """A heartbeat asserts 'I checked'; unreachable or unsynced passes must not emit one."""
    rpc = FakeRpc(unreachable=True)
    service, recorder = make_service(home, rpc, degraded_grace_seconds=0.0)
    try:
        service.run_once()
        assert [n.severity for n in recorder.notifications] == [Severity.DEGRADED]

        rpc.unreachable = False
        rpc.synced = False
        service.run_once()
        assert len([n for n in recorder.notifications if n.severity is Severity.INFO]) == 0
    finally:
        service.shutdown()


def test_degraded_grace_suppresses_first_blip(home: Path) -> None:
    rpc = FakeRpc(unreachable=True)
    service, recorder = make_service(home, rpc, degraded_grace_seconds=3600.0)
    try:
        service.run_once()
        assert recorder.notifications == []      # inside grace: log only

        rpc.unreachable = False
        service.run_once()                       # recovery re-arms
        assert service._degraded_since is None
    finally:
        service.shutdown()


def test_degraded_alerts_once_not_every_pass(home: Path) -> None:
    rpc = FakeRpc(unreachable=True)
    service, recorder = make_service(home, rpc, degraded_grace_seconds=0.0)
    try:
        service.run_once()
        service.run_once()
        service.run_once()
        degraded = [n for n in recorder.notifications if n.severity is Severity.DEGRADED]
        assert len(degraded) == 1
    finally:
        service.shutdown()


def test_full_tier_is_clamped_on_capped_channels(home: Path) -> None:
    """DESIGN S7: FULL detail may reach the trusted channel, never one whose
    transport a third party can read."""
    import dataclasses

    from canaryew.notify.base import RedactionTier

    rpc = FakeRpc(spent={f"{TXIDS[1]}:0"})
    service, _ = make_service(home, rpc)
    service.config = dataclasses.replace(service.config, redaction="full")
    trusted = RecordingChannel("trusted")
    webhookish = RecordingChannel("webhookish", max_redaction=RedactionTier.STANDARD)
    service.dispatcher = Dispatcher([trusted, webhookish])
    try:
        service.run_once()
        trusted_alert = next(
            n for n in trusted.notifications if n.severity is Severity.CRITICAL
        )
        capped_alert = next(
            n for n in webhookish.notifications if n.severity is Severity.CRITICAL
        )
        assert TXIDS[1] in trusted_alert.body          # full detail delivered
        assert TXIDS[1] not in capped_alert.body       # clamped to standard
        assert "BTC" in capped_alert.body              # value bucket survives
    finally:
        service.shutdown()


# ------------------------------------------------------------------- ack ---- #

def test_status_carries_last_heartbeat_mac_between_passes(home: Path) -> None:
    """The control-socket status must show the last emitted MAC, not null."""
    service, _ = make_service(home, FakeRpc())
    try:
        service.run_once()
        status = service.handle_command({"command": "status"})["status"]
        assert status["heartbeat"]["seq"] == 1
        assert status["heartbeat"]["mac"] is not None
    finally:
        service.shutdown()


def test_ack_clears_alert_condition_and_persists(home: Path) -> None:
    rpc = FakeRpc(spent={f"{TXIDS[0]}:0"})
    service, _ = make_service(home, rpc)
    try:
        service.run_once()
        assert service.unlock_manager.state.has_unacknowledged_alerts

        response = service.handle_command({"command": "ack", "watch_id": "w1"})
        assert response == {"ok": True, "acknowledged": 1}
        assert not service.unlock_manager.state.has_unacknowledged_alerts

        # Persisted, and the spent flag itself is retained (never auto-cleared).
        _, state = StateStore(service.config.state_path).unlock(PASSPHRASE)
        assert not state.has_unacknowledged_alerts
        assert state.watches[0].missing_outputs
    finally:
        service.shutdown()


def test_ack_while_locked_is_refused(home: Path) -> None:
    config = load_config({"CANARYEW_HOME": str(home)})
    StateStore(config.state_path).initialize(PASSPHRASE)
    service = Service(config, rpc=FakeRpc())
    try:
        service.startup()
        response = service.handle_command({"command": "ack", "watch_id": "all"})
        assert response["ok"] is False and "LOCKED" in response["error"]
    finally:
        service.shutdown()


# --------------------------------------------------------------- snapshot --- #

def test_snapshot_is_redacted(home: Path) -> None:
    rpc = FakeRpc(spent={f"{TXIDS[1]}:0"})
    service, _ = make_service(home, rpc)
    try:
        service.run_once()
        raw = service.config.snapshot_path.read_text()
        assert "vault-cosigner-a" not in raw     # no labels
        for txid in TXIDS:
            assert txid not in raw               # no outpoints

        payload = read_snapshot(service.config.snapshot_path)
        assert payload is not None
        assert payload["locked"] is False
        assert payload["outputs"] == 3
        assert payload["unacknowledged_alerts"] is True
        assert payload["heartbeat"]["seq"] == 1
        assert payload["last_block_height"] == 900_000
    finally:
        service.shutdown()
