"""Core behaviour tests: sealed store round-trip and detection semantics."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew import secrets
from canaryew.monitor import Monitor, Severity
from canaryew.node import ChainTip, NodeUnavailable, Utxo
from canaryew.store import StateStore, StoreError, StoreState, Watch, WatchedOutput

PASSPHRASE = "a-correct-horse-battery-staple-for-tests"


class FakeRpc:
    """Scriptable stand-in for bitcoind."""

    def __init__(self, *, spent: set[str] | None = None, synced: bool = True,
                 height: int = 900_000, unreachable: bool = False) -> None:
        self.spent = spent or set()
        self.synced = synced
        self.height = height
        self.unreachable = unreachable
        self.txout_calls: list[str] = []

    def chain_tip(self) -> ChainTip:
        if self.unreachable:
            raise NodeUnavailable("connection refused")
        return ChainTip(
            height=self.height,
            best_hash="00" * 32,
            initial_block_download=not self.synced,
            verification_progress=1.0 if self.synced else 0.5,
        )

    def get_txout(self, txid: str, vout: int, *, include_mempool: bool = True):
        outpoint = f"{txid}:{vout}"
        self.txout_calls.append(outpoint)
        if outpoint in self.spent:
            return None
        return Utxo(txid=txid, vout=vout, value_sat=100_000, confirmations=6,
                    script_pubkey="0014" + "ab" * 20)


def make_state(count: int = 3) -> StoreState:
    outputs = [WatchedOutput(txid=f"{i:064x}", vout=0, value_sat=100_000)
               for i in range(count)]
    return StoreState(watches=[
        Watch(watch_id="w1", label="vault-cosigner-a", outputs=outputs)
    ])


# --------------------------------------------------------------- store ----- #

def test_store_roundtrip_and_wrong_passphrase(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    keys, state = store.initialize(PASSPHRASE)
    state.watches = make_state().watches
    store.save(keys, state)

    reopened_keys, reopened = store.unlock(PASSPHRASE)
    assert reopened.total_outputs == 3
    assert reopened.watches[0].label == "vault-cosigner-a"
    assert reopened_keys.verification_phrase == keys.verification_phrase

    with pytest.raises(secrets.SecretsError):
        store.unlock("wrong-passphrase")


def test_store_refuses_to_clobber(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    store.initialize(PASSPHRASE)
    with pytest.raises(StoreError, match="already exists"):
        store.initialize(PASSPHRASE)


def test_header_carries_no_secrets(tmp_path: Path) -> None:
    """The plaintext header must be readable pre-unlock but reveal nothing."""
    store = StateStore(tmp_path / "state.json")
    keys, state = store.initialize(PASSPHRASE)
    state.watches = make_state().watches
    state.smtp_password = "super-secret-smtp"
    store.save(keys, state)

    raw = (tmp_path / "state.json").read_text()
    assert "super-secret-smtp" not in raw
    assert "vault-cosigner-a" not in raw
    assert f"{0:064x}" not in raw  # no txids in cleartext


def test_store_file_is_owner_only(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    store.initialize(PASSPHRASE)
    assert (tmp_path / "state.json").stat().st_mode & 0o077 == 0


# ------------------------------------------------------------- detection --- #

def test_clean_pass_detects_nothing() -> None:
    state = make_state()
    result = Monitor(FakeRpc()).run_pass(state)
    assert result.is_clean and result.checked == 3
    assert result.newly_missing == 0
    assert state.last_block_height == 900_000


def test_spend_is_detected_and_flagged() -> None:
    state = make_state()
    spent = f"{1:064x}:0"
    result = Monitor(FakeRpc(spent={spent})).run_pass(state)

    assert len(result.spend_events) == 1
    event = result.spend_events[0]
    assert event.severity is Severity.CRITICAL
    assert event.missing_count == 1
    assert event.missing_value_sat == 100_000
    assert event.total_outputs == 3
    assert state.watches[0].outputs[1].present is False
    assert state.watches[0].outputs[1].first_missing_at is not None
    assert state.has_unacknowledged_alerts


def test_flag_is_sticky_and_not_realerted() -> None:
    """Rule 1: a reappearing output must not produce an all-clear."""
    state = make_state()
    spent = f"{1:064x}:0"
    Monitor(FakeRpc(spent={spent})).run_pass(state)

    # Second pass with the output restored (simulating a reorg).
    rpc = FakeRpc(spent=set())
    result = Monitor(rpc).run_pass(state)

    assert result.spend_events == []           # not re-alerted
    assert state.watches[0].outputs[1].present is False  # still flagged
    assert spent not in rpc.txout_calls        # not even re-queried


def test_unsynced_node_suspends_evaluation() -> None:
    """Rule 2: an unsynced node must not manufacture spend events."""
    state = make_state()
    result = Monitor(FakeRpc(spent={f"{0:064x}:0"}, synced=False)).run_pass(state)

    assert result.skipped_reason is not None
    assert result.spend_events == []
    assert all(o.present for o in state.watches[0].outputs)


def test_unreachable_node_is_degraded_not_spent() -> None:
    """Rule 3: transport failure must never be read as a spend."""
    state = make_state()
    result = Monitor(FakeRpc(unreachable=True)).run_pass(state)

    assert result.degraded is not None
    assert result.degraded.reason == "node_unreachable"
    assert result.degraded.severity is Severity.DEGRADED
    assert result.spend_events == []
    assert all(o.present for o in state.watches[0].outputs)


def test_state_digest_changes_when_output_goes_missing() -> None:
    """Heartbeat MACs bind to this digest, so it must track presence."""
    state = make_state()
    before = state.digest()
    Monitor(FakeRpc(spent={f"{2:064x}:0"})).run_pass(state)
    assert state.digest() != before


def test_acknowledgement_clears_alert_condition() -> None:
    state = make_state()
    Monitor(FakeRpc(spent={f"{0:064x}:0"})).run_pass(state)
    assert state.has_unacknowledged_alerts

    for output in state.watches[0].missing_outputs:
        output.acknowledged = True
    assert not state.has_unacknowledged_alerts
    assert state.watches[0].missing_outputs  # history is retained
