"""Heartbeat: monotonic sequence, MAC binding, and due-scheduling."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew import secrets
from canaryew.heartbeat import (
    Heartbeat,
    build_heartbeat,
    heartbeat_notification,
    summarize,
    verify_heartbeat,
)
from canaryew.monitor import heartbeat_due
from canaryew.store import StoreState, Watch, WatchedOutput

KEYS = secrets.derive_keys(b"k" * 32)


def make_state(missing: int = 0, acked: int = 0) -> StoreState:
    outputs = [WatchedOutput(txid=f"{i:064x}", vout=0, value_sat=1000) for i in range(5)]
    for output in outputs[:missing]:
        output.present = False
    for output in outputs[:acked]:
        output.acknowledged = True
    return StoreState(watches=[Watch(watch_id="w1", label="vault", outputs=outputs)])


# ----------------------------------------------------------------- building -- #

def test_sequence_is_monotonic_and_state_updated() -> None:
    state = make_state()
    first = build_heartbeat(state, KEYS)
    second = build_heartbeat(state, KEYS)
    assert (first.seq, second.seq) == (1, 2)
    assert state.heartbeat_seq == 2
    assert state.last_heartbeat_at == second.ts


def test_mac_verifies_and_tamper_fails() -> None:
    state = make_state()
    beat = build_heartbeat(state, KEYS)
    assert verify_heartbeat(KEYS.hmac_key, beat)

    for tampered in (
        Heartbeat(beat.seq + 1, beat.ts, beat.state_summary, beat.state_digest,
                  beat.block_height, beat.mac_hex),                    # replayed seq
        Heartbeat(beat.seq, "2020-01-01T00:00:00+00:00", beat.state_summary,
                  beat.state_digest, beat.block_height, beat.mac_hex),  # altered ts
        Heartbeat(beat.seq, beat.ts, beat.state_summary, "0" * 16,
                  beat.block_height, beat.mac_hex),                    # altered state
    ):
        assert not verify_heartbeat(KEYS.hmac_key, tampered)

    other_keys = secrets.derive_keys(b"x" * 32)
    assert not verify_heartbeat(other_keys.hmac_key, beat)


def test_mac_is_domain_separated_from_raw_mac() -> None:
    """A MAC computed over the same fields without the domain prefix must differ."""
    state = make_state()
    beat = build_heartbeat(state, KEYS)
    undomained = secrets.mac(
        KEYS.hmac_key,
        str(beat.seq).encode(),
        beat.ts.encode(),
        beat.state_digest.encode(),
    )
    assert undomained != beat.mac_hex


def test_heartbeat_binds_current_state_digest() -> None:
    state = make_state()
    clean = build_heartbeat(state, KEYS)
    state.watches[0].outputs[0].present = False  # a spend happened
    after_spend = build_heartbeat(state, KEYS)
    assert clean.state_digest != after_spend.state_digest


# ---------------------------------------------------------------- summarize -- #

def test_summaries_read_correctly() -> None:
    assert summarize(make_state()) == "1 watches / 5 outputs / all present"
    assert "2 missing (2 UNACKNOWLEDGED)" in summarize(make_state(missing=2))
    assert "all acknowledged" in summarize(make_state(missing=2, acked=2))


def test_summary_carries_no_labels_or_outpoints() -> None:
    state = make_state(missing=1)
    text = summarize(state)
    assert "vault" not in text and "0000" not in text


# --------------------------------------------------------------- scheduling -- #

def test_due_immediately_on_fresh_state() -> None:
    assert heartbeat_due(StoreState(), 3600)


def test_not_due_before_interval_even_after_monitor_passes() -> None:
    """The original bug: monitor passes must not reset the heartbeat clock."""
    state = make_state()
    now = datetime.now(timezone.utc)
    build_heartbeat(state, KEYS, now=now)

    # Simulate many monitor passes refreshing last_check_at.
    state.last_check_at = (now + timedelta(minutes=50)).isoformat(timespec="seconds")

    assert not heartbeat_due(state, 3600, now=now + timedelta(minutes=55))
    assert heartbeat_due(state, 3600, now=now + timedelta(minutes=61))


def test_unparseable_timestamp_reads_as_due() -> None:
    state = make_state()
    state.heartbeat_seq = 5
    state.last_heartbeat_at = "not-a-timestamp"
    assert heartbeat_due(state, 3600)


# ------------------------------------------------------------- notification -- #

def test_notification_contains_verifiable_fields() -> None:
    state = make_state()
    beat = build_heartbeat(state, KEYS)
    rendered = heartbeat_notification(beat, KEYS.verification_phrase)
    assert f"#{beat.seq}" in rendered.title
    assert beat.mac_hex[:32] in rendered.body
    assert KEYS.verification_phrase in rendered.body
