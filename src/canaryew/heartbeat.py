"""Positive heartbeat construction and verification.

The dead-man's switch (DESIGN S4): the service proves liveness on a schedule,
and the operator treats silence as an incident. Each heartbeat carries a
monotonic sequence number and an HMAC over ``(seq, timestamp, state_digest)``
keyed by material derived from the operator's passphrase.

The MAC is domain-separated with a fixed prefix so no other MAC produced by
this system (watchfile fingerprints, future message types) can be replayed as
a heartbeat, and vice versa.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from canaryew import secrets
from canaryew.notify.base import Notification, render_heartbeat
from canaryew.store import StoreState

_DOMAIN: Final[bytes] = b"canaryew/v1/heartbeat"


@dataclass(frozen=True)
class Heartbeat:
    """One emitted heartbeat, exactly what the operator can verify."""

    seq: int
    ts: str
    state_summary: str
    state_digest: str
    block_height: int | None
    mac_hex: str


def summarize(state: StoreState) -> str:
    """Human-readable state line, e.g. ``4 watches / 41 outputs / all present``.

    Deliberately carries counts only -- no labels, no outpoints -- because it
    travels in notification bodies on the least-trusted channel.
    """
    watches = len(state.watches)
    outputs = state.total_outputs
    missing = sum(len(w.missing_outputs) for w in state.watches)
    unacked = sum(len(w.unacknowledged_missing) for w in state.watches)

    if missing == 0:
        condition = "all present"
    elif unacked == 0:
        condition = f"{missing} missing, all acknowledged"
    else:
        condition = f"{missing} missing ({unacked} UNACKNOWLEDGED)"
    return f"{watches} watches / {outputs} outputs / {condition}"


def _mac(hmac_key: bytes, seq: int, ts: str, state_digest: str) -> str:
    return secrets.mac(
        hmac_key,
        _DOMAIN,
        str(seq).encode("ascii"),
        ts.encode("ascii"),
        state_digest.encode("ascii"),
    )


def build_heartbeat(
    state: StoreState,
    keys: secrets.KeyMaterial,
    *,
    now: datetime | None = None,
) -> Heartbeat:
    """Advance the sequence and produce the next heartbeat.

    Mutates ``state`` (seq increment + ``last_heartbeat_at``); the caller must
    persist the store *before* dispatching, so that a crash between the two
    can only lose a sent heartbeat, never reuse a sequence number. A skipped
    seq is visible and explainable; a duplicated one would make replay
    detection meaningless.
    """
    reference = now or datetime.now(timezone.utc)
    ts = reference.isoformat(timespec="seconds")
    seq = state.heartbeat_seq + 1
    digest = state.digest()

    heartbeat = Heartbeat(
        seq=seq,
        ts=ts,
        state_summary=summarize(state),
        state_digest=digest,
        block_height=state.last_block_height,
        mac_hex=_mac(keys.hmac_key, seq, ts, digest),
    )
    state.heartbeat_seq = seq
    state.last_heartbeat_at = ts
    return heartbeat


def verify_heartbeat(hmac_key: bytes, heartbeat: Heartbeat) -> bool:
    """Recompute and compare the MAC in constant time.

    This is what makes a forged 'all clear' fail: the attacker would need the
    sealed HMAC key, which never exists on disk.
    """
    return secrets.verify_mac(
        hmac_key,
        heartbeat.mac_hex,
        _DOMAIN,
        str(heartbeat.seq).encode("ascii"),
        heartbeat.ts.encode("ascii"),
        heartbeat.state_digest.encode("ascii"),
    )


def heartbeat_notification(
    heartbeat: Heartbeat, verification_phrase: str
) -> Notification:
    """Render the heartbeat for dispatch."""
    return render_heartbeat(
        seq=heartbeat.seq,
        state_summary=heartbeat.state_summary,
        block_height=heartbeat.block_height,
        mac_hex=heartbeat.mac_hex,
        verification_phrase=verification_phrase,
    )
