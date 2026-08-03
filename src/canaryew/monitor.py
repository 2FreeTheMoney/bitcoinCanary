"""The detection loop.

One pass over every watched outpoint, asking bitcoind whether it is still in the
UTXO set. No key material is involved: see ``docs/DESIGN.md`` S1.

Design rules encoded here, each chosen so that failures are loud rather than
silent:

1. **Never auto-clear.** Once an output is seen missing it stays flagged until
   the operator acknowledges. A reorg that restores it is recorded, not treated
   as an all-clear -- an attempted spend is itself signal.
2. **Gate on sync.** If the node is behind or in IBD, spend evaluation is
   suspended. A partially-synced node reports outputs as absent for reasons that
   have nothing to do with theft.
3. **Unreachable != spent.** Transport failure raises a degraded condition and
   never marks an output missing.
4. **Mempool-aware.** Unconfirmed spends are detected on relay, which buys the
   operator time before confirmation. The cost is that a dropped unconfirmed
   spend can produce a false positive -- an acceptable trade in this direction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Final

from canaryew.node import BitcoinRpc, NodeError, NodeUnavailable
from canaryew.store import StoreState, Watch, WatchedOutput

logger = logging.getLogger("canaryew.monitor")

# Suppress spend evaluation until the node is this close to the tip.
MIN_VERIFICATION_PROGRESS: Final[float] = 0.9999


class Severity(str, Enum):
    INFO = "info"
    DEGRADED = "degraded"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SpendEvent:
    """One or more outputs from a single watch left the UTXO set."""

    watch_id: str
    watch_label: str
    missing: list[WatchedOutput]
    total_outputs: int
    block_height: int
    detected_at: str
    severity: Severity = Severity.CRITICAL

    @property
    def missing_count(self) -> int:
        return len(self.missing)

    @property
    def missing_value_sat(self) -> int:
        return sum(o.value_sat for o in self.missing)


@dataclass(frozen=True)
class DegradedEvent:
    """The monitor could not complete a pass."""

    reason: str
    detail: str
    detected_at: str
    severity: Severity = Severity.DEGRADED


@dataclass
class PassResult:
    """Outcome of a single monitoring pass."""

    checked: int = 0
    newly_missing: int = 0
    spend_events: list[SpendEvent] = field(default_factory=list)
    degraded: DegradedEvent | None = None
    block_height: int | None = None
    skipped_reason: str | None = None

    @property
    def is_clean(self) -> bool:
        return not self.spend_events and self.degraded is None

    @property
    def did_evaluate(self) -> bool:
        return self.skipped_reason is None and self.degraded is None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Monitor:
    """Runs detection passes against a decrypted :class:`StoreState`."""

    def __init__(self, rpc: BitcoinRpc) -> None:
        self._rpc = rpc

    def run_pass(self, state: StoreState) -> PassResult:
        """Check every still-present output once. Mutates ``state`` in place.

        The caller is responsible for persisting ``state`` afterwards and for
        dispatching any returned events.
        """
        result = PassResult()

        # -- Rule 2/3: establish that the node is reachable and synced ---------
        try:
            tip = self._rpc.chain_tip()
        except NodeUnavailable as exc:
            result.degraded = DegradedEvent(
                reason="node_unreachable",
                detail=str(exc),
                detected_at=_now(),
            )
            return result
        except NodeError as exc:
            result.degraded = DegradedEvent(
                reason="node_rpc_error", detail=str(exc), detected_at=_now()
            )
            return result

        result.block_height = tip.height

        if not tip.is_synced:
            result.skipped_reason = (
                f"node not synced (ibd={tip.initial_block_download}, "
                f"progress={tip.verification_progress:.6f}); "
                "spend evaluation suspended"
            )
            logger.warning("Skipping pass: %s", result.skipped_reason)
            state.last_block_height = tip.height
            return result

        # -- Main sweep --------------------------------------------------------
        for watch in state.watches:
            newly_missing = self._check_watch(watch, result)
            if newly_missing:
                result.spend_events.append(
                    SpendEvent(
                        watch_id=watch.watch_id,
                        watch_label=watch.label,
                        missing=newly_missing,
                        total_outputs=watch.total_outputs,
                        block_height=tip.height,
                        detected_at=_now(),
                    )
                )

        state.last_check_at = _now()
        state.last_block_height = tip.height
        return result

    def _check_watch(self, watch: Watch, result: PassResult) -> list[WatchedOutput]:
        """Check one watch, returning outputs that went missing during this pass."""
        newly_missing: list[WatchedOutput] = []

        for output in watch.outputs:
            # Rule 1: already-flagged outputs are not re-checked. Their state is
            # sticky until the operator acknowledges, so re-querying could only
            # produce a spurious all-clear after a reorg.
            if not output.present:
                continue

            try:
                utxo = self._rpc.get_txout(output.txid, output.vout)
            except NodeUnavailable as exc:
                # Rule 3: abandon the pass rather than misattribute a transport
                # failure to a spend.
                result.degraded = DegradedEvent(
                    reason="node_unreachable_midpass",
                    detail=f"{exc} (watch={watch.watch_id})",
                    detected_at=_now(),
                )
                return newly_missing
            except NodeError as exc:
                logger.error("RPC error checking %s: %s", output.outpoint, exc)
                continue

            result.checked += 1

            if utxo is None:
                output.present = False
                output.first_missing_at = _now()
                newly_missing.append(output)
                result.newly_missing += 1
                logger.critical(
                    "SPEND DETECTED watch=%s outpoint=%s",
                    watch.watch_id,
                    output.outpoint,
                )

        return newly_missing


def heartbeat_due(
    state: StoreState, interval_seconds: int, now: datetime | None = None
) -> bool:
    """Whether a positive heartbeat should be emitted.

    Measured against ``last_heartbeat_at``, never ``last_check_at``: a
    monitoring pass runs far more often than a heartbeat, so using the pass
    timestamp would keep resetting the clock and the heartbeat would silently
    never fire again -- the exact failure direction this project forbids.

    A heartbeat is always due when none has been sent, so a freshly started
    service proves liveness immediately rather than after a full interval. An
    unparseable timestamp also reads as due, for the same reason: when in
    doubt, emit.
    """
    if state.heartbeat_seq == 0 or state.last_heartbeat_at is None:
        return True
    reference = now or datetime.now(timezone.utc)
    try:
        last = datetime.fromisoformat(state.last_heartbeat_at)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (reference - last).total_seconds() >= interval_seconds
