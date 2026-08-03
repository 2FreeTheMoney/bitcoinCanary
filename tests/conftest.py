"""Shared test doubles."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew.node import ChainTip, NodeUnavailable, Utxo
from canaryew.notify.base import Notification


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


class RecordingChannel:
    """Collects notifications instead of delivering them."""

    def __init__(self, name: str = "recorder", max_redaction=None) -> None:
        self.name = name
        self.notifications: list[Notification] = []
        if max_redaction is not None:
            self.max_redaction = max_redaction

    def send(self, notification: Notification) -> None:
        self.notifications.append(notification)

    def healthy(self) -> bool:
        return True
