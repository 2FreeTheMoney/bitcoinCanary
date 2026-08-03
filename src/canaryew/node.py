"""Minimal, read-only Bitcoin Core JSON-RPC client with cookie-file auth.

Deliberately stdlib-only. canaryEW is a security tool whose value depends on a
small, auditable dependency surface; a JSON-RPC POST with HTTP basic auth does
not justify pulling in an HTTP stack.

The RPC surface is intentionally tiny and read-only. This client cannot create
wallets, import descriptors persistently, sign, or spend.
"""

from __future__ import annotations

import base64
import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

DEFAULT_TIMEOUT: Final[float] = 20.0
DEFAULT_RETRIES: Final[int] = 3
BACKOFF_BASE: Final[float] = 1.5


class NodeError(RuntimeError):
    """Raised when the node is unreachable or returns an RPC error."""


class NodeUnavailable(NodeError):
    """Transport-level failure: node down, refused, or timed out.

    Distinguished from :class:`NodeError` because the monitor must treat
    "cannot reach the node" as a degraded condition rather than as evidence
    about the state of any output.
    """


@dataclass(frozen=True)
class ChainTip:
    """Current chain state, used to gate alerting on sync status."""

    height: int
    best_hash: str
    initial_block_download: bool
    verification_progress: float

    @property
    def is_synced(self) -> bool:
        return not self.initial_block_download and self.verification_progress > 0.9999


@dataclass(frozen=True)
class Utxo:
    """One unspent output as reported by ``gettxout``."""

    txid: str
    vout: int
    value_sat: int
    confirmations: int
    script_pubkey: str


class BitcoinRpc:
    """Read-only JSON-RPC client for a local bitcoind."""

    def __init__(
        self,
        url: str,
        *,
        cookie_file: str | Path | None = None,
        rpc_user: str | None = None,
        rpc_password: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> None:
        self._url = url.rstrip("/")
        self._cookie_file = Path(cookie_file) if cookie_file else None
        self._rpc_user = rpc_user
        self._rpc_password = rpc_password
        self._timeout = timeout
        self._retries = max(1, retries)
        self._request_id = 0

        if not self._cookie_file and not (rpc_user and rpc_password):
            raise NodeError(
                "Configure either bitcoin_rpc_cookie_file or rpc_user/rpc_password."
            )

    # ----------------------------------------------------------------- auth --

    def _auth_header(self) -> str:
        """Build the basic-auth header, re-reading the cookie on every call.

        bitcoind regenerates ``.cookie`` on each restart, so caching the value
        across a node restart produces confusing 401s that look like
        misconfiguration. Re-reading is cheap and avoids that failure mode.
        """
        if self._cookie_file:
            try:
                raw = self._cookie_file.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise NodeError(
                    f"Unable to read RPC cookie file {self._cookie_file}: {exc}"
                ) from exc
            user, sep, password = raw.partition(":")
            if not sep:
                raise NodeError(f"Malformed RPC cookie file: {self._cookie_file}")
        else:
            user, password = self._rpc_user or "", self._rpc_password or ""

        token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        return f"Basic {token}"

    # ------------------------------------------------------------------ rpc --

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        """Invoke one JSON-RPC method with bounded retries and backoff."""
        self._request_id += 1
        payload = json.dumps(
            {
                "jsonrpc": "1.0",
                "id": f"canaryew-{self._request_id}",
                "method": method,
                "params": params or [],
            }
        ).encode("utf-8")

        last_error: Exception | None = None
        for attempt in range(self._retries):
            request = urllib.request.Request(
                self._url,
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": self._auth_header(),
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as response:
                    body = json.loads(response.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                # bitcoind returns RPC errors with a non-2xx status and a JSON body.
                try:
                    body = json.loads(exc.read().decode("utf-8"))
                    break
                except Exception:
                    last_error = exc
            except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
                last_error = exc

            if attempt < self._retries - 1:
                time.sleep(BACKOFF_BASE**attempt)
        else:
            raise NodeUnavailable(
                f"Bitcoin Core unreachable at {self._url} after "
                f"{self._retries} attempts: {last_error}"
            ) from last_error

        if body.get("error"):
            error = body["error"]
            raise NodeError(
                f"RPC {method} failed: {error.get('message', error)} "
                f"(code {error.get('code')})"
            )
        return body.get("result")

    # -------------------------------------------------------------- queries --

    def chain_tip(self) -> ChainTip:
        """Fetch current chain state."""
        info = self.call("getblockchaininfo")
        return ChainTip(
            height=int(info["blocks"]),
            best_hash=str(info["bestblockhash"]),
            initial_block_download=bool(info.get("initialblockdownload", False)),
            verification_progress=float(info.get("verificationprogress", 0.0)),
        )

    def get_txout(self, txid: str, vout: int, *, include_mempool: bool = True) -> Utxo | None:
        """Return the UTXO, or ``None`` if it is spent or never existed.

        This is the core primitive of canaryEW's steady state. It takes only an
        outpoint -- no xpub, no descriptor, no address -- which is precisely why
        the monitor can run without ever holding key material.

        ``include_mempool=True`` means an unconfirmed spend is detected as soon
        as it is relayed, buying the operator time before confirmation.
        """
        result = self.call("gettxout", [txid, vout, include_mempool])
        if result is None:
            return None
        return Utxo(
            txid=txid,
            vout=vout,
            value_sat=int(round(float(result["value"]) * 100_000_000)),
            confirmations=int(result.get("confirmations", 0)),
            script_pubkey=str(result.get("scriptPubKey", {}).get("hex", "")),
        )

    def scan_txout_set(self, descriptors: list[str]) -> list[Utxo]:
        """Discover UTXOs for descriptors. **Enrollment only.**

        This is the one call that touches key-bearing material. It is invoked by
        the short-lived enrollment process, never by the long-running monitor.
        The descriptors are passed as arguments and never persisted.

        Note this is a full UTXO-set scan and takes appreciable time on a node.
        """
        result = self.call("scantxoutset", ["start", descriptors])
        if not result or not result.get("success"):
            raise NodeError("scantxoutset did not complete successfully.")

        found: list[Utxo] = []
        for entry in result.get("unspents", []):
            found.append(
                Utxo(
                    txid=str(entry["txid"]),
                    vout=int(entry["vout"]),
                    value_sat=int(round(float(entry["amount"]) * 100_000_000)),
                    confirmations=int(entry.get("height", 0) and 1),
                    script_pubkey=str(entry.get("scriptPubKey", "")),
                )
            )
        return found

    def descriptor_info(self, descriptor: str) -> dict[str, Any]:
        """Validate/normalize a descriptor and obtain its checksum. Enrollment only."""
        return dict(self.call("getdescriptorinfo", [descriptor]))

    def ping(self) -> bool:
        """Cheap liveness probe used by the status endpoint."""
        try:
            self.call("uptime")
            return True
        except NodeError:
            return False
