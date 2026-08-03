"""Offline enrollment: Sparrow UTXO export -> sealed watchfile.

This is the strongest enrollment path. The operator exports their UTXO set from
Sparrow on a trusted machine; canaryEW converts it into a sealed watchfile
carrying **only outpoints**, which is then copied to the node.

The xpub, the descriptor, and every address are absent from the artifact. The
node therefore never possesses the material to derive anything, even
transiently. Compare ``docs/DESIGN.md`` S2a.

Parsing is deliberately tolerant of Sparrow's export shape rather than pinned to
one column layout: an enrollment that fails because a vendor renamed a CSV header
is an enrollment the operator postpones, and postponed enrollment means no
monitoring at all.
"""

from __future__ import annotations

import base64
import csv
import hmac
import io
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from canaryew import secrets
from canaryew.store import Watch, WatchedOutput

WATCHFILE_VERSION: Final[int] = 1
_AAD: Final[bytes] = b"canaryew/v1/watchfile"

_OUTPOINT_RE: Final[re.Pattern[str]] = re.compile(r"^([0-9a-fA-F]{64}):(\d{1,5})$")
_VALUE_HINTS: Final[tuple[str, ...]] = ("value", "amount", "sats", "satoshis", "btc")
_LABEL_HINTS: Final[tuple[str, ...]] = ("label", "note", "description", "memo")


class EnrollmentError(RuntimeError):
    """Raised when a UTXO export cannot be parsed or a watchfile is invalid."""


def looks_like_bip329(text: str) -> bool:
    """Cheap sniff for a BIP-329 label export, so the CLI can warn about its
    caveats (partial coverage, possibly-spent outputs, xpub in the file)."""
    stripped = text.strip()
    if not stripped or stripped[0] != "{":
        return False
    return '"type"' in stripped.splitlines()[0]


@dataclass(frozen=True)
class ParsedUtxo:
    """One outpoint recovered from an export."""

    txid: str
    vout: int
    value_sat: int
    label: str | None = None

    @property
    def outpoint(self) -> str:
        return f"{self.txid}:{self.vout}"


def _to_sats(raw: str) -> int:
    """Interpret a value cell as satoshis.

    Sparrow exports BTC with a decimal point; other tools export integer sats.
    A decimal point is the discriminator -- an integer with no separator is
    taken as sats, which is the safer reading because treating sats as BTC would
    inflate values by 1e8 and corrupt the value buckets in alerts.
    """
    cleaned = raw.strip().replace(",", "").replace("BTC", "").replace("sats", "").strip()
    if not cleaned:
        return 0
    try:
        if "." in cleaned:
            return int(round(float(cleaned) * 100_000_000))
        return int(cleaned)
    except ValueError:
        return 0


def _find_outpoint(values: list[str]) -> tuple[str, int] | None:
    for cell in values:
        match = _OUTPOINT_RE.match(cell.strip())
        if match:
            return match.group(1).lower(), int(match.group(2))
    return None


def parse_utxo_export(text: str) -> list[ParsedUtxo]:
    """Parse a Sparrow CSV/JSON export, a BIP-329 label export (JSONL), or a
    bare list of outpoints.

    Detection is by content, not by header name: any cell matching
    ``<64 hex>:<int>`` is treated as the outpoint.
    """
    stripped = text.strip()
    if not stripped:
        raise EnrollmentError("Export is empty.")

    if stripped[0] in "[{":
        return _parse_json(stripped)

    parsed = _parse_csv(stripped)
    if parsed:
        return parsed
    return _parse_plain(stripped)


def _parse_bip329(lines: list[dict[str, Any]]) -> list[ParsedUtxo]:
    """Extract outpoints from a BIP-329 label export.

    Only ``type: "output"`` records carry an outpoint (``ref`` = txid:vout).
    Everything else in the file -- ``tx`` (txid only), ``addr`` (address),
    ``xpub`` (the one artifact this project exists to never handle) -- cannot
    identify a UTXO and is deliberately ignored.

    Caveats live with the caller/docs rather than code: labels exist only for
    outputs the operator labeled, and they persist after spending, so a
    BIP-329-derived watch can under-cover the wallet or contain already-spent
    outputs (which alert on the first pass). The UTXO CSV export is the
    preferred artifact; this path exists because a labels file may be what the
    operator has in hand.
    """
    found: list[ParsedUtxo] = []
    saw_labels_file = False
    for row in lines:
        row_type = str(row.get("type", "")).lower()
        if row_type in ("tx", "addr", "xpub", "pubkey", "input", "wallet"):
            saw_labels_file = True
        if row_type != "output":
            continue
        match = _OUTPOINT_RE.match(str(row.get("ref", "")).strip())
        if not match:
            continue
        value = _to_sats(str(row.get("value", "")))
        label = str(row["label"]) if row.get("label") else None
        found.append(ParsedUtxo(match.group(1).lower(), int(match.group(2)), value, label))

    if not found and saw_labels_file:
        raise EnrollmentError(
            "This looks like a BIP-329 label export, but it contains no "
            "'output' records -- tx/addr/xpub labels cannot identify UTXOs. "
            "Either label your coins in Sparrow's UTXOs tab and re-export, or "
            "(preferred) use the UTXOs tab CSV export directly."
        )
    if not found:
        raise EnrollmentError("No outpoints found in JSON export.")
    return found


def _parse_json(text: str) -> list[ParsedUtxo]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Not one JSON document; try line-delimited JSON (BIP-329 exports).
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EnrollmentError(
                    f"Export is neither valid JSON nor JSON-lines: {exc}"
                ) from exc
            if isinstance(row, dict):
                rows.append(row)
        return _parse_bip329(rows)

    if isinstance(data, dict) and "type" in data:
        return _parse_bip329([data])  # a one-line BIP-329 file parses as one object

    rows = data if isinstance(data, list) else data.get("utxos", data.get("outputs", []))
    if not isinstance(rows, list):
        raise EnrollmentError("JSON export does not contain a list of outputs.")

    found: list[ParsedUtxo] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        txid, vout = None, None
        if "txid" in row and ("vout" in row or "index" in row):
            txid = str(row["txid"]).lower()
            vout = int(row["vout"] if "vout" in row else row["index"])
        else:
            hit = _find_outpoint([str(v) for v in row.values()])
            if hit:
                txid, vout = hit
        if txid is None or vout is None:
            continue

        value = 0
        for key, raw in row.items():
            if any(hint in key.lower() for hint in _VALUE_HINTS):
                value = _to_sats(str(raw))
                break
        label = next(
            (
                str(raw)
                for key, raw in row.items()
                if any(hint in key.lower() for hint in _LABEL_HINTS) and raw
            ),
            None,
        )
        found.append(ParsedUtxo(txid, vout, value, label))

    if not found:
        raise EnrollmentError("No outpoints found in JSON export.")
    return found


def _parse_csv(text: str) -> list[ParsedUtxo]:
    reader = csv.reader(io.StringIO(text))
    rows = [row for row in reader if row]
    if not rows:
        return []

    header = [cell.strip().lower() for cell in rows[0]]
    has_header = _find_outpoint(rows[0]) is None
    value_col = next(
        (i for i, h in enumerate(header) if any(x in h for x in _VALUE_HINTS)), None
    ) if has_header else None
    label_col = next(
        (i for i, h in enumerate(header) if any(x in h for x in _LABEL_HINTS)), None
    ) if has_header else None

    found: list[ParsedUtxo] = []
    for row in rows[1:] if has_header else rows:
        hit = _find_outpoint(row)
        if not hit:
            continue
        txid, vout = hit
        value = _to_sats(row[value_col]) if value_col is not None and value_col < len(row) else 0
        label = (
            row[label_col].strip()
            if label_col is not None and label_col < len(row) and row[label_col].strip()
            else None
        )
        found.append(ParsedUtxo(txid, vout, value, label))
    return found


def _parse_plain(text: str) -> list[ParsedUtxo]:
    found: list[ParsedUtxo] = []
    for line in text.splitlines():
        match = _OUTPOINT_RE.match(line.strip())
        if match:
            found.append(ParsedUtxo(match.group(1).lower(), int(match.group(2)), 0))
    if not found:
        raise EnrollmentError(
            "No outpoints found. Expected Sparrow CSV/JSON, or one "
            "'<txid>:<vout>' per line."
        )
    return found


def build_watch(utxos: list[ParsedUtxo], label: str, watch_id: str | None = None) -> Watch:
    """Turn parsed outpoints into a :class:`Watch`, rejecting duplicates."""
    if not utxos:
        raise EnrollmentError("Refusing to create a watch with no outputs.")

    seen: set[str] = set()
    outputs: list[WatchedOutput] = []
    for utxo in utxos:
        if utxo.outpoint in seen:
            continue
        seen.add(utxo.outpoint)
        outputs.append(
            WatchedOutput(txid=utxo.txid, vout=utxo.vout, value_sat=utxo.value_sat)
        )

    return Watch(
        watch_id=watch_id or f"w-{uuid.uuid4().hex[:8]}",
        label=label,
        outputs=outputs,
        source="offline",
    )


# --------------------------------------------------------------------------- #
# Import-time verification against the node
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of checking a candidate watch against the live UTXO set."""

    unspent: list[WatchedOutput]
    already_spent: list[WatchedOutput]
    block_height: int

    @property
    def unspent_value_sat(self) -> int:
        return sum(o.value_sat for o in self.unspent)


def verify_against_node(rpc: Any, watch: Watch) -> VerificationResult:
    """Partition a candidate watch into still-unspent and already-spent.

    Run at import time, *before* anything is watched. Exports routinely
    include outputs that are already gone -- BIP-329 label exports keep spent
    outputs, and even a UTXO CSV goes stale between export and import. Those
    are wallet history, not theft, and enrolling them would fire a false
    SPEND alert on the first monitoring pass.

    This is deliberately not the monitor's job: once an output is under
    watch, "it moved, but probably legitimately" is the auto-clear reasoning
    the design forbids (AGENTS.md invariant 3). Pruning is only safe here
    because these outputs have never been watched.

    Requires a synced node -- a lagging node reports recent outputs as absent
    for reasons that have nothing to do with spending (monitor rule 2 applies
    at import too). Raises :class:`EnrollmentError` if unsynced; node
    transport errors propagate as-is.
    """
    tip = rpc.chain_tip()
    if not tip.is_synced:
        raise EnrollmentError(
            f"Node is not synced (progress={tip.verification_progress:.4f}); "
            "cannot verify outputs. Retry when synced, or import with "
            "--no-verify and expect alerts for any already-spent outputs."
        )

    unspent: list[WatchedOutput] = []
    already_spent: list[WatchedOutput] = []
    for output in watch.outputs:
        if rpc.get_txout(output.txid, output.vout) is None:
            already_spent.append(output)
        else:
            unspent.append(output)
    return VerificationResult(
        unspent=unspent, already_spent=already_spent, block_height=tip.height
    )


# --------------------------------------------------------------------------- #
# Portable sealed watchfile
# --------------------------------------------------------------------------- #


def write_watchfile(path: str | Path, watch: Watch, passphrase: str) -> str:
    """Seal a watch into a transferable file.

    Encrypted with the operator passphrase so the artifact is safe to move over
    scp, a USB stick, or a LAN share. It contains outpoints and a label -- never
    an xpub, descriptor, or address.

    Returns the content fingerprint for out-of-band verification after transfer.
    """
    salt = secrets.new_salt()
    keys = secrets.unlock(passphrase, salt)

    body = json.dumps(
        {
            "watch_id": watch.watch_id,
            "label": watch.label,
            "created_at": watch.created_at,
            "source": "offline",
            "outputs": [
                {"txid": o.txid, "vout": o.vout, "value_sat": o.value_sat}
                for o in watch.outputs
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")

    sealed = secrets.seal(keys.state_key, body, _AAD)
    fingerprint = secrets.mac(keys.hmac_key, body)[:16]

    payload = {
        "version": WATCHFILE_VERSION,
        "salt": base64.b64encode(salt).decode("ascii"),
        "body": base64.b64encode(sealed).decode("ascii"),
        "fingerprint": fingerprint,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        target.chmod(0o600)
    except OSError as exc:
        # A relative --out resolves against the invoking cwd, which the
        # service user often cannot even stat (e.g. sudo -u canaryew from an
        # operator home directory). Fail with direction, not a traceback.
        raise EnrollmentError(
            f"Unable to write watchfile {target}: {exc}. "
            "Use an absolute output path in a directory writable by the "
            "current user (e.g. /tmp or the canaryEW home)."
        ) from exc
    return fingerprint


def read_watchfile(path: str | Path, passphrase: str) -> tuple[Watch, str]:
    """Open a sealed watchfile. Returns ``(watch, fingerprint)``.

    The fingerprint lets the operator confirm on the node that the file which
    arrived is the file that left, without revealing its contents.
    """
    try:
        payload: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise EnrollmentError(f"Unable to read watchfile {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise EnrollmentError(f"Watchfile {path} is not valid JSON: {exc}") from exc

    if payload.get("version") != WATCHFILE_VERSION:
        raise EnrollmentError(
            f"Unsupported watchfile version {payload.get('version')}."
        )

    keys = secrets.unlock(passphrase, base64.b64decode(payload["salt"]))
    body = secrets.unseal(keys.state_key, base64.b64decode(payload["body"]), _AAD)

    computed = secrets.mac(keys.hmac_key, body)[:16]
    declared = payload.get("fingerprint")
    if declared and not hmac.compare_digest(computed, declared):
        raise EnrollmentError(
            "Watchfile fingerprint mismatch: contents do not match the declared "
            "fingerprint. Do not import this file."
        )

    data = json.loads(body.decode("utf-8"))
    watch = Watch(
        watch_id=data["watch_id"],
        label=data["label"],
        created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        source="offline",
        outputs=[WatchedOutput(**o) for o in data["outputs"]],
    )
    return watch, computed
