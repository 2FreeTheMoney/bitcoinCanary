"""Encrypted state store.

Layout on disk is a plaintext header plus a sealed body:

    {"version": 1, "kdf": {...}, "salt": "<b64>", "body": "<b64 sealed>"}

The header must be readable before unlocking (it carries the KDF salt), so it
holds nothing sensitive. Everything of consequence -- outpoints, labels, SMTP
credentials, the heartbeat counter -- lives in the sealed body.

What is deliberately absent: xpubs and descriptors. See ``docs/DESIGN.md`` S1.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from canaryew import secrets

STORE_VERSION: Final[int] = 1
_AAD: Final[bytes] = b"canaryew/v1/store"


class StoreError(RuntimeError):
    """Raised when the state store cannot be read, written, or decrypted."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class WatchedOutput:
    """One monitored outpoint.

    Carries no address and no derivation path -- an attacker who reads the
    decrypted store learns which coins existed at enrollment, not how to derive
    anything else.
    """

    txid: str
    vout: int
    value_sat: int
    present: bool = True
    """False once the output has left the UTXO set."""
    first_missing_at: str | None = None
    acknowledged: bool = False
    """Operator confirmed this spend was authorized."""

    @property
    def outpoint(self) -> str:
        return f"{self.txid}:{self.vout}"


@dataclass
class Watch:
    """A named group of outputs enrolled together, typically one wallet."""

    watch_id: str
    label: str
    created_at: str = field(default_factory=_now)
    outputs: list[WatchedOutput] = field(default_factory=list)
    source: str = "offline"
    """How it was enrolled: 'offline' (xpub never on host) or 'onhost'."""

    @property
    def total_outputs(self) -> int:
        return len(self.outputs)

    @property
    def missing_outputs(self) -> list[WatchedOutput]:
        return [o for o in self.outputs if not o.present]

    @property
    def unacknowledged_missing(self) -> list[WatchedOutput]:
        return [o for o in self.outputs if not o.present and not o.acknowledged]


@dataclass
class StoreState:
    """Full decrypted state."""

    watches: list[Watch] = field(default_factory=list)
    heartbeat_seq: int = 0
    last_heartbeat_at: str | None = None
    """When the last positive heartbeat was emitted. Distinct from
    ``last_check_at``: a monitoring pass runs far more often than a heartbeat,
    and conflating the two makes ``heartbeat_due`` never fire again."""
    last_check_at: str | None = None
    last_block_height: int | None = None
    smtp_password: str | None = None
    """Sensitive: lets an attacker send mail as the operator.

    The brrr webhook secret deliberately does NOT live here: the LOCKED boot
    notice must be deliverable before the store is unlocked, so that secret
    lives in the plaintext (0600) environment config -- see docs/DESIGN.md S6.
    """

    def watch(self, watch_id: str) -> Watch | None:
        return next((w for w in self.watches if w.watch_id == watch_id), None)

    @property
    def total_outputs(self) -> int:
        return sum(w.total_outputs for w in self.watches)

    @property
    def has_unacknowledged_alerts(self) -> bool:
        return any(w.unacknowledged_missing for w in self.watches)

    def digest(self) -> str:
        """Stable digest of monitored state, bound into heartbeat MACs.

        Covers watch composition and per-output presence so a heartbeat cannot be
        replayed across a state change. Excludes timestamps and credentials.
        """
        material = [
            [w.watch_id, [[o.txid, o.vout, o.present] for o in w.outputs]]
            for w in sorted(self.watches, key=lambda w: w.watch_id)
        ]
        payload = json.dumps(material, separators=(",", ":"), sort_keys=True)
        from hashlib import sha256

        return sha256(payload.encode()).hexdigest()[:16]


def _to_state(raw: dict[str, Any]) -> StoreState:
    watches = [
        Watch(
            watch_id=w["watch_id"],
            label=w["label"],
            created_at=w.get("created_at", _now()),
            source=w.get("source", "offline"),
            outputs=[WatchedOutput(**o) for o in w.get("outputs", [])],
        )
        for w in raw.get("watches", [])
    ]
    return StoreState(
        watches=watches,
        heartbeat_seq=int(raw.get("heartbeat_seq", 0)),
        last_heartbeat_at=raw.get("last_heartbeat_at"),
        last_check_at=raw.get("last_check_at"),
        last_block_height=raw.get("last_block_height"),
        smtp_password=raw.get("smtp_password"),
    )


class StateStore:
    """Sealed, atomically-written state file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    # ------------------------------------------------------------ lifecycle --

    def exists(self) -> bool:
        return self.path.exists()

    def read_salt(self) -> bytes:
        """Read the KDF salt from the plaintext header (pre-unlock)."""
        try:
            header = json.loads(self.path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise StoreError(f"Unable to read state store {self.path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise StoreError(f"State store {self.path} is not valid JSON: {exc}") from exc

        if header.get("version") != STORE_VERSION:
            raise StoreError(
                f"Unsupported store version {header.get('version')}, expected {STORE_VERSION}."
            )
        return base64.b64decode(header["salt"])

    def initialize(self, passphrase: str) -> tuple[secrets.KeyMaterial, StoreState]:
        """Create a brand-new sealed store. Refuses to clobber an existing one."""
        if self.exists():
            raise StoreError(
                f"State store already exists at {self.path}. "
                "Refusing to overwrite -- move it aside deliberately if that is intended."
            )
        salt = secrets.new_salt()
        keys = secrets.unlock(passphrase, salt)
        state = StoreState()
        self._write(salt, keys, state)
        return keys, state

    def unlock(self, passphrase: str) -> tuple[secrets.KeyMaterial, StoreState]:
        """Derive keys from the passphrase and decrypt the store."""
        salt = self.read_salt()
        keys = secrets.unlock(passphrase, salt)
        return keys, self.load(keys)

    # ------------------------------------------------------------------- io --

    def load(self, keys: secrets.KeyMaterial) -> StoreState:
        """Decrypt and parse the sealed body."""
        header = json.loads(self.path.read_text(encoding="utf-8"))
        sealed = base64.b64decode(header["body"])
        plaintext = secrets.unseal(keys.state_key, sealed, _AAD)
        return _to_state(json.loads(plaintext.decode("utf-8")))

    def save(self, keys: secrets.KeyMaterial, state: StoreState) -> None:
        """Re-seal and atomically replace the store."""
        self._write(self.read_salt(), keys, state)

    def _write(
        self, salt: bytes, keys: secrets.KeyMaterial, state: StoreState
    ) -> None:
        body = json.dumps(asdict(state), separators=(",", ":")).encode("utf-8")
        sealed = secrets.seal(keys.state_key, body, _AAD)
        header = {
            "version": STORE_VERSION,
            "kdf": {
                "algorithm": "argon2id",
                "memory_kib": secrets.ARGON2_MEMORY_KIB,
                "time_cost": secrets.ARGON2_TIME_COST,
                "parallelism": secrets.ARGON2_PARALLELISM,
            },
            "salt": base64.b64encode(salt).decode("ascii"),
            "body": base64.b64encode(sealed).decode("ascii"),
        }

        # Atomic replace: a crash mid-write must never leave a truncated store,
        # because an unreadable store means the monitor stops and the operator's
        # dead-man rule fires on a false pretext.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_path = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".canaryew-", suffix=".tmp"
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(header, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self.path)
        except Exception:
            Path(temp_path).unlink(missing_ok=True)
            raise
