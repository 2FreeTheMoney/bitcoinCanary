"""Locked/unlocked lifecycle and the boot-notice state.

The store is sealed under a passphrase that exists nowhere on disk (DESIGN S6),
so after any restart the service starts LOCKED: it cannot read its watch list,
cannot heartbeat, cannot monitor. That gap must announce itself -- silence
would be indistinguishable from suppression -- so the service:

1. increments a boot counter kept in a small plaintext file (nothing secret
   in it: a count and a timestamp), and
2. emits an *unauthenticated* LOCKED notice over the webhook channel, whose
   secret deliberately lives outside the sealed store.

The notice is arithmetically incapable of reassuring anyone: it carries no
verification phrase and no MAC, and says so in its own body. An attacker who
tampers with the boot file or replays the notice can generate annoyance, not
a false all-clear.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from canaryew import secrets
from canaryew.store import StateStore, StoreState


class LockedError(RuntimeError):
    """Raised when key-dependent work is attempted before unlock."""


@dataclass(frozen=True)
class BootInfo:
    boot_count: int
    locked_since: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class UnlockManager:
    """Holds the derived keys and decrypted state once the operator unlocks.

    Thread-safe: the control socket handler and the monitor loop touch this
    from different threads.
    """

    def __init__(self, store: StateStore, boot_state_path: str | Path) -> None:
        self._store = store
        self._boot_path = Path(boot_state_path)
        self._mutex = threading.Lock()
        self._keys: secrets.KeyMaterial | None = None
        self._state: StoreState | None = None

    # ---------------------------------------------------------------- state --

    @property
    def locked(self) -> bool:
        with self._mutex:
            return self._keys is None

    @property
    def keys(self) -> secrets.KeyMaterial:
        with self._mutex:
            if self._keys is None:
                raise LockedError("Service is LOCKED; unlock with the passphrase first.")
            return self._keys

    @property
    def state(self) -> StoreState:
        with self._mutex:
            if self._state is None:
                raise LockedError("Service is LOCKED; unlock with the passphrase first.")
            return self._state

    # ----------------------------------------------------------------- boot --

    def record_boot(self) -> BootInfo:
        """Increment the boot counter. Called once, at service start."""
        count = 0
        if self._boot_path.exists():
            try:
                count = int(
                    json.loads(self._boot_path.read_text(encoding="utf-8")).get(
                        "boot_count", 0
                    )
                )
            except (ValueError, json.JSONDecodeError, OSError):
                # A corrupt boot file must not stop startup; the counter resets
                # and the operator sees an anomalous count, which is itself
                # information.
                count = 0

        info = BootInfo(boot_count=count + 1, locked_since=_now())
        self._boot_path.parent.mkdir(parents=True, exist_ok=True)
        self._boot_path.write_text(
            json.dumps({"boot_count": info.boot_count, "locked_since": info.locked_since}),
            encoding="utf-8",
        )
        os.chmod(self._boot_path, 0o600)
        return info

    # --------------------------------------------------------------- unlock --

    def unlock(self, passphrase: str) -> secrets.KeyMaterial:
        """Derive keys, decrypt the store, transition to unlocked.

        A wrong passphrase raises :class:`canaryew.secrets.SecretsError` and
        leaves the manager LOCKED. Argon2id makes each attempt cost ~256 MiB
        and a fraction of a second, which is the intended brake on guessing.
        """
        keys, state = self._store.unlock(passphrase)
        with self._mutex:
            self._keys = keys
            self._state = state
        return keys

    def save(self) -> None:
        """Persist the current state under the held keys."""
        with self._mutex:
            if self._keys is None or self._state is None:
                raise LockedError("Cannot save while LOCKED.")
            self._store.save(self._keys, self._state)
