"""PGP encryption of alert bodies, via the system ``gpg`` binary.

canaryEW holds only the operator's **public** key, in a service-owned keyring
(``--homedir``) that is separate from any user keyring on the host. There is no
secret material in this channel at all: compromise of the keyring yields the
ability to encrypt *to* the operator, nothing else.

Shelling out to ``gpg`` is deliberate. A Python OpenPGP implementation would be
a large security-critical dependency; gpg is already on the node, audited, and
the interaction surface here is two subcommands with fixed arguments.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Final

_GPG_TIMEOUT: Final[float] = 30.0


class PgpError(RuntimeError):
    """Raised when key import or encryption fails."""


class PgpEncryptor:
    """Encrypt-to-operator using a dedicated gpg home directory."""

    def __init__(
        self,
        recipient: str,
        gnupg_home: str | Path,
        *,
        gpg_binary: str = "gpg",
    ) -> None:
        if not recipient:
            raise PgpError("PGP recipient (key id, fingerprint, or email) is required.")
        self._recipient = recipient
        self._home = Path(gnupg_home)
        self._binary = gpg_binary

    def _run(self, args: list[str], stdin: bytes) -> bytes:
        self._home.mkdir(parents=True, exist_ok=True)
        self._home.chmod(0o700)
        command = [
            self._binary,
            "--batch",
            "--no-tty",
            "--homedir",
            str(self._home),
            *args,
        ]
        try:
            completed = subprocess.run(
                command,
                input=stdin,
                capture_output=True,
                timeout=_GPG_TIMEOUT,
                check=False,
            )
        except FileNotFoundError as exc:
            raise PgpError(f"gpg binary not found: {self._binary!r}") from exc
        except subprocess.TimeoutExpired as exc:
            raise PgpError(f"gpg timed out after {_GPG_TIMEOUT}s") from exc

        if completed.returncode != 0:
            # gpg stderr is operational (key ids, trust), never message content,
            # so it is safe to surface in the error for diagnosis.
            detail = completed.stderr.decode("utf-8", "replace").strip()
            raise PgpError(f"gpg exited {completed.returncode}: {detail}")
        return completed.stdout

    def import_public_key(self, armored_key: str) -> None:
        """Import the operator's public key into the service keyring."""
        self._run(["--import"], armored_key.encode("utf-8"))

    def encrypt(self, plaintext: str) -> str:
        """Return ASCII-armored ciphertext for the configured recipient.

        ``--trust-model always`` because the operator imported this key
        deliberately at setup; there is no web of trust to consult on a
        single-recipient service keyring.
        """
        armored = self._run(
            [
                "--trust-model",
                "always",
                "--armor",
                "--encrypt",
                "--recipient",
                self._recipient,
            ],
            plaintext.encode("utf-8"),
        )
        return armored.decode("ascii")

    def can_encrypt(self) -> bool:
        """Whether a usable key for the recipient exists. For the status surface."""
        try:
            self.encrypt("canaryew keyring probe")
            return True
        except PgpError:
            return False
