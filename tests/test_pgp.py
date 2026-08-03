"""PGP wrapper, exercised against the real gpg binary when available."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew.notify.pgp import PgpEncryptor, PgpError

GPG = shutil.which("gpg")
needs_gpg = pytest.mark.skipif(GPG is None, reason="gpg binary not installed")

RECIPIENT = "operator@example.org"


@pytest.fixture(scope="module")
def operator_home() -> Path:
    """An 'operator machine' keyring holding the full keypair.

    Deliberately a short mkdtemp path: gpg-agent binds an AF_UNIX socket inside
    the homedir, and pytest's tmp_path exceeds the ~104-byte socket limit.
    """
    import tempfile

    home = Path(tempfile.mkdtemp(prefix="cew-gpg-", dir="/tmp"))
    home.chmod(0o700)
    batch = [GPG, "--batch", "--no-tty", "--homedir", str(home),
             "--pinentry-mode", "loopback", "--passphrase", ""]
    subprocess.run(
        [*batch, "--quick-generate-key", RECIPIENT, "ed25519", "cert", "never"],
        check=True, capture_output=True,
    )
    subprocess.run(
        [*batch, "--quick-add-key", _fingerprint(home), "cv25519", "encrypt", "never"],
        check=True, capture_output=True,
    )
    yield home
    subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                   capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


def _fingerprint(home: Path) -> str:
    out = subprocess.run(
        [GPG, "--batch", "--no-tty", "--homedir", str(home),
         "--list-keys", "--with-colons"],
        check=True, capture_output=True, text=True,
    ).stdout
    for line in out.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise AssertionError("no fingerprint found")


def _export_public(home: Path) -> str:
    return subprocess.run(
        [GPG, "--batch", "--no-tty", "--homedir", str(home), "--armor",
         "--export", RECIPIENT],
        check=True, capture_output=True, text=True,
    ).stdout


@needs_gpg
def test_import_encrypt_and_operator_decrypts(operator_home: Path) -> None:
    """Full loop: service keyring has the public key only; operator decrypts."""
    import tempfile

    # Short path again: gpg talks to its agent even for imports, over a
    # socket inside the homedir.
    service_home = Path(tempfile.mkdtemp(prefix="cew-svc-", dir="/tmp"))
    encryptor = PgpEncryptor(RECIPIENT, service_home)
    encryptor.import_public_key(_export_public(operator_home))

    armored = encryptor.encrypt("SPEND DETECTED test message")
    assert armored.startswith("-----BEGIN PGP MESSAGE-----")
    assert "SPEND DETECTED" not in armored
    assert encryptor.can_encrypt()

    # The service keyring must hold no secret key.
    listing = subprocess.run(
        [GPG, "--batch", "--no-tty", "--homedir", str(service_home),
         "--list-secret-keys"],
        capture_output=True, text=True,
    ).stdout
    assert RECIPIENT not in listing

    decrypted = subprocess.run(
        [GPG, "--batch", "--no-tty", "--homedir", str(operator_home),
         "--pinentry-mode", "loopback", "--passphrase", "", "--decrypt"],
        input=armored, check=True, capture_output=True, text=True,
    ).stdout
    assert decrypted == "SPEND DETECTED test message"

    subprocess.run(["gpgconf", "--homedir", str(service_home), "--kill", "gpg-agent"],
                   capture_output=True)
    shutil.rmtree(service_home, ignore_errors=True)


@needs_gpg
def test_unknown_recipient_fails_closed(tmp_path: Path) -> None:
    encryptor = PgpEncryptor("nobody@example.org", tmp_path / "empty-gnupg")
    with pytest.raises(PgpError):
        encryptor.encrypt("message")
    assert not encryptor.can_encrypt()


def test_missing_binary_is_reported(tmp_path: Path) -> None:
    encryptor = PgpEncryptor(RECIPIENT, tmp_path / "g", gpg_binary="/nonexistent/gpg")
    with pytest.raises(PgpError, match="not found"):
        encryptor.encrypt("message")


def test_empty_recipient_rejected(tmp_path: Path) -> None:
    with pytest.raises(PgpError):
        PgpEncryptor("", tmp_path / "g")
