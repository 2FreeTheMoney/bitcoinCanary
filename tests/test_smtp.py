"""SMTP channel: validation, transports, injection guards, error classes."""

from __future__ import annotations

import smtplib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew.config import SmtpSettings
from canaryew.monitor import Severity
from canaryew.notify.base import DeliveryError, Notification
from canaryew.notify.smtp import SmtpChannel, validate_settings


def notification(title: str = "canaryEW ALERT - vault") -> Notification:
    return Notification(title=title, body="body text", severity=Severity.CRITICAL)


def smtp_settings(**overrides) -> SmtpSettings:
    base = dict(
        mode="smtp",
        host="mail.example.org",
        port=587,
        username="canary",
        from_addr="canary@example.org",
        to_addrs=("op@example.org",),
    )
    base.update(overrides)
    return SmtpSettings(**base)


# ------------------------------------------------------------- validation --- #

def test_valid_config_enables() -> None:
    assert validate_settings(smtp_settings(), "pw") is None


@pytest.mark.parametrize(
    ("settings", "password", "reason_fragment"),
    [
        (smtp_settings(mode="teleport"), "pw", "unknown SMTP mode"),
        (SmtpSettings(mode="disabled"), None, "disabled by configuration"),
        (smtp_settings(host=""), "pw", "SMTP_HOST"),
        (smtp_settings(from_addr=""), "pw", "SMTP_FROM"),
        (smtp_settings(to_addrs=()), "pw", "SMTP_TO"),
        (smtp_settings(), None, "no password"),
        (smtp_settings(username=""), "pw", "SMTP_USER is not set"),
        (smtp_settings(to_addrs=("evil\r\nBcc: x@y.z",)), "pw", "header injection"),
    ],
)
def test_misconfiguration_disables_with_reason(settings, password, reason_fragment) -> None:
    """Misconfiguration never throws; it degrades to a reported reason."""
    reason = validate_settings(settings, password)
    assert reason is not None and reason_fragment in reason

    channel = SmtpChannel(settings, password)
    assert not channel.enabled
    with pytest.raises(DeliveryError) as excinfo:
        channel.send(notification())
    assert excinfo.value.permanent  # disabled config can never heal on retry


# -------------------------------------------------------------- transports -- #

def test_file_transport_renders_full_message(tmp_path: Path) -> None:
    outbox = tmp_path / "outbox.log"
    channel = SmtpChannel(SmtpSettings(mode="file", file_path=str(outbox),
                                       from_addr="c@x.org", to_addrs=("o@x.org",)))
    channel.send(notification())
    text = outbox.read_text()
    assert "canaryEW ALERT - vault" in text
    assert "body text" in text
    assert channel.healthy()


def test_message_carries_deliverability_headers(tmp_path: Path) -> None:
    """Missing Message-ID and a '-0000' date are classic spam signals."""
    outbox = tmp_path / "outbox.log"
    channel = SmtpChannel(
        SmtpSettings(mode="file", file_path=str(outbox),
                     from_addr="canary@example.org", to_addrs=("op@example.org",))
    )
    channel.send(notification())
    text = outbox.read_text()

    assert "Message-ID: <" in text
    assert "@example.org>" in text      # sender's domain, not the node's fqdn
    assert "+0000" in text and "-0000" not in text


def test_helo_name_defaults_to_sender_domain_not_local_fqdn() -> None:
    """smtplib would announce EHLO [127.0.1.1] on a typical Debian host."""
    channel = SmtpChannel(smtp_settings(from_addr="canary@example.org"), "pw")
    assert channel._helo_name() == "example.org"

    override = SmtpChannel(
        smtp_settings(from_addr="canary@example.org", helo_name="node.example.org"), "pw"
    )
    assert override._helo_name() == "node.example.org"


def test_helo_name_is_used_for_the_connection(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_smtp(host, port, local_hostname=None, timeout=None):
        captured["local_hostname"] = local_hostname
        return _FakeSmtpClient(None)

    channel = SmtpChannel(smtp_settings(from_addr="canary@example.org"), "pw")
    monkeypatch.setattr(smtplib, "SMTP", fake_smtp)
    monkeypatch.setattr(
        channel, "_connect", lambda: fake_smtp("h", 587, channel._helo_name(), 30)
    )
    channel.send(notification())
    assert captured["local_hostname"] == "example.org"


def test_console_transport(capsys) -> None:
    channel = SmtpChannel(SmtpSettings(mode="console"))
    channel.send(notification())
    assert "canaryEW ALERT - vault" in capsys.readouterr().out


def test_subject_injection_refused_at_send(tmp_path: Path) -> None:
    channel = SmtpChannel(SmtpSettings(mode="file", file_path=str(tmp_path / "o.log")))
    with pytest.raises(DeliveryError) as excinfo:
        channel.send(notification(title="hi\r\nBcc: attacker@evil"))
    assert excinfo.value.permanent


# -------------------------------------------------------------- encryption -- #

class FakeEncryptor:
    def encrypt(self, plaintext: str) -> str:
        assert "canaryEW ALERT - vault" in plaintext  # title rides inside
        return "-----BEGIN PGP MESSAGE-----\nciphertext\n-----END PGP MESSAGE-----"


def test_full_detail_requires_actual_encryption() -> None:
    """The cap follows the encryption, not the channel type: dropping the PGP
    config must reduce detail, never silently leak it in plaintext mail."""
    from canaryew.notify.base import RedactionTier, cap_tier

    encrypted = SmtpChannel(smtp_settings(), "pw", encryptor=FakeEncryptor())
    plaintext = SmtpChannel(smtp_settings(), "pw")

    assert encrypted.max_redaction is RedactionTier.FULL
    assert plaintext.max_redaction is RedactionTier.STANDARD
    assert cap_tier(RedactionTier.FULL, encrypted) is RedactionTier.FULL
    assert cap_tier(RedactionTier.FULL, plaintext) is RedactionTier.STANDARD


def test_encryption_failure_sends_nothing(tmp_path: Path) -> None:
    """Fail closed: a gpg failure must not fall back to plaintext."""
    from canaryew.notify.pgp import PgpError

    class BrokenEncryptor:
        def encrypt(self, plaintext: str) -> str:
            raise PgpError("key expired")

    outbox = tmp_path / "outbox.log"
    channel = SmtpChannel(
        SmtpSettings(mode="file", file_path=str(outbox)), encryptor=BrokenEncryptor()
    )
    with pytest.raises(PgpError):
        channel.send(notification())
    assert not outbox.exists()


def test_encrypted_mail_hides_title_and_body(tmp_path: Path) -> None:
    """The mail server must see ciphertext and a generic subject only."""
    outbox = tmp_path / "outbox.log"
    channel = SmtpChannel(
        SmtpSettings(mode="file", file_path=str(outbox)), encryptor=FakeEncryptor()
    )
    channel.send(notification())
    text = outbox.read_text()
    assert "BEGIN PGP MESSAGE" in text
    assert "body text" not in text
    assert "canaryEW ALERT - vault" not in text
    assert "Subject: canaryEW notification" in text


# ---------------------------------------------------- error classification -- #

class _FakeSmtpClient:
    def __init__(self, error: Exception | None) -> None:
        self._error = error

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        pass

    def login(self, user, password) -> None:
        pass

    def send_message(self, message) -> None:
        if self._error:
            raise self._error


@pytest.mark.parametrize(
    ("error", "permanent"),
    [
        (smtplib.SMTPRecipientsRefused({"o@x.org": (550, b"no")}), True),
        (smtplib.SMTPRecipientsRefused({"o@x.org": (450, b"greylisted")}), False),
        (smtplib.SMTPDataError(554, b"rejected"), True),
        (smtplib.SMTPResponseException(451, b"try later"), False),
        (smtplib.SMTPServerDisconnected("lost"), False),
        (TimeoutError("timed out"), False),
        (ConnectionRefusedError("refused"), False),
    ],
)
def test_error_classification(monkeypatch, error, permanent) -> None:
    """5xx -> permanent (escalate now); transport blips -> transient (retry)."""
    channel = SmtpChannel(smtp_settings(), "pw")
    monkeypatch.setattr(channel, "_connect", lambda: _FakeSmtpClient(error))
    with pytest.raises(DeliveryError) as excinfo:
        channel.send(notification())
    assert excinfo.value.permanent is permanent


def test_recipient_refusal_surfaces_codes_not_addresses(monkeypatch) -> None:
    """Codes are diagnostic; addresses never belong in error strings."""
    error = smtplib.SMTPRecipientsRefused({"op@example.org": (554, b"relay denied")})
    channel = SmtpChannel(smtp_settings(), "pw")
    monkeypatch.setattr(channel, "_connect", lambda: _FakeSmtpClient(error))
    with pytest.raises(DeliveryError) as excinfo:
        channel.send(notification())
    assert "554" in str(excinfo.value)
    assert "op@example.org" not in str(excinfo.value)


def test_successful_send(monkeypatch) -> None:
    channel = SmtpChannel(smtp_settings(), "pw")
    monkeypatch.setattr(channel, "_connect", lambda: _FakeSmtpClient(None))
    channel.send(notification())  # must not raise
