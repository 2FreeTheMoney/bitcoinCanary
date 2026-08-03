"""SMTP email channel.

Hardening patterns ported from a battle-tested production mailer:

- **Misconfiguration disables, never crashes.** A broken mail config must
  degrade to a channel that reports *why* it is disabled, because the monitor
  around it has to keep running either way.
- **Transport modes ``smtp | console | file | disabled``.** Console and file
  render the full message without a mail server, which is how the alert path
  gets exercised in tests and during setup.
- **Header-injection guards**: CR/LF is rejected in every address and in the
  subject.
- **Explicit timeouts** and **mandatory STARTTLS** (except port 465, which is
  implicit TLS from the first byte).
- **Error classification drives retry**: 5xx SMTP responses are permanent --
  retrying cannot help, escalate to the next channel immediately. Everything
  else is transient.
- **Logs carry recipient count, never addresses or bodies.**

Stdlib only: ``smtplib`` + ``email.message``.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid, parseaddr
from pathlib import Path
from typing import TYPE_CHECKING, Final

from canaryew.config import SmtpSettings
from canaryew.notify.base import DeliveryError, Notification, RedactionTier

if TYPE_CHECKING:
    from canaryew.notify.pgp import PgpEncryptor

logger = logging.getLogger("canaryew.notify.smtp")

_MODES: Final[tuple[str, ...]] = ("smtp", "console", "file", "disabled")

# Subject used whenever the body is PGP-encrypted: the cleartext subject line
# transits the mail server, so it must not carry the watch label or severity.
_ENCRYPTED_SUBJECT: Final[str] = "canaryEW notification"


def _has_header_injection(value: str) -> bool:
    return "\r" in value or "\n" in value


def validate_settings(settings: SmtpSettings, password: str | None) -> str | None:
    """Return a human-readable reason this config is unusable, or ``None`` if ok.

    Never raises: the caller builds a disabled channel from the reason.
    """
    if settings.mode not in _MODES:
        return f"unknown SMTP mode {settings.mode!r} (expected one of {'|'.join(_MODES)})"
    if settings.mode == "disabled":
        return "disabled by configuration"
    if settings.mode == "file" and not settings.file_path:
        return "file mode requires CANARYEW_SMTP_FILE_PATH"
    if settings.mode in ("console", "file"):
        return None

    # mode == "smtp"
    if not settings.host:
        return "smtp mode requires CANARYEW_SMTP_HOST"
    if not settings.from_addr:
        return "smtp mode requires CANARYEW_SMTP_FROM"
    if not settings.to_addrs:
        return "smtp mode requires CANARYEW_SMTP_TO"
    for address in (settings.from_addr, *settings.to_addrs):
        if _has_header_injection(address):
            return "address contains CR/LF (header injection)"
    if settings.username and password is None:
        return "SMTP username set but no password in the sealed store"
    if password is not None and not settings.username:
        return "SMTP password present but CANARYEW_SMTP_USER is not set"
    return None


class SmtpChannel:
    """Email delivery with optional PGP encryption of the body."""

    name = "smtp"

    def __init__(
        self,
        settings: SmtpSettings,
        password: str | None = None,
        *,
        encryptor: PgpEncryptor | None = None,
    ) -> None:
        self._settings = settings
        self._password = password
        self._encryptor = encryptor
        self.disabled_reason: str | None = validate_settings(settings, password)

    @property
    def enabled(self) -> bool:
        return self.disabled_reason is None

    @property
    def max_redaction(self) -> RedactionTier:
        """How much detail this channel may carry.

        FULL (txids, exact amounts) only when a PGP encryptor is attached:
        without it the mail server and anyone who compromises it read the
        body in the clear, which is the same exposure as the webhook. The
        cap follows the *encryption*, not the channel type, so an operator
        who sets FULL and later drops the PGP config silently gets less
        detail rather than silently leaking it.
        """
        return RedactionTier.FULL if self._encryptor else RedactionTier.STANDARD

    # ------------------------------------------------------------- rendering --

    def _build_message(self, notification: Notification) -> EmailMessage:
        subject = notification.title
        body = notification.body

        if self._encryptor is not None:
            # The mail server sees ciphertext and a generic subject. The real
            # title rides inside the encrypted payload.
            body = self._encryptor.encrypt(f"{notification.title}\n\n{notification.body}")
            subject = _ENCRYPTED_SUBJECT

        if _has_header_injection(subject):
            raise DeliveryError(
                "Subject contains CR/LF; refusing to send.", permanent=True
            )

        sender = self._settings.from_addr or "canaryew@localhost"
        message = EmailMessage()
        message["From"] = sender
        message["To"] = ", ".join(self._settings.to_addrs) or "operator@localhost"
        message["Subject"] = subject
        # UTC with a real "+0000" offset. formatdate(localtime=False) emits
        # "-0000" ("zone unknown"), which some filters score as suspicious.
        message["Date"] = format_datetime(datetime.now(timezone.utc))
        # A missing Message-ID is a well-known spam signal (SpamAssassin
        # MISSING_MID); smtplib never adds one and Postfix only backfills it
        # with always_add_missing_headers. The domain is taken from the
        # sender rather than left to make_msgid's default, which would call
        # socket.getfqdn() and leak the node's internal hostname.
        message["Message-ID"] = make_msgid(domain=self._helo_name())
        message.set_content(body)
        return message

    def _helo_name(self) -> str:
        """Hostname to announce, and the Message-ID domain.

        Defaults to the sender's domain because smtplib would otherwise use
        ``socket.getfqdn()``, which on Debian resolves through the
        ``127.0.1.1`` line in /etc/hosts and announces ``EHLO [127.0.1.1]``
        -- a loopback literal that scores as HELO_LOCALHOST and reads as
        forged. Override with CANARYEW_SMTP_HELO when the node has a proper
        FQDN with matching forward/reverse DNS.
        """
        if self._settings.helo_name:
            return self._settings.helo_name
        _, address = parseaddr(self._settings.from_addr)
        domain = address.rpartition("@")[2]
        return domain or "localhost"

    # -------------------------------------------------------------- delivery --

    def send(self, notification: Notification) -> None:
        if not self.enabled:
            raise DeliveryError(
                f"SMTP channel is disabled: {self.disabled_reason}", permanent=True
            )

        message = self._build_message(notification)
        mode = self._settings.mode

        if mode == "console":
            print(f"--- canaryEW mail ({datetime.now(timezone.utc).isoformat()}) ---")
            print(message.as_string())
            return
        if mode == "file":
            path = Path(self._settings.file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as stream:
                stream.write(message.as_string())
                stream.write("\n---\n")
            return

        self._send_smtp(message)
        logger.info(
            "smtp delivered severity=%s recipients=%d",
            notification.severity.value,
            len(self._settings.to_addrs),
        )

    def _connect(self) -> smtplib.SMTP:
        """Open and secure a session. TLS is not optional in smtp mode."""
        context = ssl.create_default_context()
        helo = self._helo_name()
        if self._settings.port == 465:
            return smtplib.SMTP_SSL(
                self._settings.host,
                self._settings.port,
                local_hostname=helo,
                timeout=self._settings.timeout,
                context=context,
            )
        client = smtplib.SMTP(
            self._settings.host,
            self._settings.port,
            local_hostname=helo,
            timeout=self._settings.timeout,
        )
        if self._settings.starttls:
            client.starttls(context=context)
        return client

    def _send_smtp(self, message: EmailMessage) -> None:
        try:
            with self._connect() as client:
                if self._settings.username and self._password:
                    client.login(self._settings.username, self._password)
                client.send_message(message)
        except smtplib.SMTPRecipientsRefused as exc:
            # Codes are diagnostic gold (554 relay denied = missing auth, 550
            # unknown mailbox = typo, 450 greylisting = retryable) and carry
            # no addresses, so they are safe to surface. 4xx refusals are
            # transient; only all-5xx is permanent.
            codes = sorted({code for code, _ in exc.recipients.values()})
            permanent = all(code >= 500 for code in codes)
            raise DeliveryError(
                f"SMTP refused recipient(s), codes={codes} "
                "(554/553=relay denied, check auth; 550=unknown mailbox)",
                permanent=permanent,
            ) from exc
        except (smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as exc:
            raise DeliveryError(
                f"SMTP rejected the message: {type(exc).__name__} "
                f"(code {exc.smtp_code})",
                permanent=500 <= exc.smtp_code < 600,
            ) from exc
        except smtplib.SMTPResponseException as exc:
            permanent = 500 <= exc.smtp_code < 600
            raise DeliveryError(
                f"SMTP error {exc.smtp_code}", permanent=permanent
            ) from exc
        except (smtplib.SMTPException, OSError) as exc:
            raise DeliveryError(f"SMTP transport failure: {type(exc).__name__}") from exc

    # ---------------------------------------------------------------- health --

    def healthy(self) -> bool:
        """Connection + auth probe for the status surface. Sends nothing."""
        if not self.enabled:
            return False
        if self._settings.mode in ("console", "file"):
            return True
        try:
            with self._connect() as client:
                if self._settings.username and self._password:
                    client.login(self._settings.username, self._password)
            return True
        except Exception:
            return False
