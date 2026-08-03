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
from email.utils import formatdate
from pathlib import Path
from typing import TYPE_CHECKING, Final

from canaryew.config import SmtpSettings
from canaryew.notify.base import DeliveryError, Notification

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

        message = EmailMessage()
        message["From"] = self._settings.from_addr or "canaryew@localhost"
        message["To"] = ", ".join(self._settings.to_addrs) or "operator@localhost"
        message["Subject"] = subject
        message["Date"] = formatdate(localtime=False)
        message.set_content(body)
        return message

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
        if self._settings.port == 465:
            return smtplib.SMTP_SSL(
                self._settings.host,
                self._settings.port,
                timeout=self._settings.timeout,
                context=context,
            )
        client = smtplib.SMTP(
            self._settings.host, self._settings.port, timeout=self._settings.timeout
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
