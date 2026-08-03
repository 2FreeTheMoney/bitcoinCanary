"""brrr.now push channel.

Endpoint and payload shape are corroborated against a known-good production
integration with this API, which delivers successfully with:

    POST https://api.brrr.now/v1/{secret}
    {"title": ..., "message": ..., "interruption_level": ...}

That URL-path form is therefore the default here. The ``/v1/send`` + bearer
form from the docs remains available via ``use_bearer`` but is uncorroborated
by working code.

Fields beyond that core -- ``thread_id``, ``sound``, ``volume`` -- come from
the docs only. Because an alert must not die on an optional field, a 4xx
rejection triggers one retry with the minimal corroborated payload before the
failure is surfaced.

Chosen as the secondary channel for two properties that matter here:

1. **Critical alerts bypass Focus, Do Not Disturb, and mute.** A spend alert
   at 03:00 is exactly the case where a silenced phone defeats the system.
2. **A webhook secret is the entire credential.** No SMTP account, no keyring.
   That makes it the only channel able to run *before* the sealed store is
   unlocked, which is what turns a silent post-reboot gap into a prompt.

Stdlib-only, consistent with ``node.py``.
"""

from __future__ import annotations

import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Final

from canaryew.monitor import Severity
from canaryew.notify.base import DeliveryError, Notification, RedactionTier

logger = logging.getLogger("canaryew.notify.brrr")

API_BASE: Final[str] = "https://api.brrr.now/v1"
DEFAULT_TIMEOUT: Final[float] = 15.0

# Severity -> (interruption_level, sound). 'critical' requires the operator to
# enable critical alerts for the brrr app on-device; without that the service
# downgrades delivery, so setup docs must call this out.
_DELIVERY: Final[dict[Severity, tuple[str, str]]] = {
    Severity.CRITICAL: ("critical", "emergency"),
    Severity.DEGRADED: ("time-sensitive", "warm_soft_error"),
    Severity.INFO: ("passive", "default"),
}


class BrrrChannel:
    """Push notifications via brrr.now."""

    name = "brrr"

    # A third party sees the body in transit, so the FULL tier (txids, exact
    # amounts) is never carried on this channel regardless of the operator's
    # configured tier -- DESIGN S7. The dispatcher renders per channel and
    # clamps to this.
    max_redaction = RedactionTier.STANDARD

    def __init__(
        self,
        secret: str,
        *,
        critical_volume: float = 1.0,
        timeout: float = DEFAULT_TIMEOUT,
        use_bearer: bool = False,
    ) -> None:
        raw = secret.strip()
        if not raw:
            raise DeliveryError("brrr secret must not be empty.")
        # Operators paste what the brrr app shows them, which may be the full
        # webhook URL rather than the bare secret. Accept both -- posting to
        # ".../v1/https://..." just yields a mystifying 403.
        if raw.startswith(("http://", "https://")):
            self._url: str | None = raw.rstrip("/")
            self._secret = self._url.rsplit("/", 1)[-1]
        else:
            self._url = None
            self._secret = raw
        self._critical_volume = max(0.0, min(1.0, critical_volume))
        self._timeout = timeout
        # Default False: the URL-path form is corroborated by a working
        # production integration. Bearer is the documented alternative.
        self._use_bearer = use_bearer

    def _endpoint(self) -> str:
        if self._use_bearer:
            return f"{API_BASE}/send"
        return self._url or f"{API_BASE}/{self._secret}"

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._use_bearer:
            headers["Authorization"] = f"Bearer {self._secret}"
        return headers

    def _payload(self, notification: Notification, *, minimal: bool = False) -> dict[str, object]:
        level, sound = _DELIVERY[notification.severity]
        payload: dict[str, object] = {
            "title": notification.title,
            "message": notification.body,
            "interruption_level": level,
        }
        if minimal:
            return payload
        payload["thread_id"] = notification.thread_id
        payload["sound"] = sound
        if level == "critical":
            payload["volume"] = self._critical_volume
        return payload

    def _redact(self, text: str) -> str:
        """Errors and logs must never carry the secret (it rides in the URL)."""
        return text.replace(self._secret, redact_secret(self._secret))

    def _post(self, payload: dict[str, object]) -> None:
        request = urllib.request.Request(
            self._endpoint(),
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers=self._headers(),
        )
        with urllib.request.urlopen(request, timeout=self._timeout) as response:
            if not 200 <= response.status < 300:
                raise DeliveryError(f"brrr returned HTTP {response.status}")

    def send(self, notification: Notification) -> None:
        """Deliver one notification, raising :class:`DeliveryError` on failure."""
        try:
            self._post(self._payload(notification))
            return
        except urllib.error.HTTPError as exc:
            # A 4xx may mean an optional field was rejected. The alert matters
            # more than the metadata: fall back to the corroborated minimal
            # payload once before giving up.
            if not 400 <= exc.code < 500:
                # Deliberately does not echo the response body: it may contain
                # the secret or request echo, and this string reaches logs.
                raise DeliveryError(f"brrr rejected the request: HTTP {exc.code}") from exc
            logger.warning(
                "brrr returned HTTP %d; retrying with minimal payload", exc.code
            )
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            raise DeliveryError(f"brrr unreachable: {self._redact(str(exc))}") from exc

        try:
            self._post(self._payload(notification, minimal=True))
        except urllib.error.HTTPError as exc:
            raise DeliveryError(f"brrr rejected the request: HTTP {exc.code}") from exc
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            raise DeliveryError(f"brrr unreachable: {self._redact(str(exc))}") from exc

    def healthy(self) -> bool:
        """Reachability probe.

        Intentionally does not send a notification -- a health check that pushes
        to the operator's phone would train them to ignore canaryEW alerts,
        which is the one failure this project cannot tolerate.
        """
        try:
            request = urllib.request.Request(API_BASE, method="HEAD")
            with urllib.request.urlopen(request, timeout=5.0):
                return True
        except urllib.error.HTTPError:
            return True  # reachable; status irrelevant for a HEAD on the base
        except Exception:
            return False


def redact_secret(secret: str) -> str:
    """Safe-to-log form of a brrr secret, e.g. ``br_usr_a1b2...i9j0``."""
    if len(secret) <= 12:
        return "***"
    return f"{secret[:10]}...{secret[-4:]}"
