"""Dispatch notifications across channels with retry and escalation.

Policy, chosen for failure direction rather than politeness:

- **CRITICAL and DEGRADED go to every configured channel.** Redundancy is the
  point: suppressing the alert must require compromising all channels at once
  (DESIGN S7). Escalation is not "try the next only if the first fails" --
  everything fires.
- **Transient failures retry with backoff; permanent failures do not.** A 5xx
  rejection will not heal on retry; burning the retry budget on it just delays
  the other channels.
- **INFO (heartbeats) gets one attempt per channel, no retries.** A missed
  heartbeat is itself the operator's signal -- that is the dead-man design --
  so a retry storm every interval adds noise without adding safety.
- **A delivery failure never raises out of the dispatcher.** The monitor loop
  must keep running; failures are reported in the result and logged.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

from canaryew.monitor import Severity
from canaryew.notify.base import Channel, DeliveryError, Notification

logger = logging.getLogger("canaryew.dispatch")

NotificationSource = Notification | Callable[[Channel], Notification]
"""Either one notification for every channel, or a per-channel factory.

The factory form exists for redaction: a spend alert at FULL tier must be
re-rendered clamped to each channel's ``max_redaction`` (the webhook channel
never carries txids), and only the render step knows how to do that.
"""


@dataclass(frozen=True)
class ChannelOutcome:
    """What happened on one channel for one notification."""

    channel: str
    delivered: bool
    attempts: int
    error: str | None = None
    permanent: bool = False


@dataclass
class DispatchResult:
    """Aggregate outcome. ``delivered`` means at least one channel succeeded."""

    outcomes: list[ChannelOutcome] = field(default_factory=list)

    @property
    def delivered(self) -> bool:
        return any(o.delivered for o in self.outcomes)

    @property
    def failed_channels(self) -> list[str]:
        return [o.channel for o in self.outcomes if not o.delivered]


class Dispatcher:
    """Fan a notification out to every channel with per-channel retry."""

    def __init__(
        self,
        channels: Sequence[Channel],
        *,
        max_attempts: int = 3,
        backoff_seconds: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._channels = list(channels)
        self._max_attempts = max(1, max_attempts)
        self._backoff = backoff_seconds
        self._sleep = sleep

    @property
    def channel_names(self) -> list[str]:
        return [c.name for c in self._channels]

    def dispatch(self, source: NotificationSource) -> DispatchResult:
        result = DispatchResult()
        last_severity: Severity | None = None

        for channel in self._channels:
            notification = source(channel) if callable(source) else source
            last_severity = notification.severity
            attempts_allowed = (
                1 if notification.severity is Severity.INFO else self._max_attempts
            )
            result.outcomes.append(
                self._deliver(channel, notification, attempts_allowed)
            )

        if not result.delivered and self._channels:
            # This is the one condition the design treats as its own alarm:
            # both channels down means the heartbeat stops and the operator's
            # dead-man rule takes over. Log at critical so journald shows it.
            logger.critical(
                "notification undelivered on every channel severity=%s channels=%s",
                last_severity.value if last_severity else "unknown",
                ",".join(self.channel_names),
            )
        return result

    def _deliver(
        self, channel: Channel, notification: Notification, attempts_allowed: int
    ) -> ChannelOutcome:
        last_error: DeliveryError | None = None
        for attempt in range(1, attempts_allowed + 1):
            try:
                channel.send(notification)
                return ChannelOutcome(
                    channel=channel.name, delivered=True, attempts=attempt
                )
            except DeliveryError as exc:
                last_error = exc
                logger.warning(
                    "delivery failed channel=%s attempt=%d permanent=%s: %s",
                    channel.name,
                    attempt,
                    exc.permanent,
                    exc,
                )
                if exc.permanent:
                    break
                if attempt < attempts_allowed:
                    self._sleep(self._backoff * attempt)
            except Exception as exc:  # a channel bug must not kill the monitor
                last_error = DeliveryError(f"channel raised {type(exc).__name__}: {exc}")
                logger.exception("channel %s raised unexpectedly", channel.name)
                break

        return ChannelOutcome(
            channel=channel.name,
            delivered=False,
            attempts=attempt if last_error else 0,
            error=str(last_error) if last_error else None,
            permanent=bool(last_error and last_error.permanent),
        )
