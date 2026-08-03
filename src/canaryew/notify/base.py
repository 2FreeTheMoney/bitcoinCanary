"""Notification model, redaction tiers, and the channel protocol."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from canaryew.monitor import DegradedEvent, Severity, SpendEvent


class RedactionTier(str, Enum):
    """How much detail leaves the host.

    Default is ``MINIMAL`` -- enough to act on, not enough to inform an
    eavesdropper about which coins you hold or how much.
    """

    MINIMAL = "minimal"
    STANDARD = "standard"
    FULL = "full"

    @property
    def rank(self) -> int:
        return ("minimal", "standard", "full").index(self.value)


def cap_tier(tier: RedactionTier, channel: object) -> RedactionTier:
    """Clamp a redaction tier to what a channel is allowed to carry.

    A channel may declare ``max_redaction`` (e.g. the webhook channel caps at
    STANDARD because a third party sees the body in transit -- DESIGN S7).
    The operator's configured tier is a ceiling for trusted channels, never a
    floor for untrusted ones.
    """
    limit = getattr(channel, "max_redaction", None)
    if isinstance(limit, RedactionTier) and tier.rank > limit.rank:
        return limit
    return tier


class DeliveryError(RuntimeError):
    """A channel failed to deliver. Callers escalate to the next channel.

    ``permanent`` drives retry policy: a permanent failure (bad recipient,
    5xx rejection, malformed message) will not heal on retry, so the
    dispatcher escalates to the next channel immediately instead of burning
    the retry budget first.
    """

    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


@dataclass(frozen=True)
class Notification:
    """A channel-agnostic message ready for dispatch."""

    title: str
    body: str
    severity: Severity
    thread_id: str = "canaryew"

    @property
    def is_critical(self) -> bool:
        return self.severity is Severity.CRITICAL


class Channel(Protocol):
    """One delivery mechanism."""

    name: str

    def send(self, notification: Notification) -> None:
        """Deliver, or raise :class:`DeliveryError`."""

    def healthy(self) -> bool:
        """Cheap reachability probe for the status surface."""


def _value_bucket(sats: int) -> str:
    """Coarse magnitude, so an eavesdropper learns urgency but not holdings."""
    btc = sats / 100_000_000
    for threshold, label in (
        (0.01, "<0.01 BTC"),
        (0.1, "0.01-0.1 BTC"),
        (1, "0.1-1 BTC"),
        (10, "1-10 BTC"),
    ):
        if btc < threshold:
            return label
    return ">10 BTC"


def render_spend(
    event: SpendEvent, verification_phrase: str, tier: RedactionTier
) -> Notification:
    """Build the operator-facing alert for a detected spend."""
    lines = [
        f"Watch:        {event.watch_label}",
        f"Condition:    {event.missing_count} of {event.total_outputs} "
        "monitored outputs no longer in the UTXO set",
        f"Block height: {event.block_height:,}",
        f"Detected:     {event.detected_at}",
    ]

    if tier is not RedactionTier.MINIMAL:
        lines.append(f"Value:        {_value_bucket(event.missing_value_sat)}")

    if tier is RedactionTier.FULL:
        lines.append("")
        lines.append("Affected outputs:")
        lines.extend(
            f"  {o.txid}:{o.vout}  ({o.value_sat:,} sat)" for o in event.missing
        )

    lines += [
        "",
        f"Verification: {verification_phrase}",
        "",
        "If you did not authorize a spend from this wallet, treat this as an",
        "active compromise. Do not enter your seed phrase anywhere, and do not",
        "trust any message asking you to 'verify' or 'migrate' your seed.",
    ]

    return Notification(
        title=f"canaryEW ALERT - {event.watch_label}",
        body="\n".join(lines),
        severity=Severity.CRITICAL,
        thread_id=f"canaryew-{event.watch_id}",
    )


def render_degraded(event: DegradedEvent, verification_phrase: str) -> Notification:
    """Build the alert for 'the monitor could not do its job'.

    Distinct from a spend alert: it means canaryEW has lost the ability to
    answer the question, which is not the same as an answer of 'stolen' -- but
    it is also not 'all clear', and must never be presented as one.
    """
    body = "\n".join(
        [
            "canaryEW could not complete a monitoring pass.",
            "",
            f"Reason:   {event.reason}",
            f"Detail:   {event.detail}",
            f"Detected: {event.detected_at}",
            "",
            f"Verification: {verification_phrase}",
            "",
            "Monitoring is NOT currently confirming your outputs are present.",
        ]
    )
    return Notification(
        title="canaryEW degraded - monitoring interrupted",
        body=body,
        severity=Severity.DEGRADED,
        thread_id="canaryew-degraded",
    )


def render_heartbeat(
    seq: int,
    state_summary: str,
    block_height: int | None,
    mac_hex: str,
    verification_phrase: str,
) -> Notification:
    """Build the positive 'still alive, still watching' message.

    The MAC and monotonic sequence are what make this un-forgeable and
    un-replayable; the verification phrase is the human-checkable shorthand.
    """
    body = "\n".join(
        [
            f"seq:    {seq}",
            f"state:  {state_summary}",
            f"block:  {block_height:,}" if block_height else "block:  unknown",
            f"time:   {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
            f"mac:    {mac_hex[:32]}",
            "",
            f"Verification: {verification_phrase}",
        ]
    )
    return Notification(
        title=f"canaryEW heartbeat #{seq}",
        body=body,
        severity=Severity.INFO,
        thread_id="canaryew-heartbeat",
    )


def render_locked_notice(since: str, boot_count: int) -> Notification:
    """Pre-unlock notice: the service is up but cannot monitor yet.

    Deliberately carries NO verification phrase and NO MAC -- it is emitted
    before the passphrase is available, using a key held in cleartext on disk.
    An attacker who steals that key can replay this message and nothing else;
    critically, they cannot use it to fabricate an 'all clear', because that
    requires the sealed HMAC key.
    """
    body = "\n".join(
        [
            "canaryEW restarted and is LOCKED. Monitoring is suspended until",
            "you unlock it with your passphrase.",
            "",
            f"Locked since: {since}",
            f"Boot count:   {boot_count}",
            "",
            "This message is NOT authenticated and carries no verification",
            "phrase by design. Treat it as a prompt to go and unlock the",
            "service, never as evidence about the state of your coins.",
        ]
    )
    return Notification(
        title="canaryEW LOCKED - awaiting unlock",
        body=body,
        severity=Severity.DEGRADED,
        thread_id="canaryew-locked",
    )
