"""Dispatcher: fan-out, retry policy, and containment of channel failures."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew.dispatch import Dispatcher
from canaryew.monitor import Severity
from canaryew.notify.base import DeliveryError, Notification


def note(severity: Severity = Severity.CRITICAL) -> Notification:
    return Notification(title="t", body="b", severity=severity)


class ScriptedChannel:
    """Fails ``fail_times`` times, then succeeds."""

    def __init__(self, name: str, *, fail_times: int = 0, permanent: bool = False,
                 explode: bool = False) -> None:
        self.name = name
        self.fail_times = fail_times
        self.permanent = permanent
        self.explode = explode
        self.sends = 0

    def send(self, notification: Notification) -> None:
        self.sends += 1
        if self.explode:
            raise ValueError("channel bug")
        if self.sends <= self.fail_times:
            raise DeliveryError("scripted failure", permanent=self.permanent)

    def healthy(self) -> bool:
        return True


def no_sleep(_: float) -> None:
    pass


def test_critical_goes_to_every_channel_even_when_first_succeeds() -> None:
    a, b = ScriptedChannel("a"), ScriptedChannel("b")
    result = Dispatcher([a, b], sleep=no_sleep).dispatch(note())
    assert result.delivered
    assert a.sends == 1 and b.sends == 1  # redundancy, not fallback


def test_transient_failure_retries_then_succeeds() -> None:
    flaky = ScriptedChannel("flaky", fail_times=2)
    result = Dispatcher([flaky], max_attempts=3, sleep=no_sleep).dispatch(note())
    assert result.delivered
    assert flaky.sends == 3
    assert result.outcomes[0].attempts == 3


def test_permanent_failure_does_not_burn_retries() -> None:
    broken = ScriptedChannel("broken", fail_times=99, permanent=True)
    backup = ScriptedChannel("backup")
    result = Dispatcher([broken, backup], max_attempts=3, sleep=no_sleep).dispatch(note())
    assert broken.sends == 1          # no pointless retries
    assert backup.sends == 1          # other channel still fired
    assert result.delivered
    assert result.failed_channels == ["broken"]
    assert result.outcomes[0].permanent


def test_heartbeat_gets_single_attempt() -> None:
    """A missed heartbeat IS the signal; retry storms add noise, not safety."""
    flaky = ScriptedChannel("flaky", fail_times=1)
    result = Dispatcher([flaky], max_attempts=3, sleep=no_sleep).dispatch(
        note(Severity.INFO)
    )
    assert flaky.sends == 1
    assert not result.delivered


def test_channel_exception_is_contained() -> None:
    """A buggy channel must not take down the monitor or the other channels."""
    exploding = ScriptedChannel("exploding", explode=True)
    backup = ScriptedChannel("backup")
    result = Dispatcher([exploding, backup], sleep=no_sleep).dispatch(note())
    assert result.delivered
    assert "channel raised" in (result.outcomes[0].error or "")


def test_total_failure_is_reported_not_raised() -> None:
    broken = ScriptedChannel("broken", fail_times=99)
    result = Dispatcher([broken], max_attempts=2, sleep=no_sleep).dispatch(note())
    assert not result.delivered
    assert result.failed_channels == ["broken"]


def test_factory_source_renders_per_channel() -> None:
    """The redaction clamp depends on rendering separately for each channel."""
    a, b = ScriptedChannel("a"), ScriptedChannel("b")
    seen: list[str] = []

    def factory(channel) -> Notification:
        seen.append(channel.name)
        return Notification(title=f"for-{channel.name}", body="b",
                            severity=Severity.CRITICAL)

    result = Dispatcher([a, b], sleep=no_sleep).dispatch(factory)
    assert result.delivered
    assert seen == ["a", "b"]


def test_backoff_grows_between_attempts() -> None:
    delays: list[float] = []
    flaky = ScriptedChannel("flaky", fail_times=2)
    Dispatcher([flaky], max_attempts=3, backoff_seconds=2.0,
               sleep=delays.append).dispatch(note())
    assert delays == [2.0, 4.0]
