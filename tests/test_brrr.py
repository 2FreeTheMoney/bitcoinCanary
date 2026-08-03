"""brrr.now channel: corroborated endpoint/payload shape, minimal-payload
fallback, and secret hygiene in errors."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew.monitor import Severity
from canaryew.notify.base import DeliveryError, Notification
from canaryew.notify.brrr import BrrrChannel, redact_secret

SECRET = "br_usr_a1b2c3d4e5f6g7h8i9j0"


def note(severity: Severity = Severity.CRITICAL) -> Notification:
    return Notification(title="canaryEW ALERT", body="alert body", severity=severity)


class FakeUrlopen:
    """Captures requests; raises scripted errors in order, then succeeds."""

    def __init__(self, errors: list[Exception] | None = None) -> None:
        self.errors = list(errors or [])
        self.requests: list = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        if self.errors:
            raise self.errors.pop(0)

        class _Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return _Response()

    def payload(self, index: int = 0) -> dict:
        return json.loads(self.requests[index].data.decode("utf-8"))


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("url", code, "msg", {}, io.BytesIO(b""))


# ------------------------------------------------------- corroborated shape -- #

def test_default_form_matches_production_integration(monkeypatch) -> None:
    """URL-path endpoint, no auth header, message/interruption_level fields."""
    fake = FakeUrlopen()
    monkeypatch.setattr("urllib.request.urlopen", fake)

    BrrrChannel(SECRET).send(note())

    request = fake.requests[0]
    assert request.full_url == f"https://api.brrr.now/v1/{SECRET}"
    assert not request.has_header("Authorization")

    payload = fake.payload()
    assert payload["title"] == "canaryEW ALERT"
    assert payload["message"] == "alert body"     # 'message', never 'body'
    assert "body" not in payload
    assert payload["interruption_level"] == "critical"


def test_full_webhook_url_is_accepted_as_secret(monkeypatch) -> None:
    """Operators paste what the brrr app shows, which may be the whole URL."""
    fake = FakeUrlopen()
    monkeypatch.setattr("urllib.request.urlopen", fake)

    BrrrChannel(f"https://api.brrr.now/v1/{SECRET}/").send(note())
    assert fake.requests[0].full_url == f"https://api.brrr.now/v1/{SECRET}"


def test_full_url_secret_still_redacted_in_errors(monkeypatch) -> None:
    fake = FakeUrlopen(
        errors=[urllib.error.URLError(f"cannot reach https://api.brrr.now/v1/{SECRET}")]
    )
    monkeypatch.setattr("urllib.request.urlopen", fake)

    with pytest.raises(DeliveryError) as excinfo:
        BrrrChannel(f"https://api.brrr.now/v1/{SECRET}").send(note())
    assert SECRET not in str(excinfo.value)


def test_bearer_form_is_opt_in(monkeypatch) -> None:
    fake = FakeUrlopen()
    monkeypatch.setattr("urllib.request.urlopen", fake)

    BrrrChannel(SECRET, use_bearer=True).send(note())

    request = fake.requests[0]
    assert request.full_url == "https://api.brrr.now/v1/send"
    assert SECRET not in request.full_url
    assert request.get_header("Authorization") == f"Bearer {SECRET}"


@pytest.mark.parametrize(
    ("severity", "level", "has_volume"),
    [
        (Severity.CRITICAL, "critical", True),
        (Severity.DEGRADED, "time-sensitive", False),
        (Severity.INFO, "passive", False),
    ],
)
def test_severity_mapping(monkeypatch, severity, level, has_volume) -> None:
    fake = FakeUrlopen()
    monkeypatch.setattr("urllib.request.urlopen", fake)

    BrrrChannel(SECRET).send(note(severity))
    payload = fake.payload()
    assert payload["interruption_level"] == level
    assert ("volume" in payload) is has_volume


# ------------------------------------------------------------- degradation -- #

def test_4xx_falls_back_to_minimal_corroborated_payload(monkeypatch) -> None:
    """The alert matters more than optional metadata."""
    fake = FakeUrlopen(errors=[http_error(400)])
    monkeypatch.setattr("urllib.request.urlopen", fake)

    BrrrChannel(SECRET).send(note())

    assert len(fake.requests) == 2
    retry = fake.payload(1)
    assert set(retry) == {"title", "message", "interruption_level"}


def test_4xx_twice_fails_without_secret_leak(monkeypatch) -> None:
    fake = FakeUrlopen(errors=[http_error(404), http_error(404)])
    monkeypatch.setattr("urllib.request.urlopen", fake)

    with pytest.raises(DeliveryError) as excinfo:
        BrrrChannel(SECRET).send(note())
    assert SECRET not in str(excinfo.value)


def test_5xx_is_not_retried_with_minimal_payload(monkeypatch) -> None:
    """A server error is not a payload problem; the dispatcher owns retries."""
    fake = FakeUrlopen(errors=[http_error(503)])
    monkeypatch.setattr("urllib.request.urlopen", fake)

    with pytest.raises(DeliveryError, match="HTTP 503"):
        BrrrChannel(SECRET).send(note())
    assert len(fake.requests) == 1


def test_transport_error_redacts_secret(monkeypatch) -> None:
    """URLError text can echo the URL, which embeds the secret."""
    fake = FakeUrlopen(
        errors=[urllib.error.URLError(f"cannot reach https://api.brrr.now/v1/{SECRET}")]
    )
    monkeypatch.setattr("urllib.request.urlopen", fake)

    with pytest.raises(DeliveryError) as excinfo:
        BrrrChannel(SECRET).send(note())
    assert SECRET not in str(excinfo.value)
    assert "unreachable" in str(excinfo.value)


# ------------------------------------------------------------------ hygiene -- #

def test_empty_secret_rejected() -> None:
    with pytest.raises(DeliveryError):
        BrrrChannel("")


def test_redact_secret() -> None:
    assert redact_secret(SECRET) == "br_usr_a1b...i9j0"
    assert redact_secret("short") == "***"
