"""The long-running service: boot, unlock, monitor, heartbeat, snapshot.

Lifecycle:

    start ── record boot ── LOCKED notice via webhook ── control socket up
                                                              │
                     operator sends passphrase (canaryew unlock)
                                                              │
    build channels (SMTP password now readable) ── monitor loop ──┐
        pass → dispatch events → heartbeat if due → save → snapshot → sleep ─┘

Two rules encoded here rather than left to convention:

- **A heartbeat asserts "I checked, and your outputs are present."** A pass
  that could not evaluate (node unreachable, node unsynced) therefore emits no
  heartbeat: the operator's dead-man rule takes over, and the degraded alert
  explains why. Emitting a reassuring heartbeat while blind would be a false
  positive in the one direction this project must never fail.
- **Degraded alerts fire on sustained degradation, not the first blip.** A
  node restart should not page anyone; a node down past the grace period
  should. Recovery re-arms the alert.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Final

from canaryew import heartbeat as hb
from canaryew.config import Config
from canaryew.control import ControlServer
from canaryew.dispatch import Dispatcher
from canaryew.monitor import Monitor, PassResult, Severity, SpendEvent, heartbeat_due
from canaryew.node import BitcoinRpc
from canaryew.notify.base import (
    Channel,
    Notification,
    RedactionTier,
    cap_tier,
    render_degraded,
    render_locked_notice,
    render_spend,
)
from canaryew.notify.brrr import BrrrChannel
from canaryew.notify.pgp import PgpEncryptor
from canaryew.notify.smtp import SmtpChannel
from canaryew.secrets import SecretsError
from canaryew.snapshot import write_snapshot
from canaryew.store import StateStore, WatchedOutput
from canaryew.unlock import BootInfo, LockedError, UnlockManager

logger = logging.getLogger("canaryew.service")

DEGRADED_GRACE_SECONDS_DEFAULT = 1800.0

BOOT_NOTICE_EXIT_GRACE_SECONDS: Final[float] = 20.0
"""How long a failing startup waits for the LOCKED notice to get out before
the process dies and takes its daemon thread with it."""

BOOT_NOTICE_BACKOFF: Final[tuple[float, ...]] = (5.0, 10.0, 20.0, 30.0, 60.0, 60.0, 60.0)
"""Waits between LOCKED-notice attempts (~4.5 minutes total). Deliberately
patient: at boot the network is often unusable for the first minute, and a
lost LOCKED notice is the failure this message exists to prevent."""


class Service:
    """Owns the monitor loop and the control-socket command handlers."""

    def __init__(
        self,
        config: Config,
        *,
        rpc: BitcoinRpc | None = None,
        degraded_grace_seconds: float = DEGRADED_GRACE_SECONDS_DEFAULT,
    ) -> None:
        self.config = config
        self.store = StateStore(config.state_path)
        self.unlock_manager = UnlockManager(self.store, config.boot_state_path)
        self.rpc = rpc or BitcoinRpc(
            config.bitcoin_rpc_url,
            cookie_file=config.bitcoin_rpc_cookie_file,
            rpc_user=config.bitcoin_rpc_user or None,
            rpc_password=config.bitcoin_rpc_password or None,
        )
        self.monitor = Monitor(self.rpc)
        self.boot_info: BootInfo | None = None
        self.dispatcher: Dispatcher | None = None

        self._degraded_grace = degraded_grace_seconds
        self._degraded_since: float | None = None
        self._degraded_alerted = False
        self._last_heartbeat_mac: str | None = None
        """In-memory only: not recomputable after restart without the keys,
        so it reads null until the first post-unlock heartbeat."""
        self._unlocked = threading.Event()
        self._stop = threading.Event()
        self._control: ControlServer | None = None

    # -------------------------------------------------------------- channels --

    def _boot_channels(self) -> list[Channel]:
        """Channels usable before unlock: webhook only, by design."""
        if self.config.brrr_secret:
            return [BrrrChannel(self.config.brrr_secret, api_base=self.config.brrr_api_base)]
        return []

    def _build_dispatcher(self) -> Dispatcher:
        """Full channel set; requires the unlocked store for the SMTP password."""
        channels: list[Channel] = []

        encryptor: PgpEncryptor | None = None
        if self.config.pgp_recipient and self.config.gnupg_home:
            encryptor = PgpEncryptor(self.config.pgp_recipient, self.config.gnupg_home)

        smtp = SmtpChannel(
            self.config.smtp,
            self.unlock_manager.state.smtp_password,
            encryptor=encryptor,
        )
        if smtp.enabled:
            channels.append(smtp)
        elif self.config.smtp.mode != "disabled":
            logger.warning("SMTP channel disabled: %s", smtp.disabled_reason)

        channels.extend(self._boot_channels())
        if not channels:
            logger.critical(
                "No notification channel is configured. Detection will run but "
                "nothing can alert you. Configure SMTP and/or the webhook."
            )
        return Dispatcher(channels)

    # ------------------------------------------------------------ lifecycle --

    def startup(self) -> None:
        """Record the boot, open the control socket, announce LOCKED.

        Order matters. The control socket opens *first* so the operator can
        unlock immediately -- notifying is never allowed to delay the thing
        that ends the outage. The notice then goes out on a background
        thread, because at boot the network is frequently not usable yet
        (DNS especially, even after network-online.target), and this is the
        one message whose loss leaves the operator unable to distinguish a
        power cut from a compromise until a heartbeat fails to arrive hours
        later.
        """
        self.boot_info = self.unlock_manager.record_boot()

        # Announcing comes first because it is asynchronous and therefore
        # free: nothing later in startup is delayed by it, and if control
        # socket setup then fails, the operator still learns the service is
        # down. Silence on a failed startup would be the worst outcome --
        # the state this project exists to make impossible.
        notice_thread = self._start_boot_notice()

        try:
            self._control = ControlServer(
                self.config.control_socket_path, self.handle_command
            )
            self._control.start()
        except Exception:
            logger.critical(
                "Control socket %s could not be opened; the service cannot be "
                "unlocked and is exiting. A LOCKED notice was attempted.",
                self.config.control_socket_path,
            )
            if notice_thread is not None:
                # Give the notice a chance to leave before the process dies:
                # it is a daemon thread and would be killed on exit.
                notice_thread.join(timeout=BOOT_NOTICE_EXIT_GRACE_SECONDS)
            raise

        self._write_snapshot(None)

    def _start_boot_notice(self) -> threading.Thread | None:
        """Begin delivering the LOCKED notice in the background."""
        assert self.boot_info is not None
        dispatcher = Dispatcher(self._boot_channels(), max_attempts=1)
        if not dispatcher.channel_names:
            logger.warning(
                "No webhook secret configured; cannot announce the LOCKED state. "
                "The operator will not know the service is waiting."
            )
            return None

        notice = render_locked_notice(
            since=self.boot_info.locked_since, boot_count=self.boot_info.boot_count
        )
        thread = threading.Thread(
            target=self._announce_locked,
            args=(dispatcher, notice),
            name="canaryew-boot-notice",
            daemon=True,
        )
        thread.start()
        return thread

    def _announce_locked(self, dispatcher: Dispatcher, notice: Notification) -> None:
        """Deliver the LOCKED notice, retrying patiently through a boot race.

        Gives up only after ~5 minutes of widening attempts, and stops early
        if the operator unlocks first -- a "come unlock me" that lands after
        the fact is confusing noise.
        """
        for attempt, delay in enumerate(BOOT_NOTICE_BACKOFF, start=1):
            if self._unlocked.is_set() or self._stop.is_set():
                return
            if dispatcher.dispatch(notice).delivered:
                if attempt > 1:
                    logger.info("LOCKED notice delivered on attempt %d", attempt)
                return
            logger.warning(
                "LOCKED notice undelivered (attempt %d); retrying in %.0fs",
                attempt,
                delay,
            )
            if self._stop.wait(delay) or self._unlocked.is_set():
                return
        logger.critical(
            "LOCKED notice could not be delivered. The service is running but "
            "the operator has not been told it is waiting for a passphrase."
        )

    def shutdown(self) -> None:
        self._stop.set()
        if self._control is not None:
            self._control.stop()

    # ------------------------------------------------------- control handler --

    def handle_command(self, request: dict[str, Any]) -> dict[str, Any]:
        command = request.get("command")
        if command == "unlock":
            return self._cmd_unlock(str(request.get("passphrase", "")))
        if command == "ack":
            return self._cmd_ack(str(request.get("watch_id", "")))
        if command == "status":
            return {"ok": True, "status": self._snapshot_payload(None)}
        return {"ok": False, "error": f"unknown command {command!r}"}

    def _cmd_unlock(self, passphrase: str) -> dict[str, Any]:
        if not self.unlock_manager.locked:
            return {"ok": True, "already_unlocked": True}
        try:
            keys = self.unlock_manager.unlock(passphrase)
        except SecretsError:
            logger.warning("unlock attempt failed (wrong passphrase or tampered store)")
            return {"ok": False, "error": "wrong passphrase, or the store was tampered with"}
        self.dispatcher = self._build_dispatcher()
        self._unlocked.set()
        logger.info("store unlocked; monitoring enabled")
        # The phrase goes back over the owner-only socket so the operator can
        # confirm they unlocked with the *right* passphrase (a mistyped one
        # simply fails, but a different valid store would not).
        return {
            "ok": True,
            "verification_phrase": keys.verification_phrase,
            "fingerprint": keys.fingerprint(),
        }

    def _cmd_ack(self, watch_id: str) -> dict[str, Any]:
        try:
            state = self.unlock_manager.state
        except LockedError:
            return {"ok": False, "error": "service is LOCKED; unlock first"}
        if not watch_id:
            return {"ok": False, "error": "watch_id is required ('all' to ack everything)"}

        acknowledged = 0
        for watch in state.watches:
            if watch_id not in ("all", watch.watch_id):
                continue
            for output in watch.unacknowledged_missing:
                output.acknowledged = True
                acknowledged += 1
        if acknowledged:
            self.unlock_manager.save()
            self._write_snapshot(None)
        return {"ok": True, "acknowledged": acknowledged}

    # ------------------------------------------------------------- main loop --

    def wait_for_unlock(self, poll_seconds: float = 1.0) -> bool:
        """Block until unlocked or stopped. Returns True when unlocked."""
        while not self._stop.is_set():
            if self._unlocked.wait(timeout=poll_seconds):
                return True
        return False

    def run_forever(self) -> None:
        """Startup, wait for unlock, then poll until stopped."""
        self.startup()
        self.run_loop()

    def run_loop(self) -> None:
        """Wait for unlock, then poll until stopped. Assumes ``startup()`` ran."""
        if not self.wait_for_unlock():
            return
        logger.info("monitoring loop started (poll every %ds)", self.config.poll_interval_seconds)
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.run_once()
            except Exception:
                # One broken pass must not kill the service: the next pass may
                # succeed, and a dead service is a silent one.
                logger.exception("monitoring pass raised unexpectedly")
            elapsed = time.monotonic() - started
            self._stop.wait(max(1.0, self.config.poll_interval_seconds - elapsed))

    def run_once(self, now: datetime | None = None) -> PassResult:
        """One full cycle: pass, alerts, heartbeat, persist, snapshot."""
        state = self.unlock_manager.state
        dispatcher = self.dispatcher
        assert dispatcher is not None, "run_once before unlock"
        keys = self.unlock_manager.keys
        reference = now or datetime.now(timezone.utc)

        result = self.monitor.run_pass(state)

        tier = RedactionTier(self.config.redaction)
        for event in result.spend_events:
            # Rendered per channel: the configured tier is clamped to each
            # channel's max_redaction, so FULL detail (txids, exact amounts)
            # can reach the PGP-encrypted channel but never the webhook.
            def render_for(channel: Channel, event: SpendEvent = event) -> Notification:
                return render_spend(
                    event, keys.verification_phrase, cap_tier(tier, channel)
                )

            dispatcher.dispatch(render_for)

        self._handle_degradation(result, dispatcher, keys.verification_phrase)

        heartbeat_sent = None
        if result.did_evaluate and heartbeat_due(
            state, self.config.heartbeat_interval_seconds, now=reference
        ):
            beat = hb.build_heartbeat(state, keys, now=reference)
            # Persist first: a crash after send but before save could reuse a
            # sequence number, which would poison replay detection.
            self.unlock_manager.save()
            dispatcher.dispatch(hb.heartbeat_notification(beat, keys.verification_phrase))
            heartbeat_sent = beat
            self._last_heartbeat_mac = beat.mac_hex
        else:
            self.unlock_manager.save()

        self._write_snapshot(heartbeat_sent)
        return result

    def _handle_degradation(
        self,
        result: PassResult,
        dispatcher: Dispatcher,
        verification_phrase: str,
    ) -> None:
        if result.degraded is None:
            if self._degraded_since is not None:
                logger.info("node recovered; degraded alerting re-armed")
            self._degraded_since = None
            self._degraded_alerted = False
            return

        now = time.monotonic()
        if self._degraded_since is None:
            self._degraded_since = now
        sustained = now - self._degraded_since
        if sustained >= self._degraded_grace and not self._degraded_alerted:
            dispatcher.dispatch(render_degraded(result.degraded, verification_phrase))
            self._degraded_alerted = True
        else:
            logger.warning(
                "degraded (%.0fs of %.0fs grace): %s",
                sustained,
                self._degraded_grace,
                result.degraded.reason,
            )

    # -------------------------------------------------------------- snapshot --

    def _snapshot_payload(self, beat: hb.Heartbeat | None) -> dict[str, Any]:
        locked = self.unlock_manager.locked
        payload: dict[str, Any] = {
            "locked": locked,
            "boot_count": self.boot_info.boot_count if self.boot_info else None,
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "degraded": self._degraded_since is not None,
        }
        if locked:
            return payload

        state = self.unlock_manager.state
        payload.update(
            {
                "watches": len(state.watches),
                "outputs": state.total_outputs,
                "state_summary": hb.summarize(state),
                "unacknowledged_alerts": state.has_unacknowledged_alerts,
                "last_check_at": state.last_check_at,
                "last_block_height": state.last_block_height,
                "heartbeat": {
                    "seq": state.heartbeat_seq,
                    "ts": state.last_heartbeat_at,
                    "mac": beat.mac_hex if beat else self._last_heartbeat_mac,
                    "interval_seconds": self.config.heartbeat_interval_seconds,
                },
            }
        )
        return payload

    def _write_snapshot(self, beat: hb.Heartbeat | None) -> None:
        try:
            write_snapshot(self.config.snapshot_path, self._snapshot_payload(beat))
        except OSError:
            logger.exception("unable to write status snapshot")


TEST_TXID: Final[str] = "de" * 32
"""Obviously synthetic outpoint for drills. Never a real txid."""


def make_notification_test(
    verification_phrase: str,
    tier: RedactionTier = RedactionTier.MINIMAL,
    watch_label: str = "test-watch",
) -> Notification:
    """A test alert rendered through the real spend pipeline.

    Uses ``render_spend`` at the given tier so the drill shows exactly what a
    genuine alert will look like on that channel -- including whether txids
    and exact amounts actually arrive at FULL, which a fixed canned message
    could never demonstrate.

    The TEST banner leads the body because a phone notification previews the
    first line: the operator must be able to tell a drill from the real thing
    at a glance, without unlocking anything.
    """
    from canaryew.monitor import SpendEvent

    event = SpendEvent(
        watch_id="test",
        watch_label=watch_label,
        missing=[WatchedOutput(txid=TEST_TXID, vout=0, value_sat=12_345_678)],
        total_outputs=3,
        block_height=0,
        detected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    rendered = render_spend(event, verification_phrase, tier)
    body = "\n".join(
        [
            # ASCII only: a single non-ASCII character (an em dash, say)
            # pushes the whole message to base64 transfer encoding, which is
            # unreadable raw and scores against deliverability.
            "*** THIS IS A TEST - NOT A REAL SPEND ***",
            "Triggered by 'canaryew test-alert'. The outpoint below is fake.",
            "If you did not run that command just now, treat this as suspicious.",
            "",
            rendered.body,
        ]
    )
    return Notification(
        title="canaryEW TEST alert (not a real spend)",
        body=body,
        severity=Severity.CRITICAL,
        thread_id="canaryew-test",
    )
