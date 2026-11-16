"""Operator CLI: init/enroll/import round trip, guard rails, test-alert."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from conftest import FakeRpc

from canaryew import cli
from canaryew.store import StateStore

PASSPHRASE = "a-correct-horse-battery-staple-for-tests"
TXID_A = "a" * 64
TXID_B = "b" * 64


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("CANARYEW_HOME", str(tmp_path))
    return tmp_path


def feed_passphrases(monkeypatch, *answers: str) -> None:
    iterator = iter(answers)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(iterator))


# --------------------------------------------------------------------- init -- #

def test_init_creates_store_and_prints_phrase(home: Path, monkeypatch, capsys) -> None:
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0
    out = capsys.readouterr().out
    assert "Verification phrase:" in out
    assert StateStore(home / "state.json").exists()


def test_init_passphrase_mismatch_fails(home: Path, monkeypatch, capsys) -> None:
    feed_passphrases(monkeypatch, PASSPHRASE, "different")
    assert cli.main(["init"]) == 1
    assert not StateStore(home / "state.json").exists()


def test_init_refuses_existing_store(home: Path, monkeypatch, capsys) -> None:
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0
    assert cli.main(["init"]) == 1
    assert "already exists" in capsys.readouterr().err


# ------------------------------------------------------- enroll -> import ---- #

def test_full_offline_enrollment_round_trip(home: Path, monkeypatch, capsys) -> None:
    export = home / "sparrow-export.csv"
    export.write_text(
        "Date,Output,Address,Label,Value\n"
        f"2026-01-04,{TXID_A}:0,bc1qexample,cold,0.5\n"
        f"2026-02-11,{TXID_B}:3,bc1qother,,1.25\n"
    )
    monkeypatch.setattr(cli, "_make_rpc", lambda config: FakeRpc())

    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0

    watchfile = home / "vault.watchfile"
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main([
        "enroll", "--export", str(export), "--label", "vault-cosigner-a",
        "--out", str(watchfile), "--watch-id", "w-vault",
    ]) == 0
    out = capsys.readouterr().out
    assert "Parsed 2 outpoints" in out and "Fingerprint:" in out
    assert watchfile.exists()

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 0
    out = capsys.readouterr().out
    assert "2 still unspent" in out
    assert "Imported watch 'w-vault'" in out

    _, state = StateStore(home / "state.json").unlock(PASSPHRASE)
    assert state.watch("w-vault").total_outputs == 2

    # Re-import of the same watch id must be refused, not silently duplicated.
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 1


def _prepared_watchfile(home: Path, monkeypatch, capsys) -> Path:
    """init + enroll three outputs; returns the watchfile path."""
    export = home / "outpoints.txt"
    export.write_text(f"{TXID_A}:0\n{TXID_A}:1\n{TXID_B}:0\n")
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0
    watchfile = home / "vault.watchfile"
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main([
        "enroll", "--export", str(export), "--label", "vault",
        "--out", str(watchfile), "--watch-id", "w-vault",
    ]) == 0
    capsys.readouterr()
    return watchfile


def test_import_prunes_already_spent_history(home: Path, monkeypatch, capsys) -> None:
    """The BIP-329 case: exports carry spent outputs; those are wallet
    history and must be dropped at import, not alerted on at first pass."""
    watchfile = _prepared_watchfile(home, monkeypatch, capsys)
    monkeypatch.setattr(
        cli, "_make_rpc", lambda config: FakeRpc(spent={f"{TXID_A}:1"})
    )

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 0
    out = capsys.readouterr().out
    assert "3 outputs in the watchfile" in out
    assert "2 still unspent" in out
    assert "1 already spent" in out
    assert f"{TXID_A}:1" in out

    _, state = StateStore(home / "state.json").unlock(PASSPHRASE)
    watch = state.watch("w-vault")
    assert watch.total_outputs == 2
    assert all(o.outpoint != f"{TXID_A}:1" for o in watch.outputs)


def test_import_refuses_when_everything_is_spent(home: Path, monkeypatch, capsys) -> None:
    watchfile = _prepared_watchfile(home, monkeypatch, capsys)
    monkeypatch.setattr(
        cli, "_make_rpc",
        lambda config: FakeRpc(spent={f"{TXID_A}:0", f"{TXID_A}:1", f"{TXID_B}:0"}),
    )
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 1
    assert "already spent" in capsys.readouterr().err


def test_import_unsynced_node_refuses_verification(home: Path, monkeypatch, capsys) -> None:
    """A lagging node reports outputs absent for non-theft reasons."""
    watchfile = _prepared_watchfile(home, monkeypatch, capsys)
    monkeypatch.setattr(cli, "_make_rpc", lambda config: FakeRpc(synced=False))
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 1
    assert "not synced" in capsys.readouterr().err


def test_import_unreachable_node_gives_guidance(home: Path, monkeypatch, capsys) -> None:
    watchfile = _prepared_watchfile(home, monkeypatch, capsys)
    monkeypatch.setattr(cli, "_make_rpc", lambda config: FakeRpc(unreachable=True))
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 1
    assert "--no-verify" in capsys.readouterr().err


def test_import_no_verify_skips_the_node(home: Path, monkeypatch, capsys) -> None:
    watchfile = _prepared_watchfile(home, monkeypatch, capsys)
    monkeypatch.setattr(cli, "_make_rpc", lambda config: FakeRpc(unreachable=True))
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile), "--no-verify"]) == 0
    _, state = StateStore(home / "state.json").unlock(PASSPHRASE)
    assert state.watch("w-vault").total_outputs == 3


def test_reenrollment_replaces_the_same_watch(home: Path, monkeypatch, capsys) -> None:
    """The normal post-spend / post-deposit flow: same wallet, new outputs."""
    watchfile = _prepared_watchfile(home, monkeypatch, capsys)
    monkeypatch.setattr(cli, "_make_rpc", lambda config: FakeRpc())

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 0
    capsys.readouterr()

    # Same id without --replace is refused, with direction.
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 1
    assert "--replace" in capsys.readouterr().err

    # A fresh export of the same wallet, now with different outputs.
    export = home / "after.txt"
    export.write_text(f"{TXID_B}:7\n")
    new_watchfile = home / "after.watchfile"
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main([
        "enroll", "--export", str(export), "--label", "vault",
        "--out", str(new_watchfile), "--watch-id", "w-vault",
    ]) == 0
    capsys.readouterr()

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(new_watchfile), "--replace"]) == 0
    assert "Replacing watch 'w-vault': 3 outputs -> 1" in capsys.readouterr().out

    _, state = StateStore(home / "state.json").unlock(PASSPHRASE)
    assert len(state.watches) == 1              # replaced, not duplicated
    assert state.watch("w-vault").total_outputs == 1


def test_replace_refuses_to_discard_an_active_alarm(home: Path, monkeypatch, capsys) -> None:
    """Re-enrolling must never be a back door around 'never auto-clear'."""
    watchfile = _prepared_watchfile(home, monkeypatch, capsys)
    monkeypatch.setattr(cli, "_make_rpc", lambda config: FakeRpc())
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 0

    # Simulate a detected spend that the operator has not acknowledged.
    keys, state = StateStore(home / "state.json").unlock(PASSPHRASE)
    state.watch("w-vault").outputs[0].present = False
    StateStore(home / "state.json").save(keys, state)
    capsys.readouterr()

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile), "--replace"]) == 1
    error = capsys.readouterr().err
    assert "not acknowledged" in error and "canaryew ack" in error

    # --force is the deliberate override.
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main([
        "import", "--watchfile", str(watchfile), "--replace", "--force"
    ]) == 0


def test_remove_watch(home: Path, monkeypatch, capsys) -> None:
    watchfile = _prepared_watchfile(home, monkeypatch, capsys)
    monkeypatch.setattr(cli, "_make_rpc", lambda config: FakeRpc())
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 0
    capsys.readouterr()

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["remove-watch", "--watch", "nope"]) == 1
    assert "Known watches: w-vault" in capsys.readouterr().err

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["remove-watch", "--watch", "w-vault"]) == 0
    out = capsys.readouterr().out
    assert "Removed watch 'w-vault'" in out
    assert "No watches remain" in out

    _, state = StateStore(home / "state.json").unlock(PASSPHRASE)
    assert state.watches == []


def test_remove_watch_guards_unacknowledged_alerts(home: Path, monkeypatch, capsys) -> None:
    watchfile = _prepared_watchfile(home, monkeypatch, capsys)
    monkeypatch.setattr(cli, "_make_rpc", lambda config: FakeRpc())
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(watchfile)]) == 0

    keys, state = StateStore(home / "state.json").unlock(PASSPHRASE)
    state.watch("w-vault").outputs[0].present = False
    StateStore(home / "state.json").save(keys, state)
    capsys.readouterr()

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["remove-watch", "--watch", "w-vault"]) == 1
    assert "not acknowledged" in capsys.readouterr().err

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["remove-watch", "--watch", "w-vault", "--force"]) == 0


def test_import_refused_while_service_running(home: Path, monkeypatch, capsys) -> None:
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0
    (home / "control.sock").touch()   # pretend the service is up

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["import", "--watchfile", str(home / "x.watchfile")]) == 1
    assert "Stop it before" in capsys.readouterr().err


def test_enroll_rejects_garbage_export(home: Path, monkeypatch, capsys) -> None:
    export = home / "junk.txt"
    export.write_text("no outpoints here")
    assert cli.main([
        "enroll", "--export", str(export), "--label", "x", "--out", str(home / "o"),
    ]) == 1
    assert "No outpoints" in capsys.readouterr().err


# ---------------------------------------------------------------- secrets ---- #

def test_set_smtp_password_round_trip(home: Path, monkeypatch, capsys) -> None:
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0

    feed_passphrases(monkeypatch, PASSPHRASE, "smtp-secret-pw")
    assert cli.main(["set-smtp-password"]) == 0

    _, state = StateStore(home / "state.json").unlock(PASSPHRASE)
    assert state.smtp_password == "smtp-secret-pw"
    # And never in cleartext on disk.
    assert "smtp-secret-pw" not in (home / "state.json").read_text()


# --------------------------------------------------------------- test-alert -- #

def test_test_alert_uses_configured_brrr_api_base(home: Path, monkeypatch, capsys) -> None:
    from test_brrr import FakeUrlopen, SECRET

    fake = FakeUrlopen()
    monkeypatch.setattr("urllib.request.urlopen", fake)
    monkeypatch.setenv("CANARYEW_BRRR_SECRET", SECRET)
    monkeypatch.setenv("CANARYEW_BRRR_API_BASE", "https://notify.example.invalid/api/v1")
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["test-alert"]) == 0
    assert fake.requests[0].full_url == f"https://notify.example.invalid/api/v1/{SECRET}"
    output = capsys.readouterr().out
    assert "brrr: delivered" in output
    assert SECRET not in output


def test_test_alert_through_file_transport(home: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("CANARYEW_SMTP_MODE", "file")
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["test-alert"]) == 0
    assert "smtp: delivered" in capsys.readouterr().out

    outbox = (home / "outbox.log").read_text()
    # Unmistakably a drill, and the marker leads so a phone preview shows it.
    assert "THIS IS A TEST" in outbox
    assert outbox.index("THIS IS A TEST") < outbox.index("Verification:")
    # The test alert carries the verification phrase like a real one.
    assert "Verification:" in outbox


def test_test_alert_reflects_the_configured_tier(home: Path, monkeypatch, capsys) -> None:
    """The drill must show what a real alert looks like, or it proves nothing
    about whether full detail actually arrives."""
    from canaryew.service import TEST_TXID

    monkeypatch.setenv("CANARYEW_SMTP_MODE", "file")
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0

    # minimal: no txid, no amounts
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["test-alert"]) == 0
    minimal = (home / "outbox.log").read_text()
    assert TEST_TXID not in minimal
    (home / "outbox.log").unlink()

    # full without PGP is clamped to standard: buckets, still no txid
    monkeypatch.setenv("CANARYEW_REDACTION", "full")
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["test-alert"]) == 0
    clamped = (home / "outbox.log").read_text()
    assert TEST_TXID not in clamped
    assert "BTC" in clamped        # value bucket appears at standard


def test_test_alert_with_no_channels_fails(home: Path, monkeypatch, capsys) -> None:
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0
    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["test-alert"]) == 1
    assert "No channels" in capsys.readouterr().err


# ------------------------------------------------------------------ status --- #

def test_status_falls_back_to_snapshot(home: Path, monkeypatch, capsys) -> None:
    from canaryew.snapshot import write_snapshot

    write_snapshot(home / "status.json", {"locked": True, "boot_count": 2})
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "snapshot" in out and '"locked": true' in out


def test_status_with_nothing_available(home: Path, capsys) -> None:
    assert cli.main(["status"]) == 1
