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

def test_test_alert_through_file_transport(home: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("CANARYEW_SMTP_MODE", "file")
    feed_passphrases(monkeypatch, PASSPHRASE, PASSPHRASE)
    assert cli.main(["init"]) == 0

    feed_passphrases(monkeypatch, PASSPHRASE)
    assert cli.main(["test-alert"]) == 0
    assert "smtp: delivered" in capsys.readouterr().out

    outbox = (home / "outbox.log").read_text()
    assert "TEST" in outbox
    # The test alert carries the verification phrase like a real one.
    assert "Verification:" in outbox


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
