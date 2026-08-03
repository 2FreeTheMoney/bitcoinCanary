"""Offline enrollment: export parsing and sealed watchfile round-trip."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from canaryew import secrets
from canaryew.enroll import (
    EnrollmentError,
    build_watch,
    parse_utxo_export,
    read_watchfile,
    write_watchfile,
)

PASSPHRASE = "a-correct-horse-battery-staple-for-tests"
TXID_A = "a" * 64
TXID_B = "b" * 64


def test_parses_sparrow_style_csv() -> None:
    export = (
        "Date,Output,Address,Label,Value\n"
        f"2026-01-04,{TXID_A}:0,bc1qexample,cold-vault,0.50000000\n"
        f"2026-02-11,{TXID_B}:3,bc1qother,,1.25000000\n"
    )
    utxos = parse_utxo_export(export)
    assert len(utxos) == 2
    assert utxos[0].txid == TXID_A and utxos[0].vout == 0
    assert utxos[0].value_sat == 50_000_000   # BTC decimal -> sats
    assert utxos[0].label == "cold-vault"
    assert utxos[1].vout == 3 and utxos[1].value_sat == 125_000_000


def test_integer_values_are_read_as_sats() -> None:
    """No decimal point means sats; misreading them as BTC would inflate by 1e8."""
    utxos = parse_utxo_export(f"Output,Value\n{TXID_A}:0,250000\n")
    assert utxos[0].value_sat == 250_000


def test_parses_json_export() -> None:
    export = json.dumps(
        [{"txid": TXID_A, "vout": 2, "value": "0.01", "label": "canary"}]
    )
    utxos = parse_utxo_export(export)
    assert utxos[0].vout == 2
    assert utxos[0].value_sat == 1_000_000
    assert utxos[0].label == "canary"


def test_parses_bare_outpoint_list() -> None:
    utxos = parse_utxo_export(f"{TXID_A}:0\n{TXID_B}:1\n")
    assert [u.outpoint for u in utxos] == [f"{TXID_A}:0", f"{TXID_B}:1"]


def test_column_order_is_irrelevant() -> None:
    """Detection is by content, not header position."""
    utxos = parse_utxo_export(f"Label,Value,Outpoint\nvault,0.1,{TXID_A}:7\n")
    assert utxos[0].vout == 7 and utxos[0].value_sat == 10_000_000


def test_parses_bip329_output_records_only() -> None:
    """A BIP-329 label export: only type:'output' lines carry outpoints.
    tx/addr/xpub lines must be ignored -- especially the xpub."""
    export = "\n".join([
        json.dumps({"type": "xpub", "ref": "xpub6Bx8y8...", "label": "keystore-a"}),
        json.dumps({"type": "tx", "ref": "b" * 64, "label": "exchange withdrawal",
                    "height": 728000, "value": 999927, "origin": "wpkh([deadbeef...])"}),
        json.dumps({"type": "addr", "ref": "bc1qexampleaddr...", "label": "trade",
                    "keypath": "/0/0"}),
        json.dumps({"type": "output", "ref": f"{TXID_A}:1", "value": 250000,
                    "label": "canary-tribute"}),
        json.dumps({"type": "output", "ref": f"{TXID_B}:0", "value": 50000}),
    ])
    utxos = parse_utxo_export(export)
    assert [(u.txid, u.vout) for u in utxos] == [(TXID_A, 1), (TXID_B, 0)]
    assert utxos[0].value_sat == 250_000        # BIP-329 values are sats
    assert utxos[0].label == "canary-tribute"
    assert utxos[1].label is None


def test_bip329_keystore_label_never_reaches_the_watchfile(tmp_path: Path) -> None:
    """The xpub line's label is the operator's keystore name. Like the xpub
    itself, it must never enter the watchfile -- only output records are read."""
    export = "\n".join([
        json.dumps({"type": "xpub", "ref": "xpub6Bx8y8...", "label": "my-keystore-name"}),
        json.dumps({"type": "output", "ref": f"{TXID_A}:0", "value": 1000,
                    "label": "coin-label"}),
    ])
    utxos = parse_utxo_export(export)
    watch = build_watch(utxos, "neutral-name")
    path = tmp_path / "w.watchfile"
    write_watchfile(path, watch, PASSPHRASE)

    imported, _ = read_watchfile(path, PASSPHRASE)
    body = json.dumps(
        [{"txid": o.txid, "vout": o.vout} for o in imported.outputs]
    ) + imported.label
    assert "my-keystore-name" not in body
    assert "coin-label" not in body        # per-output labels are dropped too
    assert imported.label == "neutral-name"  # only the operator's --label survives


def test_bip329_without_output_records_gives_guidance() -> None:
    """tx/addr/xpub labels alone cannot identify UTXOs; say so, usefully."""
    export = "\n".join([
        json.dumps({"type": "xpub", "ref": "xpub6Bx8y8...", "label": "wallet"}),
        json.dumps({"type": "tx", "ref": "b" * 64, "label": "some tx"}),
    ])
    with pytest.raises(EnrollmentError, match="no 'output' records"):
        parse_utxo_export(export)


def test_single_line_bip329_output_parses() -> None:
    """One output record is a complete, valid JSON document on its own."""
    export = json.dumps({"type": "output", "ref": f"{TXID_A}:0", "value": 1000})
    utxos = parse_utxo_export(export)
    assert utxos[0].outpoint == f"{TXID_A}:0"


def test_bip329_sniff() -> None:
    from canaryew.enroll import looks_like_bip329

    assert looks_like_bip329('{"type":"tx","ref":"abc"}\n{"type":"addr"}')
    assert not looks_like_bip329(f"{TXID_A}:0\n")
    assert not looks_like_bip329('[{"txid":"abc","vout":0}]')
    assert not looks_like_bip329("")


def test_rejects_unparseable_input() -> None:
    with pytest.raises(EnrollmentError, match="No outpoints"):
        parse_utxo_export("just some prose with no outpoints in it")
    with pytest.raises(EnrollmentError, match="empty"):
        parse_utxo_export("   ")


def test_build_watch_deduplicates_and_rejects_empty() -> None:
    utxos = parse_utxo_export(f"{TXID_A}:0\n{TXID_A}:0\n{TXID_B}:1\n")
    watch = build_watch(utxos, "vault-cosigner-a")
    assert watch.total_outputs == 2
    assert watch.source == "offline"
    with pytest.raises(EnrollmentError, match="no outputs"):
        build_watch([], "empty")


# ----------------------------------------------------- node verification --- #

def test_verify_partitions_unspent_and_history() -> None:
    from conftest import FakeRpc
    from canaryew.enroll import verify_against_node

    watch = build_watch(parse_utxo_export(f"{TXID_A}:0\n{TXID_A}:1\n{TXID_B}:0\n"), "v")
    result = verify_against_node(FakeRpc(spent={f"{TXID_A}:1"}), watch)

    assert [o.outpoint for o in result.unspent] == [f"{TXID_A}:0", f"{TXID_B}:0"]
    assert [o.outpoint for o in result.already_spent] == [f"{TXID_A}:1"]
    assert result.block_height == 900_000


def test_verify_requires_synced_node() -> None:
    from conftest import FakeRpc
    from canaryew.enroll import verify_against_node

    watch = build_watch(parse_utxo_export(f"{TXID_A}:0\n"), "v")
    with pytest.raises(EnrollmentError, match="not synced"):
        verify_against_node(FakeRpc(synced=False), watch)


# ------------------------------------------------------------- watchfile --- #

def test_watchfile_roundtrip_and_fingerprint(tmp_path: Path) -> None:
    watch = build_watch(parse_utxo_export(f"{TXID_A}:0\n{TXID_B}:1\n"), "vault")
    path = tmp_path / "vault.watchfile"

    exported = write_watchfile(path, watch, PASSPHRASE)
    imported, verified = read_watchfile(path, PASSPHRASE)

    assert exported == verified          # transfer integrity check
    assert imported.watch_id == watch.watch_id
    assert imported.total_outputs == 2
    assert path.stat().st_mode & 0o077 == 0


def test_watchfile_contains_no_key_material(tmp_path: Path) -> None:
    """The transfer artifact must be safe to move over untrusted media."""
    watch = build_watch(parse_utxo_export(f"{TXID_A}:0\n"), "vault-cosigner-a")
    path = tmp_path / "vault.watchfile"
    write_watchfile(path, watch, PASSPHRASE)

    raw = path.read_text()
    assert "xpub" not in raw and "wsh(" not in raw and "bc1q" not in raw
    assert TXID_A not in raw             # outpoints are sealed, not cleartext
    assert "vault-cosigner-a" not in raw  # label is sealed too


def test_unwritable_output_path_fails_with_guidance(tmp_path: Path) -> None:
    """The service user often cannot write the invoking cwd; the failure must
    be an actionable EnrollmentError, never a raw PermissionError traceback."""
    readonly = tmp_path / "ro"
    readonly.mkdir()
    readonly.chmod(0o500)
    try:
        watch = build_watch(parse_utxo_export(f"{TXID_A}:0\n"), "vault")
        with pytest.raises(EnrollmentError, match="absolute output path"):
            write_watchfile(readonly / "sub" / "w.watchfile", watch, PASSPHRASE)
    finally:
        readonly.chmod(0o700)


def test_watchfile_rejects_wrong_passphrase(tmp_path: Path) -> None:
    watch = build_watch(parse_utxo_export(f"{TXID_A}:0\n"), "vault")
    path = tmp_path / "vault.watchfile"
    write_watchfile(path, watch, PASSPHRASE)

    with pytest.raises(secrets.SecretsError):
        read_watchfile(path, "wrong-passphrase")


def test_watchfile_detects_tampering(tmp_path: Path) -> None:
    watch = build_watch(parse_utxo_export(f"{TXID_A}:0\n"), "vault")
    path = tmp_path / "vault.watchfile"
    write_watchfile(path, watch, PASSPHRASE)

    payload = json.loads(path.read_text())
    blob = bytearray(__import__("base64").b64decode(payload["body"]))
    blob[-1] ^= 0x01
    payload["body"] = __import__("base64").b64encode(bytes(blob)).decode()
    path.write_text(json.dumps(payload))

    with pytest.raises(secrets.SecretsError):
        read_watchfile(path, PASSPHRASE)
