"""Operator CLI.

Commands that touch the sealed store directly (``init``, ``import``,
``set-smtp-password``) refuse to run while the service is up, because the
running service holds its own decrypted copy of the state and would clobber
the change on its next save. The control socket's existence is the tell.

The passphrase is always read via ``getpass`` (never argv, which leaks into
shell history and ``ps``), except for ``run --passphrase-file`` and the
systemd credential path, which exist for supervised starts.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from pathlib import Path

from canaryew import enroll as enroll_mod
from canaryew.config import Config, load_config
from canaryew.control import ControlError, send_command
from canaryew.dispatch import Dispatcher
from canaryew.node import BitcoinRpc, NodeError, NodeUnavailable
from canaryew.secrets import SecretsError
from canaryew.snapshot import read_snapshot
from canaryew.store import StateStore, StoreError


class CliError(RuntimeError):
    """Operator-facing failure; printed without a traceback."""


def _prompt_passphrase(confirm: bool = False) -> str:
    passphrase = getpass.getpass("Passphrase: ")
    if not passphrase:
        raise CliError("Passphrase must not be empty.")
    if confirm and getpass.getpass("Confirm passphrase: ") != passphrase:
        raise CliError("Passphrases do not match.")
    return passphrase


def _refuse_if_service_running(config: Config, action: str) -> None:
    if config.control_socket_path.exists():
        raise CliError(
            f"The canaryew service appears to be running "
            f"(control socket {config.control_socket_path} exists). "
            f"Stop it before running '{action}': the running service holds its "
            "own copy of the state and would overwrite this change."
        )


# ------------------------------------------------------------------ commands --


def cmd_init(config: Config, args: argparse.Namespace) -> int:
    store = StateStore(config.state_path)
    print(f"Creating sealed store at {config.state_path}")
    print("Choose the passphrase you will memorize. It is not recoverable.")
    passphrase = _prompt_passphrase(confirm=True)
    keys, _state = store.initialize(passphrase)
    print()
    print("Store created.")
    print(f"  Verification phrase:  {keys.verification_phrase}")
    print(f"  Key fingerprint:      {keys.fingerprint()}")
    print()
    print("MEMORIZE the verification phrase. Every genuine canaryEW alert will")
    print("contain it. An alert without it is a fake.")
    return 0


def cmd_enroll(config: Config, args: argparse.Namespace) -> int:
    export_path = Path(args.export)
    try:
        text = export_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"Unable to read export {export_path}: {exc}") from exc

    utxos = enroll_mod.parse_utxo_export(text)
    watch = enroll_mod.build_watch(utxos, args.label, watch_id=args.watch_id)

    if enroll_mod.looks_like_bip329(text):
        print("NOTE: this is a BIP-329 label export; only its 'output' records are used.")
        print("  - It may include already-spent outputs (wallet history). 'canaryew")
        print("    import' verifies against the node and drops those; the still-unspent")
        print("    count it reports must match your wallet's UTXO list exactly.")
        print("  - This file contains your xpub. Keep it on the trusted machine and")
        print("    delete it once the watchfile is written.")
        print()

    total_sat = sum(u.value_sat for u in utxos)
    print(f"Parsed {len(utxos)} outpoints from {export_path.name}")
    if total_sat:
        print(f"Total declared value: {total_sat:,} sat ({total_sat / 1e8:.8f} BTC)")
    else:
        print("No values found in the export; alerts will omit value buckets.")

    print()
    print("This passphrase seals the watchfile for transfer. Use your canaryEW")
    print("store passphrase so the node can open it at import time.")
    passphrase = _prompt_passphrase(confirm=True)
    fingerprint = enroll_mod.write_watchfile(args.out, watch, passphrase)
    print()
    print(f"Watchfile written: {args.out}")
    print(f"  Watch id:     {watch.watch_id}")
    print(f"  Outputs:      {watch.total_outputs}")
    print(f"  Fingerprint:  {fingerprint}")
    print()
    print("Copy the file to the node, then run 'canaryew import' there and")
    print("confirm the fingerprint matches what is printed above.")
    return 0


def _make_rpc(config: Config) -> BitcoinRpc:
    return BitcoinRpc(
        config.bitcoin_rpc_url,
        cookie_file=config.bitcoin_rpc_cookie_file,
        rpc_user=config.bitcoin_rpc_user or None,
        rpc_password=config.bitcoin_rpc_password or None,
    )


def cmd_import(config: Config, args: argparse.Namespace) -> int:
    _refuse_if_service_running(config, "import")
    store = StateStore(config.state_path)
    if not store.exists():
        raise CliError(f"No store at {config.state_path}. Run 'canaryew init' first.")

    passphrase = _prompt_passphrase()
    watch, fingerprint = enroll_mod.read_watchfile(args.watchfile, passphrase)
    total = watch.total_outputs

    if not args.no_verify:
        # Prune wallet history before anything is watched: exports routinely
        # contain already-spent outputs, and each one would fire a false SPEND
        # alert on the first pass. Only unwatched outputs may ever be pruned.
        try:
            result = enroll_mod.verify_against_node(_make_rpc(config), watch)
        except NodeUnavailable as exc:
            raise CliError(
                f"Cannot reach bitcoind to verify outputs: {exc}\n"
                "Start the node, or use --no-verify to import unchecked "
                "(already-spent outputs will then alert on the first pass)."
            ) from exc
        except NodeError as exc:
            raise CliError(f"Node error during verification: {exc}") from exc

        print(f"Verified against the node at block {result.block_height:,}:")
        print(f"  {total} outputs in the watchfile")
        print(f"  {len(result.unspent)} still unspent -> will be watched "
              f"({result.unspent_value_sat:,} sat)")
        if result.already_spent:
            print(f"  {len(result.already_spent)} already spent -> dropped as wallet history:")
            for output in result.already_spent:
                print(f"    {output.outpoint}")
        if not result.unspent:
            raise CliError(
                "Every output in this watchfile is already spent. Nothing to "
                "watch -- re-export the current UTXO set and enroll again."
            )
        watch.outputs = result.unspent

    try:
        keys, state = store.unlock(passphrase)
    except SecretsError as exc:
        raise CliError(str(exc)) from exc

    if state.watch(watch.watch_id) is not None:
        raise CliError(
            f"Watch id {watch.watch_id!r} already exists in the store. "
            "Re-enrolling a wallet replaces it: remove the old watch first "
            "or export with a new --watch-id."
        )

    state.watches.append(watch)
    store.save(keys, state)
    print(f"Imported watch {watch.watch_id!r} ({watch.total_outputs} outputs).")
    print(f"  Fingerprint verified: {fingerprint}")
    print("Restart or unlock the service to begin monitoring it.")
    return 0


def cmd_unlock(config: Config, args: argparse.Namespace) -> int:
    passphrase = _prompt_passphrase()
    response = send_command(
        config.control_socket_path,
        {"command": "unlock", "passphrase": passphrase},
        timeout=120.0,  # Argon2id on small hardware can take a while
    )
    if not response.get("ok"):
        raise CliError(response.get("error", "unlock failed"))
    if response.get("already_unlocked"):
        print("Service is already unlocked.")
        return 0
    print("Unlocked. Monitoring is starting.")
    print(f"  Verification phrase: {response.get('verification_phrase')}")
    print("Confirm this is YOUR phrase. If it is not, you unlocked the wrong store.")
    return 0


def cmd_status(config: Config, args: argparse.Namespace) -> int:
    payload: dict | None
    try:
        response = send_command(config.control_socket_path, {"command": "status"})
        payload = response.get("status") if response.get("ok") else None
        source = "service"
    except ControlError:
        payload = read_snapshot(config.snapshot_path)
        source = "snapshot (service not reachable)"

    if payload is None:
        print("No status available. Is the service installed and running?")
        return 1
    print(f"canaryEW status [{source}]")
    print(json.dumps(payload, indent=2))
    return 0


def cmd_ack(config: Config, args: argparse.Namespace) -> int:
    response = send_command(
        config.control_socket_path, {"command": "ack", "watch_id": args.watch}
    )
    if not response.get("ok"):
        raise CliError(response.get("error", "ack failed"))
    count = response.get("acknowledged", 0)
    if count:
        print(f"Acknowledged {count} flagged output(s).")
        print("They remain recorded as spent; re-enroll the wallet to watch its new outputs.")
    else:
        print("Nothing to acknowledge.")
    return 0


def cmd_set_smtp_password(config: Config, args: argparse.Namespace) -> int:
    _refuse_if_service_running(config, "set-smtp-password")
    store = StateStore(config.state_path)
    if not store.exists():
        raise CliError(f"No store at {config.state_path}. Run 'canaryew init' first.")
    passphrase = _prompt_passphrase()
    try:
        keys, state = store.unlock(passphrase)
    except SecretsError as exc:
        raise CliError(str(exc)) from exc
    password = getpass.getpass("SMTP password (empty to clear): ")
    state.smtp_password = password or None
    store.save(keys, state)
    print("SMTP password " + ("stored in the sealed store." if password else "cleared."))
    return 0


def cmd_pgp_import(config: Config, args: argparse.Namespace) -> int:
    from canaryew.notify.pgp import PgpEncryptor, PgpError

    if not config.pgp_recipient:
        raise CliError("Set CANARYEW_PGP_RECIPIENT before importing a key.")
    if config.gnupg_home is None:
        raise CliError("CANARYEW_GNUPG_HOME is not set.")
    try:
        armored = Path(args.key).read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"Unable to read key file {args.key}: {exc}") from exc

    encryptor = PgpEncryptor(config.pgp_recipient, config.gnupg_home)
    try:
        encryptor.import_public_key(armored)
        if not encryptor.can_encrypt():
            raise CliError(
                f"Key imported, but encryption to {config.pgp_recipient!r} failed. "
                "Does the recipient match the key's uid/fingerprint?"
            )
    except PgpError as exc:
        raise CliError(str(exc)) from exc
    print(f"Public key imported. Encryption to {config.pgp_recipient} verified.")
    return 0


def cmd_test_alert(config: Config, args: argparse.Namespace) -> int:
    """Send a real CRITICAL through every configured channel, deliberately."""
    from canaryew.notify.base import Channel
    from canaryew.notify.pgp import PgpEncryptor
    from canaryew.notify.smtp import SmtpChannel
    from canaryew.notify.brrr import BrrrChannel
    from canaryew.service import make_notification_test

    store = StateStore(config.state_path)
    if not store.exists():
        raise CliError(f"No store at {config.state_path}. Run 'canaryew init' first.")
    passphrase = _prompt_passphrase()
    try:
        keys, state = store.unlock(passphrase)
    except SecretsError as exc:
        raise CliError(str(exc)) from exc

    channels: list[Channel] = []
    encryptor = None
    if config.pgp_recipient and config.gnupg_home:
        encryptor = PgpEncryptor(config.pgp_recipient, config.gnupg_home)
    smtp = SmtpChannel(config.smtp, state.smtp_password, encryptor=encryptor)
    if smtp.enabled:
        channels.append(smtp)
    elif config.smtp.mode != "disabled":
        print(f"SMTP channel disabled: {smtp.disabled_reason}")
    if config.brrr_secret:
        channels.append(BrrrChannel(config.brrr_secret))
    if not channels:
        raise CliError("No channels configured; nothing to test.")

    result = Dispatcher(channels).dispatch(make_notification_test(keys.verification_phrase))
    for outcome in result.outcomes:
        status = "delivered" if outcome.delivered else f"FAILED ({outcome.error})"
        print(f"  {outcome.channel}: {status}")
    if not result.delivered:
        raise CliError("Test alert was not delivered on any channel.")
    print()
    print("Check that the alert arrived AND that it broke through your phone's")
    print("Focus/DND (brrr critical alerts must be enabled on-device).")
    return 0


def cmd_run(config: Config, args: argparse.Namespace) -> int:
    from canaryew.service import Service

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    store = StateStore(config.state_path)
    if not store.exists():
        raise CliError(f"No store at {config.state_path}. Run 'canaryew init' first.")

    service = Service(config)
    service.startup()

    passphrase = _startup_passphrase(args)
    if passphrase is not None:
        response = service.handle_command(
            {"command": "unlock", "passphrase": passphrase}
        )
        if not response.get("ok"):
            raise CliError(f"Startup unlock failed: {response.get('error')}")

    try:
        service.run_loop()
    except KeyboardInterrupt:
        pass
    finally:
        service.shutdown()
    return 0


def _startup_passphrase(args: argparse.Namespace) -> str | None:
    """Passphrase for supervised starts: explicit file, or a systemd credential."""
    if getattr(args, "passphrase_file", None):
        try:
            return Path(args.passphrase_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise CliError(f"Unable to read passphrase file: {exc}") from exc
    credentials_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials_dir:
        candidate = Path(credentials_dir) / "canaryew.passphrase"
        if candidate.exists():
            return candidate.read_text(encoding="utf-8").strip()
    return None


# --------------------------------------------------------------------- main --


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="canaryew",
        description="Early-warning monitor for unauthorized Bitcoin spends.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("init", help="create the sealed store and verification phrase")

    p_enroll = sub.add_parser(
        "enroll", help="convert a Sparrow UTXO export into a sealed watchfile (trusted machine)"
    )
    p_enroll.add_argument("--export", required=True, help="Sparrow CSV/JSON export, or txid:vout lines")
    p_enroll.add_argument("--label", required=True, help="name for this watch, e.g. vault-cosigner-a")
    p_enroll.add_argument("--out", required=True, help="output watchfile path")
    p_enroll.add_argument("--watch-id", default=None, help="stable id (default: generated)")

    p_import = sub.add_parser("import", help="import a sealed watchfile into the store (node)")
    p_import.add_argument("--watchfile", required=True)
    p_import.add_argument(
        "--no-verify",
        action="store_true",
        help="skip checking outputs against the node (already-spent outputs "
        "will then alert on the first monitoring pass)",
    )

    sub.add_parser("unlock", help="unlock the running service with your passphrase")
    sub.add_parser("status", help="show service status")

    p_ack = sub.add_parser("ack", help="acknowledge flagged outputs after an authorized spend")
    p_ack.add_argument("--watch", required=True, help="watch id, or 'all'")

    sub.add_parser("set-smtp-password", help="store the SMTP password in the sealed store")

    p_pgp = sub.add_parser("pgp-import", help="import your PGP public key into the service keyring")
    p_pgp.add_argument("--key", required=True, help="ASCII-armored public key file")

    sub.add_parser("test-alert", help="send a labeled TEST alert through every channel")

    p_run = sub.add_parser("run", help="run the monitoring service (foreground)")
    p_run.add_argument(
        "--passphrase-file",
        default=None,
        help="unlock at start from this file (development; production uses "
        "'canaryew unlock' or a systemd credential)",
    )

    return parser


_COMMANDS = {
    "init": cmd_init,
    "enroll": cmd_enroll,
    "import": cmd_import,
    "unlock": cmd_unlock,
    "status": cmd_status,
    "ack": cmd_ack,
    "set-smtp-password": cmd_set_smtp_password,
    "pgp-import": cmd_pgp_import,
    "test-alert": cmd_test_alert,
    "run": cmd_run,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config()
        return _COMMANDS[args.subcommand](config, args)
    except (CliError, ControlError, StoreError, enroll_mod.EnrollmentError, SecretsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
