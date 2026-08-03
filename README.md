# canaryEW

Early-warning service for self-custodied Bitcoin. Detects unauthorized movement
of coins under watched keys and notifies you through channels an attacker cannot
silently suppress.

Built to run on a headless Debian-family node alongside Bitcoin Core, reading
the node over `cookie`-file RPC.

## The one idea worth understanding

**canaryEW never stores an xpub.**

Detecting "funds moved" does not require one. It requires knowing which outputs
you own and asking whether they are still unspent — which Bitcoin Core answers
from an outpoint alone:

```
gettxout <txid> <vout>   →  object = unspent      →  null = spent
```

Discovering which outputs you own is your *wallet software's* job, done on a
trusted machine: enrollment consumes an outpoint-bearing export (Sparrow's
BIP-329 labels file, a CSV, or a bare `txid:vout` list) and canaryEW never
handles the xpub in any form. The always-on monitor holds only outpoints.
(A deferred on-host enrollment mode would use the xpub once, in a short-lived
process, then discard it — see DESIGN 2b.)

An attacker who fully compromises the host therefore gets a bounded snapshot of
which coins existed when you enrolled — not the ability to derive your future
addresses, reconstruct your wallet, or watch you forever.

## Silence is the alarm

The obvious attack on any alerting system is to kill it before stealing. canaryEW
inverts that: it emits authenticated heartbeats on a schedule, each carrying a
monotonic counter and an HMAC keyed from your passphrase.

- Killing the service stops the heartbeat → **you notice**
- Replaying an old heartbeat has a stale counter → **you notice**
- Forging a reassuring "all clear" requires the HMAC key → **not available externally**

Your operating rule becomes one line: *if the heartbeat stops, treat it as an
incident until proven otherwise.*

## Status

Implemented and tested end to end:

| Component | State |
|---|---|
| Key hierarchy (Argon2id → HKDF → state/HMAC/phrase) | done, tested |
| Sealed state store (ChaCha20-Poly1305, atomic writes) | done, tested |
| Bitcoin Core RPC client (stdlib-only, cookie auth) | done |
| Detection loop + failure-direction rules | done, tested |
| Offline enrollment (Sparrow export → sealed watchfile) | done, tested |
| Channels: PGP-encrypted SMTP + brrr.now webhook | done, tested |
| Dispatcher (fan-out, retry, permanent/transient) | done, tested |
| Heartbeat emitter (domain-separated MAC, save-before-send) | done, tested |
| Unlock lifecycle + control socket + LOCKED boot notice | done, tested |
| Operator CLI (init/enroll/import/unlock/status/ack/test-alert) | done, tested |
| Keyless FastAPI status surface | done, tested |
| systemd units + deploy.sh + nginx | done |
| On-host enrollment (`scantxoutset`) | deferred by decision |

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and
[`docs/RUNBOOK.md`](docs/RUNBOOK.md) for operator setup, including the
Sparrow UTXO export flow and what to expect from it.

## Quick start (development)

```bash
python3 -m venv .venv
./.venv/bin/pip install -e '.[dev]'
./.venv/bin/python -m pytest tests/ -q
```

## Threat model, stated honestly

| Adversary | Outcome |
|---|---|
| Steals the disk or a backup | Gets ciphertext. Sealed store, key not on disk. |
| Compromises the mail server | Gets ciphertext. Alerts are PGP-encrypted to your key. |
| Phishes you with a fake alert | Fails — no verification phrase. |
| Kills the service to stay quiet | Heartbeat stops. You notice. |
| **Gets root on the running host** | **Reads outpoints and keys from memory. Not defended.** |

No userspace design resists root on a live host. What this architecture buys is
that the loss is bounded to outpoints rather than keys, and that suppressing the
alarm is itself detectable.

## Design decisions worth knowing

- **Stdlib-only RPC client.** A JSON-RPC POST with basic auth does not justify an
  HTTP dependency in a security tool.
- **Deliberately standalone.** Sharing a process, database, or unix user with
  any larger application would subsume canaryEW's threat model into that
  app's. Patterns may be shared; runtime is not. Optional one-way event
  emission only.
- **Never auto-clear a flagged output.** A reorg that restores a spent output is
  recorded, not treated as an all-clear — an attempted spend is signal.
- **Unreachable node is never read as a spend.** Transport failure raises a
  degraded condition instead.

## License

MIT — see [`LICENSE`](LICENSE).
