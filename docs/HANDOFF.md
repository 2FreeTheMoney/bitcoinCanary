# canaryEW — Handoff

Status as of 2026-08-03 (deployed and running). Read this plus `docs/DESIGN.md`
before continuing. Operator-facing setup lives in `docs/RUNBOOK.md`.

## What this is

Early-warning service for a headless Bitcoin node. Detects unauthorized
spends from watched wallets and notifies through channels an attacker cannot
silently suppress. Motivated by the class of incident where a hardware-wallet
seed-generation weakness puts existing keys at risk: the coins cannot be
moved instantly, so early detection of the first unauthorized spend is worth
real engineering.

## The invariant that defines the project

**No xpub or descriptor is ever written to disk or held by the long-running
monitor.** Detection needs only outpoints, because `gettxout <txid> <vout>`
returns null when spent. The xpub is needed once at enrollment (offline, on the
trusted machine), then discarded.

If a proposed feature seems to need the xpub at runtime, the feature is wrong.
Supporting rules and hard-won platform quirks are in `AGENTS.md`.

## Decisions already made — do not relitigate

| Decision | Choice | Why |
|---|---|---|
| Secrets at rest | **Passphrase on start** | Nothing on disk can open the store. Cost paid by the LOCKED boot notice (DESIGN S6). |
| Second channel | **brrr.now** (not brrr.com — fabric company) | `critical` interruption level bypasses DND; webhook secret is the whole credential, works pre-unlock. |
| brrr secret home | **Env file, not sealed store** | Must be usable pre-unlock. One home only; `StoreState.webhook_secret` was removed. |
| Enrollment | **Offline via Sparrow export** | xpub never reaches the node. On-host `scantxoutset` path still deferred. |
| PGP | **`gpg` on device, public key only** | No secret material in that channel; service-owned keyring under `CANARYEW_GNUPG_HOME`. |
| Service control | **Unix socket, not localhost HTTP** | Filesystem is the auth layer; passphrase never on a TCP stack. |
| Status surface | **Keyless process reading a snapshot file** | Web compromise yields nothing; monitor has zero network listeners. |
| Heartbeat semantics | **No heartbeat while blind; save-before-send** | A heartbeat asserts "I checked"; seq monotonicity survives crashes. |
| Co-resident apps | **Not integrated** at process/data layer | Patterns shared, runtime separate. |
| HTTP | **stdlib only** for RPC and brrr | Small auditable dependency surface. |

## Built and tested (153 tests passing)

```
src/canaryew/
  secrets.py     Argon2id(256MiB) -> HKDF -> state key / HMAC key / phrase
  store.py       Sealed store; plaintext header (salt only) + sealed body
  node.py        Stdlib Bitcoin Core JSON-RPC, cookie auth re-read per call
  monitor.py     Detection loop; heartbeat_due keyed on last_heartbeat_at
  enroll.py      BIP-329/CSV/JSON/bare-list parser, sealed watchfile
  config.py      CANARYEW_* env config (EnvironmentFile convention)
  heartbeat.py   Domain-separated MAC build/verify, state summaries
  dispatch.py    Fan-out to all channels, retry policy, INFO=1 attempt
  unlock.py      LOCKED->unlocked manager, boot counter file
  control.py     Unix-socket control server/client (unlock/ack/status)
  service.py     Run loop: pass -> alerts -> heartbeat -> save -> snapshot
  snapshot.py    Redacted status file bridging monitor -> keyless web
  cli.py         init/enroll/import/unlock/status/ack/set-smtp-password/
                 pgp-import/test-alert/run
  notify/base.py Notification model, redaction tiers, renderers
  notify/brrr.py brrr.now channel, severity -> interruption level
  notify/smtp.py smtp|console|file|disabled, production mailer hardening
  notify/pgp.py  gpg wrapper, public-key-only service keyring
  web/app.py     FastAPI keyless status surface (health/status/heartbeat)
deploy/          canaryew.service, canaryew-web.service, env example,
                 nginx subpath snippet, deploy.sh
docs/RUNBOOK.md  Operator setup, enrollment expectations, drills,
                 deliverability and planned-maintenance guidance
```

Run tests: `./.venv/bin/python -m pytest tests/ -q`

## Verified live on a real node (2026-08-03)

First end-to-end deployment is done, and these are no longer theoretical:

- **BIP-329 enrollment → import verification → monitoring.** A 19-output
  labels export enrolled; import pruned 9 already-spent outputs as wallet
  history and watched the 10 still unspent, matching the wallet exactly.
  Sparrow's BIP-329 labels export is confirmed to exist and to include spent
  outputs; a dedicated UTXO-set CSV export is NOT confirmed in current
  Sparrow — the CSV parser stays for other tools, but BIP-329 is the primary
  documented path.
- **PGP-encrypted SMTP delivery**, with the password from the sealed store.
- **brrr push at `critical`**, confirmed to break through a phone's silent
  mode. The full payload (`thread_id`/`sound`/`volume`) is accepted in
  practice, not just the minimal corroborated core.
- **Detection loop against live bitcoind**, cookie auth via a shared group,
  snapshot and control socket working.
- **Scheduled heartbeats arriving on both channels** -- the dead-man switch
  is armed, not just implemented.
- **Inbox (not Junk) mail delivery**, after fixing HELO/Message-ID/Date; see
  runbook section 8 for the deliverability checklist.

Still unexercised in production: the reboot drill (runbook section 9 —
LOCKED notice, then unlock), a real spend alert, and `ack` + re-enrollment.

## Sensible next steps, in rough order

1. **Run the reboot drill** (runbook section 9): confirm the LOCKED notice
   arrives over the webhook before unlock, since that notice is what makes
   passphrase-on-start survivable.
2. **`canaryew verify-heartbeat`** — paste seq/ts/mac (+ digest from
   `/api/heartbeat/latest`) and check it offline. The primitives exist in
   `heartbeat.py`; only the CLI surface is missing.
3. **Watch removal / replacement** (`canaryew remove-watch`) to complete the
   re-enrollment loop without manual store surgery.
4. **tpm2 unlock provider** — the provider seam exists conceptually
   (DESIGN S6 table); nothing is pluggable in code yet.
5. **On-host enrollment** via `scantxoutset` if the operator ever wants it —
   `node.scan_txout_set` and `descriptor_info` are already implemented and
   deliberately unused.
6. Consider a `Restart=` watchdog integration (systemd `WatchdogSec` +
   `sd_notify`) so a hung (not dead) loop also gets restarted.

## Operator-specific context

Lives in `docs/PRIVATE-NOTES.md` (gitignored) — deployment specifics, canary
tribute placement, and cross-repo pattern sources do not belong in a public
repository.
