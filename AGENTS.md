# Agent Learnings — canaryEW

## Non-negotiable invariants

These are the reason the project exists. Changing any of them requires an
explicit decision recorded in `docs/DESIGN.md`, not an incidental refactor.

1. **No xpub or descriptor is ever written to disk, or held by the long-running
   monitor.** Enrollment is a separate short-lived process. If a feature seems to
   need the xpub at runtime, the feature is wrong.
2. **The monitor's steady state uses only outpoints** via `gettxout`.
3. **Never auto-clear a flagged output.** Sticky until operator acknowledgement.
4. **Transport failure is never a spend.** `NodeUnavailable` → degraded, never
   a missing output.
5. **Silence is the alarm.** Any change that could stop heartbeats without
   alerting is a regression.

## Conventions

- Python 3.10+, always a local `.venv` — never the system interpreter.
- `from __future__ import annotations` in every module; full type hints.
- Deployment shape: systemd + `uvicorn --factory`, dedicated unix user,
  `EnvironmentFile`, nginx subpath proxy, `deploy/deploy.sh`.
- Stdlib over dependencies for anything security-critical. The RPC client is
  stdlib-only on purpose.

## Crypto notes

- Argon2id at 256 MiB / t=3 / p=4 measures ~0.25 s on a development laptop.
  It runs at unlock only, never in the poll loop.
- Wordlist is exactly 256 entries so `byte % len` is unbiased. If you edit it,
  keep the count at 256 and re-check for duplicates.
- `secrets.mac()` length-prefixes its parts; naive concatenation would let
  `("ab","c")` and `("a","bc")` collide.
- Python cannot reliably zero `bytes`. `wipe()` is best-effort on `bytearray`
  only, and this limitation is documented rather than hidden.

## Architecture decisions made during build-out

- **The heartbeat clock is `last_heartbeat_at`, never `last_check_at`.** The
  first version measured against the pass timestamp, which every poll
  refreshes, so the second heartbeat would never come due. There is a
  dedicated regression test.
- **The brrr webhook secret lives in the env file, not the sealed store.**
  One home only: it must work pre-unlock for the LOCKED notice.
  `StoreState.webhook_secret` was removed for this reason.
- **Control is a unix socket (0600), not HTTP.** `unlock`/`ack`/`status`
  ride line-delimited JSON; the handler must never echo the request (it can
  contain the passphrase) into an error.
- **The web status app is keyless.** It reads only the redacted snapshot
  file. Do not give it the store path, the socket, or RPC credentials —
  breaking that property is a regression, not a convenience.
- **No heartbeat while blind.** Degraded or unsynced passes skip the
  heartbeat; save-before-send ordering protects seq monotonicity.
- **Degraded alerts fire after a sustained grace (default 30 min), once per
  outage.** Recovery re-arms.

## Platform quirks that cost time

- AF_UNIX socket paths are capped (~104 bytes on macOS). pytest `tmp_path`
  can exceed it — control-socket and gpg tests use short `mkdtemp` dirs.
- gpg contacts its agent (socket inside `--homedir`) even for public-key
  imports; batch key generation needs `--pinentry-mode loopback`.
- `socketserver.shutdown()` deadlocks if `serve_forever()` was never
  entered; `ControlServer.stop()` guards on the thread having started.

## Testing

- `FakeRpc` in `tests/test_core.py` is scriptable for spent/synced/unreachable.
- Cover failure *directions*, not just happy paths: unsynced node, unreachable
  node, and reorg-restores-output all have dedicated tests.
