# canaryEW — Operator Runbook

Step-by-step setup and operations. Assumes a Debian-family node running
Bitcoin Core, and that you run Sparrow on a separate trusted machine.

Commands shown as `canaryew ...` mean, on the node:

```bash
sudo -u canaryew /opt/canaryew/.venv/bin/canaryew ...
```

(Alias that in your shell; the runbook keeps the short form.) The CLI reads
`/etc/canaryew/canaryew.env` automatically — the same file the systemd units
load — with real environment variables taking precedence, so hand-run
commands and the service always see the same configuration. Point
`CANARYEW_ENV_FILE` elsewhere for non-standard layouts.

---

## 1. What you are setting up

- A **monitor service** on the node that holds only *outpoints* — never an
  xpub, descriptor, or address — and asks bitcoind every 10 minutes whether
  each one is still unspent.
- A **positive heartbeat** every 6 hours. Your operating rule afterwards is
  one line: **if the heartbeat stops, treat it as an incident until proven
  otherwise.**
- Two alert channels: **PGP-encrypted email** (primary) and **brrr.now push**
  (secondary; also the only channel that works before you unlock the service
  after a reboot).
- A **verification phrase** — four words you memorize. Every genuine alert
  contains it. An alert without it is a fake, full stop.

## 2. Prerequisites

- Bitcoin Core running and synced, cookie-file RPC readable by the `canaryew`
  user (the deploy script adds it to the `bitcoin` group if one exists).
- The **brrr app** installed on your phone and a webhook secret from
  brrr.now.
- A **submission-only SMTP account** — an account that can send mail but has
  no mailbox worth stealing. Do not reuse a personal account password.
- Your **PGP public key** exported as an armored `.asc` file. Only the public
  key ever reaches the node.
- Sparrow, on your trusted machine, with the wallet(s) you want watched.

## 3. Install on the node

```bash
git clone <repo> canaryEW && cd canaryEW
sudo deploy/deploy.sh
sudoedit /etc/canaryew/canaryew.env    # fill in every section
```

The env file is `root:canaryew 0640`. It holds everything *except* the SMTP
password (sealed store, step 5) — including the brrr secret, which lives here
deliberately so the post-reboot LOCKED notice can be sent before unlock.

## 4. Initialize the sealed store

```bash
canaryew init
```

- Choose a strong passphrase you can type from memory. It is stretched with
  Argon2id (256 MiB) and **exists nowhere on disk, ever**. There is no
  recovery: a forgotten passphrase means re-initializing and re-enrolling.
- The command prints your **verification phrase** (4 words) and a key
  fingerprint. **Memorize the phrase.** Write it nowhere digital. It is what
  lets you trust an alert at 03:00 on a phone screen.

## 5. Configure the channels

**brrr.now** — put the webhook secret in `canaryew.env`. Then, on your phone:
**enable Critical Alerts for the brrr app.** Without that OS-level permission
a spend alert silently downgrades to an ordinary notification and will not
break through Do Not Disturb — which defeats the reason this channel exists.

**SMTP password** (goes in the sealed store, not the env file):

```bash
canaryew set-smtp-password
```

**PGP** — copy your public key to the node and import it into the
service-owned keyring:

```bash
canaryew pgp-import --key /tmp/mykey.asc && rm /tmp/mykey.asc
```

The import verifies a test encryption. From then on mail bodies are encrypted
before they touch SMTP: your mail server sees ciphertext and a generic
subject line.

### What leaves the host in an alert

Know exactly what each channel's transport can see:

| Channel | Transport sees | Content ceiling |
|---|---|---|
| brrr push | third-party servers + Apple/Google push: **full title and body in transit** | hard-capped at `standard` — txids and exact amounts are never sent here, regardless of config |
| Email + PGP | mail servers see a **generic subject and ciphertext only** | `full` allowed — detail is encrypted to your key |
| Email without PGP | mail servers see everything | treat like the push channel; configure PGP |

At the default `minimal` tier an alert carries: **the watch label you chose,
a count** ("2 of 11 outputs"), **block height, timestamp, and your
verification phrase**. `standard` adds coarse value buckets. `full` adds
txids and exact amounts.

**Raising the tier is safe once PGP is working**, because each channel is
rendered separately and clamped to what it can protect. With
`CANARYEW_REDACTION=full`:

- **PGP-encrypted email** carries full detail — txids you can paste into a
  block explorer and exact amounts, which is what you actually want at 03:00.
- **The push** is still clamped to `standard`: value buckets, never txids.
- **Unencrypted email** (no `CANARYEW_PGP_RECIPIENT`) is also clamped to
  `standard`. The cap follows the encryption, not the channel, so removing
  the PGP config quietly reduces detail instead of leaking it in the clear.

The residual trade-off: full-tier alerts put txids in your mailbox, so an
attacker who obtains both your mail *and* your PGP private key learns which
coins were yours. Against that, an alert you can act on immediately. With a
working PGP setup, `full` is the recommended tier.

Therefore: **the watch `--label` is the one string of yours that rides
through third-party infrastructure.** Choose labels you would be comfortable
reading aloud — `vault-a`, not your Sparrow keystore name or anything that
identifies the wallet's nature or size. Nothing else from your wallet files
survives enrollment: BIP-329 keystore labels, coin labels, addresses, and
xpubs are all dropped before the watchfile is built (there are tests pinning
this).

## 6. Enrollment — UTXO export and what to expect

Enrollment is the one step where key-derived information exists anywhere near
this system, so it is done **offline, on your trusted machine**, and the node
only ever receives sealed outpoints.

### 6a. Export from Sparrow: BIP-329 labels

On the trusted machine, per wallet, use Sparrow's **BIP-329 labels export**
(a line-delimited JSON file of `{"type": ..., "ref": ..., "label": ...}`
records).

**What canaryEW uses from it.** Only the `"type":"output"` records — their
`ref` is a `txid:vout` outpoint, which is exactly what a watch is made of.
`tx` records (txid only), `addr` records, and the `xpub` record cannot
identify UTXOs and are ignored. Values on output records are read as sats
(integers) or BTC (decimal point); they only feed the coarse "value bucket"
in `standard`-tier alerts, so enrollment succeeds without them.

**Spent outputs in the export are expected and handled.** Label exports
include wallet history — outputs that have long since been consolidated or
spent. That is fine: `canaryew import` verifies every output against the
node and drops already-spent ones before anything is watched (section 6c).

**This file contains your xpub.** It never goes near the node, stays off
cloud drives, and gets deleted once the watchfile is written.

Other accepted formats, if you have them from another tool or workflow: a
CSV whose rows contain `txid:vout` cells, a JSON array of
`{"txid": ..., "vout": ...}` objects, or a plain text file with one
`txid:vout` per line (you can build that last one by hand from Sparrow's
UTXOs tab in a pinch). A dedicated UTXO-set CSV export has not been verified
to exist in current Sparrow.

**Expectations to check before continuing:**

- `canaryew enroll` prints how many outpoints it parsed. With a BIP-329
  export this count *includes spent history*, so it may exceed your UTXO
  count — the authoritative cross-check is the **"still unspent" count at
  import (6c), which must match Sparrow's UTXOs tab exactly.** Fewer means
  the export omitted current coins, which would go unwatched.
- **Enrollment is a snapshot.** You are enrolling the UTXOs that exist right
  now. Consequences:
  - Any later *deliberate spend* from the wallet **will trigger a critical
    alert**. That is correct behavior, not a false positive — acknowledge it
    and re-enroll (section 11).
  - *Deposits* after enrollment are **not** watched. Deposit detection is off
    by design (it would require storing future addresses). After any planned
    deposit, re-export and re-enroll.
  - Change outputs created by a spend are not watched until you re-enroll.

### 6b. Build the sealed watchfile (trusted machine)

```bash
canaryew enroll --export labels.jsonl --label vault-cosigner-a \
    --out vault.watchfile --watch-id w-vault
```

Use your store passphrase when prompted, so the node can open the file. Note
the printed **fingerprint**. The watchfile contains outpoints, values, and
the label — sealed. No xpub, no descriptor, no address, in any form.

Repeat per wallet. If you keep **canary tribute UTXOs** on an at-risk seed
(small deliberate deposits whose movement proves the seed is being swept),
enroll them too — and keep one on the receive chain at a low index, because a
throughput-optimized sweeper often checks only the receive chain and would
miss a canary parked on the change chain.

### 6c. Import on the node

Transfer the watchfile (scp/USB — it is sealed, so untrusted transport is
acceptable), then:

```bash
canaryew import --watchfile vault.watchfile
```

Import **verifies every output against your node** before anything is
watched, and reports the partition:

```
Verified against the node at block 912,447:
  19 outputs in the watchfile
  10 still unspent -> will be watched (41,250,000 sat)
  9 already spent -> dropped as wallet history:
    b8562b0c...:1
    ...
```

Already-spent outputs are wallet history (consolidations, old spends that
label exports retain) — dropping them *before* enrollment is what prevents a
storm of false SPEND alerts on the first pass. This pruning happens only at
import, never after: once an output is watched, any movement is the
operator's call, full stop. Verification requires a synced node; if bitcoind
is unreachable you may `--no-verify`, accepting first-pass alerts for any
stale outputs.

Sanity-check the "still unspent" count and value against Sparrow before
continuing — if fewer coins survived verification than Sparrow shows as
unspent, the export was incomplete.

**Compare the printed fingerprint with the one from `enroll`, over a channel
that is not the transfer path.** A mismatch means the file that arrived is
not the file that left: do not import it. Delete the export file on the
trusted machine once the import is verified.

The import command refuses to run while the service is up (the running
service would overwrite the change) — stop it first, or import before
starting.

## 7. Start and unlock

```bash
sudo systemctl start canaryew canaryew-web
canaryew unlock     # prompts for the passphrase
```

`unlock` prints the verification phrase back. **Confirm it is yours.** Then:

```bash
canaryew status
```

Expect: `locked: false`, your watch/output counts, a recent
`last_check_at`, the current block height, and heartbeat `seq: 1`.

## 8. Test the full alert path — do not skip

```bash
canaryew test-alert
```

This sends a clearly-labeled TEST through **every** configured channel at
critical severity. Verify all of:

- [ ] The email arrived and **decrypts** with your key.
- [ ] The push arrived and **broke through Focus/DND/mute** at critical level.
- [ ] Both carry your verification phrase.

You have now seen a real alert once, before it matters. If the push did not
break through, fix Critical Alerts permission on the phone and re-test.

**The email must land in the inbox, not Junk.** A spam-filed alert is a
suppressed alert — indistinguishable, to you, from one that was never sent.
PGP mail is unusually spam-prone: the body is high-entropy ciphertext with no
readable words. canaryEW does its part (proper `Message-ID`, `+0000` date,
and an `EHLO` of your sender's domain rather than the library default, which
on Debian announces the useless `[127.0.1.1]`). If alerts still land in Junk:

- Read the `Received:` and `X-Spam-Status:` headers of a junked message.
  `from [127.0.1.1]` or `unknown [<ip>]` means HELO/rDNS scoring — set
  `CANARYEW_SMTP_HELO` to a name with matching forward/reverse DNS, or add a
  PTR record for the node's address.
- No `X-Spam-*` headers at all means your *client* filed it, not the server;
  mark a few messages "not junk" so it relearns.
- Once a few alerts have been junked, Bayesian filters keep junking them.
  Retrain (`sa-learn --ham`) rather than waiting it out.
- Whitelisting the authenticated sender is legitimate here — it is your own
  account: `whitelist_auth canary@example.org` in SpamAssassin's `local.cf`.

## 9. Reboot drill — also do not skip

```bash
sudo reboot
```

Expected sequence:

1. Within a minute of boot you receive a **LOCKED notice** on your phone:
   "restarted and locked, come unlock me." It carries *no* verification
   phrase — by design; it is a prompt, never evidence about your coins.
2. Heartbeats and monitoring are suspended (`canaryew status` shows
   `locked: true`).
3. You run `canaryew unlock`; monitoring and heartbeats resume.

This is the cost of the passphrase-on-start decision, paid on purpose: an
unattended reboot suspends monitoring loudly rather than storing key
material on disk. **If you ever get a LOCKED notice you cannot explain by a
power cut or planned reboot, treat it as an incident.**

## 10. Steady-state operations

- **Heartbeat every 6 h** (passive push + email). You do not need to read
  them; you need to *notice their absence*. Set a recurring expectation —
  e.g., check at breakfast that overnight heartbeats exist.
- **The dead-man rule:** no heartbeat for over one interval → investigate
  now. Possible causes, all of which deserve attention: node down, service
  killed, both channels failing, host offline, or suppression by an attacker.
- The status page (`http://<node>/canaryew/api/status` if nginx-proxied)
  shows `snapshot_stale: true` when the monitor has stopped writing — that is
  the same signal through a second lens.
- A **degraded** alert means canaryEW cannot currently verify your outputs
  (node unreachable/unsynced past the 30-minute grace). It is not "stolen",
  but it is never "all clear". Fix the node; recovery re-arms alerting.

## 11. When an alert fires

**If you authorized the spend** (you knew when you signed it):

```bash
canaryew ack --watch w-vault
```

Flagged outputs stay recorded as spent (never auto-cleared), heartbeats
report "all acknowledged". Then, once change settles: re-export from
Sparrow, re-enroll, re-import — your new outputs are not watched until you do.

**If you did not authorize it — assume active compromise:**

1. Verify the alert is genuine: your 4-word phrase must be present.
2. Do **not** enter any seed phrase anywhere. Ignore any message asking you
   to "verify", "migrate", or "protect" your wallet — after a public
   advisory, fake rescue prompts are the expected phishing vector.
3. If a quorum of keys remains under your control, move remaining funds
   using known-good hardware from clean seed material.
4. For a multisig vault where one cosigner seed is suspect: re-key that
   cosigner and keep the quorum shape.
5. Preserve the node (do not wipe): `journalctl -u canaryew`, the sealed
   store, and bitcoind logs are your forensic record.

A spend alert never clears itself. Silence after an alert means the alert
still stands.

## 12. Maintenance

- **Rotate the brrr secret**: update `canaryew.env`, restart the service.
- **Change SMTP password**: `canaryew set-smtp-password` (service stopped).
- **Upgrade**: `git pull && sudo deploy/deploy.sh`, then restart + unlock.
- **Re-enrollment cadence**: after every deliberate spend or deposit; and
  worth doing annually regardless, so the watched snapshot stays honest.
- **Passphrase change**: not currently supported in place — initialize a new
  store (`mv` the old one aside), re-import watchfiles, re-set the SMTP
  password. Your verification phrase changes with it: re-memorize.
