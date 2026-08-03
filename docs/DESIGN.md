# canaryEW — Design

Early-warning service that detects unauthorized movement of Bitcoin held under
watched keys, and notifies the operator through channels an attacker cannot
silently suppress.

## 1. The governing insight

A naive watch-only monitor stores an xpub, derives addresses, and polls for
activity. That design puts the most sensitive artifact in the system — a key
that reveals every past and future address, the full transaction graph, and the
complete balance — on a always-on, network-attached host, in a process that must
read it on every poll.

**canaryEW never stores an xpub, and after enrollment never holds one in memory.**

Detecting "funds moved" does not require the xpub. It requires knowing which
outputs you own and checking whether they are still unspent. Bitcoin Core answers
exactly that question from an outpoint alone:

```
gettxout <txid> <vout>   →  object  = still unspent
                         →  null    = spent (or never existed)
```

So the xpub is needed only once, during enrollment, to discover the UTXO set.
After that it is discarded. The steady-state monitor operates on outpoints.

### Why this matters

| Artifact | What it discloses | canaryEW storage |
|---|---|---|
| xpub | every past + future address, full history, balance, forever | **never stored** |
| descriptor | same, plus quorum composition | **never stored** |
| outpoint set | the specific UTXOs enrolled, at enrollment time | encrypted at rest |
| labels | operator-chosen names | encrypted at rest |

An attacker who fully compromises the host obtains a bounded snapshot — which
UTXOs existed when you enrolled — not the ability to derive your future
addresses or reconstruct your wallet. That is a categorically smaller loss.

## 2. Enrollment modes

### 2a. Offline enrollment (recommended)

The xpub never touches the node at all.

```
[trusted machine]                            [node]
  Sparrow BIP-329 labels export ──┐
  or CSV / outpoint list        ──┤
                                  ↓
                         canaryew enroll
                                  ↓
                  sealed watchfile (outpoints only)
                                  ├──── sneakernet / scp ────→ canaryew import
```

The operator's wallet software already knows the UTXO set; Sparrow's BIP-329
labels export carries it as `output` records, and `canaryew enroll` extracts
exactly those. In this mode canaryEW on the node has no capability to derive
addresses even transiently, because it never possesses the material to do so.

### 2b. On-host enrollment (convenient)

```
canaryew enroll --xpub <xpub> --descriptor <desc> --gap 100
```

The descriptor is passed to bitcoind's `scantxoutset` to discover UTXOs, held in
process memory for the duration of the scan, then zeroed. Nothing is persisted.
The process is short-lived and separate from the long-running monitor, so the
descriptor is never resident in the always-on service.

Weaker than 2a — an attacker with root *at the moment of enrollment* can capture
it — but enrollment is rare and can be scheduled deliberately.

## 3. Steady-state monitoring

```
        ┌──────────────── every POLL_INTERVAL ─────────────────┐
        │                                                      │
   unseal K_state                                              │
        ↓                                                      │
   decrypt outpoint set (memory only)                          │
        ↓                                                      │
   for each outpoint:  bitcoind gettxout txid vout             │
        ↓                                                      │
   any null → SPEND DETECTED ──→ alert pipeline                │
        ↓                                                      │
   update last_check, block_height, emit heartbeat if due ──────┘
```

Cost is one cheap RPC per watched output. A vault with 40 UTXOs polled every 10
minutes is negligible load on a node.

### Optional: deposit detection

Off by default. When enabled, canaryEW additionally stores the scriptPubKeys of
the next N unused addresses so it can detect *incoming* funds. This raises stored
sensitivity (those scripts reveal future addresses), so it is opt-in per watch
with an explicit warning. For a cold vault the correct posture is to leave it off
and re-enroll after any deliberate deposit.

## 4. The dead-man's switch

The obvious attack on any alerting system is to disable it before stealing. If
silence means "all is well," suppression wins.

canaryEW inverts this: **silence is the alarm.**

The service emits a positive heartbeat on a fixed schedule. Each heartbeat
carries a monotonic counter and an HMAC over `(counter, timestamp, state_digest)`
keyed by material derived from the operator's passphrase.

```
heartbeat = {
  seq: 1417,
  ts: 2026-08-02T14:00:00Z,
  state: "4 watches / 41 outputs / all present",
  block: 912_443,
  mac: HMAC-SHA256(K_hmac, seq || ts || state_digest)
}
```

Properties this gives you:

- **Killing the service is detectable.** No heartbeat within the expected window
  is itself the signal to investigate.
- **Replay is detectable.** The counter is monotonic; a replayed old heartbeat
  has a stale sequence number.
- **Forgery requires K_hmac.** An attacker who knows your email address cannot
  fabricate a reassuring "all clear."
- **Suppression at the mail layer is detectable** if you also enable the optional
  second channel, because both would have to be silenced simultaneously.

The operator's job reduces to a simple rule: *if the heartbeat stops, treat it as
an incident until proven otherwise.*

**A heartbeat asserts "I checked, and your outputs are present."** A pass that
could not evaluate — node unreachable, node unsynced — therefore emits no
heartbeat: the dead-man rule takes over and the degraded alert explains why.
Emitting a reassuring heartbeat while blind would be a false positive in the
one direction this design must never fail.

## 5. Alert authentication — the shared secret

At setup the operator supplies a passphrase. From it, Argon2id derives a key
hierarchy:

```
passphrase ──Argon2id(salt, m=256MiB, t=3, p=4)──> KEK (32B)
                                                    │
              HKDF-SHA256(KEK, info=...)  ──────────┼──> K_state         (encrypt state at rest)
                                                    ├──> K_hmac          (heartbeat + alert MAC)
                                                    └──> verification    (4 words from BIP39 list)
```

The **verification phrase** is 4 deterministic words the operator memorizes. It
appears in every genuine notification. Its purpose is narrow but real: it
authenticates the *message* to a human who is reading email on a phone under
stress, without requiring them to verify an HMAC by hand.

> Honest limitation: an attacker with root on the live host can read the
> verification phrase from process memory and forge convincing alerts. It defeats
> external spoofing and partial compromise, not full host compromise. Its real
> value is that it makes a *fake* alert — the phishing vector most likely to be
> aimed at you after a public advisory — fail closed.

## 6. Secrets at rest and the unlock model

`KEK` must survive an unattended reboot on a headless host, or the service fails
to resume monitoring after a power cut — which, given the dead-man's switch,
produces a false alarm rather than a silent failure. That is the correct failure
direction, but it is still operationally bad.

**Decision: passphrase on start.** No key material capable of opening the store
exists on disk in any form. After a reboot the service comes up `LOCKED` and
waits for the operator to supply the passphrase via `canaryew unlock`, which
talks to the service over a **unix control socket** (0600, service-user-only).
The socket was chosen over the originally sketched localhost HTTP unlock route:
access control is the filesystem rather than an auth layer, and the passphrase
never transits a TCP stack. A systemd credential
(`$CREDENTIALS_DIRECTORY/canaryew.passphrase`) is supported for supervised
starts that accept the trade-off.

| Provider | Unattended reboot | Resists disk theft | Resists live root |
|---|---|---|---|
| **`passphrase` (chosen)** | no | **yes — nothing derivable on disk** | no |
| `tpm2` — `systemd-creds` sealed to TPM + PCR policy | yes | yes | no |
| `keyfile` — key on removable media | yes, if media present | yes, if media removed | no |

The provider is a pluggable interface so `tpm2` can be added later without
touching the store format, but `passphrase` is the shipped default and the one
the operational docs assume.

### The cost of this choice, and how it is paid

Passphrase-on-start has one real drawback: **an unattended reboot leaves
monitoring suspended until a human intervenes.** Combined with S4, silence then
means "possibly compromised, possibly just a power cut," and the operator cannot
tell which without walking to the machine.

That ambiguity is unacceptable, so the locked state announces itself.

canaryEW keeps a **boot-notice key** outside the sealed store, used for exactly
one message type: *"I restarted and am locked, come unlock me."* It is
domain-separated in the HMAC construction so it is arithmetically incapable of
producing a valid all-clear. The notice carries no verification phrase and says
so in its own body.

```
reboot ──> service starts LOCKED
             │
             ├─ emits unauthenticated LOCKED notice via brrr  (needs only a webhook secret)
             │
             └─ waits ──> operator unlocks ──> monitor resumes, heartbeats resume
```

Threat consequence: an attacker who reads the boot-notice key from disk can spam
"I am locked" messages. That is an annoyance, not a compromise — and critically
it is the *opposite* of a useful lie, because the message an attacker would want
to send is a reassuring one, which requires the sealed HMAC key they do not have.

This is also why the second channel is a webhook rather than email: a webhook
secret is the entire credential, so the locked-state notice can be delivered
before SMTP credentials (which live in the sealed store) are available.

**No userspace design resists root on a live host.** This is stated plainly
rather than papered over. What the architecture buys is that even total host
compromise yields outpoints, not keys — and the dead-man's switch means the
compromise cannot be used to silence the alarm without raising it.

## 7. Notification channels

Ordered by trust. At least one must be configured; two are recommended so that
suppressing alerts requires compromising both.

### PGP-encrypted email (primary)

- Operator onboards a **public** key only — canaryEW holds nothing secret here.
- Alert bodies are encrypted to that key before handing to SMTP, so the mail
  server (and anyone who compromises it) sees ciphertext.
- Sent through operator-supplied SMTP credentials, which *are* sensitive and live
  in the sealed store. Use a submission-only account.

### brrr.now push (secondary, and the locked-state channel)

`POST https://api.brrr.now/v1/send` with `Authorization: Bearer <secret>`.
Chosen for two properties rather than convenience:

1. **Critical alerts bypass Focus, Do Not Disturb, and mute.** A spend alert at
   03:00 is precisely the case where a silenced phone defeats the entire system.
   canaryEW maps severity onto brrr's interruption levels:

   | Severity | `interruption_level` | Sound | Rationale |
   |---|---|---|---|
   | spend detected | `critical` | `emergency` | must wake the operator |
   | degraded / locked | `time-sensitive` | `warm_soft_error` | breaks DND, not alarming |
   | heartbeat | `passive` | `default` | silent; only its *absence* matters |

   Critical alerts require the operator to enable them for the brrr app
   on-device. Setup docs must call this out — without it, delivery silently
   downgrades and the loudest alert becomes an ordinary one.

2. **A webhook secret is the whole credential.** No SMTP account, no keyring.
   That is what makes it the only channel able to run before the sealed store is
   unlocked (S6).

Metadata leakage: brrr learns *that* you were alerted and when. Per their docs,
message bodies are not stored on the backend and history stays on-device, but
the conservative assumption is still that the transport sees the body — which is
why minimal redaction is the default and `full` tier is refused on this channel.

Health checks on this channel deliberately do **not** send a test notification.
Training the operator to ignore canaryEW pushes is the one failure this project
cannot tolerate.

## 8. Alert content and redaction tiers

Default is maximally redacted — enough to act, not enough to inform an
eavesdropper.

| Tier | Content |
|---|---|
| `minimal` (default) | watch label, count of affected outputs, timestamp, block height, verification phrase |
| `standard` | adds which output indices, and value buckets (not exact amounts) |
| `full` | adds txids and exact values — for PGP-encrypted channel only, refused on webhook |

Example minimal alert:

```
canaryEW ALERT — 2026-08-02T14:07:31Z

Watch:        vault-cosigner-a
Condition:    2 of 11 monitored outputs no longer in the UTXO set
Block height: 912,447
Verification: harvest cobalt ember thrush

If you did not authorize a spend from this wallet, treat as an
active compromise. Do not enter your seed anywhere.
```

## 9. Status surface

A small FastAPI app bound to `127.0.0.1`, proxied by nginx at a subpath if LAN
access is wanted.

- `GET /api/health` — liveness, no state access
- `GET /api/status` — redacted operational status (+ snapshot staleness flag)
- `GET /api/heartbeat/latest` — last heartbeat seq/ts/mac for manual verification

**The web process is keyless by construction.** The monitor writes a redacted
snapshot file (counts, heights, timestamps, heartbeat seq/MAC — nothing else);
the web app only reads that file, runs as a separate user, and holds no
passphrase, no keys, no RPC credentials, and no control-socket access.
Compromising it yields information the operator would read out loud anyway.
Because the snapshot carries nothing sensitive, the endpoints need no session
auth; LAN exposure policy is nginx's problem.

Status never exposes outpoints or labels. It answers: is it running, is it
locked, when did it last check, what block, when was the last heartbeat — and
`snapshot_stale: true` when the monitor has stopped writing, which is the
dead-man signal through a second lens.

## 10. Relationship to other applications on the node

**Deliberately not integrated at the process or data layer with anything.**

canaryEW's entire value proposition is that it keeps working, and keeps being
trustworthy, when other things are compromised. Sharing a process, a database, a
unix user, or a secret with a larger application — one with a web UI, a
database dependency, imports, and a much wider attack surface — would subsume
canaryEW's threat model into that application's.

What may be shared with co-resident applications:

- **Patterns**, not code: FastAPI + `uvicorn --factory`, systemd unit shape,
  `deploy/deploy.sh`, nginx subpath mounting, `AGENTS.md` learnings convention.
- **The node**, read-only, via separate cookie-file access under a separate user.
- **One-way event emission (optional):** canaryEW may append signed events to a
  spool directory that another application reads. Never the reverse. canaryEW
  accepts no input from other applications and exposes no API to them.

Separate unix user, separate systemd unit, separate secrets, separate port.

## 11. Failure modes and their directions

Designed so that every failure is loud rather than silent.

| Failure | Behavior |
|---|---|
| bitcoind unreachable | retry with backoff; after grace period, alert (degraded, not spend) |
| node not synced / reorg | compare block height; suppress spend alerts until synced, alert on prolonged stall |
| SMTP down | retry, escalate to webhook, record in status |
| both channels down | heartbeat stops → operator's dead-man rule fires |
| service killed | heartbeat stops → same |
| disk full / state corrupt | fail closed, stop heartbeats |
| false positive from a legitimate spend | operator acknowledges via CLI; watch is re-enrolled |

A spend alert is never retracted automatically. It requires operator
acknowledgement, because the one thing worse than a false alarm is a real alarm
that clears itself.

## 12. Non-goals

- Not a wallet. Holds no private keys, cannot sign, cannot spend.
- Not a balance tracker.
- Not a block explorer or indexer.
- Does not protect against root on the live host — it bounds the loss and makes
  suppression detectable.
