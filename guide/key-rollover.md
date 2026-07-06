# TDNS Operator Guide: Automatic DNSSEC Rollovers

TDNS automates three kinds of DNSSEC rollover. This guide
covers all three; most of it (sections 1-12) is the KSK
engine, which is the most involved because it coordinates
with the parent. Sections 14 (ZSK) and 15 (algorithm
rollover) build on that foundation and are shorter.

TDNS includes a fully automated KSK rollover engine. Once
a zone is configured with a DNSSEC policy that has
`rollover:` set, no operator intervention is required for
the normal case: the engine selects keys, publishes them,
pushes DS records to the parent over whichever scheme the
parent advertises, verifies the result by querying the
parent's agent, and -- when something goes wrong -- drops
into a long-term retry mode with explicit status visible
from the CLI. Operators can interject (`asap` to force an
early rollover, `cancel` to take one back, `unstick` to
skip a backoff), but the steady-state mode is hands-off.

The same engine supports cadences from seconds (testbeds)
through monthly (conservative production). The
configuration model is the same in either case; only the
numbers change.

The audience for this guide is operators with hands-on
experience in DNS and DNSSEC who are new to *automated*
KSK rollover specifically. It assumes you know what a
DNSKEY, DS, RRSIG, TTL, and the DNSSEC chain of trust
are; it explains how those pieces relate to each other in
the context of frequent rollovers, what tdns parameters
control which behaviour, and how to choose values that
fit your operational reality.

For the rigorous timing math (cache-flush invariants,
equations E1-E13, the parent-DS-RRset contract) see the
companion document
[Rollover Timing Equations](rollover-timing-equations.md).
For multi-provider deployments where leader election picks
which provider drives the rollover, see the
[tdns-mp guide](../../tdns-mp/guide/).


## 0. Three kinds of rollover

It helps to keep the three rollover types distinct, because
they differ in whether the parent is involved:

- **KSK rollover** (same algorithm) -- replace the
  key-signing key. The DS at the parent must change, so this
  is **parent-coordinated**: the engine publishes the new
  key, pushes/confirms the DS at the parent, then retires
  the old key. This is the bulk of the guide (sections
  1-13).
- **ZSK rollover** (same algorithm) -- replace the
  zone-signing key. The ZSK has **no parent dependency** (no
  DS), so this is purely local: pre-publish, activate,
  retire, remove, on a lifetime cadence. Section 14.
- **Algorithm rollover** -- change the signing *algorithm*
  (e.g. ED25519 -> a PQ algorithm), not just the key. This
  rides the same pipelines but the generator starts minting
  the new algorithm and the old one drains out. Section 15.
  Today the **relaxed-mode ZSK** algorithm rollover is
  implemented; KSK-algorithm and strict-mode rollovers are
  refused with a clear error (later work).

All three share the same policy YAML (section 1), the same
`auto-rollover` CLI tree (section 2), and the same `status`
output (section 3). The role filter flags `--ksk` / `--zsk`
select which role a command acts on.


## 1. Configuring the engine

The rollover engine is configured per DNSSEC policy. A
zone references a policy by name; the policy carries the
rollover settings.

```yaml
zones:
   example.com.:
      dnssec-policy: production-weekly

dnssecpolicies:
   production-weekly:
      algorithm: ecdsap256sha256
      mode:      ksk-zsk
      ksk:
         lifetime:     7d
         sig-validity: 14d
      zsk:
         lifetime:     30d
         sig-validity: 14d
      rollover:
         method:                      multi-ds
         num-ds:                      3
         parent-agent:                parent.example.net:53
         ds-publish-delay:            5m
         max-attempts-before-backoff: 5
         softfail-delay:              1h
         dsync-scheme-preference:     auto
      ttls:
         dnskey:     1h
         max_served: 8h
      clamping:
         enabled: true
         margin:  15m
```

Most fields have sensible defaults. The minimal required
set is `algorithm`, `mode`, `ksk.lifetime`,
`ksk.sig-validity`, `rollover.method`, and
`rollover.parent-agent`. Everything else is either
derived from `ds-publish-delay` or carries an engine
default.

Two rollover **methods** are supported:

- **`multi-ds`** keeps a pipeline of `num-ds` DS records
  at the parent at all times. The next-to-roll-in key is
  pre-published, so rollover is just "promote the next
  pipeline slot." This is the recommended default.
- **`double-signature`** publishes the new key and signs
  with both during the overlap window. More
  bandwidth-intensive but tolerates a wider class of
  parent-side timing edge cases.
- **`none`** disables automated rollover for the policy.

`rollover.dsync-scheme-preference` controls which delivery
transport(s) the engine uses against the parent. The
parent advertises supported schemes via DSYNC at
`_dsync.<parent>`; this knob decides what to do when the
parent advertises more than one:

| Value             | Both advertised             | One advertised   | Neither |
|-------------------|-----------------------------|------------------|---------|
| `auto` (default)  | parallel UPDATE + NOTIFY    | use that one     | wait    |
| `prefer-update`   | UPDATE only                 | use that one     | wait    |
| `prefer-notify`   | NOTIFY only                 | use that one     | wait    |
| `force-update`    | UPDATE only                 | UPDATE or wait   | wait    |
| `force-notify`    | NOTIFY only                 | NOTIFY or wait   | wait    |

"wait" = `child-config:waiting-for-parent` softfail
capped at 1h backoff, never hardfails, auto-recovers when
DSYNC reappears. `auto` is the right default for almost
every operator. See §5 for the dispatch mechanics.

`rollover.ds-publish-delay` is the single most
operationally-important knob. It tells the engine how
long to wait, after sending UPDATE (or NOTIFY) to the
parent, before expecting to see the new DS RRset served:

| Parent type                          | Recommended `ds-publish-delay` |
|--------------------------------------|--------------------------------|
| Direct-publish (parent runs tdns-auth or similar) | `30s` to `5m`     |
| Registry with ~hourly batched publication         | `1h`              |
| Registry with daily publication                   | `24h`             |
| Manual operator-reviewed registry                 | per registry SLA  |

The engine derives the per-attempt observation budget
(`confirm-timeout` = `ds-publish-delay × 1.2`), the poll
cadence (`confirm-poll-max` = `clamp(delay/10, 30s, 5m)`)
and the long-term retry interval (`softfail-delay` =
`max(1h, delay)`) from this number, so getting it roughly
right matters more than getting it exactly right.

Full reference of policy parameters:

| Parameter | Required | Default | Purpose |
|-----------|----------|---------|---------|
| `algorithm` | yes | -- | DNSSEC algorithm (e.g. `ECDSAP256SHA256`, `MLDSA44`) |
| `mode` | no | `ksk-zsk` | `ksk-zsk` or `csk` |
| `ksk.lifetime` | yes | -- | Rollover cadence (`next = active_at + lifetime`) |
| `ksk.sig-validity` | yes | -- | RRSIG validity for DNSKEY signatures |
| `zsk.lifetime` | yes | -- | ZSK cadence (out of scope today; engine does not auto-roll ZSKs) |
| `zsk.sig-validity` | yes | -- | RRSIG validity for non-DNSKEY signatures |
| `rollover.method` | yes | `none` | `multi-ds`, `double-signature`, or `none` |
| `rollover.num-ds` | no | `3` (multi-ds) / `2` (double-sig) | DS pipeline depth |
| `rollover.parent-agent` | yes if `method != none` | -- | Parent's address for DS queries, `host:port` |
| `rollover.ds-publish-delay` | no | `5m` | Parent's expected DS publication latency |
| `rollover.max-attempts-before-backoff` | no | `5` | Softfail flurry size |
| `rollover.softfail-delay` | no | derived (`max(1h, ds-publish-delay)`) | Long-term-mode probe interval |
| `rollover.dsync-scheme-preference` | no | `auto` | See table above |
| `rollover.confirm-initial-wait` | no | `2s` | First-poll delay after a push |
| `rollover.confirm-poll-max` | no | derived (`clamp(delay/10, 30s, 5m)`) | Maximum DS-poll cadence |
| `rollover.confirm-timeout` | no | derived (`ds-publish-delay × 1.2`) | Per-attempt observation budget |
| `rollover.parent-cds-poll-estimate` | no | `1m` | Parent's CDS fetch latency (NOTIFY scheme) |
| `rollover.standby-time` | no | `1m` | Pause between propagation-complete and AtomicRollover |
| `ttls.dnskey` | no | (zone default) | TTL for DNSKEY RRset |
| `ttls.max_served` | no | unbounded | Maximum TTL the daemon will serve |
| `clamping.enabled` | no | `false` | Whether to clamp TTLs near rollover |
| `clamping.margin` | yes if `clamping.enabled` | -- | TTL floor and retired-KSK hold time |


## 2. The CLI surface

All commands live under
`tdns-cli auth keystore dnssec auto-rollover`. Each
inherits two persistent filter flags, `--ksk` and `--zsk`,
which limit the operation to keys of that role.

```
auto-rollover when          --zone Z [--ksk|--zsk] [--offline]
auto-rollover asap          --zone Z [--ksk|--zsk]
auto-rollover cancel        --zone Z [--ksk|--zsk]
auto-rollover policy-change  --zone Z --policy P
auto-rollover status        --zone Z [--ksk|--zsk] [--offline] [-v]
auto-rollover reset         --zone Z --keyid N [--offline [--force]]
auto-rollover unstick       --zone Z [--offline [--force]]
auto-rollover validate ...
```

`when`, `asap`, and `cancel` default to the KSK role; pass
`--zsk` to operate on the zone-signing key instead (a ZSK
roll has no parent coordination -- see section 14).
`policy-change` is the algorithm-rollover trigger (section
15).

| Subcommand | Purpose |
|------------|---------|
| `when`     | Computes -- without changing anything -- the earliest moment a KSK rollover could safely fire (driven by max TTL, the `num-ds` pipeline state, and current confirm timers). Also shows the next-scheduled time (driven by `ksk.lifetime`). `--offline` performs the computation locally against the keystore if the daemon is down. |
| `asap`     | Schedules a manual KSK rollover at the earliest safe moment. Persists the request to the keystore so a daemon restart doesn't lose it. |
| `cancel`   | Cancels a pending `asap` request before it has fired. |
| `status`   | The main operator window into the engine -- see §3. |
| `reset`    | Clears `last_rollover_error` for one specific key after the operator has intervened. Takes `--keyid` because errors are scoped per key. `--offline` writes directly to the keystore with a daemon-alive guard you can override with `--force`. |
| `unstick`  | The engine throttles itself after persistent failures by setting `next_push_at` into the future. `unstick` clears that field so the next tick will probe the parent immediately, without waiting `softfail-delay`. |
| `validate` | Parses and cross-checks a DNSSEC policy file; surfaces invalid durations, missing required fields, and cross-field constraint violations. |
| `policy-change` | Binds the zone to a new DNSSEC policy to start an algorithm rollover (section 15). It only changes the algorithm of *future*-generated keys; the existing keys drain out in order. It does NOT perform the roll -- `asap --zsk` is the throttle. |

The `when` command shows two times:

- **next scheduled** -- when the engine will fire the
  next rollover (driven by `ksk.lifetime`).
- **earliest possible** -- the soonest the engine could
  fire an unscheduled rollover if you requested one
  (driven by zone TTLs and DS readiness).

These two times are usually different, sometimes by a
wide margin. Both are correct answers to different
operator questions.


## 3. Reading `auto-rollover status`

`status` is the operator's primary diagnostic. Its output
is organised into four blocks.

**1. Headline state and phase.** A single one-word state
(`OK`, `ACTIVE`, `SOFTFAIL`) plus the engine's current
phase:

| Phase | Meaning |
|-------|---------|
| `idle` | No rollover in flight. |
| `pending-child-publish` | New key published in the child zone, waiting for TTL clearance. |
| `pending-parent-push` | Ready to send DS to the parent on the next tick. |
| `pending-parent-observe` | DS pushed; engine is polling the parent agent for confirmation. |
| `parent-push-softfail` | Parent isn't accepting; engine has dropped into long-term-retry mode (one probe per `softfail-delay`). |
| `pending-child-withdraw` | DS confirmed; old key now scheduled for withdrawal once safe. |

When the state isn't steady, a one-line `Hint:` field
diagnoses why.

**2. DS push state and DS observation state.** Two
side-by-side blocks describing each side of the parent
hop. The push side carries:

- `ParentAdvertisesUpdate` / `ParentAdvertisesNotify`
  with a tri-state `Known` flag -- distinguishes "parent
  doesn't support this scheme" from "engine hasn't probed
  yet."
- `Submitted` / `SubmittedKeyIDs` -- the DS RRset most
  recently pushed (rollover_index range + SEP keyids).
- `LastUpdate` and `LastAttemptScheme` -- when, and over
  which transport(s); e.g. `UPDATE,NOTIFY` if both legs
  succeeded in parallel.

The observe side carries:

- `ObservedKeyIDs` / `ObservedAt` -- the most recent
  positive result from polling `parent-agent`.
- `ConfirmedKeyIDs` -- legacy confirmation fallback.
- `NextPoll` / `ExpectedBy` / `AttemptTimeout` -- the
  upcoming poll fire time, the soft deadline
  (`LastUpdate + ds-publish-delay`), and the hard budget
  (`LastUpdate + confirm-timeout`).

**3. Per-key tables.** One row per KSK and ZSK with:
`keyid`, `state`, `published`, `state_since`,
`next_transition`, `next_transition_at` and any sticky
`last_rollover_error`.

**4. Softfail and error context.** Visible when the
engine has dropped into long-term retry:
`HardfailCount` (size of the initial flurry burst),
`LastSoftfailAt`, `LastSoftfailCat` (category --
`parent-rejected`, `transport`, `child-config`,
`waiting-for-parent`, ...), `LastSoftfailDetail`, and
`NextPushAt` (when the next probe will fire). Add `-v`
for the full error string and the resolved policy.


## 4. PQ-safe parent UPDATEs

When the engine pushes DS over the UPDATE scheme, it
signs the message with the child zone's active SIG(0)
keypair from the local keystore. There is no algorithm
filter at the call site -- the engine asks for "the
active SIG(0) key for this zone" and signs with whatever
algorithm that key happens to use.

If the operator has provisioned an MLDSA44 (or other PQ)
SIG(0) key via tdns-cli, and the algorithm is registered
in the running binary (see section 4 of
[Special Features](special-features.md)), the parent
UPDATE is signed with that PQ algorithm, no extra
configuration required.

This matters because PQ DNSKEYs are large -- a parent
that accepts SIG(0)-signed UPDATEs lets the child roll a
PQ KSK without having to first publish a large CDS RRset
that the parent then has to fetch and validate. The same
SIG(0) machinery that authenticates the UPDATE is itself
PQ-safe.


## 5. DSYNC-aware dispatch and verification

The engine never assumes how the parent wants to be
talked to. Every push starts with a discovery step:

1. Resolve `_dsync.<parent>` through the local IMR.
2. Split the returned DSYNC RRset into UPDATE-capable
   entries and NOTIFY-capable entries. (NOTIFY entries
   must advertise `CDS` or `ANY` to count for DS
   rollover.)
3. Combine the discovered capability with the policy's
   `dsync-scheme-preference` (table in §1) to produce
   one or two delivery choices.
4. Record what the parent advertised, so `status` output
   can later distinguish "not advertised" from "not yet
   probed."

When two schemes survive selection (the common
`auto`-mode case), the dispatcher fans out two goroutines
-- one for UPDATE, one for NOTIFY -- and joins them. The
aggregator follows an **any-success-wins** rule: if at
least one path returns NOERROR, the push is considered
to have succeeded, and the `Scheme` field becomes a
comma-joined list of the winning schemes. If both paths
fail, the most actionable failure category wins
(`parent-rejected` > `transport` > `child-config`).

Critically, "the push succeeded" does not mean "the DS
appeared at the parent." The engine independently verifies
by polling the address in `rollover.parent-agent`:

- After an initial `confirm-initial-wait` delay
  (default 2s), the engine queries the parent agent for
  DS, every `confirm-poll-max` (default 1m).
- The match check canonicalises both sides (keytag +
  algorithm + digest type + digest) and looks for set
  equality.
- If the match arrives before `confirm-timeout`
  (default 1h), the phase advances. If not, the engine
  drops into `parent-push-softfail` and one push probe
  per `softfail-delay` from then on, until either the
  match arrives or the operator runs `auto-rollover
  unstick`.

The net effect: rollover proceeds whenever the parent
operates correctly, regardless of which delivery
mechanism it accepts, and stalls visibly (with category
and detail in `status` output) when it doesn't.

**NOTIFY async-rejection asymmetry.** The parent-side
NOTIFY scanner runs *after* the NOTIFY ACK is sent. CDS
validation failures, RFC 9615 signaling check failures,
and RFC 8078 bootstrap policy refusals at the parent
therefore surface as `parent-publish-failure` from the
child's point of view -- not as `parent-rejected`, even
when the underlying cause is a parent-side rejection. To
diagnose, consult the parent-side scanner logs. UPDATE
pushes are synchronous and do surface parent rejections
as `parent-rejected` with EDE detail when the parent
supplies one.


## 6. Rapid rollover: the mental model

The defaults in §1 produce a reasonable production
deployment. To depart from them sensibly -- and especially
to roll faster than weekly -- it helps to understand the
three knobs that govern rollover safety. They are easy to
confuse with each other but in fact independent. Treating
them as coupled produces working-but-suboptimal setups;
treating them as orthogonal lets you tune each for its
own purpose.

The three knobs are:

1. **Maximum zone TTL.** Bounds how long stale data can
   live in resolver caches. Determines the **earliest
   possible rollover time** if you ever need to roll
   outside the regular schedule.
2. **KSK lifetime.** The rollover cadence -- the
   policy-driven "next scheduled rollover" interval.
   Independent of safety bounds; choose based on key
   compromise risk, regulatory requirements, or
   operational preference.
3. **RRSIG validity.** How long signatures remain valid
   in already-served responses. Determines
   **signing-outage tolerance** -- how long the signing
   infrastructure can be down before RRSIGs in cache
   start expiring and the zone goes bogus.

Each knob has exactly one job:

| Knob | Bounds what | Primary use |
|------|-------------|-------------|
| Max zone TTL | Cache flush time | Earliest unscheduled rollover |
| KSK lifetime | Scheduled rollover cadence | Routine rotation interval |
| RRSIG validity | Signing-outage survival | Weekend / holiday resilience |

The same fact stated differently: **none of these
constrains the other two.** A 5-minute rollover cadence is
fine with a 14-day RRSIG validity. An 8-hour TTL is fine
with a 7-day cadence. A 30-day RRSIG validity is fine
with a 1-hour TTL. The combinations that look "weird" are
often the right answers.


### 6.1 TTL bounds cache-flush time

When you change something in your zone, validators that
have cached the old data continue to use it until either
their cache TTL expires *or* the cached RRSIG expires.
Either of those forces them to refetch, and the refetch
returns fresh state. So each cache entry stops being
usable after `min(TTL, remaining_RRSIG_validity)`.

For "all caches everywhere are now using fresh state,"
the bound is the longest such interval across all
validators that recently cached the data. Conservative
upper bound: TTL itself. This is true regardless of how
long RRSIG validity is, because TTL is the cap.

For a **rollover** specifically, the operationally
relevant cache-flush concern is: "all validators are
using the new DNSKEY data before the parent points to a
different key." The answer is your zone's max TTL plus a
small safety margin. Nothing else.


### 6.2 KSK lifetime sets cadence, not safety

The rollover cadence is a policy choice, not a safety
boundary. You roll keys periodically because:

- It exercises the rollover machinery, so you find out
  it's broken when you have time to fix it rather than
  during an emergency.
- It limits the operational window in which a compromised
  key matters.
- Some compliance regimes mandate periodic rotation.

The cadence does not have to be related to any safety
property. A 7-day cadence with an 8-hour TTL is a normal,
sensible setup. So is a 5-minute cadence on a testbed
where you want the machinery exercised continuously.

The only real lower bound on cadence is operational: how
often are you willing to be paged for things that go
wrong? See §9.


### 6.3 RRSIG validity governs outage survival

A signed zone serves RRSIGs. RRSIGs have explicit
`Inception` and `Expiration` fields in the wire format.
After `Expiration`, validators reject responses signed by
that RRSIG: they will no longer treat the data as
authentic and will return SERVFAIL to their clients. The
zone goes bogus from the validator's perspective,
regardless of cache TTLs.

For the zone to keep validating, the signing engine must
periodically re-sign the zone and replace expiring RRSIGs
with fresh ones. The re-sign cadence is determined by the
engine's "resign when remaining validity drops below
threshold" rule -- typically resign when remaining
validity drops below half (or a third) of the full
validity period.

So at any given moment, the RRSIGs published in the zone
have remaining validity somewhere in `[resign_threshold,
full_validity]`. The minimum value of that range is your
**signing-outage tolerance**: if the signing engine
breaks now, that's how long the zone will keep
validating before RRSIGs in caches start expiring and
you're in trouble.

A long weekend is roughly four days. Add a buffer for
diagnosis and fix once the operator returns. Six days is
a comfortable target. Seven days is conservative.

If you set RRSIG validity to 7 days and resign at
half-expiry (when 3.5 days remain), the floor of
remaining validity is 3.5 days. Not enough. If you set
14 days and resign at half-expiry (when 7 days remain),
the floor is 7 days. Comfortable.

This argument has nothing to do with rollover cadence or
zone TTLs. It is purely about signing-infrastructure
resilience.


### 6.4 The cache-flush analysis (for the curious)

This subsection is optional reading. It justifies the
claim in §6.1 that "TTL is the cache-flush bound
regardless of RRSIG validity."

Consider a single validator that just queried your zone
and now has the DNSKEY RRset cached, with the
accompanying RRSIG.

The validator's cache entry expires at `fetch_time +
min(TTL, RRSIG_remaining_validity_at_fetch_time)`.

Either condition forces a refetch. Either way, the
refetch delivers fresh state. So the cache entry
"expires" -- in the sense of "no longer represents stale
state for our purposes" -- at the earlier of those two
times.

For an "all validators have fresh state" bound, we want
the worst-case validator's cache age. The worst case is
a validator that fetched immediately before our
rollover, with `RRSIG_remaining == full_validity`
(because we just signed). Cache age = `min(TTL,
full_validity)`.

In any reasonable production zone, `TTL << full_validity`
(your zone's TTLs are hours, your RRSIG validity is days
or weeks). So `min(TTL, full_validity) = TTL`. RRSIG
validity drops out of the cache-flush bound entirely.

The unusual `TTL > full_validity` regime would invert
this and make `RRSIG_remaining` the bound. tdns currently
assumes the typical regime; if you have a specific
reason to invert it, you will need to engage with the
design docs. The default tdns earliest-rollover gate is
just `now + max_ttl + margin`.

The full timing math -- the cache-flush invariants and
the parent-DS-RRset contract -- is in
[Rollover Timing Equations](rollover-timing-equations.md).


## 7. Worked examples


### 7.1 The 10-minute testbed

You're running a multi-provider DNSSEC testbed and want
to exercise the rollover machinery as fast as practical.
You can afford zone TTLs of seconds. You don't care about
long-weekend resilience because the testbed is on a local
network with you watching it.

```yaml
dnssecpolicies:
   testbed-fast:
      algorithm: ECDSAP256SHA256
      mode: ksk-zsk
      ksk:
         lifetime: 10m
         sig-validity: 30m
      zsk:
         lifetime: 24h
         sig-validity: 1h
      rollover:
         method: multi-ds
         num-ds: 3
         parent-agent: 192.0.2.1:53
         ds-publish-delay: 30s
      ttls:
         dnskey: 60s
         max_served: 300s
      clamping:
         enabled: true
         margin: 60s
```

Notes:

- `ksk.lifetime: 10m` makes the next-scheduled rollover
  fire ten minutes after the current active key became
  active. Your testbed will roll continuously.
- `ksk.sig-validity: 30m` is much shorter than production
  but appropriate for a local testbed where outages are
  minutes, not days. The engine resigns DNSKEY RRSIGs as
  they approach expiry.
- `ttls.max_served: 300s` caps everything in the zone at
  five minutes; combined with `clamping.margin: 60s`,
  the engine can do an unscheduled rollover within ~5
  minutes if needed.
- `clamping.margin: 60s` is the safety floor for TTL near
  rollover; you cannot go much lower without bumping into
  clock skew between the primary and validators.

This setup will roll cleanly in steady state. Don't
deploy it to production -- the short RRSIG validity means
the zone will go bogus within an hour of any
signing-engine hiccup.


### 7.2 Production with weekly cadence

You run a real zone, want to roll weekly to demonstrate
operational confidence in the rollover machinery, and
need to survive long weekends without paging.

```yaml
dnssecpolicies:
   production-weekly:
      algorithm: ECDSAP256SHA256
      mode: ksk-zsk
      ksk:
         lifetime: 7d
         sig-validity: 14d
      zsk:
         lifetime: 30d
         sig-validity: 14d
      rollover:
         method: multi-ds
         num-ds: 3
         parent-agent: parent.example.net:53
         ds-publish-delay: 5m
         max-attempts-before-backoff: 5
         softfail-delay: 1h
      ttls:
         dnskey: 1h
         max_served: 8h
      clamping:
         enabled: true
         margin: 15m
```

Notes:

- `ksk.lifetime: 7d` schedules a rollover every week.
- `ksk.sig-validity: 14d` with engine-default
  resign-at-half means RRSIGs always have at least 7
  days remaining. Friday-evening signing failure leaves
  you 7 days of validity in caches -- comfortably more
  than any plausible long weekend plus diagnosis time.
- `ttls.max_served: 8h` caps zone TTLs at eight hours,
  bounding the cache-flush window for emergency
  rollovers. With `clamping.margin: 15m`, an unscheduled
  rollover can fire about eight hours after request.
- `ds-publish-delay: 5m` is appropriate for a parent
  that publishes DS within a small batch window. For a
  registry that publishes hourly, set `1h` instead; for
  a daily registry, set `24h`. The engine derives the
  per-attempt timeout and softfail-delay defaults from
  this number.

This is a sensible default for most production
deployments. Adjust `ksk.lifetime` if you want a
different cadence; the rest of the parameters scale with
operational reality, not cadence.


### 7.3 Production with monthly cadence

Same operational reality but you want a more conservative
rollover rhythm -- perhaps to align with monthly
maintenance windows.

```yaml
dnssecpolicies:
   production-monthly:
      algorithm: ECDSAP256SHA256
      mode: ksk-zsk
      ksk:
         lifetime: 30d
         sig-validity: 14d
      zsk:
         lifetime: 90d
         sig-validity: 14d
      rollover:
         method: multi-ds
         num-ds: 3
         parent-agent: parent.example.net:53
         ds-publish-delay: 5m
         max-attempts-before-backoff: 5
         softfail-delay: 1h
      ttls:
         dnskey: 1h
         max_served: 8h
      clamping:
         enabled: true
         margin: 15m
```

The only change from 7.2 is `ksk.lifetime` (30 days vs 7
days) and `zsk.lifetime`. Everything else stays the same:
long-weekend resilience, cache-flush bound, parent
expectations, safety margin. The orthogonality of the
three knobs lets you change cadence without touching the
rest.

Some operators prefer to bump `ksk.sig-validity` higher
(to 30d) for monthly cadence as well, on the theory that
"I'm only checking on this thing monthly so it should
survive a long absence." That's reasonable but not
necessary -- the engine re-signs continuously, not on the
rollover schedule.


## 8. The `clamping` choice

When clamping is enabled, the engine progressively lowers
TTLs near a scheduled rollover so that cached data
flushes faster as the rollover approaches. This shortens
the window during which old DNSKEY data could be cached
past a rollover.

For most production deployments with `ttls.max_served`
set, you do not need clamping enabled -- the always-on
TTL ceiling already gives you a known cache-flush bound.
Clamping is more useful for zones where you want to keep
TTLs high in steady state but shorten them just before
rollovers.

If you enable clamping, `clamping.margin` is required and
is both:

- The TTL floor immediately before rollover (TTLs cannot
  be clamped below this).
- The retired-KSK hold time (how long a retired KSK stays
  in the zone after rollover, before final removal).

Set it to something well above clock-skew tolerance (60
seconds minimum, 15 minutes typical for production).


## 9. Operational considerations for fast cadences

Fast rollover cadences are operationally sound -- the
engine keeps the zone validating throughout -- but they
have real costs that are easy to underestimate:

**Alert noise.** Each rollover is a chance for something
to softfail. Multiply by zones managed and rollovers per
week and you may discover that your paging system is
processing more rollover events than anything else.
Operators learn to ignore the alerts. When something
genuinely fails, it's missed.

**Stuck-zone duration.** If a rollover hits hardfail at
the start of a long weekend, it sits stuck-but-working
until Monday. The zone keeps validating with the
*previous* active key -- the state machine is
specifically designed so that key advancement is gated
on the new DS being confirmed at the parent, and hardfail
freezes that advancement. Nothing breaks. But for some
compliance regimes, "a rollover did not complete on
schedule" is itself an audit finding even when the zone
is fine.

**Bug exposure rate.** Until the engine has been
well-soaked, fast cadences carry higher absolute risk of
hitting a bug regardless of operator presence.

For these reasons, **production zones should default to
cadences of 7 days or longer.** Faster cadences are
appropriate for testbeds, research zones, and zones with
specific regulatory requirements that mandate short key
lifetimes. The rollover machinery itself does not impose
a lower bound -- you can roll every minute if you really
want -- but you should not.


## 10. Validation and verification

Once the policy is configured, validate the YAML before
restarting the daemon:

```sh
tdns-cli auth keystore dnssec policy validate \
   --file /etc/tdns/tdns-auth.yaml
```

This parses every policy under `dnssecpolicies:` and
reports configuration errors (invalid durations, missing
required fields, cross-field constraint violations)
without affecting the running daemon. The same validation
runs implicitly when the daemon loads the config, but
doing it ahead of time avoids a broken restart.

After deployment, query the zone's rollover state:

```sh
tdns-cli auth keystore dnssec auto-rollover status \
   --zone=example.com.
tdns-cli auth keystore dnssec auto-rollover when \
   --zone=example.com.
```


## 11. What the engine handles automatically vs. what needs you

The engine handles:

- Generating new KSK and ZSK key pairs as the pipeline
  needs them.
- Publishing DNSKEY changes in the zone with appropriate
  pre-publication and post-removal hold times.
- Sending UPDATE or NOTIFY to the parent at the right
  moments.
- Polling the parent's DS state until the change is
  observed.
- Retrying with exponential backoff on transient
  failures.
- Going into long-term softfail mode if multiple attempts
  fail, with continued probing forever.
- Re-signing the zone (DNSKEY and other RRsets) as RRSIGs
  approach expiry, completely independent of rollover
  state.

The engine does *not* handle automatically:

- **Initial DS publication** at the parent. The first DS
  record must be published manually or via your
  registrar's normal workflow before automated rollover
  can begin. The engine takes over from there.
- **Hardfail recovery**. If a rollover fails enough times
  to hit hardfail, it stops and waits for operator
  intervention. The zone keeps working with the previous
  active key; you have time to investigate. Use
  `auto-rollover unstick` after fixing the underlying
  cause.
- **Algorithm rollover** (e.g. RSA → ECDSA, or
  ECDSA → MLDSA). Out of scope today.
- **ZSK rollover**. Out of scope today; the policy's
  `zsk.lifetime` is honored as RRSIG validity input but
  the engine does not currently roll ZSKs automatically.


## 12. When something goes wrong

The failure categories the engine recognizes:

- **child-config:waiting-for-parent**: the parent
  advertises no DSYNC scheme this rollover policy can use
  (either no DSYNC at all, or `force-*` policy and the
  forced scheme isn't advertised). The engine halts but
  probes forever with backoff capped at 1h, never
  increments the hardfail counter, and auto-recovers when
  the parent restores DSYNC advertisement. No operator
  action required on the child side.

- **child-config:local-error**: something on your side is
  wrong (no SIG(0) key, no DS to publish, parent zone not
  resolvable, CDS publish-and-sign queue failure). Goes
  to softfail after `max-attempts-before-backoff`
  consecutive failures. Operator intervention typically
  required.

- **transport**: network-level failure to reach the
  parent (timeout, connection refused). The engine
  retries.

- **parent-rejected**: the parent acknowledged the
  request but responded with REFUSED, NOTAUTH, FORMERR,
  or SERVFAIL. The daemon's logs include EDE codes when
  the parent supplies them -- these are the most
  operationally-actionable errors. For NOTIFY pushes, the
  new `EDENotifyDsyncSchemeNotAdvertised` EDE catches
  misconfigured children on the very first push.

- **parent-publish-failure**: the parent acknowledged but
  the DS RRset never appeared in the parent zone. The
  engine retries. NOTE: on a NOTIFY-advertising parent,
  async CDS validation failures inside the parent's
  scanner surface here rather than as parent-rejected
  (NOTIFY ACK is sent before the scan runs). Consult the
  parent-side scanner logs to disambiguate
  parent-internal causes.

For investigations, start by reading the daemon logs and
the output of `auto-rollover status`. The status output
identifies the current phase and the most recent failure
reason. The softfail/hardfail counters tell you how many
attempts have happened. The `last_softfail_*` fields tell
you when and why.


## 14. ZSK rollover

A ZSK rollover replaces the zone-signing key. Unlike the
KSK, the ZSK has no DS at the parent, so there is **no
parent coordination** -- the whole rollover is local to the
zone and bounded only by the zone's own TTLs. This makes it
much simpler than the KSK case, and most of sections 4-12
(parent DS push, confirm, softfail, DSYNC dispatch) do not
apply.

The lifecycle is the familiar pre-publish roll: a standby
ZSK is generated and published ahead of time; when the
active ZSK reaches `zsk.lifetime` (or you trigger it),
standby becomes active, the old active becomes retired, and
after a drain window (propagation delay + the longest TTL it
signed) the retired key is removed and its signatures are
stripped. The engine keeps `standby-zsk-count` standbys
ready so a roll never waits on key generation.

**Configuration.** The ZSK lifetime and signature validity
live in the same policy block as the KSK:

```yaml
   mypolicy:
      algorithm:   ED25519
      zsk:
         lifetime:    2w      # roll cadence (forever = never)
         sigvalidity: 2h
```

`zsk.lifetime: forever` disables the scheduled roll; you can
still roll manually with `asap --zsk`.

**Operating it.** The same `auto-rollover` commands drive
the ZSK, with `--zsk`:

```
auto-rollover when   --zone Z --zsk     # next/earliest ZSK roll
auto-rollover asap   --zone Z --zsk     # roll at the earliest moment
auto-rollover cancel --zone Z --zsk     # cancel a pending asap
auto-rollover status --zone Z           # shows KSK and ZSK both
```

`asap --zsk` schedules a roll for the next worker tick; if
no standby ZSK is ready yet, the request persists until one
is and then fires (it is not lost). Because a ZSK roll has
no DS dance, `when --zsk` shows only the local schedule
(active_at + lifetime) and a "ready / waiting-for-standby"
status -- there are no parent-DS gates. The `status` output
lists ZSKs alongside KSKs, each with its own `active_seq`
counter (the n-th active ZSK in the zone's history), which
ticks up by one on every roll -- a quick confirmation that a
roll progressed.


## 15. Algorithm rollover

An algorithm rollover changes the signing *algorithm*, not
just the key -- for example ED25519 to a post-quantum
algorithm. It reuses the rollover pipelines: you bind the
zone to a policy with the new algorithm, and from then on
newly-generated keys carry it while the old-algorithm keys
drain out in the normal FIFO order. Nothing is swapped
synchronously; the transition is gradual and safe at every
instant.

Today the **relaxed-mode ZSK** algorithm rollover is
implemented. The following are deliberately **refused** with
a clear error rather than run unsafely (they are later
work): a KSK-algorithm rollover (it needs the parent-DS
engine), a CSK-algorithm change, a both-roles-at-once
change, and a ZSK-algorithm change under strict completeness
mode.

**The completeness knob.** A ZSK signs the whole zone, so a
strict reading of RFC 4035 would require maintaining
old-algorithm signatures over the entire zone throughout the
drain -- expensive. TDNS exposes a global choice:

```yaml
dnssec:
   completeness: relaxed     # strict (default) | relaxed
```

`relaxed` (the alg-split model) drops the maintained
whole-zone double-signature: the new algorithm signs
everything and the old-algorithm key simply drains, which
every validator still accepts (a validator needs one working
chain, not one per algorithm). A ZSK algorithm rollover
requires `relaxed`; under the default `strict` it is
refused.

**The two-command workflow.** Binding the new algorithm and
performing the roll are separate steps:

```
# 1. bind the new algorithm (changes only FUTURE keys)
auto-rollover policy-change --zone Z --policy newalg-policy

# 2. drive the drain (each asap promotes the next standby)
auto-rollover asap --zone Z --zsk
```

`policy-change` does NOT roll anything -- it writes the
zone's policy override so that future-generated ZSKs use the
new algorithm, and the existing keys keep draining in order.
The roll then advances on the normal ZSK cadence, or you
accelerate it with `asap --zsk`: each `asap` promotes the
next standby, and because the existing standbys are already
propagated, successive `asap`s run back-to-back until the
new-algorithm keys take over. A second `policy-change` while
a roll is already in flight is refused; cancel first
(`cancel --zsk`) if you need to change course.

**Watching it.** `auto-rollover status` shows an
algorithm-transition line in the header while a roll is in
flight, e.g.

```
Algorithm rollover: ZSK ED25519 -> MAYO1  (in progress), 1 of 3 published ZSKs on new algorithm
```

The roll is complete when every live ZSK is on the new
algorithm and the old-algorithm keys have drained out and
been removed.

For the design rationale and the safety model see
`tdns/docs/2026-06-17-algorithm-rollover-evaluation.md` (the
ZSK alg roll) and
`tdns/docs/2026-06-21-ksk-algorithm-rollover-plan.md` (the
planned KSK alg roll).


## 16. Further reading

- **Timing math:** the canonical engine reference is
  [Rollover Timing Equations](rollover-timing-equations.md)
  -- cache-flush invariants, parent-DS-RRset contract,
  equations E1-E13.
- **Design background:** the rollover-overhaul plan at
  `tdns/docs/2026-04-29-rollover-overhaul.md` documents
  the state machine, failure model, and
  softfail/hardfail bookkeeping.
- **NOTIFY-scheme push path:** the design at
  `tdns/docs/2026-04-30-rollover-notify-scheme.md`
  documents the parallel UPDATE+NOTIFY DS-push model
  and the `dsync-scheme-preference` knob.
- **Multi-provider DNSSEC:** see the
  [tdns-mp guide](../../tdns-mp/guide/) for KSK rollover
  in multi-provider deployments. The single-provider
  guidance here applies; the multi-provider extension
  adds leader election so only one provider drives the
  rollover at a time.
- **DSYNC (RFC 9859):** the parent-side advertisement
  of delegation-sync schemes. Required for automated
  rollover. See section 1 of
  [Special Features](special-features.md) for the
  delegation-sync mechanics this engine reuses.
- **RFC 7583:** DNSSEC Key Rollover Timing
  Considerations. The conceptual foundation for the
  bounds discussed here.
