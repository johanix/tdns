# TDNS Operator Guide: Rapid Automated KSK Rollover

This guide walks through configuring tdns-auth and tdns-agent to
perform automated KSK rollovers on a configurable cadence — from
seconds-apart for testbeds, through hours and days for routine
operations, up to monthly or quarterly for stable production.

The audience is operators with hands-on experience in DNS and
DNSSEC who are new to *automated* KSK rollover specifically. The
guide assumes you know what a DNSKEY, DS, RRSIG, TTL, and the
DNSSEC chain of trust are; it explains how those pieces relate
to each other in the context of frequent rollovers, what tdns
parameters control which behaviour, and how to choose values that
fit your operational reality.

If you are looking for the architecture or design rationale, see
the design documents under `tdns/docs/`. This document is the
operator-facing how-to.


## 1. The mental model: three independent knobs

DNSKEY rollover safety is governed by three operational
parameters that are easy to confuse with each other but are in
fact independent. Configuring them as if they were coupled
produces working-but-suboptimal setups; configuring them as
genuinely orthogonal lets you tune each for its own purpose.

The three knobs are:

1. **Maximum zone TTL.** Bounds how long stale data can live in
   resolver caches. Determines the **earliest possible rollover
   time** if you ever need to roll outside the regular schedule.
2. **KSK lifetime.** The rollover cadence — the policy-driven
   "next scheduled rollover" interval. Independent of safety
   bounds; choose based on key compromise risk, regulatory
   requirements, or operational preference.
3. **RRSIG validity.** How long signatures remain valid in
   already-served responses. Determines **signing-outage
   tolerance** — how long the signing infrastructure can be
   down before RRSIGs in cache start expiring and the zone goes
   bogus.

Each knob has exactly one job:

| Knob | Bounds what | Primary use |
|------|-------------|-------------|
| Max zone TTL | Cache flush time | Earliest unscheduled rollover |
| KSK lifetime | Scheduled rollover cadence | Routine rotation interval |
| RRSIG validity | Signing-outage survival | Weekend / holiday resilience |

The same fact stated differently: **none of these constrains the
other two.** A 5-minute rollover cadence is fine with a 14-day
RRSIG validity. An 8-hour TTL is fine with a 7-day cadence. A
30-day RRSIG validity is fine with a 1-hour TTL. The combinations
that look "weird" are often the right answers.


## 2. Why the three knobs are orthogonal

Operators frequently couple these in their head because all three
are time durations applied to the same zone. Coupling them was
historically common because some implementations enforced
relationships that didn't actually need to exist. The tdns engine
treats them as independent. Here is why they actually are:


### 2.1 TTL bounds cache-flush time

When you change something in your zone, validators that have
cached the old data continue to use it until either their cache
TTL expires *or* the cached RRSIG expires. Either of those
forces them to refetch, and the refetch returns fresh state. So
each cache entry stops being usable after `min(TTL,
remaining_RRSIG_validity)`.

For "all caches everywhere are now using fresh state," the
bound is the longest such interval across all validators that
recently cached the data. Conservative upper bound: TTL itself.
This is true regardless of how long RRSIG validity is, because
TTL is the cap.

For a **rollover** specifically, the operationally-relevant
cache-flush concern is: "all validators are using the new DNSKEY
data before the parent points to a different key." The answer is
your zone's max TTL plus a small safety margin. Nothing else.


### 2.2 KSK lifetime sets cadence, not safety

The rollover cadence is a policy choice, not a safety boundary.
You roll keys periodically because:

- It exercises the rollover machinery, so you find out it's
  broken when you have time to fix it rather than during an
  emergency.
- It limits the operational window in which a compromised key
  matters.
- Some compliance regimes mandate periodic rotation.

The cadence does not have to be related to any safety property.
A 7-day cadence with an 8-hour TTL is a normal, sensible setup.
So is a 5-minute cadence on a testbed where you want the
machinery exercised continuously.

The only real lower bound on cadence is operational: how often
are you willing to be paged for things that go wrong? Faster
cadence means more rollovers per week means more chances for
something to break in a way that needs human attention. We
discuss this in section 5.


### 2.3 RRSIG validity governs outage survival

A signed zone serves RRSIGs. RRSIGs have explicit `Inception`
and `Expiration` fields in the wire format. After `Expiration`,
validators reject responses signed by that RRSIG: they will no
longer treat the data as authentic and will return SERVFAIL to
their clients. The zone goes bogus from the validator's
perspective, regardless of cache TTLs.

For the zone to keep validating, the signing engine must
periodically re-sign the zone and replace expiring RRSIGs with
fresh ones. The re-sign cadence is determined by the engine's
"resign when remaining validity drops below threshold" rule —
typically resign when remaining validity drops below half (or a
third) of the full validity period.

So at any given moment, the RRSIGs published in the zone have
remaining validity somewhere in `[resign_threshold,
full_validity]`. The minimum value of that range is your
**signing-outage tolerance**: if the signing engine breaks now,
that's how long the zone will keep validating before RRSIGs in
caches start expiring and you're in trouble.

A long weekend is roughly four days. Add a buffer for diagnosis
and fix once the operator returns. Six days is a comfortable
target. Seven days is conservative.

If you set RRSIG validity to 7 days and resign at half-expiry
(when 3.5 days remain), the floor of remaining validity is 3.5
days. Not enough. If you set 14 days and resign at half-expiry
(when 7 days remain), the floor is 7 days. Comfortable.

This argument has nothing to do with rollover cadence or zone
TTLs. It is purely about signing-infrastructure resilience.


## 3. The cache-flush analysis (for the curious)

This subsection is optional reading. It justifies the claim in
section 2.1 that "TTL is the cache-flush bound regardless of
RRSIG validity."

Consider a single validator that just queried your zone and now
has the DNSKEY RRset cached, with the accompanying RRSIG.

The validator's cache entry expires at `fetch_time +
min(TTL, RRSIG_remaining_validity_at_fetch_time)`.

Either condition forces a refetch. Either way, the refetch
delivers fresh state. So the cache entry "expires" — in the
sense of "no longer represents stale state for our purposes" —
at the earlier of those two times.

For an "all validators have fresh state" bound, we want the
worst-case validator's cache age. The worst case is a validator
that fetched immediately before our rollover, with `RRSIG_remaining
== full_validity` (because we just signed). Cache age = `min(TTL,
full_validity)`.

In any reasonable production zone, `TTL << full_validity`
(your zone's TTLs are hours, your RRSIG validity is days or
weeks). So `min(TTL, full_validity) = TTL`. RRSIG validity drops
out of the cache-flush bound entirely.

The unusual `TTL > full_validity` regime would invert this and
make `RRSIG_remaining` the bound. tdns currently assumes the
typical regime; if you have a specific reason to invert it, you
will need to engage with the design docs and probably need
custom work. The default tdns earliest-rollover gate is just
`now + max_ttl + margin`.


## 4. Worked examples

Three illustrative scenarios with concrete values.


### 4.1 The 10-minute testbed

You're running a multi-provider DNSSEC testbed and want to
exercise the rollover machinery as fast as practical. You can
afford zone TTLs of seconds. You don't care about long-weekend
resilience because the testbed is on a local network with you
watching it.

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

- `ksk.lifetime: 10m` makes the next-scheduled rollover fire ten
  minutes after the current active key became active. Your
  testbed will roll continuously.
- `ksk.sig-validity: 30m` is much shorter than production but
  appropriate for a local testbed where outages are minutes,
  not days. The engine resigns DNSKEY RRSIGs as they approach
  expiry.
- `ttls.max_served: 300s` caps everything in the zone at five
  minutes; combined with `clamping.margin: 60s`, the engine can
  do an unscheduled rollover within ~5 minutes if needed.
- `clamping.margin: 60s` is the safety floor for TTL near
  rollover; you cannot go much lower without bumping into clock
  skew between the primary and validators.

This setup will roll cleanly in steady state. Don't deploy it to
production — the short RRSIG validity means the zone will go
bogus within an hour of any signing-engine hiccup.


### 4.2 Production with weekly cadence

You run a real zone, want to roll weekly to demonstrate
operational confidence in the rollover machinery, and need to
survive long weekends without paging.

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
- `ksk.sig-validity: 14d` with engine-default resign-at-half
  means RRSIGs always have at least 7 days remaining.
  Friday-evening signing failure leaves you 7 days of validity
  in caches — comfortably more than any plausible long weekend
  plus diagnosis time.
- `ttls.max_served: 8h` caps zone TTLs at eight hours,
  bounding the cache-flush window for emergency rollovers. With
  `clamping.margin: 15m`, an unscheduled rollover can fire
  about eight hours after request.
- `ds-publish-delay: 5m` is appropriate for a parent that
  publishes DS within a small batch window. For a registry that
  publishes hourly, set `1h` instead; for a daily registry,
  set `24h`. The engine derives the per-attempt timeout and
  softfail-delay defaults from this number.

This is a sensible default for most production deployments.
Adjust `ksk.lifetime` if you want a different cadence; the rest
of the parameters scale with operational reality, not cadence.


### 4.3 Production with monthly cadence

Same operational reality but you want a more conservative
rollover rhythm — perhaps to align with monthly maintenance
windows.

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

The only change from 4.2 is `ksk.lifetime` (30 days vs 7 days)
and `zsk.lifetime`. Everything else stays the same: long-weekend
resilience, cache-flush bound, parent expectations, safety
margin. The orthogonality of the three knobs lets you change
cadence without touching the rest.

Some operators prefer to bump `ksk.sig-validity` higher (to
30d) for monthly cadence as well, on the theory that "I'm only
checking on this thing monthly so it should survive a long
absence." That's reasonable but not necessary — the engine
re-signs continuously, not on the rollover schedule.


## 5. Operational considerations for fast cadences

Fast rollover cadences are operationally sound — the engine
keeps the zone validating throughout — but they have real costs
that are easy to underestimate:

**Alert noise.** Each rollover is a chance for something to
softfail. Multiply by zones managed and rollovers per week and
you may discover that your paging system is processing more
rollover events than anything else. Operators learn to ignore
the alerts. When something genuinely fails, it's missed.

**Stuck-zone duration.** If a rollover hits hardfail at the
start of a long weekend, it sits stuck-but-working until Monday.
The zone keeps validating with the *previous* active key — the
state machine is specifically designed so that key advancement
is gated on the new DS being confirmed at the parent, and
hardfail freezes that advancement. Nothing breaks. But for some
compliance regimes, "a rollover did not complete on schedule"
is itself an audit finding even when the zone is fine.

**Bug exposure rate.** Until the engine has been well-soaked,
fast cadences carry higher absolute risk of hitting a bug
regardless of operator presence.

For these reasons, **production zones should default to
cadences of 7 days or longer.** Faster cadences are appropriate
for testbeds, research zones, and zones with specific regulatory
requirements that mandate short key lifetimes. The rollover
machinery itself does not impose a lower bound — you can roll
every minute if you really want — but you should not.


## 6. Required configuration parameters

Per-zone configuration:

```yaml
zones:
  example.com:
    dnssec-policy: production-weekly  # name of the policy below
    # ... other zone fields
```

Per-policy configuration (under `dnssecpolicies:` at the top
level of the daemon config):

| Parameter | Required | Default | Purpose |
|-----------|----------|---------|---------|
| `algorithm` | yes | — | DNSSEC algorithm (e.g. `ECDSAP256SHA256`) |
| `mode` | no | `ksk-zsk` | `ksk-zsk` (separate KSK and ZSK) or `csk` (combined) |
| `ksk.lifetime` | yes | — | Rollover cadence (next scheduled = `active_at + lifetime`) |
| `ksk.sig-validity` | yes | — | RRSIG validity for DNSKEY signatures |
| `zsk.lifetime` | yes | — | ZSK rollover cadence (out of scope today; engine doesn't roll automatically) |
| `zsk.sig-validity` | yes | — | RRSIG validity for non-DNSKEY signatures |
| `rollover.method` | yes | `none` | `multi-ds`, `double-signature`, or `none` |
| `rollover.num-ds` | no | `3` (multi-ds) / `2` (double-signature) | DS count during rollover |
| `rollover.parent-agent` | yes if `method != none` | — | Parent's UPDATE/NOTIFY receiver, `host:port` |
| `rollover.ds-publish-delay` | no | `5m` | Parent's expected DS publication latency |
| `rollover.max-attempts-before-backoff` | no | `5` | Softfail threshold |
| `rollover.softfail-delay` | no | derived (≥ 1h, ≥ ds-publish-delay) | Long-term-mode probe interval |
| `rollover.dsync-scheme-preference` | no | `auto` | DSYNC scheme to use for DS push (see §6.4) |
| `rollover.confirm-initial-wait` | no | `2s` | First-poll delay after UPDATE |
| `rollover.confirm-poll-max` | no | derived (clamped 30s..5m) | Maximum DS-poll cadence |
| `rollover.confirm-timeout` | no | derived (`ds-publish-delay × 1.2`) | Per-attempt observation budget |
| `rollover.dsync-required` | no | `true` | Refuse if parent doesn't advertise DSYNC |
| `ttls.dnskey` | no | (zone default) | TTL for DNSKEY RRset |
| `ttls.max_served` | no | unbounded | Maximum TTL the daemon will serve |
| `clamping.enabled` | no | `false` | Whether to clamp TTLs near rollover |
| `clamping.margin` | yes if `clamping.enabled` | — | Safety floor for clamped TTL and retired-key hold time |


### 6.1 The `rollover.method` choice

`multi-ds` and `double-signature` are the two automated KSK
rollover algorithms.

- **`multi-ds`** publishes multiple DS records at the parent
  during the transition window (default 3). Validators see DS
  records for the outgoing key, the active key, and the
  incoming key simultaneously. This is the recommended default
  for most parents.

- **`double-signature`** publishes two DS records and signs
  the DNSKEY RRset with both keys during the transition. More
  bandwidth-intensive but tolerates a wider class of parent-
  side timing edge cases.

- **`none`** disables automated rollover for the policy. Use
  for zones where you'll roll manually.


### 6.2 The `rollover.ds-publish-delay` choice

This single number drives most of the timing defaults. It tells
the engine how long to wait, after sending the UPDATE (or
NOTIFY) to the parent, before expecting to see the new DS RRset
served at the parent's nameservers.

Common values:

| Parent type | Recommended `ds-publish-delay` |
|-------------|-------------------------------|
| Parent runs tdns-auth or similar direct-publish | `30s` to `5m` |
| Registry with batched publication, ~hourly | `1h` |
| Registry with daily publication | `24h` |
| Manual operator-reviewed registry | depends; consult registry SLA |

The engine derives the per-attempt timeout (`× 1.2`), poll
cadence (`min(delay/10, 5m)`), and softfail-delay (`max(1h,
delay)`) from this, so getting it roughly right matters more
than getting it exactly right.


### 6.3 The `rollover.dsync-scheme-preference` choice

This knob controls which DSYNC scheme(s) the rollover engine
uses to push the DS update to the parent. The parent advertises
its supported schemes via DSYNC RRs at `_dsync.<parent>`; this
knob decides what to do when the parent advertises more than
one, or when the operator wants to pin a specific scheme.

| Value | Both adv. | One adv. | Neither |
|-------|-----------|----------|---------|
| `auto` (default) | parallel UPDATE + NOTIFY | the advertised one | wait |
| `prefer-update` | UPDATE only | the advertised one | wait |
| `prefer-notify` | NOTIFY only | the advertised one | wait |
| `force-update` | UPDATE only | UPDATE only or wait | wait |
| `force-notify` | NOTIFY only | NOTIFY only or wait | wait |

"wait" = `child-config:waiting-for-parent` softfail, capped at
1h backoff, never hardfails, auto-recovers when DSYNC reappears.

`auto` is the right default for almost every operator: when the
parent advertises both UPDATE and NOTIFY for CDS, the engine
sends both in parallel. Either path NOERROR is enough to enter
the observe phase. The cost is one extra UDP NOTIFY per attempt
on a parent that advertises both; the benefit is that an
"advertised but broken" scheme on one path doesn't block the
rollover when the other works.

`prefer-*` values give explicit single-scheme behaviour on a
both-advertising parent — useful for log hygiene or when
debugging one path. `force-*` values are for testbeds and
adversarial-testing: if the parent doesn't advertise the
forced scheme, the engine refuses to fall through to the other
one (you asked for `force`, you got `force`).

NOTIFY async-rejection asymmetry: parent-side ProcessCDSNotify
runs *after* the NOTIFY ACK is sent. CDS validation failures,
RFC 9615 signaling check failures, and RFC 8078 bootstrap
policy refusals at the parent therefore surface as
`parent-publish-failure` from the child's POV — not as
`parent-rejected`, even when the underlying cause is a
parent-side rejection. To diagnose, consult the parent-side
scanner logs. (UPDATE pushes are synchronous and do surface
parent rejections as `parent-rejected` with EDE detail.)


### 6.4 The `clamping` choice

When clamping is enabled, the engine progressively lowers TTLs
near a scheduled rollover so that cached data flushes faster as
the rollover approaches. This shortens the window during which
old DNSKEY data could be cached past a rollover.

For most production deployments with `ttls.max_served` set, you
do not need clamping enabled — the always-on TTL ceiling already
gives you a known cache-flush bound. Clamping is more useful for
zones where you want to keep TTLs high in steady state but
shorten them just before rollovers.

If you enable clamping, `clamping.margin` is required and is
both:

- The TTL floor immediately before rollover (TTLs cannot be
  clamped below this).
- The retired-KSK hold time (how long a retired KSK stays in
  the zone after rollover, before final removal).

Set it to something well above clock-skew tolerance (60 seconds
minimum, 15 minutes typical for production).


## 7. Validation and verification

Once the policy is configured, validate the YAML before
restarting the daemon:

```sh
tdns-cliv2 zone keystore dnssec policy validate --file /etc/tdns/tdns-auth.yaml
```

This parses every policy under `dnssecpolicies:` and reports
configuration errors (invalid durations, missing required
fields, cross-field constraint violations) without affecting the
running daemon. The same validation runs implicitly when the
daemon loads the config, but doing it ahead of time avoids a
broken restart.

After deployment, query the zone's rollover state:

```sh
tdns-cliv2 auth keystore dnssec auto-rollover status --zone=example.com.
tdns-cliv2 auth keystore dnssec auto-rollover when --zone=example.com.
```

The `status` command shows the current phase, the active and
standby KSKs, and any in-flight or recent rollover state. The
`when` command shows two times:

- **next scheduled** — when the engine will fire the next
  rollover (driven by `ksk.lifetime`).
- **earliest possible** — the soonest the engine could fire an
  unscheduled rollover if you requested one (driven by zone
  TTLs and DS readiness).

These two times are usually different, sometimes by a wide
margin. Both are correct answers to different operator
questions.


## 8. What the engine handles automatically vs. what needs you

The engine handles:

- Generating new KSK and ZSK key pairs as the pipeline needs
  them.
- Publishing DNSKEY changes in the zone with appropriate
  pre-publication and post-removal hold times.
- Sending UPDATE or NOTIFY to the parent at the right moments.
- Polling the parent's DS state until the change is observed.
- Retrying with exponential backoff on transient failures.
- Going into long-term softfail mode if multiple attempts fail,
  with continued probing forever.
- Re-signing the zone (DNSKEY and other RRsets) as RRSIGs
  approach expiry, completely independent of rollover state.

The engine does *not* handle automatically:

- **Initial DS publication** at the parent. The first DS record
  must be published manually or via your registrar's normal
  workflow before automated rollover can begin. The engine
  takes over from there.
- **Hardfail recovery**. If a rollover fails enough times to
  hit hardfail, it stops and waits for operator intervention.
  The zone keeps working with the previous active key; you have
  time to investigate. Use `auto-rollover unstick` after fixing
  the underlying cause.
- **Algorithm rollover** (e.g. RSA → ECDSA). Out of scope today.
- **ZSK rollover**. Out of scope today; the policy's
  `zsk.lifetime` is honored as RRSIG validity input but the
  engine does not currently roll ZSKs automatically.


## 9. When something goes wrong

The failure categories the engine recognizes:

- **child-config:waiting-for-parent**: the parent advertises no
  DSYNC scheme this rollover policy can use (either no DSYNC at
  all, or `force-*` policy and the forced scheme isn't
  advertised). The engine halts but probes forever with backoff
  capped at 1h, never increments the hardfail counter, and
  auto-recovers when the parent restores DSYNC advertisement.
  No operator action required on the child side.

- **child-config:local-error**: something on your side is wrong
  (no SIG(0) key, no DS to publish, parent zone not resolvable,
  CDS publish-and-sign queue failure). Goes to softfail after
  `max-attempts-before-backoff` consecutive failures. Operator
  intervention typically required.

- **transport**: network-level failure to reach the parent
  (timeout, connection refused). The engine retries.

- **parent-rejected**: the parent acknowledged the request but
  responded with REFUSED, NOTAUTH, FORMERR, or SERVFAIL. The
  daemon's logs include EDE codes when the parent supplies them
  — these are the most operationally-actionable errors. For
  NOTIFY pushes, the new `EDENotifyDsyncSchemeNotAdvertised`
  EDE catches misconfigured children on the very first push.

- **parent-publish-failure**: the parent acknowledged but the
  DS RRset never appeared in the parent zone. The engine
  retries. NOTE: on a NOTIFY-advertising parent, async CDS
  validation failures inside the parent's scanner surface here
  rather than as parent-rejected (NOTIFY ACK is sent before the
  scan runs). Consult the parent-side scanner logs to
  disambiguate parent-internal causes.

For investigations, start by reading the daemon logs and the
output of `auto-rollover status`. The status output identifies
the current phase and the most recent failure reason. The
softfail/hardfail counters tell you how many attempts have
happened. The `last_softfail_*` fields tell you when and why.


## 10. Further reading

- **Design background:** the rollover-overhaul plan at
  `tdns/docs/2026-04-29-rollover-overhaul.md` documents the
  state machine, failure model, and softfail/hardfail
  bookkeeping.
- **NOTIFY-scheme push path:** the design at
  `tdns/docs/2026-04-30-rollover-notify-scheme.md` documents
  the parallel UPDATE+NOTIFY DS-push model and the
  `dsync-scheme-preference` knob (§6.3 above).
- **Multi-provider DNSSEC:** see the tdns-mp guide
  (`tdns-mp/guide/`) for KSK rollover in multi-provider
  deployments. The single-provider guidance here applies; the
  multi-provider extension adds leader election so only one
  provider drives the rollover at a time.
- **DSYNC (RFC 9859):** the parent-side advertisement of
  delegation-sync schemes. Required for automated rollover.
- **RFC 7583:** DNSSEC Key Rollover Timing Considerations. The
  conceptual foundation for the bounds discussed here.
