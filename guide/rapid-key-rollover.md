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
discuss this in section 6.


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


## 4. Timing equations and cache-flush invariants

This section is the **canonical reference** for the rollover
engine's timing math. Implementation must match the equations
here. If code disagrees, this section wins or the disagreement is
filed as a design issue.

The earlier "cache-flush analysis" (§3) gives the intuition; this
section makes it rigorous.

### 4.1 Notation

Throughout: `T_X` denotes a **timestamp** (a moment in wall time);
plain `X` denotes a **duration** (a difference between two
timestamps). Equations mix the two; durations always add to or
subtract from timestamps to yield timestamps.

`KSK_n` denotes the n-th KSK in the rollover pipeline. `T_roll_n`
is the moment KSK_n becomes active and starts signing the zone's
RRSIG-over-DNSKEY (and therefore the entire chain of trust).

### 4.2 Parameters

Every duration the timing math depends on, with the config knob
or observation that supplies its value.

| Symbol | Type | Source | What it represents |
|--------|------|--------|--------------------|
| `parent_prop` | duration | operator estimate via `rollover.ds-publish-delay` | Parent-side primary→secondary AXFR/IXFR + parent registry-pipeline latency. Time between "child sent UPDATE / NOTIFY accepted by parent" and "parent's secondaries serve the new DS RRset." |
| `DS_TTL` | duration | **observable** in DS responses (every DS poll carries the TTL field) | TTL of the DS RRset at the parent. Bounds how long resolvers cache the old DS after parent publishes a new one. |
| `child_prop` | duration | `kasp.propagation_delay` | Child-side primary→secondary propagation. Time between "child primary publishes new DNSKEY RRset" and "all child secondaries serve it." |
| `DNSKEY_TTL` | duration | derived: `min(ttls.dnskey, ttls.max_served)` clamped further by K-step clamping near rollover | TTL of the DNSKEY RRset as actually served to validators. Bounds how long resolvers cache the old DNSKEY RRset after the child publishes a new one. |
| `KSK_lifetime` | duration | `ksk.lifetime` config knob | Rollover cadence — the policy-driven interval between successive KSK activations. Steady-state: `T_roll_n − T_roll_{n−1} = KSK_lifetime`. |
| `retirement_period` | duration | `effective_margin = max(clamping.margin, max_observed_TTL)` in current engine | The hold time between a KSK transitioning to retired (at T_roll_n) and being removed (at T_roll_n + retirement_period). During the retirement period the key's DNSKEY is still in the zone but the engine no longer signs new things with it. Sized so that all cached RRSIGs by the retiring key have flushed by the time it's removed (see §4.5.1). |
| `N` | dimensionless | `rollover.num-ds` config knob | Multi-DS pipeline depth — how many DS records the engine maintains at the parent simultaneously (active + N−1 future). |
| `T_roll_n` | timestamp | `T_roll_n = T_roll_{n−1} + KSK_lifetime` (steady-state cadence; bootstrap defines `T_roll_1` independently) | Moment KSK_n becomes the active signer. |
| `T_DS_pub_n` | timestamp | observed from parent DS query (= when DS for KSK_n first appears at parent) | Moment parent's primary publishes DS for KSK_n. |
| `T_DNSKEY_pub_n` | timestamp | engine-controlled: ds-published → standby transition for KSK_n | Moment child's primary publishes DNSKEY_n in the served DNSKEY RRset. |

### 4.3 The two cache-flush invariants

For KSK_n to take over signing safely at `T_roll_n`, two
independent cache-flush conditions must hold.

**Invariant DS** — *if* a validator has the parent's DS RRset in
its cache at `T_roll_n`, that cached RRset must contain DS_n.
Validators with no cached DS are fine: they fetch fresh on the
next need and get DS_n. The dangerous case is a validator with a
stale cache entry that excludes DS_n; for that to be impossible
at `T_roll_n`, every cache entry created before DS_n landed at
the parent's secondaries must have expired by `T_roll_n`. The
worst case is a validator that fetched DS just before secondaries
had DS_n; its cache lasts `DS_TTL` more. So:

```
T_DS_pub_n + parent_prop + DS_TTL  ≤  T_roll_n               (E1)
```

Equivalently, the latest DS_n can be published at parent and still
satisfy the invariant:

```
T_DS_pub_n  ≤  T_roll_n − parent_prop − DS_TTL               (E2)
```

**Invariant DNSKEY** — *if* a validator has the child's DNSKEY
RRset in its cache at `T_roll_n`, that cached RRset must contain
DNSKEY_n. Same reasoning on the child side:

```
T_DNSKEY_pub_n + child_prop + DNSKEY_TTL  ≤  T_roll_n        (E3)
```

Equivalently:

```
T_DNSKEY_pub_n  ≤  T_roll_n − child_prop − DNSKEY_TTL        (E4)
```

The two invariants are independent because they govern different
caches: DS lives at the parent and is cached on the way down the
delegation chain; DNSKEY lives at the child and is cached when
validators look up the chain. Both must be in place at `T_roll_n`.

### 4.4 DS-side: the parent-DS-RRset contract

The multi-DS scheme is best stated as a contract on the parent's
DS RRset rather than a derived property of the engine's internal
state.

**Contract.** The parent's DS RRset *always* contains exactly
`N` records (`N` = `rollover.num-ds`). Never fewer, never more.

The composition cycles between two states:

**State A — "retiring":** during the retirement period after a
rollover, the parent holds:
```
{ DS_{n−1},  DS_n,  DS_{n+1},  ...,  DS_{n+N−2} }
   ↑           ↑         ↑                     ↑
   retiring   active    future_1 …          future_{N−2}
```

**State B — "post-retirement":** after the just-rolled-out key has
been removed locally (its retirement period elapsed), the parent
holds:
```
{ DS_n,   DS_{n+1},   DS_{n+2},  ...,  DS_{n+N−1} }
   ↑         ↑                                  ↑
   active   future_1                       future_{N−1}
```

Total in both states: N records. The transition from State A to
State B is always **simultaneous** — the same DNS UPDATE drops
DS_{n−1} and adds DS_{n+N−1}, which keeps the parent's RRset at
exactly N records throughout (no transient state with N−1 or N+1).

**State A** holds for the retirement period (typically a few minutes
to a few hours, depending on `clamping.margin` /
`max_observed_TTL`). **State B** holds for the rest of the
rollover lifetime (`KSK_lifetime − retirement_period`, the
overwhelming majority of normal operation).

For N=3, the smallest interesting case:
- State A: `{DS_{n−1}, DS_n, DS_{n+1}}` — one retiring key's DS,
  one active, one future.
- State B: `{DS_n, DS_{n+1}, DS_{n+2}}` — no retiring key's DS,
  active plus two future.

The DNSKEY RRset in the *child* zone does not have a strict
"always N" contract — when the engine holds a future KSK in
ds-published state (DNSKEY not yet revealed; see §4.7), the
DNSKEY RRset shrinks even though the DS RRset stays at N. The
DS-side contract holds even while the DNSKEY-side composition
varies, because DS records are post-quantum-opaque and the
cost of an extra DS record at the parent is negligible.

### 4.5 Maintaining the contract: events and atomicity

Four engine actions are involved in keeping the parent's DS
RRset compliant with the contract:

**(a) Rollover fires at `T_roll_n`.** KSK_{n−1} → retired,
KSK_n → active in the *child* zone via `AtomicRollover`.
**Parent DS RRset is unchanged.** The composition simply gets
relabeled — what was the "active" slot (DS_{n−1}) is now the
"retiring" slot, and what was "future_1" (DS_n) is now "active."
The parent's primary, secondaries, and validator caches see no
change.

**(b) Retirement period elapses; KSK_{n−1} → removed.** This is the
critical event. The child-side action happens first: remove
DNSKEY_{n−1} from the served DNSKEY RRset and re-sign the RRset
with the new active KSK_n.

*After* DNSKEY_{n−1} has been removed from the child DNSKEY
RRset, two parent-side operations must happen in a single
atomic DNS UPDATE:

  - Remove DS_{n−1} from the parent's RRset.
  - Add DS_{n+N−1} (the next pre-publication slot).

Both go in the same wire-level transaction. After this, the
parent transitions from State A to State B. The contract is
preserved throughout: at every instant, the parent serves
exactly N DS records.

**Comments:**

- **No additional wait between local removal and parent update
  is needed.** The retirement period was sized precisely to
  ensure that by `T_remove_{n−1}` no cached RRSIG anywhere
  references KSK_{n−1} (see §4.5.1 for the sizing constraint).
  Validators that still have a stale DNSKEY RRset cached (with
  KSK_{n−1} included in the key set) are harmless: no RRSIG
  points at KSK_{n−1} as its signer, so no validation chain
  leans on DS_{n−1}.

- **Trigger.** The local retired → removed state transition of
  KSK_{n−1}, owned by the child-side rollover engine. The
  retirement period that gates this transition is the
  `effective_margin = max(clamping.margin, max_observed_TTL)`
  of the child zone — sized so that the §4.5.1 invariant holds.

- **Why removing DS_{n−1} promptly matters.** DS_{n−1}
  authenticates a key the operator has decided to roll away
  from. That key may be weakened, suspect, or actually
  compromised — it could be exactly *why* the operator is
  rolling. Leaving DS_{n−1} at the parent longer than the
  retirement period requires extends the window during which
  an attacker holding the old key material can still produce
  validatable responses. The retired → removed transition is
  the right trigger; nothing else is.

#### 4.5.1 What `retirement_period` must guarantee

The "no extra wait needed" argument above relies on a precise
sizing constraint for the `retirement_period`:

```
retirement_period  ≥  min(DNSKEY_TTL, KSK.SigValidity)       (E5)
```

where `KSK.SigValidity` is the RRSIG validity period for KSK
signatures over the DNSKEY RRset. Why this bound:

A validator that cached the DNSKEY response just before
`T_roll_n` holds a response whose effective lifetime in cache is
`min(DNSKEY_TTL, RRSIG_remaining_validity_at_cache_time)`.
Worst case: the RRSIG was signed just before being fetched, so
its remaining validity equals the full `KSK.SigValidity`. Cache
lifetime in that worst case = `min(DNSKEY_TTL, KSK.SigValidity)`.

For all such cached responses (and therefore all cached RRSIGs
by KSK_{n−1}) to have flushed from validator caches by
`T_remove_{n−1}`, the retirement period must be at least this
duration.

For the testbed: `min(DNSKEY_TTL, KSK.SigValidity) =
min(5m, 20m) = 5m`. The configured `effective_margin =
max(clamping.margin, max_observed_TTL) = max(5m, 5m) = 5m`.
The constraint is met exactly.

The current engine's `effective_margin` formula generally
satisfies this constraint because `max_observed_TTL ≥
DNSKEY_TTL ≥ min(DNSKEY_TTL, KSK.SigValidity)`. But the
constraint should be made an explicit policy-validation check
at config-load time: if an operator sets `KSK.SigValidity <
clamping.margin` AND `KSK.SigValidity < max_observed_TTL`, the
sizing rule still holds, but for the wrong reason. The
operator-facing rule is best stated as the explicit inequality
above.

**(c) Pipeline maintenance.** The engine continuously generates
new KSKs and submits their DS to the parent so that future slots
are filled when (b) needs to add DS_{n+N−1}. This generation is
decoupled from the rollover schedule — keys are generated
whenever the local pipeline-fill logic notices a slot needs
filling.

**(d) Bootstrap and recovery.** First time the engine sees a
zone, or after a hardfail-and-recovery, the contract may not
hold (parent has fewer than N records). The engine fills the
pipeline as fast as the parent's `parent_prop + DS_TTL` allows.
During this fill, the contract's "always exactly N" claim is
relaxed; once the pipeline is full it holds again.

### 4.6 DS-side: when does DS_n land at the parent?

To validate Invariant DS (E1), we need `T_DS_pub_n` — the moment
DS_n first appeared in the parent's RRset.

**The simple framing:** `DS_n is published at the same atomic
operation that removes DS_{n−N}` (the State A → State B
transition described in §4.5(b)). That operation happens at:

```
T_DS_pub_n  =  T_roll_{n−N+1} + retirement_period            (E6)
```

Where `T_roll_{n−N+1}` is the moment KSK_{n−N+1} became active.
(If you prefer to think in "rollovers ago": the State A → State
B transition that publishes DS_n is the one immediately
following the (N−1)-rollovers-ago activation.)

Substituting `T_roll_{n−N+1} = T_roll_n − (N − 1) × KSK_lifetime`:

```
T_DS_pub_n  =  T_roll_n − (N − 1) × KSK_lifetime + retirement_period   (E7)
```

Lead time before `T_roll_n`:

```
lead_DS  =  T_roll_n − T_DS_pub_n
         =  (N − 1) × KSK_lifetime − retirement_period       (E8)
```

For Invariant DS (E1) to hold:

```
(N − 1) × KSK_lifetime − retirement_period  ≥  parent_prop + DS_TTL   (E9)
```

Equivalently, the operational constraint on the rollover cadence:

```
(N − 1) × KSK_lifetime  ≥  retirement_period + parent_prop + DS_TTL   (E10)
```

**Interpretation.** The multi-DS pipeline depth `N` gives the
engine `(N − 1)` rollover cycles of buffer for DS-side
propagation. Subtract the retirement period (during which the new
"future" slot doesn't yet exist at the parent), and what
remains must accommodate `parent_prop + DS_TTL`. Choose `N`,
`KSK_lifetime`, `retirement_period`, and the parent's `DS_TTL`
such that E10 holds; the rest is automatic.

**For the testbed config.** N=3, KSK_lifetime=10m,
retirement_period=5m (`clamping.margin`), parent_prop≈30s, DS_TTL≈5m:

```
(N − 1) × KSK_lifetime  =  2 × 10m  =  20m
retirement_period + parent_prop + DS_TTL  =  5m + 30s + 5m  =  10m30s
20m ≥ 10m30s     ✓     (9m30s of headroom)
```

The testbed is comfortably within its DS-side budget. E10 becomes
interesting at smaller `N` (e.g. would-be N=2 multi-DS would have
`(N − 1) × KSK_lifetime = 10m` against the 10m30s requirement —
fail), or with much faster cadences (`KSK_lifetime = 2m` against
the same requirement — fail unless `N` is raised).

**Production rule of thumb.** For comfortable margins, pick:

```
N  ≥  ⌈(retirement_period + parent_prop + DS_TTL) / KSK_lifetime⌉ + 1   (E11)
```

For typical production values (retirement_period=8h, parent_prop=5m,
DS_TTL=1h, KSK_lifetime=7d): RHS of E11 = ⌈9h5m / 168h⌉ + 1 =
1 + 1 = 2. So even N=2 works comfortably for slow cadences. The
default N=3 gives substantial margin.

### 4.7 DNSKEY-side: precise engine equation for ds-published → standby

The child controls `T_DNSKEY_pub_n` directly: it's the moment the
rollover engine advances KSK_n from state `ds-published` to
`standby`, at which point the DNSKEY enters the served DNSKEY
RRset.

To minimize DNSKEY exposure (the post-quantum motivation for
keeping unrevealed keys at DS-only), the engine should advance
**as late as the invariant permits**:

```
T_DNSKEY_pub_n  =  T_roll_n − child_prop − DNSKEY_TTL        (E12)
```

Equivalently, the engine's transition rule:

> Advance KSK_n from `ds-published` to `standby` at time
> `T_roll_n − child_prop − DNSKEY_TTL`.

E12 is the canonical formula. Any code that implements
ds-published → standby must use it.

### 4.8 Effective DNSKEY_TTL: the clamping caveat

The DNSKEY_TTL parameter is the TTL **as served to validators at
the moment they cache the response**, not the TTL the operator
configured.

Three knobs collapse into the served TTL:

1. **`ttls.dnskey`** — operator's intended DNSKEY TTL (e.g. 2h).
2. **`ttls.max_served`** — zone-wide TTL ceiling. The serving
   layer clamps any RRset's TTL down to this on-the-wire. So the
   served DNSKEY TTL is `min(ttls.dnskey, ttls.max_served)`.
3. **K-step clamping near rollover** — when clamping is enabled,
   TTLs progressively reduce to `clamping.margin` as `T_roll_n`
   approaches. A validator that queries during the clamping
   window caches an even shorter TTL.

For the cache-flush invariant the engine must use the **largest
TTL a validator might have cached just before `T_DNSKEY_pub_n`**.
That's `min(ttls.dnskey, ttls.max_served)` when clamping has not
yet kicked in for the upcoming rollover. K-step clamping
shortens this further but is conservative (not relied on by the
invariant).

So the operator-facing rule:

```
DNSKEY_TTL  =  min(ttls.dnskey, ttls.max_served)             (E13)
```

If `ttls.max_served` is set (recommended for any zone with
auto-rollover), it's the value that matters.

### 4.9 Parent-side parameters: observable, not unknown

Yesterday's framing of "parent-side timing as an unknown gap" was
incorrect. Both `parent_prop` and `DS_TTL` have well-defined
sources:

- **`parent_prop` ≈ `rollover.ds-publish-delay`.** The operator
  estimates parent-side latency as the `ds-publish-delay` config
  knob and tunes it per parent based on observed behaviour.
  `ds-publish-delay = 30s` for direct-publish parents,
  `ds-publish-delay = 1h` for batched registries, and so on. The
  engine's existing usage of `ds-publish-delay` as the
  observation budget is consistent with this interpretation.

- **`DS_TTL` is observable.** Every DS RRset response from the
  parent (or its secondaries) carries the TTL in the wire format.
  The engine can extract and remember it on each successful poll.
  Until the engine consumes this observation explicitly, callers
  that need `DS_TTL` for safety bounds can use `ds-publish-delay`
  itself as an upper-bound proxy (since
  `parent_prop + DS_TTL ≤ 2 × ds-publish-delay` in any
  operator-tuned configuration).

The protocol gap is narrower than it might appear: today's DNS
UPDATE doesn't carry a TTL hint from child to parent, so the
parent sets `DS_TTL` unilaterally based on its own policy. That's
fine for the engine because it observes the value rather than
declaring it.

### 4.10 Worked example: the testbed config

Concrete numbers from the `fastroll` policy:

```
KSK.lifetime         = 10m
rollover.ds-publish-delay = 30s
kasp.propagation_delay    = 1m
ttls.dnskey          = 2h
ttls.max_served      = 5m
clamping.margin      = 5m
rollover.num-ds      = 3
```

Derived parameters:

```
parent_prop  = ds-publish-delay  = 30s
child_prop   = kasp.propagation_delay  = 1m
DNSKEY_TTL   = min(ttls.dnskey, ttls.max_served)  = min(2h, 5m)  = 5m
DS_TTL       = (observed from DS responses; assume ≈ parent's policy = 5m for this testbed)
```

For a rollover from KSK_n to KSK_n+1 with active KSK_n stamped at
`active_at = 09:11:41`:

```
T_roll_{n+1}     = active_at + KSK.lifetime  = 09:21:41

T_DNSKEY_pub_{n+1}  = T_roll_{n+1} − child_prop − DNSKEY_TTL
                    = 09:21:41 − 1m − 5m
                    = 09:15:41
```

So KSK_{n+1}'s DNSKEY enters the served zone at `09:15:41` — six
minutes before the rollover. Pipeline keys further out
(`KSK_{n+2}`) follow the same formula with `T_roll_{n+2} =
T_roll_{n+1} + KSK.lifetime`, putting their `T_DNSKEY_pub` 10
minutes later.

For the example status snapshot from the testbed (taken at
`09:19:16`, 8 minutes after `active_at`):

```
KSK_{n+1}  T_DNSKEY_pub  =  09:15:41   (3m35s in the past)
                        →  should already be in `standby` state
                           with DNSKEY served

KSK_{n+2}  T_DNSKEY_pub  =  09:25:41   (6m25s in the future)
                        →  correctly held in `ds-published` state
```

If the testbed shows KSK_{n+1} still in `ds-published` at
`09:19:16`, the engine's transition formula disagrees with this
section — either the engine is using a different formula (bug)
or its check cadence skipped past the transition moment without
acting (cadence bug, separate concern).

### 4.11 Visual timeline

A single key's path through the pipeline, annotated with the
cache-flush windows:

```
KSK_n state:

   created → ds-published ─────────────────── standby ──── active ──── retired ── removed
             ▲                                ▲           ▲                       ▲
             T_DS_pub_n                       T_DNSKEY_   T_roll_n                end of life
             (parent publishes DS)            pub_n
                                              (child publishes DNSKEY)

DS-side cache-flush window (parent → validator):

             T_DS_pub_n        +     parent_prop     +     DS_TTL              ≤  T_roll_n
             |                                                                |
             └────────── all validators have new DS by here ──────────────────┘

DNSKEY-side cache-flush window (child → validator):

                                              T_DNSKEY_pub_n    +    child_prop  +  DNSKEY_TTL  ≤  T_roll_n
                                              |                                                  |
                                              └─── all validators have new DNSKEY by here ──────┘
```

The DS window is much wider than the DNSKEY window in steady
state, because multi-DS pre-publishes DS several rollovers in
advance. The DNSKEY window is exactly `child_prop + DNSKEY_TTL`
by construction (engine times the transition to make it so).

Multi-key view of the multi-DS pipeline (N=3), shown as two
snapshots: just before `T_roll_n` (rollover about to fire) and
just after `T_roll_n + retirement_period` (State A → State B
transition just completed):

```
KSK_{n-2}:    ─ retired ─ removed ──────────────→
KSK_{n-1}:    ─ standby ─── active ─── retired ── removed ────────→
KSK_n:        ─ ds-published ────────── standby ─── active ────────────→
KSK_{n+1}:    ─ ds-published ────────────────────── ds-published ─── standby ──→
KSK_{n+2}:    ─ created ─────────────── ds-published ─────────────────────→
                                       ▲          ▲                ▲
                                  T_roll_n     +retirement      T_DNSKEY_pub_{n+1}
                                                _period         = T_roll_{n+1} − child_prop − DNSKEY_TTL

Snapshot 1 — right BEFORE T_roll_n (KSK_{n-1} still active):

   Served DNSKEY RRset (child):
      ─ KSK_{n-2}   (retired, signing has stopped, DNSKEY still in zone)
      ─ KSK_{n-1}   (active, signing)
      ─ KSK_n       (standby; DNSKEY revealed since T_DNSKEY_pub_n)
      (KSK_{n+1}, KSK_{n+2}: still ds-published — DNSKEYs hidden)

   Parent DS RRset (State B_{n-1}):  N = 3 records
      ─ DS for KSK_{n-1}   (active)
      ─ DS for KSK_n       (future_1)
      ─ DS for KSK_{n+1}   (future_2)

Snapshot 2 — right AFTER T_roll_n + retirement_period
                (KSK_{n-1} just removed; State A → State B transition):

   Served DNSKEY RRset (child):
      ─ KSK_n       (active, signing — became active at T_roll_n)
      ─ KSK_{n+1}   (standby; DNSKEY not yet revealed if T_DNSKEY_pub_{n+1}
                     hasn't elapsed yet — see Snapshot 1's KSK_n case)
      (KSK_{n-1}: removed at T_roll_n + retirement_period; DNSKEY gone)

   Parent DS RRset (State B_n):  N = 3 records
      ─ DS for KSK_n       (active)
      ─ DS for KSK_{n+1}   (future_1)
      ─ DS for KSK_{n+2}   (future_2; just added in the atomic remove+add
                            with the State A → State B transition)
```

Between the two snapshots, several things shift simultaneously
or in close sequence:

- **At T_roll_n:** child-side `AtomicRollover` swaps KSK_{n-1}
  → retired and KSK_n → active. Parent DS RRset unchanged.
- **At T_roll_n + retirement_period:** KSK_{n-1} → removed in
  the child (DNSKEY gone), DNSKEY RRset re-signed by KSK_n, and
  in a single DNS UPDATE to the parent: drop DS_{n-1}, add
  DS_{n+2}. Parent transitions State A_n → State B_n.
- **Later, at T_DNSKEY_pub_{n+1} = T_roll_{n+1} − child_prop −
  DNSKEY_TTL:** KSK_{n+1}'s DNSKEY enters the zone (ds-published
  → standby).

`KSK_{n+2}` remains in `ds-published` (DNSKEY hidden) until its
own T_DNSKEY_pub_{n+2}, which is one rollover lifetime past
T_DNSKEY_pub_{n+1}. This is the post-quantum benefit of
delaying ds-published → standby until E12 forces it: at any
moment, only the active key's DNSKEY plus (at most) one
imminently-promoted standby's DNSKEY is exposed. Future keys
remain DS-only.

### 4.12 Verification rule

This section is the **canonical reference** for the engine's
timing behaviour. Any code change that affects:

- when DS is submitted to the parent
- when ds-published → standby fires
- when standby → active fires
- the relationship between any two of the timestamps `T_DS_pub`,
  `T_DNSKEY_pub`, `T_roll`

must be verified against equations E1–E13. Specifically:

- The two cache-flush invariants: E1 (DS-side) and E3 (DNSKEY-side).
- The retirement-period sizing: E5.
- The DS-side derived constraints: E6, E7, E8, E9, E10, E11.
- The DNSKEY-side engine equation: E12.
- The effective DNSKEY_TTL definition: E13.

If code computes `T_DNSKEY_pub` differently from E12, the code is
wrong. If a refactor would change the semantics, update this
section first (in a design doc), then update the code, then
update the operator guide to match.

If the engine starts using a parameter not in §4.2's table, that
parameter must be added to the table. Implicit parameters are
the source of all the timing bugs we have hit so far.


## 5. Worked examples


### 5.1 The 10-minute testbed

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


### 5.2 Production with weekly cadence

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


### 5.3 Production with monthly cadence

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


## 6. Operational considerations for fast cadences

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


## 7. Required configuration parameters

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


### 6.3 The `clamping` choice

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


## 8. Validation and verification

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


## 9. What the engine handles automatically vs. what needs you

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


## 10. When something goes wrong

The four failure categories the engine recognizes:

- **child-config**: something on your side is wrong (sign
  failure, no DS to publish, parent zone not resolvable).
  Operator must fix; the engine will retry indefinitely with a
  capped backoff if the failure is "no usable scheme advertised
  at parent" (this auto-recovers when the parent comes back).
  Other child-config flavours go to hardfail after
  `max-attempts-before-backoff` consecutive failures.

- **transport**: network-level failure to reach the parent
  (timeout, connection refused). The engine retries.

- **parent-rejected**: the parent acknowledged the request but
  responded with REFUSED, NOTAUTH, FORMERR, or SERVFAIL. The
  daemon's logs include EDE codes when the parent supplies them
  — these are the most operationally-actionable errors.

- **parent-publish-failure**: the parent acknowledged but the
  DS RRset never appeared in the parent zone. The engine
  retries.

For investigations, start by reading the daemon logs and the
output of `auto-rollover status`. The status output identifies
the current phase and the most recent failure reason. The
softfail/hardfail counters tell you how many attempts have
happened. The `last_softfail_*` fields tell you when and why.


## 11. Further reading

- **Design background:** the rollover-overhaul plan at
  `tdns/docs/2026-04-29-rollover-overhaul.md` documents the
  state machine, failure model, and softfail/hardfail
  bookkeeping.
- **NOTIFY-scheme push path:** the design at
  `tdns/docs/2026-04-30-rollover-notify-scheme.md` documents
  the upcoming work for parents that advertise NOTIFY-based
  DSYNC instead of UPDATE-based DSYNC.
- **Multi-provider DNSSEC:** see the tdns-mp guide
  (`tdns-mp/guide/`) for KSK rollover in multi-provider
  deployments. The single-provider guidance here applies; the
  multi-provider extension adds leader election so only one
  provider drives the rollover at a time.
- **DSYNC (RFC 9859):** the parent-side advertisement of
  delegation-sync schemes. Required for automated rollover.
- **RFC 7583:** DNSSEC Key Rollover Timing Considerations. The
  conceptual foundation for the bounds discussed here.
