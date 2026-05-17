# Rollover Timing Equations and Cache-Flush Invariants

This document is the **canonical reference** for the
TDNS automated KSK rollover engine's timing math.
Implementation must match the equations here. If code
disagrees, this document wins or the disagreement is
filed as a design issue.

For the operator-facing how-to, the mental model behind
the parameter choices, worked examples and CLI usage, see
[Automatic DNSSEC Key Rollovers](key-rollover.md). That
document gives the intuition; this one makes it rigorous.


## 1. Key states

A KSK in the rollover pipeline moves through seven states.
Each state has a defined entry condition (the prerequisite
for the transition that creates it) and a defined exit
condition (what allows the engine to advance the key to
the next state).

**`created`.** Fresh keypair has been generated and its DS
pushed to the parent (via DNS UPDATE or CDS publication).
DNSKEY is *not* in the served zone; only the parent has
been informed. The engine is awaiting parent-side
observation of the DS.
*Exit:* parent's DS RRset includes the key's DS record.

The pipeline holds at most one `created` key at a time. The
engine enforces this as a hard cap (`num_ds + 1` total
pipeline depth) so that a stalled parent-publication path
can't drive unbounded key generation: a second `created`
key would not help — both would queue behind the same DS
push.

**`ds-published`.** Parent has been observed to serve the
DS for this key. DNSKEY is still not in the served child
zone — the engine deliberately holds it back to minimize
DNSKEY exposure (see §8). Parent-side propagation
(`parent_prop + DS_TTL`) starts from the moment of
observation.
*Exit:* the engine reaches `T_DNSKEY_pub_n = T_roll_n −
child_prop − DNSKEY_TTL` (E12); time to put DNSKEY in the
served zone.

**`published`.** DNSKEY is now in the served child zone
but caches may still hold pre-publish responses, so the
key is *not* yet usable for signing. Both child-side
(`T_published + child_prop + DNSKEY_TTL`) and parent-side
(`T_DS_observed + parent_prop + DS_TTL`) cache-flush gates
are running.
*Exit:* both gates have elapsed — caches everywhere now
serve RRsets that include this key.

**`standby`.** Cache-flush is complete; the key is
genuinely ready and could be made active *immediately*.
The state exists so the engine can hold the key for a
configurable pause before AtomicRollover, giving the
operator a window to abort the natural-cadence rollover.
**Any pause in `standby` is a policy choice
(`rollover.standby_time`, default 1m), not a safety
requirement** — published→standby→active with
`standby_time = 0` is a perfectly safe rollover.
`auto-rollover asap` bypasses the pause entirely; the
cache-flush gates that gated published→standby remain in
force and cannot be bypassed.
*Exit:* `standby_at + standby_time` reached, OR operator
triggers asap.

**`active`.** The key is the zone's signing KSK.
AtomicRollover fired: the previously-active KSK
transitioned to `retired` in the same operation that
promoted this one. From now until its own retirement,
this key signs the DNSKEY RRset and (transitively) the
entire chain of trust below the zone.
*Exit:* `T_roll_{n+1}` reached — the next-up standby key
gets promoted, this key transitions to `retired`.

**`retired`.** The key is no longer signing new things,
but its DNSKEY remains in the zone and its DS remains at
the parent. Cached RRSIGs and DS responses still in flight
may reference this key; we wait the `retirement_period`
(= `effective_margin`) so they can drain.
*Exit:* `retired_at + effective_margin` reached. The
DNSKEY is removed from the served zone, and the same
atomic parent UPDATE that drops this key's DS adds the
next future slot's DS — keeping the parent's DS RRset at
exactly N (§4).

**`removed`.** Terminal. DNSKEY is out of the zone; DS is
out of the parent. The key's lifecycle is complete. Rows
in this state are kept for audit/history and excluded from
`num_ds`-against-parent counts.


## 2. Notation

Throughout: `T_X` denotes a **timestamp** (a moment in
wall time); plain `X` denotes a **duration** (a difference
between two timestamps). Equations mix the two; durations
always add to or subtract from timestamps to yield
timestamps.

`KSK_n` denotes the n-th KSK in the rollover pipeline.
`T_roll_n` is the moment KSK_n becomes active and starts
signing the zone's RRSIG-over-DNSKEY (and therefore the
entire chain of trust).


## 3. Parameters

Every duration the timing math depends on, with the config
knob or observation that supplies its value.

| Symbol | Type | Source | What it represents |
|--------|------|--------|--------------------|
| `parent_prop` | duration | operator estimate via `rollover.ds-publish-delay` | Parent-side primary→secondary AXFR/IXFR + parent registry-pipeline latency. Time between "child sent UPDATE / NOTIFY accepted by parent" and "parent's secondaries serve the new DS RRset." |
| `DS_TTL` | duration | **observable** in DS responses (every DS poll carries the TTL field) | TTL of the DS RRset at the parent. Bounds how long resolvers cache the old DS after parent publishes a new one. |
| `child_prop` | duration | `kasp.propagation_delay` | Child-side primary→secondary propagation. Time between "child primary publishes new DNSKEY RRset" and "all child secondaries serve it." |
| `DNSKEY_TTL` | duration | derived: `min(ttls.dnskey, ttls.max_served)` clamped further by K-step clamping near rollover | TTL of the DNSKEY RRset as actually served to validators. Bounds how long resolvers cache the old DNSKEY RRset after the child publishes a new one. |
| `KSK_lifetime` | duration | `ksk.lifetime` config knob | Rollover cadence — the policy-driven interval between successive KSK activations. Steady-state: `T_roll_n − T_roll_{n−1} = KSK_lifetime`. |
| `retirement_period` | duration | `effective_margin = max(clamping.margin, max_observed_TTL)` in current engine | The hold time between a KSK transitioning to retired (at T_roll_n) and being removed (at T_roll_n + retirement_period). During the retirement period the key's DNSKEY is still in the zone but the engine no longer signs new things with it. Sized so that all cached RRSIGs by the retiring key have flushed by the time it's removed (see §5.1). |
| `N` | dimensionless | `rollover.num-ds` config knob | Number of DS records the engine maintains at the parent simultaneously (active + N−1 future). Internal pipeline depth is `N + 1`: the extra key sits in `created` with its DS push in flight to the parent and joins the N-at-parent set once the parent observes it. |
| `T_roll_n` | timestamp | `T_roll_n = T_roll_{n−1} + KSK_lifetime` (steady-state cadence; bootstrap defines `T_roll_1` independently) | Moment KSK_n becomes the active signer. |
| `T_DS_pub_n` | timestamp | observed from parent DS query (= when DS for KSK_n first appears at parent) | Moment parent's primary publishes DS for KSK_n. |
| `T_DNSKEY_pub_n` | timestamp | engine-controlled: ds-published → published transition for KSK_n | Moment child's primary publishes DNSKEY_n in the served DNSKEY RRset. |
| `standby_time` | duration | `rollover.standby_time` config knob (default 1m) | Pause between when KSK_n reaches the genuine `standby` state (propagation complete, ready) and when AtomicRollover fires standby→active. Operator observability window; `auto-rollover asap` bypasses it. |


## 4. The two cache-flush invariants

For KSK_n to take over signing safely at `T_roll_n`, two
independent cache-flush conditions must hold.

**Invariant DS** — *if* a validator has the parent's DS
RRset in its cache at `T_roll_n`, that cached RRset must
contain DS_n. Validators with no cached DS are fine: they
fetch fresh on the next need and get DS_n. The dangerous
case is a validator with a stale cache entry that excludes
DS_n; for that to be impossible at `T_roll_n`, every cache
entry created before DS_n landed at the parent's
secondaries must have expired by `T_roll_n`. The worst
case is a validator that fetched DS just before
secondaries had DS_n; its cache lasts `DS_TTL` more. So:

```
T_DS_pub_n + parent_prop + DS_TTL  ≤  T_roll_n               (E1)
```

Equivalently, the latest DS_n can be published at parent
and still satisfy the invariant:

```
T_DS_pub_n  ≤  T_roll_n − parent_prop − DS_TTL               (E2)
```

**Invariant DNSKEY** — *if* a validator has the child's
DNSKEY RRset in its cache at `T_roll_n`, that cached RRset
must contain DNSKEY_n. Same reasoning on the child side:

```
T_DNSKEY_pub_n + child_prop + DNSKEY_TTL  ≤  T_roll_n        (E3)
```

Equivalently:

```
T_DNSKEY_pub_n  ≤  T_roll_n − child_prop − DNSKEY_TTL        (E4)
```

The two invariants are independent because they govern
different caches: DS lives at the parent and is cached on
the way down the delegation chain; DNSKEY lives at the
child and is cached when validators look up the chain.
Both must be in place at `T_roll_n`.


## 5. DS-side: the parent-DS-RRset contract

The multi-DS scheme is best stated as a contract on the
parent's DS RRset rather than a derived property of the
engine's internal state.

**Contract.** The parent's DS RRset *always* contains
exactly `N` records (`N` = `rollover.num-ds`). Never
fewer, never more.

`N` counts DS records *at the parent*, not keys in the
engine's internal pipeline. In steady state the engine
holds one additional KSK in `created` whose DS push is in
flight to the parent — it joins the N-at-parent set the
moment the parent's primary publishes its DS, at which
point the next pipeline-fill tick generates the *next*
`created` key. Internal pipeline depth is therefore
`N + 1`, but the contract on the parent's RRset remains
exactly `N`.

The composition cycles between two states:

**State A — "retiring":** during the retirement period
after a rollover, the parent holds:
```
{ DS_{n−1},  DS_n,  DS_{n+1},  ...,  DS_{n+N−2} }
   ↑           ↑         ↑                     ↑
   retiring   active    future_1 …          future_{N−2}
```

**State B — "post-retirement":** after the just-rolled-out
key has been removed locally (its retirement period
elapsed), the parent holds:
```
{ DS_n,   DS_{n+1},   DS_{n+2},  ...,  DS_{n+N−1} }
   ↑         ↑                                  ↑
   active   future_1                       future_{N−1}
```

Total in both states: N records. The transition from
State A to State B is always **simultaneous** — the same
DNS UPDATE drops DS_{n−1} and adds DS_{n+N−1}, which
keeps the parent's RRset at exactly N records throughout
(no transient state with N−1 or N+1).

**State A** holds for the retirement period (typically a
few minutes to a few hours, depending on `clamping.margin`
/ `max_observed_TTL`). **State B** holds for the rest of
the rollover lifetime
(`KSK_lifetime − retirement_period`, the overwhelming
majority of normal operation).

For N=3, the smallest interesting case:
- State A: `{DS_{n−1}, DS_n, DS_{n+1}}` — one retiring
  key's DS, one active, one future.
- State B: `{DS_n, DS_{n+1}, DS_{n+2}}` — no retiring
  key's DS, active plus two future.

The DNSKEY RRset in the *child* zone does not have a
strict "always N" contract — when the engine holds a
future KSK in ds-published state (DNSKEY not yet revealed;
see §8), the DNSKEY RRset shrinks even though the DS
RRset stays at N. The DS-side contract holds even while
the DNSKEY-side composition varies, because DS records
are post-quantum-opaque and the cost of an extra DS
record at the parent is negligible.


## 5.1 Maintaining the contract: events and atomicity

Four engine actions are involved in keeping the parent's
DS RRset compliant with the contract:

**(a) Rollover fires at `T_roll_n`.** KSK_{n−1} →
retired, KSK_n → active in the *child* zone via
`AtomicRollover`. **Parent DS RRset is unchanged.** The
composition simply gets relabeled — what was the "active"
slot (DS_{n−1}) is now the "retiring" slot, and what was
"future_1" (DS_n) is now "active." The parent's primary,
secondaries, and validator caches see no change.

**(b) Retirement period elapses; KSK_{n−1} → removed.**
This is the critical event. The child-side action happens
first: remove DNSKEY_{n−1} from the served DNSKEY RRset
and re-sign the RRset with the new active KSK_n.

*After* DNSKEY_{n−1} has been removed from the child
DNSKEY RRset, two parent-side operations must happen in
a single atomic DNS UPDATE:

  - Remove DS_{n−1} from the parent's RRset.
  - Add DS_{n+N−1} (the next pre-publication slot).

Both go in the same wire-level transaction. After this,
the parent transitions from State A to State B. The
contract is preserved throughout: at every instant, the
parent serves exactly N DS records.

**Comments:**

- **No additional wait between local removal and parent
  update is needed.** The retirement period was sized
  precisely to ensure that by `T_remove_{n−1}` no cached
  RRSIG anywhere references KSK_{n−1} (see §5.2 for the
  sizing constraint). Validators that still have a stale
  DNSKEY RRset cached (with KSK_{n−1} included in the key
  set) are harmless: no RRSIG points at KSK_{n−1} as its
  signer, so no validation chain leans on DS_{n−1}.

- **Trigger.** The local retired → removed state
  transition of KSK_{n−1}, owned by the child-side
  rollover engine. The retirement period that gates this
  transition is the
  `effective_margin = max(clamping.margin, max_observed_TTL)`
  of the child zone — sized so that the §5.2 invariant
  holds.

- **Why removing DS_{n−1} promptly matters.** DS_{n−1}
  authenticates a key the operator has decided to roll
  away from. That key may be weakened, suspect, or
  actually compromised — it could be exactly *why* the
  operator is rolling. Leaving DS_{n−1} at the parent
  longer than the retirement period requires extends the
  window during which an attacker holding the old key
  material can still produce validatable responses. The
  retired → removed transition is the right trigger;
  nothing else is.


### 5.2 What `retirement_period` must guarantee

The "no extra wait needed" argument above relies on a
precise sizing constraint for the `retirement_period`:

```
retirement_period  ≥  min(DNSKEY_TTL, KSK.SigValidity)       (E5)
```

where `DNSKEY_TTL` is the **served** DNSKEY TTL per §9 /
E13 (`min(ttls.dnskey, ttls.max_served)`), not the
operator-configured `ttls.dnskey` alone. This matters
operationally: it lets operators run long RRSIG validities
(7–10 days for weekend safety) alongside short served TTLs
(1–2h, clamped lower near rollover) for rapid rollover
cadence. Sized against the served TTL, E5 reflects what
validators can actually cache.

Why this bound:

A validator that cached the DNSKEY response just before
`T_roll_n` holds a response whose effective lifetime in
cache is
`min(DNSKEY_TTL, RRSIG_remaining_validity_at_cache_time)`.
Worst case: the RRSIG was signed just before being
fetched, so its remaining validity equals the full
`KSK.SigValidity`. Cache lifetime in that worst case =
`min(DNSKEY_TTL, KSK.SigValidity)`.

For all such cached responses (and therefore all cached
RRSIGs by KSK_{n−1}) to have flushed from validator caches
by `T_remove_{n−1}`, the retirement period must be at
least this duration.

For the testbed: served `DNSKEY_TTL = min(2h, 5m) = 5m`,
`KSK.SigValidity = 20m`, so
`min(DNSKEY_TTL, KSK.SigValidity) = 5m`. With
`effective_margin = max(clamping.margin, max_observed_TTL)
= max(5m, 5m) = 5m`, the constraint is met exactly.

E5 is checked at policy-load against `clamping.margin` —
the operator-controllable lower bound on
`effective_margin`. The runtime `max_observed_TTL` can
only push it higher, so passing the load-time check is
sufficient.

**(c) Pipeline maintenance.** The engine continuously
generates new KSKs and submits their DS to the parent so
that future slots are filled when (b) needs to add
DS_{n+N−1}. This generation is decoupled from the rollover
schedule — keys are generated whenever the local
pipeline-fill logic notices a slot needs filling.

**(d) Bootstrap and recovery.** First time the engine
sees a zone, or after a hardfail-and-recovery, the
contract may not hold (parent has fewer than N records).
The engine fills the pipeline as fast as the parent's
`parent_prop + DS_TTL` allows. During this fill, the
contract's "always exactly N" claim is relaxed; once the
pipeline is full it holds again.


## 6. DS-side: when does DS_n land at the parent?

To validate Invariant DS (E1), we need `T_DS_pub_n` — the
moment DS_n first appeared in the parent's RRset.

**The simple framing:** `DS_n is published at the same
atomic operation that removes DS_{n−N}` (the State A →
State B transition described in §5.1(b)). That operation
happens at:

```
T_DS_pub_n  =  T_roll_{n−N+1} + retirement_period            (E6)
```

Where `T_roll_{n−N+1}` is the moment KSK_{n−N+1} became
active. (If you prefer to think in "rollovers ago": the
State A → State B transition that publishes DS_n is the
one immediately following the (N−1)-rollovers-ago
activation.)

Substituting
`T_roll_{n−N+1} = T_roll_n − (N − 1) × KSK_lifetime`:

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
(N − 1) × KSK_lifetime − retirement_period  ≥  parent_prop + DS_TTL + standby_time   (E9)
```

Equivalently, the operational constraint on the rollover
cadence:

```
(N − 1) × KSK_lifetime  ≥  retirement_period + parent_prop + DS_TTL + standby_time   (E10)
```

**Interpretation.** The multi-DS pipeline depth `N` gives
the engine `(N − 1)` rollover cycles of buffer for
DS-side propagation. Subtract the retirement period
(during which the new "future" slot doesn't yet exist at
the parent), and what remains must accommodate
`parent_prop + DS_TTL` plus any operator-configured
`standby_time` pause between cache-flush completion and
AtomicRollover (see §8). Choose `N`, `KSK_lifetime`,
`retirement_period`, `standby_time`, and the parent's
`DS_TTL` such that E10 holds; the rest is automatic.

**For the testbed config.** N=3, KSK_lifetime=10m,
retirement_period=5m (`clamping.margin`),
parent_prop≈30s, DS_TTL≈5m, standby_time=1m:

```
(N − 1) × KSK_lifetime  =  2 × 10m  =  20m
retirement_period + parent_prop + DS_TTL + standby_time  =  5m + 30s + 5m + 1m  =  11m30s
20m ≥ 11m30s     ✓     (8m30s of headroom)
```

The testbed is comfortably within its DS-side budget.
E10 becomes interesting at smaller `N` (e.g. would-be N=2
multi-DS would have `(N − 1) × KSK_lifetime = 10m`
against the 11m30s requirement — fail), or with much
faster cadences (`KSK_lifetime = 2m` against the same
requirement — fail unless `N` is raised).

**Note on DS_TTL.** The engine resolves `DS_TTL` by
observing the parent's DS RRset (or via a `ttls.ds`
policy override). When multiple DS records appear in one
RRset, the engine uses the **minimum** TTL across them,
not the maximum. RFC 1035 §3.2.1 requires all records of
an RRset to share the same TTL, so for any compliant
parent `min == max` and the choice is academic. For a
non-compliant parent emitting mixed TTLs, RFC 2181 §5.2
requires resolvers to treat the RRset as a single unit —
the only sane cache behavior is to evict the whole RRset
on the smallest TTL, since a cache cannot keep individual
records past their stated expiration nor split the RRset.
So validator caches in practice flush the DS RRset at
`min(TTLs)`, which makes `min` the actual upper bound on
cache retention. Using `max` would over-pessimize
E10/E11 lead times based on a TTL the cache will never
honor.

**Production rule of thumb.** For comfortable margins,
pick:

```
N  ≥  ⌈(retirement_period + parent_prop + DS_TTL) / KSK_lifetime⌉ + 1   (E11)
```

For typical production values (retirement_period=8h,
parent_prop=5m, DS_TTL=1h, KSK_lifetime=7d): RHS of E11 =
⌈9h5m / 168h⌉ + 1 = 1 + 1 = 2. So even N=2 works
comfortably for slow cadences. The default N=3 gives
substantial margin.


## 7. DNSKEY-side: engine equations and the state split

The child controls `T_DNSKEY_pub_n` directly: it's the
moment the rollover engine advances KSK_n into the state
where its DNSKEY enters the served DNSKEY RRset.

To minimize DNSKEY exposure (the post-quantum motivation
for keeping unrevealed keys at DS-only), the engine
advances **as late as the invariant permits**:

```
T_DNSKEY_pub_n  =  T_roll_n − child_prop − DNSKEY_TTL        (E12)
```

The engine implements three distinct moments around
`T_roll_n`, each with its own state transition:

1. **ds-published → published** at `T_DNSKEY_pub_n` (E12
   above). DNSKEY enters the served zone but caches still
   hold pre-publish responses; KSK_n is *not* yet usable
   for signing.

2. **published → standby** at
   `max(T_DNSKEY_pub_n + child_prop + DNSKEY_TTL,
        T_DS_pub_n + parent_prop + DS_TTL)`.
   Both child-side and parent-side propagation have
   completed; the key is genuinely ready. The engine
   stamps `standby_at` on the key at this moment.

3. **standby → active** at `standby_at + standby_time`,
   where `standby_time` is an operator-configured pause
   (`rollover.standby_time`, default 1m). The pause gives
   the operator a window to abort the natural-cadence
   rollover post-propagation. `auto-rollover asap`
   bypasses this pause; `asap` is exactly an operator
   override of the natural cadence, and the pause is
   part of that natural cadence.

Why split "DNSKEY in zone" into two states (`published`
and `standby`)? Because the operational meaning differs:
a `published` key is in flight (caches may still reject
signatures by it); a `standby` key has flushed all stale
state and can fire on operator command. Collapsing them
obscures whether the engine has done its cache-flush
waiting or not.

E12 is the canonical formula. Any code that implements
ds-published → published must use it.


## 8. Effective DNSKEY_TTL: the clamping caveat

The DNSKEY_TTL parameter is the TTL **as served to
validators at the moment they cache the response**, not
the TTL the operator configured.

Three knobs collapse into the served TTL:

1. **`ttls.dnskey`** — operator's intended DNSKEY TTL
   (e.g. 2h).
2. **`ttls.max_served`** — zone-wide TTL ceiling. The
   serving layer clamps any RRset's TTL down to this
   on-the-wire. So the served DNSKEY TTL is
   `min(ttls.dnskey, ttls.max_served)`.
3. **K-step clamping near rollover** — when clamping is
   enabled, TTLs progressively reduce to `clamping.margin`
   as `T_roll_n` approaches. A validator that queries
   during the clamping window caches an even shorter TTL.

For the cache-flush invariant the engine must use the
**largest TTL a validator might have cached just before
`T_DNSKEY_pub_n`**. That's
`min(ttls.dnskey, ttls.max_served)` when clamping has not
yet kicked in for the upcoming rollover. K-step clamping
shortens this further but is conservative (not relied on
by the invariant).

So the operator-facing rule:

```
DNSKEY_TTL  =  min(ttls.dnskey, ttls.max_served)             (E13)
```

If `ttls.max_served` is set (recommended for any zone
with auto-rollover), it's the value that matters.


## 9. Parent-side parameters: observable, not unknown

Both `parent_prop` and `DS_TTL` have well-defined sources:

- **`parent_prop` ≈ `rollover.ds-publish-delay`.** The
  operator estimates parent-side latency as the
  `ds-publish-delay` config knob and tunes it per parent
  based on observed behaviour. `ds-publish-delay = 30s`
  for direct-publish parents, `ds-publish-delay = 1h` for
  batched registries, and so on. The engine's existing
  usage of `ds-publish-delay` as the observation budget is
  consistent with this interpretation.

- **`DS_TTL` is observable.** Every DS RRset response
  from the parent (or its secondaries) carries the TTL in
  the wire format. The engine can extract and remember it
  on each successful poll. Until the engine consumes this
  observation explicitly, callers that need `DS_TTL` for
  safety bounds can use `ds-publish-delay` itself as an
  upper-bound proxy (since
  `parent_prop + DS_TTL ≤ 2 × ds-publish-delay` in any
  operator-tuned configuration).

The protocol gap is narrower than it might appear: today's
DNS UPDATE doesn't carry a TTL hint from child to parent,
so the parent sets `DS_TTL` unilaterally based on its own
policy. That's fine for the engine because it observes
the value rather than declaring it.


## 10. Worked example: the testbed config

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

For a rollover from KSK_n to KSK_n+1 with active KSK_n
stamped at `active_at = 09:11:41`:

```
T_roll_{n+1}     = active_at + KSK.lifetime  = 09:21:41

T_DNSKEY_pub_{n+1}  = T_roll_{n+1} − child_prop − DNSKEY_TTL
                    = 09:21:41 − 1m − 5m
                    = 09:15:41
```

So KSK_{n+1}'s DNSKEY enters the served zone at
`09:15:41` — six minutes before the rollover. Pipeline
keys further out (`KSK_{n+2}`) follow the same formula
with `T_roll_{n+2} = T_roll_{n+1} + KSK.lifetime`, putting
their `T_DNSKEY_pub` 10 minutes later.

For the example status snapshot from the testbed (taken
at `09:19:16`, 8 minutes after `active_at`):

```
KSK_{n+1}  T_DNSKEY_pub  =  09:15:41   (3m35s in the past)
                        →  should already be in `standby` state
                           with DNSKEY served

KSK_{n+2}  T_DNSKEY_pub  =  09:25:41   (6m25s in the future)
                        →  correctly held in `ds-published` state
```

If the testbed shows KSK_{n+1} still in `ds-published` at
`09:19:16`, the engine's transition formula disagrees with
this section — either the engine is using a different
formula (bug) or its check cadence skipped past the
transition moment without acting (cadence bug, separate
concern).


## 11. Visual timeline

A single key's path through the pipeline, annotated with
the cache-flush windows:

```
KSK_n state:

   created → ds-published ─── published ── standby ── active ──── retired ── removed
             ▲                 ▲            ▲          ▲                       ▲
             T_DS_pub_n        T_DNSKEY_    propagation T_roll_n                end of life
             (parent           pub_n        complete    (= standby_at +
              publishes DS)    (child       (engine     standby_time;
                               publishes    stamps      asap bypasses
                               DNSKEY)      standby_at) the pause)

DS-side cache-flush window (parent → validator):

             T_DS_pub_n        +     parent_prop     +     DS_TTL              ≤  T_roll_n
             |                                                                |
             └────────── all validators have new DS by here ──────────────────┘

DNSKEY-side cache-flush window (child → validator):

                                              T_DNSKEY_pub_n    +    child_prop  +  DNSKEY_TTL  ≤  T_roll_n
                                              |                                                  |
                                              └─── all validators have new DNSKEY by here ──────┘
```

The DS window is much wider than the DNSKEY window in
steady state, because multi-DS pre-publishes DS several
rollovers in advance. The DNSKEY window is exactly
`child_prop + DNSKEY_TTL` by construction (engine times
the transition to make it so).

Multi-key view of the multi-DS pipeline (N=3), shown as
two snapshots: just before `T_roll_n` (rollover about to
fire) and just after `T_roll_n + retirement_period`
(State A → State B transition just completed):

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

Between the two snapshots, several things shift
simultaneously or in close sequence:

- **At T_roll_n:** child-side `AtomicRollover` swaps
  KSK_{n-1} → retired and KSK_n → active. Parent DS RRset
  unchanged.
- **At T_roll_n + retirement_period:** KSK_{n-1} →
  removed in the child (DNSKEY gone), DNSKEY RRset
  re-signed by KSK_n, and in a single DNS UPDATE to the
  parent: drop DS_{n-1}, add DS_{n+2}. Parent transitions
  State A_n → State B_n.
- **Later, at
  T_DNSKEY_pub_{n+1} = T_roll_{n+1} − child_prop −
  DNSKEY_TTL:** KSK_{n+1}'s DNSKEY enters the zone
  (ds-published → standby).

`KSK_{n+2}` remains in `ds-published` (DNSKEY hidden)
until its own T_DNSKEY_pub_{n+2}, which is one rollover
lifetime past T_DNSKEY_pub_{n+1}. This is the
post-quantum benefit of delaying ds-published → standby
until E12 forces it: at any moment, only the active key's
DNSKEY plus (at most) one imminently-promoted standby's
DNSKEY is exposed. Future keys remain DS-only.


## 12. Verification rule

This document is the **canonical reference** for the
engine's timing behaviour. Any code change that affects:

- when DS is submitted to the parent
- when ds-published → published fires (i.e., when DNSKEY
  enters the served zone — E12)
- when published → standby fires (when both child-side and
  parent-side propagation have completed)
- when standby → active fires (= standby_at +
  standby_time, with asap bypassing the pause)
- the relationship between any two of the timestamps
  `T_DS_pub`, `T_DNSKEY_pub`, `T_roll`

must be verified against equations E1–E13. Specifically:

- The two cache-flush invariants: E1 (DS-side) and E3
  (DNSKEY-side).
- The retirement-period sizing: E5.
- The DS-side derived constraints: E6, E7, E8, E9, E10,
  E11.
- The DNSKEY-side engine equation: E12.
- The effective DNSKEY_TTL definition: E13.

If code computes `T_DNSKEY_pub` differently from E12, the
code is wrong. If a refactor would change the semantics,
update this document first (in a design doc), then update
the code, then update the operator guide to match.

If the engine starts using a parameter not in §3's table,
that parameter must be added to the table. Implicit
parameters are the source of all the timing bugs we have
hit so far.
