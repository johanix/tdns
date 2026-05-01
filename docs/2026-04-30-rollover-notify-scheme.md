# Rollover engine: NOTIFY-scheme push path

Author: Johan / Claude
Date: 2026-04-30
Status: planning — no code yet
Branch: TBD (off `rollover-overhaul` once that lands)

Follow-up to the rollover overhaul (`2026-04-29-rollover-overhaul.md`).
That work fixed the softfail state machine, parent-side EDE, and the
CLI-via-API rewrite. It did not touch one cross-cutting limitation:
the rollover engine pushes DS via DNS UPDATE only. Parents that
advertise the NOTIFY scheme in DSYNC are unreachable for automated
KSK rollover.

> **Phase numbering note.** Phase numbers in this document (1–9) are
> local to this work. References to "Phase 11" or "Phase 12" are to
> the rollover-overhaul doc and concern UPDATE-side EDE and the
> deferred test harness respectively. Phase 7 here is the NOTIFY-side
> mirror of rollover-overhaul Phase 11; Phase 8 here is the test
> harness rollover-overhaul Phase 12 deferred.

## Background

`PushWholeDSRRset` in [ksk_rollover_ds_push.go:148](tdns/v2/ksk_rollover_ds_push.go:148)
hardcodes `core.SchemeUpdate` in both of its `LookupDSYNCTarget`
calls (line 198 / 200). That's the entire reason the rollover engine
is UPDATE-only on the **child** side. Everything else in the
child-side pipeline — target DS computation, observe-phase polling,
softfail handling, CDS lifecycle — is either scheme-agnostic or
already implemented elsewhere in the codebase.

The **parent** side is mostly already there. NOTIFY(CDS) is accepted
([notifyresponder.go:132](tdns/v2/notifyresponder.go:132)), CDS is
fetched from child NSs and DNSSEC-validated
([scanner.go:1078 `ProcessCDSNotify`](tdns/v2/scanner.go:1078)),
DS adds/removes are computed via CDS→DS conversion and routed back
through the standard delegation backend as a CHILD-UPDATE. DSYNC
publishing already supports both `NOTIFY` and `UPDATE` schemes
([ops_dsync.go:69](tdns/v2/ops_dsync.go:69)).

Two parent-side gaps remain:

1. **No EDE on synchronous NOTIFY rejections.** Phase 11 of the
   rollover overhaul attached EDE codes to UPDATE rejections in
   `updateresponder.go`. The equivalent work on `notifyresponder.go`
   has not been done. Synchronous rejections (parent zone not
   authoritative, qname not a child delegation, zone in error
   state) return REFUSED/NOTAUTH/SERVFAIL with no EDE. The child
   then has only the rcode to go on.
2. **Asymmetric error model on async failures (fundamental, not a
   bug).** NOTIFY ACK is sent at
   [notifyresponder.go:233](tdns/v2/notifyresponder.go:233) *before*
   the async scan runs. ProcessCDSNotify failures (CDS not in sync
   across child NSs, RFC 9615 signaling verification fails, RFC 8078
   bootstrap policy refuses, etc.) result in NOERROR at the wire +
   DS never appears at the parent → `parent-publish-failure` from
   the child's POV, regardless of the actual reason. This is
   structural — NOTIFY by RFC is fire-and-forget at the wire — and
   not fixable inside the NOTIFY ACK path. Mitigations are
   out-of-band (parent-side WARN logs, possibly RFC 9567 error
   reporting if either operator has it wired up).

The general delegation-sync path (`delegation_sync.go:343`,
`SyncZoneDelegation` and friends) already supports both schemes via
`BestSyncScheme` ([childsync_utils.go:386](tdns/v2/childsync_utils.go:386))
and routes NOTIFY(CDS) through `NotifierEngine`. The pieces exist.
What's missing is wiring them into the rollover engine, with the
extra bookkeeping the rollover state machine needs (failure
categorization, attempt tracking, CDS-cleanup ownership).

The two relevant scheme paths in the codebase today:

- `SyncZoneDelegationViaUpdate` — diff-based DNS UPDATE for arbitrary
  delegation changes; used by API-driven sync, not by the rollover
  engine.
- `SyncZoneDelegationViaNotify` — publishes CSYNC and/or CDS at the
  child apex, signs them, queues NOTIFY(CSYNC) or NOTIFY(CDS) onto
  `notifyq`. Synthesizes CDS from arbitrary in-zone DNSKEYs.

`SynthesizeCdsRRs` in [ops_cds.go:22](tdns/v2/ops_cds.go:22) reads the
zone's apex DNSKEY RRset and converts every SEP key to a CDS. The
rollover engine, however, has its own opinion about which keys
belong in the target DS set: `ComputeTargetDSSetForZone` reads the
keystore (not the zone) and includes keys in states `created`,
`ds-published`, `standby`, `published`, `active`, `retired`. These
two sets *should* be the same in steady state, but during a rollover
they will diverge — that's the whole point of the rollover state
machine.

A naive port of `SyncZoneDelegationViaNotify` into the rollover
engine would publish a CDS RRset that does not correspond to the DS
RRset the rollover engine expects the parent to publish. The result
would be: parent processes CDS, publishes the wrong DS, child polls
for the right DS, observes the wrong one, declares
`parent-publish-failure`. Wrong, in a way that would only surface at
runtime against a CDS-consuming parent. Avoidable by deriving CDS
from the rollover engine's target KSK set, not from the zone's
current DNSKEY RRset.

## Goals

1. The rollover engine pushes DS via NOTIFY(CDS) when the parent
   advertises a NOTIFY DSYNC RR for CDS (or ANY).
2. UPDATE-only testbeds (parents advertising only UPDATE) behave
   identically to today — single-path UPDATE, no NOTIFY traffic.
3. **Default `auto` policy sends UPDATE and NOTIFY in parallel when
   the parent advertises both schemes**, eliminating the "advertised
   but broken" failure mode where the child has no recourse if the
   preferred scheme silently doesn't work end-to-end at the parent.
4. Operator can pin behavior via a per-policy knob:
   `auto` (default, parallel-on-both), `prefer-update`,
   `prefer-notify`, `force-update`, `force-notify`. `prefer-*`
   gives explicit single-scheme behavior on a both-advertising parent.
5. The state machine handles **all combinations** of parent-side
   delegation-sync mechanism advertisement: none, UPDATE-only,
   NOTIFY-only, both. Including transitions in any direction at any
   rollover phase, transient or permanent. **When the parent has no
   usable scheme advertised, the child halts the rollover but
   recovers automatically when the parent restores delegation-sync
   support — no operator intervention required.** This is enforced
   by the `child-config:waiting-for-parent` subcategory which never
   hardfails (1h backoff cap, indefinite retry).
6. CDS records the rollover engine publishes are removed from the
   child zone via three cleanup triggers (confirmed observation,
   pre-dispatch when no longer using NOTIFY, and terminal hardfail),
   without disturbing CDS records that some other caller (general
   delegation-sync) owns.
7. Status output identifies which scheme(s) each attempt used
   (comma-joined for parallel).
8. Test harness covers all three push modes (UPDATE-only,
   NOTIFY-only, parallel) and the four user-supplied parent-flip
   scenarios — the right time to build the tick-handler harness is
   when adding scheme variability makes the abstraction earn its
   keep.
9. **Rollover push paths are extractable.** The push dispatcher,
   per-scheme push functions, scheme selection, CDS cleanup, and
   the per-zone tick logic are callable from tdns-mp/v2's
   `KeyStateWorker` ([tdns-mp/v2/key_state_worker.go:27](tdns-mp/v2/key_state_worker.go:27))
   in addition to tdns/v2's. tdns-mp does not currently invoke
   rollover push at all — its KeyStateWorker only does basic key
   state transitions. Making the push code reachable from
   tdns-mp's orchestrator is part of this work, not a follow-up.
   Concretely: hidden globals (`Zones`, `lgSigner`,
   `AcquireRolloverLock`, `conf.Internal.ImrEngine`,
   `conf.Internal.DnssecPolicies`) become injected dependencies on
   the entry-point functions. Each KeyStateWorker wires its own
   versions; the push engine itself becomes orchestrator-agnostic.
10. Parent-side EDE attachment for synchronous NOTIFY rejections,
   mirroring the UPDATE-side Phase 11 work from rollover-overhaul.
   Includes a new gate that refuses NOTIFY(CDS)/NOTIFY(CSYNC) when
   the parent's own DSYNC RRset does not advertise NOTIFY for that
   RRtype, with EDE detail `"parent does not advertise NOTIFY for
   type X; ignoring"` — the most operator-actionable diagnostic in
   the set, since it catches misconfigured children on the first
   push instead of after `attempt-timeout` elapses. Async
   rejections from `ProcessCDSNotify` cannot be surfaced via
   NOTIFY ACK and are explicitly out of scope for this work.

## Out of scope

- The general `SyncZoneDelegation` path. Already supports both
  schemes; out of scope here.
- Multi-DS-algorithm. Engine still emits SHA-256 only.
- ZSK rollover.
- NOTIFY support for any RR type other than CDS (CSYNC for delegation
  data is delegation-sync's territory).
- DSYNC discovery refactoring. Reuse `Imr.DsyncDiscovery`.
- Parent-side `ProcessCDSNotify` improvements (CDS→DS conversion,
  DNSSEC validation, CHILD-UPDATE routing). Already implemented
  and orthogonal to this work.
- Parent-side DSYNC NOTIFY advertising. Already implemented in
  `ops_dsync.go`.
- Surfacing async `ProcessCDSNotify` failures back to the child
  through the NOTIFY ACK. Structurally impossible — NOTIFY ACK is
  sent before the async scan runs. Out-of-band reporting (RFC 9567)
  is a separate project.
- Encrypted/authenticated NOTIFY. NOTIFY(CDS) is unauthenticated at
  the wire today; same as the UPDATE path's reliance on SIG(0) is
  for UPDATE only. CDS on the wire is published into a signed zone
  by the child, so origin authentication is via DNSSEC on the CDS
  RRset itself — same as `SyncZoneDelegationViaNotify` today.

## Constraints

- **Testbed continuity (same carve-out as rollover-overhaul).**
  UPDATE-only parents must continue to work without operator action.
  When the parent advertises only UPDATE, `auto` returns
  `[UPDATE]` — single-path UPDATE behavior, identical to today.
  No NOTIFY traffic on UPDATE-only testbeds.
- **No backwards compat in code.** The codebase rule applies: no
  dual-format parsing, no legacy fallbacks. The new policy field
  defaults to `auto`; old configs without the field get the safe
  default.
- **Reuse, don't fork.** Reuse `Imr.DsyncDiscovery`,
  `NotifierEngine`, the internal-update queue, `SignRRset`, and the
  KSK-row query that `ComputeTargetDSSetForZone` already runs.
- **Stay separate from `SyncZoneDelegation`.** Argued below under
  "Reuse vs separate."
- **Orchestrator-agnostic push engine.** All rollover push entry
  points take their dependencies as injected parameters — no
  package-level globals, no implicit `conf.Internal.X` lookups,
  no `Zones.Get()` calls inside the push code. tdns/v2's
  `KeyStateWorker` and tdns-mp/v2's `KeyStateWorker` each
  construct their own dependency bundle and call the same push
  functions. The push engine doesn't know which orchestrator
  invoked it. This mirrors the DNS-115 pattern (TM decoupled
  from role globals via injected callbacks) — same shape, applied
  to the rollover engine.
- **Leader-only rollover in multi-provider deployments.** In a
  tdns-mp multi-provider setup, only the elected leader for a
  zone's provider group runs the rollover engine for that zone.
  This is intentional — the rollover state machine is per-zone,
  and concurrent rollover attempts from multiple providers would
  diverge their views of the keystore. tdns-mp's KeyStateWorker
  enforces this via the `AcquireLock` injection: a leader-aware
  wrapper consults gossip-based group leadership state (DNS-160)
  before delegating to `tdns.AcquireRolloverLock`. The rollover
  engine itself remains group-membership-agnostic; it just sees
  a lock acquirer that sometimes returns `ErrNotLeader`, treated
  identically to a contended lock (skip this cycle, retry next).

## Design

### Extraction shape: orchestrator-agnostic push engine

Survey of the existing rollover push code identifies the following
implicit dependencies that must become injected parameters:

| Today (implicit) | Where used | Becomes |
|------------------|-----------|---------|
| `Zones.Get()` / `Zones.Items()` | [ksk_rollover_automated.go:725, 808, 993](tdns/v2/ksk_rollover_automated.go:725) — iterates rolloverable zones | Injected: each orchestrator iterates its own zones and calls the per-zone tick directly. The push engine takes a single `*ZoneData`. |
| `lgSigner` | Throughout push paths — logger | Injected `*slog.Logger` (or wrapped equivalent), threaded through deps. |
| `AcquireRolloverLock(zone)` | [ksk_rollover_automated.go:79](tdns/v2/ksk_rollover_automated.go:79) — per-zone serialization | Injected `AcquireLock func(zoneName string) (release func(), err error)`. tdns/v2 wires the existing `AcquireRolloverLock` directly. tdns-mp wires a leader-aware wrapper that consults the gossip-based leader-election state (DNS-160) before delegating to `tdns.AcquireRolloverLock`. The `ErrNotLeader` sentinel is treated by the tick handler as "skip this cycle" — same shape as a contended lock. |
| `conf.Internal.ImrEngine` | [ksk_rollover_automated.go:807](tdns/v2/ksk_rollover_automated.go:807) — IMR for DSYNC discovery | Injected `*Imr` (already partially threaded; finish the job). tdns-mp already has access via [tdns-mp/v2/imr.go:12-14](tdns-mp/v2/imr.go:12-14) and `conf.Config.Internal.ImrEngine`; passes the underlying `*tdns.Imr` straight through. |
| `conf.Internal.DnssecPolicies` | Policy lookup at tick time | Injected resolved `*RolloverPolicy` per call, OR injected `PolicyForZone func(zoneName string) (*RolloverPolicy, error)` callback if the orchestrator wants late binding. |

The entry-point shape:

```go
// In tdns/v2 (or a sub-package — placement decision below).
// tdns-mp imports tdns/v2 already, so types stay where they are.

type RolloverEngineDeps struct {
    KDB             *KeyDB
    Zone            *ZoneData
    Imr             *Imr
    NotifyQ         chan NotifyRequest
    InternalUpdateQ chan *ZoneUpdate
    Policy          *RolloverPolicy
    AcquireLock     func(zoneName string) (release func(), err error)
    Logger          *slog.Logger
    Now             func() time.Time   // injected for testability
}

func PushDSRRsetForRollover(ctx context.Context, deps RolloverEngineDeps) (KSKDSPushResult, error)

func RolloverAutomatedTick(ctx context.Context, deps RolloverEngineDeps) error
```

The orchestrator's responsibility:

```go
// tdns/v2/key_state_worker.go (existing, refactored):
func KeyStateWorker(ctx context.Context, conf *Config) error {
    for zone := range Zones.Items() {                  // tdns/v2-specific zone iteration
        deps := RolloverEngineDeps{
            KDB: conf.Internal.KeyDB,
            Zone: zone,
            Imr: conf.Internal.ImrEngine,
            // ... wire the rest from conf
            AcquireLock: AcquireRolloverLock,
            Logger: lgSigner,
            Now: time.Now,
        }
        if err := RolloverAutomatedTick(ctx, deps); err != nil { ... }
    }
}

// tdns-mp/v2/key_state_worker.go (new wiring):
func KeyStateWorker(ctx context.Context, conf *Config) error {
    for zone := range mpZoneIterator() {                // MP-specific zone iteration
        deps := tdns.RolloverEngineDeps{
            KDB: conf.Config.HsyncDB.KeyDB,             // unwrap embedded *tdns.KeyDB
            Zone: mpZone.ZoneData,                      // unwrap embedded *tdns.ZoneData
            Imr: conf.Config.Internal.ImrEngine,        // direct *tdns.Imr (see below)
            AcquireLock: mpLeaderAwareLockAcquirer,     // wraps IsLeader + AcquireRolloverLock
            Logger: mpLgSigner,
            Now: time.Now,
            // ... etc
        }
        if err := tdns.RolloverAutomatedTick(ctx, deps); err != nil { ... }
    }
}
```

**Placement decision: keep in tdns/v2.** tdns-mp already imports
tdns/v2 directly (per [tdns-mp/v2/start_agent.go:20](tdns-mp/v2/start_agent.go:20)
and the embedding pattern in `HsyncDB`/`MPZoneData`). No need to
move the rollover engine to a third package — making it
dependency-injected in place is sufficient.

**No type duplication.** Both orchestrators pass `*tdns.ZoneData`
and `*tdns.KeyDB` (tdns-mp's wrappers embed these, so unwrapping
is field access). No interfaces to define for the core types.

**Imr in tdns-mp: already wired.** tdns-mp has its own `Imr`
wrapper at [tdns-mp/v2/imr.go:12-14](tdns-mp/v2/imr.go:12-14):

```go
type Imr struct {
    *tdns.Imr
}
```

Constructed via `&Imr{conf.Config.Internal.ImrEngine}` (see
[tdns-mp/v2/delegation_sync.go:26](tdns-mp/v2/delegation_sync.go:26)
and [tdns-mp/v2/apihandler_agent.go:530](tdns-mp/v2/apihandler_agent.go:530)).
The wrapper exists so tdns-mp can add MP-local methods later;
today it just promotes `*tdns.Imr` methods unchanged
(`DsyncDiscovery` at [tdns/v2/dsync_lookup.go:83](tdns/v2/dsync_lookup.go:83)
is already used at
[tdns-mp/v2/parentsync_leader.go:1309](tdns-mp/v2/parentsync_leader.go:1309)).

For rollover deps, tdns-mp passes `conf.Config.Internal.ImrEngine`
directly (the underlying `*tdns.Imr`), bypassing the wrapper —
the rollover engine doesn't need MP-local Imr methods. If MP
later adds methods that the rollover engine should consume, the
deps struct would change to take an interface instead of
`*tdns.Imr`; that's a future concern, not this work's.

**Leader-aware lock acquirer in tdns-mp.** Per the multi-provider
design, only the elected leader for a zone's provider group runs
the rollover engine. The `AcquireLock` injection is the right
seam for this check — it already gates "should I be doing this
for this zone right now?" tdns-mp wires:

```go
// tdns-mp/v2/rollover_lock.go (new ~30 LOC):
func mpLeaderAwareLockAcquirer(zoneName string) (release func(), err error) {
    if !leaderElection.IsLeader(zoneName) {
        return nil, ErrNotLeader              // sentinel; tick skips
    }
    return tdns.AcquireRolloverLock(zoneName)  // delegate to existing
}
```

The rollover engine's tick handler treats `ErrNotLeader`
identically to "lock currently held": skip this cycle, no error
escalation, retry next cycle. That keeps the engine
group-membership-agnostic — it just sees a lock acquirer that
sometimes says no.

### Discovery and scheme selection

Per-attempt DSYNC lookup. No policy-time caching. DSYNC is already
fetched per attempt today (the hardcoded `LookupDSYNCTarget` call
inside `PushWholeDSRRset`); cost stays the same. IMR caches DSYNC
results per its normal cache rules, so the apparent per-attempt
fetch is a cache hit at steady state.

**Parallel sends are a first-class case.** When a parent advertises
both UPDATE and NOTIFY for CDS, the default policy sends both. Cost
is one extra UDP NOTIFY per attempt; benefit is that an
advertised-but-broken scheme on one path doesn't block the rollover
when the other works. Both paths derive their target set from the
same `loadTargetKSKsForRollover` query, so they intend identical DS
writes — duplicate writes at the parent are idempotent.

New helper `pickRolloverSchemes` (plural), signature roughly:

```go
func pickRolloverSchemes(
    ctx context.Context,
    zd *ZoneData,
    imr *Imr,
    pol *DnssecPolicy,
) (schemes []schemeChoice, err error)

type schemeChoice struct {
    Scheme string         // "UPDATE" | "NOTIFY"
    Target *DsyncTarget
}
```

Logic:

1. `imr.DsyncDiscovery(ctx, zd.ZoneName, ...)` — fetches all DSYNC
   RRs at the parent.
2. Categorize advertised schemes: any UPDATE RR (matches all
   RRtypes) and any NOTIFY RR with `Type == TypeCDS || TypeANY`.
3. Apply `pol.Rollover.DsyncSchemePreference`. Returned slice
   indicates which schemes to attempt this push:

   | Policy | UPDATE adv. | NOTIFY adv. | Both adv. | Neither |
   |--------|-------------|-------------|-----------|---------|
   | `auto` (default) | `[UPDATE]` | `[NOTIFY]` | **`[UPDATE, NOTIFY]` (parallel)** | error |
   | `prefer-update` | `[UPDATE]` | `[NOTIFY]` | `[UPDATE]` | error |
   | `prefer-notify` | `[UPDATE]` | `[NOTIFY]` | `[NOTIFY]` | error |
   | `force-update` | `[UPDATE]` | error | `[UPDATE]` | error |
   | `force-notify` | error | `[NOTIFY]` | `[NOTIFY]` | error |

4. Resolve each chosen DSYNC RR's Target/Port to a `DsyncTarget`
   (same `net.LookupHost` step as `BestSyncScheme`).
5. **Failure mode "no usable scheme":** `child-config:waiting-for-parent`
   subcategory. See "Failure categorization" below.

`auto` is the operator default and means "use everything advertised;
let the parent sort it out." `prefer-*` is for operators who want
explicit single-scheme behavior even on a parent that advertises
both — useful for log hygiene or debugging. `force-*` is for
testbeds and adversarial-testing.

This intentionally diverges from `BestSyncScheme`:

- `BestSyncScheme` reads `delegationsync.child.schemes` from viper
  (a process-wide list). The rollover engine has a per-policy knob.
- `BestSyncScheme` filters NOTIFY by RRtype CSYNC or ANY. The
  rollover engine filters by RRtype CDS or ANY. A parent can
  legitimately advertise different schemes for CSYNC vs CDS.
- `BestSyncScheme` returns on first match in operator-listed order.
  The rollover engine returns a parallel set under `auto`.

Two callers, two filter rules, two enum models. Don't unify.

### Push phase: two phases, not one

The rollover state machine separates two concerns:

1. **Push phase.** Get the parent to acknowledge our intent at the
   wire level. UPDATE NOERROR or NOTIFY NOERROR — either is a
   wire-level commitment ("I heard you, I'll do something").
   Neither is a confirmation that DS will actually appear.
2. **Observe phase.** Poll DS at the parent until the target DS
   appears or `attempt-timeout` elapses. This is the only place
   where the rollover engine learns whether DS publication
   actually succeeded. Scheme-agnostic.

In the parallel model, the push phase has up to two wire-level
attempts (UPDATE and NOTIFY); they are dispatched concurrently and
their wire-level results are aggregated. The observe phase is
unchanged in shape and unchanged in code path. The child has no
way to attribute a successful observation to UPDATE vs. NOTIFY —
and doesn't need to.

### NOTIFY push path

```go
func pushDSRRsetViaNotify(
    ctx context.Context,
    zd *ZoneData,
    kdb *KeyDB,
    target *DsyncTarget,
    notifyq chan NotifyRequest,
) (KSKDSPushResult, error)
```

Steps:

1. **Compute target KSK set.** Refactor: extract
   `loadTargetKSKsForRollover(kdb, zone) ([]kskForDSRow, ...)` from
   `ComputeTargetDSSetForZone` — the SQL query is the source of
   truth for "keys belonging in the rollover-target DS RRset."
   Two callers wrap it: `ComputeTargetDSSetForZone` (DS, unchanged)
   and a new `ComputeTargetCDSSetForZone` (CDS, new).
2. **Compute CDS records** from the rollover-target KSK rows. Same
   `dnskey.ToDS(SHA256)` followed by wrapping in `*dns.CDS`. TTL
   choice: match the zone's CDS TTL convention (`ops_cds.go` uses
   120s; align with that).
3. **Publish-and-sign as a single transaction.** Queue an
   internal-update with anti-CDS ClassANY delete + ClassINET adds
   for the engine-computed CDS set, plus the sign step (CDS RRSIG
   + apex NSEC re-sign). Same shape as `PublishCdsRRs` but
   parameterized on the engine-computed set instead of synthesizing
   from in-zone DNSKEYs.
   - **On transaction success:** proceed to step 4.
   - **On transaction failure** (publish failed, signing failed,
     or NSEC re-sign failed): queue a rollback internal-update
     (anti-CDS ClassANY delete only; restore pre-push state),
     categorize as `child-config:local-error`, return without sending NOTIFY.
     Best-effort rollback: if the rollback's own sign step fails
     too (signing infra fully broken), log ERROR — that is an
     operator-alarm condition outside the rollover engine's scope.
4. **Persist `last_published_cds_index_low/high`** on
   RolloverZoneState. These are the rollover engine's claim of
   ownership over the current CDS RRset for cleanup-time comparison.
5. **Send NOTIFY(CDS)** via NotifierEngine. Allocate a fresh
   `Response chan NotifyResponse` on the `NotifyRequest`; block on
   it bounded by a context timeout (~30s, same shape as the current
   45s SendUpdate timeout). NotifierEngine writes back the actual
   rcode + err + EDE (see Phase 4 prerequisite below).
6. **Categorize NOTIFY response:**
   - transport error from `SendNotify` (no target replied
     successfully) → transport
   - rcode REFUSED/SERVFAIL/FORMERR/NOTAUTH from any-success-wins
     aggregate → parent-rejected. Surface EDE detail in
     `KSKDSPushResult.Detail` for operator diagnostics
     (e.g. `EDENotifyDsyncSchemeNotAdvertised` is much more
     actionable than bare REFUSED).
   - rcode NOERROR → success.
7. **On NOERROR**, return `KSKDSPushResult{Status: success,
   Scheme: "NOTIFY"}`. The dispatcher persists state. CDS stays
   published; cleanup happens later via Trigger 1.
8. **On NOTIFY failure (transport or parent-rejected)**, leave CDS
   published. The zone has signed CDS at the apex matching the
   saved `last_published_cds_index_low/high`. Next attempt
   re-derives the same CDS set, the publish-and-sign transaction
   becomes a no-op (same RRset already there), and the engine
   re-sends NOTIFY. No churn.

The NOTIFY ACK is the same wire-protocol commitment as UPDATE
NOERROR: "I will publish what you advertised." Neither commitment
guarantees DS will actually appear; that's the observe phase's
job, scheme-agnostic.

### Dispatcher

Rename `PushWholeDSRRset` → `pushDSRRsetViaUpdate` (lower-case,
package-private). New public function:

```go
func PushDSRRsetForRollover(
    ctx context.Context,
    zd *ZoneData,
    kdb *KeyDB,
    imr *Imr,
    pol *DnssecPolicy,
    notifyq chan NotifyRequest,
) (KSKDSPushResult, error)
```

Logic:

1. **Pick schemes:** call `pickRolloverSchemes` → slice of one or
   two `schemeChoice`. If error → return `child-config:waiting-for-parent`
   (after running Trigger-2 cleanup if `last_published_cds_index_*`
   is set).
2. **Pre-dispatch CDS cleanup (Trigger 2):** if the chosen schemes
   do NOT include NOTIFY AND `last_published_cds_index_*` is set,
   run `cleanupCdsAfterConfirm` first (best-effort).
3. **Dispatch in parallel.** Spawn one goroutine per scheme:
   - UPDATE goroutine → `pushDSRRsetViaUpdate(...)`.
   - NOTIFY goroutine → `pushDSRRsetViaNotify(...)`.
   Each returns its own `KSKDSPushResult`. Bound by a single
   `attempt-timeout` covering both.
4. **Aggregate wire-level results** (push-phase outcome only —
   observe is downstream and unaffected):
   - **Any** path returned `Status: success` (NOERROR at the wire)
     → push succeeds. Aggregate `KSKDSPushResult.Scheme` is set to
     the comma-joined list of paths that succeeded
     (`"UPDATE"`, `"NOTIFY"`, or `"UPDATE,NOTIFY"`); used for
     `last_attempt_scheme` and status display only. Persist
     `last_ds_submitted_index_low/high`, `last_attempt_scheme`,
     and (if NOTIFY succeeded) `last_published_cds_index_low/high`.
   - **All** paths failed → push fails. Aggregate category =
     most-actionable: `parent-rejected` (with concatenated EDE
     details) > `transport` > `child-config:local-error`. Surface
     all per-path details in `KSKDSPushResult.Detail` for
     diagnostics.
5. Persist + return the aggregate result.

Both call sites in `RolloverAutomatedTick`
([line 202](tdns/v2/ksk_rollover_automated.go:202) and
[line 397](tdns/v2/ksk_rollover_automated.go:397)) switch over to
the dispatcher; the policy and notifyq are already in scope at both
sites.

**Single-scheme as a degenerate case.** When `pickRolloverSchemes`
returns a 1-element slice (most common case under any policy except
`auto`-with-both-advertised), the dispatcher spawns one goroutine
and aggregates trivially. No special-case code path.

### CDS cleanup

RFC 7344 §4.1: child should remove CDS once the parent has updated
DS. Cleanup ownership is asserted by `last_published_cds_index_low/
high IS NOT NULL`, **not** by `last_attempt_scheme`. The scheme
name is diagnostic; the index range is the engine-functional
ownership marker.

Cleanup runs at three trigger points, all calling the same
`cleanupCdsAfterConfirm(zd, kdb)` helper. All three are
short-circuited by `last_published_cds_index_low/high IS NULL`
(nothing to clean up).

**Trigger 1 — confirmed observation (primary path).**

```
on confirmed observation:
   if last_published_cds_index_low/high IS NOT NULL:
       cleanupCdsAfterConfirm(zd, kdb)
   advance keys...
```

This handles the steady-state NOTIFY-pushed rollover: push,
observe, confirm, clean up.

**Trigger 2 — start of any push attempt that won't republish CDS.**

After `pickRolloverSchemes` returns, before dispatching:

```
schemes, err := pickRolloverSchemes(ctx, zd, imr, pol)
if last_published_cds_index_low/high IS NOT NULL:
   if err != nil OR NOTIFY not in schemes:
       cleanupCdsAfterConfirm(zd, kdb)  // best-effort
       // proceed: return child-config:waiting-for-parent (err case)
       //          or dispatch the chosen schemes (UPDATE-only case)
```

This handles parent-side scheme transitions mid-rollover:

- **Scenario 1 tail.** Parent flips DSYNC NOTIFY→UPDATE-only in the
  middle of a rollover where the previous attempt was NOTIFY (or
  parallel) and published CDS. Next attempt's `pickRolloverSchemes`
  returns `[UPDATE]`; NOTIFY is absent; cleanup runs first, removes
  the now-stale CDS, then UPDATE dispatches.
- **Scenario 2 middle.** Parent withdraws DSYNC entirely after a
  NOTIFY-pushed cycle. `pickRolloverSchemes` errors with "no usable
  scheme"; cleanup runs first (parent can't consume CDS-based
  signal anyway), then return
  `child-config:waiting-for-parent`. CDS does not sit orphaned for
  the duration of the outage.

NOTIFY → NOTIFY transitions don't need pre-cleanup:
`pushDSRRsetViaNotify`'s anti-CDS ClassANY delete in step 3
naturally replaces whatever CDS was there.

**Trigger 3 — terminal hardfail.**

When the rollover state machine transitions to terminal hardfail
(operator-attention-required state):

```
on hardfail transition:
   if last_published_cds_index_low/high IS NOT NULL:
       cleanupCdsAfterConfirm(zd, kdb)  // best-effort
```

Catches the scenario-4 hardfail tail: NOTIFY-pushed CDS exists,
NOTIFY never recovered, no observation ever confirmed. The
hardfail itself is the signal that the rollover is dead; leaving
orphan CDS is unhelpful.

All three triggers are best-effort: if the cleanup queue or
comparison errors, log and continue. The CDS RRset is in the
child zone, not on any rollover-critical path.

`cleanupCdsAfterConfirm`:

1. Read current CDS RRset from `zd` (in-memory zone, no DNS round-
   trip).
2. Reload the KSK rows referenced by the saved
   `last_published_cds_index_low/high` from the keystore. These
   rows MAY have advanced state since the push (most likely have —
   the confirmation is what triggered advancement). State is
   irrelevant; only the key material matters for CDS derivation.
3. Re-derive the **expected CDS RRset** from those rows using the
   same `dnskey.ToDS(SHA256)` + `*dns.CDS` wrapping used at push
   time.
4. Compare expected vs. current CDS as a **set of (KeyTag, Algorithm,
   DigestType, Digest) tuples** (not bytewise — TTL, ownername case,
   and RRset ordering are immaterial; the four DS-identifying fields
   are what defines a DS/CDS record).
   - **Equal sets** → we still own this CDS RRset. Queue
     `UnpublishCdsRRs` (anti-CDS ClassANY delete only; no adds).
     Clear `last_published_cds_index_low/high`.
   - **Unequal sets** → another caller has changed CDS. Log INFO
     (`"rollover: CDS no longer matches last push, leaving in
     place"`), clear `last_published_cds_index_low/high` so we
     don't retry next cycle, leave CDS on the wire. The other
     caller owns its lifecycle now.
5. If the row reload itself fails (rows deleted, sqlite error):
   treat as "unequal" — log WARN, clear index range, leave CDS.

The comparison is on the four DS-identifying tuple fields rather
than bytewise so that incidental differences (TTL adjustments,
re-canonicalization on re-signing) don't trip ownership detection.
If a third party publishes a CDS with the *same* (KeyTag, Algorithm,
DigestType, Digest) tuples we did, treating it as ours and
unpublishing is the correct outcome — they wanted exactly what we
wanted, the parent has confirmed, the signal has served its
purpose.

This is intentionally conservative. The general delegation-sync
path also publishes CDS for non-rollover DS edits and has its own
implicit lifecycle ("CDS reflects the current DS intent until the
parent picks it up"). The rollover engine only cleans up what it
owns.

Alternative considered: a "published-by" tag on CDS records, e.g.
embedding a sentinel TXT record alongside. Rejected. CDS RRs are
visible on the wire and signed; any tag is observable and
unsightly. The compare-on-cleanup approach is cheap and good
enough.

### Parent-side: what's already there, what's missing

The parent-side NOTIFY(CDS) path is largely complete. For
completeness in the design, the four moving parts:

| Parent-side concern | Status | Location |
|---------------------|--------|----------|
| Advertise NOTIFY scheme in DSYNC | done | [ops_dsync.go:69](tdns/v2/ops_dsync.go:69) |
| Accept NOTIFY(CDS) at the wire | done | [notifyresponder.go:132](tdns/v2/notifyresponder.go:132) |
| Fetch CDS from child NSs, validate, compute DS adds/removes | done | [scanner.go:1078](tdns/v2/scanner.go:1078) |
| Route DS changes through delegation backend | done | scanner.go CHILD-UPDATE flow |
| **EDE on synchronous NOTIFY rejection** | **missing** | Phase 11 only touched updateresponder.go |
| **Gate on whether parent advertises NOTIFY for this RRtype** | **missing** | NotifyResponder does not consult its own zone's DSYNC RRset |
| **Surfacing async ProcessCDSNotify failures** | **structurally impossible** | NOTIFY is fire-and-forget at the wire |

The first four entries mean the rollover engine's NOTIFY push will,
on a healthy parent, work end-to-end out of the gate. No
parent-side feature work is required to ship a basic NOTIFY-scheme
rollover.

The fifth entry — EDE attachment for synchronous NOTIFY rejections
— is the same kind of operator-experience improvement that Phase 11
of rollover-overhaul did for UPDATE. It's worth doing for symmetry
and because the child-side `parent-rejected` category is much less
useful without a specific reason. New phase below.

The sixth entry is the most important parent-side gap. Today,
`NotifyResponder` does **no** consultation of its own zone's DSYNC
RRset before scanning. A child that sends NOTIFY(CDS) to a parent
that advertises only NOTIFY(CSYNC) — or only UPDATE, or no DSYNC
at all — gets silently scanned anyway. That is wrong on two axes:
the parent operator never opted into NOTIFY(CDS) but is now doing
the work, and the child operator never gets told their config is
wrong. The right behavior is: `NotifyResponder` looks up the
parent zone's DSYNC RRset, checks whether the incoming
`(scheme=NOTIFY, RRtype=qtype)` pair is advertised (with `RRtype=ANY`
matching everything), and on miss returns REFUSED + an EDE saying
"this parent does not advertise NOTIFY for type X; ignoring." The
DSYNC RRset is local zone data — the lookup is in-memory, no DNS
round-trip. Folded into the new phase below.

The seventh entry is an unavoidable consequence of the NOTIFY model.
It does have one important implication for the child-side design:
**the rollover-engine's `parent-rejected` category will be much
rarer on NOTIFY-pushed attempts than on UPDATE-pushed ones**, and
`parent-publish-failure` correspondingly more common. This is not a
bug. Operators should be told, in the docs, that on a
NOTIFY-advertising parent the most likely category for a broken
push is `parent-publish-failure` even when the underlying cause is
a CDS validation problem. To diagnose, they need to consult the
parent-side scanner logs.

### Failure categorization

Four top-level categories; `child-config` splits into two
subcategories that differ in recovery model.

| Category | Push-phase trigger (per-path; aggregated by dispatcher) | Recovery model |
|----------|--------------------------------------------------------|----------------|
| `child-config:waiting-for-parent` | `pickRolloverSchemes` returned no usable scheme: parent advertises no DSYNC at all; or `force-X` policy and X not advertised; or `prefer-*` and parent advertises neither. | **Indefinite softfail. Backoff capped at 1h. Never hardfails.** Recovers automatically when parent's DSYNC matches the policy's needs. |
| `child-config:local-error` | No SIG(0); no DS to publish; ParentZone unresolvable; UPDATE SignMsg failed; NOTIFY publish-and-sign transaction failed (after rollback). Engine-internal failure. | Existing softfail→hardfail path. Operator intervention required. |
| `transport` | UPDATE: i/o timeout, conn refused, no route. NOTIFY: `SendNotify` returned with no successful target. Aggregated across paths only when **all** paths fail at transport. | Existing softfail→hardfail path. |
| `parent-rejected` | Wire-level rejection rcode (REFUSED/NOTAUTH/FORMERR/SERVFAIL) on at least one path while no path returned NOERROR. EDE concatenated across paths into `KSKDSPushResult.Detail`. | Existing softfail→hardfail path. EDE-driven diagnostics. |
| `parent-publish-failure` | Observe-phase only: at least one push path NOERRORed, but DS never matched target within `attempt-timeout`. Scheme-agnostic by construction; unchanged from UPDATE-only design. | Existing softfail→hardfail path. Will fire more often on NOTIFY pushes (async ProcessCDSNotify failures surface here, not on the wire). |

**Push-phase aggregation rule (parallel mode).** The dispatcher
combines per-path results:

- If **any** path returned `Status: success` (wire-level NOERROR):
  push succeeds, enter observe phase. Per-path failures on the
  other path are logged at WARN but do not block; the working path
  carries the rollover.
- If **all** paths failed: push fails. Aggregate category =
  most-actionable: `parent-rejected` if any path got an explicit
  rejection rcode; else `transport` if all paths failed at the
  network layer; else `child-config:local-error` for engine-internal
  failures. EDE/details from all failed paths are concatenated for
  diagnostics.

**Single-scheme degenerate case.** When `pickRolloverSchemes`
returns one path, aggregation is trivial — that path's result
becomes the aggregate result.

**Subcategory rationale.** `child-config:waiting-for-parent` is the
"halt is OK if no mechanism for parent sync is available, but
recover when parent recovers" guarantee. The rollover state machine
must check the subcategory before counting a softfail toward the
hardfail threshold:

```
on softfail:
  if category == "child-config:waiting-for-parent":
     // never hardfail; cap backoff at 1h; keep probing forever
     schedule_next_probe(min(softfail_delay * 2^attempt, 1h))
     do not increment hardfail_count
  else:
     // existing softfail → hardfail path
     existing_softfail_bookkeeping()
```

The 1h cap is also the natural IMR DSYNC re-fetch cadence (typical
parent DSYNC TTL); the probe IS the poll. No separate slow-tick
infrastructure.

### Schema additions

Two new columns on `RolloverZoneState`. Migration via the same
`dbMigrateSchema` mechanism rollover-overhaul Phase 2 used.

```sql
last_attempt_scheme              TEXT,        -- "UPDATE" | "NOTIFY" | "UPDATE,NOTIFY"; NULL if no attempt yet
last_published_cds_index_low     INTEGER,     -- ownership marker for CDS cleanup
last_published_cds_index_high    INTEGER,
```

`last_attempt_scheme` is **diagnostic only** — the engine never
decides anything from this column; status output reads it for
display. The current scheme(s) are re-derived per attempt from
DSYNC. Comma-joined when parallel sends ran (one or both paths
returned wire-level NOERROR).

`last_published_cds_index_low/high` is engine-functional: it gates
CDS cleanup ownership. NULL means "we have no CDS published" (or
"some other caller owns whatever CDS is currently published").
Set whenever a NOTIFY push (parallel or single) successfully
completes the publish-and-sign transaction, regardless of whether
the parallel UPDATE path also succeeded.

`RolloverZoneRow`, `LoadRolloverZoneRow`, the canonical CREATE
TABLE in `db_schema.go`, and accessors all extend by three fields.

### RolloverStatus / status output

Add to `RolloverStatus` ([messages_rollover.go](tdns/v2/messages_rollover.go)):

```go
LastAttemptScheme string `json:"lastAttemptScheme,omitempty"` // "UPDATE" | "NOTIFY" | "UPDATE,NOTIFY"
```

Status-output rendering: rename "last UPDATE" → "last push" (the
old wording was scheme-baked) and append a `via …` qualifier:

```
last push          14:30:00 UTC (5m23s ago) via UPDATE,NOTIFY(CDS)
```

In the ACTIVE and SOFTFAIL templates from the rollover-overhaul doc,
the line replaces the existing `last UPDATE` line one-for-one. No
new line; just renamed and qualified. The comma-joined form
indicates parallel sends ran and at least one wire-level
acknowledged.

### Configuration knob

New field on `DnssecPolicyRolloverConf`:

```yaml
dnssecpolicies:
  fastroll:
    rollover:
      method: multi-ds
      ds-publish-delay: 5m
      max-attempts-before-backoff: 5
      softfail-delay: 1h
      dsync-scheme-preference: auto    # new; default "auto"
```

Values:

| Value | Both adv. | One adv. | Neither |
|-------|-----------|----------|---------|
| `auto` (default) | **parallel UPDATE + NOTIFY** | the advertised one | error (waiting-for-parent) |
| `prefer-update` | UPDATE only | the advertised one | error |
| `prefer-notify` | NOTIFY only | the advertised one | error |
| `force-update` | UPDATE only | UPDATE only or error | error |
| `force-notify` | NOTIFY only | NOTIFY only or error | error |

Unknown values: parse error in `FinishDnssecPolicy`. Cross-field
validation: nothing required.

`auto` is the correct default for almost every operator: it gives
maximum resilience against parent-side mismatches between announced
and actual support, at the cost of one extra UDP NOTIFY per attempt
when both schemes are advertised. `prefer-*` is for operators who
want explicit single-scheme behavior on a both-advertising parent
(log hygiene, debugging). `force-*` is for testbeds and
adversarial-testing.

### Reuse vs separate from SyncZoneDelegation

Don't reuse. Four reasons:

1. **Diff vs target.** `SyncZoneDelegation` operates on
   `DelegationSyncStatus` carrying NS/A/AAAA/DS adds and removes
   computed against the parent's current state. The rollover
   engine has the full target DS set in hand and does not have
   (or want) a "current-parent-DS" probe at push time. Translating
   target → diff would require an extra parent query on every push.
2. **Failure categorization.** `SyncZoneDelegation` returns
   `(string, uint8 rcode, UpdateResult, error)`. The rollover
   engine needs `KSKDSPushResult.Category` at every error path.
   Either every error path in `SyncZoneDelegation` grows a category
   field (changing its API for one caller) or the caller infers
   category from `(rcode, error)` heuristically. Both worse than
   keeping a small dedicated push path.
3. **Lifecycle bookkeeping.** `last_ds_submitted_index_low/high`,
   `last_attempt_started_at`, `last_attempt_scheme`,
   `last_published_cds_index_*`, `hardfail_count` are all
   rollover-specific and have no place in `SyncZoneDelegation`.
4. **CDS lifecycle.** The rollover engine needs the
   compare-on-cleanup ownership check on confirmation. The general
   delegation-sync path doesn't — it manages CDS while delegation
   data is in flux, with no observable terminal "DS confirmed by
   parent" event.

One small extraction worth doing: a private helper
`signAndQueueCdsNotify(zd, kdb, target, notifyq) error` that does
sign + queue. Both `SyncZoneDelegationViaNotify` and the new
`pushDSRRsetViaNotify` could call it. Optional. Skip if it doesn't
collapse meaningful duplication.

### Testing

Phase 12 of rollover-overhaul left a tick-handler unit-test harness
as future work. Adding NOTIFY support is the right moment to build
it: a second push path forces the test interface to actually be
swappable rather than a fiction.

Harness shape:

```go
type rolloverTickHarness struct {
    kdb        *KeyDB                                // sqlite-in-memory
    zd         *ZoneData                             // synthetic
    pushDS     func(ctx, zd, kdb, imr, pol, notifyq) (KSKDSPushResult, error)
    queryDS    func(ctx, zone, agent string) (...DSObservation, error)
    notifyq    chan NotifyRequest                    // captured, asserted
    updateq    chan UpdateRequest                    // captured, asserted
    now        time.Time                             // injected
}
```

Coverage matrix (~20-25 cases):

- Per phase: idle, pending-child-publish, pending-parent-push,
  pending-parent-observe, parent-push-softfail,
  pending-child-withdraw.
- Per push mode: UPDATE-only, NOTIFY-only, parallel-both.
- Per per-path outcome combination (parallel mode): UPDATE-success
  + NOTIFY-success, UPDATE-success + NOTIFY-fail, UPDATE-fail +
  NOTIFY-success, UPDATE-fail + NOTIFY-fail.
- Per failure category at the push site: success,
  `child-config:waiting-for-parent` (asserts
  hardfail_count NOT incremented, backoff capped at 1h),
  `child-config:local-error` (asserts existing softfail bookkeeping),
  transport, parent-rejected, parent-publish-failure (observe-phase,
  scheme-agnostic).
- Parent-flip scenarios (the four user-supplied combinations):
  - Mid-rollover scheme transition NOTIFY→UPDATE asserts trigger-2
    cleanup.
  - DSYNC withdrawn for N cycles, then restored asserts indefinite
    softfail + automatic recovery on parent restoration.
  - Parent advertises both, both succeed asserts default `auto`
    aggregate behavior.
  - Parent advertises NOTIFY only, NOTIFY transport-fails asserts
    transport softfail and Step 8 no-churn-on-retry semantics.

Unit tests assert post-tick state: `RolloverPhase`,
`hardfail_count`, `last_softfail_*`, `last_attempt_scheme`,
`last_published_cds_index_*`, and the contents of
`notifyq`/`updateq` (e.g. that a NOTIFY-path tick produced a
NotifyRequest with `RRtype == TypeCDS` and a ZONE-UPDATE on the
internal queue with the expected anti-CDS + adds; that a parallel
tick produced both).

`PushDSRRsetForRollover` is injected so tests don't make actual DNS
queries. `pickRolloverSchemes` is exercised directly in its own
unit tests (table-driven over advertised-schemes × policy-preference,
asserting parallel return for `auto` × both-advertised).

### Logging

Existing rollover log lines gain a `scheme=…` field reflecting
which paths were dispatched:

```
WARN  rollover: parent push failed schemes=UPDATE,NOTIFY zone=cpt.p.axfr.net.
      attempt=2/5 category=parent-rejected
      detail="UPDATE: rcode=REFUSED EDE=18 'prohibited' | NOTIFY: rcode=REFUSED EDE=24 'parent does not advertise NOTIFY for type CDS'"

INFO  rollover: parent push partial success schemes=UPDATE,NOTIFY zone=cpt.p.axfr.net.
      succeeded=UPDATE failed=NOTIFY
      detail="NOTIFY: i/o timeout to 192.0.2.1:53"
```

The "partial success" line at INFO level is operationally useful:
it lets the operator see that one path is broken even though the
rollover is succeeding (via the working path). Don't suppress.

No new metrics labels — `tdns_rollover_softfail_zones_total{category=…}` already
covers the relevant axes. Adding `scheme=…` would explode cardinality on
zones with no NOTIFY-capable parents.

## Implementation phases

Each phase = one or two commits on a branch off `rollover-overhaul`
(once that lands). Order is sequential except phase 1a (tdns-mp
wiring), phase 8 (parent-side EDE), and phase 9 (test harness),
all of which can land in parallel with the main child-side
sequence (phases 2-7).

| Phase | Title | Notes |
|-------|-------|-------|
| 1 | Refactor + extraction: dependency-inject rollover push paths; extract loadTargetKSKsForRollover; rename PushWholeDSRRset → pushDSRRsetViaUpdate; introduce dispatcher PushDSRRsetForRollover | No behavior change in tdns/v2; enables tdns-mp wiring |
| 1a | Wire tdns-mp/v2/KeyStateWorker to invoke rollover push | Parallel to phase 2-7 once phase 1 lands; non-blocking for child-side feature work |
| 2 | Schema additions + RolloverZoneRow extensions | last_attempt_scheme (TEXT, comma-joined), last_published_cds_index_* |
| 3 | Policy knob (`dsync-scheme-preference`) + pickRolloverSchemes + tests | Default `auto`. Returns `[]schemeChoice`, may be 1 or 2 entries |
| 4 | pushDSRRsetViaNotify + ComputeTargetCDSSetForZone + parallel dispatch in PushDSRRsetForRollover | Wires into dispatcher; aggregate per-path results |
| 5 | CDS cleanup with three triggers | `cleanupCdsAfterConfirm` + Trigger 1/2/3 hooks |
| 6 | Subcategorize child-config + softfail cap for waiting-for-parent | `child-config:waiting-for-parent` never hardfails, backoff capped at 1h |
| 7 | RolloverStatus.LastAttemptScheme + CLI rendering | Rename "last UPDATE" → "last push"; comma-joined for parallel |
| 8 | Parent-side: DSYNC scheme gate + EDE on synchronous NOTIFY rejection | Mirror Phase 11 of rollover-overhaul + new "scheme not advertised" gate; can land in parallel with phases 1-7 |
| 9 | Tick-handler test harness with parallel scheme support | The largest phase |
| 10 | Docs + ops runbook update | Cross-reference 2026-04-29-rollover-overhaul.md |

### Phase 1 — Refactor + extraction (no behavior change)

This phase has two parts that land together because the
dependency-inject refactor touches the same call sites as the
rename. Total scope is larger than a typical "refactor" phase.

**Part A — extraction:**

1. Define `RolloverEngineDeps` struct in tdns/v2 (placement: a new
   file, e.g. `tdns/v2/rollover_engine_deps.go`, or appended to
   an existing rollover file).
2. Convert `RolloverAutomatedTick` to take `RolloverEngineDeps`
   instead of `(zd *ZoneData, conf *Config)`.
3. Find every internal use of:
   - `Zones.Get()` / `Zones.Items()` → push out to caller (the
     orchestrator iterates; the tick handles a single
     pre-resolved zone).
   - `lgSigner` → use `deps.Logger`.
   - `AcquireRolloverLock(zone)` → use `deps.AcquireLock(zone)`.
   - `conf.Internal.ImrEngine` → use `deps.Imr`.
   - `conf.Internal.DnssecPolicies` lookup → use `deps.Policy`
     (resolved by orchestrator before call).
4. Update `KeyStateWorker` ([key_state_worker.go:27](tdns/v2/key_state_worker.go:27))
   to construct `RolloverEngineDeps` per-zone and call
   `RolloverAutomatedTick(ctx, deps)`. Behavior unchanged.

**Part B — rename + dispatcher introduction:**

5. Extract `loadTargetKSKsForRollover(kdb *KeyDB, zone string) (rows []kskForDSRow, indexLow, indexHigh int, indexRangeKnown bool, err error)`.
6. Rewrite `ComputeTargetDSSetForZone` as a thin wrapper that calls
   the helper and converts to DS.
7. Rename `PushWholeDSRRset` → `pushDSRRsetViaUpdate` (lower-case).
   Update its signature to take `RolloverEngineDeps` (or a subset).
8. Introduce `PushDSRRsetForRollover` dispatcher; delegate to
   `pushDSRRsetViaUpdate` only (no NOTIFY yet). Both call sites in
   the tick switch over.
9. Build, run existing tests. tdns/v2 behavior is unchanged.

### Phase 1a — Wire tdns-mp's KeyStateWorker

Independent of phases 2-7; can land any time after phase 1.
Specifically: tdns-mp's KeyStateWorker
([tdns-mp/v2/key_state_worker.go:27](tdns-mp/v2/key_state_worker.go:27))
currently does basic key-state transitions but does not invoke any
rollover push. With phase 1 done, the push functions are now
callable; tdns-mp wires them.

1. **New file `tdns-mp/v2/rollover_lock.go`** (~30 LOC):
   leader-aware lock acquirer. Consults gossip-based leadership
   state via the existing leader-election machinery (DNS-160)
   and delegates to `tdns.AcquireRolloverLock` only when the
   local instance is leader for the zone's provider group:

   ```go
   var ErrNotLeader = errors.New("rollover: not leader for this zone, skipping")

   func mpLeaderAwareLockAcquirer(zoneName string) (release func(), err error) {
       if !leaderElection.IsLeader(zoneName) {
           return nil, ErrNotLeader
       }
       return tdns.AcquireRolloverLock(zoneName)
   }
   ```

   The exact `IsLeader(zoneName)` call should use whatever helper
   the existing per-group election work exposes (see DNS-160 /
   `parentsync_leader.go` for the pattern; the rollover lock
   acquirer follows the same idiom).

2. **tdns/v2 side** (~10 LOC modified): the rollover tick handler
   recognizes `ErrNotLeader` (or any "soft" lock-acquisition
   failure) and treats it as "skip this cycle, no error
   escalation." tdns/v2's own `AcquireRolloverLock` never returns
   this error, so behavior in single-provider deployments is
   unchanged. This is a small adjustment to the lock-acquisition
   error handling in `RolloverAutomatedTick`.

3. **Modify `tdns-mp/v2/key_state_worker.go`** (~30-50 LOC added):
   construct `tdns.RolloverEngineDeps` per zone and call
   `tdns.RolloverAutomatedTick(ctx, deps)`. Field wiring:
   - `KDB` ← `conf.Config.HsyncDB.KeyDB` (embedded `*tdns.KeyDB`)
   - `Zone` ← `mpZone.ZoneData` (embedded `*tdns.ZoneData` from `MPZoneData`)
   - `Imr` ← `conf.Config.Internal.ImrEngine` (direct
     `*tdns.Imr`; the tdns-mp `Imr` wrapper at
     [tdns-mp/v2/imr.go:12-14](tdns-mp/v2/imr.go:12-14) is
     bypassed for the rollover engine since it doesn't need MP-local
     methods)
   - `NotifyQ`, `InternalUpdateQ` ← MP's existing channels
   - `Policy` ← MP's `DnssecPolicies` lookup
   - `AcquireLock` ← `mpLeaderAwareLockAcquirer` from step 1
   - `Logger` ← MP's `lgSigner` equivalent
   - `Now` ← `time.Now`
4. Build tdns-mp; run existing tests; run a manual rollover smoke
   test on an MP zone to confirm leader-only execution.

This phase is essentially "one new file (~30 LOC for the lock
acquirer) plus one new for-loop in KeyStateWorker plus a small
error-handling adjustment in tdns/v2 to recognize `ErrNotLeader`."
Half a day at most.

Independently shippable: until it lands, tdns-mp continues to do
no automated rollover push (its current behavior); after, MP
zones get the same rollover capability as single-provider zones,
restricted to the elected leader per the multi-provider design.

### Phase 2 — Schema + state

1. Migration entries (one per new column).
2. Update `db_schema.go` canonical CREATE TABLE.
3. Extend `RolloverZoneRow` and `LoadRolloverZoneRow`.
4. Accessors: `setLastAttemptScheme(zone, scheme)`,
   `setPublishedCdsRange(zone, low, high)`,
   `clearPublishedCdsRange(zone)`.
5. Build, run existing tests against a copy of a testbed
   `RolloverZoneState` table.

### Phase 3 — Policy knob + scheme selection

1. New field on `DnssecPolicyRolloverConf` and `RolloverPolicy`:
   `DsyncSchemePreference string`.
2. Parse + validate in `FinishDnssecPolicy`.
3. Implement `pickRolloverSchemes` — returns `[]schemeChoice`,
   may be 1 or 2 entries depending on advertised × policy.
4. Unit tests: table-driven over (advertised UPDATE? + advertised
   NOTIFY?) × (auto, prefer-update, prefer-notify, force-update,
   force-notify) → 4 × 5 = 20 cells. Asserts parallel return for
   `auto` × both-advertised; asserts error for "no usable scheme"
   cases (and that the dispatcher will categorize these as
   `child-config:waiting-for-parent`).
5. Build.

### Phase 4 — NOTIFY push path + parallel dispatch

**Prerequisite (~10 lines of code in notifier.go):**

1. `Notifier` (notifier.go:50-58) propagates `SendNotify`'s actual
   rcode/err through `NotifyResponse` instead of hardcoding success.
2. `NotifyResponse` (notifier.go:23-28) gains
   `EDE []dns.EDNS0_EDE`.
3. `SendNotify` (notifier.go:64-132) extracts EDE from each
   target's response (when present) and returns it alongside
   rcode/err. Aggregation policy stays any-success-wins; on a
   successful overall outcome with mixed per-target rcodes, the
   returned EDE is from the first NOERROR target (i.e. empty in
   the typical case). On overall failure, the returned EDE is
   from the last failing target's response (most-recent-loss
   wins for diagnostics).
4. Existing callers that don't allocate `Response` are unaffected.

Phase work:

1. `ComputeTargetCDSSetForZone` (wraps `loadTargetKSKsForRollover`).
2. `pushDSRRsetViaNotify` — publish CDS via internal-update queue
   transactionally with sign, queue NOTIFY(CDS) with a Response
   channel, await ack/error, categorize.
3. Optional helper `signAndQueueCdsNotify` if duplication with
   `SyncZoneDelegationViaNotify` earns it.
4. **Parallel dispatch in `PushDSRRsetForRollover`.** Spawn one
   goroutine per `schemeChoice`. Each writes into a shared
   per-path result slice. After all return (bounded by
   `attempt-timeout`), aggregate per the rules in Failure
   Categorization.
5. Persist `last_attempt_scheme` (comma-joined for parallel),
   `last_published_cds_index_*` on success (whenever NOTIFY path
   completed publish-and-sign successfully, regardless of UPDATE
   path outcome).
6. Build.

### Phase 5 — CDS cleanup (three triggers)

1. `cleanupCdsAfterConfirm(zd, kdb)` — compare-on-cleanup logic
   (gated only on `last_published_cds_index_*` being non-NULL;
   no-op if NULL).
2. Hook trigger 1 — `pending-parent-observe` confirmed branch.
3. Hook trigger 2 — in `PushDSRRsetForRollover` dispatcher, after
   `pickRolloverSchemes` returns. Pre-cleanup if chosen schemes do
   NOT include NOTIFY (i.e. UPDATE-only) AND
   `last_published_cds_index_*` is set; or if `pickRolloverSchemes`
   errored.
4. Hook trigger 3 — wherever the state machine transitions to
   terminal hardfail (rollover-overhaul defines this site;
   reuse it).
5. Build.

### Phase 6 — child-config subcategorization + softfail cap

1. Split `KSKDSPushResult.Category` "child-config" into two values:
   `child-config:waiting-for-parent` and `child-config:local-error`.
   `pickRolloverSchemes` errors map to the first; all other
   child-config sources map to the second.
2. In the tick handler's softfail path, gate `hardfail_count++`
   and the existing softfail-delay calculation on the subcategory:
   - `:waiting-for-parent` → cap backoff at 1h, never increment
     `hardfail_count`. Probe forever.
   - `:local-error` → existing softfail bookkeeping unchanged.
3. Status output (Phase 7) renders the subcategory.
4. Build, unit tests asserting hardfail_count behavior across both
   subcategories.

### Phase 7 — Status struct + CLI rendering

1. Add `LastAttemptScheme` to `RolloverStatus` and populate in
   `ComputeRolloverStatus`. Comma-joined for parallel.
2. CLI status template: rename "last UPDATE" → "last push", add
   `via X` (or `via X,Y`) suffix.
3. Render `child-config:waiting-for-parent` distinctly in
   softfail status (e.g. "waiting for parent to advertise DSYNC")
   so operators don't think their rollover is broken.
4. Build.

### Phase 8 — Parent-side EDE + DSYNC scheme gate

Independent of phases 1-7; can land any time. Two things in this
phase:

**(a) DSYNC scheme gate.** Today `NotifyResponder` accepts
NOTIFY(CDS) and NOTIFY(CSYNC) regardless of whether the receiving
parent advertises NOTIFY for that RRtype. Add a gate, run after
the existing "qname is a child delegation" check:

```go
// In NotifyResponder, CDS/CSYNC branch, after IsChildDelegation:
if !zd.advertisesDsyncNotify(ntype) {
    m.SetRcode(dnr.Msg, dns.RcodeRefused)
    edns0.AttachEDEToResponse(m, edns0.EDENotifyDsyncSchemeNotAdvertised,
        fmt.Sprintf("parent zone %s does not advertise NOTIFY for type %s; ignoring",
            targetZoneName, dns.TypeToString[ntype]))
    dnr.ResponseWriter.WriteMsg(m)
    return nil
}
```

`advertisesDsyncNotify(qtype)` reads the parent zone's local DSYNC
RRset (in-memory, no DNS round-trip) via
`zd.GetOwner("_dsync." + zd.ZoneName)` — the same lookup
[ops_dsync.go:23](tdns/v2/ops_dsync.go:23) already uses. Iterates
the owner's DSYNC RRset, checks for any DSYNC RR with
`Scheme == SchemeNotify` and `Type == qtype || Type == ANY`. If
no `_dsync` owner exists at all → fail closed (EDE detail says
"no DSYNC RRset published").

This is the single most operator-actionable EDE in the set: a
child operator misconfigured to send NOTIFY against an
UPDATE-only parent gets a precise, immediate diagnostic on the
first attempt instead of waiting `attempt-timeout` for a
parent-publish-failure.

**(b) EDE attachment for synchronous NOTIFY rejections.** Mirrors
Phase 11 of rollover-overhaul, scoped to `notifyresponder.go`.

New EDE codes for NOTIFY-specific synchronous rejection reasons.
Add to [edns0/edns0_ede.go](tdns/v2/edns0/edns0_ede.go), package
`edns0`, alongside the existing `EDEZoneUpdate*` block:

- `EDENotifyDsyncSchemeNotAdvertised` — see (a) above. The most
  important one.
- `EDENotifyTargetNotChildDelegation` — qname not a child
  delegation in the receiving parent zone
  ([notifyresponder.go:149](tdns/v2/notifyresponder.go:149)).
- `EDENotifyParentNotAuthoritative` — parent zone not
  authoritative ([notifyresponder.go:142](tdns/v2/notifyresponder.go:142)).
- `EDENotifyZoneInErrorState` — target zone in error state
  ([notifyresponder.go:165](tdns/v2/notifyresponder.go:165)).
- `EDENotifyUnknownType` — unsupported NOTIFY RRtype
  ([notifyresponder.go:157](tdns/v2/notifyresponder.go:157)).

Existing `EDEZoneUpdate*` codes don't fit; these are notify-side
concerns.

Attach EDE in each rejection branch of `NotifyResponder` before
the `WriteMsg` call.

Targeted tests:
- NOTIFY(CDS) to a parent whose DSYNC advertises only
  NOTIFY(CSYNC) → REFUSED + `EDENotifyDsyncSchemeNotAdvertised`.
- NOTIFY(CDS) for a non-child-delegation qname → REFUSED +
  `EDENotifyTargetNotChildDelegation`.

This phase is parent-side only and orthogonal to the child-side
push work. It can land before phases 1-7 (improving operator
experience for any existing manual NOTIFY testing) or after.
Symmetric coverage on `NotifyResponder(SOA)` is out of scope here —
SOA NOTIFY is the secondary-zone xfr-trigger path, not delegation
sync — but the same EDE-on-rejection treatment would be cheap to
extend to it later.

Async failures inside `ProcessCDSNotify` are deliberately *not*
addressed — there is no NOTIFY ACK left to attach EDE to by the
time those run.

### Phase 9 — Tick-handler test harness

1. `rollover_tick_test.go` with the harness scaffolding.
2. Coverage matrix as described under Testing (parallel mode +
   parent-flip scenarios).
3. Build, run.

This is the largest single phase — probably one to two days on its
own. The harness has reuse value beyond NOTIFY support: every
future rollover-state-machine change benefits from it.

### Phase 10 — Docs

1. New paragraph in [2026-04-29-rollover-overhaul.md](tdns/docs/2026-04-29-rollover-overhaul.md)
   pointing at this doc as the NOTIFY-scheme follow-up.
2. Config-reference entry for `dsync-scheme-preference`.
3. **Operator note: NOTIFY async rejection asymmetry.** Document
   that on a NOTIFY-advertising parent, the most likely failure
   category for a broken push is `parent-publish-failure` even
   when the underlying cause is a CDS validation problem. To
   diagnose, consult the parent-side scanner logs.
4. Any operator runbook updates (if a runbook exists for
   `auto-rollover` — currently it does not, so this may be empty).

## Risks / open questions

1. **CDS-ownership shared with delegation-sync.** Compare-on-cleanup
   is cheap but assumes no race between push and confirm. If
   delegation-sync republishes CDS in that window, the rollover
   engine declines to clean up — safe outcome, leaves stale CDS on
   the wire until the other caller's lifecycle prunes it. Acceptable
   in practice; document it in the operator notes.

2. **NotifierEngine response plumbing — verified, small fix needed.**
   `NotifyRequest.Response` (notifier.go:20) and `NotifyResponse`
   (notifier.go:23) are wired: `Notifier` writes back when the
   channel is non-nil (notifier.go:52-58). However, the response is
   currently a hardcoded `{Msg: "OK", Rcode: dns.RcodeSuccess,
   Error: false}` — `Notifier` discards both return values from
   `zd.SendNotify(...)` at notifier.go:50. Phase 4 prerequisite is
   a one-line fix: `rcode, err := zd.SendNotify(...)` and propagate
   into `NotifyResponse`. Existing caller `SyncZoneDelegationViaNotify`
   (delegation_sync.go:534-552) does not allocate Response, so this
   change is backward-compatible (existing callers stay no-op-on-Response).

3. **SendNotify multi-target aggregation — any-success-wins (kept).**
   `SendNotify` (notifier.go:64-132) iterates over `targets` and
   returns success if any target replied NOERROR (notifier.go:127).
   Kept as-is for rollover-NOTIFY: a parent operator publishing
   multiple NOTIFY listeners (typically one A + one AAAA on the
   same host, or two anycast endpoints) is asserting "any of these
   will pick up the signal." Once one acknowledges, downstream
   propagation is the parent's responsibility. The rollback
   transactional model (item 4 below) means a partial parent
   failure that we don't see here surfaces later as
   `parent-publish-failure` from the observe phase, which is the
   correct category.

   EDE on the parent's response is currently discarded; the
   rollover engine's `parent-rejected` category benefits
   significantly from EDE pass-through, so `NotifyResponse` grows
   an `EDE []dns.EDNS0_EDE` field as part of the Phase 4
   prerequisite fix (typed, not flat string — Phase 7 emits
   programmatically-meaningful codes that the child should be
   able to switch on).

4. **Sign-failure handling — transactional rollback.**
   Treat `(publish CDS, sign CDS RRset, re-sign apex NSEC)` as a
   single transaction. NOTIFY(CDS) is only sent after the
   transaction commits successfully. If any step inside the
   transaction fails, roll the publish back: queue an anti-CDS
   ClassANY delete to restore the zone to pre-push state, do not
   send NOTIFY, categorize as `child-config:local-error`. The rollover engine
   never leaves an unsigned CDS at the apex; if the transaction
   cannot complete cleanly, the zone is restored to its pre-push
   shape and the next tick retries from scratch.

   Implementation note: the rollback delete itself is a zone
   change requiring sign + NSEC re-sign. If signing infra is
   broken hard enough that the rollback delete also fails, that
   is a separate alarm — operator intervention required, log
   ERROR. The rollover engine's responsibility ends at "best-effort
   queue the rollback"; if signing is fully unavailable, leaving
   an unsigned anti-delete in the queue is the correct outcome
   (the zone serving infra surfaces the issue).

5. **`force-notify` against an UPDATE-only parent.** Right behavior
   is `child-config:waiting-for-parent` (operator pinned a scheme
   the parent doesn't currently advertise). Indefinite softfail
   with 1h cap; recovers automatically when parent starts
   advertising NOTIFY. Don't fall back to UPDATE — `force` is
   `force`. Operators using `force-*` are explicitly opting out of
   automatic-fallthrough behavior.

6. **Operator changes preference mid-rollover.** Policy reload
   swaps `auto` → `force-notify` while a UPDATE-pushed rollover is
   observing. Observe is scheme-agnostic; it continues. Next push
   (softfail probe) uses the new scheme. No special handling
   needed.

7. **CDS TTL.** `ops_cds.go` hardcodes 120s. The rollover engine's
   target DS TTL is 3600s (also hardcoded in
   `ComputeTargetDSSetForZone`). Both are kept as-is and they are
   not coupled: CDS is a *signal* the child publishes briefly so
   the parent picks it up, then unpublishes (per RFC 7344 §4.1).
   DS is the actual delegation record published at the parent for
   the lifetime of the rolled key. A short CDS TTL helps the
   cleanup unpublish propagate quickly through resolver caches; a
   longer DS TTL is normal delegation behavior. Aligning the two
   would be a category mistake.

8. **NOTIFY observability lag.** UPDATE NOERROR is a synchronous
   commit-at-the-wire; NOTIFY NOERROR is a "I'll fetch CDS later"
   commitment. The parent's CDS-fetch + DS-publish pipeline is the
   `ds-publish-delay` we already model. Operators with slow-fetch
   parents will need a higher `ds-publish-delay` for NOTIFY than
   for UPDATE on the same parent; document this. Don't try to
   auto-distinguish.

## Estimated effort

Single developer, careful incremental commits:

- Phase 1 (refactor + extraction): one to one-and-a-half days
- Phase 1a (tdns-mp KeyStateWorker wiring): half a day
- Phase 2 (schema): one to two hours
- Phase 3 (policy + pickRolloverSchemes): half a day
- Phase 4 (NOTIFY push path + parallel dispatch): one to one-and-a-half days
- Phase 5 (CDS cleanup with three triggers): half a day
- Phase 6 (subcategorize + softfail cap): half a day
- Phase 7 (status + CLI): one to two hours
- Phase 8 (parent-side NOTIFY EDE + DSYNC gate): half to one day, parallelizable
- Phase 9 (test harness with parallel scheme cases): two days
- Phase 10 (docs): one to two hours

Total: roughly 6-8 days. Phase 9 dominates if done properly. Core
child-side (phases 1-7) lands in four to five days; phase 1a runs
in parallel; phase 8 (parent-side) is parallelizable; phase 9 is
the long tail and is independently shippable.
Core feature (phases 1-6 child-side + phase 7 parent-side EDE) lands
in three to four days; phase 8 is the long tail and is
independently shippable.
