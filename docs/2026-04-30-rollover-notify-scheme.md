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
2. UPDATE remains the default scheme on parents that advertise both.
   Existing UPDATE-only testbeds behave identically.
3. Operator can pin scheme via a per-policy knob:
   `auto` (default), `prefer-update`, `prefer-notify`, `force-update`,
   `force-notify`.
4. The four-category failure model carries over unchanged in shape.
   Trigger conditions extend cleanly into the NOTIFY path.
5. CDS records the rollover engine publishes are removed from the
   child zone after the parent confirms DS, without disturbing CDS
   records that some other caller (general delegation-sync) owns.
6. Status output identifies which scheme each attempt used.
7. Test harness covers both schemes — the right time to build the
   tick-handler harness is when adding a second push path makes
   the abstraction earn its keep.
8. Parent-side EDE attachment for synchronous NOTIFY rejections,
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
  Default scheme preference is `auto` ≡ prefer-UPDATE so that an
  UPDATE-only parent is selected unchanged.
- **No backwards compat in code.** The codebase rule applies: no
  dual-format parsing, no legacy fallbacks. The new policy field
  defaults to `auto`; old configs without the field get the safe
  default.
- **Reuse, don't fork.** Reuse `Imr.DsyncDiscovery`,
  `NotifierEngine`, the internal-update queue, `SignRRset`, and the
  KSK-row query that `ComputeTargetDSSetForZone` already runs.
- **Stay separate from `SyncZoneDelegation`.** Argued below under
  "Reuse vs separate."

## Design

### Discovery and scheme selection

Per-attempt DSYNC lookup. No policy-time caching. DSYNC is already
fetched per attempt today (the hardcoded `LookupDSYNCTarget` call
inside `PushWholeDSRRset`); cost stays the same. IMR caches DSYNC
results per its normal cache rules, so the apparent per-attempt
fetch is a cache hit at steady state.

New helper `pickRolloverScheme`, signature roughly:

```go
func pickRolloverScheme(
    ctx context.Context,
    zd *ZoneData,
    imr *Imr,
    pol *DnssecPolicy,
) (scheme string, target *DsyncTarget, err error)
```

Logic:

1. `imr.DsyncDiscovery(ctx, zd.ZoneName, ...)` — fetches all DSYNC
   RRs at the parent.
2. Categorize advertised schemes: any UPDATE RR (matches all
   RRtypes) and any NOTIFY RR with `Type == TypeCDS || TypeANY`.
3. Apply `pol.Rollover.DsyncSchemePreference`:
   - `auto` / `prefer-update`: pick UPDATE if advertised; else
     NOTIFY; else error.
   - `prefer-notify`: pick NOTIFY if advertised; else UPDATE; else
     error.
   - `force-update`: pick UPDATE if advertised; else error.
   - `force-notify`: pick NOTIFY if advertised; else error.
4. Resolve the chosen DSYNC RR's Target/Port to a `DsyncTarget`
   (same `net.LookupHost` step as `BestSyncScheme`).
5. Failure mode "no usable scheme": child-config category. Operator
   has either misconfigured the policy (e.g. force-notify on an
   UPDATE-only parent) or the parent has regressed.

This intentionally diverges from `BestSyncScheme`:

- `BestSyncScheme` reads `delegationsync.child.schemes` from viper
  (a process-wide list). The rollover engine has a per-policy knob.
- `BestSyncScheme` filters NOTIFY by RRtype CSYNC or ANY. The
  rollover engine filters by RRtype CDS or ANY. A parent can
  legitimately advertise different schemes for CSYNC vs CDS.
- `BestSyncScheme` returns on first match in operator-listed order.
  The rollover engine needs explicit prefer/force semantics.

Two callers, two filter rules, two enum models. Don't unify.

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
3. **Publish CDS in the child apex** via the internal-update queue.
   Anti-CDS ClassANY delete + ClassINET adds. Same shape as
   `PublishCdsRRs` but parameterized on the engine-computed set
   instead of synthesizing from in-zone DNSKEYs. Failure → child-config.
4. **Sign** if `OptOnlineSigning || OptInlineSigning`. Same code
   path as `SyncZoneDelegationViaNotify`. Failure → child-config.
5. **Persist `last_published_cds_index_low/high`** on
   RolloverZoneState. These are the rollover engine's claim of
   ownership over the current CDS RRset for cleanup-time comparison.
6. **Send NOTIFY(CDS)** via NotifierEngine. Use the `Response`
   channel on `NotifyRequest` (already in the struct, currently
   unused in this caller) so we get a synchronous rcode/error pair
   back. Bound the wait by a context timeout (~30s, same shape as
   the current 45s SendUpdate timeout).
7. **Categorize NOTIFY response:**
   - transport error → transport
   - rcode REFUSED/SERVFAIL/FORMERR/NOTAUTH → parent-rejected
   - rcode NOERROR → success
8. **On NOERROR**, persist `last_ds_submitted_index_low/high` and
   `last_attempt_scheme = "NOTIFY"`. Same downstream flow as the
   UPDATE path.

The NOTIFY ACK is the same wire-protocol commitment as UPDATE
NOERROR: "I will publish what you advertised." If the parent
publishes neither REFUSED nor the expected DS within the attempt
budget, that's `parent-publish-failure`, identical to the UPDATE
path.

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

Picks the scheme via `pickRolloverScheme`, dispatches, returns the
per-scheme result. Both call sites in `RolloverAutomatedTick`
([line 202](tdns/v2/ksk_rollover_automated.go:202) and
[line 397](tdns/v2/ksk_rollover_automated.go:397)) switch over to
the dispatcher; the policy and notifyq are already in scope at both
sites.

### CDS cleanup on confirmation

RFC 7344 §4.1: child should remove CDS once the parent has updated
DS. Cleanup site: `pending-parent-observe` confirmed branch in the
tick handler.

```
on confirmed observation:
   if last_attempt_scheme == "NOTIFY":
       cleanupCdsAfterConfirm(zd, kdb)
   advance keys...
```

`cleanupCdsAfterConfirm`:

1. Read current CDS RRset from `zd` (in-memory zone, no DNS round-
   trip).
2. Compute target CDS from current keystore (post-advance state if
   the cleanup runs after key advance, or pre-advance if before —
   pick "pre-advance" so the comparison matches what we just
   pushed).
3. If current CDS == last-published-CDS (per saved
   `last_published_cds_index_low/high`) AND that matches the keys
   we pushed: queue `UnpublishCdsRRs`. Clear
   `last_published_cds_index_low/high`.
4. Otherwise: another caller has touched CDS in the meantime. Log
   INFO ("rollover: CDS owned by another caller, leaving in
   place"), clear our index range so we don't try again next
   cycle, leave CDS on the wire.

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

Same four categories. Trigger conditions:

| Category | UPDATE-side trigger (existing) | NOTIFY-side trigger (new) |
|----------|--------------------------------|---------------------------|
| `child-config` | no SIG(0); no DS to publish; ParentZone unresolvable; SignMsg failed | + `pickRolloverScheme` returned no usable scheme; + CDS publish to internal-update queue failed; + CDS sign failed; + `force-update`/`force-notify` not advertised |
| `transport` | i/o timeout; conn refused; no route; DSYNC empty | + NOTIFY transport failure (timeouts to NotifierEngine target) |
| `parent-rejected` | rcode REFUSED/NOTAUTH/FORMERR/SERVFAIL on UPDATE | + same on NOTIFY ACK *(synchronous rejections only — see asymmetry note)* |
| `parent-publish-failure` | NOERROR + DS never appears within attempt-timeout | unchanged in shape; will fire more often on NOTIFY pushes (async rejection inside ProcessCDSNotify shows up here) |

The `KSKDSPushResult.Category` field is set by each scheme's
implementation; the dispatcher does not transform it. The tick
handler's softfail-bookkeeping path stays identical.

### Schema additions

Two new columns on `RolloverZoneState`. Migration via the same
`dbMigrateSchema` mechanism rollover-overhaul Phase 2 used.

```sql
last_attempt_scheme              TEXT,        -- "UPDATE" | "NOTIFY", NULL if no attempt yet
last_published_cds_index_low     INTEGER,     -- ownership marker for CDS cleanup
last_published_cds_index_high    INTEGER,
```

`last_attempt_scheme` is **diagnostic only** — the engine never
decides anything from this column; status output reads it for
display. The current scheme is re-derived per attempt from DSYNC.

`last_published_cds_index_low/high` is engine-functional: it gates
CDS cleanup ownership. NULL means "we have no CDS published" (or
"some other caller owns whatever CDS is currently published").

`RolloverZoneRow`, `LoadRolloverZoneRow`, the canonical CREATE
TABLE in `db_schema.go`, and accessors all extend by three fields.

### RolloverStatus / status output

Add to `RolloverStatus` ([messages_rollover.go](tdns/v2/messages_rollover.go)):

```go
LastAttemptScheme string `json:"lastAttemptScheme,omitempty"` // "UPDATE" | "NOTIFY"
```

Status-output rendering: rename "last UPDATE" → "last push" (the
old wording was scheme-baked) and append a `via …` qualifier:

```
last push          14:30:00 UTC (5m23s ago) via NOTIFY(CDS)
```

In the ACTIVE and SOFTFAIL templates from the rollover-overhaul doc,
the line replaces the existing `last UPDATE` line one-for-one. No
new line; just renamed and qualified.

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

| Value | Meaning |
|-------|---------|
| `auto` (default) | Prefer UPDATE; fall through to NOTIFY |
| `prefer-update` | Synonym for auto (explicit form) |
| `prefer-notify` | Prefer NOTIFY; fall through to UPDATE |
| `force-update` | Use UPDATE only; child-config error if not advertised |
| `force-notify` | Use NOTIFY only; child-config error if not advertised |

Unknown values: parse error in `FinishDnssecPolicy`. Cross-field
validation: nothing required — the four categories cover all
combinations.

`force-*` is for testbeds and adversarial-testing scenarios. In
production, `auto` is the correct default for almost every operator.

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

Coverage matrix (~12-16 cases):

- Per phase: idle, pending-child-publish, pending-parent-push,
  pending-parent-observe, parent-push-softfail,
  pending-child-withdraw.
- Per scheme: UPDATE, NOTIFY.
- Per failure category at the push site: success, child-config,
  transport, parent-rejected, parent-publish-failure (latter is
  observe-phase, scheme-agnostic).

Unit tests assert post-tick state: `RolloverPhase`,
`hardfail_count`, `last_softfail_*`, `last_attempt_scheme`,
`last_published_cds_index_*`, and the contents of
`notifyq`/`updateq` (e.g. that a NOTIFY-path tick produced a
NotifyRequest with `RRtype == TypeCDS` and a ZONE-UPDATE on the
internal queue with the expected anti-CDS + adds).

`PushDSRRsetForRollover` is injected so tests don't make actual DNS
queries. `pickRolloverScheme` is exercised directly in its own unit
tests (table-driven over advertised-schemes × policy-preference).

### Logging

Existing rollover log lines gain a `scheme=UPDATE|NOTIFY` field:

```
WARN  rollover: parent push failed scheme=NOTIFY zone=cpt.p.axfr.net.
      attempt=2/5 category=parent-rejected detail="rcode=REFUSED EDE=18 'prohibited'"
```

No new metrics labels — `tdns_rollover_softfail_zones_total{category=…}` already
covers the relevant axes. Adding `scheme=…` would explode cardinality on
zones with no NOTIFY-capable parents.

## Implementation phases

Each phase = one or two commits on a branch off `rollover-overhaul`
(once that lands). Order is sequential except phase 7 (test
harness) which can land late.

| Phase | Title | Notes |
|-------|-------|-------|
| 1 | Refactor: extract loadTargetKSKsForRollover; rename PushWholeDSRRset → pushDSRRsetViaUpdate; introduce dispatcher PushDSRRsetForRollover | No behavior change |
| 2 | Schema additions + RolloverZoneRow extensions | last_attempt_scheme, last_published_cds_index_* |
| 3 | Policy knob (`dsync-scheme-preference`) + pickRolloverScheme + tests | Default `auto` |
| 4 | pushDSRRsetViaNotify + ComputeTargetCDSSetForZone | Wires into dispatcher |
| 5 | CDS cleanup on confirmation | `cleanupCdsAfterConfirm` in observe path |
| 6 | RolloverStatus.LastAttemptScheme + CLI rendering | Rename "last UPDATE" → "last push" |
| 7 | Parent-side: DSYNC scheme gate + EDE on synchronous NOTIFY rejection | Mirror Phase 11 of rollover-overhaul + new "scheme not advertised" gate; can land in parallel with phases 1-6 |
| 8 | Tick-handler test harness with both schemes | The largest phase |
| 9 | Docs + ops runbook update | Cross-reference 2026-04-29-rollover-overhaul.md |

### Phase 1 — Refactor (no behavior change)

1. Extract `loadTargetKSKsForRollover(kdb *KeyDB, zone string) (rows []kskForDSRow, indexLow, indexHigh int, indexRangeKnown bool, err error)`.
2. Rewrite `ComputeTargetDSSetForZone` as a thin wrapper that calls
   the helper and converts to DS.
3. Rename `PushWholeDSRRset` → `pushDSRRsetViaUpdate` (lower-case).
4. Introduce `PushDSRRsetForRollover` dispatcher; delegate to
   `pushDSRRsetViaUpdate` only (no NOTIFY yet). Both call sites in
   the tick switch over.
5. Build, run existing tests.

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
3. Implement `pickRolloverScheme`.
4. Unit tests: table-driven over (advertised UPDATE? + advertised
   NOTIFY?) × (auto, prefer-update, prefer-notify, force-update,
   force-notify) → 4 × 5 = 20 cells. Many collapse but worth
   exhaustive coverage.
5. Build.

### Phase 4 — NOTIFY push path

1. `ComputeTargetCDSSetForZone` (wraps `loadTargetKSKsForRollover`).
2. `pushDSRRsetViaNotify` — publish CDS via internal-update queue,
   sign, queue NOTIFY(CDS) with a Response channel, await ack/error,
   categorize.
3. Optional helper `signAndQueueCdsNotify` if duplication with
   `SyncZoneDelegationViaNotify` earns it.
4. Wire into dispatcher.
5. Persist `last_attempt_scheme`, `last_published_cds_index_*` on
   success.
6. Build.

### Phase 5 — CDS cleanup

1. `cleanupCdsAfterConfirm(zd, kdb)` — compare-on-cleanup logic.
2. Hook into `pending-parent-observe` confirmed branch.
3. Build.

### Phase 6 — Status struct + CLI rendering

1. Add `LastAttemptScheme` to `RolloverStatus` and populate in
   `ComputeRolloverStatus`.
2. CLI status template: rename "last UPDATE" → "last push", add
   `via X` suffix.
3. Build.

### Phase 7 — Parent-side EDE + DSYNC scheme gate

Independent of phases 1-6; can land any time. Two things in this
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
RRset (in-memory, no DNS round-trip), checks for any DSYNC RR with
`Scheme == SchemeNotify` and `Type == qtype || Type == ANY`. If
no DSYNC RRset published at all → fail closed (EDE detail says
"no DSYNC RRset published").

This is the single most operator-actionable EDE in the set: a
child operator misconfigured to send NOTIFY against an
UPDATE-only parent gets a precise, immediate diagnostic on the
first attempt instead of waiting `attempt-timeout` for a
parent-publish-failure.

**(b) EDE attachment for synchronous NOTIFY rejections.** Mirrors
Phase 11 of rollover-overhaul, scoped to `notifyresponder.go`.

New EDE codes for NOTIFY-specific synchronous rejection reasons:

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

Existing `EDEZoneUpdates*` codes don't fit; these are notify-side
concerns.

Attach EDE in each rejection branch of `NotifyResponder` before
the `WriteMsg` call.

Targeted tests:
- NOTIFY(CDS) to a parent whose DSYNC advertises only
  NOTIFY(CSYNC) → REFUSED + `EDENotifyDsyncSchemeNotAdvertised`.
- NOTIFY(CDS) for a non-child-delegation qname → REFUSED +
  `EDENotifyTargetNotChildDelegation`.

This phase is parent-side only and orthogonal to the child-side
push work. It can land before phases 1-6 (improving operator
experience for any existing manual NOTIFY testing) or after.
Symmetric coverage on `NotifyResponder(SOA)` is out of scope here —
SOA NOTIFY is the secondary-zone xfr-trigger path, not delegation
sync — but the same EDE-on-rejection treatment would be cheap to
extend to it later.

Async failures inside `ProcessCDSNotify` are deliberately *not*
addressed — there is no NOTIFY ACK left to attach EDE to by the
time those run.

### Phase 8 — Tick-handler test harness

1. `rollover_tick_test.go` with the harness scaffolding.
2. Coverage matrix as described under Testing.
3. Build, run.

This is the largest single phase — probably one to two days on its
own. The harness has reuse value beyond NOTIFY support: every
future rollover-state-machine change benefits from it.

### Phase 9 — Docs

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

2. **NOTIFY response handling in NotifierEngine.** Currently
   `NotifyRequest.Response` is in the struct but neither
   `SyncZoneDelegationViaNotify` nor any other caller waits on it.
   Need to verify that `NotifierEngine` actually populates the
   Response channel with rcode + transport status, and that the
   response carries enough information to categorize. Worst case:
   a small fix to `notifier.go` to unconditionally write Response
   when the channel is non-nil. Trivial.

3. **Sign-failure ambiguity.** If CDS publish succeeds but signing
   fails, we have an unsigned CDS sitting at the apex. Today
   `SyncZoneDelegationViaNotify` logs and proceeds with NOTIFY
   anyway. The rollover engine should be stricter: sign failure →
   child-config, abort the NOTIFY, leave CDS published (next
   tick's signing pass picks it up if the signing infra recovers).
   Document this divergence from the delegation-sync path; both
   choices are defensible.

4. **`force-notify` against an UPDATE-only parent.** Right behavior
   is child-config (operator pinned a scheme the parent doesn't
   support). Loud and immediate. Don't fall back.

5. **Operator changes preference mid-rollover.** Policy reload
   swaps `auto` → `force-notify` while a UPDATE-pushed rollover is
   observing. Observe is scheme-agnostic; it continues. Next push
   (softfail probe) uses the new scheme. No special handling
   needed.

6. **CDS TTL.** `ops_cds.go` hardcodes 120s. The rollover engine's
   target DS TTL is 3600s (also hardcoded in
   `ComputeTargetDSSetForZone`). These are independent — CDS lives
   in the child zone briefly, DS lives in the parent for the
   rollover lifetime. Keep both as is.

7. **NOTIFY observability lag.** UPDATE NOERROR is a synchronous
   commit-at-the-wire; NOTIFY NOERROR is a "I'll fetch CDS later"
   commitment. The parent's CDS-fetch + DS-publish pipeline is the
   `ds-publish-delay` we already model. Operators with slow-fetch
   parents will need a higher `ds-publish-delay` for NOTIFY than
   for UPDATE on the same parent; document this. Don't try to
   auto-distinguish.

## Estimated effort

Single developer, careful incremental commits:

- Phase 1 (refactor): half a day
- Phase 2 (schema): one to two hours
- Phase 3 (policy + scheme selection): half a day
- Phase 4 (NOTIFY push path): one day
- Phase 5 (CDS cleanup): half a day
- Phase 6 (status + CLI): one to two hours
- Phase 7 (parent-side NOTIFY EDE + DSYNC gate): half to one day, parallelizable
- Phase 8 (test harness): one to two days
- Phase 9 (docs): one to two hours

Total: roughly 4-6 days. Phase 8 dominates if done properly.
Core feature (phases 1-6 child-side + phase 7 parent-side EDE) lands
in three to four days; phase 8 is the long tail and is
independently shippable.
