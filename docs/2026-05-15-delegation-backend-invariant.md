# Delegation Backend Required for Child Updates

**Date:** 2026-05-15
**Status:** Implemented (branch `delegation-backend-invariant`)

## Background: the bug

A parent zone running tdns-authv2 was observed to accumulate
DS records for one child indefinitely — 247 DS RRs for a
single child after two days of automated KSK rollover
testing.

Investigation showed two unrelated problems, only one of
which is a code bug:

1. **Operator mistake (not in scope here)**: the parent's
   binary lacked ML-DSA-44 algorithm support; the child's
   SIG(0)-signed DDNS UPDATEs were rejected with
   `dns: bad algorithm` at the SIG(0) validation step.
   The DEL-old-DS + ADD-new-DS update never landed.

2. **The bug**: the parallel CDS-NOTIFY path continued to
   work and continued to push DS records into the parent's
   zone, but always reported `N adds, 0 removes` from the
   scanner's diff. After every rollover, the parent
   accumulated more DS records without ever removing the
   stale ones.

## Root cause: asymmetric read and write paths

The parent zone (`p.axfr.net`) was configured with
`allow-child-updates: true` but no `delegation-backend:`.
That made the write path and the read path disagree on
where "current child delegation data" lives:

- **Write path**:
  `ZoneUpdater` for `CHILD-UPDATE` fell through to the
  legacy `ApplyChildUpdateToZoneData`, which mutated the
  in-memory zone tree directly (no
  `ChildDelegationData` DB rows, no zonefile fragment).
- **Read path** (scanner, building "current DS" for the
  diff): guarded by `if zd.DelegationBackend != nil`.
  With no backend configured the block was skipped, the
  "current DS" set stayed empty, and `RRsetDiffer(new, [])`
  always returned `len(new) adds, 0 removes`.

Every CDS NOTIFY → scanner → CHILD-UPDATE cycle therefore
added the child's full CDS-derived DS set to the parent
zone again. The in-memory zone deduplicated identical RRs
but every unique DS the child had ever published accumulated.

## The invariant

> **A zone that accepts child updates must have a
> delegation backend.**

Enforced at config-parse time. Choices:

- `direct` — mutates the in-memory zone tree and persists
  to the source zonefile after each apply. This is the
  back-compat option for primary zones loaded from a file.
- `db` — writes to the `ChildDelegationData` SQLite table.
  The in-memory zone is **not** updated, so AXFR will not
  reflect child updates until a reload.
- `zonefile` — DB + on-disk zone file fragment. Same
  in-memory caveat as `db`.
- A named custom backend from the `delegation-backends:`
  config block.

There is no silent default. A zone with
`allow-child-updates: true` and no `delegation-backend:`
is marked broken at parse time with:

```
zone has 'allow-child-updates' but no 'delegation-backend' configured, zone in error state
```

## Code changes

### `parseconfig.go`

1. New cross-field validation after the child-update-policy
   switch: if `OptAllowChildUpdates` is set and
   `zconf.DelegationBackend` is empty, mark the zone broken
   and skip it.

2. Backend wiring moved **out** of the `if zdp.FirstZoneLoad`
   block. The backend is now resolved and assigned to
   `zd.DelegationBackend` synchronously on every parse
   pass — both initial load and reload (SIGHUP / `config
   reload-zones`). Backend constructors don't touch zone
   data, so this is safe before `FirstZoneLoad` has
   completed.

3. The `OptDelSyncParent &&` gate is dropped — a zone that
   accepts child updates needs a backend regardless of
   whether it advertises itself as a delegation-sync
   parent.

4. Signing setup and delegation-sync setup conditions are
   also lifted out of the `if zdp.FirstZoneLoad` block, so
   their option checks are re-evaluated on every reload.
   On first load they still register `OnFirstLoad`
   callbacks; on reload they call the (idempotent) setup
   functions directly. Rollover-policy setup is left
   first-load-only because `ObserveParentDSTTL` spawns a
   long-running goroutine and re-spawning on reload would
   leak; a follow-up should make that reload-safe.

### `zone_updater.go`

The fallback path in the `CHILD-UPDATE` handler is gone.
If a CHILD-UPDATE arrives for a zone with
`OptAllowChildUpdates=false` it is dropped with a WARN; if
`DelegationBackend` is nil despite the option being set
(should be impossible after config validation) it is
dropped with an ERROR (`invariant violation`).

`OptDirty` management is now the backend's responsibility.
`direct` sets and clears it as it persists; `db` and
`zonefile` leave it alone because they don't touch
in-memory zone data.

### `scanner.go`

Both `ProcessCDSNotify` (DS diff synthesis) and
`ProcessCSYNCNotify` (NS/glue) now log loudly when a
parent zone with `OptAllowChildUpdates` lacks a
DelegationBackend, rather than silently producing
"empty current state". `ProcessCSYNCNotify` refuses to
continue in that case (returns an error). This is
defensive — config validation should make the situation
impossible — but it ensures a future regression of the
same class surfaces in the log on first NOTIFY rather
than after days of silent accumulation.

### `delegation_backend_direct.go`

`DirectDelegationBackend.ApplyChildUpdate` now persists
to the source zonefile via `zd.WriteZone(true, false)`
after a successful in-memory mutation. Without
persistence, every CHILD-UPDATE mutates RAM only, is
lost on restart, and the scanner re-discovers the
"missing" delegation on first NOTIFY — reaccumulating
from scratch.

If the zone has no source zonefile (in-memory-only),
persistence is skipped with a debug log. If the file
write fails, the in-memory state is kept and the error
is logged as a WARN; the update is not failed (next
successful update or explicit zone-write will catch up).

## Operator impact

Any existing config with `allow-child-updates: true` and
no `delegation-backend:` will now refuse to load the zone.
Operators must explicitly choose a backend:

```yaml
zones:
   p.axfr.net.:
      type: primary
      zonefile: /etc/tdns/zones/p.axfr.net
      options: [allow-child-updates, delegation-sync-parent]
      delegation-backend: direct   # <-- now required
```

`direct` preserves the prior in-memory behavior and adds
zonefile persistence on each apply.

## Recovery: cleaning the stale accumulation

Once the fix is deployed and the affected parent zone is
restarted with `delegation-backend: direct`, the next CDS
scan will compute its diff against the real current DS
set in the in-memory zone. For a zone that has
accumulated `N` stale DS RRs while only `K` are valid in
the child's current CDS, the scanner will report
`0 adds, N-K removes` and `ApplyChildUpdateToZoneData`
will delete the stale records in one pass — automatically.

## Follow-ups (not in this change)

- Make rollover-policy setup (`EvaluateRolloverPolicyInvariants`
  + `ObserveParentDSTTL`) reload-safe so its condition
  check can also leave the `FirstZoneLoad` gate.
- Decide whether `db` and `zonefile` backends should
  also update the in-memory zone tree (currently they
  don't, which means AXFR is stale until reload).
- Consider whether all `*OnFirstLoad` setup functions
  should be runnable on reload, with explicit
  idempotency guarantees, as the general policy.
