# Automated ZSK rollover

**Date:** 2026-05-21
**Author:** Johan Stenstam
**Status:** Implemented (2026-05-22)
**Depends on:** `2026-05-21-configurable-rrsig-validity-plan.md`
(configurable, adhered-to RRSIG validity + floor invariant; supplies the
"signatures outlive the served TTL" guarantee S4 relies on).
**Related design docs:**
 - `2026-04-23-automated-ksk-rollover.md` (the KSK engine this builds beside)
 - `2026-04-29-rollover-overhaul.md` (states KSK rollover scope; ZSK
   "informational only / out of scope" — this doc closes that gap)
 - `2026-03-04-signer-key-rollover.md` (the generic key-state machine)
 - `2026-05-02-rollover-timing-report.md` (RRSIG-validity / TTL timing)

> **Implementer notes.** (1) `file:line` refs are a 2026-05-21 snapshot
> — locate code by the named *symbol*, not the line number; **plan #1
> (configurable RRSIG validity) lands first and will have shifted the
> line numbers cited here** (e.g. in `sign.go`, `key_state_worker.go`).
> (2) Strict order: **#1 → #2 this plan → #3**; do not start this plan
> until #1 has landed (S4 depends on #1's floor).

## Purpose

Automate zone-signing-key (ZSK) rollover. Today ZSKs never roll on
their own: the standby ZSK is generated and pre-published, but nothing
detects ZSK age or activates the successor. An operator must run
`keystore dnssec rollover --keytype ZSK` by hand.

ZSK rollover is a **local pre-publish roll** — no parent, no DS, no
DSYNC/CDS, no multi-DS pipeline, no parent-observe/softfail machinery.
It is therefore far simpler than KSK rollover, and most of the
mechanics already exist (see {{exists}}). This plan adds the missing
automation, timing safety, and live config.

## Key finding: the pre-publish mechanics already exist {#exists}

The served apex DNSKEY RRset is built from `published ∪ standby ∪
retired ∪ active` (`FetchZoneDnskeysSql`, `tdns/v2/ops_dnskey.go:23`,
plus the active set added in `PublishDnskeyRRs`). Consequences:

 - A **standby** ZSK is already present in the published DNSKEY RRset —
   it is pre-published, just not signing. Activation is therefore safe
   immediately: resolvers already have the key.
 - A **retired** ZSK stays in the DNSKEY RRset until it is removed, so
   resolvers can still validate old cached RRSIGs made by it during the
   removal window.

That is exactly the DNSKEY-visibility invariant a pre-publish ZSK roll
needs — for free. A correct roll is then just: activate a (already
pre-published) standby ZSK, re-sign, keep the retired ZSK until its
RRSIGs age out of caches, then remove it. Every mechanical step exists;
what is missing is the orchestration and the removal timing.

## Architecture decision: reuse the existing KeyStateWorker

ZSK rollover runs as a **new step inside the existing
`KeyStateWorker` tick**, not as a separate goroutine.

`KeyStateWorker` is already not KSK-only. Each tick,
`checkAndTransitionKeys` (`tdns/v2/key_state_worker.go:110`) runs the
KSK engine (`rolloverAutomatedForAllZones`) alongside the generic /
ZSK-relevant steps: `transitionPublishedToStandby`,
`transitionRetiredToRemoved`, and `maintainStandbyKeys` (which already
generates standby ZSKs). The KSK rollover engine is itself just one
call in that sequence.

Reasons to extend it rather than fork a worker:

 - **Single writer on shared rows.** KSK and ZSK steps mutate the same
   `DnssecKeyStore` rows for the same zone. One goroutine with a
   deterministic step order avoids two tickers racing.
 - **Ordering is load-bearing.** The ZSK roll must run after
   `published→standby` (a ready standby must exist) and is cleaned up
   by `retired→removed` on a later tick. A single tick gives that
   ordering for free.
 - **Lock reuse.** The per-zone rollover lock that serialises the KSK
   engine against API mutators is reused by the ZSK step.
 - **Cadence.** The 1-minute `check_interval` over-samples ZSK
   lifetimes (hours+); no dedicated ticker is warranted.
 - **Less machinery.** No second goroutine lifecycle, config interval,
   or duplicated zone iteration.

Separation of concerns is preserved at the code level: the new logic
lives in its own file/function `rolloverZsksForAllZones`, mirroring
`rolloverAutomatedForAllZones`, so the module boundary stays clean and
extractable later.

## Goals / non-goals

Goals:
 - Age-based automatic ZSK rollover driven by `ZSK.Lifetime`.
 - Make ZSK policy config live (it is currently dead).
 - Safe, TTL-aware removal of the retired ZSK.
 - Make RRSIG validity honour policy `SigValidity` (prerequisite; also
   fixes a latent KSK inconsistency).
 - Status/observability for ZSK rollover.

Non-goals:
 - Any parent coordination (ZSKs have none).
 - Generalising the KSK rollover FSM. Its complexity is ~all parent
   coordination; ZSK reuses only the small generic pieces.
 - Multi-provider (`tdns-mp`) ZSK rollover — `tdns-mp` has its own
   `key_state_worker`; a follow-up mirrors this there.
 - `csk` mode — a CSK is a single key rolled as a KSK; "ZSK rollover"
   does not apply. ZSK auto-roll only fires in `ksk-zsk` mode with a
   real ZSK (flags 256).

## Current state

### What KSK rollover has (for contrast)

A parent-coordinated phase machine
(`idle → pending-child-publish → pending-parent-push →
pending-parent-observe → pending-child-withdraw`, plus
`parent-push-softfail`), driven by `RolloverAutomatedTick`
(`ksk_rollover_automated.go:67`), triggered by
`active_at + KSK.Lifetime` or manual `asap`. DS push (UPDATE/NOTIFY+
CDS), DSYNC scheme selection, parent polling, multi-DS pipeline,
K-step TTL clamp, atomic swap, retirement margin
`max(clamping.margin, max_observed_ttl)`. None of the parent machinery
applies to ZSK.

### What ZSK already has

 - Same state lineage `created → published → standby → active →
   retired → removed` (no `ds-published`).
 - `KeyStateWorker` already, for ZSK: maintains a standby ZSK (default
   count 1, `defaultStandbyZskCount`); `published→standby` after
   `propagationDelay`; `retired→removed` after `propagationDelay`;
   `triggerResign` on each transition.
 - Standby ZSK pre-published in the DNSKEY RRset ({{exists}}).
 - Signer signs with active ZSKs and auto-drops RRSIGs by keys no
   longer active (`sign.go:192-212`).
 - Activation primitive: `RolloverKey(zone, "ZSK")` does
   standby→active + active→retired in one tx
   (`keystore.go:1199`), exposed as
   `keystore dnssec rollover --keytype ZSK`.

## Gaps

Config:
 - **C1 — `ZSK.Lifetime` is dead.** Parsed but never read at runtime
   (only assigned at `ksk_rollover_policy.go:489`, `parseconfig.go:278`).
   Grep confirms zero runtime readers, vs. ~25 for `KSK.Lifetime`. This
   is the rollover *cadence* knob and is what this plan wires up.
 - **C2 — RRSIG validity is hardcoded (separate workstream).**
   `sign.go:236` uses `sigLifetime(now, 3600*24*30)` — flat 30 days for
   every RRSIG, ignoring policy. Fixing this (configurable, adhered-to
   sig-validity with a floor invariant) is its own workstream —
   `2026-05-21-configurable-rrsig-validity-plan.md` — because it equally
   affects KSK machinery (E5/E10/E11, the resigner). This ZSK plan
   **depends on** that work for safe removal timing but does not define
   it. ZSK rollover only *consumes* correct sig-validity behaviour.

Code:
 - **G1 — No age trigger.** Nothing compares an active ZSK's age to
   `ZSK.Lifetime`. There is no `active_at` for ZSKs (the KSK-only
   `RolloverKeyState` is populated only for keys with a rollover index).
 - **G2 — No auto-promotion.** `RolloverKey(ZSK)` is manual-only.
 - **G3 — Unsafe removal timing.** Generic `retired→removed` fires
   after `propagationDelay` (default 1h), not a function of RRSIG
   validity / zone max-TTL (`key_state_worker.go:207-210`). Unsafe
   whenever zone TTLs exceed 1h.
 - **G4 — No observability.** `auto-rollover status` prints "automated
   ZSK rollover not implemented".

## Design: the automated ZSK pre-publish roll

Per `ksk-zsk`-mode zone with a real ZSK and `ZSK.Lifetime > 0`, each
tick:

1. **Steady state.** One active ZSK (signs all non-DNSKEY RRsets) and
   one standby ZSK (pre-published, not signing), maintained by
   `maintainStandbyKeys`.
2. **Due check.** If `now − active_ZSK.active_at ≥ ZSK.Lifetime` and a
   standby ZSK exists, the roll is due. No extra standby-age wait: the
   `published→standby` transition already required `propagationDelay`
   of DNSKEY-RRset visibility, so any key *in* standby is already
   propagated and safe to activate. (No `zsk.standby-time` knob — ZSK
   has no parent timing to coordinate, unlike KSK.)
3. **Activate.** `RolloverKey(zone, "ZSK")`: standby→active (stamp
   `active_at`), old active→retired (stamp `retired_at`). Then
   `triggerResign` — the signer re-signs every non-DNSKEY RRset with
   the new ZSK and drops the old ZSK's RRSIGs (`sign.go:192-212`).
4. **Hold.** The retired ZSK remains in the DNSKEY RRset so resolvers
   can still validate old RRSIGs cached before the re-sign propagated.
5. **Remove.** Once `now − retired_at ≥ removalMargin` (TTL-aware,
   {{s4}}), `retired→removed`; the key leaves the DNSKEY RRset.
6. **Refill.** `maintainStandbyKeys` regenerates a fresh standby ZSK,
   restoring the steady state.

No DNSKEY publish-and-wait is needed before step 3 because the standby
was pre-published and has been visible for `propagationDelay` already.

## Implementation

### S1 — wire `ZSK.Lifetime` as the rollover cadence (C1)

 - Read `ZSK.Lifetime` in the new ZSK roll step (S3). Semantics mirror
   `KSK.Lifetime`: `0` / `forever` = never roll.
 - No new ZSK policy block is needed — pre-publish is the only ZSK
   method, timed off `ZSK.Lifetime`, `propagationDelay`, and the
   TTL-aware removal margin (S4). (See open question on a separate ZSK
   standby pause.)
 - RRSIG validity is **out of scope here** (C2) — handled by
   `2026-05-21-configurable-rrsig-validity-plan.md`. The signer's RRSIG
   validity behaviour is a dependency, not a deliverable of this plan.

### S2 — track ZSK `active_at` (G1)

Add an `active_at` column to `DnssecKeyStore` (it already has
`published_at` / `retired_at`; `db_schema.go`). Stamp it on activation
in:
 - `RolloverKey` (`keystore.go:1267-1269`, the standby→active UPDATE),
 - `EnsureActiveDnssecKeys` bootstrap activation (`sign.go`), and
 - any other standby→active path.

ZSK-due = `now − active_at ≥ ZSK.Lifetime`. Rationale for a new column
rather than reusing `RolloverKeyState.active_at`: that table is
KSK-rollover bookkeeping (keyed by rollover index); `DnssecKeyStore` is
the natural home for a per-key activation timestamp and keeps ZSK
independent of the KSK engine.

### S3 — `rolloverZsksForAllZones` step (G2)

New function in a new file `zsk_rollover.go` (mirrors
`rolloverAutomatedForAllZones`), invoked from `checkAndTransitionKeys`
(`key_state_worker.go:110`). Placement: after
`transitionPublishedToStandby` (a ready standby must exist) and before
`transitionRetiredToRemoved` / `maintainStandbyKeys`.

Per zone, skip unless: signing enabled, not multi-provider,
`DnssecPolicy != nil`, mode is `ksk-zsk` (not `csk`),
`ZSK.Lifetime > 0`. Then, under the per-zone rollover lock
(`AcquireRolloverLock`):

```text
active  = active ZSK (flags 256); if none → log + skip
if now - active.active_at < ZSK.Lifetime: skip
standby = any standby ZSK (flags 256)   // standby state already implies
                                        // >= propagationDelay visibility
if no standby: log "ZSK roll due but no standby available"; skip
RolloverKey(zone, "ZSK")     // standby→active(+active_at), active→retired
triggerResign(conf, zone)
```

Idempotent and self-throttling: after the roll the new active ZSK is
young, so the due check is false until the next lifetime elapses;
`maintainStandbyKeys` refills the standby.

### S4 — TTL-aware ZSK removal (G3) {#s4}

Make `transitionRetiredToRemoved` (`key_state_worker.go:172`) use a
TTL-aware margin for ZSKs instead of bare `propagationDelay`. Removal
margin = **`propagationDelay + LoadZoneSigningMaxTTL(zone)`** (a *sum*,
not the KSK path's `max`).

Why a sum: after the roll the primary re-signs immediately, but a
**secondary** can still serve an old-ZSK RRSIG until the re-signed zone
reaches it — up to `propagationDelay` after `T_roll`. A resolver that
fetches at that latest moment then caches the old RRSIG for up to
`max_observed_ttl`. So the retired ZSK must stay published until
`retired_at + propagationDelay + max_observed_ttl`, after which no
resolver can hold a still-cached RRSIG made by it. This is intentionally
more conservative than `effectiveMarginForZone`
(`ksk_rollover_automated.go:1637`, `max(clamping.margin,
max_observed_ttl)`) — the KSK path's `max` omits the propagation term,
which the `2026-05-02-rollover-timing-report.md` already flags as an
approximation; the cost of the sum is only keeping a retired ZSK
published slightly longer. Because the configurable-sig-validity floor
(plan #1) guarantees `SigValidity ≥ servedTTL`, the old ZSK's signatures
always outlive that cache window, so removal is a pure TTL question — no
sig-validity term in the margin.

The function already special-cases SEP keys in rollover zones (skips
them; `key_state_worker.go:186-190`). Add the ZSK branch: for non-SEP
retired keys, gate on `propagationDelay + max_observed_ttl` rather than
bare `propagationDelay`.

### S5 — observability (G4)

Populate the ZSK section of `auto-rollover status`
(`cli/ksk_rollover_cli.go`, the `--zsk` rendering): show each ZSK's
state, `active_at`, and next roll = `active_at + ZSK.Lifetime`, and
whether a ready standby exists. Drop the "not implemented" line.
Optionally a one-line invariant note (removal margin ≥ max served TTL).

## Edge cases

 - **No ready standby when due.** Do not activate (would leave the zone
   with no successor and break the next roll). Log and wait;
   `maintainStandbyKeys` will produce one, and the roll fires a tick or
   two later. ZSK lifetimes ≫ standby-generation time, so this is
   transient.
 - **KSK reused as ZSK (no real ZSK).** `EnsureActiveDnssecKeys` reuses
   a KSK as CSK when no real ZSK exists (`sign.go:303-317`). That is
   effectively `csk` behaviour — skip ZSK auto-roll (no flags-256 key).
 - **KSK and ZSK due same tick.** Independent keys (SEP vs non-SEP);
   both steps run sequentially in one tick. Each calls `triggerResign`;
   the resigner coalesces, so the zone re-signs once.
 - **`csk` mode.** Skipped (see non-goals).
 - **`tdns-mp`.** Separate worker; mirror in a follow-up.

## Testing

 - Due logic: active ZSK older than `ZSK.Lifetime` with a standby
   present → roll; no standby → no roll; `Lifetime == 0` → never.
 - Roll effect: after a roll, the new ZSK is active and signs a
   non-apex RRset; the old ZSK is retired and still in the DNSKEY
   RRset; a fresh standby is regenerated.
 - Removal margin: a retired ZSK is not removed before
   `propagationDelay + max_observed_ttl`; removed after.
 - `csk` mode and KSK-reused-as-ZSK zones do not auto-roll.
 - Integration (lab/NetBSD VM): a short-`ZSK.Lifetime` zone rolls its
   ZSK end-to-end with no validation break across the roll.

## Implementation order

**Dependency:** the configurable-RRSIG-validity workstream
(`2026-05-21-configurable-rrsig-validity-plan.md`) should land first, or
at least its floor invariant, so S4's "signatures outlive the TTL"
assumption is enforced rather than assumed. ZSK rollover can be built in
parallel but should not be enabled in production ahead of it.

1. **S1 `ZSK.Lifetime` wiring** (read in S3). **DONE**
2. **S2 `active_at` column** + stamping. Schema + write sites. **DONE**
3. **S3 `rolloverZsksForAllZones`** wired into the tick. Core feature. **DONE**
4. **S4 TTL-aware removal** for ZSK. **DONE**
5. **S5 status** rendering. **DONE**

Build after each Go change:
`cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`. `gofmt -w` every
edited file. Do not modify v1 (`tdns/tdns/`), `tdns/obe/`,
`tdns/music/`.

## Open questions

**Resolved (2026-05-21):**
 - *Standby pause* → **none, no new knob.** The `published→standby`
   transition already waits `propagationDelay`, so any standby key is
   already propagated; readiness = "a standby ZSK exists" (see S3).
 - *Removal margin* → **sum**: `propagationDelay + max_observed_ttl`
   (see S4 for the secondary-lag + cache reasoning).
 - *CLI manual-roll coexistence* → keep `keystore dnssec rollover
   --keytype ZSK` as a manual immediate override; **no "asap" state**
   for ZSK. It stamps `active_at`, so the auto due-check sees a fresh
   key and won't double-roll; `maintainStandbyKeys` refills the consumed
   standby. No extra state.
 - *Schema change* → per "no installed base," add the `active_at`
   column by changing the schema directly (dev/test DBs are recreated);
   no migration shim.

No open questions remain for this plan.

## File-change checklist

 - `tdns/v2/db_schema.go` — `active_at` column on `DnssecKeyStore` (S2).
 - `tdns/v2/keystore.go` — stamp `active_at` in `RolloverKey`
   standby→active (S2); read it where ZSK age is computed.
 - `tdns/v2/zsk_rollover.go` (new) — `rolloverZsksForAllZones` (S3).
 - `tdns/v2/key_state_worker.go` — invoke the ZSK step in
   `checkAndTransitionKeys` (S3); TTL-aware ZSK branch in
   `transitionRetiredToRemoved` (S4).
 - `tdns/v2/cli/ksk_rollover_cli.go` — ZSK status rendering (S5).
 - sample policy YAML — document that `zsk.lifetime` now drives
   automated ZSK rollover.
