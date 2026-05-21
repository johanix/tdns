# Configurable, adhered-to RRSIG validity

**Date:** 2026-05-21
**Author:** Johan Stenstam
**Status:** Planning — ready to implement
**Affects:** signer, resigner, DNSSEC-policy config, KSK rollover
validators (E5/E10/E11). Prerequisite for
`2026-05-21-automated-zsk-rollover-plan.md`.
**Related:** `2026-05-02-rollover-timing-report.md`,
`2026-04-23-automated-ksk-rollover.md`.

> **Implementer notes.** (1) `file:line` refs are a 2026-05-21 snapshot
> — locate code by the named *symbol* (`SignRRset`, `NeedsResigning`,
> `checkE5`, …), not the line number. (2) Strict order across the three
> plans: **#1 this plan → #2 ZSK rollover → #3 large KSKs**; this one is
> first and lands before the others edit the same files.

## Problem

RRSIG validity is hardcoded. `SignRRset` stamps every RRSIG with a
fixed 30-day lifetime regardless of policy:

```go
// sign.go:236
rrsig.Inception, rrsig.Expiration = sigLifetime(now, 3600*24*30) // 30 days
```

`sigLifetime` (`sign.go:51`) applies that lifetime plus 0–60s jitter
and a 60s+jitter backdated inception. There is no branch on keytype or
RRtype: the KSK-over-DNSKEY RRSIG, DS RRSIGs, and all ZSK RRSIGs get
the same 30 days.

Meanwhile the policy carries per-keytype `KSK/ZSK/CSK.SigValidity`
fields that the signer **never reads**. They are assigned at parse time
only (`ksk_rollover_policy.go:489`, `parseconfig.go:278`). The KSK
rollover validators *do* read `KSK.SigValidity` (E5 at
`ksk_rollover_validation.go:159`, and the `auto-rollover validate`
printout), so the invariant checks validate a number the signer does
not honor — the invariant is fiction.

This is wrong in both directions: it silently overrides an operator who
needs *longer* validity (a signer offline between infrequent signings;
an expensive PQC KSK that should sign the DNSKEY RRset rarely), and it
makes the validators meaningless.

## Principle (why this is shaped the way it is)

RRSIG validity is an **operational** parameter, not a rollover
parameter. It is set by two pressures, neither tied to key rollover:

1. **Serve-correctness.** A resolver caches `(RRset, RRSIG)` for the
   RRset's TTL and uses that cached RRSIG for the whole TTL. If the
   signature's remaining validity falls below the TTL while it is being
   served, the resolver eventually holds an expired signature and goes
   bogus. So at serve time, remaining validity must always exceed the
   RRset's TTL.
2. **Outage survival.** Signatures must outlive a plausible signer
   outage so a dead signer does not expire the zone.

Rollover cadence and retirement timing, by contrast, are governed
entirely by **TTLs** — how fast caches flush keys in and out. These are
orthogonal axes. Coupling validity to rollover cadence (the old "short
ZSK sig-validity because ZSK rolls often" instinct) is a category
error.

The safety hinge is a single **floor invariant**:

> For every RRset type, `SigValidity ≥ served TTL of that RRset
> (+ propagation margin)`.

The floor does double duty. It guarantees serve-correctness directly,
and it keeps key rollover a one-variable problem: with `SigValidity ≥
servedTTL`, `min(servedTTL, SigValidity)` always collapses to the TTL,
so the rollover retirement period (`max(clamping.margin,
max_observed_ttl)`, the TTL-based `effectiveMarginForZone`) keeps
covering it without ever having to reason about signature expiry. This
is the property the 30-day hardcode was protecting by accident; we
replace the magic number with an *enforced* invariant, so validity
becomes a real operator knob without becoming a footgun.

## Design

### Granularity: one default + DNSKEY + DS overrides

Full per-RRtype validity is overkill. The two RRtypes that warrant
independent control are the chain-of-trust RRsets:

 - **DNSKEY** RRset — signed by the KSK; low volume (one RRset); for a
   large/PQC KSK you want a long validity so the expensive signature is
   produced rarely.
 - **DS** RRsets — the delegation links to children; low volume (only at
   secure delegations), high correctness significance, and entangled
   with child KSK-rollover / delegation-sync timing, so operators want a
   lever distinct from the bulk zone.

Everything else (SOA, NS, A, AAAA, MX, TXT, NSEC/NSEC3, …) uses the
zone default.

This **replaces** the per-keytype `KSK/ZSK/CSK.SigValidity` (wrong
axis). `Lifetime` stays per-keytype — that genuinely is rollover
cadence. (No backwards-compat: per project convention there is no
installed base; change the schema.)

Config (3-space indent):

```yaml
dnssecpolicies:
   foo:
      algorithm:  ECDSAP256SHA256
      ksk:
         lifetime:  90d        # rollover cadence (unchanged, per-keytype)
      zsk:
         lifetime:  30d
      sigvalidity:
         default:   14d        # all RRsets unless overridden
         dnskey:    90d        # DNSKEY RRset (KSK-signed)
         ds:        14d        # DS RRsets at delegations (ZSK-signed)
```

`dnskey` / `ds` empty → inherit `default`.

### Config + runtime structs

 - `DnssecPolicyConf` (`structs.go:326`): drop `SigValidity` from the
   `KSK`/`ZSK`/`CSK` sub-structs (leave their `Lifetime`); add a
   `SigValidity struct { Default, Dnskey, Ds string }`.
 - `DnssecPolicy` (`structs.go:355`): replace the `SigValidity` carried
   inside `KeyLifetime` with a resolved
   `SigValidity struct { Default, DNSKEY, DS uint32 }` (seconds).
 - Parsing (`ksk_rollover_policy.go` `parseDnssecPolicyConfImpl`,
   `ValidateDnssecPoliciesFromFile`, and the `parseconfig.go` default):
   parse the three durations; resolve `dnskey`/`ds` to `default` when
   empty. Reuse `GenKeyLifetime`'s duration parsing (split it so
   lifetime and sig-validity parse independently).

### `ttls` rename: disambiguate the two DS TTLs

Today `ttls.ds` (`DnssecPolicyTTLS.DS`, `structs.go:385-389`) means the
*parent's* DS RRset TTL for **our own** delegation, read by the E10/E11
rollover invariants. That name now collides with the served TTL of DS
RRsets **we publish for our children** (the bound for `sigvalidity.ds`).
Rename to make each unambiguous:

 - `ttls.parent-ds` (`DnssecPolicyTTLS.ParentDS`) — *renamed from*
   `ttls.ds`. Parent's DS TTL for our delegation; E10/E11 read this.
 - `ttls.ds` (`DnssecPolicyTTLS.DS`, **new meaning**) — served TTL of DS
   RRsets we publish at our children's secure delegations. Symmetric
   with `ttls.dnskey`; bounds the `sigvalidity.ds` floor.

**The child controls its own DS TTL** (design decision): when a child
expresses a DS TTL via CDS or DNS UPDATE, the signer honours it and does
**not** override it. `ttls.ds` is the fallback used only when the child
has no opinion. Consequence for the floor: the config-time `ds` check
uses `ttls.ds` (the fallback), and the runtime check uses the actual
observed served DS TTL — so a child that sets a DS TTL larger than
`ttls.ds` (and larger than the parent's `sigvalidity.ds` can cover) does
not break correctness silently; the parent zone is flagged
(`DnssecPolicyWarning`/`DnssecError`) by the runtime guard.

Rename blast radius (no back-compat per project convention): the
`structs.go` field + comment, the YAML/mapstructure key in
`DnssecPolicyTtlsConf`, every E10/E11 read site
(`ksk_rollover_validation.go`), and samples.

### Signer adheres (`sign.go:236`)

In `SignRRset`, choose the lifetime by the RRset type instead of the
constant:

```text
switch rrset.RRtype {
case DNSKEY: v = pol.SigValidity.DNSKEY
case DS:     v = pol.SigValidity.DS
default:     v = pol.SigValidity.Default
}
rrsig.Inception, rrsig.Expiration = sigLifetime(now, v)
```

No zero-fallback: a policy with an unset/unsafe validity never reaches
the signer in a signing zone, because the floor check (below) has
already marked such zones with `DnssecError` and they do not sign.
`SignRRset` already has `zd`, so `zd.DnssecPolicy` is in reach. (SIG(0)
at `sign.go:84` is unrelated transaction signing — leave it.)

### Resigner becomes validity-aware (`sign.go:268`)

Today `NeedsResigning` re-signs when remaining lifetime
`< 3 × resignerengine.interval` — a fixed multiple of a *separate* knob,
unrelated to validity. Once validity is honored and can be short, the
trigger must guarantee no *served* signature ever has remaining validity
below its served TTL. `NeedsResigning` has the `*dns.RRSIG`
(`TypeCovered` → the right per-RRtype validity), so:

> re-sign when `remaining_validity < servedTTL(type) + propagationDelay
> + scanInterval` — the `scanInterval` slack ensures a signature never
> dips below `servedTTL` between two resigner passes (this is what the
> old `3 × resignerengine.interval` crudely approximated).

Decouples the refresh trigger from `resignerengine.interval` as the
*threshold* (it remains only the scan *cadence*). The floor invariant
(below) guarantees `SigValidity` is comfortably larger than this
threshold, so resigning always has room.

### Floor validation (two checks: config-load + runtime)

Runs for **every** signed zone, not only clamped ones — unlike today's
`checkE5`, which returns early when clamping is disabled
(`ksk_rollover_validation.go:155`). Serve-correctness is universal.

Let `H(type) = servedTTL(type) + propagationDelay`. The three bands
(conservative thresholds per design decision):

 - `SigValidity(type) ≤ 2 × H(type)`, **or `sigvalidity.default`
   unset** → **hard error**: set `DnssecError` (service-impacting,
   `enums.go:324`) on every zone using the policy. The zone refuses to
   sign / SERVFAILs; the daemon and all other zones run normally
   (the server starts whenever possible).
 - `2 × H < SigValidity < 4 × H` → **warning**: set the non-impacting
   `DnssecPolicyWarning` (see below). The zone signs.
 - `SigValidity ≥ 4 × H` → fine.

This unifies "incomplete policy" and "unsafe validity" into one hard-
error path: a zone is never silently signed with an unsafe or
defaulted validity.

`servedTTL(type)` differs between the two checkpoints:

**Config-load check** — uses *policy-derived* TTLs:
 - `dnskey` → `configuredServedDnskeyTTL` (`ksk_rollover_validation.go:192`,
   = min(`ttls.dnskey`, `ttls.max_served`)).
 - `ds` → `ttls.ds` (the new fallback child-DS TTL).
 - `default` → `ttls.max_served`.
 - **Skip rule (critical, avoids the silent trap):** if a value's
   governing TTL is *unset* (0 / no ceiling), **skip that value's
   config-time band check** — do **not** treat `servedTTL = 0` as a real
   bound (that would make the floor pass trivially and silently disable
   the protection). Defer entirely to the runtime check. The only
   config-time hard error that always fires is `sigvalidity.default`
   being unset. (The built-in default policy sets no ceilings, so its
   `dnskey`/`ds`/`default` band checks are all skipped at config time —
   safe, since `14d/30d/14d` clear any realistic runtime TTL.)

**Runtime check** — the universal backstop. After each `SignZone`,
compare resolved validities against the zone's *observed* served TTL via
`LoadZoneSigningMaxTTL` (`max_observed_ttl`, `ksk_rollover_automated.go:1639`)
and set/clear `DnssecError`/`DnssecPolicyWarning` on the zone. This
catches everything config-time couldn't: unset ceilings, high zone-file
TTLs, and **child-driven DS TTLs** (a child's CDS/UPDATE can set a DS
TTL larger than `ttls.ds`; see the `ttls` section — the parent must then
carry a `sigvalidity.ds` large enough, or be flagged here).
Pragmatically use the single `max_observed_ttl` as the bound for all
three values — conservative (it over-constrains `dnskey`/`ds` slightly,
harmless since those are configured longer). Per-type observed TTL
tracking is a possible later refinement, not needed for v1.

**`DnssecPolicyWarning` is introduced here** (this plan lands first):
a non-impacting `ErrorType` (in `enums.go`, *excluded* from
`serviceImpactingErrors` and `autoRolloverImpactingErrors`), following
the `RolloverPolicyWarning` precedent. Plan #3's A.4 (CSK/large-alg
warning) **reuses** this type rather than defining its own.

Set/clear both error types per zone on each config (re)load so they are
idempotent: `zd.SetError(...)` / `zd.ClearError(...)`.

### KSK rollover validators (rename + now-meaningful)

 - `checkE5` (`ksk_rollover_validation.go:159`): `pol.KSK.SigValidity`
   → `pol.SigValidity.DNSKEY`. With the signer adhering and the floor
   enforced, E5's `min(served DNSKEY_TTL, sig-validity)` is now a true
   statement and collapses to the TTL.
 - `auto-rollover validate` printout (`cli/auto_rollover_validate.go:216`)
   and any `RolloverStatus` field carrying `KskSigValidity`: source from
   `SigValidity.DNSKEY`.
 - E10/E11: confirm they key off `KSK.Lifetime` (cadence), not
   sig-validity; no change expected.

### Defaults

The current default policy sets `zsk sigvalidity: 2h`
(`parseconfig.go:1100`) and the `fastroll` sample likewise. Once the
signer *obeys* policy and the conservative floor is enforced, `2h`
becomes a **hard error** for any zone whose `H = servedTTL +
propagationDelay` makes `2h ≤ 2×H` — i.e. essentially all of them
(propagationDelay defaults to 1h, so `H ≥ 1h`, `2×H ≥ 2h`). So revising
defaults is **mandatory**, not optional: the built-in default policy's
own `sigvalidity` must satisfy `> 2×H` (ideally `≥ 4×H`) for the TTLs
that policy implies. Propose: `default: 14d`, `dnskey: 30d` (longer for
PQC), `ds: 14d` — all far above `4×H` for normal TTLs. Confirm the exact
numbers during implementation against the default policy's own TTLs.

## Implementation order

1. **Config/struct reshape:** move sig-validity to
   `default/dnskey/ds`; parse + resolve. `ttls.ds` → `ttls.parent-ds`
   rename + new `ttls.ds`. Drop per-keytype `SigValidity`. Update the
   default policy + samples (new safe defaults).
2. **`DnssecPolicyWarning` error type** in `enums.go` (non-impacting;
   reused later by plan #3's A.4).
3. **Floor validation:** the universal config-load check with the
   three bands (hard `DnssecError` ≤ 2×H or unset; `DnssecPolicyWarning`
   in (2×,4×)); runtime guard via `max_observed_ttl`. Land before
   adherence so bad values mark zones broken, not silently obeyed.
4. **Signer adherence:** `sign.go:236` picks validity by RRtype.
5. **Resigner coupling:** `NeedsResigning` driven by per-RRtype
   validity + served TTL + scan-interval slack.
6. **Validator rename:** E5 / CLI / status read `SigValidity.DNSKEY`;
   E10/E11 read `ttls.parent-ds`.

Steps 3 and 4 must ship together (3 before 4). Build after each:
`cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`; `gofmt -w` edits.
Do not touch v1 / obe / music.

## Edge cases / interactions

 - **`csk` mode.** One key signs everything; it uses the per-RRtype
   selection like any other (DNSKEY override for the DNSKEY RRset, DS
   override for DS, default elsewhere). No CSK-specific validity knob.
 - **DS RRsets exist only at secure delegations.** A zone with no signed
   children never emits a DS RRSIG; the `ds` knob is then inert. Fine.
 - **Clamping (K-step).** Clamping lowers *served TTL* near a KSK roll;
   the floor is `validity ≥ served TTL`, and clamping only *reduces*
   served TTL, so a roll never tightens the floor. Safe by construction.
 - **Large-KSK plan.** A long `dnskey` validity is exactly what an
   expensive PQC KSK wants (sign the DNSKEY RRset seldom); this knob is
   the lever for that. See `2026-05-21-large-ksk-...md`.
 - **tdns-mp.** Its signer path must honor the same selection; mirror.

## Open questions

**Resolved (2026-05-21):**
 - *DS served-TTL source* → dedicated **`ttls.ds`** (fallback child-DS
   TTL); rename existing `ttls.ds` (parent's DS TTL) → **`ttls.parent-ds`**.
 - *DS TTL ownership* → **the child controls its DS TTL** (CDS / DNS
   UPDATE); the signer never overrides it. `ttls.ds` is the fallback for
   children with no opinion. Child-driven DS TTLs above `ttls.ds` are
   caught by the runtime floor check, not silently accepted.
 - *Zero/incomplete value* → **no compiled fallback**. Missing
   `sigvalidity.default`, or a floor violation, is a **hard error**
   (`DnssecError`) on each zone using the policy; the daemon still starts.
 - *Floor checkpoints* → config-load (policy TTLs; **skip** any value
   whose ceiling is unset) + runtime after `SignZone` (observed
   `max_observed_ttl`, the universal backstop). See Floor validation.
 - *Refresh-headroom shape* → re-sign when `remaining < servedTTL +
   propagationDelay + scanInterval`.
 - *Floor margin* → require `SigValidity > 2 × (servedTTL +
   propagationDelay)` (hard error otherwise); **warn** below `4 ×`.
 - *Default-policy numbers* → adopt `default: 14d`, `dnskey: 30d`,
   `ds: 14d`. The built-in default policy sets no TTL ceilings
   (`BuiltinDefaultDnssecPolicy`, `parseconfig.go:1098`), so config-time
   band checks are skipped and these clear any realistic runtime TTL.
   The current `zsk sigvalidity: 2h` **must** be replaced by these.

No open questions remain for this plan.

## File-change checklist

 - `tdns/v2/structs.go` — `DnssecPolicyConf.SigValidity{Default,Dnskey,
   Ds}`; drop per-keytype `SigValidity`; `DnssecPolicy.SigValidity`
   resolved struct. `DnssecPolicyTTLS`: `DS` → `ParentDS`; add new `DS`.
   Same renames in `DnssecPolicyTtlsConf` (YAML `ds` → `parent-ds`, new
   `ds`).
 - `tdns/v2/enums.go` — introduce non-impacting `DnssecPolicyWarning`
   (enum const, `ErrorTypeToString`, `errorTypeReportOrder`; excluded
   from `serviceImpactingErrors` / `autoRolloverImpactingErrors`).
   (Plan #3 A.4 reuses it.)
 - `tdns/v2/ksk_rollover_policy.go` — parse/resolve the three values in
   `parseDnssecPolicyConfImpl` + `ValidateDnssecPoliciesFromFile`.
 - `tdns/v2/parseconfig.go` — default policy values (safe per floor);
   split `GenKeyLifetime` so sig-validity parses independently of
   lifetime.
 - `tdns/v2/sign.go` — RRtype-based validity in `SignRRset`
   (`sign.go:236`); validity-aware `NeedsResigning` (`sign.go:268`).
 - `tdns/v2/ksk_rollover_validation.go` — `checkE5` → `SigValidity.DNSKEY`;
   E10/E11 → `ttls.parent-ds`; new universal floor check (3 bands,
   independent of clamping; sets `DnssecError` / `DnssecPolicyWarning`).
 - config-load wiring (`parseconfig.go` zone loop) — set/clear
   `DnssecError` / `DnssecPolicyWarning` per zone from the floor check.
 - `tdns/v2/cli/auto_rollover_validate.go` — printout source rename.
 - `tdns/v2/rollover_api_funcs.go` — any `KskSigValidity` status field
   source rename.
 - sample policy YAML — new `sigvalidity:` block; `ttls.parent-ds` +
   `ttls.ds`; safe defaults.
 - `tdns-mp` signer path — mirror the RRtype-based selection.
