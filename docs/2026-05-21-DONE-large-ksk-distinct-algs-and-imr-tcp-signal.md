# Large KSKs: distinct KSK/ZSK algorithms + IMR DS-based TCP signaling

**Date:** 2026-05-21
**Author:** Johan Stenstam
**Status:** Implemented on branch `feat/large-ksk-support` (2026-05-22)
**Related drafts:**
 - `draft-johani-dnsop-dnssec-large-ksk-00` (Proposals 1 and 2 below)
 - `draft-johani-dnsop-dnssec-alg-private-ranges-00` (where a large
   KSK algorithm number would come from)
**Related design docs:**
 - `2026-05-13-miekg-dns-pluggable-algorithms-proposal.md`
   (how a real PQC/large algorithm gets wired into the crypto layer)
 - `2026-05-16-imr-improvement-plan.md`

> **Implementer notes.** (1) `file:line` refs are a 2026-05-21 snapshot
> — locate code by the named *symbol*, not the line number; plans #1/#2
> land first and will have shifted some lines cited here. (2) Strict
> order: **#1 (configurable RRSIG validity) → #2 (ZSK rollover) → #3
> this plan**; do not start this plan until #1 and #2 have landed. Part A
> reuses `DnssecPolicyWarning` (introduced in #1) and #1's `dnskey`
> sig-validity lever; Part B is independent of #1/#2 but still ordered
> last. Parts A and B are independent of each other.

## Purpose

Implement the two mechanisms from `draft-johani-dnsop-dnssec-large-ksk`:

 - **(a)** Allow a zone to be signed with a *large* algorithm on the
   KSK and a *small/traditional* algorithm on the ZSK (different
   algorithms for the two key roles). This is draft Proposal 1.
 - **(b)** Let the IMR (recursive resolver) recognize, from the
   algorithm number in a parent's DS RRset, that the child's DNSKEY
   RRset is likely too large for UDP, and query that DNSKEY RRset
   directly over TCP — skipping the truncated-UDP-then-retry round
   trip. This is draft Proposal 2.

The set of "large" algorithm numbers is a **config option** for now
(no registry annotation yet). The IMR must be **instrumented** so we
can see when large algorithms are encountered and when a direct-TCP
query is issued as a result.

## Goals / non-goals

Goals:
 - Distinct KSK and ZSK algorithms across the full automated key
   lifecycle (bootstrap, ensure-active, standby generation, rollover).
 - IMR config-driven list of large algorithm numbers; direct-TCP
   DNSKEY fetch when a cached parent DS uses such an algorithm.
 - Instrumentation touchpoints identified (exact counter design left
   to implementation time).

Non-goals:
 - Adding any actual large/PQC crypto algorithm. That is the separate
   pluggable-algorithms work; this plan is testable today with e.g. an
   RSASHA512 KSK + ECDSAP256SHA256 ZSK, or ED25519 KSK + ECDSAP256
   ZSK. The "large" property in (b) is decoupled from real key sizes —
   it is whatever the operator lists in config.
 - A registry-annotation source for "large" (draft Proposal 2 option
   2). Config only for now.
 - Validator-side changes. Validation already accepts any single valid
   algorithm path; nothing to change there.

---

# Shared — algorithm classification (`dnssec.large_algorithms`)

Both parts need to know which algorithm numbers are "large": Part B to
decide on TCP, and Part A to warn when a large algorithm signs the bulk
of the zone (A.4). Rather than bury the list under `imrengine` (a pure
signer may have no `imrengine:` section, and coupling the signer to IMR
config is wrong), it lives in a neutral top-level block consumed by
both subsystems. This is the config stand-in for the eventual IANA
registry annotation from draft Proposal 2.

Config: add a top-level `Dnssec` block to `Config`
(`tdns/v2/config.go:42`):

```go
type DnssecConf struct {
   // LargeAlgorithms lists DNSSEC algorithm numbers whose DNSKEY/RRSIG
   // sizes are large for UDP transport. Consumed by the IMR (Part B,
   // DS-based TCP) and the signer (Part A.4, CSK/ZSK warning).
   LargeAlgorithms []uint8 `yaml:"large_algorithms" mapstructure:"large_algorithms"`
}
// in Config:
Dnssec DnssecConf `yaml:"dnssec" mapstructure:"dnssec"`
```

`mapstructure` decodes a YAML integer list into `[]uint8` directly.
Build a derived `map[uint8]bool` once at config load (e.g. on
`conf.Internal`) and expose a single classifier both subsystems call:

```go
func (conf *Config) IsLargeAlgorithm(alg uint8) bool
```

YAML (3-space indent):

```yaml
dnssec:
   # Algorithm numbers whose DNSKEY RRsets are large. The IMR queries
   # such a child's DNSKEY over TCP when the parent DS uses one; the
   # signer warns if one is used to sign the bulk of a zone.
   large_algorithms: [ 199 ]   # 199 = ML-DSA-44 (our private-use code point)
```

---

# Part A — distinct KSK/ZSK algorithms

## A.1 Current state (what already works)

Three things already behave the way the draft wants, so this part is
smaller than it first appears:

1. **The signing loop is per-key algorithm-aware.** `SignRRset`
   (`tdns/v2/sign.go:117`) selects KSKs for the DNSKEY RRset and ZSKs
   for everything else (`sign.go:172-176`), then writes each RRSIG's
   algorithm from the signing key itself:
   `rrsig.Algorithm = key.DnskeyRR.Algorithm` (`sign.go:235`). A KSK
   on algorithm A and a ZSK on algorithm B already produce A-signed
   DNSKEY and B-signed everything-else with no further change.

2. **There is no "sign with every algorithm in the DNSKEY RRset"
   enforcement.** The signer signs with the active *keys*, not with
   every *algorithm* present in the apex DNSKEY RRset. This is exactly
   the relaxed signer-side rule of draft Proposal 1 — it is already
   the de-facto behavior, so Proposal 1 requires **no removal of an
   existing check**. (Confirm by grep that no code asserts every apex
   algorithm appears on every RRset.)

3. **The manual CLI already supports per-role algorithms.** `keystore
   dnssec generate` takes independent `--keytype` (KSK|ZSK|CSK) and
   `--algorithm` flags (`tdns/v2/cli/keystore_cmds.go:188-198`). An
   operator can already create a KSK with one algorithm and a ZSK with
   another by hand.

4. **DS generation reads the per-key algorithm.** The DS path uses
   `dnskey.Algorithm` per key (`keystore_cmds.go:788`), so a
   large-algorithm KSK yields a DS carrying that algorithm number with
   no change.

## A.2 The single chokepoint

Automated key generation forces **one** algorithm onto both roles:
`DnssecPolicy` has a single `Algorithm uint8` field
(`tdns/v2/structs.go:355-373`), populated from the single
`DnssecPolicyConf.Algorithm string` (`tdns/v2/structs.go:326-347`,
parsed at `tdns/v2/ksk_rollover_policy.go:479-504`). Every automated
generation site reads `zd.DnssecPolicy.Algorithm` for both KSK and
ZSK:

 - `EnsureActiveDnssecKeys` — KSK at `sign.go:367`, bootstrap-KSK
   registration at `sign.go:375`, ZSK at `sign.go:397`.
 - `key_state_worker.go` standby generation
   (`maintainStandbyKeysForType`, ~`tdns/v2/key_state_worker.go:230-289`):
   `alg := zd.DnssecPolicy.Algorithm` then used for both roles.
 - `tdns-mp/v2/key_state_worker.go` — same pattern, mirror any change.

The keygen primitives themselves already take an explicit `alg uint8`:
`GenerateKeypair(... alg uint8, keytype string ...)`
(`tdns/v2/sig0_utils.go:267`), `GenerateAndStageKey(... alg uint8,
keytype string)` (`tdns/v2/keystore.go:983`), `GenerateKeyMaterial`
(`tdns/v2/sig0_utils.go:99`). So the fix is purely *which* algorithm
each call site passes — no signature change to the primitives.

## A.3 Changes for Part A

### A.3.1 Policy config: optional per-role algorithm override

In `DnssecPolicyConf` (`tdns/v2/structs.go:326`) the `KSK`/`ZSK`/`CSK`
sub-structs currently hold only `Lifetime`/`SigValidity`. Add an
optional per-role `Algorithm string`:

```go
KSK struct {
   Lifetime    string
   SigValidity string
   Algorithm   string `yaml:"algorithm" mapstructure:"algorithm"`
}
ZSK struct {
   Lifetime    string
   SigValidity string
   Algorithm   string `yaml:"algorithm" mapstructure:"algorithm"`
}
// CSK: leave single-algorithm; a CSK is one key, so it uses the
// top-level policy Algorithm. Do not add a per-role override there.
```

Keep the top-level `DnssecPolicyConf.Algorithm` as the default. The
per-role field, when empty, inherits the top-level value. This keeps
all existing single-algorithm policies working unchanged (no
backwards-compat shim needed — empty means inherit, which is the
existing behavior).

### A.3.2 Runtime policy struct

In `DnssecPolicy` (`tdns/v2/structs.go:355`) add resolved per-role
algorithms:

```go
type DnssecPolicy struct {
   Name         string
   Algorithm    uint8 // default / CSK algorithm (unchanged meaning)
   KSKAlgorithm uint8 // resolved: per-role override or Algorithm
   ZSKAlgorithm uint8 // resolved: per-role override or Algorithm
   ...
}
```

### A.3.3 Policy parsing

In `parseDnssecPolicyConfImpl` (`tdns/v2/ksk_rollover_policy.go:479`)
resolve the per-role algorithms after the top-level one:

```go
alg := dns.StringToAlgorithm[normalize(dp.Algorithm)]
if alg == 0 { return nil, fmt.Errorf("policy %q: unknown algorithm %q", name, dp.Algorithm) }
kskAlg := alg
if s := strings.TrimSpace(dp.KSK.Algorithm); s != "" {
   kskAlg = dns.StringToAlgorithm[strings.ToUpper(s)]
   if kskAlg == 0 { return nil, fmt.Errorf("policy %q: unknown KSK algorithm %q", name, dp.KSK.Algorithm) }
}
// same for zskAlg from dp.ZSK.Algorithm
out := &DnssecPolicy{
   Name: name, Algorithm: alg,
   KSKAlgorithm: kskAlg, ZSKAlgorithm: zskAlg,
   ...
}
```

Apply the identical resolution in `ValidateDnssecPoliciesFromFile`
(`ksk_rollover_policy.go:508-540`) so offline `validate` catches bad
per-role algorithm names too.

### A.3.4 Key generation call sites

Replace the role-blind `zd.DnssecPolicy.Algorithm` with the resolved
per-role field:

 - `sign.go:367` KSK generation → `zd.DnssecPolicy.KSKAlgorithm`.
 - `sign.go:375` `RegisterBootstrapActiveKSK(..., zd.DnssecPolicy.Algorithm)`
   → pass `zd.DnssecPolicy.KSKAlgorithm` (this records the KSK's
   algorithm for rollover/clamp scheduling; it must match the KSK).
 - `sign.go:397` ZSK generation → `zd.DnssecPolicy.ZSKAlgorithm`.
 - `key_state_worker.go` `maintainStandbyKeysForType`: the function
   already receives a `keytype` ("KSK"/"ZSK") and an `alg`. Change the
   caller to pass `KSKAlgorithm` when keytype=="KSK" and `ZSKAlgorithm`
   when keytype=="ZSK" (instead of one `alg := zd.DnssecPolicy.Algorithm`
   for both). Verify the standby/rollover logic keys keys by role, not
   by a single zone algorithm.
 - `tdns-mp/v2/key_state_worker.go`: mirror.

### A.3.5 CLI

Manual generation already works (A.1 point 3). Add to the plan:
 - Verify `keystore dnssec generate --keytype KSK --algorithm X` and a
   second invocation with `--keytype ZSK --algorithm Y` land two keys
   with distinct algorithms in the keystore for the same zone.
 - Optionally surface the policy's resolved per-role algorithms in
   whatever `auto-rollover`/policy-show CLI exists, so an operator can
   confirm the policy resolved as intended. (Low priority.)

### A.3.6 Correctness review (no code, but must verify)

Grep and read to confirm nothing assumes a single zone algorithm or
asserts KSK alg == ZSK alg:
 - Rollover state machine (`ksk_rollover_*.go`): does any step compare
   or assume a shared algorithm across KSK and ZSK? The K-step clamp
   and rollover scheduler are KSK-scoped; confirm ZSK algorithm is
   never read where the KSK's is expected.
 - DS generation / CDS / publication: per-key algorithm (already true
   at `keystore_cmds.go:788`); confirm CDS path too.
 - `tdns-mp` multi-provider publish/merge of DNSKEYs: confirm merging
   remote DNSKEYs does not assume a uniform algorithm.

### A.3.7 Tests

 - Policy parse test: a policy with `ksk.algorithm` and `zsk.algorithm`
   distinct from the top-level resolves to the expected
   `KSKAlgorithm`/`ZSKAlgorithm`; empty per-role inherits; bad name
   errors.
 - Signing test: a zone with a KSK on algorithm A and ZSK on B
   produces a DNSKEY RRset RRSIG'd by A only and a non-apex RRset
   RRSIG'd by B only (assert `RRSIG.Algorithm`).
 - End-to-end keygen test through `EnsureActiveDnssecKeys` with a
   distinct-algorithm policy: assert the active KSK and ZSK have the
   configured algorithms.

### A.3.8 Sample config

Document in `tdns/cmd/.../*.sample.yaml` and any policy sample (3-space
indent):

```yaml
dnssec:
   split_algorithms:                # required for the mixed pair below
      RSASHA512: [ ECDSAP256SHA256 ]

dnssecpolicies:
   large-ksk:
      algorithm:  ECDSAP256SHA256   # default / ZSK fallback
      ksk:
         algorithm:  RSASHA512      # stand-in for a large/PQC alg
         lifetime:   90d
      zsk:
         algorithm:  ECDSAP256SHA256
         lifetime:   30d
```

See A.3.9 for the `split_algorithms` gate that the mixed pair requires.

### A.3.9 Gating which KSK/ZSK algorithm pairs are allowed (2026-06-16)

Per-role algorithm support (A.3.1–A.3.4) lets a policy name any KSK
algorithm with any ZSK algorithm. Not every combination should be
operationally permitted, so a deployment-wide allowlist gates which
*mixed* pairs are accepted. This lives under the shared `dnssec:`
block, not under `dnssecpolicies:` — like `large_algorithms`, it is a
property of the deployment, not of any single named policy, and every
policy is validated against it.

```yaml
dnssec:
   large_algorithms: [ 10 ]
   split_algorithms:                  # kskAlg -> permitted zskAlgs
      RSASHA512: [ ED25519, ECDSAP256SHA256 ]
      # FALCON512: [ ED25519 ]        # PQ algs, registered at runtime
```

Semantics (fail closed):
- A policy with `ksk.algorithm == zsk.algorithm` always passes; no
  entry needed.
- A policy whose KSK and ZSK algorithms **differ** is rejected at
  config parse unless that exact pair is listed. Error:
  `policy %q: KSK algorithm A may not pair with ZSK algorithm B; not
  listed in dnssec.split_algorithms`.

Implementation:
- `DnssecConf.SplitAlgorithms map[string][]string` (`config.go`),
  derived to `Internal.SplitAlgorithms map[uint8]map[uint8]bool` via
  `buildSplitAlgorithmSet` (`large_ksk.go`). Unknown algorithm names
  are dropped with a warning (a typo gates rather than silently
  permits). PQ names resolve through the same runtime-populated
  `dns.StringToAlgorithm` as the policy `algorithm:` field.
- `validateSplitAlgorithm(name, kskAlg, zskAlg, allowed)` enforces the
  rule. Wired into all three parse paths: runtime config load
  (`parseconfig.go`), `parseDnssecPolicyConfImpl`, and the standalone
  `ValidateDnssecPoliciesFromFile` CLI validator (which reads a
  `dnssec.split_algorithms` block from the validated file).
- Tests: `TestValidateSplitAlgorithm`, `TestBuildSplitAlgorithmSet`,
  `TestParseDnssecPolicyConfSplitGate` (`large_ksk_test.go`).

Related fix found in the same pass: the automated KSK-rollover
pipeline-fill (`ksk_rollover_automated.go`) generated rolled KSKs with
`pol.Algorithm` instead of `pol.KSKAlgorithm`, so a per-role KSK
algorithm was honored for the *initial* KSK but silently lost on every
rollover. Corrected to `pol.KSKAlgorithm`.

## A.4 Warn when a large algorithm signs the bulk of the zone

The large-KSK pattern only pays off when the large algorithm is
confined to the KSK (apex DNSKEY RRset). If a large algorithm is used
in a **zone-signing role** — a CSK, the ZSK, or a KSK reused as the ZSK
because no real ZSK exists — every RRSIG in the zone is inflated,
defeating the point. The signer must warn (not reject) in that case.

### A.4.1 The condition

Warn when the algorithm that signs non-DNSKEY RRsets is in
`dnssec.large_algorithms`. The effective bulk-signing algorithm is:

 - `mode: csk` → the CSK algorithm (`policy.Algorithm`); **headline case**.
 - otherwise → `policy.ZSKAlgorithm`.
 - runtime edge: a zone that ends up KSK-only (KSK reused as ZSK, no
   real ZSK — `sign.go:303-317`, `keystore.go:912-916`) → the KSK
   algorithm. This is not visible from policy alone, so it is caught at
   generation time (A.4.4) rather than config time.

This is broader than `mode == csk`; a large `zsk.algorithm` is the same
mistake.

### A.4.2 Mechanism: a non-impacting error type (no new subsystem)

The codebase already models "warning" as an `ErrorType` that no
*impacting* list references — see `RolloverPolicyWarning`
(`tdns/v2/enums.go:260-263`), which is excluded from
`serviceImpactingErrors` (`enums.go:324`) and
`autoRolloverImpactingErrors` (`enums.go:314`) and is therefore
visibility-only. There is no `zd.SetWarning()` and none is needed.

Use the `DnssecPolicyWarning` error type **introduced by plan #1**
(`2026-05-21-configurable-rrsig-validity-plan.md`), which lands first
and already needs it for the marginal sig-validity band. It is a
non-impacting `ErrorType` (in `enums.go`, excluded from
`serviceImpactingErrors` and `autoRolloverImpactingErrors`), following
the `RolloverPolicyWarning` precedent (`enums.go:260-263`). There is no
`zd.SetWarning()` and none is needed. If #3 somehow lands first, create
the type here per that precedent (enum const, `ErrorTypeToString`,
`errorTypeReportOrder`; out of both impacting lists).

Set with the existing API:
`zd.SetError(DnssecPolicyWarning, "large algorithm %s signs the bulk of
the zone (%s role); whole-zone signatures inflated", algName, role)`,
and `zd.ClearError(DnssecPolicyWarning)` when the condition no longer
holds, so it is idempotent across reloads. (A thin `SetWarning` alias
over the same registry is optional and cosmetic — skipped here to match
the `RolloverPolicyWarning` precedent.)

### A.4.3 Placement 1 — zone-config validation (primary)

The zone loop in `parseconfig.go` already holds `zd` and calls
`zd.SetError(...)` for config problems (`parseconfig.go:600` etc.).
After the zone's DNSSEC policy is resolved, compute the effective
bulk-signing algorithm (A.4.1) and, if `conf.IsLargeAlgorithm(alg)`,
`zd.SetError(DnssecPolicyWarning, ...)`; else
`zd.ClearError(DnssecPolicyWarning)`. Runs at startup and on every
reload, on the affected zone. Catches **policy intent**.

### A.4.4 Placement 2 — `validate` CLI for policy files (no zones)

The offline `validate` CLI parses policies without zones, so there is
no `zd`. Route this warning through the existing policy
coupling-warning path (`warnDnssecPolicyCoupling` /
`CollectDnssecPolicyCouplingWarnings`, `ksk_rollover_policy.go`) so it
renders as structured CLI output alongside the other coupling warnings.

### A.4.5 Placement 3 — key generation (defensive)

Covers the runtime KSK-reused-as-ZSK case and the manual
`keystore dnssec generate --keytype CSK --algorithm <large>` path that
bypasses policy entirely. At the generation sites
(`EnsureActiveDnssecKeys`, `GenerateAndStageKey`) set the same
`DnssecPolicyWarning` on the zone when a large-alg key is created in a
zone-signing role. For the pure-CLI path with no live `zd`, emit a
`lgSigner.Warn` plus a printed CLI notice. Catches **runtime reality**.

### A.4.6 Tests

 - Policy with `mode: csk` and a CSK algorithm in
   `dnssec.large_algorithms` produces `DnssecPolicyWarning` on the zone;
   not service- or rollover-impacting (`HasErrorOtherThan` tolerates it
   where appropriate).
 - Large `zsk.algorithm` triggers the same warning.
 - A large KSK with a small ZSK produces **no** warning (the supported
   pattern).
 - Clearing: flipping the policy back to a small bulk algorithm clears
   the warning on reload.

---

# Part B — IMR: DS algorithm → direct TCP for the child DNSKEY

## B.1 Current state

 - **Where the DS is obtained and cached.** `handleReferral`
   (`tdns/v2/dnslookup.go:2364`) extracts DS RRs from a referral's
   authority section and caches the DS RRset under the child zone name
   with `Context=ContextReferral` (`dnslookup.go:2420-2463`,
   `Set(...)` at ~2454). The `*dns.DS` RR exposes `.Algorithm` (the
   child KSK's algorithm) — this is the signal.
 - **Where the child DNSKEY is fetched.** During validation,
   `validateRRsetWithRRSIG` calls the fetcher
   (`tdns/v2/cache/rrset_validate.go:128`), which is
   `IterativeDNSQueryFetcher` (`dnslookup.go:3303`) →
   `IterativeDNSQuery(ctx, signer, dns.TypeDNSKEY, servers, ...)`.
   `ValidateDNSKEYs` (`rrset_validate.go:610`) also reads the cached DS
   for the DS-anchored fast path.
 - **Where transport is chosen and the query is sent.** The iterative
   walker `IterativeDNSQueryWithLoopDetection` (`dnslookup.go:1007`)
   builds the query (`dnslookup.go:1095`), prioritizes
   (server, addr, transport) tuples (`dnslookup.go:1152-1153`), and
   calls `tryServer` per tuple (`dnslookup.go:1176`). `tryServer`
   (`dnslookup.go:1837`) looks up the shared per-transport client
   `imr.Cache.DNSClient[t]` and calls `c.Exchange(m, addr, ...)`
   (`dnslookup.go:1885`).
 - **UDP vs TCP today.** For Do53, `DNSClient.Exchange`
   (`tdns/v2/core/dnsclient.go:182-238`) tries UDP first, then retries
   over TCP on TC=1 (`dnsclient.go:208-211`). EDNS(0) UDP buffer is set
   to 4096 (`m.SetEdns0(4096, true)`, e.g. `dnslookup.go:1827`).
 - **Constraint on forcing TCP.** `ForceTCP` is a *field on the shared
   `DNSClient`* (`dnsclient.go:94`). Mutating it to force TCP for one
   query would force TCP for *all* concurrent queries through that
   client and is racy. So a **per-query** TCP path is required; we must
   not toggle the shared client's `ForceTCP`.

## B.2 Config: large algorithm numbers (shared block)

The list lives in the shared `dnssec.large_algorithms` block (see the
Shared section), not under `imrengine`. The IMR copies the derived set
from config into the `Imr` struct (`tdns/v2/imrengine.go:27`) so the
hot path does not reach back into `Config` on every query:

```go
// in Imr
largeAlgs map[uint8]bool
```

Populate in `InitImrEngine` (`imrengine.go:101+`, near where
`Tuning`/`RequireDnssecValidation` are copied) from the shared
`conf.Dnssec.LargeAlgorithms` (or directly from the derived set behind
`conf.IsLargeAlgorithm`). Add a small accessor:

```go
func (imr *Imr) isLargeAlgorithm(alg uint8) bool {
   return imr.largeAlgs != nil && imr.largeAlgs[alg]
}
```

Config sample is the `dnssec.large_algorithms` block shown in the
Shared section; nothing IMR-specific to add to `imrengine:`.

## B.3 The decision hook (single, central)

Put the decision in `IterativeDNSQueryWithLoopDetection`
(`dnslookup.go:1007`), right after the query message is built
(`dnslookup.go:1095`) and before the prioritize/try loop
(`dnslookup.go:1152`). This one spot covers both the validator-driven
DNSKEY fetch and any other DNSKEY query:

```go
forceTCP := false
if qtype == dns.TypeDNSKEY {
   if ds := imr.Cache.Get(qname, dns.TypeDS); ds != nil && ds.RRset != nil {
      for _, rr := range ds.RRset.RRs {
         if d, ok := rr.(*dns.DS); ok && imr.isLargeAlgorithm(d.Algorithm) {
            forceTCP = true
            // INSTRUMENTATION: large-alg-encountered (see B.5)
            break
         }
      }
   }
}
```

Notes:
 - Key on `qname` because the DS is cached under the child zone name,
   which equals the DNSKEY owner name.
 - **Validation state of the DS is irrelevant** here. This is a pure
   transport optimization (draft §"Resolver Behavior"), so use the DS
   algorithm regardless of `ds.State` (secure/insecure/indeterminate).
   It never affects the validation outcome.
 - Multiple DS RRs: any one large-algorithm DS triggers TCP.
 - The fetcher passes the child's own auth servers, so this is in
   practice a direct DNSKEY query; `forceTCP` applies cleanly to it.

## B.4 Plumbing forceTCP to the wire (dedicated client, internal transport)

The cache already holds one dedicated client per transport
(`cache/rrset_cache.go:61-64`: Do53/DoT/DoH/DoQ). Forced-TCP joins that
map the same way, under a new **internal** transport value, rather than
as a one-off field or a per-call interface method. Plain TCP differs
from DoT/DoQ in exactly one respect — it is an *override of Do53*, not a
selectable rotation peer — so it must be **fenced out of candidate
selection and config** while still living in the client map.

Why this over the alternatives: mutating the shared client's `ForceTCP`
per query is racy; adding an `ExchangeTCP` interface method grows the
interface and adds a parallel exchange path. A dedicated client reuses
the dormant-but-built `ForceTCP`/`WithForceTCP` machinery
(`dnsclient.go:105`, `:204`) with no new client code, and keying it by a
transport value makes the existing lookup and per-transport counter work
unchanged.

1. **New internal transport value.** Add `TransportDo53TCP` to the
   `Transport` enum (`core/dnsclient.go`). Add a `TransportToString`
   entry (for logs/counters). `IsEncryptedTransport(TransportDo53TCP)`
   → false. **Do not** add a `StringToTransport` mapping (so a config
   `transports: [...]` list can never request it). Audit `switch`
   statements over `Transport` for any that need the new case.

2. **Map entry.** In `cache/rrset_cache.go` alongside the others:
   ```go
   client[core.TransportDo53TCP] =
       core.NewDNSClient(core.TransportDo53, "53", nil, core.WithForceTCP())
   ```
   (A Do53 client whose `Exchange` goes straight to TCP via the existing
   `ForceTCP` branch — zero new client code.)

3. **Fence from selection.** `candidateTransports`/`prioritizeServers`
   (`dnslookup.go:817`) must never emit `TransportDo53TCP`. Since they
   build the candidate list explicitly (Do53 always appended, encrypted
   ones by weight), simply not adding it there keeps it out of rotation.

4. **Thread the bool to `tryServer`.** Change
   `tryServer(ctx, server, addr, t, m, qname, qtype)`
   (`dnslookup.go:1837`) to accept a trailing `forceTCP bool`; update
   the single call site (`dnslookup.go:1176`).

5. **Substitute the transport in `tryServer`.** Replace the client
   lookup and counter (`dnslookup.go:1844`, `:1848`):
   ```go
   eff := t
   if forceTCP && t == core.TransportDo53 {
      eff = core.TransportDo53TCP
   }
   c, exist := imr.Cache.DNSClient[eff]
   if !exist { return nil, 0, fmt.Errorf("no DNS client for transport %d", eff) }
   server.IncrementTransportCounter(eff)   // direct-TCP queries counted here
   ...
   r, _, err := c.Exchange(m, addr, Globals.Debug && !imr.Quiet)  // unchanged
   ```
   `forceTCP` only substitutes for Do53; DoT/DoH/DoQ are already
   stream/connection transports, so a large-alg DNSKEY reached over them
   needs no override.

The existing wall-clock RTT measurement and outbound-query hooks stay
as-is. No interface change; no shared-state mutation; the `Exchange`
call site is untouched.

## B.5 Instrumentation (touchpoints; counter design deferred)

The IMR has no Prometheus/expvar; existing patterns are: module-level
atomic counters with a getter (`tdns/v2/ksk_rollover_clamp.go`
`ClampMetrics()`), per-`AuthServer` transport counters
(`cache/authserver.go:476` `IncrementTransportCounter`), and `slog`
structured logging (`var lgImr = Logger("engine")`, `var lgDns`).

Because forced-TCP is its own transport value (B.4), **one of the two
signals is already covered**: `direct-TCP-DNSKEY-issued` is just the
`TransportDo53TCP` per-`AuthServer` transport counter, incremented for
free by the existing `IncrementTransportCounter(eff)` call. No new
metric needed for it; a `SnapshotTransportCounters` reader already
exists (`cache/authserver.go:489`).

That leaves one event to add (final shape at implementation time —
likely a module-level `atomic.Uint64` with a getter, mirroring
`ClampMetrics`):

 - **large-algorithm-encountered** — at the B.3 hook when a cached DS
   with a large algorithm is found for a DNSKEY query. Suggested log:
   `lgDns.Info("large-alg DS observed; will query child DNSKEY over TCP",
   "zone", qname, "alg", d.Algorithm)`.

The distinction is worth keeping: "encountered" counts decisions
(per-process), while the `Do53TCP` transport counter counts issued
queries (per-server). Together they satisfy "track when such alg nos
are encountered while traversing the tree and when using that to query
over TCP directly." Surface the encountered-counter wherever
`ClampMetrics` is read today.

## B.6 Edge cases

 - **DS not yet cached at DNSKEY-query time.** In the normal referral
   flow `handleReferral` caches the DS before validation fetches the
   DNSKEY, so the lookup hits. If for some path the DS is absent, the
   feature simply does nothing and the legacy UDP-then-TCP behavior
   applies (no correctness impact). Acceptable.
 - **False positive** (small DNSKEY treated as large): only an
   unnecessary TCP query; never affects correctness (draft §Limitations).
 - **False negative** (large ZSK behind a small-alg KSK): DS signals
   small, IMR falls back to UDP-then-TCP. Out of scope; the draft
   accepts it.
 - **Recursion within the walk.** `forceTCP` is recomputed per
   `IterativeDNSQuery` call from qtype+DS; intermediate referral steps
   for a DNSKEY query keep qtype=DNSKEY, so TCP applies throughout the
   (typically single-hop) fetch. Harmless if a referral step goes over
   TCP.
 - **tdns-mp** embeds the same IMR; no separate change needed beyond
   the shared code.

## B.7 Tests

 - Unit: `isLargeAlgorithm` set construction from config.
 - Decision hook: seed cache with a DS (large alg) for zone Z; assert a
   DNSKEY query for Z computes `forceTCP=true`; with a non-large DS,
   `false`; with no DS, `false`; non-DNSKEY qtype, `false`.
 - Transport substitution: with `forceTCP`, `tryServer` selects
   `DNSClient[TransportDo53TCP]` and increments the `Do53TCP` counter;
   that client queries over TCP and never attempts UDP (loopback server
   asserting protocol). `TransportDo53TCP` never appears in
   `candidateTransports` output or accepted config.
 - Integration (lab/NetBSD VM, not this dev box): a delegation whose DS
   uses a configured large algorithm is fetched for DNSKEY over TCP on
   first validation with no preceding truncated UDP exchange; counter
   increments observed.

---

# Implementation order

Parts A and B are independent and can land separately, but both depend
on the shared `dnssec.large_algorithms` block — land that first.

0. **Shared:** `DnssecConf`/`Config.Dnssec` + derived set +
   `conf.IsLargeAlgorithm`. Trivial; unblocks A.4 and B.
1. **A — policy plumbing:** config struct fields → runtime struct →
   parser (+ offline validate) → keygen call sites (`sign.go`,
   `key_state_worker.go`, tdns-mp mirror). Build, then policy-parse and
   signing unit tests.
2. **A — correctness review** (A.3.6) and end-to-end keygen test.
3. **A.4 — large-alg-in-bulk warning:** `DnssecPolicyWarning` error
   type (non-impacting) + the three placements (config validation,
   `validate` CLI, key generation). Tests per A.4.6.
4. **B — decision hook:** `Imr.largeAlgs` from the shared set,
   `isLargeAlgorithm`, the B.3 hook (compute `forceTCP`, no wire change
   yet — assert via test).
5. **B — wire path:** `TransportDo53TCP` enum + map entry (fenced from
   selection/config), `forceTCP` param + transport substitution in
   `tryServer`.
6. **B — instrumentation:** encountered-counter + log; issued-count is
   the `Do53TCP` transport counter (free).
7. Sample-config docs for both parts.

Build after each Go change:
`cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
(and `cd tdns-mp/cmd && ... make` after touching the tdns-mp keyworker).
`gofmt -w` every edited `.go` file. Do not modify v1 (`tdns/tdns/`),
`tdns/obe/`, or `tdns/music/`.

# Open questions

**Resolved (2026-05-21):**
 - *Config home for the large-alg list* → shared top-level
   `dnssec.large_algorithms`, consumed by both signer and IMR (see the
   Shared section). Not under `imrengine`.
 - *CSK/large algorithm* → **warn, never reject**, via a non-impacting
   `DnssecPolicyWarning` error type; condition is "large algorithm in a
   zone-signing role," not just `mode: csk` (see A.4).
 - *Per-role algorithm placement* → **nested** under
   `dnssecpolicies.<name>.ksk.algorithm` / `.zsk.algorithm`, grouping
   with the existing per-role lifetime/sigvalidity.

Still open:
1. **Counter exposure.** Which existing surface should report the
   encountered-counter (follow `ClampMetrics`' reader)? The issued-count
   is already the `Do53TCP` transport counter. Identify in B.5.
2. **Real large algorithm.** ML-DSA-44 is algorithm 199 (our
   private-use code point) and is implemented in our miekg/dns fork
   (see `2026-05-13-miekg-dns-pluggable-algorithms-proposal.md`), so a
   genuine PQC KSK on 199 is testable where that fork is in use, with
   `dnssec.large_algorithms: [ 199 ]`. Where the fork is not available,
   substitute a classical stand-in (e.g. RSASHA512 KSK + ECDSAP256 ZSK)
   and set `dnssec.large_algorithms` to match the stand-in KSK alg so
   the warning (A.4) and TCP path (B) still fire.
3. **`SetWarning` sugar.** Skipped for now (A.4.2 reuses `SetError`
   with a non-impacting type, per the `RolloverPolicyWarning`
   precedent). Revisit only if more warning categories appear.

# File-change checklist

Shared:
 - `tdns/v2/config.go` — `DnssecConf` + `Config.Dnssec`; derived
   large-alg set + `conf.IsLargeAlgorithm`.
 - sample YAML — top-level `dnssec.large_algorithms` block.

Part A:
 - `tdns/v2/structs.go` — `DnssecPolicyConf` per-role `Algorithm`
   (nested in `KSK`/`ZSK` sub-structs); `DnssecPolicy`
   `KSKAlgorithm`/`ZSKAlgorithm`.
 - `tdns/v2/ksk_rollover_policy.go` — resolve per-role algs in
   `parseDnssecPolicyConfImpl` and `ValidateDnssecPoliciesFromFile`;
   emit the A.4 coupling warning for the `validate` CLI.
 - `tdns/v2/sign.go` — `EnsureActiveDnssecKeys` lines 367/375/397;
   A.4.5 generation-time warning.
 - `tdns/v2/key_state_worker.go` — standby gen per-role alg.
 - `tdns-mp/v2/key_state_worker.go` — mirror.
 - `tdns/v2/enums.go` — **reuse** `DnssecPolicyWarning` (introduced by
   plan #1); create it here only if #3 lands first.
 - `tdns/v2/parseconfig.go` — A.4.3 zone-config warning in the zone loop
   (`zd.SetError`/`ClearError(DnssecPolicyWarning)`).
 - sample policy YAML.

Part B:
 - `tdns/v2/core/dnsclient.go` — `TransportDo53TCP` enum value;
   `TransportToString` entry; `IsEncryptedTransport` → false; no
   `StringToTransport` mapping. Audit `switch`es over `Transport`.
 - `tdns/v2/cache/rrset_cache.go` — `client[TransportDo53TCP] =
   NewDNSClient(Do53, "53", nil, WithForceTCP())` in the client-map
   builder (`:61-64`).
 - `tdns/v2/imrengine.go` — `Imr.largeAlgs` from the shared set, init
   wiring, `isLargeAlgorithm`.
 - `tdns/v2/dnslookup.go` — decision hook in
   `IterativeDNSQueryWithLoopDetection`; `forceTCP` param on
   `tryServer` + call site; transport substitution (`eff`) at the client
   lookup/counter; keep `TransportDo53TCP` out of `candidateTransports`.
 - encountered-counter (module-level `atomic.Uint64` + getter, alongside
   `ksk_rollover_clamp.go` style); issued-count is the `Do53TCP`
   transport counter (free).
