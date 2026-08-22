# Adversarial merge-risk review: `feature/dsync-api-scheme` (#349)

**Date:** 2026-08-19
**Branch under review:** `feature/dsync-api-scheme` @ `e5fb3eb4`
**Base:** `origin/main` @ `2eb39052`
**Size:** 35 files, +5655 / −111 (of which ~1300 lines are tests, ~1300 docs)

**Lens:** *regression risk only.* tdns has no DSYNC API support today, so a
DSYNC API that is imperfect is not a regression. The question this review
answers is the other one: **what works correctly on `main` today that merging
this branch would break or degrade?**

Method: build + test both trees side by side, then read every diff hunk that
touches code reachable without the new scheme, and settle the interesting ones
with differential tests run against both trees rather than by reading.

---

## Verdict

**Mergeable, with one pre-merge config audit.**

The risk is not in the ~5000 lines of new DSYNC API code — that code is
correctly gated and stays inert unless an operator opts in. The risk is
concentrated in roughly fifteen lines that swap a config reader.

| # | Finding | Severity | Nature |
|---|---------|----------|--------|
| 1 | `delegationsync:` goes from inert to live in `tdns-auth` | **HIGH** | Dormant config activates; new records published into served zones |
| 2 | Update-policy semantics change for all zones, all transports | MEDIUM | Security fix + correctness fix, but on live paths |
| 3 | DDNS child updates: SERVFAIL-after-10s becomes immediate NOERROR | MEDIUM | Fix, but visible protocol behavior change |

Findings 2 and 3 are both improvements. They are listed because they change
what existing clients observe, not because they are wrong.

---

## FINDING 1 — `delegationsync:` goes from inert to live in `tdns-auth` (HIGH)

### What changes

`v2/ops_dsync.go` and `v2/zone_utils.go` switch from
`viper.GetString("delegationsync...")` to a typed struct
(`DelegationSyncConfig()`, new in `v2/config_delegationsync.go`) decoded from
the same YAML. This reads as a pure refactor. It is not, because:

**The global viper singleton is never populated in `tdns-auth` or
`tdns-agent`.**

`go list -deps ./cmdv2/auth` returns only:

```
github.com/johanix/tdns/v2
github.com/johanix/tdns/v2/{algorithms,core,cache,edns0,notifyerrors}
github.com/johanix/dnssec-algorithms/pkcs8
```

Nothing in that graph calls `viper.ReadInConfig` / `SetConfigFile` /
`MergeInConfig`. Only `tdns-cli`, `tdns-imr` and `tdns-debug` populate viper,
and none of those load zones in auth mode. Verified for `cmd/auth`,
`cmd/agent`, `cmdv2/auth`, `cmdv2/agent` — all zero viper references.

Consequently, on `main` today in `tdns-auth`:

- `viper.GetStringSlice("delegationsync.parent.schemes")` → `[]`, so
  `PublishDsyncRRs` iterates an empty list and **publishes nothing**;
- `viper.GetString("delegationsync.parent.update.target")` → `""`, so
  `SetupZoneSync` computes `dns.Fqdn("")` = `"."`, passes
  `dns.IsDomainName(".")`, and calls `ParentSig0KeyPrep(".")` — generating a
  SIG(0) keypair for the **root**. (This is precisely the bug the branch's own
  comment describes and fixes.)

### Proof

Decoding the *shipped* sample config `cmdv2/auth/tdns-auth.sample.yaml` — whose
`delegationsync:` block is active, not commented out — the way `ParseConfig`
does, and comparing against what viper sees:

```
STRUCT  schemes=[notify update]
STRUCT  notify.target="notifications.{ZONENAME}" port=5354 types=[CDS CSYNC] addrs=[127.0.0.1 ::1]
STRUCT  update.target="updates.{ZONENAME}"       port=5354 types=[ANY]       addrs=[127.0.0.1 ::1]
STRUCT  bootstrap.methods=""

VIPER   parent.schemes=[]
VIPER   parent.update.target=""
VIPER   child.schemes=[]

MAIN    SetupZoneSync updateTarget would be "."
```

### Consequences after merge

For **every zone with the `delegation-sync-parent` option** (the gate is
`zd.Options[OptDelSyncParent]` in `SetupZoneSync`):

1. `_dsync.<zone>` gains DSYNC RRs — CDS/CSYNC via NOTIFY and ANY via UPDATE,
   both on port 5354.
2. `notifications.<zone>` and `updates.<zone>` gain A/AAAA records. With the
   shipped sample values that is **`127.0.0.1` and `::1` published into a
   served zone**.
3. Serial bump and re-signing on DNSSEC-signed zones.
4. `ParentSig0KeyPrep` runs against the real target instead of `"."`,
   generating a new keypair and publishing a KEY RR at a new name.
5. Children performing DSYNC discovery start finding a parent that advertises
   NOTIFY and UPDATE, and **begin sending delegation-sync traffic to a
   subsystem that is dormant today**.

### Mitigating factors (verified)

- All three `SetupZoneSync` call sites (`refreshengine.go:785`,
  `dynamic_primary.go:434`, `parseconfig.go:1152`) **log the error and
  continue**. A `delegationsync:` block that is incomplete enough to make
  `PublishDsyncRRs` return `"... config broken"` cannot abort zone loading.
- `MaybeAddAddressRR` only appends to a local slice; a mid-loop error discards
  the whole RRset rather than leaving the zone half-updated.
- Ordering is correct: `SetDelegationSyncConfig` is called at
  `parseconfig.go:~500`, well before `ParseZones` reaches `SetupZoneSync` at
  `~1152`, on both first start and reload.

### Secondary concern: the migration is half done

The parent side now reads the struct; the child side still reads viper:

| Call site | Reader |
|---|---|
| `ops_dsync.go` (publication), `zone_utils.go:982` | struct (live after merge) |
| `childsync_utils.go:403`, `zone_utils.go:1005` — `child.schemes` | viper (still dead) |
| `sig0_utils.go:191`, `ops_key.go:109` — keygen | viper (still dead) |
| `truststore_verify.go:87..181` — key-verification | viper (still dead) |

So after the merge the parent half of delegation sync is live and the child
half is still inert in `tdns-auth`. That asymmetry is worth knowing before
someone debugs it from scratch.

### Recommended action

This is a **config audit**, not a code fix. Before merging, enumerate the zones
carrying `delegation-sync-parent` and decide per zone whether the DSYNC records
that will now be published — with the addresses currently in the config — are
what is wanted. Fix the `addresses:` or drop the block/option accordingly.

---

## FINDING 2 — Update-policy semantics change for every zone, on every transport (MEDIUM)

Extracting `evalUpdatePolicyRR` (new `v2/update_policy_eval.go`) out of
`ApproveChildUpdate` and `ApproveAuthUpdate` also replaced `strings.HasSuffix` /
`!=` with label-aligned, case-insensitive DNS-name comparison
(`nameWithinPrincipal` → `dns.IsSubDomain` / `dns.CanonicalName`).

This governs `updatepolicy.child` **and** `updatepolicy.zone`, on the existing
RFC 2136 SIG(0) path — not only the new API scheme. The branch's own comment
says so explicitly, and it is correct to.

Differential test, same file compiled against both trees:

| case | `main` | merged |
|---|---|---|
| `selfsub`, owner `evilchild1.example.`, signer `child1.example.` | **approved** | refused |
| `self` / `selfsub`, owner `CHILD1.example.`, signer `child1.example.` | refused | **approved** |
| `selfsub`, principal `.` (root) | approved (everything) | refused |
| `selfsub`, principal `""` | approved | refused |
| `selfsub`, relative signer `child1.example` (no trailing dot) | refused | approved |
| policy `none` / `bogus` / `""` | refused, EDE 519 | refused, EDE 519 (unchanged) |

**Row 1 is a genuine security fix.** On `main`, `strings.HasSuffix` makes the
holder of `child1.example.`'s key authoritative over a differently-named
sibling delegation `evilchild1.example.`.

**Row 2 is correct DNS semantics** — case carries no meaning in DNS, and `main`
refuses legitimate updates over it.

**Rows 3–5 are latent, not live.** `TrustUpdate` (`sig0_validate.go:344`)
returns an error on every path where `us.Validated == false` — both the
`len(us.Signers) == 0` branch and the explicit `!us.Validated` guard — so the
responder returns before `ApproveUpdate`. `ApproveChildUpdate` is therefore
never reached with an empty `SignerName`, and its `unvalidatedKeyUpload` bypass
is already unreachable on `main`. The root-principal row (3) only bites if a
zone genuinely has a root-named SIG(0) principal — plausible *only* because
`main` has been generating exactly such keys (see Finding 1), which this branch
also stops doing.

**Net live delta: rows 1 and 2, both improvements.** Worth one confirmation
that no lab zone depends on the sibling-prefix behavior of row 1.

Minor observability note: the per-record `Debug` logging of add/remove and the
`"owner"`/`"signer"` structured fields move into the shared function; the
field name changes from `signer` to `principal`. Any log tooling keyed on
`signer=` in these two messages needs updating.

---

## FINDING 3 — DDNS child updates: SERVFAIL-after-10s becomes immediate NOERROR (MEDIUM)

On `main`, `UpdateResponder` sends `Cmd: "CHILD-UPDATE"` to `UpdateQ` with a
buffered `Resp` channel and then waits on it. But `ZoneUpdaterEngine`'s
`CHILD-UPDATE` branch **never calls `respond()`**. So every *successful* child
delegation update over DDNS stalls the full `UpdateApplyTimeout` (10 s) and then
answers **SERVFAIL + `EDEZoneUpdateApplyTimeout`**.

The branch adds `ur.respond(...)` on every exit of that branch, plus
`TRUSTSTORE-UPDATE` commit/rollback, the unknown-command default, and
`DEFERRED-UPDATE`.

This is a fix, but it changes what children observe on a live path:

- rcode SERVFAIL → NOERROR on success
- latency 10 s → ~immediate
- refusal paths (`!allowChildUpdates`, `backend == nil`) now return
  `EDEZoneUpdateNotApplied` promptly instead of `EDEZoneUpdateApplyTimeout`
  after 10 s

Test harnesses, child retry logic, or monitoring calibrated against today's
behavior will read differently.

**Safety check:** `respond()` (`zone_updater.go:76`) is nil-safe and
non-blocking (`select` with `default`), and is documented as safe to call more
than once. It **cannot** wedge the single `ZoneUpdaterEngine` goroutine that
serves every zone. Verified by reading, and the merged suite is clean under
`-race`.

---

## Checked and clear

Recorded so these do not get re-litigated.

| Area | Result |
|---|---|
| Build (all modules, both trees) | Identical failure set. Pre-existing only: generated `version.go` (`appName`/`appVersion`/`appDate`), absent `v2/hpke` and `obe` replace dirs. **No new breakage.** |
| `go vet ./...` (v2, merged) | Clean |
| Tests | 1012 → 1112 `go test` runs, all pass on both trees. **Zero tests removed** (40 new test functions added). |
| `-race` | Merged v2 suite clean |
| Dependencies | **No `go.mod` / `go.sum` change at all** |
| External consumers (`tdns-mp` compiles against `v2`) | Exported surface purely additive: **102 symbols added, 0 removed**. `DsyncResult` gains a `Validated` field; every construction in-repo is keyed. |
| Package init side effects | **No `init()`** in any new file |
| New DSYNC API listener | `SetupDsyncApiRouter` returns nil unless `api` ∈ `delegationsync.parent.schemes`; `StartDsyncApiListener` returns nil on a nil router. **No socket bound unless opted in**, no default listen address. Refuses to start without TLS rather than falling back to plaintext. |
| New DB table `DsyncApiCredential` | `CREATE TABLE IF NOT EXISTS`, additive, no migration of existing tables |
| New management-API route | `/dsync-api/credential`, additive, under the existing operator-key subrouter |
| `UnpublishDsyncRRs` extra URI/TXT deletes | Gated on `api` ∈ schemes via `DsyncApiTargetName`; no change for existing deployments |
| Sample config | New `api:` block added **commented out**; `schemes:` unchanged at `[notify, update]` |
| `childsync_utils.go` `BestSyncScheme` | `net.LookupHost` skip is conditional on `Scheme == SchemeAPI`; NOTIFY/UPDATE path byte-identical |
| Merge cleanliness | The 3 commits `main` has that the branch lacks touch **zero** of the same files — the clean merge is structural, not a lucky textual merge |

---

## Recommendation

Merge, but treat Finding 1 as a pre-merge checklist item rather than a
post-merge surprise. Concretely:

1. List zones with `delegation-sync-parent`.
2. For each, confirm the DSYNC records that will now be published — including
   the `addresses:` currently in the config — are intended.
3. Merge.

Everything else in this branch is either an improvement or provably inert.

### Follow-up worth tracking separately

- Finish the viper → struct migration for the `delegationsync.child.*` and
  keygen/key-verification subtrees, so the two halves agree.
- Consider whether `PublishDsyncRRs`'s all-or-nothing "existing DSYNC RRset is
  the operator's" guard should become per-scheme; the branch deliberately
  leaves it alone, and documents why.
