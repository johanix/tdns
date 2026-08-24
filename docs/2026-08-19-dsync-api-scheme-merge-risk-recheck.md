# Merge-risk recheck: `feature/dsync-api-scheme` (#349)

**Date:** 2026-08-19
**Branch:** `feature/dsync-api-scheme` @ `e5fb3eb`
**Base:** `origin/main` @ `7a68e8e` (the earlier review used `2eb39052`; the
delta since then is this recheck plus #357 cert-init, neither of which
touches the files under review)
**Lens:** *regression of existing TDNS behaviour only.* A buggy DSYNC API is
not a regression. A change to RFC 2136 UPDATE, zone load, config parse,
NOTIFY/UPDATE delegation sync, or SIG(0) key upload is.

This rechecks
[`2026-08-19-dsync-api-scheme-merge-risk-review.md`](2026-08-19-dsync-api-scheme-merge-risk-review.md)
and re-does the same adversarial pass. Finding 1 of that review is **wrong**.
Findings 2 and 3 stand, with Finding 3 broadened. One additional real risk
is listed.

Method: read every non-new-API hunk against `main`, then settle the config
question with a ParseConfig-shaped decode of `cmdv2/auth/tdns-auth.sample.yaml`
rather than by inspecting `go list -deps`.

---

## Verdict on the earlier review

| # | Earlier claim | This recheck |
|---|---------------|--------------|
| 1 | `delegationsync:` is inert on `main` in `tdns-auth` because viper is never populated; merge would start publishing DSYNC RRs | **REFUTED.** `ParseConfig` feeds the processed YAML into the global viper via `viper.ReadConfig`. Parent DSYNC publication already runs on `main` for zones with `delegation-sync-parent`. The struct swap is equivalent on the sample (and documented) YAML shape. |
| 2 | Update-policy name matching changes for all zones, all transports | **CONFIRMED.** Live delta is a security fix plus case-insensitive DNS comparison. |
| 3 | Successful child DDNS updates: SERVFAIL-after-10s → immediate NOERROR | **CONFIRMED**, and it also applies to **TRUSTSTORE-UPDATE** (SIG(0) KEY upload), which the earlier review mentioned only in passing. |

The earlier "proof" decoded the sample into the new struct and compared it
to a viper that had never gone through `ParseConfig`. That experiment does
not describe `tdns-auth`. The `go list -deps ./cmdv2/auth` search looked for
`ReadInConfig` / `SetConfigFile` / `MergeInConfig` and missed `ReadConfig`
inside `v2/parseconfig.go`, which `cmdv2/auth` does depend on.

This matches operational evidence: if viper were empty, `tdns-auth` on `main`
would already be broken in many places (`dnsengine.ports.*`, `external.tmpdir`,
`delegationsync.child.schemes`, …). It is not.

---

## What is actually true about the config reader swap

`ParseConfig` (both trees, `v2/parseconfig.go`):

1. YAML → `configMap`
2. `mapstructure` decode of `configMap` into `Config` (`TagName: "yaml"`,
   **no** `WeaklyTypedInput`)
3. `yaml.Marshal(configMap)` → `viper.ReadConfig`

On `main`, step 2 ignores `delegationsync:` (no struct field); step 3 still
puts it in viper; `PublishDsyncRRs` / `SetupZoneSync` read viper.

On the branch, step 2 fills `Config.DelegationSync`; `SetDelegationSyncConfig`
installs that for the parent publication path. Empirically, against the
shipped sample:

```
STRUCT  schemes=[notify update]  notify.target=notifications.{ZONENAME} port=5354 addrs=[127.0.0.1 ::1]
VIPER   schemes=[notify update]  notify.target=notifications.{ZONENAME} port=5354 addrs=[127.0.0.1 ::1]
```

Identical. `uint16` ports decode from YAML integers. Extra subtrees
(`parent.update.keygen`, `child.update`) are unused by mapstructure and left
for viper, which still reads them. Decode of the sample **succeeds**.

So merging this branch does **not** newly activate DSYNC publication. Zones
that already have `delegation-sync-parent` and a populated `delegationsync.parent`
block already publish NOTIFY/UPDATE DSYNC RRs and A/AAAA at the configured
targets on `main` today.

---

## Findings (regression / visible-behaviour only)

### FINDING A — Stricter decode of `delegationsync:` can fail the whole daemon (MEDIUM)

`mapstructure` without `WeaklyTypedInput` rejects shapes viper currently
accepts. A probe with scalar / quoted forms:

| YAML | viper on `main` | ParseConfig decode after merge |
|------|-----------------|--------------------------------|
| `schemes: notify` | `[]string{"notify"}` | **error** (want slice) |
| `types: CDS` | `[]string{"CDS"}` | **error** (want slice) |
| `addresses: 127.0.0.1` | `[]string{"127.0.0.1"}` | **error** (want slice) |
| `port: "5354"` | `5354` | **error** (`uint16` vs string) |
| `port: 5354` + list forms (the sample) | works | works, values identical |

`decoder.Decode` failing is fatal: `ParseConfig` returns, `tdns-auth` does not
start. The blast radius is the process, not just DSYNC.

All four sample files (`cmdv2/auth`, `cmdv2/agent`, `cmd/auth`, `cmd/agent`)
use the list + unquoted-int shape. A live config copied from those is fine.
A live config that relied on viper's leniency is not.

**Pre-merge check:** the live `delegationsync:` block uses lists for
`schemes` / `types` / `addresses` and an unquoted integer `port`. If it does,
this finding does not apply.

### FINDING B — Update-policy name matching, all zones, all transports (MEDIUM, improvement)

Confirmed. `evalUpdatePolicyRR` replaces `strings.HasSuffix` / `!=` with
`dns.IsSubDomain` / `dns.CanonicalName`. This is on the existing RFC 2136
SIG(0) path (`ApproveChildUpdate` and `ApproveAuthUpdate`), not only the new
API handler.

| case | `main` | merged |
|------|--------|--------|
| `selfsub`, owner `evilchild1.example.`, signer `child1.example.` | approved | refused |
| `self` / `selfsub`, owner `CHILD1.example.`, signer `child1.example.` | refused | approved |
| `selfsub`, principal `.` | approved (every FQDN `HasSuffix` ".") | refused |
| `selfsub`, empty principal | approved | refused |
| `none` / unknown / `""` | refused, EDE 519 | refused, EDE 519 |

Rows 1 and 2 are live. Row 1 is a real sibling-prefix authorization hole.
Row 2 is correct DNS semantics. Rows 3–4 remain latent on the validated
SIG(0) path (`TrustUpdate` returns before `ApproveUpdate` when
`!us.Validated`).

Log field `signer` → `principal` in the two rejection lines. Add/remove
Debug logs still fire; they moved into the shared function.

`policy: none` on the zone side lost its dedicated `case "none"`; the
unified `default` returns the same EDE. Not a behaviour change.

### FINDING C — DDNS waiter: CHILD-UPDATE **and** TRUSTSTORE-UPDATE now answer (MEDIUM, improvement)

On `main`, `UpdateResponder` always waits on `ur.Resp` (10 s,
`UpdateApplyTimeout`) then SERVFAILs with `EDEZoneUpdateApplyTimeout` if
nobody writes the channel. `ZONE-UPDATE` already calls `respond()`.
`CHILD-UPDATE` and `TRUSTSTORE-UPDATE` do not.

So today every *successful*:

- child delegation UPDATE (the DSYNC UPDATE scheme, and any
  `allow-child-updates` RFC 2136 child update)
- SIG(0) KEY upload (`TRUSTSTORE-UPDATE`)

stalls 10 s and answers SERVFAIL, even though the change was applied.

The branch adds `ur.respond(...)` on those branches (and on the unknown-command
and wrong-queue paths). `respond()` is nil-safe and non-blocking; the scanner's
`CHILD-UPDATE` (no `Resp`) is unchanged.

Visible protocol change for those two live paths:

- success: SERVFAIL + EDE timeout → NOERROR, ~immediate
- refusal (`!allowChildUpdates`, no backend): timeout SERVFAIL → prompt
  SERVFAIL + `EDEZoneUpdateNotApplied`

Caveat, not a new bug: `TRUSTSTORE-UPDATE` still swallows per-key
`Sig0TrustMgmt` errors and then `respond(true, nil)` if `tx.Commit()`
succeeds. On `main` that path also "succeeded" in the database and then
lied with a timeout SERVFAIL. After merge it may lie with NOERROR if every
`Sig0TrustMgmt` failed and the commit of an empty/partial tx still
succeeded. Pre-existing error swallowing, newly visible as success.

### FINDING D — `api` already present in `parent.schemes` becomes a real scheme (LOW, config-dependent)

On `main`, `PublishDsyncRRs` treats unknown scheme names as a warn-and-skip.
`api` in `delegationsync.parent.schemes` is therefore **inert today**.

After merge it is a real scheme: DSYNC + URI + TXT are published (defaults
fill in if the `api:` block is absent), and `StartDsyncApiListener` runs.
The sample does **not** put `api` in `schemes:` (the new block is commented
out). A live config that already listed `api` as future-proofing would
change.

Child side: `BestSyncScheme` on `main` **errors the whole function** on an
unknown scheme. `schemes: [api, notify, update]` currently breaks child
sync. After merge it would try API then fall through. That is a fix for a
currently-broken config, not a regression of `[notify, update]`.

The `net.LookupHost` skip is gated on `Scheme == SchemeAPI`. NOTIFY/UPDATE
resolution is unchanged.

---

## Not a regression (checked)

| Area | Result |
|------|--------|
| Viper population in `tdns-auth` | `viper.ReadConfig` in `ParseConfig`. Finding 1's premise is false. |
| Parent DSYNC publication for `notify`/`update` | Same values from the struct as from viper, on the sample shape. Existing RRset still short-circuits (`PublishDsyncRRs` all-or-nothing guard unchanged). |
| `SetupZoneSync` empty `update.target` | New skip avoids generating a SIG(0) key for `"."`. Only differs when the template is empty. Sample has a target. A notify-only parent with no update target is a fix, not a break. |
| Child `delegationsync.child.*` / keygen / key-verification | Still viper. Viper is populated. The "half-done migration" is real as a consistency footnote, not a behaviour change. |
| `UnpublishDsyncRRs` extra URI/TXT deletes | Gated on `api` ∈ schemes via `DsyncApiTargetName`. No change unless `api` is offered. |
| New listener | `SetupDsyncApiRouter` returns nil unless `api` ∈ schemes; `StartDsyncApiListener` returns nil on a nil router. `StartAuth` always starts the engine goroutine; it exits immediately when unconfigured. One extra "starting engine" log line. No socket. Refuses plaintext. |
| New DB table `DsyncApiCredential` | `CREATE TABLE IF NOT EXISTS`, additive. Production `NewKeyDB(..., force=false, ...)`. |
| New management-API route `/dsync-api/credential` | Additive, operator-key subrouter. |
| `DsyncResult.Validated` | Additive field at the end of the struct. NOTIFY/UPDATE do not read it. (Steps 2 and 3 of `DsyncDiscovery` forget to set it; that is an API-scheme bug, not an existing-path regression.) |
| `delegation_sync.go` `case "API"` | Only reached if `BestSyncScheme` returns `"API"`, which requires `api` in `child.schemes`. |
| Dependencies | No `go.mod` / `go.sum` change. |
| Package `init()` | None in new files. |
| Zone load on `PublishDsyncRRs` error | All three `SetupZoneSync` call sites log and continue. Unchanged. |
| Unused-key warnings | On `main`, mapstructure reports the whole `delegationsync` key as unused (and viper still uses it). After merge that warning goes away and `delegationsync.parent.update.keygen` / `delegationsync.child.update` appear instead — still used by viper. Log noise, not a functional change. Do not delete those subtrees because the warning says "unknown". |

---

## Recommendation

Merge, after two config glances rather than a zone-by-zone DSYNC audit:

1. Live `delegationsync:` uses list form for `schemes` / `types` / `addresses`
   and an unquoted integer `port` (Finding A). If yes, ParseConfig will not
   newly fail.
2. Live `delegationsync.parent.schemes` does **not** already contain `api`
   (Finding D). If it does, decide whether publishing the API records (and
   possibly starting a listener) is intended.

Findings B and C change what existing UPDATE clients observe. Both are
corrections of current bugs. Test harnesses or child retry logic calibrated
to "child update = 10 s then SERVFAIL" will need to be recalibrated.

Do **not** treat Finding 1 of the earlier review as a pre-merge checklist
item. Parent DSYNC is already live on `main`.
