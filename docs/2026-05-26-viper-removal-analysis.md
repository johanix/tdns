# Viper removal: analysis (tdns/v2)

Date: 2026-05-26
Status: ANALYSIS — no implementation work scheduled.
Scope: tdns/v2 (this repo). The corresponding tdns-mp analysis lives at
[tdns-mp/docs/2026-05-26-viper-removal-analysis.md](https://github.com/johanix/tdns-mp/blob/main/docs/2026-05-26-viper-removal-analysis.md).

## Motivation

`github.com/spf13/viper` is a *large* dependency. Looking at the
declared (not necessarily linked) transitive deps for viper@1.16.0:

- ~67 declared dependencies including:
  - `cloud.google.com/go/firestore`
  - `github.com/hashicorp/consul/api`
  - `go.etcd.io/etcd/api/v3`, `client/v2`, `client/v3`
  - `google.golang.org/grpc`
  - GCP compute/metadata, etcd, Consul, AWS-related crypt helpers

Go's linker dead-code-eliminates the heavy ones (we don't import
`viper/remote`), so they aren't in the final binaries. But:

- All ~25-30 transitive entries land in `go.sum`.
- Every vulnerability scanner reads `go.sum` and reports CVEs in every
  module listed, **regardless of whether the binary actually links them**.
- Same for SBOM generation, supply-chain audits, and dependency-version
  pinning policies.

The dependency footprint is a real cost paid for an upside (remote
config providers, env-var binding, multi-format support) we don't
actually use. We use viper purely as a key-value lookup against a
YAML file that has already been parsed into the Config struct by
mapstructure.

## Current state in tdns/v2

- `viper.ReadConfig(...)` is called inside `(*Config).ParseConfig`,
  re-feeding the processed config map into viper for compatibility
  with the rest of the codebase.
- Subsequent code reads via `viper.GetString("key.path")`,
  `viper.GetInt(...)`, `viper.GetBool(...)`, `viper.GetDuration(...)`,
  `viper.GetStringSlice(...)`.
- The Config struct exists in parallel and is also populated by
  mapstructure from the same map. Some config sections have struct
  representation; some do not.

### Numbers (audit 2026-05-26)

- **99 viper-Get sites** across 39 files in tdns/v2 (excluding cli/).
- **59 unique keys** in literal form, plus 4 sites with computed keys.
- **5 keys** map cleanly to existing Config struct paths with yaml tags.
- **10 keys** have a corresponding Go field on the struct hierarchy
  but the field has no `yaml:"..."` tag — mapstructure doesn't
  populate them; viper reads directly from the map.
- **~55 keys** have no struct representation at all. Whole config
  sections (audit, delegationsync, validator, scanner, keystate,
  verifyengine, childsync, large parts of dnsengine and service)
  are viper-only.

## The structural split

The pattern of which config sections have structs versus which are
viper-only is not random. Sections that grew up with the original
config struct design (DnsEngine, Service, MultiProvider) have struct
fields. Sections added later as engines accumulated (audit web,
delegation sync, validator engine, scanner) reach the config via
viper because adding a struct field would have been more work at the
time. Coexistence has been the actual state of the codebase for a
long time.

This is not accidental, but it is unfortunate. Removing viper means
formalizing every existing viper-only key as a real struct field with
a `yaml:"..."` tag.

## Audit categories

### MAPPED (5 keys) — already work via struct field

These are call sites where the field exists and is yaml-tagged.
Replacing `viper.GetString("dnsengine.certfile")` with
`conf.DnsEngine.CertFile` is mechanical.

- `dnsengine.certfile`         → `conf.DnsEngine.CertFile`
- `dnsengine.keyfile`          → `conf.DnsEngine.KeyFile`
- `imrengine.certfile`         → `conf.Imr.CertFile`
- `imrengine.keyfile`          → `conf.Imr.KeyFile`
- `log.file`                   → `conf.Log.File`

### PARTIALLY MAPPED (10 keys) — field exists, yaml tag missing

These have a Go field, but no `yaml:"..."` tag, so mapstructure
doesn't populate the field from the YAML. Viper reads the YAML
directly via the in-memory config map and bypasses the struct.
Trivial fix: add the missing tags.

- `agent.remote.beatinterval`  → `MultiProvider.Remote.BeatInterval`
- `agent.remote.locateinterval`→ `MultiProvider.Remote.LocateInterval`
- `db.file`                    → `Db.File`
- `service.debug`              → `Service.Debug`
- `multi-provider.syncengine.intervals.beatinterval`        → `MultiProvider.Syncengine.Intervals.BeatInterval` (no tag)
- `multi-provider.syncengine.intervals.discoveryretry`      → `MultiProvider.Syncengine.Intervals.DiscoveryRetry` (no tag)
- `multi-provider.syncengine.intervals.hello_fast_attempts` → `MultiProvider.Syncengine.Intervals.HelloFastAttempts` (no tag)
- `multi-provider.syncengine.intervals.hello_fast_interval` → `MultiProvider.Syncengine.Intervals.HelloFastInterval` (no tag)
- `multi-provider.syncengine.intervals.helloretry`          → `MultiProvider.Syncengine.Intervals.HelloRetry` (no tag)
- `multi-provider.syncengine.intervals.reconcile`           → `MultiProvider.Syncengine.Intervals.Reconcile` (no tag)

### FULLY MISSING (~55 keys) — no struct field at all

Whole sections need new sub-structs:

| Section | Keys | Used by |
|---|---|---|
| `delegationsync.*` (parent + child) | 21 | `delegation_sync.go`, `truststore_verify.go`, `ops_dsync.go` |
| `dnsengine.{debug,verbose,ports.*}`  | 5  | `do53.go`, `dot.go`, `doh.go`, `doq.go` |
| `scanner.*`                          | 4  | `scanner.go` |
| `validator.*`                        | 3  | `validatorengine.go`, `truststore_verify.go` |
| `service.{maxrefresh,minrefresh,resign}` | 3 | `refreshengine.go` |
| `server.{hostname,id,version}`       | 3  | various |
| `childsync.*`                        | 3  | `childsync_utils.go` |
| `keystate.*`                         | 2  | `keystate.go` |
| `verifyengine.*`                     | 2  | `keybootstrapper.go` |
| `external.{filedir,tmpdir}`          | 2  | `scanner.go` |
| `resignerengine.*`                   | 2  | (referenced via computed key) |
| `dns.resolvers`, `resolver.address`, `cli.maxwait`, `common.command`, `musicd.rootCApem` | 5 | various |

(Detailed key list available in the audit appendix at the bottom.)

## Effort estimate

This is **not** an incidental cleanup. Realistic estimate:

- **3-5 hours**: design the new sub-structs. Especially
  `DelegationSyncConf` has deep nesting (Parent.Update.KeyVerification.
  MaxAttempts etc.) and needs care.
- **2-3 hours**: add the fields with correct yaml tags. Verify each
  config sample file (in `cmd*/`) parses correctly.
- **4-6 hours**: replace ~99 viper call sites with struct access. Some
  require plumbing `*Config` to where it's currently absent (engines
  that took a config fragment, not the whole `*Config`).
- **3-5 hours**: testing each daemon with real configs. Catch
  mismatches between "old viper key" and "new struct field default
  value". Viper returns zero-value for missing keys; struct field is
  also zero-value, but the *defaults* may have been set elsewhere
  (in code that explicitly sets `viper.SetDefault`, or just relied on
  the field being unset).
- **2-4 hours**: surprises.

**Total: 15-25 hours of focused work, spread across multiple sessions.**

## Strategic options

### (A) Commit to full removal

End state: no viper in tdns/v2, ~25-30 fewer go.sum entries,
substantially cleaner config story (Config struct is the authoritative
description of all config). Pure win long-term; real cost upfront.

### (B) Defer; track but don't schedule

Document the state (this doc) and revisit when a specific viper-related
problem surfaces (e.g. a CVE in a viper transitive dep, or vulnerability
scanner noise becoming intolerable). The cost of waiting is the
ongoing supply-chain noise.

### (C) Incremental opportunistic removal

Whenever code is touched for other reasons, convert any viper reads
in that file to struct reads. Over months, viper usage shrinks
organically. No focused refactor cost. The endpoint is asymptotically
the same as (A) but the timeline is open-ended.

## Recommendation

(C) for now, with (A) as the agreed-upon endgame. Document in CLAUDE.md
that touching a file with `viper.GetX` calls is a hint to convert them
during the same change.

Schedule (A) explicitly when one of these triggers fires:
- A CVE in a viper transitive dep that we'd otherwise have to ignore.
- The vulnerability scan noise crosses a threshold that costs more
  than 20 hours of audit work to triage.
- An external consumer of tdns/v2 complains about the go.sum footprint.

## Audit appendix: full key list

Keys grouped by category, with destination paths or "MISSING".

**MAPPED — already work as struct field + yaml tag:**

```
dnsengine.certfile     → conf.DnsEngine.CertFile
dnsengine.keyfile      → conf.DnsEngine.KeyFile
imrengine.certfile     → conf.Imr.CertFile
imrengine.keyfile      → conf.Imr.KeyFile
log.file               → conf.Log.File
```

**PARTIALLY MAPPED — field exists, missing yaml tag:**

```
agent.remote.beatinterval                              → MultiProvider.Remote.BeatInterval
agent.remote.locateinterval                            → MultiProvider.Remote.LocateInterval
db.file                                                → Db.File
service.debug                                          → Service.Debug
multi-provider.syncengine.intervals.beatinterval       → MultiProvider.Syncengine.Intervals.BeatInterval
multi-provider.syncengine.intervals.discoveryretry     → MultiProvider.Syncengine.Intervals.DiscoveryRetry
multi-provider.syncengine.intervals.hello_fast_attempts→ MultiProvider.Syncengine.Intervals.HelloFastAttempts
multi-provider.syncengine.intervals.hello_fast_interval→ MultiProvider.Syncengine.Intervals.HelloFastInterval
multi-provider.syncengine.intervals.helloretry         → MultiProvider.Syncengine.Intervals.HelloRetry
multi-provider.syncengine.intervals.reconcile          → MultiProvider.Syncengine.Intervals.Reconcile
```

**FULLY MISSING — no struct field at all:**

```
agent.update.keygen.algorithm
childsync.update-a
childsync.update-aaaa
childsync.update-ns
cli.maxwait
common.command
delegationsync.child.schemes
delegationsync.child.update.keygen.algorithm
delegationsync.child.update.keygen.generator
delegationsync.child.update.keygen.mode
delegationsync.leader-election-ttl
delegationsync.parent.bootstrap.methods
delegationsync.parent.notify.addresses
delegationsync.parent.notify.port
delegationsync.parent.notify.target
delegationsync.parent.notify.types
delegationsync.parent.schemes
delegationsync.parent.update.addresses
delegationsync.parent.update.key-verification.max-attempts
delegationsync.parent.update.key-verification.mechanisms
delegationsync.parent.update.key-verification.require-dnssec
delegationsync.parent.update.key-verification.retry-interval
delegationsync.parent.update.keygen.algorithm
delegationsync.parent.update.port
delegationsync.parent.update.target
delegationsync.parent.update.types
dns.resolvers
dnsengine.debug
dnsengine.ports.doh
dnsengine.ports.doq
dnsengine.ports.dot
dnsengine.verbose
external.filedir
external.tmpdir
keystate.allow_auto_bootstrap
keystate.require_manual_bootstrap
musicd.rootCApem
resignerengine.interval
resignerengine.keygen.mode
resolver.address
scanner.at-apex.checks
scanner.at-apex.interval
scanner.interval
scanner.options
server.hostname
server.id
server.version
service.maxrefresh
service.minrefresh
service.resign
validator.active
validator.dnskey.trusted.file
validator.sig0.trusted.file
verifyengine.attempts
verifyengine.retry_interval
```
