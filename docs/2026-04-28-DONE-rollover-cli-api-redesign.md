# Auto-rollover CLI redesign: move off direct DB access, talk to the
# server via API

Author: Johan / Claude
Date: 2026-04-28
Status: draft (no implementation work yet)

## Background

The `auto-rollover` subcommands under `tdns-cliv2 auth keystore dnssec`
operate today by opening the signer's keystore sqlite file directly:

   * `status`, `when` — read RolloverZoneState + RolloverKeyState +
     DnssecKeyStore.
   * `asap`, `cancel`, `reset`, `unstick` — write the same tables.

Implementation entry points: `openKeystoreForCli` in
`tdns/v2/cli/ksk_rollover_cli.go` calls `Conf.MainInit` to load the
daemon's full config (so it can find `db.file`), then opens the sqlite
file with `tdns.NewKeyDB(dbPath, false, nil)`.

This has four operational problems:

1. The CLI host needs read-write access to the daemon's sqlite file.
   That forces all ops onto the same machine and makes filesystem
   permissions a load-bearing security boundary.
2. The CLI must load (and template-expand, and dnssec-policy-resolve)
   the daemon's full config just to discover `db.file`. When the
   running daemon and the CLI invocation see different config files
   (e.g. CLI falls back to the default `/etc/tdns/tdns-cli.yaml` while
   the daemon runs from `/etc/tdns/tdns-auth.yaml`) the CLI silently
   reads from a stale or unrelated keystore. This bit us during the
   fast-roller debug session on 2026-04-28 — the CLI reported "no
   DNSSEC policy" because it was reading the wrong config.
3. Writers race against the running daemon's tick loop. `reset`,
   `unstick`, and `asap` all mutate state that `RolloverAutomatedTick`
   re-reads on the next tick. Single-writer sqlite plus the BEGIN/
   COMMIT discipline in `kdb.Begin` keeps it from corrupting data, but
   the *semantics* of "I just cleared last_rollover_error / nulled the
   submitted range" depend on the operator manually stopping the
   daemon first, which is undocumented and error-prone.
4. There is no path to remote operation. Running ops against several
   signers in a lab — or against a production signer from a jump
   host — requires either ssh + sudo + local CLI invocation or a
   parallel side channel (Ansible, etc.).

The right shape is the same one already used by `tdns-cliv2 auth
zone ...` and friends: the CLI is a thin HTTP client, the signer
exposes endpoints under `/api/v1/rollover/`, and all keystore writes
happen in-process under the daemon's own locks.

## Goals (acceptance criteria)

1. Every `auto-rollover` subcommand has an HTTP endpoint on the signer
   API server. Read endpoints are GET; mutating endpoints are POST.
2. The CLI's default mode is "talk to the API server." Direct keystore
   access is preserved only as an explicit `--offline` mode for
   postmortem use when the daemon is down.
3. No CLI subcommand requires loading the daemon's full config in
   default (online) mode. The CLI in online mode needs only:
   API server URL, API key, and the zone name on the command line.
4. Concurrency: server-side handlers serialize against the running
   tick loop. An operator does not have to stop the daemon before
   running `unstick` / `reset` / `asap` / `cancel`.
5. The on-disk wire format (sqlite schema, RolloverZoneState columns,
   RolloverKeyState columns) is unchanged. This is purely a transport
   redesign.

## Out of scope

* Auth redesign. The signer API already uses `X-API-Key` header
   authentication via `apiKeyAuthMiddleware` in
   `tdns/v2/apirouters.go`; reuse that as-is. (My earlier suggestion
   to use SIG(0) for admin endpoints was wrong — SIG(0) is the wire
   auth for DNS UPDATE, not the API.)
* Multi-tenant ACLs. A single API key is enough to gate all rollover
   operations the same way it gates today's `/zone` endpoints.
* Server-side rollover policy or scheduling logic. Untouched.
* The mp-signer and other roles that maintain rollover state
   independently. This doc is scoped to `tdns-auth` (the role that
   owns the canonical rollover state machine).

## Endpoint design

Mount under `/api/v1/rollover/`. Reuse the existing zone-API style:
JSON request bodies (`application/json`), JSON response bodies, the
existing X-API-Key middleware, error semantics matching `apihandler_zone.go`
(HTTP 200 with `{"error": true, "errorMsg": "..."}` for
operationally-expected failures, HTTP 4xx/5xx only for protocol-level
problems).

| Subcmd     | Method | Path                       | Body                                       | Response                                             |
|------------|--------|----------------------------|--------------------------------------------|------------------------------------------------------|
| `status`   | GET    | `/rollover/status`         | `?zone=cpt.p.axfr.net.`                    | full RolloverStatus struct (see below)               |
| `when`     | GET    | `/rollover/when`           | `?zone=cpt.p.axfr.net.`                    | `{earliest, fromIdx, toIdx, gates[]}`                |
| `asap`     | POST   | `/rollover/asap`           | `{"zone": "..."}`                          | `{requestedAt, earliest, fromIdx, toIdx}`            |
| `cancel`   | POST   | `/rollover/cancel`         | `{"zone": "..."}`                          | `{cleared: bool}`                                    |
| `reset`    | POST   | `/rollover/reset`          | `{"zone": "...", "keyid": 62999}`          | `{cleared: bool}`                                    |
| `unstick`  | POST   | `/rollover/unstick`        | `{"zone": "..."}`                          | `{clearedKeys: int}`                                 |

The split GET-for-reads / POST-for-mutations matters: it lets ops
folks hit `status` and `when` from a browser or `curl` for ad-hoc
checks without worrying about accidentally triggering a write.

## Response shapes (server-side structs)

These belong in `tdns/v2/core/messages.go` (or a new
`messages_rollover.go` next to it) so both server and CLI import them
from one place.

```go
// RolloverStatus is the full report rendered by `auto-rollover status`.
// Field names mirror the sqlite columns the CLI already reads today.
type RolloverStatus struct {
   Zone               string             `json:"zone"`
   Phase              string             `json:"phase"`
   PhaseAt            string             `json:"phaseAt,omitempty"`
   InProgress         bool               `json:"inProgress"`
   Submitted          *DSRange           `json:"submitted,omitempty"`
   Confirmed          *DSRange           `json:"confirmed,omitempty"`
   ManualRequestedAt  string             `json:"manualRequestedAt,omitempty"`
   ManualEarliest     string             `json:"manualEarliest,omitempty"`
   Observe            *ObserveStatus     `json:"observe,omitempty"`
   KSKs               []RolloverKeyEntry `json:"ksks"`
   ZSKs               []RolloverKeyEntry `json:"zsks"`
   Policy             *PolicySummary     `json:"policy,omitempty"`
}

type DSRange struct {
   Low  int `json:"low"`
   High int `json:"high"`
}

type RolloverKeyEntry struct {
   KeyID            uint16 `json:"keyid"`
   ActiveSeq        *int   `json:"activeSeq,omitempty"`
   State            string `json:"state"`
   Published        string `json:"published,omitempty"`
   StateSince       string `json:"stateSince,omitempty"`
   LastRolloverErr  string `json:"lastRolloverError,omitempty"`
}
```

Verbose / "show CSK" toggling stays a CLI rendering concern; the
server always returns the full struct.

## Server-side implementation

Three files:

* `tdns/v2/apihandler_rollover.go` — HTTP handlers, registered from
   the existing router setup in `apirouters.go`.
* `tdns/v2/rollover_api_funcs.go` — pure functions that take
   `(*KeyDB, zone, ...)` and return the response structs. These are
   thin wrappers over what the CLI does today: `LoadRolloverZoneRow`,
   `GetDnssecKeysByState`, `ComputeEarliestRollover`,
   `SetManualRolloverRequest`, `ClearManualRolloverRequest`,
   `ClearLastRolloverError`, `UnstickRollover`. Most of the existing
   CLI rendering logic moves here verbatim; just stops calling
   `fmt.Printf` and starts populating a struct.
* `tdns/v2/cli/ksk_rollover_cli.go` — CLI gets a thin client per
   subcommand.

### Concurrency

The signer's `RolloverAutomatedTick` runs on the rollover worker
goroutine. API mutating handlers MUST take the same lock the tick
takes, so that e.g. `unstick` can't run interleaved with a
`pending-parent-push` advance. Two options:

1. Add a per-zone `sync.Mutex` to `RolloverZoneRow` (or to a parallel
   in-memory map keyed by zone) and have both the tick and the API
   handler take it.
2. Push the actual mutation through a request channel consumed by the
   rollover worker, the same pattern as `DnsUpdateQ` /
   `DeferredUpdateQ`. The handler waits on a per-request response
   channel.

Option 2 is more invasive but matches the rest of the codebase. **My
recommendation: option 1 for v1**, with a clear comment explaining
that option 2 is the long-term shape if the rollover worker grows
more state. The current handlers are short-lived and atomic; per-zone
mutexes are cheap.

Read endpoints (`status`, `when`) do not need the lock — they're
sqlite reads under the existing kdb connection, and sqlite WAL mode
already gives us snapshot reads while writers are in flight.

## Client side (CLI)

Each subcommand becomes:

```go
func newAutoRolloverUnstickCmd() *cobra.Command {
   c := &cobra.Command{
      Use: "unstick",
      ...,
      Run: func(cmd *cobra.Command, args []string) {
         tdns.Globals.App.Type = tdns.AppTypeCli
         api := GetApiClient("auth", true)
         var resp tdns.RolloverUnstickResponse
         err := api.PostJSON("/api/v1/rollover/unstick",
            tdns.RolloverUnstickRequest{Zone: dns.Fqdn(zonename)},
            &resp)
         ...
      },
   }
   ...
}
```

`GetApiClient("auth", ...)` already exists; the CLI knows how to dial
the auth daemon's API server using the credentials configured in the
CLI's own `tdns-cli.yaml`. It does *not* need to load the daemon's
zone or template config in this mode.

### `--offline` fallback

A small minority of operations are useful when the daemon is *down*
(postmortem, recovering from a wedged signer, etc.):

* `status` — show what state the zone was left in.
* `unstick`, `reset` — manually edit the keystore so the next start
   doesn't immediately re-wedge.

For these, keep the current direct-DB code path behind an explicit
`--offline` flag:

```
tdns-cliv2 auth keystore dnssec auto-rollover unstick \
    --zone cpt.p.axfr.net. --offline
```

`--offline` is the only mode that requires `--config <daemon-config>`,
so the existing config-loading machinery stays scoped to that flag.
Default mode does not load the daemon config at all.

`when` and `asap` should NOT have an offline mode — they need a
running daemon to schedule against. (Computing `Earliest` offline is
technically possible but operationally meaningless: the daemon won't
see the `manual_rollover_*` rows until it next reads them, and if
the daemon is down there's no point scheduling.) `cancel` similarly
is online-only — if the daemon is down, the manual request isn't
firing anyway.

## Phases

### Phase 1 — server-side scaffolding

1. Add `messages_rollover.go` with request/response structs.
2. Add `apihandler_rollover.go` with one route + handler stub per
   subcommand. All handlers initially return "not implemented" with
   structured error.
3. Wire into `apirouters.go` under the existing X-API-Key subrouter
   for the auth daemon role.
4. Add per-zone mutex (option 1 above) in `ksk_rollover_zone_state.go`
   or a new `rollover_lock.go`.
5. Update `RolloverAutomatedTick` to take the per-zone lock around
   its phase advances.

### Phase 2 — read endpoints

1. Implement `status` server-side by moving the existing CLI rendering
   logic into `rollover_api_funcs.go::ComputeRolloverStatus`. The CLI's
   pretty-printing stays in the CLI; the API returns the struct.
2. Implement `when` similarly — wraps `ComputeEarliestRollover`.
3. Convert the CLI `status` and `when` subcommands to HTTP-by-default,
   keeping `--offline` as a flag that takes the old code path.
4. Verify both binaries build clean; run a manual smoke test against
   a lab signer.

### Phase 3 — write endpoints

1. Implement `cancel`, `reset`, `unstick`, `asap` server-side. Each
   handler takes the per-zone mutex, calls the existing function
   (`ClearManualRolloverRequest`, `ClearLastRolloverError`,
   `UnstickRollover`, `SetManualRolloverRequest`), and returns the
   response struct.
2. Convert the four CLI subcommands one at a time. Each conversion is
   its own commit so that any regression bisects cleanly.

### Phase 4 — cleanup

1. Once all subcommands are converted and exercised in the lab,
   audit `openKeystoreForCli` callers. Anything outside the
   `--offline` paths should be gone.
2. The `[WARN/config] no config file specified` warning that fires
   today on every CLI invocation should disappear in the default
   (online) mode, because the CLI no longer calls `MainInit` for the
   daemon config.

## Risks / open questions

1. **Lock granularity.** A single zone's tick is fast, so a per-zone
   mutex blocking an API handler for milliseconds is fine. If the
   tick ever grows long-running work (e.g. inline DNS UPDATE retries
   under the lock), reconsider option 2.
2. **`--offline` write paths.** Allowing `unstick --offline` while the
   daemon is *up but unresponsive* is a footgun — the operator might
   think they're surgically editing dead state when really they're
   racing a live writer. Mitigation: `--offline` writers should
   refuse if a tdns-auth process is currently running and holding the
   sqlite file open (lockfile check, or a `SELECT` of a sentinel
   value the daemon writes on startup). Alternative: require
   `--offline --force` for writers and accept the operator owns the
   risk.
3. **Schema versioning.** None of this changes the schema, so no
   migration. The risk surface is the response struct: once
   third-party tooling starts consuming `/rollover/status`, the JSON
   field names become a contract. Pick names carefully in Phase 1
   and don't rename later.
4. **Other roles.** `tdns-mp-signerv2` and any future signer role
   will need parallel endpoints. Out of scope for this doc, but the
   `messages_rollover.go` structs should be designed to be reusable
   across roles (i.e. don't bake "auth" into field names).

## Estimated effort

Rough sketch, single developer, no calendar pressure:

* Phase 1: half a day. Mostly boilerplate.
* Phase 2: one day. Read endpoints + CLI conversion + smoke test.
* Phase 3: one to two days. Four mutating endpoints, each its own
   commit, plus testing against a lab zone.
* Phase 4: half a day. Cleanup + doc updates.

Total: 2–3 days of focused work. Cherry-pickable per-phase onto the
fast-roller branches if needed, but probably cleaner to land once on
main after the fast-roller branches merge.
