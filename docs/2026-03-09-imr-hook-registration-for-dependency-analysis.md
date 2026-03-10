# IMR Hook Registration for Dependency Analysis Tool

**Date:** 2026-03-09
**Status:** Plan

## Context

Goal: analyze DNS-level external dependencies of a service (web page, etc.)
by instrumenting the IMR resolver. The analysis workflow is:

1. Flush IMR cache (clean slate)
2. Point browser at IMR resolver, load a web page
3. View ALL queries: client queries from browser + iterative sub-queries to auth servers
4. Selectively block names (NXDOMAIN, NODATA, DROP, REDIRECT, ALLOW)
5. Flush + retry, see what breaks

Example use case: "Can this service function if everything outside .SE is unreachable?"

The dependency analysis tool is a **separate application** (new repo, derivative
of `tdns-imr-v2`) that links against `tdns` and registers custom hooks — exactly
like how KDC registers custom query/update handlers via `RegisterQueryHandler` /
`RegisterUpdateHandler` in `registration.go`.

This document covers **only the changes to tdns** — adding pluggable hook points
to the IMR. The analysis tool itself lives in a separate repo and is out of scope.

## Complexity assessment

This is a **very small change** to tdns. The entire modification touches **3 files**
with approximately **100 lines of new code** total:

| File | New/changed lines | Nature |
|------|------------------|--------|
| `v2/registration.go` | ~80 new lines | 3 type definitions, 6 global vars, 3 Register functions, 3 getters. All follow the exact pattern of the existing `RegisterQueryHandler` + `getQueryHandlers`. Pure boilerplate. |
| `v2/imrengine.go` | ~10 changed lines | Replace a single `imr.ImrResponder(ctx, ...)` call with a hook loop + the same call. |
| `v2/dnslookup.go` | ~12 new lines | Insert two small hook loops: one before `c.Exchange()`, one after response received. |

**No new files.** No struct changes. No config changes. No new dependencies.

**Risk:** Near zero. When no hooks are registered (the default), the getter
functions return nil slices and the `range` loops execute zero iterations.
The existing code path is identical. All existing applications (`tdns-imr-v2`,
`tdns-auth`, `tdns-scanner`, etc.) are completely unaffected.

**Pattern precedent:** `RegisterQueryHandler` (line 55), `RegisterNotifyHandler`
(line 140), `RegisterUpdateHandler` (line 255), `RegisterEngine` (line 334),
`RegisterAPIRoute` (line 374) — all in `v2/registration.go`. The IMR hooks
follow this same proven pattern exactly.

## Interception points

There are **3 hook points** where the IMR needs to become pluggable:

### Hook 1: Client query arrival (`createImrHandler`)

**File:** `v2/imrengine.go:1570` — inside the `case dns.OpcodeQuery:` branch
of the closure returned by `createImrHandler()`, just before `imr.ImrResponder()`
is called at line 1579.

**What a hook sees:** qname, qtype, client address (via ResponseWriter), EDNS0 options.

**What a hook can do:**
- **Observe** (log the query for dependency tracking)
- **Intercept** (synthesize a response — NXDOMAIN/NODATA/DROP — for RPZ blocking)

**Default behavior (no hook):** call `ImrResponder()` directly (unchanged).

### Hook 2: Outbound iterative query (`tryServer`)

**File:** `v2/dnslookup.go:1610` — inside `tryServer()`, just before
`c.Exchange(m, addr, ...)` at line 1611.

**What a hook sees:** qname, qtype, server name, server address, chosen transport.

**What a hook can do:**
- **Observe** (log the sub-query + link it to the client query via context)
- **Intercept** (block the query, return error — prevents resolution via blocked nameservers)

**Default behavior (no hook):** call `c.Exchange()` directly (unchanged).

### Hook 3: Response received (after `tryServer` returns)

**File:** `v2/dnslookup.go:854` — in `IterativeDNSQueryWithLoopDetection()`,
after `tryServer()` returns a response.

**What a hook sees:** qname, qtype, the DNS response message, server name,
address, transport used, rcode.

**What a hook can do:**
- **Observe** (log what was returned, track referral chains)
- This hook is observe-only (response already received)

**Default behavior (no hook):** process response normally (unchanged).

## Design: Follow the RegisterQueryHandler pattern

### New types (in `v2/registration.go`)

```go
// ImrClientQueryHookFunc is called when an external client query arrives
// at the IMR listener.
// Return nil ctx to keep the original context, or a new context to enrich it.
// Return nil *dns.Msg to proceed with normal resolution.
// Return a non-nil *dns.Msg to short-circuit: the msg is sent as the response
// and resolution is skipped.
type ImrClientQueryHookFunc func(ctx context.Context, w dns.ResponseWriter,
    r *dns.Msg, qname string, qtype uint16,
    msgoptions *edns0.MsgOptions) (context.Context, *dns.Msg)

// ImrOutboundQueryHookFunc is called before the IMR sends an iterative query
// to an authoritative server.
// Return nil to proceed with the query.
// Return a non-nil error to skip this server (behaves as if the server
// didn't respond).
type ImrOutboundQueryHookFunc func(ctx context.Context, qname string,
    qtype uint16, serverName string, serverAddr string,
    transport core.Transport) error

// ImrResponseHookFunc is called after the IMR receives a response from an
// authoritative server. Observe-only — return value is ignored.
type ImrResponseHookFunc func(ctx context.Context, qname string, qtype uint16,
    serverName string, serverAddr string, transport core.Transport,
    response *dns.Msg, rcode int)
```

### Registration functions (in `v2/registration.go`)

Following the exact pattern of `RegisterQueryHandler`:

```go
var (
    globalImrClientQueryHooks      []ImrClientQueryHookFunc
    globalImrClientQueryHooksMutex sync.RWMutex

    globalImrOutboundQueryHooks      []ImrOutboundQueryHookFunc
    globalImrOutboundQueryHooksMutex sync.RWMutex

    globalImrResponseHooks      []ImrResponseHookFunc
    globalImrResponseHooksMutex sync.RWMutex
)

func RegisterImrClientQueryHook(hook ImrClientQueryHookFunc) error { ... }
func RegisterImrOutboundQueryHook(hook ImrOutboundQueryHookFunc) error { ... }
func RegisterImrResponseHook(hook ImrResponseHookFunc) error { ... }
```

Plus internal getters:

```go
func getImrClientQueryHooks() []ImrClientQueryHookFunc { ... }
func getImrOutboundQueryHooks() []ImrOutboundQueryHookFunc { ... }
func getImrResponseHooks() []ImrResponseHookFunc { ... }
```

### Hook invocation points

**Hook 1 — `v2/imrengine.go:1570`** (in `createImrHandler` closure):

Current code (line 1579):
```go
imr.ImrResponder(ctx, w, r, qname, qtype, msgoptions)
```

Becomes:
```go
// Run IMR client query hooks (dependency analysis, RPZ, etc.)
hookCtx := ctx
for _, hook := range getImrClientQueryHooks() {
    newCtx, response := hook(hookCtx, w, r, qname, qtype, msgoptions)
    if newCtx != nil {
        hookCtx = newCtx
    }
    if response != nil {
        w.WriteMsg(response)
        return
    }
}
imr.ImrResponder(hookCtx, w, r, qname, qtype, msgoptions)
```

**Hook 2 — `v2/dnslookup.go:1610`** (in `tryServer`, before `c.Exchange`):

Current code (line 1611):
```go
r, _, err := c.Exchange(m, addr, Globals.Debug && !imr.Quiet)
```

Insert before:
```go
// Run IMR outbound query hooks
for _, hook := range getImrOutboundQueryHooks() {
    if err := hook(ctx, qname, qtype, server.Name, addr, t); err != nil {
        return nil, t, 0, err
    }
}
```

**Hook 3 — `v2/dnslookup.go:878`** (after `tryServer` returns successfully):

After the nil-response check at line 873, insert:
```go
// Run IMR response hooks
for _, hook := range getImrResponseHooks() {
    hook(ctx, qname, qtype, server.Name, addr, transport, r, r.MsgHdr.Rcode)
}
```

## Files to modify

| File | Change | Lines affected |
|------|--------|-------|
| `v2/registration.go` | Add 3 hook types, 3 Register functions, 3 getters, global storage vars | ~80 new lines at end of file |
| `v2/imrengine.go` | Hook 1 invocation in `createImrHandler` | ~10 lines replacing line 1579 |
| `v2/dnslookup.go` | Hook 2 invocation before `c.Exchange`, Hook 3 after response | ~12 lines total |

No new files in tdns. No struct changes. No config changes. The hooks use the
same global registration pattern as `RegisterQueryHandler` — no `Imr` struct
modification needed.

## What the external tool does (out of scope, but for reference)

A new repo (`tdns-depanalyzer` or similar) with a `main.go` structured like
`cmdv2/imrv2/main.go`:

```go
func init() {
    // Register hooks before TDNS init (same pattern as KDC)
    tdns.RegisterImrClientQueryHook(depanalyzer.OnClientQuery)
    tdns.RegisterImrOutboundQueryHook(depanalyzer.OnOutboundQuery)
    tdns.RegisterImrResponseHook(depanalyzer.OnResponse)

    // Register custom CLI commands
    // (session start/stop/show/analyze, rpz add/remove/list/clear)
}
```

The tool would:
- Log all client queries + iterative sub-queries (linked via context values)
- Maintain an in-memory session of query trees
- Maintain persistent RPZ-like block rules (JSON file)
- Provide CLI commands for the analysis workflow:
  - `session start` / `stop` / `show` / `analyze`
  - `rpz add` / `remove` / `list` / `clear`
  - `flush everything` (full cache flush + re-prime root hints)

## Implementation order

1. Add hook types and registration functions to `v2/registration.go`
2. Insert Hook 1 call site in `v2/imrengine.go`
3. Insert Hook 2 + Hook 3 call sites in `v2/dnslookup.go`
4. `gofmt -w` on modified files
5. Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
6. Create Linear issues for tracking

## Verification

1. Build succeeds with no hooks registered (zero-cost: `getImrClientQueryHooks()`
   returns nil slice, loop body never executes)
2. Existing `tdns-imr-v2` behavior is identical — no functional change
3. A simple test hook can be registered in `imrv2/root.go` init to verify the
   mechanism works:
   ```go
   tdns.RegisterImrClientQueryHook(func(ctx context.Context,
       w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16,
       msgoptions *edns0.MsgOptions) (context.Context, *dns.Msg) {
       fmt.Printf("CLIENT QUERY: %s %s\n", qname, dns.TypeToString[qtype])
       return ctx, nil // proceed normally
   })
   ```
