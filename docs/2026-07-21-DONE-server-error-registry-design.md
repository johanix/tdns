# Server-Wide Error Registry (with clear-ownership subtyping)

**Date:** 2026-07-21
**Scope:** `v2/` (module `github.com/johanix/tdns/v2`) and `cmdv2/`.
**Status:** design agreed in discussion 2026-07-21; ready to implement.
**Motivating bug:** `tdns-auth config status` reports the *configured* set of
DNS transports as if they were live, even when a listener never started
(e.g. the DoT/DoH/DoQ cert+key files were missing, so the encrypted
listeners were skipped at boot). The daemon *knows* — it computed
`certKey = false` in `v2/do53.go` and skipped `DnsDoTEngine`/`DnsDoHEngine`/
`DnsDoQEngine` — but the status handler (`v2/apihandler_funcs.go`, `case
"status"`) copies `conf.DnsEngine` verbatim and hardcodes
`resp.Msg = "Configuration is ok"`. The truth is discarded.

---

## 1. Why a registry, not a one-off

Propagating "the cert failed" to `config status` as a special case would fix
this symptom and teach us nothing. tdns already has the cautionary tale: at
the zone level, many unrelated causes all call `zd.SetError(DnssecError,
...)`. Because there is a single `DnssecError` type and no subtyping, nothing
can safely *clear* it — a clearer cannot know whether the condition it fixed
is the one that set the error, or whether some other cause is still live.

The fix is not more plumbing; it is **subtyping with clear-ownership**: every
distinct cause gets a distinct (category, subtype), and an error may only be
cleared by the code that owns that class and has re-verified the condition.

## 2. Scope and non-goals

**In scope now:**
- A standalone server-wide error registry (types + storage + set/clear/list).
- A minimal taxonomy sufficient for the transport/cert case.
- Instrumentation of **only** the new/adjacent TLS + transport-listener code
  and the config-time cert-file check.
- Reporting active errors in `config status` (auth; the same mechanism is
  available to imr/agent status).

**Explicit non-goals:**
- **Not** shared with the zone error system. Zones run under an immutable
  copy-on-write snapshot model; the server registry is low-frequency,
  multi-writer, plain-mutex state and must stay entirely separate from the
  zone snapshot path. A future ZoneError redesign may borrow this taxonomy,
  but not this code or its locking.
- **Not** a repo-wide error-instrumentation sweep. Other subsystems adopt the
  registry when they are worked on; that is a separate project. What we build
  now must have the right architecture so they *can*.

## 3. Core model

```go
// v2/servererror.go  (package tdns)

type ErrorCategory uint8
const (
    ErrCatTransport ErrorCategory = iota + 1 // a listener/transport is not serving
    ErrCatConfig                             // a configured input is missing/invalid
    ErrCatOther                              // catch-all until a category is defined
)

type ErrorSubtype uint8
const (
    // Transport subtypes
    ErrSubCert ErrorSubtype = iota + 1 // cert/key could not be loaded for a listener
    ErrSubPort                         // a listener socket failed to bind
    // Config subtypes
    ErrSubCertMissing                  // a configured cert/key file is absent/unreadable
    // (extend as needed)
)

type ServerError struct {
    Category  ErrorCategory
    Subtype   ErrorSubtype
    Message   string    // human detail: which file, which host:port, the underlying err
    FirstSeen time.Time
    LastSeen  time.Time
}
```

Identity is the **(Category, Subtype)** pair: one live entry per class. A
second `Set` of the same class updates `Message`/`LastSeen` (and may
aggregate — e.g. "affects dot:853, doh:443"), it does not stack. Per-instance
multiplicity (e.g. one error per zone) is deliberately *not* a server-registry
concern; that is what a future per-zone registry is for.

Subtypes are namespaced by convention to their category (the comments group
them). We keep a single `ErrorSubtype` enum rather than per-category enums for
simplicity; a `(category, subtype)` that is nonsensical is a programming error,
not a runtime input.

## 4. The registry

```go
type ServerErrorRegistry struct {
    mu   sync.Mutex
    errs map[errKey]ServerError // errKey = struct{Category; Subtype}
}

func (r *ServerErrorRegistry) set(cat ErrorCategory, sub ErrorSubtype, msg string)
func (r *ServerErrorRegistry) clear(cat ErrorCategory, sub ErrorSubtype)
func (r *ServerErrorRegistry) List() []ServerError // sorted, for status/JSON
func (r *ServerErrorRegistry) HasCategory(cat ErrorCategory) bool
```

- Lives at `conf.Internal.ServerErrors` (one instance per daemon). Plain
  `sync.Mutex`; writes are rare (boot, config reload, a listener failing).
- `set`/`clear` are **unexported**. Callers go through **named, owned helper
  functions** (next section), so every clear point is greppable and located
  with the code that owns the truth. This is the structural guard against the
  DnssecError mistake.

## 5. Ownership and the clearing discipline

Two rules:

1. **Distinct cause → distinct subtype.** Because `ErrSubCert` ≠ `ErrSubPort`,
   the cert-revalidation path clears *only* Cert and cannot wipe a live Port
   error.
2. **One owner per (category); the owner clears via a named helper, using
   clear-then-reassert on its authoritative revalidation path.** This is the
   pattern the zone parse loop already uses (`SetError(NoError)` at the top of
   each zone, re-set if still broken).

Owners and helpers (the only blessed mutators):

| (Category, Subtype) | Owner | Set helper, called when | Clear helper, called when |
| --- | --- | --- | --- |
| `Config/CertMissing` | **parseconfig** | a configured `dnsengine.certfile`/`keyfile` is absent/unreadable at (re)load | parseconfig re-reads on reload and the files are now present/readable |
| `Transport/Cert` | **DnsEngine** | encrypted listeners were skipped because the cert/key would not load | a fresh engine start loads the cert (boot-scoped: registry starts empty each boot) |
| `Transport/Port` | **DnsEngine** | a listener socket failed to bind (privileged port, address-in-use) | a fresh engine start binds successfully |

Worked example — your missing-cert case sets **two** errors, owned by two
different parts of the code, which is the taxonomy working as intended:

- parseconfig finds the certfile absent → `Set Config/CertMissing`.
- DnsEngine can't load the cert, skips DoT/DoH/DoQ → `Set Transport/Cert`.
- `config status` reports both; the top line degrades.
- You add the files and **restart**. New boot: registry empty; parseconfig
  finds the files (no `Config/CertMissing`); DnsEngine loads the cert and
  starts the listeners (no `Transport/Cert`). Clean.

**Why boot-scoped `Transport/*` is correct (no hot listener restart):**
config reload (`parseconfig` with `reload=true`) re-reads zones and config but
does not today tear down and rebuild the DNS listeners. So a `Transport/*`
error genuinely persists until the daemon is restarted, and reporting it that
way is honest. parseconfig still clears its *own* `Config/*` errors every
reload. If we later add hot listener re-attach on reload, the DnsEngine's
clear helper simply gets called from that path too — the architecture already
allows it, no redesign.

## 6. Instrumentation points (this change only)

- `v2/do53.go` `DnsEngine`: at the `certKey = false` decision, if any of
  dot/doh/doq is configured → `setTransportCertError(...)` with the load
  error. (Currently `v2/do53.go:119-153`.)
- `v2/dot.go` `DnsDoTEngine` (and the DoH/DoQ engines): when a listener's
  `ListenAndServe`/bind returns an error before it is serving →
  `setTransportPortError(hostport, err)`. do53 and dot are `dns.Server` with a
  clean `NotifyStartedFunc`/error return; DoH/DoQ get the same treatment where
  their engines expose a bind result (best-effort in round 1, noted below).
- `v2/parseconfig.go`: the `dnsengine` cert/key existence check (the static
  half already done by `config check`) → `setConfigCertMissing(...)` /
  cleared by the reload revalidation.

Rounds-of-work note: do53 + dot bind-failure and the cert cases are exact in
round 1. If a DoH/DoQ engine does not surface a clean "did it bind" signal, its
`Transport/Port` detection is a fast follow rather than a blocker; the
`Transport/Cert` case already covers "encrypted transports didn't start
because of the cert", which is the reported bug.

## 7. Reporting in `config status`

- Additive field on the status API response
  (`v2/apihandler_funcs.go`, `case "status"`): `ServerErrors []ServerError`
  from `conf.Internal.ServerErrors.List()`. Additive — existing CLI/tdns-mp
  consumers ignore it until updated.
- The hardcoded `resp.Msg = "Configuration is ok"` becomes conditional:
  `"DEGRADED: N active error(s)"` when the registry is non-empty.
- `config status -v` (`v2/cli/config_cmds.go`) prints, after the transports
  line:
  ```
  DnsEngine: active transports: [do53]          (unchanged label; see below)
  Errors:
    [Transport/Cert]   dot,doh,doq not started: load /etc/tdns/certs/x.crt: no such file (since 14:08:00)
    [Config/CertMissing] dnsengine.certfile /etc/tdns/certs/x.crt: no such file
  Status: DEGRADED — 2 active error(s)
  ```
- The existing `active transports:` line still prints the configured list; the
  registry is what tells the truth about what is *not* serving. (Making that
  line itself reflect actually-bound listeners is a nice follow-up but is not
  required once the errors are reported — and it would need the per-listener
  bind tracking that `Transport/Port` already implies.)

## 8. Concurrency

Plain `sync.Mutex` around a small map. Writers: boot (DnsEngine), config
reload (parseconfig), an occasional listener-failure goroutine. Reader: the
status API handler. No hot path, no per-request contention, and — by design —
**no contact with the zone snapshot machinery**. This is the whole reason it
is a separate system.

## 9. Implementation phases

1. **P1 — registry core.** `v2/servererror.go`: types, registry, unexported
   set/clear, `List`/`HasCategory`, `conf.Internal.ServerErrors`. Unit tests
   (set/clear/dedup/ownership-helper behavior). No behavior change.
2. **P2 — instrument + report.** Owned helpers + call sites in do53/dot(/doh/
   doq best-effort)/parseconfig; status API field; `config status` rendering;
   degraded top line. Test: a config with a missing certfile yields
   `Config/CertMissing` + `Transport/Cert` and a DEGRADED status; a good config
   yields none.
3. **P3 — docs.** guide/config-tdns-auth.md (status semantics + the error
   table) and a short note in the ops guide.

## 10. Future (out of scope)

- A per-zone error redesign that replaces the untyped `DnssecError` with the
  same (category, subtype) discipline — learning from this registry but built
  on the zone snapshot model, not sharing this code or its mutex.
- Making `active transports:` reflect actually-bound listeners (rides on the
  `Transport/Port` tracking).
- Hot listener re-attach on config reload (lets a cert fix + reload clear
  `Transport/Cert` without a restart).
