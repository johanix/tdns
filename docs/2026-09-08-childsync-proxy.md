# Parent-side delegation sync via tdns-agent (`childsync-proxy`)

**Status:** design, implementation not started and not authorised.
**Base:** `main` (f4bea22). Work in the **`v2/` tree only**.
**Mirrors:** `2026-06-22-DONE-agent-dsync-proxy-for-clueless-primary-plan.md` (the
child-side proxy, shipped) — this is the same idea seen from the other end of
the delegation.
**Depends on nothing; conflicts with nothing currently in flight.** It touches
`ops_dsync.go`, `zone_utils.go:SetupZoneSync`, the delegation-backend family and
`main_initfuncs.go`, and adds the first non-sqlite SQL driver to `v2/go.mod`.
The one file it shares with open delegation-sync work is `ops_dsync.go` (the
alignment plan's D-7 `{ZONENAME}` expansion rider — no relation to this
document's own D-7).

---

## 1. What exists, and what is missing

tdns has a complete parent-side delegation-sync implementation. It lives in
tdns-auth and assumes tdns-auth **is** the parent primary:

| function | where | assumption it makes |
|---|---|---|
| publish the `_dsync` DSYNC RRset (+ URI/TXT/SVCB/glue) | `v2/ops_dsync.go:72` `PublishDsyncRRs` | it can write the parent zone |
| generate + publish the UPDATE receiver's SIG(0) KEY | `v2/delegation_sync.go:273` `Sig0KeyPreparation` → `PublishKeyRRs` | it can write the parent zone |
| receive NOTIFY(CDS/CSYNC) | `v2/notifyresponder.go:160` `NotifyResponder` | — |
| scan the child, diff, act | `v2/scanner.go:110` `ScannerEngine` | reads current state from `DelegationBackend` |
| receive DNS UPDATE from the child | `v2/updateresponder.go:126` `UpdateResponder` | — |
| receive DSYNC API POST from the child | `v2/dsync_api_delegation.go` | — |
| answer KeyState inquiries | `v2/defaultqueryhandlers.go:57` | — |
| authorize / validate | truststore, `updatepolicy.child`, `delegationpolicy`, coherence checks | — |
| **apply** the approved change | `UpdateRequest{Cmd:"CHILD-UPDATE"}` → `DelegationBackend.ApplyChildUpdate` | pluggable already |

What is missing is a deployment in which the parent zone's primary is
DSYNC-unaware (BIND, Knot, a registry provisioning pipeline) and a **tdns-agent
secondary of the parent zone** performs the parent's half on its behalf.

The child side already has exactly this: `parentsync-proxy`
(`v2/delsync_proxy*.go`), an agent that secondaries a child zone whose primary
is DSYNC-unaware and speaks to the parent for it. The parent-side analogue does
not exist. This document specifies it.

**Name: `childsync-proxy`.** `childsync` is what a parent offers its children;
`parentsync` is what a child does towards its parent; each proxy is named after
the option it proxies. `delegation-sync-proxy` is already a deprecated alias
for `parentsync-proxy`, so the naming is settled by precedent.

---

## 2. Topology

```
   child.example.                              example. (the parent)
   ┌──────────────┐                            ┌───────────────────────────┐
   │ child primary│                            │ parent primary  (BIND/…)  │
   │  (any impl)  │                            │  DSYNC-unaware            │
   └──────┬───────┘                            └──────┬──────────────┬─────┘
          │                                     AXFR/ │        DDNS  │
          │  NOTIFY(CDS/CSYNC)                 NOTIFY │      (TSIG)  │ ▲
          │  DNS UPDATE (SIG(0))                      ▼              ▼ │
          │  DSYNC API (HTTPS)                 ┌──────────────────────────┐
          └───────────────────────────────────▶│  tdns-agent              │
                                               │  secondary of example.   │
             KeyState inquiry (KEY, SIG(0)) ──▶│  option: childsync-proxy │
                                               └──────────────────────────┘
                                                     ▲
                          the parent zone's DSYNC RRset points HERE
```

The agent:

- is a **secondary** of the parent zone, so it holds the delegation data,
  the `_dsync` RRset and the child KEYs the parent publishes;
- is **not** in the parent's NS set and does not answer ordinary queries
  (`v2/defaultqueryhandlers.go:163` already refuses them on an agent);
- **is** the host the parent's DSYNC RRset names as NOTIFY / UPDATE / API
  receiver, so children send their delegation traffic here;
- writes nothing into its own copy of the zone — its copy is replaced by the
  next transfer — and instead pushes approved changes **upward to the parent
  primary**.

## 3. The two halves, and the one structural insight

### 3.1 Downward half — "tell the primary what to publish"

The agent must get four things into the parent zone, because a child discovers
the service by looking them up in the parent:

1. `_dsync.example. DSYNC …` — one RR per (type, scheme), naming the agent;
2. `<target>. A/AAAA` — the agent's addresses, for the NOTIFY and UPDATE
   schemes (a child must reach the target by name);
3. for the API scheme, `URI` + `TXT` at the API target
   (`v2/ops_dsync_api.go:49,80`);
4. `<update-target>. KEY` — the UPDATE receiver's SIG(0) public key, which the
   child needs to verify KeyState responses; plus the bootstrap `SVCB`
   (`v2/ops_dsync.go:481`) derived from the zone's bound `delegationpolicy`.

`PublishDsyncRRs` computes all of these today and posts one
`UpdateRequest{Cmd:"ZONE-UPDATE", InternalUpdate:true}`. On an agent secondary
that update **would be applied to the in-memory copy and silently lost at the
next transfer** — `zoneMayOriginateContent` (`v2/zone_origination.go:46`)
returns `true` for every app that is not tdns-auth, by design, so none of the
existing origination gates fire. This is the first thing the design has to fix,
and it is a real hazard rather than a theoretical one.

### 3.2 Upward half — "receive, validate, apply"

**The structural insight that makes this cheap:** all three receive channels
already converge on a single choke point.

```
NOTIFY(CDS/CSYNC) ─▶ ScannerEngine ─▶ OnDelegationChange  ┐
DNS UPDATE (SIG0) ─▶ UpdateResponder ─▶ ApproveChildUpdate ├─▶ UpdateRequest{Cmd:"CHILD-UPDATE"}
DSYNC API (HTTPS) ─▶ DsyncApiPostDelegation               ┘          │
                                                                     ▼
                                            zd.DelegationBackend.ApplyChildUpdate()
```

(`v2/scanner.go:137`, `v2/updateresponder.go:515`, `v2/dsync_api_delegation.go:188`;
dispatch at `v2/zone_updater.go:241`.)

So the entire "apply" half is **the `DelegationBackend` interface**, not a new
pipeline: a store to persist the intent and a writer to deliver it (D-7).

And there is precedent for a backend that hands data out of process:
`ZonefileDelegationBackend` (`v2/delegation_backend_zonefile.go`) persists to
the sqlite DB and regenerates `$INCLUDE` fragments for someone else to fold in,
with an optional notify command. The two new pieces are the same idea with
different endings — a writer that pushes over DNS UPDATE (§5.4, §5.6), and a
store that hands off to a registry provisioning system through a shared
database (§5.8).

Everything between the wire and that choke point — SIG(0) validation, the
truststore, `updatepolicy.child`, `ApproveActionsForPrincipal`, the bound
`delegationpolicy`, `CheckDelegationCoherenceForUpdate`,
`CheckDelegationNSCoherenceForUpdate`, child-key verification — is
transport-agnostic and role-agnostic and needs **no change at all**. Role C of
`2026-08-23-proxy-delegation-sync-scope.md` ("the parent verifies its own
requirements on every channel") is satisfied verbatim: the proxy is the parent
for these purposes, running the parent's own code.

---

## 4. Design decisions

### D-1. `childsync-proxy` implies `childsync`; it does not replace it

`parentsync` and `parentsync-proxy` are mutually exclusive
(`v2/parseoptions.go:420`) because they are two different actors — the child
itself versus a proxy for it. That reasoning does not carry over. A
`childsync-proxy` zone genuinely *does* offer childsync: it advertises DSYNC,
receives on every scheme, and applies the parent's policy. The only difference
is where the resulting writes land.

Roughly a dozen sites gate on `zd.Options[OptChildSync]` — `dsyncApiParentZone`
(`v2/dsync_api_server.go:333`), the KeyState responder
(`v2/defaultqueryhandlers.go:57`), `Sig0KeyPreparation`
(`v2/delegation_sync.go:309`), the `/zone/childsync` handler
(`v2/apihandler_zone.go:1201`), `SetupZoneSync`. Making the two options
exclusive would mean rewriting every one of them into a predicate, for no
behavioural gain.

**Decision:** the parser materialises `OptChildSync` whenever
`OptChildSyncProxy` is set. Every existing `OptChildSync` gate keeps working
unchanged; the four or five places that must behave *differently* test
`OptChildSyncProxy` explicitly. Writing both in the config is legal and
redundant, not an error. Setting `childsync-proxy` on anything but a tdns-agent
secondary is a `ConfigError` (same shape as `parentsync-proxy` at
`v2/zone_utils.go:1749`).

### D-2. Acceptance is decoupled from publication, and that is not new

The obvious objection to the upward half: the child gets `NOERROR` for its
UPDATE before the parent primary has the change. Two candidate answers:

**(i) Synchronous.** `ApplyChildUpdate` pushes to the primary inline and returns
its outcome, so `NOERROR` means the primary has it. **Rejected.** `ZoneUpdater`
is a single goroutine serving every zone on the server
(`v2/zone_updater.go:241` and its loop). One unreachable primary would stall
delegation updates, DSYNC publication and internal zone updates for every zone
the daemon holds. That is disqualifying regardless of how attractive the
semantics are.

**(ii) Persist, then push.** `ApplyChildUpdate` writes the store row — durable,
fast, no network — and hands the change to a dedicated outbound engine. The
child's `NOERROR` means "accepted and recorded by the parent's delegation
service". **Adopted.**

This is not a weakening introduced here. `delegationbackend: db` and
`delegationbackend: zonefile` already have exactly this contract on tdns-auth:
the update is recorded for an external generator to pick up, and `NOERROR`
already means acceptance rather than publication. The `direct` backend is the
only one where the two coincide, and `direct` is already refused on a secondary
(`v2/delegation_backend_validate.go:65`). The new backend automates a last hop
that is today manual; it does not move the acknowledgement point.

What the design owes in exchange is **visibility**: per-zone and per-child push
state, a bounded retry with backoff, a per-zone `DelegationSyncWarning` when the
queue is stuck, and a reconciler that closes the loop against what the primary
actually serves (§6.4). All of those are specified below.

*(The DSYNC API channel is HTTP and could afford to wait. Deferred as a
`Prefer: respond-async` / 202-vs-200 refinement — see §11.)*

### D-3. The store is the intended state; the transferred zone is the actual state

The scanner already reads current delegation state from the backend, not from
the zone (`v2/scanner.go:251` for DS, `:877` for NS/glue), precisely so that a
parent handing data out of process still computes correct diffs. Every backend
inherits that for free from the (store, writer) split (D-7), the way
`ZonefileDelegationBackend` inherits it from `DBDelegationBackend` today. Which
store — local sqlite or a shared MariaDB (§5.8) — changes nothing here.

**But the store starts empty, and that is a live hazard even today.** On a fresh
parent with `delegationbackend: db`, `GetDelegationData` returns nothing for a
child that already has a delegation, so the first CSYNC or CDS diff is computed
against an empty current state — spurious adds, and no removes ever. The
existing code comments name this outcome as the reason the backend is mandatory,
but nothing seeds the backend. On tdns-auth it is masked by deployments that use
`direct`. A proxy cannot use `direct`, so the proxy makes it acute.

**Decision:** the first successful transfer of a `childsync-proxy` parent zone
runs an **adoption pass**: for every child delegation present in the served
zone, if the store holds no rows for that child, insert what the zone holds —
marked `origin: observed` (§5.8.2), so a later audit can tell an observation
from a child's assertion. The reconciler (§6.4) is then meaningful, and —
importantly — it must remain **additive with respect to unknown children**: a
child with no rows in the store is never a reason to delete anything from the
parent. Only children the service has actually seen are reconciled.

This is worth doing as a standalone fix (§10, item **C-0**) whether or not the
rest of this lands.

### D-4. One writer per parent zone, in v1

Two agents both fronting one parent zone would both receive (a child picks one
DSYNC target) and both push. Identical intent converges — the pushes are
declarative per child and idempotent — but divergent DB state does not: two
agents that saw different subsets of updates would fight, each re-pushing its
own view on every reconcile.

The child side solved the analogous problem with leader election
(`2026-03-09-parentsync-leader-election.md`). That machinery is MP-specific and
not worth lifting for v1.

**Decision:** exactly one agent per parent zone may carry a *writing* backend.
Additional agents may run with `writer: manual` (receive and record, publish
nothing) for warm standby. Enforced by documentation and by an operator-visible
warning, not by a protocol — there is no way for one agent to detect another.
Flagged as future work in §11.

### D-5. The writer is bounded to delegation names, in the writer

The agent holds DDNS write authority over the parent zone. The primary's own
`update-policy` should bound it (§8), but the primary is someone else's
configuration and a tdns bug must not be able to rewrite a parent apex even
against a permissive primary.

**Decision:** `ParentZoneWriter` refuses, before it builds a message, any action
whose owner is not one of:

- a child delegation point of the parent, or a name below one;
- an in-bailiwick nameserver name reachable from a child's NS RRset (glue);
- one of the agent's own advertisement names (`_dsync.<parent>`, the configured
  NOTIFY/UPDATE/API targets, the SVCB bootstrap name).

A refusal is an internal-invariant `ERROR` with the offending owner named, in
the same spirit as the KEY guard at `v2/zone_updater.go:273`. Defence in depth,
not the load-bearing gate.

### D-6. No new DS-intent question

`2026-08-23-proxy-delegation-sync-scope.md` settles who may assert what about
DS. Role B (the child-side proxy) needed a new rule because it has no access to
intent. Role C — the parent — has none of its own and validates what arrives.
The `childsync-proxy` **is** Role C, running Role C's existing code on Role C's
existing channels. Nothing in this design forms a DS opinion, and nothing here
should.

### D-7. Persistence and delivery are two axes, not one backend name

Agreed 2026-09-08, and it is what makes `external-db` fit without a fourth
opaque type name.

`DelegationBackend` today conflates two independent questions. Read the existing
implementations as answers to both — and the two this document adds — and the
axes fall out:

| backend | where intent is stored | how it reaches the parent |
|---|---|---|
| `direct` | the in-memory zone | this server *is* the primary |
| `db` | the KeyDB (sqlite) | nothing — an operator picks it up |
| `zonefile` | the KeyDB (sqlite) | `$INCLUDE` fragments + a notify command |
| `upstream` (§5.4) | the KeyDB (sqlite) | DDNS to the primary |
| **`external-db`** | **a shared MariaDB** | nothing — a separate consumer picks it up |

`zonefile` is already `store=sqlite, writer=fragments`. `upstream` is already
`store=sqlite, writer=ddns`. Adding `external-db` as a fifth opaque name would
mean the two axes get multiplied out by hand every time either gains a value,
and the combination an operator most plausibly wants next — a shared MariaDB
*and* a DDNS push, so the registry pipeline sees the data and the zone is
updated anyway — would need a sixth name.

**Decision: name the two axes in the config, keep the type names as sugar.**

```yaml
delegationbackends:
  - name: registry-handoff
    store:  external-db        # sqlite | external-db | direct
    writer: none               # none | ddns | zonefile | command
```

`type: db`, `type: direct`, `type: zonefile`, `type: upstream` and
`type: external-db` all remain accepted and expand to a (store, writer) pair,
so no existing config changes and the short spellings stay available. `direct`
is the one combination that is not free-form: it is `store=direct, writer=none`
and rejects any other writer, because the in-memory zone *is* the delivery.

The `DelegationBackend` interface itself does not change. What changes is that
`LookupDelegationBackend` composes a store and a writer instead of returning a
hand-written struct per name.

### D-8. `external-db` holds delegation data only — never the KeyDB

The KeyDB holds SIG(0) and DNSSEC **private key material**, the truststore, the
TSIG secrets and the zone journal. A shared MariaDB whose whole purpose is to be
readable by a registry provisioning system is the last place any of that should
live, and moving it there to solve a concurrency problem in one table would be a
security regression paid for a convenience.

**Decision:** `external-db` opens its **own** `*sql.DB`, owned by the backend,
and stores exactly the delegation handoff. The KeyDB stays sqlite, stays local,
stays private. Nothing else in tdns learns about the external database.

That also bounds the work: the dialect-sensitive surface is one file's worth of
SQL, not the 21 tables in `v2/db_schema.go` and the ~490 `kdb.`/`KeyDB.` call
sites around them.

### D-9. Do not inherit the KeyDB's single-transaction gate

`KeyDB.Begin` (`v2/db.go:67`) refuses to start a transaction while another is
open anywhere in the process — a `db.Ctx` string guarded by `KeyDB.mu`, checked
and set before `DB.Begin()`. That is a sensible accommodation of sqlite's
single-writer model and it is exactly the property that makes the current `db`
backend unfit for a shared store.

A naive `external-db` would copy the pattern because every other backend in the
tree goes through `kdb.Begin`. It must not: the external store uses an ordinary
`database/sql` pool with per-call transactions and no process-wide gate. Stated
here because the copy is the natural mistake, not a hypothetical one.

---

## 5. Component design

### 5.1 New / changed types

```go
// v2/childsync_proxy.go

// ChildSyncProxyState is the parent-side analogue of ProxyUpdateState
// (v2/delsync_proxy_update.go:30): what stands between this agent and being a
// working DSYNC receiver for its parent zone.
type ChildSyncProxyState string

const (
    // The served parent zone carries every record the advertisement needs and
    // the agent holds the private half of the published receiver KEY.
    ChildSyncProxyReady ChildSyncProxyState = "ready"
    // A delta exists between what this agent wants advertised and what the
    // parent zone serves, and it has been handed to the writer.
    ChildSyncProxyPublishing ChildSyncProxyState = "publishing"
    // A delta exists and there is no automatic writer: the operator must
    // publish the block at the primary.
    ChildSyncProxyWaiting ChildSyncProxyState = "waiting-for-publication"
    // A KEY is published at the UPDATE target and the agent does not hold its
    // private half. Do not mint a competing key.
    ChildSyncProxyForeignKey ChildSyncProxyState = "foreign-key"
    // The parent zone has not been transferred yet; nothing can be decided.
    ChildSyncProxyNoZone ChildSyncProxyState = "no-zone-data"
)
```

```go
// v2/parent_zone_writer.go

// ParentZoneWriter is how a childsync-proxy agent gets records into the parent
// zone it is a secondary of. Actions use the RFC 2136 classes the rest of the
// tree uses: ClassINET add, ClassNONE delete-RR, ClassANY delete-RRset.
//
// Write is expected to be reasonably prompt but NOT to be called from the
// ZoneUpdater goroutine — see D-2.
type ParentZoneWriter interface {
    Write(ctx context.Context, parentZone string, actions []dns.RR, desc string) error
    Name() string
}
```

Three implementations:

| writer | mechanism | when |
|---|---|---|
| `ddns` | RFC 2136 UPDATE over TCP, TSIG-signed, to the zone's primaries | the primary accepts DDNS (BIND `update-policy`, Knot `acl … action: update`, tdns-auth `allow-updates`) |
| `zonefile` | delegates to `ZonefileDelegationBackend`'s fragment writer + notify command | the primary is generated from files |
| `manual` | writes nothing; renders the instruction block and raises the per-zone warning | default when nothing is configured; also the standby posture (D-4) |

`ZoneData` gains one field beside the existing `DelegationBackend`
(`v2/structs.go:185`):

```go
    ParentWriter ParentZoneWriter // childsync-proxy: how to write to the parent primary
```

### 5.2 Splitting compute from install

`PublishDsyncRRs` (`v2/ops_dsync.go:72`) is ~180 lines that compute records and
then post one `ZONE-UPDATE`. Extract the computation:

```go
// DsyncPublication is everything a childsync zone must have published for its
// DSYNC service to be discoverable and usable.
type DsyncPublication struct {
    DsyncRRs   []dns.RR // DSYNC at _dsync.<zone>, plus URI/TXT at the API target
    AddressRRs []dns.RR // A/AAAA at the NOTIFY/UPDATE/API targets
    SVCBRRs    []dns.RR // bootstrap SVCB (derived from the bound delegationpolicy)
    ReceiverKEY *dns.KEY // the UPDATE receiver's SIG(0) public key, or nil
}

func (zd *ZoneData) BuildDsyncPublication(ctx context.Context, kdb *KeyDB) (*DsyncPublication, error)
```

`PublishDsyncRRs` becomes `BuildDsyncPublication` + the existing enqueue, so
tdns-auth behaviour is bit-identical. The per-scheme "already published, leave
it alone" logic (`publishedDsyncSchemes`) stays inside the builder — it is what
makes the function safe to re-run, which the proxy relies on far more heavily
than tdns-auth does.

`ReceiverKEY` folds in what `Sig0KeyPreparation` does today. On the proxy path
the key is **generated but not published locally** — the same split
`proxyEnsureSig0Key` (`v2/delsync_proxy_update.go:165`) already makes on the
child side, and for the same reason.

### 5.3 The advertisement reconciler

```go
// ReconcileChildSyncAdvertisement compares what this agent needs advertised in
// the parent zone against what the served (transferred) copy actually carries,
// and hands the delta to the zone's ParentWriter.
//
// Idempotent and cheap: an in-memory RRset diff, no network unless there is a
// delta. Safe to run on every refresh.
func (zd *ZoneData) ReconcileChildSyncAdvertisement(ctx context.Context, kdb *KeyDB) (ChildSyncProxyState, error)
```

Order of checks, mirroring `proxySig0PublicationState`
(`v2/delsync_proxy_update.go:122`):

1. No published zone data yet → `ChildSyncProxyNoZone`, no warning (the zone is
   simply still loading).
2. `BuildDsyncPublication`.
3. KEY at the UPDATE target: present and ours → fine; present and not ours →
   `ChildSyncProxyForeignKey` + warning, and **do not** include a KEY in the
   delta (never mint a competing key); absent → include ours.
4. Diff each RRset (DSYNC, URI, TXT, A/AAAA, SVCB, KEY) against the served zone,
   ignoring TTL. Empty delta and step 3 satisfied → `ChildSyncProxyReady`, clear
   the warning.
5. Non-empty delta → hand to `zd.ParentWriter`. `manual` →
   `ChildSyncProxyWaiting` + warning + instruction block; otherwise
   `ChildSyncProxyPublishing`.

Registered as a **PostRefresh hook** through
`registerStandardRefreshHooks` (`v2/zone_hooks.go:67`), self-gating on
`OptChildSyncProxy` — unconditionally registered for every zone, once, at
construction, exactly as that function's contract requires. The hook is what
makes the loop close: the agent asks for records, the primary publishes them,
the next transfer brings them back, the diff goes empty, the warning clears.

The `advertisesDsyncNotify` gate in `NotifyResponder`
(`v2/notifyresponder.go:30`) reads the same transferred `_dsync` RRset, so the
NOTIFY receiver comes up exactly when the advertisement has landed. That is the
right coupling, not an accident to be worked around.

### 5.4 The composed delegation backend

Per D-7 the backend is a (store, writer) pair rather than a hand-written struct
per name. The store is the part that persists intent; the writer is the part
that delivers it.

```go
// v2/delegation_backend.go

// DelegationStore persists intended delegation state. Implementations:
// sqliteStore (the KeyDB, today's `db`), externalDBStore (§5.8), directStore
// (the in-memory zone, today's `direct`).
//
// ApplyChildUpdate is ATOMIC over ur.Actions: a child update is one intent and
// must not be observable half-applied, by tdns's own reconciler or by an
// external consumer.
type DelegationStore interface {
    ApplyChildUpdate(parentZone string, ur UpdateRequest) error
    GetDelegationData(parentZone, childZone string) (map[string]map[uint16][]dns.RR, error)
    ListChildren(parentZone string) ([]string, error)
    Name() string
}

// composedDelegationBackend is what LookupDelegationBackend now returns.
type composedDelegationBackend struct {
    backendName string
    store  DelegationStore
    writer ParentZoneWriter   // nil for writer: none
    pushq  chan<- ParentPushRequest
}
```

- `ApplyChildUpdate`: `store.ApplyChildUpdate` (durable on return), then — when
  a writer is configured — a non-blocking enqueue of a `ParentPushRequest`
  naming the affected children. Returns the **store's** outcome, which is what
  D-2 means by acceptance. A full push queue is logged and **not** an error: the
  reconciler re-derives the delta from the store, so a dropped push is
  recovered, the same argument `ProxyDelegationPostRefresh` makes for its
  dropped enqueue (`v2/delsync_proxy.go:209`).
- `GetDelegationData` / `ListChildren`: straight through to the store.
- `Name()`: the configured backend name, so log lines keep naming what the
  operator wrote.

Today's three backends fall out as (sqlite, none), (direct, none) and
(sqlite, zonefile), and must behave identically after the split — that is what
the equivalence suite in §10 is for.

### 5.5 `ParentPushEngine`

A new engine, started only when at least one zone carries `OptChildSyncProxy`.
Standard shape per `CONTEXT.md`: `ctx` first, `select` on `ctx.Done()`, handles a
closed channel, never blocks shutdown.

```go
func ParentPushEngine(ctx context.Context, conf *Config) error
```

Per request:

1. For each affected child, read intended state from the store and current
   state from the served parent zone.
2. Compute a **declarative per-child delta** (adds + removes, scoped to that
   child's delegation point and its in-bailiwick glue) rather than replaying the
   original actions. Idempotent under retry, and correct after a dropped push.
3. Apply the §D-5 name bound.
4. `zd.ParentWriter.Write(...)`.
5. On failure: exponential backoff, capped, bounded attempts. On exhaustion,
   raise `DelegationSyncWarning` naming the child and the last rcode/EDE; keep
   the stored row (it is still the intent) and let the reconciler retry on the next
   refresh.
6. On success: clear the per-child failure state. Do **not** mark it confirmed —
   confirmation is the next transfer's job (§6.4).

Coalescing: several updates for one child collapse to one push, because the
delta is recomputed from the store at push time rather than carried in the request.

### 5.6 `ddnsParentZoneWriter`

Reuses the existing transport rather than adding one.

- Message: `dns.Msg` with `SetUpdate(parentZone)` and the delta in `Ns`.
- Targets: the writer's configured `targets`, defaulting to the zone's
  `Primaries` addresses (`v2/structs.go:441`) — the machine the agent already
  transfers from is, in every sane deployment, the machine to update.
- TSIG: `TsigMaterialForPeer` / `StampTsigForPeer`
  (`v2/tsig_peer.go:242,255`), key name from the writer config, defaulting to
  the primary peer's own key. Stamp immediately before each exchange — that
  split exists precisely so a queued message does not go out with a stale
  timestamp and earn a BADTIME.
- Transport: TCP, for the same reason the delegation-sync UPDATEs use it
  (`v2/childsync_utils.go:136`).
- Send: `SendUpdate` (`v2/childsync_utils.go:107`) needs a TSIG provider, which
  it has no parameter for. Add `sendUpdateVia(ctx, msg, zone, addrs, provider)`
  and make `SendUpdate` call it with `nil`. **Do not fork the transport** — its
  return contract (transport error vs. rejection rcode, and the ctx-cancellation
  handling in `exchangeCancellable`) is subtle, hard-won and documented at
  length there.
- Rcode handling: `NOTAUTH`/`REFUSED` → the primary's policy rejects us; that is
  an operator problem, so warn loudly and stop retrying quickly rather than
  hammering. `SERVFAIL`/transport → ordinary backoff. `NOERROR` → success.

An unsigned writer (no TSIG key) is refused unless the backend config sets
`allow-insecure`, matching the posture of `ParentSyncApiConf.AllowInsecure`
(`v2/config_delegationsync.go:259`): a lab convenience, never production.

### 5.7 Wiring the receivers on the agent

Three concrete gaps, all small:

**(a) The DSYNC API listener is auth-only.** `StartAgent`
(`v2/main_initfuncs.go:334`) does not start it; `StartAuth` (`:283`) does. Add
the same block. `SetupDsyncApiRouter` already returns `nil` when the scheme is
not configured, so an agent that does not offer API gets no listener.

**(b) The agent blanket-REFUSEs ordinary queries.** `v2/defaultqueryhandlers.go:163`.
The KeyState wrapper is installed *above* that refusal, so a child's KeyState
inquiry to a `childsync-proxy` agent currently receives a `REFUSED` reply — and
`queryKeyState` (`v2/keystate_verify.go:386`) treats any non-NOERROR as a
failure. **The KeyState channel is therefore broken on an agent today**, which
also means the child-side proxy cannot inquire against an agent-fronted parent.

Narrow fix: when the app is an agent, the query carries a KeyState option, and
`FindZone(qname)` returns a zone with `OptChildSync`, fall through to
`zd.QueryResponder` instead of refusing. Everything else the agent serves stays
refused. Do not widen this into "agents answer queries for childsync zones" —
the agent is not in the NS set and must not look like it is.

**(c) `SetupZoneSync` must not publish locally.** `v2/zone_utils.go:1661`
calls `PublishDsyncRRs` and `ParentSig0KeyPrep` unconditionally for
`OptChildSync`. On a `childsync-proxy` zone both must route to the proxy
publisher. `Sig0KeyPreparation`'s origination backstop
(`v2/delegation_sync.go:323`) does not help: it delegates to
`zoneMayOriginateContent`, which returns `true` off tdns-auth by design.

Everything else already works on the agent unchanged: `NotifyResponder` finds
the parent secondary via `FindZone` and gates on the transferred `_dsync` RRset;
`UpdateResponder` needs only `OptAllowChildUpdates` and a backend;
`ScannerEngine`, `ZoneUpdaterEngine`, `UpdateHandler`, `DelegationSyncher`,
`NotifyHandler` and `DnsEngine` are all already in `StartAgent`; `/keystore`,
`/truststore`, `/zone/childsync`, `/dsync-api/credential` and
`/dsync-api/cert-credential` are already registered for agents
(`v2/apirouters.go:99`). `DelegationSyncWarning` is not in
`serviceImpactingErrors` (`v2/enums.go:445`), so a degraded advertisement does
not take the zone dark or make it refuse NOTIFY.

### 5.8 The `external-db` store

The problem it solves: `store: sqlite` means the KeyDB file, and sqlite is a
single-writer store with a process-wide gate in front of it (D-9). A separate
provisioning consumer cannot participate — it can neither hold a transaction
while tdns wants one, nor be given a network handle to a local file. Handing
delegation data to a registry pipeline therefore needs a store that is *designed*
for a second process: MariaDB first, PostgreSQL behind the same shim.

#### 5.8.1 The schema is a published interface

This is the part that deserves the most care, and it is the reason the existing
`ChildDelegationData` shape should not simply be recreated in MariaDB.

Once another team's code reads these tables, the shape is a contract. Three
things the current shape cannot express, each of which the consumer needs:

1. **What changed since I last looked.** There is no revision, no sequence, no
   timestamp. A consumer can only re-read everything and diff, every time.
2. **What belongs together.** A child update that removes one NS and adds
   another is one atomic intent. Row-at-a-time reading can observe the removal
   without the addition, and provisioning that intermediate state breaks the
   delegation.
3. **Where it came from.** No channel, no principal, no time. A registry wants
   an audit trail for a delegation change, and the adoption pass (D-3) needs to
   distinguish a row it *observed* in the zone from one a child *asserted*.

There is also a smaller wart worth not reproducing: `UNIQUE (owner, rr)`
(`v2/db_schema.go:31`) omits `parent`, so inserts are globally scoped while the
matching `DELETE … WHERE parent=? AND owner=? …` is parent-scoped. Harmless in
practice — a delegation name has exactly one parent — but wrong as a contract,
and it forecloses ever storing anything parent-scoped that is not a delegation
name.

#### 5.8.2 Two tables plus an ack table

```sql
-- DNS names and RRtypes are ASCII, so the name columns are declared ascii
-- rather than utf8mb4. That is not cosmetic: it is what keeps the primary key
-- below InnoDB's 3072-byte limit. In utf8mb4 the four key columns would come to
-- ~3124 bytes and the CREATE would be rejected.
--
-- `rr` is unbounded (a long TXT or a post-quantum KEY exceeds 255 chars), so it
-- cannot be in the key directly. A stored SHA-256 of it can.

-- Current intended state: what the parent zone should contain.
-- A materialised view of the log, maintained in the same transaction.
CREATE TABLE tdns_delegation (
    parent      VARCHAR(255) CHARACTER SET ascii NOT NULL,
    child       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    owner       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    rrtype      VARCHAR(16)  CHARACTER SET ascii NOT NULL,
    rr          TEXT NOT NULL,
    rr_hash     BINARY(32) AS (UNHEX(SHA2(rr, 256))) STORED,
    origin      VARCHAR(16) NOT NULL,          -- observed | asserted
    revision    BIGINT      NOT NULL,          -- log revision that last touched this row
    updated_at  DATETIME(3) NOT NULL,
    PRIMARY KEY (parent, owner, rrtype, rr_hash),
    KEY (parent, child),
    KEY (revision),
    CONSTRAINT chk_origin CHECK (origin IN ('observed','asserted'))
);

-- Append-only change log: the truth. One row per action, grouped by change_id,
-- ordered by revision.
CREATE TABLE tdns_delegation_log (
    revision    BIGINT AUTO_INCREMENT PRIMARY KEY,
    change_id   BINARY(16)   NOT NULL,         -- one UUID per applied UpdateRequest
    parent      VARCHAR(255) CHARACTER SET ascii NOT NULL,
    child       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    op          VARCHAR(16)  NOT NULL,         -- add | del-rr | del-rrset
    owner       VARCHAR(255) CHARACTER SET ascii NOT NULL,
    rrtype      VARCHAR(16)  CHARACTER SET ascii NOT NULL,
    rr          TEXT,                          -- NULL for del-rrset
    channel     VARCHAR(16)  NOT NULL,         -- update | dsync-api | scanner | adopt
    principal   VARCHAR(255),                  -- SIG(0) signer or API principal
    applied_at  DATETIME(3)  NOT NULL,
    KEY (change_id),
    KEY (parent, revision),
    CONSTRAINT chk_op CHECK (op IN ('add','del-rr','del-rrset'))
);

-- Written ONLY by the consumer, read only by tdns. Never a shared mutable
-- column on the tables above: that is where two writers fight.
CREATE TABLE tdns_delegation_ack (
    consumer    VARCHAR(64)  CHARACTER SET ascii NOT NULL,
    parent      VARCHAR(255) CHARACTER SET ascii NOT NULL,
    revision    BIGINT       NOT NULL,         -- provisioned through here
    status      VARCHAR(16)  NOT NULL,         -- ok | failed
    detail      TEXT,
    acked_at    DATETIME(3)  NOT NULL,
    PRIMARY KEY (consumer, parent)
);
```

`origin`, `op` and `status` are `VARCHAR` + `CHECK` rather than `ENUM`:
`ENUM` reads better in MariaDB and has no PostgreSQL equivalent that survives a
schema diff, and adding a value to an `ENUM` is a table rebuild. The dialect
shim (§5.8.3) is only worth having if the schema does not itself pin a vendor.

**Why a log and a state table rather than either alone.** The state table alone
cannot answer "what changed" or "what belongs together". The log alone forces
every reader — including tdns's own scanner diff, which asks for current state
on the hot path (`v2/scanner.go:251,877`) — to replay history. Maintaining both
in one transaction costs one extra statement per action and gives the consumer
both an incremental feed and a cheap full rebuild. The state table is derivable
from the log, so if they ever disagree the log wins and the state table is
rebuilt.

**Change grouping.** `ApplyChildUpdate` receives one `UpdateRequest` carrying
all the actions of one child update. It mints one `change_id`, writes every
action to the log and applies every one to the state table, in a single
transaction. A consumer that reads `WHERE revision > watermark ORDER BY
revision` and stops at a `change_id` boundary never sees half a change.

**Consumer contract, to be documented alongside the DDL:**

- read `tdns_delegation_log` incrementally from your own watermark, applying
  whole `change_id` groups; or read `tdns_delegation` for a full rebuild;
- write your progress to `tdns_delegation_ack`;
- never write the other two tables. Grants enforce this (§5.8.5).

#### 5.8.3 Dialect

Two constructs differ between MariaDB and PostgreSQL and nothing else in this
SQL does: the placeholder style (`?` vs `$n`) and the upsert
(`INSERT … ON DUPLICATE KEY UPDATE` vs `INSERT … ON CONFLICT … DO UPDATE`).

**Write against a ~30-line dialect shim from the first commit, ship MariaDB
only.** Not because PostgreSQL is planned, but because the alternative is
inlining MariaDB syntax at a dozen call sites and discovering later that adding
a driver is a refactor rather than a config value. `INSERT OR REPLACE`
(`v2/delegation_backend_db.go:23`) is sqlite-only and must not be carried over
verbatim; note also that it *replaces the whole row*, which would reset `origin`
and `revision`, so the upsert has to name its columns either way.

Driver: `github.com/go-sql-driver/mysql`. It is the first SQL driver besides
sqlite3 in `v2/go.mod` — worth calling out in review, since it is a new
dependency for every binary that links `v2/`, not just tdns-agent.

#### 5.8.4 Schema ownership and startup verification

tdns creates its own sqlite tables unconditionally at startup (`dbSetupTables`,
`v2/db.go:108`, which calls `Fatal` on any failure). That posture is wrong for a
database somebody else's DBA owns and somebody else's application also uses.

- `auto-migrate: false` by default. tdns ships the DDL; the DBA runs it.
- At startup, **verify** the schema — tables present, expected columns with
  compatible types — and on a mismatch set `ConfigError` on the zone naming the
  discrepancy. Not `Fatal`: one misconfigured zone must not take down a daemon
  serving others.
- `auto-migrate: true` is available for lab and single-owner deployments and
  creates the tables if absent. It never alters an existing table.

#### 5.8.5 Operational posture

- **Availability.** With `store: external-db`, the delegation service is only as
  available as the database. Connection pool with bounded per-call timeouts;
  on failure `ApplyChildUpdate` returns an error, so the child gets a refusal
  rather than a `NOERROR` for something that was not recorded. That is forced by
  D-2: acceptance *means* recorded, so a store that cannot record must not
  accept. It is also the one respect in which `external-db` is less forgiving
  than sqlite, and the sample config should say so.
- **Credentials.** The DSN carries a password, so it is a `SensitiveString`
  (`v2/config.go:34`) and is never echoed by the config API. TLS to the database
  is configurable and on by default for a non-loopback host.
- **Grants.** Document least privilege for both principals:

  ```sql
  -- tdns
  GRANT SELECT, INSERT, UPDATE, DELETE ON reg.tdns_delegation     TO 'tdns'@'%';
  GRANT SELECT, INSERT                 ON reg.tdns_delegation_log TO 'tdns'@'%';
  GRANT SELECT                         ON reg.tdns_delegation_ack TO 'tdns'@'%';
  -- the provisioning consumer
  GRANT SELECT                         ON reg.tdns_delegation     TO 'prov'@'%';
  GRANT SELECT                         ON reg.tdns_delegation_log TO 'prov'@'%';
  GRANT SELECT, INSERT, UPDATE         ON reg.tdns_delegation_ack TO 'prov'@'%';
  ```

  No `DELETE` on the log for anyone: it is append-only, and pruning is a DBA
  operation with its own retention policy, not something either program does.

#### 5.8.6 What `GetDelegationData` returns when there is nothing

Worth fixing while touching this. `DBDelegationBackend.GetDelegationData`
returns an **error** for a child with no rows (`v2/delegation_backend_db.go:122`),
and `ZonefileDelegationBackend` reads that error as "no data left, remove the
file" (`v2/delegation_backend_zonefile.go:50`) — an error value carrying a
meaning, which the adoption pass (D-3) and the reconciler (§6.4) both have to
distinguish from a real failure. An external store adds genuine failures
(network, auth, timeout) to the same return, so the conflation stops being
survivable.

Make "no rows" an empty result with a nil error, on **both** stores, and fix the
zonefile caller in the same change. Small, but it is a precondition for C-0 and
C-5 being correct rather than accidentally correct.

---

## 6. Behaviour

### 6.1 Cold start

1. Agent starts, transfers the parent zone.
2. PostRefresh → `ReconcileChildSyncAdvertisement`. No DSYNC RRset in the zone
   → full delta. Receiver SIG(0) key generated (keystore only).
3. `ddns` writer pushes DSYNC + URI/TXT + A/AAAA + KEY + SVCB to the primary in
   one message. `manual` writer instead logs the block and raises the warning.
4. Primary applies, bumps serial, NOTIFYs the agent.
5. Next transfer: adoption pass (D-3) seeds the store from existing delegations;
   advertisement diff is empty; state `ready`; warning cleared.
6. Children can now discover and use the service.

### 6.2 A child's DNS UPDATE

1. `UpdateResponder` classifies `CHILD-UPDATE`, validates SIG(0) against the
   truststore, applies `updatepolicy.child` and the coherence checks — all
   unchanged.
2. `UpdateRequest` → `ZoneUpdater` → the composed backend's `ApplyChildUpdate`
   → one atomic store write → `ur.respond(true, nil)` → child gets `NOERROR`.
   With `store: external-db` the same step also appends the change to
   `tdns_delegation_log` under one `change_id`, in the same transaction, and
   the registry consumer can act on it from there.
3. `ParentPushEngine` recomputes the child's delta from the store and pushes.
4. Primary applies, NOTIFYs, agent transfers, reconciler sees intent == actual.

### 6.3 A child's NOTIFY(CDS)

Unchanged through `ScannerEngine`: the scanner reads current DS from the backend
(the store, correctly seeded), scans the child, and enqueues a `CHILD-UPDATE` from
`OnDelegationChange` (`v2/scanner.go:137`). From there it is §6.2 step 2 onward.

### 6.4 Confirmation and reconciliation

The DB is intent; the transferred zone is fact. On every parent-zone refresh,
for each child **with DB rows**, compare and re-push any difference. This is the
mechanism that recovers:

- a push dropped because the queue was full;
- a push the primary silently declined;
- a change an operator made directly at the primary that contradicts recorded
  intent (re-asserted — the delegation service is the authority for children
  that use it);
- the agent restarting with an empty in-flight queue.

It is deliberately the same shape as `ProxyStartupReconcile`
(`v2/delsync_proxy_update.go:464`) on the child side.

**Non-goal, stated so it is not built by accident:** the reconciler never
deletes a delegation for a child with no rows in the store. An empty store must
never be able to empty a parent zone — and with `store: external-db` that is not
hypothetical: an empty result is also what a fresh database, a wrong
`table-prefix`, or a schema restored from nothing looks like.

---

## 7. Config

Two axes in the existing `delegationbackends:` list (D-7), with the old type
names kept as sugar so no existing config changes.

```yaml
delegationbackends:

  # (a) tdns writes to the primary itself. Local sqlite is enough: nothing
  #     else reads it.
  - name: parent-primary
    store:  sqlite            # sqlite | external-db | direct   (default: sqlite)
    writer: ddns              # none | ddns | zonefile | command (default: none)
    ddns:
      targets: []             # default: this zone's configured primaries
      key: agent-to-primary   # TSIG key name from the keystore
      allow-insecure: false   # permit an unsigned UPDATE. Lab only.
      retry-interval: 60s
      max-attempts: 10

  # (b) hand off to a registry provisioning system. tdns writes nothing to
  #     the parent; the consumer does.
  - name: registry-handoff
    store:  external-db
    writer: none
    external-db:
      driver: mysql                                  # mysql (MariaDB) — pgx later
      dsn: "tdns:@tcp(db.example.net:3306)/reg"      # SensitiveString; never echoed
      password: "…"                                  # or in the DSN; SensitiveString
      tls: true                                      # default true off-loopback
      ca-file: /etc/tdns/db-ca.pem
      table-prefix: tdns_                            # default "tdns_"
      auto-migrate: false                            # default false — see §5.8.4
      max-open-conns: 8
      timeout: 5s

zones:
  example.:
    type: secondary
    primaries: [ { addr: 192.0.2.1:53, key: xfr-key } ]
    options: [ childsync-proxy, allow-child-updates ]
    delegationbackend: registry-handoff
    delegationpolicy: registry-strict
    updatepolicy:
      child:
        type: selfsub
        rrtypes: [ NS, A, AAAA, DS, KEY ]
```

Type-name sugar, all still accepted:

| `type:` | expands to |
|---|---|
| `direct` | `store: direct, writer: none` |
| `db` | `store: sqlite, writer: none` |
| `zonefile` | `store: sqlite, writer: zonefile` |
| `upstream` | `store: sqlite, writer: ddns` |
| `external-db` | `store: external-db, writer: none` |

Writing `type:` together with `store:` or `writer:` is an error, not a
precedence rule — the same posture `foldDeprecatedDelegationSync`
(`v2/config_delegationsync.go:73`) takes towards a config that sets a setting in
two places, and for the same reason: picking a winner silently leaves the
operator reading one line while the server obeys another.

The global `childsync:` block is unchanged and already global
(`v2/config_delegationsync.go:149`). Its `notify.addresses` /
`update.addresses` / `api.addresses` mean "the addresses to publish at the
target" — which on a proxy are the *agent's* addresses. That is already the
correct meaning; no change.

Validation to add in `validateDelegationBackendCombination`
(`v2/delegation_backend_validate.go:37`):

- `store: direct` accepts only `writer: none`; on a secondary it is already
  refused outright.
- `childsync-proxy` requires a backend that can hand data out of process — any
  (store, writer) pair except `store: direct`.
- `writer: ddns` requires `childsync-proxy` on the zone, and therefore a
  secondary.
- `writer: ddns` with neither `ddns.key` nor `ddns.allow-insecure` is a config
  error naming both.
- `store: external-db` requires a `dsn`, and — unless `auto-migrate` — a schema
  that passes the startup check (§5.8.4), which fails the *zone* with
  `ConfigError` rather than the daemon.

---

## 8. Security

**The agent holds delegation-write authority over the parent zone.** That is the
whole point, and it needs to be bounded on both ends.

*At the primary* — document per implementation. BIND:

```
update-policy {
    grant agent-to-primary zonesub  NS DS A AAAA;
    grant agent-to-primary name _dsync.example.  DSYNC URI TXT;
    grant agent-to-primary subdomain _dsync.example.  A AAAA SVCB KEY;
};
```

Not `allow-update { key …; }`, which grants the whole zone including the apex
SOA and NS. The doc must say why.

*At the agent* — the §D-5 name bound in `ParentZoneWriter`, so a bug on the
receive path cannot become an apex rewrite even against a permissive primary.

*Trust boundaries unchanged.* The DSYNC API listener stays on its own socket
with its own credentials (`v2/dsync_api_server.go:45` explains why, and the
reasoning holds identically here: a registrant is not an operator). Child SIG(0)
keys live in the agent's own truststore — a `TRUSTSTORE-UPDATE` writes to the
KeyDB and never to the zone (`v2/zone_updater.go:480`), so nothing about key
bootstrap needs the agent to author anything.

*New exposure worth naming:* the agent's TSIG key to the primary is a
higher-value credential than anything the child-side proxy holds. Compromising
the agent means being able to repoint every delegation in the parent zone,
bounded only by the primary's `update-policy`. That is an argument for the
narrow grant above, and for not co-locating this agent with anything else.

---

## 9. Failure modes

| failure | behaviour |
|---|---|
| primary unreachable | backoff, bounded attempts, then `DelegationSyncWarning`; DB keeps intent; reconciler retries every refresh |
| primary REFUSES/NOTAUTH | fast stop + loud warning naming rcode and EDE — an operator problem, not a transient |
| push queue full | logged, dropped; reconciler re-derives from the store |
| agent restarts with pushes in flight | in-memory queue lost; first refresh reconciles |
| foreign KEY at the UPDATE target | `foreign-key`, warning, no competing key minted; NOTIFY and API schemes unaffected |
| advertisement never lands | `waiting-for-publication`; `advertisesDsyncNotify` keeps refusing NOTIFY with `EDENotifyDsyncSchemeNotAdvertised`, which is the honest answer |
| operator edits a delegation at the primary | reconciler re-asserts recorded intent for children the service knows; leaves unknown children alone |
| two writing agents (D-4) | not prevented; documented as unsupported |
| parent zone expires | existing `HasExpired` guards already refuse UPDATE and queries |
| external store unreachable | `ApplyChildUpdate` errors → the child is refused rather than told NOERROR for something unrecorded (D-2). Per-zone `DelegationSyncWarning`; the DSYNC service is only as available as the store |
| external store schema mismatch | zone-level `ConfigError` at startup naming the discrepancy; the daemon and its other zones keep running (§5.8.4) |
| consumer falls behind or stops | nothing breaks in tdns: the log grows and `tdns_delegation_ack` stops advancing. Monitoring the ack watermark is the consumer operator's job, and the doc says so |
| consumer writes the state table anyway | prevented by grants (§5.8.5), not by convention |

---

## 10. Implementation plan

LOC figures are rough order of magnitude, implementation and tests separately.

| # | item | files | impl | test | risk |
|---|---|---|---|---|---|
| **C-0** | seed the delegation backend from the served zone on first load ("adoption pass"); reconciler is additive for unknown children | `delegation_backend_db.go`, new `delegation_adopt.go` | 90 | 140 | **medium** — fixes a live bug (§D-3) and is independently shippable |
| **C-1** | `OptChildSyncProxy`: enum, parse, implies-childsync, agent+secondary gate | `enums.go`, `parseoptions.go`, `zone_utils.go` | 70 | 110 | low |
| **C-2** | split `PublishDsyncRRs` into `BuildDsyncPublication` + install; tdns-auth behaviour bit-identical | `ops_dsync.go` | 130 | 160 | **medium** — refactor of a function every parent depends on; the per-scheme guard must survive intact |
| **C-3** | `ParentZoneWriter` + the three writers; `sendUpdateVia` TSIG parameter | new `parent_zone_writer.go`, `childsync_utils.go` | 220 | 260 | medium |
| **C-4a** | `GetDelegationData` returns an empty result, not an error, for "no rows"; fix the zonefile caller that reads the error as a signal (§5.8.6) | `delegation_backend_db.go`, `delegation_backend_zonefile.go` | 30 | 60 | low — precondition for C-0 and C-5 being correct rather than accidentally correct |
| **C-4b** | split `DelegationBackend` into (store, writer) per D-7; `type:` names become sugar; validation | `delegation_backend.go`, `delegation_backend_validate.go`, `parseconfig.go` | 160 | 190 | **medium** — touches every existing backend's construction; behaviour must be unchanged for `direct`/`db`/`zonefile` |
| **C-4c** | the `upstream` writer wired onto that split | new `delegation_backend_upstream.go` | 90 | 120 | low |
| **C-4d** | `external-db` store: dialect shim, MariaDB driver, the three tables, change grouping, startup schema verification | new `delegation_store_externaldb.go`, `delegation_store_schema.go`, `go.mod` | 420 | 480 | **medium-high** — new dependency for every `v2/` binary; the schema is a published interface and is expensive to change afterwards |
| **C-5** | `ParentPushEngine` + per-child delta + backoff + warnings | new `parent_push_engine.go`, `main_initfuncs.go` | 240 | 280 | medium |
| **C-6** | `ReconcileChildSyncAdvertisement` + state machine + PostRefresh hook | new `childsync_proxy.go`, `zone_hooks.go` | 260 | 320 | medium |
| **C-7** | receiver wiring: DSYNC API listener on agent; KeyState query fix; `SetupZoneSync` routing | `main_initfuncs.go`, `defaultqueryhandlers.go`, `zone_utils.go` | 80 | 130 | **medium** — the KeyState fix is a live bug and wants its own test |
| **C-8** | operator surface: `zone childsync proxy-status` / `advert` / `reconcile`; instruction block | `apihandler_zone.go`, `cli/zone_cmds.go`, `childsync_proxy.go` | 190 | 130 | low |
| **C-9** | docs + sample config: `cmdv2/agent/tdns-agent.sample.yaml`, `guide/special-features.md`, primary-side `update-policy` recipes, the `external-db` DDL, grants and consumer contract | docs | 220 | — | low |

**Rough total: ~2100 implementation, ~2260 test.**

### Ordering

1. **C-4a, then C-0, each alone.** Both fix existing correctness bugs, both are
   meaningful on tdns-auth with none of the rest, and everything downstream
   assumes a correctly seeded backend that reports emptiness as emptiness.
   C-4a first: C-0's adoption pass has to distinguish "no rows" from "the store
   is broken", and today it cannot.
2. **C-7's KeyState fix, alone.** Also an existing bug: the KeyState channel is
   broken against any agent today. Small, testable, no dependencies.
3. **C-2 and C-4b.** The two refactors, each with an exact-behaviour test on the
   existing paths, landed before anything depends on the new shapes.
   Independent of each other, so they can go in parallel.
4. **C-1, C-3, C-4c** — option plumbing, writer, the `upstream` writer on the
   settled split.
5. **C-4d.** The external store, on a settled (store, writer) split. It is
   deliberately *not* on the critical path for a working `childsync-proxy`:
   `store: sqlite, writer: ddns` is a complete deployment, so C-4d can be
   reviewed on its own schedule and its schema argued about without holding
   anything else up.
6. **C-5, C-6** — the two engines.
7. **C-7 remainder, C-8, C-9.**

Nothing here should land as one PR. C-4a, C-0 and the KeyState fix are
separately reviewable and separately valuable; the rest is inert until C-6
registers the hook.

### Tests

Mirror the existing proxy suites (`delsync_proxy_test.go`,
`delsync_proxy_update_test.go`, `delsync_proxy_prerefresh_test.go`), which is
also where the fixtures for "an agent secondary with a scratch `new_zd`" already
live:

- **Unit:** advertisement diff (each RRset, each of the five states); the §D-5
  name bound (an apex SOA, an out-of-bailiwick name, an unrelated child, each
  refused); per-child delta from DB + served zone; adoption pass idempotence;
  writer rcode classification.
- **Integration (in-process):** a fake primary answering DDNS — accept, REFUSE,
  SERVFAIL, silence — driving the full receive→persist→push→transfer→reconcile
  loop over all three inbound channels.
- **Regression:** `PublishDsyncRRs` output before and after C-2, byte-identical
  on the tdns-auth path; a `childsync-proxy` zone never posts a `ZONE-UPDATE`
  for its own zone (assert on the `UpdateQ`); an empty DB never produces a
  delete.
- **Shutdown:** `ParentPushEngine` exits on `ctx.Done()` with a full queue and a
  hung writer, per `CONTEXT.md`.
- **Store equivalence:** one table-driven suite run against both stores —
  sqlite in a temp file, MariaDB in a container, skipped when no DSN is set.
  The two must agree on every `DelegationBackend` operation, or the (store,
  writer) split is a lie and C-4b has regressed something.
- **`external-db` specifically:** a change spanning several actions appears in
  the log under one `change_id` and is never observable half-applied by a reader
  ordering on `revision`; the upsert preserves `origin` and advances `revision`;
  the startup schema check fails the zone (and only that zone) on a missing
  column; a store outage produces a refusal, never a `NOERROR`.

---

## 11. Open questions

**Q-1 — synchronous acknowledgement on the API channel.** HTTP can afford to
wait where RFC 2136 through a shared `ZoneUpdater` cannot. A `Prefer:
wait=<sec>` returning `200` on confirmed publication and `202` otherwise would
give registrar clients a genuinely stronger promise on the one channel that can
carry it. Deliberately out of scope for v1; noted because the 202 shape should
be reserved now rather than retrofitted over a `200`.

**Q-2 — multiple writing agents (D-4).** Needs either leader election or a
coordination record in the parent zone. Not designed here. The failure mode if
someone deploys it anyway is push-flapping, which is noisy rather than silent —
acceptable for v1.

**Q-3 — does the proxy also front `_signal` / RFC 9615 names?** The child-side
proxy explicitly cannot (`v2/child_bootstrap.go:18`: `_signal` lives in the
nameserver's zone). The parent-side question is different — whether
`at-ns` child-key verification works when the *parent* is proxied — and the
answer appears to be yes, because verification is a lookup the agent performs
outward via its IMR (`v2/truststore_verify.go:89`) and needs no local authority.
Worth confirming with a test rather than by reading.

**Q-4 — IXFR.** The reconciler diffs whole RRsets from the served zone, so IXFR
versus AXFR is transparent. Untested against a primary that answers IXFR with a
condensed delta; the existing `OptRequestIxfr` machinery should make this a
non-issue, but it should be exercised.

**Q-5 — does anything else want to live in the external store?** The truststore
is the candidate an operator will ask about next: a registry pipeline that
provisions delegations plausibly also wants to see which child keys the parent
trusts. D-8 says no for now, and the reason is only partly about key material —
the truststore holds child *public* keys, so the security argument is weaker
there than it is for the keystore. The stronger reason is that the delegation
tables are a small, self-contained contract and the truststore's shape is still
moving (`2026-09-02-delegation-sync-unification-plan.md` §3 is mid-flight on the
verification vocabulary). Revisit once that settles; do not widen D-8 quietly in
the meantime.

**Q-6 — log retention.** `tdns_delegation_log` grows without bound and nothing
in tdns prunes it, by design (§5.8.5: no `DELETE` grant for either program).
That is right for a v1 — a DBA with a retention policy is a better answer than a
pruner racing a consumer's watermark — but it is an operational obligation the
deployment doc has to state plainly rather than leave implied.

---

## 12. What this design deliberately does not do

- **No new validation, authorization or coherence logic.** The proxy runs the
  parent's existing code. Anything that is wrong for a proxied parent is wrong
  for tdns-auth too, and belongs in a fix to the shared path.
- **No DS opinion.** See D-6.
- **No second implementation of anything.** The transport is `SendUpdate`, the
  TSIG is `tsig_peer.go`, the hook registration is
  `registerStandardRefreshHooks`, the degraded-state reporting is
  `DelegationSyncWarning`. `external-db` is the one place a second
  implementation appears — two stores behind one interface — which is why C-4b
  puts them behind a shared split with a shared test suite (§10) rather than
  letting a second storage path grow its own edges. The lesson of
  `2026-09-02-delegation-sync-unification-plan.md` — two implementations of one
  thing diverge, and the divergence produces bugs ten days apart — is the main
  constraint this design was written under.
- **No AXFR service.** The agent stays out of the NS set and keeps refusing
  ordinary queries; only the KeyState inquiry is carved out, as narrowly as it
  can be.
- **No migration of the KeyDB off sqlite.** See D-8. `external-db` is one
  handoff table set, not a database abstraction layer for tdns.

---

## Amendment 2026-09-08 — implementation basis

Implementation authorised 2026-09-08. Branch `feature/childsync-proxy`, cut from
`childsync-proxy` (= `main` f4bea22 plus this document). One commit per §10
item, in §10 order, with C-4a, C-0 and the KeyState half of C-7 first so each
can be peeled into its own PR.

### A-1. PR #514 audit

PR #514 (`fix/sign-before-publish`, 93 commits) has merge-base f4bea22, this
document's base. Of the files this document cites, 24 are byte-identical on
#514, including every file it creates or rewrites: `ops_dsync.go`, the four
`delegation_backend*.go`, `zone_hooks.go`, `defaultqueryhandlers.go`,
`notifyresponder.go`, `delsync_proxy*.go`, `childsync_utils.go`,
`tsig_peer.go`, `db.go`, `db_schema.go`, `zone_origination.go`,
`config_delegationsync.go`, `keystate_verify.go`. The `DelegationBackend`
interface, the `CHILD-UPDATE` choke point, the `OnZonePostRefresh` mechanism,
`SetupZoneSync`'s body and `zoneMayOriginateContent` are unchanged. D-1 to D-9
stand. A branch cut from either base merges forward onto the other without
conflict.

**Interface drift on #514, none of it a design change:**

- `UpdateResponder` and `ValidateUpdate` take a `context.Context`. C-7's tests
  that drive the UPDATE channel pass one.
- `Conf.Internal.Scanner` became `Conf.Internal.GetScanner()`, an atomic that
  returns nil before `ScannerEngine` publishes. `childNameserverAsker` is
  nil-safe, and `StartAgent` starts the scanner, so the agent path holds.
- `rememberDiscoveredChildKey` takes a context and returns a done channel;
  `KeyDB.engineCtx` is gone. §8's "trust boundaries unchanged" holds.
- `ResignQ` carries `ResignRequest`; `SetupZoneSigning` is
  `registerForPeriodicResign`. Agents never sign; nothing here touches them.

**What #514 supplies, to be reused rather than rebuilt (§12):**

- `scanner.imr()` resolves the IMR at the point of use, fixing #503. A freshly
  started proxy therefore accepts child UPDATEs before any NOTIFY has arrived.
- `retryWithBackoff` (`delsync_retry.go`) is context-aware. §5.5's backoff is
  that function. Note the divergence from `sendUpdateWithRetry`, which retries
  `REFUSED`; §5.6 stops fast on it, because on this side `REFUSED` means the
  primary's policy, an operator problem.
- `sameKeyRdata` (`ops_key.go`) compares KEY records on RDATA, ignoring owner
  and TTL. §5.3 step 3's "present and ours" is that comparison.
- `PublishCsyncRRAndWait` (`ops_csync.go`) is a publish-then-verify-postcondition
  shape C-2 may follow.

**Line drift.** Citations in this document were taken on `main`; on #514 they
move as follows. Cosmetic, listed so a reader on either base can follow them.

| citation | main | #514 |
|---|---|---|
| `zone_utils.go` `SetupZoneSync` / proxy `ConfigError` | 1661 / 1749 | 1754 / 1854 |
| `delegation_sync.go` `Sig0KeyPreparation` / childsync gate / origination backstop | 273 / 309 / 323 | 289 / 325 / 339 |
| `main_initfuncs.go` `StartAuth` / `StartAgent` | 283 / 334 | 287 / 338 |
| `parseoptions.go` parentsync exclusivity | 420 | 396 |
| `structs.go` `Primaries` | 441 | 488 |
| `scanner.go` `ScannerEngine` / `OnDelegationChange` / DS read / NS read | 110 / 137 / 251 / 877 | 145 / 172 / 288 / 927 |
| `updateresponder.go` `ApproveChildUpdate` | 515 | 529 |
| `zone_updater.go` dispatch / KEY guard / truststore | 241 / 273 / 480 | 238 / 270 / 477 |

`zone_hooks.go:67` is line 65 on both bases.

### A-2. §5.3 step 5: the reconciler enqueues; it never writes

Step 5 of §5.3 is replaced:

> 5. Non-empty delta → `manual` writer: `ChildSyncProxyWaiting`, the warning
>    and the instruction block, all in memory. Any other writer: a
>    **non-blocking enqueue** of `ParentPushRequest{Kind: advertisement}` to
>    `ParentPushEngine`, state `ChildSyncProxyPublishing`. A full queue is
>    logged and recovered by the next refresh, exactly as §5.4 says for child
>    pushes.

The hook runs in two places, and neither may do network I/O. On first load it
runs on the refresh engine goroutine (`initialLoadZone` → `Refresh` →
`FetchFromUpstream` → `OnZonePostRefresh`), where #514's engine redesign states
the invariant that the engine goroutine performs no unbounded blocking
operation. On every later refresh it runs on a pool worker, and a DDNS exchange
with backoff there holds one of a bounded set. The hook signature
`func(zd *ZoneData)` also carries no context. The enqueue makes both moot.

Consequently `ParentPushRequest` carries a `Kind` — `children` (the affected
child names) or `advertisement` — and `ParentZoneWriter.Write` is called from
exactly one goroutine, the push engine's. §5.5 step 1–2 compute the delta per
kind: for `advertisement`, from `BuildDsyncPublication` against the served
zone; for `children`, from the store against the served zone. The D-5 name
bound applies to both, and the advertisement names are the third bullet of
D-5.

### A-3. `external-db` lives in its own module

What links a driver into a binary is the import graph. `v2/db.go` imports the
sqlite driver, so every binary that links `v2/` carries it; a MariaDB driver
imported from package `tdns` would spread the same way, which is what §5.8.3's
review note observed. The store is therefore not a file in `v2/`.

**Decision:** module `github.com/johanix/tdns/v2/externaldb` at
`v2/externaldb/`, with its own `go.mod`, importing `v2/` the way `v2/cli` and
`v2/debug` do. It implements `DelegationStore` and so imports `tdns`; `tdns`
cannot import it back. Wiring is by registration:

- package `tdns` gains `RegisterDelegationStore(name string, factory
  DelegationStoreFactory)`, consulted by the store axis of the composed backend
  (§5.4). Part of C-4b, since it is the seam.
- `externaldb` registers `"external-db"` in `init()`.
- `cmdv2/agent/main.go` blank-imports the module, beside the sqlite driver it
  already imports; `cmdv2/agent/go.mod` gains the replace line. No other
  binary imports it.
- A binary whose main did not import it reports `store: external-db` as a
  `ConfigError` naming the binary: "not compiled into tdns-auth".

The `external-db:` config block of §7 is parsed by `tdns` into a plain
`ExternalDBConf` (data only, no driver) and handed to the factory. §5.8.3's
dependency note is retired: the driver is linked into tdns-agent only. D-8
gains the sentence "and it is linked into the agent alone".

The store equivalence suite (§10 *Tests*) cannot be an internal test of package
`tdns` — importing the store there is an import cycle. It lives in the
`externaldb` module's tests, driving both stores through the registry, with the
MariaDB half skipped when no DSN is set.

### A-4. §10 corrections

| # | change |
|---|---|
| **C-0** | the sqlite table gains an `origin` column (`asserted` \| `observed`) through `dbMigrateSchema`'s `ALTER TABLE ADD COLUMN` path, default `asserted` for existing rows. The pass runs once per zone from the `OnFirstLoad` path (`SetupZoneSync`), for any `OptChildSync` zone whose store is not `direct` |
| **C-4b** | adds the store registry (`delegation_backend.go`, ~40 lines) |
| **C-4d** | files: `v2/externaldb/{go.mod,store.go,dialect.go,schema.go,store_test.go}`, `cmdv2/agent/main.go`, `cmdv2/agent/go.mod`. The equivalence suite moves here. Tested against a live MariaDB, not sqlite alone |
| **C-5** | `ParentPushRequest.Kind`; the engine computes advertisement deltas as well as child deltas (A-2) |
| **C-6** | the reconciler enqueues (A-2); `ReconcileChildSyncAdvertisement` loses its network path entirely and becomes a pure in-memory diff |
