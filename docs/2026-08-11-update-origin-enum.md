# Collapse the UpdateRequest origin booleans into one enum

**Date:** 2026-08-11
**Status:** PROPOSED — agreed in principle, deliberately deferred to its own
change because it is invasive.
**Context:** `2026-08-10-ddns-cli-and-api-updates.md`

---

## The problem

`UpdateRequest` now carries three booleans that all answer one question — where
did this request come from:

```go
InternalUpdate bool // not a DNS UPDATE from the outside
PreAuthorized  bool // authorization settled by the API handler
Replay         bool // re-application of already-persisted deltas
```

They are not independent. Exactly one of four origins is true for any request:

| Origin | Today | update-policy | Persist delta |
|--------|-------|---------------|---------------|
| wire (RFC 2136) | all three false | enforced | yes |
| internal publisher (CSYNC/CDS/KEY) | `InternalUpdate` | bypassed | yes |
| management API | `PreAuthorized` | bypassed | yes |
| delta replay | `Replay` + `InternalUpdate` | bypassed | **no** |

Three booleans encode eight states, four of which are meaningless and one of
which — `PreAuthorized` on a request that arrived over the wire — would be an
unauthenticated update accepted as authorized. Nothing in the type system says
so; it is prevented today by the fact that only one function sets the flag.

The behaviour is already spread across several sites that each re-derive the
origin by testing a different combination:

- the applier's policy gate: `!InternalUpdate && !PreAuthorized`
- the TTL decision: `!InternalUpdate && !PreAuthorized`
- delta persistence: `!Replay`
- the updater's admission check: `InternalUpdate || (PreAuthorized && …)`

Each of those is a place to forget a flag when a fifth origin appears, and the
failure mode is silent: a missed `PreAuthorized` in the TTL test rewrites an
operator's TTL, a missed `Replay` doubles the persisted history on every
restart. Both of those were real bugs found in review rather than by the
compiler.

## The proposal

One field:

```go
type UpdateOrigin uint8

const (
    OriginWire     UpdateOrigin = iota // RFC 2136 UPDATE from outside
    OriginInternal                     // this server's own publishers
    OriginAPI                          // management API, authorization already settled
    OriginReplay                       // re-application of persisted deltas
)
```

with the policy expressed once, as predicates on the origin rather than as
boolean arithmetic scattered through the call sites:

```go
func (o UpdateOrigin) EnforcesUpdatePolicy() bool { return o == OriginWire }
func (o UpdateOrigin) OwnsRecordTTL() bool        { return o != OriginWire }
func (o UpdateOrigin) PersistsDelta() bool        { return o != OriginReplay }
```

Adding a fifth origin — the DSYNC-API child self-service surface is the obvious
candidate, and it wants *policy enforced* unlike the management API — then means
adding one constant and answering three questions, with the compiler unable to
help but the questions at least all in one file.

## Why it is not in the phase 1/2 work

It touches every `InternalUpdate` site in the tree, which is far more than the
update path: the `ops_*` publishers all set it, as do the rollover and
delegation-sync paths. That is a large mechanical diff through code the phase
1/2 changes were already modifying, and mixing it in would have made those
changes much harder to review for the things that actually needed review.

It is also not urgent: the current encoding is *correct*, just fragile.

## Shape of the change

1. Add `UpdateOrigin` and the predicates. Keep the three booleans, derived from
   the origin, so nothing breaks yet.
2. Convert the four decision sites to the predicates.
3. Convert producers to set `Origin` instead of the booleans, one subsystem at
   a time — `ops_*`, rollover, delegation sync, the API handler, the replay
   path.
4. Delete the booleans once nothing sets them.

Step 4 is the one that catches anything missed: a producer still setting a
boolean stops compiling.

## Test that should exist regardless

Whatever the encoding, this deserves a table test over the origins asserting
all three behaviours — policy enforcement, TTL ownership, delta persistence —
for each. Today those are covered in three separate tests that each vary one
flag, which is exactly why two of the combinations were wrong.

## Not in scope

The DSYNC-API surface itself. It is named above only because it is the reason
a fifth origin is likely, and because its authorization model differs from the
management API's in a way the enum should be able to express.
