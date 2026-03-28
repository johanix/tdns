# Architectural Improvements

Date: 2026-03-26
Status: Collection of needed improvements

## 1. Empty REPLACE Operations for Stale Data Cleanup

### Problem

When an agent's role changes (e.g. was a signer, no longer
is) or stale data persists from a previous configuration,
the combiner has no way to learn that the data should be
removed. The current behavior is:

- If I'm not a signer, I don't send DNSKEYs.
- If I have no NS records, I don't send NS.

This means stale contributions persist indefinitely. The
originator cannot easily delete them because:

1. It may no longer have the exact records to delete.
2. A ClassNONE delete requires knowing the precise RRs.
3. The combiner policy now correctly rejects DNSKEYs from
   non-signers, but this only prevents NEW contributions —
   it doesn't remove OLD ones.

### Proposed Solution

**Explicit empty REPLACE operations.** When an agent has
nothing to contribute for an RRtype, it should send a
REPLACE operation with an empty RRset. The combiner
interprets this as "this agent has zero records of this
type" and removes any stale contributions.

The `ReplaceCombinerDataByRRtype` function already handles
empty replacement sets correctly — it deletes the agent's
contribution for that owner+rrtype.

### When to Send Empty REPLACEs

**On resync (push phase):** When the agent resyncs to the
combiner, it currently sends its local data as REPLACE
operations. It should also send empty REPLACEs for RRtypes
it does NOT contribute:

- **Not a signer?** → REPLACE DNSKEY with empty set
- **No NS records?** → REPLACE NS with empty set
- **No KEY?** → REPLACE KEY with empty set

The set of "potentially contributed RRtypes" is known
from the AllowedLocalRRtypes preset: DNSKEY, CDS, CSYNC,
NS, KEY. For each of these, if the agent has no data, it
sends an empty REPLACE.

**On startup (first sync):** Same logic as resync. The
agent's first contribution to the combiner after startup
should establish a clean baseline for all RRtypes.

**On role change detection:** If the agent detects (via
HSYNCPARAM) that it is no longer a signer, it should
proactively send empty REPLACE for DNSKEY.

### Implementation Sketch

In the resync push phase (syncheddataengine.go), after
sending local data as Operations:

```go
for rrtype := range AllowedLocalRRtypes {
    if !sentRRtypes[rrtype] {
        ops = append(ops, core.RROperation{
            Operation: "replace",
            RRtype:    dns.TypeToString[rrtype],
            Records:   []string{}, // empty = delete
        })
    }
}
```

### Interaction with DNSKEY Policy

The new `checkDNSKEYPolicy` rejects DNSKEYs from
non-signers. An empty REPLACE for DNSKEY from a
non-signer should be ACCEPTED (it's a deletion, not a
contribution). The policy check should distinguish
between "adding DNSKEYs" (reject for non-signers) and
"removing DNSKEYs" (always accept).

### Risk

Low. `ReplaceCombinerDataByRRtype` already handles empty
sets. The change is in the agent (send empty REPLACEs)
and a minor policy adjustment in the combiner (allow
empty REPLACE from non-signers for DNSKEY).

## 2. Move Message Handlers Out of tdns-transport

### Problem

The transport layer (`tdns-transport/v2/transport/`) contains
application-level message handlers:

- `HandlePing` — ping/pong with nonce
- `HandleBeat` — heartbeat processing
- `HandleHello` — peer introduction
- `HandleKeystate` — DNSKEY key state signaling
- `HandleSync` / `HandleUpdate` — zone data sync
- `HandleConfirm` — delivery confirmation
- `HandleRfi` — request for information

These handlers know about message semantics (signal types,
key inventories, zones, nonces) that should be application
concerns. The transport layer should only provide:

- Router and middleware chain
- Chunk assembly/disassembly
- Crypto (encrypt/decrypt/sign/verify)
- Peer registry and transport selection

### Why It Matters

When application logic lives in the transport layer:

- Bugs like "empty key inventory rejected" require fixing
  tdns-transport instead of the application.
- Different applications (agent, combiner, signer) cannot
  customize handler behavior without forking transport code.
- The transport package grows unboundedly as new message
  types are added.

### Proposed Solution

Move all `Handle*` functions from `tdns-transport` to the
application layer:

- `HandlePing` → stays in transport (ping is a transport
  built-in, agreed exception)
- `HandleBeat` → tdns or tdns-mp (application routing)
- `HandleHello` → tdns or tdns-mp
- `HandleKeystate` → tdns-mp (signer/agent specific)
- `HandleSync` / `HandleUpdate` → tdns-mp
- `HandleConfirm` → tdns or tdns-mp
- `HandleRfi` → tdns or tdns-mp

The `InitializeAgentRouter`, `InitializeCombinerRouter`,
`InitializeSignerRouter` functions would also move — they
are role-specific wiring that belongs in the application.

The transport layer keeps:
- `DNSMessageRouter` (generic routing)
- Middleware (auth, crypto, stats, logging)
- `RouteToCallback` / `RouteToMsgHandler`
- `ChunkNotifyHandler` (chunk assembly)
- `SendResponseMiddleware`

### Risk

Medium. Many call sites. But the handlers are already
self-contained functions — moving them is mechanical.
The router registration API doesn't change.

### Priority

Not urgent. The current architecture works. Address when
doing the agent extraction or during a dedicated cleanup
pass.

## 3. Separate Combiner Persistence from Editing

### Problem

The combiner currently conflates two distinct roles:

1. **Persistence**: store agent contributions so they
   survive restarts and can be recovered via resync.
2. **Editing**: apply stored contributions to the live
   zone (CombineWithLocalChanges).

Today these are tightly coupled — data is rejected at
receipt time based on editing policy (e.g. DNSKEYs from
non-signers, mp-disallow-edits zones). This means:

- Rejected data is lost (not persisted for recovery).
- A zone transitioning from unsigned→signed has no
  pre-existing DNSKEY contributions to apply.
- An mp-disallow-edits combiner cannot serve as a
  persistence backup for other combiners.
- Empty REPLACE cleanup requires the combiner to accept
  data it currently rejects.

### Proposed Solution

**Accept all contributions from authorized agents for
persistence. Apply editing policy only when building
the live zone.**

Receipt path (always accept):
- Agent sends contribution → combiner stores in
  AgentContributions + persists to DB. No policy
  checks beyond basic authorization.

Edit path (apply policy):
- `CombineWithLocalChanges` filters contributions
  before applying to zone data:
  - Skip DNSKEYs from non-signers
  - Skip all edits for mp-disallow-edits zones
  - Apply RRtype whitelist (AllowedLocalRRtypes)

This separates "what we know" (persistence) from
"what we do" (editing).

### Benefits

- Resync always succeeds (persistence is unconditional)
- Empty REPLACE works naturally (clears persistent store)
- Zone role changes take effect immediately (policy is
  evaluated at edit time, not receipt time)
- Combiner can serve as persistence backup regardless
  of local signing role

### Impact on Current Code

- Remove `checkDNSKEYPolicy` from `combinerProcessOperations`
  (receipt path)
- Add equivalent filtering in `CombineWithLocalChanges`
  (edit path)
- Remove mp-disallow-edits rejection in receipt path
- Keep authorization checks (only authorized agents may
  contribute)

### Priority

Medium. Implement alongside the empty REPLACE work
(item 1) since both affect the same code paths.

## 4. SIG(0) Key Persistence Across Restarts

### Problem

Agents generate SIG(0) keys for delegation sync (parent
UPDATE signing) during OnLeaderElected. The key is stored
in the local KeyDB and sent to peers and the combiner.
However, when agents restart, the generated key may be
lost if the KeyDB is ephemeral or not properly persisted.

Observed symptom: agent A generates key "DjcP" and sends
it to peers B and C. B and C store it in their SDEs
(attributed to A). Agent A restarts, loses the key. Now
B and C have A's old key but A doesn't. If A wins another
election, it generates a NEW key, creating inconsistency.

### Proposed Solution

1. Ensure SIG(0) keys survive restarts by verifying the
   KeyDB file path is persistent (not /tmp or in-memory).
2. On startup, check for existing SIG(0) keys before
   requesting from peers or generating new ones (the
   OnLeaderElected handler already does step a→b→c:
   local check, peer check, generate — but only if the
   local KeyDB is properly persisted).
3. Consider adding a "key reconciliation" step to resync:
   if we have a local SIG(0) key, verify peers agree on
   which key is current.

### Priority

Low. This is primarily a deployment/config concern
(ensure db.file points to a persistent path). Code-level
fixes are defensive only.

## 5. Leader Election Consensus Requires All Peers

### Problem

Leader elections use a consensus protocol that requires
ALL configured peers to participate (vote). If any peer
is unreachable or not participating (e.g. running mpagent
without election support), the election should never
complete.

Observed symptom: with alpha running mpagent (no election
support) and delta/echo running tdns-agent (with election
support), stale keys appeared that could only have been
generated by OnLeaderElected — suggesting elections
completed without alpha's participation.

### Investigation Needed

Verify that the election protocol correctly blocks when
a peer doesn't respond:
- Does the vote timeout correctly prevent unilateral
  election?
- Is there a fallback path that allows self-election
  when peers are "silent" (as opposed to "down")?
- Does the group election path (Phase 6) have the same
  consensus requirement as the per-zone path?

### Priority

Medium. Incorrect elections can cause key proliferation
and inconsistent delegation sync state. Investigate
before enabling elections in mpagent.
