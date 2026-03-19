# Provider Groups and Gossip-Based State Sharing

**Date:** 2026-03-19
**Status:** All 6 phases implemented

## Problem

Three related reliability issues in the current agent
communication model:

1. **Unreliable leader election.** Elections require all
   configured peers to be OPERATIONAL, but OPERATIONAL is a
   unilateral state — agent A may consider B OPERATIONAL
   while B considers A UNKNOWN. Elections trigger once (via
   `NotifyPeerOperational`) and if the window is missed,
   nothing retriggers them. Result: one agent has a leader,
   the other has none, and neither knows they disagree.

2. **Stuck discovery.** Agent A has B as KNOWN, B has A as
   UNKNOWN. B keeps querying IMR for A's discovery records,
   gets cached NXDOMAIN, retries forever. No cache flush
   mechanism in the automated path. They stay stuck
   indefinitely.

3. **No shared state.** Each agent maintains its own view of
   peer states. There is no mechanism for agents to discover
   that their views disagree. Functions that depend on
   collective agreement (elections, parentsync) fail silently
   when views diverge.

## Design Overview

Three new concepts address all three issues:

- **Provider groups**: Deterministic grouping of providers
  that share zones. Reduces per-zone overhead to per-group.
- **Gossip protocol**: Agents exchange full group state on
  every beat. State converges within two beat intervals.
- **IMR cache flush on stuck discovery**: After repeated
  NXDOMAIN failures, flush the relevant cache entries and
  retry.

## Provider Groups

### Definition

A **provider group** is the set of provider identities that
together serve a set of zones. It is derived purely from
HSYNC3 data.

For each zone, extract the set of provider identities from
the HSYNC3 RRset at the zone apex. All zones that have the
same set of provider identities belong to the same **zone
group**. The providers in that set form the **provider
group**.

Example: if zones `a.example.`, `b.example.`, `c.example.`
all have HSYNC3 records for `{agent.alpha.example.,
agent.echo.example.}`, they form one zone group served by
one provider group.

### Group Hash

The group hash is computed from the sorted list of member
identities. This is deterministic — any agent with the same
HSYNC3 data computes the same hash.

```go
func computeGroupHash(identities []string) string {
    sorted := slices.Sorted(slices.Values(identities))
    h := sha256.New()
    for _, id := range sorted {
        h.Write([]byte(id))
    }
    return hex.EncodeToString(h.Sum(nil))[:16]
}
```

### Group Naming

Group hashes are not human-friendly. Each provider may
propose a name for a group. Names should be short and
pronounceable (for use in logs, CLI output, tabular
displays).

**Naming protocol:**

Each provider includes in its gossip state a proposed name
for each group it belongs to, along with the proposer's
identity and a timestamp of when the name was chosen.

```go
type GroupNameProposal struct {
    GroupHash  string
    Name       string
    Proposer   string    // provider identity
    ProposedAt time.Time // when proposer chose name
}
```

**Resolution rules:**

1. For each group hash, collect all proposals (from gossip
   merge).
2. The proposal with the earliest `ProposedAt` timestamp
   wins.
3. On collision (two different group hashes resolve to the
   same name): the group whose winning proposal has the
   earlier timestamp keeps the name. The other group falls
   back to the next-earliest non-colliding proposal.
4. Until a name is resolved, use the truncated group hash
   as display name.

This is computationally stable: once a name is chosen and
propagated, it sticks. New agents joining the group will
receive the existing name via gossip and adopt it.

### Zone Group Dynamics

Adding or removing a zone does not change the provider
group — the group is defined by the set of providers, not
the set of zones. If a zone adds a new provider (changing
its HSYNC3 RRset), that zone migrates to the zone group for
the new provider set. The old and new provider groups
continue to exist as long as at least one zone uses each
set of providers.

### Computation

Each agent computes provider groups locally from its own
HSYNC3 data. Agents may temporarily disagree on group
composition (e.g., during zone loading). This is handled
by including group membership in gossip — disagreements are
detected when an agent receives gossip for a group it
doesn't recognize or with different members than expected.

## Gossip Protocol

### Overview

For each provider group, each agent periodically sends a
gossip message to all other group members. The gossip
message contains the sender's full state table for the
group. On receiving gossip, agents merge state using
timestamp-based conflict resolution.

Gossip rides on the existing BEAT mechanism. The current
`AgentBeatPost` payload is minimal (identity, interval,
zones, timestamp) and will be extended with gossip data.
This is backward-compatible: agents that don't understand
the new fields ignore them and continue to function as
today.

### Gossip Message Structure

```go
type GossipMessage struct {
    // Group identification
    GroupHash string
    GroupName GroupNameProposal

    // State table: one entry per group member
    // Key: provider identity
    Members map[string]MemberState

    // Election state for this group
    Election GroupElectionState
}

type MemberState struct {
    Identity   string
    PeerStates map[string]string // key: peer identity,
                                 // value: state of that
                                 // peer as seen by this
                                 // member (UNKNOWN/KNOWN/
                                 // INTRODUCED/OPERATIONAL/
                                 // DEGRADED/etc.)
    Zones      []string          // zones this member
                                 // serves in this group
    Timestamp  time.Time         // set by the member
                                 // itself, only that
                                 // member updates its
                                 // own timestamp
}

type GroupElectionState struct {
    Leader       string    // identity of current leader,
                          // empty if none
    Term         uint32
    LeaderExpiry time.Time
}
```

### Extended Beat Payload

The existing `AgentBeatPost` is extended with an optional
gossip field:

```go
type AgentBeatPost struct {
    // Existing fields (unchanged)
    MessageType    AgentMsg
    MyIdentity     string
    YourIdentity   string
    MyBeatInterval uint32
    Zones          []string
    Time           time.Time

    // New: gossip for all groups shared with recipient
    Gossip []GossipMessage `json:",omitempty"`
}
```

A single beat between two agents may carry gossip for
multiple groups (if the two agents share membership in
more than one provider group).

### Merge Rules

When agent A receives gossip from agent B:

1. For each `MemberState` entry in the gossip:
   - If the entry is for a member A doesn't have, store it.
   - If A already has state for that member, compare
     timestamps. **Keep the entry with the later
     timestamp.** Only the member itself sets its own
     timestamp, so the latest timestamp is always the most
     authoritative.
   - Never overwrite a member's state report with an older
     timestamp, regardless of source.
   - Note: each member's `PeerStates` map is that member's
     view of all other members. This is an atomic unit —
     always replaced as a whole (never merge individual
     peer entries from different timestamps).

2. For `GroupNameProposal`: merge using the naming
   resolution rules (earliest proposal wins).

3. For `GroupElectionState`: accept if term is higher than
   locally known term.

### Convergence

With N agents in a group and beat interval T:

- **Direct path**: Agent A sends gossip to all N-1 peers.
  Within one beat interval, all agents that can reach A
  have A's latest state.
- **Transitive path**: If A cannot reach C but both can
  reach B, then within 2 beat intervals A's state reaches
  C via B.
- **Worst case convergence**: (N-1) × T for a chain
  topology. In practice, with full mesh, convergence is T.

### Frequency

Gossip uses the existing beat interval (default 15 seconds,
configurable via `agent.remote.beatinterval`). No
additional timers or channels needed.

### Scale

Expected worst case: 20 agents total, one busy agent in 5
provider groups with up to 5 agents each. That agent sends
gossip in 5 groups × 4 peers = 20 beat messages per
interval, each carrying state for up to 5 members. The
gossip payload per message is ~500 bytes. Total overhead:
~10 KB per beat interval. Negligible.

## IMR Cache Flush for Stuck Discovery

### Problem

When an agent is stuck in UNKNOWN→KNOWN, the discovery
retrier queries the IMR for DNS records (`_https._tcp.<id>`,
`api.<id>`, etc.) and gets NXDOMAIN. The IMR caches the
negative response per the SOA MINIMUM TTL. The retrier
loops, hitting cache every time, never getting fresh data.

### Fix

Track consecutive failures per discovery target. After N
failures (configurable, default 3), flush the relevant
names from the IMR cache before the next retry.

```go
// In agent discovery retry loop
if consecutiveFailures >= flushThreshold {
    imr.FlushName(targetName)
    consecutiveFailures = 0  // reset after flush
}
```

The IMR already has flush capabilities (used in the
interactive CLI). Wire them into the agent discovery
process.

### Scope

Flush is surgical: only the specific names that are failing.
Not the entire cache, not a subtree — just the exact qnames
that returned NXDOMAIN.

## Unverified Gossip (Discovery Kick)

### Concept

Beats currently require INTRODUCED state (HELLO must have
succeeded). But an agent stuck in UNKNOWN receives nothing
from the other side and has no way to know it's stuck.

If an agent receives a beat from an unknown sender (JWS
signature cannot be verified because the sender's key is
not yet discovered), it cannot trust the content. However,
the **existence** of the message is informative: someone
who knows our identity and address is trying to talk to us.

### Behavior

When an agent receives an unverified beat:

1. **Do NOT merge** gossip state or update any authoritative
   state tables.
2. **Do log** the event: "Received unverified beat from
   claimed identity X" (at Debug level to avoid log spam).
3. **Do trigger** a discovery retry for the claimed sender
   identity, including IMR cache flush for that identity's
   discovery names. This is safe — worst case it's an extra
   DNS lookup.
4. **Do NOT respond** to the beat (no acknowledgment to
   unverified senders).

This creates a "discovery kick" path: if A has B as
OPERATIONAL and B has A as UNKNOWN, A's beats to B will
cause B to flush its IMR cache and retry discovery for A.
Once B discovers A, the normal HELLO→INTRODUCED→OPERATIONAL
progression takes over and verified gossip begins.

### Security Considerations

An attacker could send forged beats to trigger discovery
retries. This is low-risk:

- Discovery retries are just DNS lookups (read-only).
- Rate limiting on the discovery retrier already exists
  (ticker-based, not per-message).
- No state is modified based on unverified content.
- No response is sent (no amplification).

## Mutual OPERATIONAL and Group Callbacks

### Current Problem

`NotifyPeerOperational()` fires when a single peer
transitions to OPERATIONAL in this agent's local view. But
the peer may not yet consider us OPERATIONAL. Functions
that need collective agreement (elections) trigger too
early.

### New Callback: OnGroupOperational

When an agent's merged gossip state table for a provider
group shows **every cell in the N×(N-1) matrix as
OPERATIONAL**, fire `OnGroupOperational(groupHash)`.
This means every member reports every other member as
OPERATIONAL — true mutual agreement, not just self-
reported state.

```go
// After gossip merge, check if all members see all
// others as OPERATIONAL
func (pg *ProviderGroup) checkGroupOperational() {
    for _, member := range pg.Members {
        for peer, state := range member.PeerStates {
            if state != "OPERATIONAL" {
                return
            }
        }
    }
    // Full NxN agreement — fire callback
    if !pg.operationalFired {
        pg.operationalFired = true
        pg.onGroupOperational(pg.GroupHash)
    }
}
```

This replaces `NotifyPeerOperational()` as the trigger for
elections and other cooperative functions.

### OnGroupDegraded

Similarly, when any member drops below OPERATIONAL (as
reported via gossip), fire `OnGroupDegraded(groupHash)`.
This can trigger leader failover or other recovery actions.

## Per-Group Elections

### Change

Replace per-zone elections with per-group elections. The
leader for a provider group handles leader duties (currently
parentsync) for **all zones** in that group.

### Benefits

- Dramatically fewer elections: one per provider group
  instead of one per zone. For 500 zones with the same
  two providers, that's 1 election instead of 500.
- Election state propagates via gossip — all group members
  see the same leader/term/expiry.
- Election trigger is `OnGroupOperational` — guaranteed
  to fire only when all members agree on collective state.

### Election Protocol

The existing election protocol (ELECT-CALL → ELECT-VOTE →
ELECT-CONFIRM, 3-phase with 5-second timeouts) works
unchanged. The only differences:

- Scope is per-group instead of per-zone.
- Triggered by `OnGroupOperational` instead of
  `NotifyPeerOperational`.
- Election state (`GroupElectionState`) is included in
  gossip, so agents that miss the election messages (e.g.,
  briefly unreachable) learn the result via gossip merge.

## Implementation Order

### Phase 1: IMR Cache Flush + IMR CLI (independent,
unblocks Phase 4)

**Automated flush in discovery loop:**

- Wire IMR flush into agent discovery retry loop
- Track consecutive failures per discovery target
- Flush specific names after N failures
- **Files**: `agent_utils.go`, `agent_discovery.go`,
  possibly IMR flush interface

**IMR cache query capability:**

The IMR cache supports cache-only lookups via
`Cache.Get(qname, qtype)` — this never triggers external
queries. Cache entries carry rich metadata: TTL, expiration
time, DNSSEC validation state, response code, cache
context (answer/referral/NXDOMAIN), and transport used.
The cache is iterable via `RRsets.IterBuffered()` and
filterable by suffix (existing `imr dump suffix` uses
this pattern).

**New CLI commands:**

```
agent imr query {qname} {qtype}
```
Extract RRset with metadata from IMR cache. Cache-only
— no external queries triggered. Shows: RRs, TTL
remaining, expiration time, validation state, cache
context (answer/referral/NXDOMAIN), transport used. Uses
`Cache.Get(qname, qtype)`.

```
agent imr flush {qname}
```
Selective flush of `{qname}` and everything below it in
the cache. Uses existing `Cache.FlushDomain(qname, false)`
(flush all, not just non-structural).

```
agent imr reset
```
Flush entire cache from root down, then re-prime (root NS
+ trust anchors). Uses existing `Cache.FlushAll()` +
re-run priming sequence.

```
agent peer reset --id {identity}
```
Reset discovery of `{identity}` to initial state (NEEDED).
All cached discovery data for that identity discarded.
Flush IMR cache entries for the identity's discovery
names (`_https._tcp.<id>`, `api.<id>`, `_<port>._tcp.
api.<id>`, `_dns._tcp.<id>`, `dns.<id>`). Restart
discovery from scratch.

```
agent imr show --id {identity}
```
Show all IMR cache entries related to discovery of
`{identity}`. Iterates cache via `RRsets.IterBuffered()`,
filters entries where name matches or is a subdomain of
the identity FQDN, plus the well-known discovery names
(`_https._tcp.<id>`, `api.<id>`, SVCB, TLSA, KEY
records). Displays each entry with metadata.

**Files**: `agent_utils.go`, `agent_discovery.go`,
new CLI commands in `cli/` (or existing agent CLI file)

### Phase 2: Provider Groups (independent, enables Phase 3)

- Compute provider groups from HSYNC3 data
- Group hash computation
- Store groups in AgentRegistry or new structure
- Recompute on HSYNC3 changes

**CLI command:**

```
agent gossip group list
```
List all provider groups this agent belongs to. For each
group show: group name (or hash if unnamed), member
identities, and a sample of zones (first 5) from the
corresponding zone group plus total zone count.

Example output:
```
GROUP        MEMBERS                          ZONES (5/312)
nordics      agent.netnod.se. agent.nic.se.   a.se. b.se. c.se. d.se. e.se.
cdn-pair     agent.cf.com. agent.akamai.com.  x.com. y.com. z.com. w.com. v.com.
```

- **Files**: new `provider_groups.go`, `agent_utils.go`,
  `hsyncengine.go`, CLI commands

### Phase 3: Gossip Protocol (depends on Phase 2)

- Extend `AgentBeatPost` with `Gossip` field
- Build gossip messages from local state + cached peer
  state
- Gossip merge logic (timestamp-based)
- Group name proposals and resolution

**CLI command:**

```
agent gossip group state --group {group}
```
Show current gossip state for a provider group as an
N×(N-1) matrix. Each row is a reporting agent; each
column is that reporter's view of another agent's state.
The diagonal is empty (an agent doesn't report on
itself). Also shows election state and timestamp age
for each reporter.

Example output (3-agent group):
```
Group: nordics (hash: 3a7f...)
Leader: agent.netnod.se. (term 4, expires in 23m)

REPORTER / PEER     netnod.se.   nic.se.       iis.se.      AGE
agent.netnod.se.    —            OPERATIONAL   OPERATIONAL   2s
agent.nic.se.       OPERATIONAL  —             KNOWN         8s
agent.iis.se.       OPERATIONAL  OPERATIONAL   —             14s
```

This immediately reveals asymmetric state: in the
example above, `nic.se.` has `iis.se.` as KNOWN while
`iis.se.` has `nic.se.` as OPERATIONAL — indicating a
problem in that direction. A healthy group shows
OPERATIONAL in every non-diagonal cell.

- **Files**: `agent_structs.go` (or `core/messages.go`),
  `hsync_beat.go`, new `gossip.go`, CLI commands

### Phase 4: Unverified Gossip / Discovery Kick (depends
on Phase 1 + 3)

- Detect unverified beats (JWS validation failure)
- Trigger discovery retry + cache flush for claimed sender
- Diagnostic logging
- **Files**: beat receiving path in `hsync_beat.go` or
  transport layer

### Phase 5: Mutual OPERATIONAL + OnGroupOperational
(depends on Phase 3)

- Check group state after gossip merge
- Fire `OnGroupOperational` callback
- Fire `OnGroupDegraded` callback
- **Files**: `provider_groups.go`, `hsyncengine.go`

### Phase 6: Per-Group Elections (depends on Phase 5) — DONE

- `LeaderElectionManager` extended with `groupElections`
  map (keyed by group hash) alongside existing per-zone
  `elections` map
- `StartGroupElection()` runs the same 3-phase protocol
  (CALL→VOTE→CONFIRM) but broadcasts via first zone in
  group, includes `_group` hash in records
- `HandleGroupMessage()` dispatches election messages
  with `_group` record to group election handlers
- `IsLeader(zone)` checks group leader first (via
  `GetGroupForZone`), falls back to per-zone election
- `GetAllLeaders()` merges group and per-zone leaders,
  expanding group leaders to all covered zones
- `OnGroupOperational` fires `StartGroupElection` with
  group members and zones
- `OnFirstLoad` defers to `DeferGroupElection` for
  multi-agent zones (election triggered by gossip)
- Election state included in gossip via
  `GetGroupElectionState()` called from
  `BuildGossipForPeer`
- Re-election scheduled at 90% of leaderTTL per group
- **Files**: `parentsync_leader.go`, `provider_groups.go`,
  `gossip.go`, `hsyncengine.go`, `hsync_transport.go`

### Backward Compatibility Note

Phase 3 (gossip) augments the existing beat payload with
an optional `json:",omitempty"` field. Agents that don't
understand gossip ignore the field and continue with
current behavior. This allows gradual rollout — agents can
be upgraded one at a time.

## Existing Code to Reuse

- `AgentBeatPost` / `AgentBeatResponse` — extend, not
  replace
- `SendHeartbeats()` / `SendBeatWithFallback()` — gossip
  piggybacks on existing beat path
- `HeartbeatHandler()` — extend to process gossip
- `HsyncEngine` beat ticker — no change to timing
- `GetZoneAgentData()` — source of HSYNC3 identity data
  for group computation
- IMR flush commands — already implemented in interactive
  IMR, wire into automated path
- `LeaderElectionManager` — adapt scope from zone to group

## Verification

1. Deploy two agents with shared zones
2. Verify provider group computed correctly (logs)
3. Verify gossip appears in beat messages (packet capture
   or debug log)
4. Kill one agent, verify the other detects state change
   via gossip timeout (member's timestamp stops advancing)
5. Restart killed agent, verify UNKNOWN→KNOWN unsticks
   via IMR cache flush (triggered by unverified beat from
   the other agent)
6. Verify `OnGroupOperational` fires when both agents
   reach OPERATIONAL
7. Verify per-group election succeeds and leader is
   consistent on both agents
8. Add third agent, verify gossip convergence with N=3
9. Test group naming: both agents propose names, earliest
   wins
