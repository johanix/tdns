# Empty REPLACE Operations for Stale Data Cleanup

Date: 2026-03-26
Status: DESIGN PROPOSAL

## Problem

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

## Proposed Solution

**Explicit empty REPLACE operations.** When an agent has
nothing to contribute for an RRtype, it should send a
REPLACE operation with an empty RRset. The combiner
interprets this as "this agent has zero records of this
type" and removes any stale contributions.

The `ReplaceCombinerDataByRRtype` function already handles
empty replacement sets correctly — it deletes the agent's
contribution for that owner+rrtype.

## When to Send Empty REPLACEs

### On resync (push phase)

When the agent resyncs to the combiner, it currently sends
its local data as REPLACE operations. It should also send
empty REPLACEs for RRtypes it does NOT contribute:

- **Not a signer?** → REPLACE DNSKEY with empty set
- **No NS records?** → REPLACE NS with empty set
- **No KEY?** → REPLACE KEY with empty set

The set of "potentially contributed RRtypes" is known
from the AllowedLocalRRtypes preset: DNSKEY, CDS, CSYNC,
NS, KEY. For each of these, if the agent has no data, it
sends an empty REPLACE.

### On startup (first sync)

Same logic as resync. The agent's first contribution to
the combiner after startup should establish a clean
baseline for all RRtypes.

### On role change detection

If the agent detects (via HSYNCPARAM) that it is no longer
a signer, it should proactively send empty REPLACE for
DNSKEY. This handles the case where the zone owner removes
a provider from the signers list.

## Implementation Sketch

In the resync push phase (syncheddataengine.go), after
sending local data as Operations:

```go
// For each allowed RRtype that we did NOT send data for,
// send an empty REPLACE to clear stale contributions.
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

## Scope

This applies to all agent→combiner contributions:
- NS records
- DNSKEY records (signer-only)
- KEY records (SIG(0) publication)
- CDS/CSYNC (combiner-generated, but also agent-sourced)

## Interaction with DNSKEY Policy

The new `checkDNSKEYPolicy` rejects DNSKEYs from
non-signers. An empty REPLACE for DNSKEY from a
non-signer should be ACCEPTED (it's a deletion, not a
contribution). The policy check should distinguish
between "adding DNSKEYs" (reject for non-signers) and
"removing DNSKEYs" (always accept).

## Risk

Low. `ReplaceCombinerDataByRRtype` already handles empty
sets. The change is in the agent (send empty REPLACEs)
and a minor policy adjustment in the combiner (allow
empty REPLACE from non-signers for DNSKEY).
