# Non-Signing Provider Gates

**Date:** 2026-03-20
**Status:** Plan

## Problem

When a zone has multiple providers but only some are signers
(HSYNCPARAM signers= lists a subset of HSYNC3 providers),
non-signing providers must not modify the zone (they can't
re-sign it) and must not request NS additions until they
can serve signed responses.

Currently the combiner silently drops contributions from
non-signing providers and the agent sits with PENDING
transactions that never complete.

## Two Independent Gates

### Gate 1: No Edits for Non-Signers (Static)

A non-signing provider must never modify the zone. This is
determined at zone-load time from HSYNCPARAM and does not
change at runtime.

Trigger: zone has signers= key (zone is signed) AND our
label is not in the signers list.

Enforced at: combiner (reject edits), agent (don't send
edits to combiner, reject local addrr/delrr).

### Gate 2: No NS Contributions Until Signed Zone Available (Dynamic)

A non-signing provider's agent must not originate NS
contributions (requesting its own nameservers be added to
the NS set) until it can serve signed responses. Adding
an NS pointing at servers that return unsigned data breaks
DNSSEC validation.

Trigger: we are not a signer AND we do not yet receive
the signed zone via a properly configured transfer chain.

This gate requires CONFIG UPSTREAM/DOWNSTREAM (future
work). Short-term: non-signing providers are fully
read-only for signed zones, which implicitly enforces
this gate.

These are independent:
- Gate 1 is about MAKING changes (requires signing ability)
- Gate 2 is about REQUESTING changes (requires serving
  ability)

## Implementation Plan

### Phase 1: Rename allow-combine to allow-edits

**Goal:** Align option naming with actual semantics. The
combiner edits specific RRsets in the zone, it does not
"combine" two equal inputs. Consistent with the existing
"RFI EDITS" naming.

**Changes:**

1. **enums.go**: Rename OptAllowCombine to OptAllowEdits.
   Change string "allow-combine" to "allow-edits" in both
   ZoneOptionToString and StringToZoneOption maps.

2. **All references**: Update all code that reads or sets
   OptAllowCombine to use OptAllowEdits. ~9 references
   across enums.go, parseoptions.go, main_initfuncs.go,
   zone_utils.go.

3. **Zone configs**: Any zone config YAML files that use
   `allow-combine` in options must be updated to
   `allow-edits`.

4. **Log messages**: Update log strings that mention
   "allow-combine" or "combine".

**Files:** enums.go, parseoptions.go, main_initfuncs.go,
zone_utils.go, sample YAML configs

### Phase 2: Combiner REJECT Confirmation

**Goal:** Eliminate silent drops. Combiner sends REJECT
back to agent with reason, and tracks the rejection.

**Changes:**

1. **combiner_msg_handler.go**: When CombinerProcessUpdate
   returns an error due to the signing guard, send a
   CONFIRM with status REJECTED and the reason string
   back to the originating agent (via DNSTransport or
   API).

2. **combiner_chunk.go**: Track rejected contributions
   in the combiner's rejected edits list (same mechanism
   used for policy rejections). Currently the signing
   guard returns an error but doesn't record the
   rejection.

3. **Agent side**: When agent receives a REJECT
   confirmation, mark the record as REJECTED (not
   PENDING) in the SDE and log the reason.

**Files:** combiner_msg_handler.go, combiner_chunk.go,
syncheddataengine.go

### Phase 3: mp-disallow-edits Option

**Goal:** Make the non-signing state visible in zone list
output across all roles (agent, combiner, signer). Prevent
the agent from sending edits to the combiner.

This is a general synthetic option set on any role when
the zone is signed but we are not a signer.

**Changes:**

1. **enums.go**: Add OptMPDisallowEdits zone option
   with string "mp-disallow-edits".

2. **hsync_utils.go / populateMPdata()**: When guard 4
   fires (zone is signed, we are not a signer), set
   OptMPDisallowEdits on the zone. Clear it when guard 4
   passes (in case signers list changes). This applies
   to all roles.

3. **zone_utils.go**: In the combiner's HSYNC change
   handler (AppTypeCombiner case), check populateMPdata
   result. If MPdata is nil due to guard 4, set
   OptMPDisallowEdits and do NOT set OptAllowEdits.

4. **Agent routing (syncheddataengine.go)**: In the
   update-to-combiner path, check OptMPDisallowEdits.
   If set, skip sending to combiner entirely. For remote
   SYNCs from other agents, generate an immediate REJECT
   confirmation back to the originating agent.

**Files:** enums.go, hsync_utils.go, zone_utils.go,
syncheddataengine.go

### Phase 4: Agent-Side Local Update Rejection

**Goal:** Agent rejects local addrr/delrr commands for
non-signing zones at the API level, with a clear error.

**Changes:**

1. **apihandler_agent.go (add-rr/del-rr)**: Before
   processing, check if the zone has OptMPDisallowEdits.
   If so, return an error: "zone is signed but this
   provider is not a signer; modifications not allowed".

2. **Agent SYNC receive path**: When receiving a SYNC
   from a remote agent for a zone with
   OptMPDisallowEdits, accept into SDE for awareness
   (gossip, state tracking) but do NOT forward to
   combiner. Generate immediate REJECT confirmation for
   the update portion.

**Files:** apihandler_agent.go, syncheddataengine.go

### Phase 5: NS Contribution Gating (Future)

**Goal:** Non-signing provider can eventually contribute
NS once it receives the signed zone via a properly
configured transfer chain.

**Short-term decision:** For now, a non-signing provider
is fully read-only for a signed zone. No contributions
of any kind -- no local addrr/delrr, no forwarding
remote SYNCs to combiner, no NS contributions. This is
enforced by Phases 2-4 above.

**Long-term solution:** CONFIG UPSTREAM/DOWNSTREAM.

The zone always enters a provider via the combiner and
exits via the signer. For a non-signing provider to
serve a signed zone, its combiner must receive the zone
from a signing provider's authoritative servers (which
serve the signed version) instead of from the customer's
upstream server (which serves unsigned).

This requires:
1. A mechanism for the agent to tell the combiner to
   change its upstream (primary) for a specific zone
   from the customer's server to a signing provider's
   auth server.
2. Robust confirmation that the combiner has applied
   the upstream change.
3. Persistence of the upstream override so it survives
   restarts.
4. Modified zone loading: after parsing zone configs but
   before the initial zone load, apply any persistent
   upstream overrides.

Once the combiner receives the signed zone from a
signing provider, the local signer (running in
non-signing mode) passes it through unchanged, and the
provider can serve signed responses. At that point the
gate opens and the agent can contribute NS records for
its nameservers.

This is the CONFIG UPSTREAM/DOWNSTREAM mechanism already
identified as future work.

## Phase Order

Phase 1 is a clean rename, no behavioral change.
Phases 2-4 fix the current broken behavior (silent drops,
stuck PENDING, missing rejection). Phase 5 is future work
requiring CONFIG UPSTREAM/DOWNSTREAM.

  Phase 1 (rename) ->
  Phase 2 (combiner REJECT) ->
  Phase 3 (mp-disallow-edits option) ->
  Phase 4 (agent-side rejection) ->
  Phase 5 (future: CONFIG UPSTREAM/DOWNSTREAM)
