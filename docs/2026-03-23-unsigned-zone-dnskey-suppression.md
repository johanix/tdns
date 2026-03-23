# Unsigned Zone DNSKEY Suppression + KEYSTATE Timeout Fix

**Date:** 2026-03-23
**Status:** Plan (approved)

## Problem 1: DNSKEY Noise in Unsigned Zones

Zones with no `signers=` key in HSYNCPARAM (unsigned zones)
are still getting DNSKEYs distributed between agents and
published by combiners. DNSKEYs in an unsigned zone are
meaningless noise.

Example: ardbeg.whisky.dnslab has `nsmgmt="agent"` but no
signers. Both alpha and delta distribute keypairs and
publish them via their combiners.

## Problem 2: KEYSTATE Exchange Timeouts

Frequent "timeout waiting for signer response (15s)"
warnings. Root cause: the `keystateRfiChan` in
TransportManager is zone-agnostic. When zone A is waiting
for a KEYSTATE response and zone B's proactive KEYSTATE
arrives, it gets routed to zone A's dedicated channel.
Zone A rejects it (wrong zone) and times out.

## Part A: KEYSTATE Timeout Fix

### Root Cause

`routeKeystateMessage()` in `hsync_transport.go` routes
all inventory messages to `keystateRfiChan` when set,
without checking the zone name.

### Fix

Store the expected zone name alongside the channel pointer.
In `routeKeystateMessage`, check zone match before routing
to the dedicated channel. Mismatches fall through to the
shared `KeystateInventory` channel (proactive handler).

**Files:** hsync_transport.go (~15 lines), hsync_utils.go
(~5 lines)

## Part B: DNSKEY Suppression

### Current Guards

Key generation at the signer is already guarded:
`OptInlineSigning` is not set for unsigned zones, so
`key_state_worker.go` skips generation. **No fix needed
at signer key generation.**

### Fix 1: Signer KEYSTATE Inventory Response

**File:** signer_msg_handler.go

Before calling `GetKeyInventory`, check if we are a signer
for this zone (`zd.MPdata.WeAreSigner`). If not (whether
the zone is unsigned or signed by others), send empty
inventory. The check is "are WE a signer" not "does the
zone HAVE signers".

### Fix 2: Agent LocalDnskeysFromKeystate

**File:** hsync_utils.go

Add guard at function entry: if zone is unsigned
(`!zd.MPdata.ZoneSigned`), return early without feeding
any keys into the SDE.

### Fix 3: Agent SYNC-DNSKEY-RRSET Handler

**File:** hsyncengine.go

Add check before feeding DNSKEY changes to SDE: if zone
is unsigned, skip the sync.

### Fix 4: Agent Proactive KEYSTATE Handler

**File:** hsyncengine.go

Add check before triggering DNSKEY distribution after
proactive inventory: if zone is unsigned, skip.

### Fix 5: Combiner DNSKEY Rejection (Defense-in-Depth)

**File:** combiner_chunk.go

In the operation processing loop, reject DNSKEY operations
for zones where HSYNCPARAM has no signers.

## Implementation Order

1. Part A (KEYSTATE timeout) -- fixes frequent warnings
2. Part B fixes 2+4 (agent guards) -- stops distribution
3. Part B fix 1 (signer guard) -- stops at source
4. Part B fix 3 (agent SYNC handler) -- covers remote path
5. Part B fix 5 (combiner guard) -- defense-in-depth

## Verification

### KEYSTATE timeout
- Restart agent with 4+ MP zones
- No "timeout waiting for signer response" in logs
- All zones show successful KEYSTATE exchange

### DNSKEY suppression
- ardbeg.whisky.dnslab (unsigned): no DNSKEYs in zone
  transfer, no DNSKEY entries in SDE
- Signed zones (caol-ila, whisky): DNSKEYs still work
- addrr/delrr: still works for signed zones
- Key rollover: still works for signed zones
