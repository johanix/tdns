# Unsigned Zone DNSKEY Suppression

**Date:** 2026-03-23
**Status:** Plan

## Problem

Zones with no `signers=` key in HSYNCPARAM (unsigned zones)
are still getting DNSKEYs generated, distributed between
agents, and published by combiners. This is wrong -- DNSKEYs
in an unsigned zone are meaningless noise.

Example: ardbeg.whisky.dnslab has `nsmgmt="agent"` but no
signers. Both alpha and delta generate keypairs, exchange
them via SYNC, and publish them via their combiners.

## Three-Layer Fix

### Layer 1: Signer -- Don't Generate Keys for Unsigned Zones

The signer generates keypairs based on DNSSEC policy and
`OptInlineSigning`. With the "no signing without
authorization" fix, `OptInlineSigning` is NOT set for zones
with no signers. But key generation may be triggered by
other paths:

- DNSSEC policy evaluation during zone load
- KeyStateWorker periodic checks
- KEYSTATE inventory requests from agent

**Fix:** All key generation paths must check whether the
zone has signers authorized. If `analyzeHsyncSigners`
returns `weShouldSign=false` AND `zoneSigned=false`, no
keys should be generated.

Also check: does the signer's KEYSTATE response include
keys for unsigned zones? If so, the agent receives them
and distributes.

### Layer 2: Agent -- Don't Distribute DNSKEYs for Unsigned Zones

The agent receives KEYSTATE from the signer and feeds
local DNSKEYs into the SDE via `LocalDnskeysFromKeystate`.
The SDE then distributes them to remote agents and the
combiner.

**Fix:** `LocalDnskeysFromKeystate` should check the
HSYNCPARAM: if no signers are listed, return early without
feeding any keys into the SDE.

Also: the DNSKEY SYNC from remote agents (carrying their
foreign keys) should be accepted into the SDE (for
awareness) but NOT forwarded to the combiner for unsigned
zones. This is already handled by the `OptMPDisallowEdits`
guard for non-signing providers, but for unsigned zones
(NO provider is a signer) there's no specific guard yet.

### Layer 3: Combiner -- Reject DNSKEY Operations for Unsigned Zones

Last line of defense. The combiner's
`combinerProcessOperations` should check the HSYNCPARAM:
if no signers are listed, reject DNSKEY operations.

**Fix:** In the operation processing loop, when the RR
type is DNSKEY, check the zone's HSYNCPARAM. If signers
is empty, reject with reason "DNSKEY not allowed in
unsigned zone".

## Implementation Order

Layer 1 (signer) stops the problem at the source.
Layer 2 (agent) prevents distribution even if keys exist.
Layer 3 (combiner) prevents publication as last defense.

All three should be implemented together for correctness.

## Related Issue: KEYSTATE Timeouts

Separate from the DNSKEY suppression, there are frequent
KEYSTATE exchange failures:

```
WARNING: KEYSTATE exchange FAILED: timeout waiting for
signer response (15s)
```

This needs investigation:
- Is the signer overloaded?
- Is the KEYSTATE request not reaching the signer?
- Is the response being consumed by the wrong handler?
- Is there a channel contention issue (single-slot
  response channel)?
- Does it correlate with specific zones or all zones?
