# Semantics of Multi-Provider Change Tracking

This document captures design decisions and corner cases for
how multi-provider zone changes are tracked, confirmed, and
routed between agents, combiners, and signers.

## Principles

1. **Agents accept all valid data from peers.** The SDE
   (Synched Data Engine) stores data from all providers
   regardless of whether the local provider will act on it.
   SDEs should be as synchronized as possible across all
   providers in a group.

2. **Only the combiner decides what to apply.** The combiner
   enforces policy (signing authorization, protected
   namespaces, RR type restrictions). An agent does not
   second-guess the combiner's policy -- it forwards data
   and lets the combiner accept or reject.

3. **Rejection means combiner rejection.** A REJECTED
   confirmation from an agent means the local combiner
   rejected the data based on policy the agent may not be
   aware of. It does NOT mean the agent refused to store
   the data.

4. **Non-forwarding is not rejection.** When an agent
   accepts data into its SDE but does not forward to its
   combiner (e.g., because OptMPDisallowEdits is set),
   the agent sends ACCEPTED -- not REJECTED -- back to the
   originator. The data was successfully delivered to the
   agent. The internal decision not to forward is
   transparent to the sender.

5. **The sender sends to all providers; the receiver
   decides.** The sender does not filter recipients based
   on signing status or other provider-specific state.
   The receiver knows its own state and acts accordingly.

## Corner Cases

### Non-Signing Provider Receives DNSKEY SYNC

**Scenario:** signer.alpha sends DNSKEYs to agent.echo
via agent-to-agent SYNC. Echo is a provider for the zone
but not a signer (HSYNCPARAM signers= does not include
echo).

**Behavior:**
- agent.echo accepts the DNSKEYs into its SDE (principle 1)
- agent.echo does NOT forward to combiner.echo because
  OptMPDisallowEdits is set (echo is not a signer)
- agent.echo sends ACCEPTED back to agent.alpha
  (principle 4)

**Why not REJECTED:** signer.alpha tracks DNSKEY
propagation and blocks key rollover until all agents
confirm. If echo rejects, alpha's key rollover is blocked
by a provider that has no role in the signing process.
The DNSKEYs reach echo's zone via zone transfer (from
alpha's signer), not via combiner edits.

**Why not filter at sender:** Alpha could in theory skip
sending to non-signers. But:
- Echo's SDE benefits from having the data (awareness,
  consistency checking, gossip)
- The sender should not need to understand each
  receiver's internal state
- The HSYNCPARAM signers list could change; echo might
  become a signer later

### Non-Signing Provider Receives NS SYNC

**Scenario:** agent.alpha adds an NS record and sends
SYNC to agent.echo. Echo is not a signer.

**Behavior:**
- agent.echo accepts the NS into its SDE
- agent.echo does NOT forward to combiner.echo
- agent.echo sends ACCEPTED back to agent.alpha

The NS reaches echo's zone via zone transfer from
alpha's signer (which serves the signed zone including
the new NS). Echo's combiner is not involved.

### Non-Signing Provider Local addrr/delrr

**Scenario:** Operator runs `agent zone addrr` on echo
for a zone where echo is not a signer.

**Behavior:**
- The add-rr API endpoint checks OptMPDisallowEdits
- Returns an immediate error: "zone is signed but this
  provider is not a signer; modifications not allowed"
- No data enters the SDE or reaches the combiner

**Why reject at the API level:** This is a local command,
not a peer SYNC. The operator needs immediate feedback
that the operation is not possible. Silently accepting
would be confusing.

### Combiner Receives Update for Non-Signing Zone

**Scenario:** Despite agent-side guards, an UPDATE reaches
combiner.echo for a zone where echo is not a signer
(e.g., from an older agent version or a race condition).

**Behavior:**
- Combiner checks MP authorization (checkMPauthorization)
- Rejects with per-record RejectedItems
- Sends CONFIRM with status=FAILED back to the agent
- Records the rejection in the combiner's rejected edits
  audit trail

This is the last line of defense. The combiner always
enforces its own policy regardless of what the agent did.

## Option Summary

| Option | Meaning | Set By |
|--------|---------|--------|
| allow-edits | Combiner may edit this zone | populateMPdata (provider + signer) |
| mp-disallow-edits | Zone is signed, we are not a signer | populateMPdata (provider, not signer) |
| mp-not-listed-error | We are not listed as a provider at all | populateMPdata (guard 3 failure) |
| multi-signer | Multiple providers sign this zone | populateMPdata (otherSigners > 0) |
| inline-signing | Signer should sign this zone | populateMPdata (WeAreSigner) |
