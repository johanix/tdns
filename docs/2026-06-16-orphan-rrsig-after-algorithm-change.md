# Open problem: orphan RRSIGs after a key/algorithm change

Status: OPEN — needs design thought. Not yet fixed. Discovered
2026-06-16 while validating per-role KSK/ZSK algorithms on the nox auth
server. Independent of the per-role-algorithm work (see
2026-06-16-dnssec-config-restructure-and-policy-gating.md) — it would
happen on any algorithm change and on any `keystore dnssec clear`.


## Symptom

A zone (mayo.pq.axfr.net) was originally signed with ED25519 keys.
We then deleted the ED25519 keys, generated MAYO5 (KSK) + MAYO2 (ZSK),
and re-signed. Querying the SOA shows it carries TWO RRSIGs:

    mayo.pq.axfr.net. SOA RRSIG 15  ... 45360 ...   # ED25519 (alg 15), STALE
    mayo.pq.axfr.net. SOA RRSIG 206 ... 44560 ...   # MAYO2   (alg 206), current

The signing inception times differ (the ED25519 sig is from the
original signing; the MAYO2 sig is from the re-sign), confirming this
is a leftover from before the key change. The ED25519 key 45360 no
longer exists in the keystore, so its RRSIG is unverifiable — there is
no published ED25519 DNSKEY to validate against.

The re-signing operation appended the new-key RRSIG without reconciling
the existing RRSIG set against the current key set.


## Why the naive fix is wrong

"On re-sign, delete all existing RRSIGs first" would break legitimate
multi-signature states, all of which are CORRECT and must be preserved:

- **Algorithm rollover (RFC 6781 §4.1.4):** during an algorithm change
  the zone is deliberately double-signed with old AND new algorithms
  for the whole transition, so resolvers on either DNSKEY can validate.
- **ZSK rollover:** pre-publish / double-signature rollovers carry two
  same-algorithm RRSIGs for a window.
- **Multi-signer (RFC 8901):** multiple operators' ZSKs co-sign the same
  RRset by design.

In ALL of those, the "extra" RRSIG has a live, published DNSKEY behind
it. So the discriminator is NOT "more than one sig" or "algorithms
differ" — it is **provenance**: does a currently-published key still
back this RRSIG?


## The harder nuance (operator-stated 2026-06-16)

The tempting precise rule — "remove an RRSIG iff no currently-published
key matches its (algorithm, keytag)" — is NOT obviously safe either:

- In a normal algorithm rollover we still HAVE the keys for both algs,
  so the old-alg RRSIGs have backing keys and the rule keeps them.
  Fine.
- But in THIS case we no longer have the old-alg keys at all. One could
  argue removal is then OK (the sigs are unverifiable anyway).
- HOWEVER: consider an operator who LOST the old keys by mistake. Then
  it may be *very important* to KEEP those old signatures in the zone
  while quickly phasing in replacement keys — because as long as the
  old DNSKEY is still published (and cached by resolvers), the existing
  old-alg RRSIGs are the only thing keeping the zone validatable for
  those resolvers until the new keys propagate. Stripping them on
  re-sign would turn a recoverable key-loss into an immediate
  validation outage.

So "no matching key in the keystore" is not sufficient justification
for removal: the relevant question may be whether the corresponding
DNSKEY is still PUBLISHED in the zone (and thus still cached by
resolvers), not merely whether we still hold the private key. Removing
an RRSIG whose DNSKEY is still published — even if we lost the private
key — could be actively harmful.


## Questions to resolve before fixing

1. Where does re-signing build the RRSIG set (SignRRset / the re-sign
   path) — is it purely additive, or does it rebuild from the current
   key set? If additive, the orphan survives by construction.
2. Is the orphan RRSIG persisted in the SDE / zone store from the
   original signing and never invalidated, or recomputed each serve?
   (Memory: SDE is a runtime cache; combiner is source of truth for
   non-DNSKEY RRs — so this may be cache invalidation, not signing
   logic.)
3. Does the key-state machine's active->retired->removed flow already
   strip a removed key's RRSIGs? Leading hypothesis: `keystore dnssec
   clear` is a HARD delete that bypasses the graceful removal path that
   would otherwise have cleaned up. If so the bug is narrower: `clear`
   (and algorithm change) needs to reconcile served RRSIGs.
4. What is the correct removal predicate? Candidates, weakest to
   strongest justification for removal:
     a. private key gone from keystore        (WEAK — see key-loss case)
     b. DNSKEY no longer published in the zone (stronger — resolvers can
        no longer have it cached as valid beyond TTL)
     c. DNSKEY unpublished AND past the DNSKEY TTL / propagation delay
        (strongest — guarantees no resolver still treats it as valid)
   (c) aligns with the existing clamping / propagation-delay machinery
   and is probably the safe answer, but needs confirmation.


## Scope note

Orthogonal to the committed per-role-algorithm work; does not block it.
Reproduce: sign a zone with alg X, `keystore dnssec clear -z <zone>
--force` (or change the policy algorithm), then dig SOA +dnssec — the
old-alg RRSIG persists alongside the new one.
