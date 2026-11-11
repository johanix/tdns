# An accepted UPDATE records the SIG(0) key as trusted

**Date:** 2026-11-09. Based on main `675dc0ab`. Refs johanix/tdns-mp#404.
**Status:** implemented (branch `fix/404-update-noerror-trusts-key`).

## The reading, and its cost

Ruling (a) on tdns-mp #404: an UPDATE signed with the zone's SIG(0) key that
the parent answers NOERROR proves that the parent trusts the key, whether or
not it speaks KeyState. A KeyState answer stays the other proof.

tdns-mp's key hold stops the leader's syncs until the key is trusted. So that
a held zone can earn the proof at all, tdns-mp no longer holds for a key the
parent never gave a verdict on (`parent_state` 0): the next sync tests it.
NOERROR records the key trusted, here. BADKEY starts the re-bootstrap, which
waits for the key to be served (#917).

**The cost:** one sync may be signed with a key the parent has not verified
yet. That happens only where the parent never says, by KeyState, whether it
trusts the key.

## What changed

- `signDelegationUpdate` returns the keys it signed with.
- `recordUpdateAccepted` sets the key's `parent_state` to `KeyStateTrusted`
  after a NOERROR, in the delegation sync (`sendDelegationUpdate`) and in the
  DS delivery (`sendDSViaUpdate`). It logs once, when the state changes.
- Only an UPDATE signed with exactly one key records anything.
  `GetSig0Keys` returns the first active key row, so in practice that is
  every UPDATE. If there were more signatures, which one the parent checked
  would not be known.
- A NOERROR overrides an earlier KeyState verdict: it is the later proof.
- A REFUSED, a BADKEY or any other rcode records nothing. Neither does the
  self-signed bootstrap ceremony: a parent may accept it and verify the key
  later.
- A failure to record is logged and the UPDATE stands; the next accepted one
  records it.

## Tests

- `TestAnAcceptedUpdateRecordsTheKeyTrusted`,
  `TestAnAcceptedUpdateOverridesAnEarlierVerdict`.
- `TestARefusedUpdateRecordsNothing`: REFUSED, and BADKEY, which reaches the
  re-bootstrap.
- `TestOnlyTheKeyThatSignedIsRecorded`: with two active rows, only the
  signing key is recorded.
- `TestSendDSViaUpdate...`: the DS delivery records on NOERROR and not on
  REFUSED.

Each recording call was removed in turn, and a test caught each removal.
