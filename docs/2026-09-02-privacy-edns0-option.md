# The PRIVACY EDNS(0) option (replacing the PR flag bit)

**Date**: 2026-09-02
**Status**: IMPLEMENTED
**Component**: `v2/edns0`, tdns-imr (`v2`), dog (`cmdv2/dog`)

## 1. Why

The privacy signal used to be a flag bit: bit 12 of the OPT header TTL,
"PR" for Privacy Requested. Two problems with that:

- **Flag bits are scarce.** There are sixteen of them, shared by
  everything EDNS(0) will ever want to signal, and each one spent is
  spent for good. Option codes are cheap: 65001-65534 is private-use
  space and this implementation had used six of them.
- **A bit can only say yes or no.** "Encrypted or fail" is one policy,
  but the more useful one for most stubs is "prefer encrypted, cleartext
  is acceptable if that is all there is". A bit cannot express it, and a
  second bit for the second policy is exactly the wrong trade.

## 2. The option

Code **65007**, in the private-use range with the other tdns-local
options (`v2/edns0/edns0_defs.go`). Payload: **exactly one octet**. An
option whose OPTION-LENGTH is not 1 is skipped -- guessing at the intent
of a malformed signal is worse than ignoring it. Skipped rather than
treated as end-of-scan: if a sender emits more than one, a malformed
option ahead of a valid one must not mask it, or a strict request would
read as no request at all. Privacy failing open is the wrong direction.

The octet's meaning depends on the direction of travel, because the two
directions answer different questions. A receiver always knows which
direction it is looking at, so one code serves both.

### Query direction: what the client wants (`edns0.PrivacyLevel`)

| Value | Name | Meaning |
|-------|------|---------|
| 0 | `PrivacyNone` | No opinion. Legal to send; means what sending nothing means. |
| 1 | `PrivacyOpportunistic` | Prefer an encrypted transport, accept cleartext when there is none. Availability wins over privacy. |
| 2 | `PrivacyStrict` | Encrypted or nothing. No cleartext fallback; fail the query instead. |

An unknown value is treated as `PrivacyNone`. A resolver cannot honor
semantics it has never heard of, and the alternative -- reading "higher
than strict" as "at least as strict as strict" -- would let an unknown
future value SERVFAIL queries.

### Response direction: what the resolver did (`edns0.PrivacyStatus`)

| Value | Name | Meaning |
|-------|------|---------|
| 0 | `PrivacyCleartext` | The answer was fetched over an unencrypted transport. |
| 1 | `PrivacyEncrypted` | The answer was fetched over an encrypted transport. |
| 2 | `PrivacyCached` | The answer came from cache; the resolver asserts nothing about the transport the data originally arrived over. |

`PrivacyCached` is deliberately its own value rather than being folded
into one of the other two. A cache entry does record the transport of
the exchange that filled it, but the data may have been assembled,
revalidated or refreshed over other paths since, so the honest answer to
"was this private?" is "it came from cache".

The status is attached **only when the query carried the PRIVACY
option**, at any level. A client that never asked gets an unchanged
response.

One imprecision is known and accepted: `PrivacyCached` is reported for
answers `ImrResponder` serves from its own cache short-circuits. Deeper
inside the walk, `IterativeDNSQuery` returns the *recorded* transport
for data it serves from cache (a CNAME hop, say), so such an answer is
reported as encrypted or cleartext rather than as cached. Making this
exact means returning a from-cache flag out of the whole resolution
path, which is a much larger change than the distinction is worth today.
It never over-claims: under strict privacy cached cleartext data is not
served at all, and the recorded transport is never more private than
what the data actually got.

## 3. What the IMR does with it

The resolution path carries an `edns0.PrivacyLevel` where it used to
carry a `requireEncrypted bool` (`IterativeDNSQuery` and everything it
calls, plus `forwardQuery`). Three behaviors:

| | transport pool | cache | no encrypted transport available |
|---|---|---|---|
| none | OOTS shares, Do53 included | any entry | — |
| opportunistic | encrypted first, Do53 appended last | any entry | falls back to cleartext |
| strict | encrypted only | entries whose transport was encrypted | SERVFAIL + EDE `EDEPrivacyRequestedUnavailable` |

Opportunistic is a *preference*, expressed by ordering rather than by
filtering: `candidateTransports` draws only from the encrypted pool and
then appends Do53 as the last resort the client said it would accept.
On the forward path the same rule orders the upstreams
(`forwardUpstreamsForPrivacy`).

Cache admissibility differs on purpose: strict skips a cached entry that
arrived over cleartext and re-queries, opportunistic keeps the hit. An
opportunistic client accepted cleartext, so making it pay for a re-query
would buy it nothing it asked for.

Internal traffic the IMR generates for its own purposes -- glue
revalidation, DNSKEY fetches, NS-address resolution, trust-anchor init,
root refresh -- always passes `PrivacyNone`. Privacy is a client signal
about a client's query; it is not a property of the resolver's
housekeeping.

### The strict-privacy failure is a sentinel

`ErrPrivacyUnavailable` (`v2/dnslookup.go`), matched with `errors.Is`.
The responder previously recognised this failure with
`strings.Contains(err.Error(), "PR flag requires encrypted transport")`,
which made every error string on that path part of the interface: a
reworded message would have silently dropped the EDE.

Everything that can reach that dead end wraps the sentinel, and every
path that can report it attaches the EDE
(`attachPrivacyUnavailableEDE`):

- the iterative precheck (no server offers an encrypted transport) and
  the iterative exhaustion path (every encrypted tuple was tried);
- the forward precheck (no encrypted upstream) and the forward
  exhaustion path -- under strict privacy the only upstreams tried were
  the encrypted ones, so exhausting them *is* the privacy failure: a
  cleartext upstream might have answered and the client forbade asking;
- the responder's NS-address-resolution branch, which remembers a
  strict-privacy failure across callback attempts (a later address may
  still produce an answer) and reports it only if none of them does.

The precheck asks `candidateTransports` whether a server has an
encrypted transport rather than scanning the server itself, so it cannot
disagree with the tuple selection that follows it about what "available"
means -- notably over a nil map entry, or an encrypted transport at
weight 0 or 1, which OOTS -03 puts below the threshold for use.

## 4. dog

`+PR` / `+PRIVACY`, optionally with a value:

```
dog @resolver example.com A +pr                  # strict (bare +PR)
dog @resolver example.com A +pr=opportunistic    # or +pr=1
dog @resolver example.com A +pr=strict           # or +pr=2
dog @resolver example.com A +pr=none             # or +pr=0
```

Bare `+PR` is **strict**, which is what the flag bit always meant: an
existing command line keeps doing what it did rather than silently
becoming more permissive.

dog warns when strict privacy is asked for over an unencrypted hop to
the resolver itself (including the Do53-TCP retry after truncation).
Opportunistic gets no warning -- accepting cleartext is what it asked
for. The warnings are still warnings rather than hard failures; the
`TODO` marking them is unchanged by this work.

Responses print the status by name:

```
;; EDNS: option: PRIVACY: 1 (encrypted)
```

## 5. Migration

The flag bit is **gone**, not deprecated: `edns0_pr.go` is deleted,
`MsgOptions.PR` is replaced by `Privacy`/`HasPrivacy`, and `rr_print`
no longer prints `pr` among the EDNS flags. An old dog querying a new
IMR sets bit 12, which is now ignored; a new dog querying an old IMR
sends an option the old IMR does not look at. Both degrade to "no
privacy handling", which is the safe direction for a signal whose
absence means "no opinion" -- except under strict privacy, where the
client should treat a response with no PRIVACY status as a resolver that
did not honor the request.

## 6. Relationship to the transport-selection policy

`docs/2026-06-12-transport-selection-policy.md` proposes a unified
`TransportPolicy` enum that folds this privacy axis together with the
large-response (DNSKEY) axis. That design is not implemented. This work
is deliberately narrower: it moves the privacy signal off the flag bit
and gives level 1 real behavior, using the existing per-query plumbing.
When the unified policy lands, the "decode signal → axis contributions"
step is what changes; the option's wire format does not.
