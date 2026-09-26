# Refreshing before expiry: a refresh engine, and transport signals

**Written 2026-09-26.** Proposal. Line references are to main at `ec6e8626`.
Follows from #781: tdns-imr keeps a transport signal it has learned for as long
as it runs, and never refreshes it. It also sets the frame for #466 (delegation
prefetch), which wants the same kind of machinery for NS RRsets.

**Status:** proposal, not implemented.

## The principles

1. **The TTL is the contract.** A transport signal's weights are the
   operator's load control: `dot:5` asks a large resolver to send 5% of its
   queries over DoT, not all of them. The TTL is how fast a change takes
   effect. A resolver that keeps using a signal past its TTL misses a
   transport added since (DoQ turned on), and keeps the old split when the
   operator has changed it, including when the operator has cut DoT back
   because the servers were struggling.
2. **Refresh only what is used.** The root is always used. TLD delegations
   nearly always. Anything deeper, and every transport signal, only
   sometimes; an idle one must cost nothing.
3. **A refresh made after expiry is a leak.** Once the signal is gone, the
   next query to that server goes out as if no signal existed, which means
   over Do53, the traffic the signal exists to protect. So a used signal is
   refreshed before it expires, over a transport it allows.
4. **A signal seen in a response is a claim, not a fact.** On the cleartext
   path an attacker can forge one. A changed signal is checked before it is
   applied.
5. **One engine for all time-based re-fetch.** The root refresher exists;
   #466 and #781 would add two more loops of the same kind. They should be
   clients of one engine, not three loops.

`do53:0` stays a preference, not a gate. Do53 is mandatory for nameservers
today, so `do53:0` gives Do53 no share of the weighted draw but leaves it as
the last resort, as `candidateTransports` does now (`v2/dnslookup.go:1042`,
pinned by `TestCandidateTransports_Do53ZeroStillFallback`). A hard "never Do53"
waits until Do53 stops being mandatory.

## What exists today

- **One timer loop.** `RefreshRoot` (`v2/imr_root_refresh.go:68`) re-queries
  `. NS` 60 s before expiry, retrying every 15 s with a 1 s floor, whether or
  not anything is using the root. A forwarded root is never refreshed (#728). A
  refresh whose new expiry is still inside the 60 s lead does not count (#727).
  It is started only by `startServing` (`v2/imrengine.go:491`), so an embedder
  that calls `InitImrEngine` alone gets no root refresh.
- **Nothing else runs on a timer.** Signal and TLSA discovery, NS revalidation
  and out-of-bailiwick address lookups are started by queries. Zone-state
  rechecks and address-family probes are deadlines checked when the state is
  read.
- **Signals never expire.** `applyTransportMapToServer` (`v2/dnslookup.go:2361`)
  stores the weights on the shared `AuthServer`, which stays in
  `AuthServerMap` for the life of the process. The SVCB's TTL plays no part. A
  lookup that finds a signal is recorded as a success, which `DiscoveryTracker`
  never retries. Since #777, a cached denial holds "no signal" only while it is
  cached.
- **Every upstream query carries the OOTS option** (EDNS 65001), unless
  `use-transport-signals` is `false`. It is decided once per
  `IterativeDNSQuery` (`v2/dnslookup.go:1460`) and built into the one message
  every server is sent (`buildQuery`, `:2201`). A server that honours the
  opt-in, as tdns-auth does, puts its SVCB and the SVCB's RRSIG in the
  Additional section of every response. With large signatures that is a
  large share of each response, and it pushes UDP answers towards truncation.
- **A server's own signal is harvested from positive answers only**
  (`parseTransportForServerFromAdditional`, called at `v2/dnslookup.go:1653`).
  Negative answers and referrals from the server renew nothing. Signals for a
  child's nameservers are harvested from the parent's referral
  (`ParseAdditionalForNSAddrs`, `:1860`). All of them are applied without
  validation.
- **Usage is recorded per nameserver, not per zone.** `tryServer`
  (`v2/dnslookup.go:2216`) counts attempts, carried answers and failures per
  transport on the `AuthServer`, and `RecordRTT` keeps a last-sample time. No
  cache entry or `cache.Zone` records any use.
- **`ImrQuery` has no privacy level.** It always walks with
  `edns0.PrivacyNone` (`v2/imrengine.go:796`, `:845`), so a signal lookup
  through it can go over Do53 even when the server signals encryption.

## Transport signals (#781)

### The life of a server's signal

| state | weights used for queries | OOTS opt-in sent | what moves it on |
|---|---|---|---|
| unknown | none (Do53 default) | yes | a signal harvested or looked up |
| fresh | the signal's | **no** | the refresh window opening |
| refresh window | the signal's | yes | a harvested signal equal to the current one, over an encrypted transport: back to fresh |
| expired | none | yes | the next query to the server; see below |
| refresh failed | the signal's, for a short grace | yes | a successful lookup; or the grace ending: expired |
| denied | none | no, while the denial is cached | the cached denial expiring (#777) |

**The refresh window** is the last part of the TTL: a fraction of it, with a
floor for short TTLs. While it is open, ordinary queries to the server carry the
OOTS option again, and the next response brings the current signal back. The
refresh costs nothing but a few bytes on queries that would have been sent
anyway. A server nobody sends queries to is never asked, so use-gating comes
free.

**Harvesting.** A server's own signal, seen in any response from that server
(answer, NODATA, NXDOMAIN or referral), is judged against what is known:

- **Equal, and the response came over an encrypted transport:** the expiry is
  renewed from the SVCB's TTL.
- **Equal, but the response came over Do53:** nothing is renewed. An on-path
  attacker could replay the old signal after the operator has changed it, and
  keep `dot:5` alive when the operator has moved to `dot:50`. A server whose
  signal offers encryption receives encrypted queries regularly, so renewal
  still happens without an extra query.
- **Different:** not applied. It triggers a verifying lookup.
- **First signal for a server nothing is known about:** applied, as today. A
  forged first signal can only steer queries between the server's transports,
  and Do53 stays the last resort.

`parseTransportForServerFromAdditional` needs the transport the response came
over, which it is not given today; `tryServer` has it (`wireTransport`).

**The verifying lookup** asks for `_dns.<ns>` over a transport the current
signal allows. It needs a variant of `ImrQuery` that takes a privacy level:
strict when the current signal offers an encrypted transport. When the zone is
signed, the answer is validated; `applyTransportRRsetFromAnswer`
(`v2/dnslookup.go:2510`) already receives the verdict. Only that answer is
applied. One verifying lookup runs per server at a time (the existing
`DiscoveryTracker` gives this), and after one has confirmed the current signal,
further mismatches are ignored for a cooldown, so forged mismatches cannot buy
an attacker a lookup each.

**The fallback lookup.** A server that was used while its window was open, but
never echoed its signal, gets the same lookup shortly before expiry. That
happens when the server does not echo on the responses it gave: NSD's
transport-signalling branch never echoes on NXDOMAIN or NODATA, and tdns-auth
does not echo for zones it serves as a secondary. This lookup is the refresh
engine's job; everything else in this section happens on the query path.

**Expiry.** An expired signal's weights stop driving queries. What stays is a
note of the transports the server has offered. The next query to the server
carries the OOTS option and goes over one of those transports, so the first use
after a long idle spell is neither in cleartext nor delayed by a separate
lookup. Its response brings the current signal. If the server no longer runs
that transport, the query falls back as its privacy level allows, and the
fallback's response carries the new signal. This is one query per server per
expiry, which does not undermine the operator's load control.

**A failed refresh.** When the fallback or verifying lookup fails (timeout,
SERVFAIL), the last weights stay in use for a grace: the smaller of one TTL and
a fixed cap of a few minutes. The engine retries with backoff meanwhile. After
the grace the signal expires as above. This is the only use of a signal past
its TTL.

**Strict privacy** keeps #777's behaviour for servers in the unknown state: the
precheck looks their signals up and waits for them. An expired server with an
encrypted transport in its note can carry a strict query at once, over that
transport.

**Denied servers** get no opt-in while the denial is cached. The zone has said
there is no signal, and #777 already holds that verdict for exactly that long.

## The refresh engine

### What it owns

Keeping cached data fresh before it expires. Nothing else: server and zone
backoff, forward-zone quarantine, address-family probes and zone-state rechecks
re-evaluate state rather than re-fetch data, and stay where they are.

### Shape

- **Items.** One per thing to keep fresh: a kind, a key (the owner name),
  its expiry, the last time it was used, the last refresh, and backoff state.
- **One scheduler goroutine.** A queue ordered by due time, one timer for the
  earliest item, and a wake-up channel for items added or moved. Due times get
  jitter, so a burst of entries cached together does not refresh together.
- **Kinds.** Each kind supplies:
  - when an item is due: a lead or a fraction of the TTL, with a floor;
  - whether it is in use: always, or used since the last refresh;
  - how to fetch it, with its own privacy and transport policy;
  - how to read the new expiry, so that a fetch that does not move it forward
    counts as a failure (#727's rule, for every kind).
- **One backoff scheme** for failed fetches, taken over from
  `DiscoveryTracker`'s: exponential from a base, with a cap.
- **A worker limit**, so a large set of items falling due together cannot
  flood the upstream servers.
- **A clock that tests can drive.** Timing is the whole point of the engine,
  and the tests must not sleep through TTLs.
- **A view.** `imr dump refresh`, and the same over the API (#447): every item,
  its kind, its expiry, when it is next due, when it was last used and last
  refreshed, and its failures.
- **Lifecycle.** Started where both `ImrEngine` and an embedder's
  `InitImrEngine` reach, and stopped by the engine's context.

### Its clients

| kind | in use | due | fetch |
|---|---|---|---|
| transport signal (#781) | the server was queried while its window was open | shortly before expiry, if no echo arrived | `_dns.<ns>` over a transport the signal allows |
| root NS (stage 2) | always | 60 s before expiry, retry 15 s | `. NS` from the live roots; hints if gone; never while `.` is forwarded |
| TLD delegation (#466) | always | a fraction of the TTL | the NS RRset and its nameservers' addresses |
| deeper delegation (#466) | queried enough, recently: a hit count with decay | a fraction of the TTL | as for a TLD |

Transport signals are the lightest client. The query path does almost all of
their refreshing, and the engine only runs the fallback lookups.

The root moves over in its own stage, after the engine has proven itself on
signals. It has been broken twice (#443, #722), and its tests must pass
unchanged across the move.

Deeper delegations need something that does not exist today: a record of use
per zone. `serversForQuestion` is the natural place to count a zone as used.
That cost belongs to #466, not to #781.

## Tests

For transport signals, all without the network, over DNS clients that record
what they are asked:

- **No Do53 at expiry:** a signal kept fresh across several TTLs by echoes and
  by the fallback lookup; no query to that server goes over Do53 unless the
  weighted draw picks it.
- **Weights follow the operator:** a signal that changes from `dot:5` to
  `dot:50`, and one that adds DoQ, is in use within one TTL.
- **The opt-in:** it is sent only when the signal is unknown, in its window,
  or expired, and not while a denial is cached.
- **Idle servers cost nothing:** a server not queried during its window gets no
  lookup, and its signal expires.
- **First use after expiry:** the query goes over a noted encrypted transport,
  carries the opt-in, and its response renews the signal.
- **Attacks:**
  - a different signal in a Do53 response is not applied, and starts one
    verifying lookup;
  - a replayed equal signal over Do53 renews nothing;
  - a stream of forged mismatches starts one lookup, not one each.
- **A failed refresh:** the old weights hold for the grace, then expire.
- **`do53:0`:** such a server's queries stay encrypted across several TTLs,
  with Do53 used only when the encrypted attempts fail.

For the engine: due times, jitter bounds, the in-use rule, backoff, the worker
limit, and a fetch that does not move the expiry counting as a failure, all on
the test clock.

## Staging

| step | content | depends on | status |
|---|---|---|---|
| E1 | the engine, with transport signals as its first client; the per-server OOTS opt-in; harvesting from every response kind with the equal/different rules; the verifying and fallback lookups; `ImrQuery` with a privacy level; expiry, the transport note and the grace; the view | — | not started |
| E2 | the root refresher as an engine client | E1 | not started |
| E3 | TLD delegations as a client; then deeper delegations, with per-zone use tracking (#466) | E1; E2 for the shared semantics | not started |

## Size

Estimated lines added, in the codebase's style, comments included:

| step | production | tests |
|---|---|---|
| E1 | 730–830 | about 900 |
| E2 | about 150 changed | about 100 |
| E3 | about 350 | about 350 |

E1 is large because the engine cannot be tested for real without a client, and
signals are the client that needs it now. It could be split in two PRs: the
engine with an in-test client first, then signals.

## Open questions

1. **Must a harvested signal validate** before it renews the expiry? With the
   opt-in withheld most of the time, and renewal only from encrypted
   responses, an attacker has few chances. Validating each harvested SVCB
   against the zone's DNSKEY costs a DNSKEY fetch per zone, and makes the
   echo only as cheap as the cache makes it.
2. **The window's size:** what fraction of the TTL, and what floor. It must be
   long enough to catch one query to a moderately used server; the fallback
   lookup covers the rest.
3. **The grace after a failed refresh:** one TTL, a fixed cap, or the smaller
   of the two, as proposed.
4. **Out-of-bailiwick owners.** For `ns.example.com` serving `example.com`, the
   signal is served by the same servers, so a strict lookup works. For
   `ns1.provider.net`, the lookup goes to `provider.net`'s servers, which may
   not encrypt. Allow cleartext there, since it reveals only the nameserver's
   name, or let the signal expire?
5. **Non-strict first use when nothing is noted.** A server whose signal expired
   before any encrypted transport was noted, or whose note is empty, gets
   its first query over Do53 with the opt-in. Acceptable, or should an
   opportunistic query wait for a lookup the way a strict one does?
