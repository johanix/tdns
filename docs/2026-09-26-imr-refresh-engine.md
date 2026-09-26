# Refreshing before expiry: a refresh engine, and transport signals

**Written 2026-09-26.** Proposal. Line references are to main at `ec6e8626`.
Follows from #781: tdns-imr keeps a transport signal it has learned for as long
as it runs, and never refreshes it. It also sets the frame for #466 (delegation
prefetch), which wants the same kind of machinery for NS RRsets.

**Status:** proposal, revision 2.1, not implemented.

**Revisions:**
- **r1**, 2026-09-26: merged as `9a168618` (#783).
- **r2**, 2026-09-26, after an external review of r1:
  - the refresh window and the fallback lookup's in-use rule are separate
    (§The refresh window, §In use and the fallback lookup);
  - the `_dns` lookups walk to the owner zone with opportunistic privacy
    (§The lookups);
  - signals on a parent's referral follow the same harvest rules
    (§Harvesting);
  - a denial is a withdrawal, not a failed refresh (§The life of a server's
    signal);
  - the OOTS option is decided per server, in `tryServer`
    (§The OOTS opt-in);
  - r1's five open questions are settled (§Decisions), and the tests and a
    must-not-regress list are extended.
- **r2.1**, 2026-09-26, after a re-review of r2:
  - an expired signal is not unknown: it keeps its last weights to compare
    against, only unknown takes a first signal, and the first use after an
    idle expiry starts a lookup (§The life of a server's signal,
    §Harvesting, §Expiry);
  - a refresh not completed by the end of the TTL is grace, however far it
    got, and signal jitter stays inside the window (§The grace, §Shape);
  - the message copy in `tryServer` is a deep one (§The OOTS opt-in).

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
   refreshed before it expires.
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
- **Signals are applied in two places, both without validation.**
  - A server's own signal is harvested from its positive answers only
    (`parseTransportForServerFromAdditional`, called at
    `v2/dnslookup.go:1653` inside `len(r.Answer) != 0`). Its negative
    answers (`handleNegative`, `:1684`) and referrals renew nothing.
  - Signals for a child's nameservers are harvested from the parent's
    referral (`ParseAdditionalForNSAddrs`, `:1860`; the
    `use-transport-signals` check is at `:1931`).
- **Usage is recorded per nameserver, not per zone.** `tryServer`
  (`v2/dnslookup.go:2216`) counts attempts, carried answers and failures per
  transport on the `AuthServer`, and `RecordRTT` keeps a last-sample time. No
  cache entry or `cache.Zone` records any use.
- **`ImrQuery` has no privacy level.** It always walks with
  `edns0.PrivacyNone` (`v2/imrengine.go:796`, `:845`).

## Transport signals (#781)

### The life of a server's signal

| state | weights in the draw | OOTS on queries to it | leaves the state when |
|---|---|---|---|
| unknown: never learned, or a denial has expired | none (Do53 default) | yes | a signal is harvested or looked up: **fresh** |
| fresh | the signal's | **no** | the refresh window opens: **window** |
| window | the signal's | yes | an equal signal arrives over an encrypted transport: **fresh**, expiry renewed. The fallback lookup answers: **fresh**. It is denied: **denied**. It fails: **grace**. The TTL runs out with the server in use and no refresh completed: **grace**. The TTL runs out with the server not in use: **expired** |
| grace | the signal's | yes | a lookup answers, or an equal signal arrives over an encrypted transport: **fresh**. A lookup is denied: **denied**. The grace ends: **expired** |
| expired | none; the last signal is kept to compare against, and as the note of the transports the server offered | yes | the server is used: **grace**, with a lookup started (§Expiry) |
| denied | none | no | the cached denial expires (#777): **unknown** |

**A denial is a withdrawal.** A fallback or verifying lookup answered with
NXDOMAIN or NODATA means the operator has taken the signal down. The weights
are dropped at once, with no grace, and the server gets no opt-in while the
denial is cached, the lifetime #777 already gives it.

**The grace** is only for a refresh that has not succeeded:
- a lookup that failed: a timeout or SERVFAIL, an answer from a signed owner
  zone that is not Secure, or an answer whose expiry does not move forward
  (#727's rule);
- a server in use whose refresh has not completed when the TTL runs out,
  whether its lookup is in flight, queued behind the worker limit, or not yet
  started. A busy engine must not turn into Do53 for that server;
- the lookup started by the first use after an idle expiry (§Expiry).

It lasts the smaller of one TTL and five minutes. The engine retries with
`DiscoveryTracker`'s backoff inside it. This is the only use of a signal past
its TTL.

### The refresh window

The window is the time before expiry when queries to the server carry the
OOTS option again:

**W = min(60 s, max(5 s, 10% of the TTL))**

It is kept short on purpose. A window long enough to catch every moderately
used server would put the option, and so the signal and its RRSIG in every
response, back on all queries to a busy server for hours when the TTL is a
day: the size problem the design exists to remove. The fallback lookup, not
the window, covers servers that are quiet near the end of the TTL.

### In use, and the fallback lookup

**In use** means the server was sent a query since its signal was last
renewed or learned. A server used all through the TTL and idle in the last
minute is in use.

**The fallback lookup** is due at the window's midpoint, `expiry − W/2`, for a
server that is in use and has not had an equal signal over an encrypted
transport since the window opened. Two kinds of server need it:
- servers that were busy but quiet during the window;
- servers that do not echo on the responses they gave. NSD's
  transport-signalling branch never echoes on NXDOMAIN or NODATA, for
  out-of-bailiwick NS names, or with `minimal-responses`. tdns-auth does not
  echo for zones it serves as a secondary, and echoes only for the first NS
  name where it originates the signal.

A server not in use gets no lookup, and its signal expires. Idle costs
nothing.

### The OOTS opt-in

Decided per server in `tryServer`, from that server's state:
- sent in **unknown**, **window**, **grace** and **expired**;
- withheld in **fresh** and **denied**.

The question's message is shared by every server a lookup tries
(`buildQuery`, `v2/dnslookup.go:2201`). `tryServer` therefore adds or removes
the option on a copy, never on the shared message: a question that tries one
fresh server and one in its window sends the option to the second only. The
copy is a deep one (`dns.Msg.Copy`), with an OPT RR of its own; a shallow
copy shares `Extra`, and adding the option to it would add it to the shared
message.

### Harvesting

A signal can arrive in two places:
1. **A server's own signal, in any response from that server:** answer,
   NODATA, NXDOMAIN or referral. Today only answers are harvested.
2. **A child nameserver's signal, in a parent's referral**
   (`ParseAdditionalForNSAddrs`).

Both are judged the same way. "The transport" is the one the response came
over: to the server itself in case 1, to the parent in case 2.
`parseTransportForServerFromAdditional` is not given it today; `tryServer`
has it (`wireTransport`).

- **Equal, over an encrypted transport:** the expiry is renewed from the
  SVCB's TTL. The content is not changing, so this is not validated.
- **Equal, over Do53:** nothing is renewed. An on-path attacker could replay
  the old signal after the operator has changed it, and keep `dot:5` alive
  when the operator has moved to `dot:50`.
- **Different:** not applied. It starts one verifying lookup.
- **For a server in unknown:** applied, as today. A forged first signal can
  only steer queries between the server's own transports:
  `applyTransportMapToServer` sets transports, ALPN order and weights, and
  never addresses. Do53 stays the last resort.

These rules hold in every state that has a signal to compare against: fresh,
window, grace, and expired, where the comparison is with the last signal.
**Only unknown takes a first signal.** Treating an expired server as unknown
would accept a signal over Do53 after an idle spell: the replay that "equal,
over Do53" refuses while the signal is live.

After a verifying lookup has confirmed the current signal, further mismatches
start no new lookup for a short cooldown: a few minutes, never longer than the
TTL. The cooldown never cancels the fallback lookup, so a real operator change
that arrives during it is still picked up before expiry.

### The lookups

The verifying and the fallback lookup are the same query: `_dns.<ns>`, the
signal type (SVCB, or TSYNC when configured).

**It is a walk to the owner zone, not a query to the nameserver.** For
`ns.example.com` the record lives in `example.com`. For `ns1.provider.net` it
lives in `provider.net`, whose servers the signal says nothing about. Requiring
every hop to encrypt would fail for every out-of-bailiwick nameserver, and for
any walk that still has a cleartext hop.

So the lookups use **opportunistic privacy**: encrypted where a hop's servers
signal it, Do53 where they do not. The lookup reveals only the nameserver's
name, which resolving its addresses has already revealed. For an in-bailiwick
nameserver whose zone's servers signal encryption, the walk's last hop is
encrypted anyway.

- **A signed owner zone:** only a Secure answer is applied.
  `applyTransportRRsetFromAnswer` (`v2/dnslookup.go:2510`) already receives
  the verdict. Anything else counts as a failed lookup.
- **An unsigned owner zone:** the answer is applied, as today.

This needs a variant of `ImrQuery` that takes a privacy level, used by these
two lookups only. Every existing caller of `ImrQuery` stays at `PrivacyNone`.

Both lookups share `DiscoveryTracker`, so a verify started by a harvest and a
fallback started by the engine for the same server are one query in flight.
`DiscoveryTracker` records a success as terminal today. The refresh path
resets the owner before its lookup, so the tracker only de-duplicates lookups
in flight and backs off failures.

Out-of-bailiwick signals are always looked up before expiry when in use.
Those servers often cannot echo, and letting their signals expire instead
would leave them with no refresh at all.

### Expiry, first use, and strict privacy

**Expiry.** An expired signal's weights leave the draw, and its engine item is
dropped. The signal itself is kept: it is what a later signal is compared
against, and it is the note of the transports the server offered.

**First use after an idle expiry.** When the server is used again:
- it moves to **grace**, and the last weights return to the draw for as long
  as the grace lasts;
- its engine item is re-created, and the `_dns` lookup starts at once;
- its queries carry the OOTS option, so a server that echoes can settle the
  grace with an equal signal over an encrypted transport before the lookup
  answers;
- a server that does not echo gets its weights back from the lookup. Without
  it, such a server would stay expired, and the operator's changes would
  never be learned.

The grace here lasts as long as the lookup: normally well under a second, and
never longer than the grace's cap. The alternative, no weights until the
lookup answers, would send those queries over Do53.

**First use of an unknown server.** A non-strict query goes over Do53 with the
opt-in. That is one query, its response carries the signal, and a client that
did not ask for strict privacy has accepted cleartext. It does not wait.

**Strict privacy** keeps #777's behaviour: for a server in **unknown**, the
precheck looks the signal up and waits for it. A server in **expired** whose
last signal offered an encrypted transport can carry a strict query at once:
its first use puts it in grace, with the last weights.

### Known limits

- **A signal offering only Do53 never renews from a harvest**, since equal
  over Do53 renews nothing. It is refreshed by the fallback lookup, over Do53.
  An on-path attacker who can spoof that lookup, for an unsigned owner zone,
  can hold the old weights. That is inherent to an unsigned zone reached in
  cleartext.
- **A man in the middle of an encrypted transport** can replay an equal
  signal, and keep the current weights until the server goes idle or the
  fallback runs. The IMR does not verify certificates on its connections to
  authoritative servers; that is by design for opportunistic transport, and
  equal harvests are not validated. A cap of "at most N renewals from
  harvests, then one validated lookup" would bound it. It is not needed for
  E1.

## The refresh engine

### What it owns

Keeping cached data fresh before it expires. Nothing else: server and zone
backoff, forward-zone quarantine, address-family probes and zone-state rechecks
re-evaluate state rather than re-fetch data, and stay where they are. Signal
and TLSA discovery, NS revalidation and out-of-bailiwick address lookups stay
query-driven; they are not engine clients.

### Shape

- **Items.** One per thing to keep fresh: a kind, a key (the owner name),
  its expiry, the last time it was used, the last refresh, and backoff state.
  An item is created when its data is learned, and dropped when the data
  expires idle or is withdrawn. A signal's item is re-created when its server
  is used again after an idle expiry. `AuthServerMap` is never pruned, so without
  that the scheduler would grow with every nameserver ever seen.
- **One scheduler goroutine.** A queue ordered by due time, one timer for the
  earliest item, and a wake-up channel for items added or moved. Due times get
  jitter, so a burst of entries cached together does not refresh together.
  The jitter is bounded per kind: a signal item's due time stays inside its
  window.
- **Kinds.** Each kind supplies:
  - when an item is due;
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
| transport signal (#781) | queried since the signal was last renewed or learned | the window's midpoint, if no equal encrypted echo arrived in the window | `_dns.<ns>`, opportunistic |
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

## Decisions

r1's open questions, settled in r2:

1. **Harvested signals are not validated when equal and encrypted.** They
   renew the expiry; the content is not changing. The verifying lookup's
   answer is validated when the owner zone is signed, and only a Secure answer
   is applied.
2. **The window is `min(60 s, max(5 s, 10% of the TTL))`.** The fallback
   lookup, on "in use since the last renewal", covers the rest.
3. **The grace is the smaller of one TTL and five minutes.**
4. **Out-of-bailiwick owners are looked up**, opportunistically, validated
   when their zone is signed. They are never left to expire instead.
5. **A non-strict first use of an unknown server goes over Do53 with the
   opt-in.** Strict keeps #777's wait. (r2.1: an expired server is not
   unknown; see §Expiry.)

## Tests

For transport signals, all without the network, over DNS clients that record
what they are asked:

- **No Do53 at expiry:** a signal kept fresh across several TTLs by echoes and
  by the fallback lookup; no query to that server goes over Do53 unless the
  weighted draw picks it. The tests must say exactly that, not "no Do53 ever":
  a draw that picks Do53 on a server whose signal has a Do53 share is not a
  leak.
- **Weights follow the operator:** a signal that changes from `dot:5` to
  `dot:50`, and one that adds DoQ, is in use within one TTL.
- **The opt-in:** it is sent only in unknown, window, grace and expired, and
  not while a denial is cached.
- **Per server:** two servers in one `IterativeDNSQuery`, one fresh and one in
  its window: the option goes to the second only.
- **In use vs. the window:** a server used while fresh and idle during a 60 s
  window still gets its fallback lookup, and its signal does not expire.
- **Idle costs nothing:** a server idle for the whole TTL gets no lookup, its
  signal expires, and its engine item is gone.
- **First use after an idle expiry, a server that echoes:** the server is in
  grace with its last weights, its queries carry the opt-in, and an equal
  signal over an encrypted transport makes it fresh.
- **First use after an idle expiry, a server that does not echo:** a `_dns`
  lookup runs, and the weights come back from that lookup, or from an equal
  signal over an encrypted transport, never from a signal over Do53.
- **After an idle expiry, a signal over Do53:** equal or different, it is not
  applied; it starts at most one verifying lookup.
- **A refresh late at the end of the TTL:** a server in use whose fallback is
  still queued (worker limit, jitter) when the TTL runs out is in grace, not
  expired, and no query to it goes over Do53 unless the draw picks it.
- **The parent's referral:** a first child signal is applied; a later equal
  one over Do53 to the parent renews nothing; a later different one starts one
  verifying lookup and is not applied.
- **Out of bailiwick:** the lookup of `_dns.ns1.provider.net` walks with
  opportunistic privacy, and still refreshes when `provider.net` has no
  encrypted signal.
- **Withdrawal:** a fallback lookup answered with NODATA or NXDOMAIN moves the
  server to denied, with no grace; one answered with SERVFAIL gives the grace,
  then expiry.
- **Attacks:**
  - a different signal in a Do53 response is not applied, and starts one
    verifying lookup;
  - a replayed equal signal over Do53 renews nothing;
  - a stream of forged mismatches starts one lookup, not one each;
  - the cooldown after a confirming lookup does not cancel the fallback, so an
    operator change is in use by the end of the TTL.
- **One lookup in flight:** a verify started by a harvest and the engine's
  fallback for the same server are one `DiscoveryTracker` lookup.
- **`do53:0`:** such a server's queries stay encrypted across several TTLs,
  with Do53 used only when the encrypted attempts fail.

For the engine: due times, jitter bounds, the in-use rule, backoff, the worker
limit, items dropped when their data expires idle, and a fetch that does not
move the expiry counting as a failure, all on the test clock.

## Must not regress

- `do53:0` remains a last-resort fallback, not a gate;
  `TestCandidateTransports_Do53ZeroStillFallback` stays.
- #777: a cached denial is "no signal" for exactly its cache lifetime; the
  first strict query after it expires looks again; a strict query to a server
  in unknown still prechecks and waits.
- `use-transport-signals: false` still suppresses the OOTS option, and still
  ignores signals in the Additional section.
- `applyTransportMapToServer` still does not touch addresses: a signal must
  never become a redirect.
- Only a server in unknown takes a first signal. An expired server is judged
  against its last signal.
- `RefreshRoot` is untouched in E1: the 60 s lead, the 15 s retry, the 1 s
  floor, no refresh while `.` is forwarded, a fetch whose new expiry is still
  inside the lead not counting, and `force=true`.
- Every existing caller of `ImrQuery` stays at `PrivacyNone`. The privacy
  argument is for the two new lookups only.
- Signal and TLSA discovery, NS revalidation and out-of-bailiwick address
  lookups stay query-driven.

## Staging

| step | content | depends on | status |
|---|---|---|---|
| E1 | the engine, with transport signals as its first client: the per-server OOTS opt-in in `tryServer`; harvesting from every response kind and from the parent's referral, with the equal/different rules; the verifying and fallback lookups, opportunistic, through an `ImrQuery` that takes a privacy level; withdrawal, expiry, the transport note and the grace; the view | — | not started |
| E2 | the root refresher as an engine client | E1 | not started |
| E3 | TLD delegations as a client; then deeper delegations, with per-zone use tracking (#466) | E1; E2 for the shared semantics | not started |

#781 is done once E1 shows that a used signal stays fresh across several TTLs
with no Do53 except the weighted draw, an idle signal expires, a changed
signal is in use within one TTL, and a replayed equal signal over Do53 renews
nothing. #466 stays open until E3.

## Size

Estimated lines added, in the codebase's style, comments included:

| step | production | tests |
|---|---|---|
| E1 | 800–900 | about 1050 |
| E2 | about 150 changed | about 100 |
| E3 | about 350 | about 350 |

r2 and r2.1 add to E1 the harvest from the parent's referral and from every
response kind, the per-server copy of the message, the withdrawal path, the
expired state's comparison and first-use lookup, and the tests for them. E1 could be split in two PRs: the engine with an in-test client
first, then signals.
