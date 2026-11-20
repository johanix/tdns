# The transport signal's alternative endpoint: a ServiceMode TargetName

**Date:** 2026-11-14. **Status:** r4 implemented on `oots-endpoint`, merged
into main in #1118; r5 (section 9) in the pull request for #1128 and #1129.
Points marked **Decided** were settled on 2026-11-14; everything else is
proposed.

**Revisions:**
- **r1**, 2026-11-14: first write-up, with six open questions.
- **r2**, 2026-11-14, after rulings on those questions (section 7):
  - an unvalidated record with a target is ignored in whole, and every hop of
    an alias path must validate (section 4);
  - a transport named in two records: one record is used (section 2);
  - the server does not inject the target's addresses (section 5);
  - a signed nameserver zone with an unsigned target zone is operator
    guidance (section 4).
- **r3**, 2026-11-14, after the cleartext token was split:
  - `udp` and `tcp` replace `do53`, and take a TargetName and a `port` like any
    other transport, which reverses r2's rule that cleartext never moves
    (section 2);
  - an endpoint is a name and a port; a name may have many addresses, which is
    how a transport is spread over several hosts (section 2);
  - how the resolver uses endpoints: the weight caps discretionary use, a
    truncation retry goes to the address that truncated, a failing endpoint
    falls back to the nameserver's name on port 53 (section 3).
- **r3.1**, 2026-11-14: the old `do53` token survives as a receive-only
  shorthand, and is not retired (section 2).
- **r4**, 2026-11-14, after the path to an implementation was worked through:
  - a record's `port` and target apply to every transport it names, and the
    DoH-alone exception is dropped (section 2);
  - a record that loses the tie-break is inert for that transport only, and `.`
    wins an equal-priority conflict (section 2);
  - ports are sockets: which transports may share one (section 2);
  - TCP the resolver initiates goes to the `tcp` endpoint, a truncation retry to
    the address and port that truncated, and forced TCP without a `tcp` endpoint
    to the nameserver on port 53 (section 3);
  - backoff and RTT are keyed by address, port and transport, and the lookup of a
    target's addresses never uses a redirected endpoint (section 3);
  - the fallback to the nameserver's name on port 53 is decided (section 3);
  - configuration: `ports:` and later `targets:` maps replace `records:` and the
    proposed `target:` key (section 5);
  - mixed versions: a lossless codec is a precondition for publishing the new
    tokens (section 8, new).
- **r5**, 2026-11-18, after the ruling on F25 in the CodeRabbit review of
  #1118: a ServiceMode target other than `.` is a server of its own, with its
  own backoff and RTT, apart from the nameserver that redirects to it
  (section 9, new; one line added to section 3).

Builds on `2026-10-04-transport-signal-publication-and-serving.md` (the
authoritative side), `2026-09-26-imr-refresh-engine.md` (the resolver side, itself
a proposal) and tdns #994 (open: the `port` key, and several SVCB records in one
signal). This note is about tdns. It does not change any draft text.

## 1. The problem

A nameserver `foo.example` offers a transport somewhere other than where its
default is: on another port, which #994 handles, or on another host,
`dot-foo.example`. The signal has to say so, and the resolver has to be able to
act on it without trusting more than it should.

The pressure behind it is load. Operators fear the cost of encrypted transports
(all traffic on DoT would cost several times the CPU of Do53) and of TCP. They
want to say "please only 30% TCP" and "send the DoT traffic to serverX and the
TCP traffic to serverY". The signal has to be flexible enough to say that.

## 2. The shape of the signal

**Decided.** Every SvcParam (`oots`, `port`, any other) lives in the ServiceMode
SVCB records at `_dns.<ns-name>`. The TargetName is only a target: a name whose
addresses the resolver looks up. There is no new SvcParam; an `oots-server` key
was considered and dropped, because TargetName already says where the endpoint
is.

```
_dns.foo.example. IN SVCB 1 dot-foo.example. oots="dot:30" port=1234
_dns.foo.example. IN SVCB 1 doq-foo.example. oots="doq:30" port=1235
_dns.foo.example. IN SVCB 1 tcp-foo.example. oots="tcp:30"
_dns.foo.example. IN SVCB 1 .                oots="doh:20"
```

Here DoT and DoQ go to their own hosts on their own ports, TCP the resolver
initiates goes to `tcp-foo.example` on port 53 (and at most 30% of optional
TCP, if the resolver chooses any), DoH stays on `foo.example`, and UDP is not
mentioned, so it stays on `foo.example` at weight 100.

**The tokens. Decided.** `udp` and `tcp` (cleartext DNS over UDP or TCP, default
port 53), `dot`, `doq`, `doh`. `udp` and `tcp` replace the earlier `do53`, which
treated two very different transports as one. Both default to 100 when absent:
TCP is mandatory for DNS servers (RFC 7766, RFC 9210), and a default of 0 would
make every existing signal claim there is none. So `oots="tcp:30"` keeps UDP at
100 and sets TCP to 30. They are named `udp` and `tcp`, not `udp53` and `tcp53`,
because a record can give them another port; the encrypted tokens carry no port
either.

**The old token survives as a deprecated, receive-only shorthand. Decided.**
`do53:N` reads as `udp:N` and `tcp:N`, carries no TargetName and no port, and is
ignored in a record that has one; an explicit `udp` or `tcp` entry wins over it.
Servers never emit it. Retiring it outright was the alternative, at the cost of
old signals' `do53:0` ("send me none") being read as 100.

**Endpoints.** An endpoint is a name and a port. Rules for a record:

- **One record is one endpoint.** TargetName `.` is the nameserver itself, the
  name whose `_dns.` label owns the record. Any other TargetName is an
  alternative host. A record without `port` uses each named transport's default
  port at that name: 53, 853 or 443.
- **The record's `oots` names the transports offered at that endpoint.** The
  TargetName and `port` apply to every transport the record names, as RFC 9461
  has it for `port`. A record that wants different endpoints for different
  transports is written as several records, one transport each; tdns-auth does
  that itself (section 5). #994's exception, that `port` applies to `doh` only
  when `doh` is alone in its record, is dropped.
- **Cleartext is not special. Decided.** `udp` and `tcp` take a TargetName and a
  `port` like any other transport. The delegation guarantees only that the
  nameserver's own name answers on port 53, and that stays true whatever the
  signal says.
- **A truncation retry needs TCP where UDP is.** A `udp` entry with a port or a
  target sends the TCP retry after truncation to the same address and port, so
  the operator serves TCP there. If it does not, the retry fails and the resolver
  falls back (section 3).
- **One endpoint per transport. Decided.** A transport named in two records with
  different endpoints is a misconfiguration. The resolver uses one of the two and
  never neither: ignoring both would take a working setup down. The rule for
  choosing is proposed: the lowest SvcPriority, then the lowest RDATA in DNSSEC
  canonical order (RFC 4034 section 6.3), so that the outcome does not depend on
  the order an RRset happens to arrive in. The priority bytes come first in the
  RDATA and the root name sorts before any label, so on equal priority `.` wins:
  the nameserver itself beats an alternative host. The losing record is inert for
  that transport only; it still supplies the other transports it names. It is not
  a standby. A warning when such an RRset is loaded would help the operator
  (proposed).
- **Ports are sockets.** A publisher refuses an endpoint whose transports clash
  on one socket: DoQ and `udp` on one UDP port; DoT, DoH and `tcp` on one TCP
  port. A `udp` entry with a port also needs TCP at that port for the retry, so
  it takes the port on TCP as well, and DoT or DoH there is refused. `udp` and
  `tcp` sharing one port is the natural case and is allowed. A resolver takes the
  records as given. A warning at load when no listen address of the server uses
  the published port (a front end may legitimately publish one).
- **A name can have many addresses. Decided.** One endpoint does not mean one
  host. The target is a name: it may have several A and AAAA records, or be
  anycast, and the resolver chooses among its addresses as it does for any
  nameserver name (round-trip time, back-off per address). That is how a
  transport is spread over several hosts. The weight caps the transport's share
  as a whole, not per address.
- **Priority is otherwise not used to order endpoints.** Write 1 on every
  record. Plain SVCB uses priority to order a fallback list and to shuffle
  equals; an OOTS resolver reads the RRset as a set of endpoints and chooses by
  weight, as #994 already does.

## 3. What the resolver does

**With the target.**

- **Decided.** It resolves the target's addresses (A and AAAA, CNAMEs followed),
  as for any nameserver name, and does nothing else with the name. It never
  looks up an SVCB, or any signal, at the target. A second place that can state
  weights and ports is a second source of truth, and the design allows none. If
  the target has an SVCB of its own, it is not read.
- **Looking up the target's addresses never uses a redirected endpoint.** A
  target may be served by the very nameserver whose transport is redirected to it:
  `dot-foo.example` may be served by `foo.example`, whose DoT is redirected to
  `dot-foo.example`. So those lookups go to the nameserver's name on its default
  ports, and run off the query path, as the TLSA follow-up does. Until the
  addresses are known, the transport uses its default endpoint.
- **Delegating the whole signal is AliasMode, and only that.** `_dns.<ns>` holds
  one AliasMode record whose TargetName, written with its `_dns.` label (RFC 9460
  section 3 queries it as written), leads to an RRset that may itself hold
  ServiceMode records with targets. That composition needs no extra rule beyond
  the alias depth cap of the 2026-10-04 design and R5 below. It is how a provider
  publishes one multi-host signal for many customer names.

**With the weights and endpoints. Decided** (the model as confirmed):

- **The weight caps optional use.** A `udp` or `tcp` weight limits the share of
  queries the resolver chooses on its own to send over that transport, so "only
  30% TCP" is `tcp:30`. It never gates TCP that the protocol or a policy
  requires: truncation retries and forced TCP, such as the escalation for large
  responses, ignore it, `tcp:0` included. A resolver that chooses no optional
  TCP satisfies any cap, and a received weight does not by itself make a
  resolver choose TCP. Neither `udp:0` nor `tcp:0` is a hard gate: cleartext on
  port 53 is mandatory, so it stays the last resort.
- **A signalled endpoint receives its transport's traffic.** With no signalled
  endpoint for a transport, the resolver uses the nameserver's name at the
  transport's default port.
- **Which TCP goes where.** TCP the resolver initiates, forced or optional,
  goes to the `tcp` endpoint. A truncation retry goes to the address and port
  that truncated: if UDP went to `serverZ` on port 5353 and truncated, the TCP
  retry goes to `serverZ` on 5353. Forced TCP with no signalled `tcp` endpoint
  goes to the nameserver's name on port 53, never to the port of a `udp`
  endpoint.
- **A failing endpoint falls back. Decided.** An address that fails is backed off
  on, and the target's other addresses are tried. When none works, the resolver
  falls back to the nameserver's name on port 53.
- **Backoff and RTT follow the endpoint, down to the port.** They are keyed by
  address, port and transport. A same-host `udp` endpoint on port 5353 that
  fails must not back off the fallback on port 53, the one endpoint that has to
  keep working, and a changed port starts with a clean slate.
  - (r5, 2026-11-18) At a target, backoff and RTT belong to the target, not to
    the nameserver whose signal sent the transport there (section 9).
- **The operator asserts that the alternative endpoint serves the nameserver's
  zones.** Nothing checks it before connecting. An endpoint that refuses, times
  out or fails the handshake is a failure like any other, handled as above.

## 4. Trust

**Decided.** A signal that directs the resolver away from the nameserver to a
new name must be secure, so it requires DNSSEC validation.

- **R1.** A record with a non-`.` TargetName is honored only if the RRset that
  carries it validates as Secure, however the resolver obtained it: a direct
  lookup of `_dns.<ns>`, or the Additional section of a response with the RRSIG
  that rides along. Insecure, Bogus, or no RRSIG: not honored.
- **R2. Decided.** An RRset that does not validate is not thrown away. Its
  records with TargetName `.` are honored as today. Its records with a non-`.`
  TargetName are ignored in whole. Keeping their weights and port while dropping
  the target would apply details meant for another host to the nameserver's own,
  which does more harm than good.
- **R3.** A resolver that does not validate never honors a non-`.` TargetName.
- **R4.** A record with TargetName `.`, with or without `port`, needs no
  validation. That is unchanged.
- **R5. Decided.** When the signal is reached through AliasMode, every RRset on
  the path must validate, the alias records and the final RRset alike, for a
  target at the end of it to be honored.

R1 to R5 cover `udp` and `tcp` like any other transport: a redirected cleartext
endpoint needs a Secure signal.

Why R5: validating only the final RRset proves what the zone that holds it says.
It does not prove that the nameserver's operator authorized it, because anyone
can sign their own zone. The authorization is the alias record in the
nameserver's own zone, so that hop has to be Secure too. Without R5, a forged
alias pointing at an attacker's own signed RRset would satisfy R1.

Consequences:

- An operator whose zone is unsigned can still cap shares ("only 30% TCP") and
  move a transport to another port on its own host, because both stay on the
  same host (R4). Steering a transport to another host needs a signed zone.
- A vanity name in an unsigned zone does not inherit a provider's redirects
  through its alias. It still inherits the provider's records with TargetName
  `.`. The resolver should log, at debug level, and count a redirect it ignored
  for want of validation, because the operator would otherwise see nothing
  (proposed).
- The 2026-09-26 design argues that a forged first signal "can only steer
  queries between the server's own transports", because applying a signal sets
  transports, ALPN order and weights and never addresses. A TargetName gives the
  signal an address decision for the first time. R1 and R5 are what keep the
  argument true.

**The target's addresses. Decided.** No stricter than a nameserver name's. The
reasoning: `foo.example` is itself known only by name, and a resolver accepts its
A and AAAA records unsigned when no RRSIGs are available. An attacker who can
forge the target's address can forge the nameserver's equally, so once the
pointer is secure the redirect gives that attacker nothing new. In practice both
names belong to one provider, which usually signs its infrastructure. So the
target's addresses are treated exactly as any nameserver's: validated when signed
and the chain is Secure, not used when Bogus, accepted when Insecure. `ipv4hint`
and `ipv6hint` are not read.

One case lowers the bar and is named here so it is not a surprise: the
nameserver's zone is signed and the target's zone is not. An address that could
not have been forged for `foo.example` can then be forged for `dot-foo.example`.
**Decided:** this is operator guidance, not a resolver rule. Sign the zone of an
alternative endpoint.

**Authenticated connections (later).** RFC 9461 has a client authenticate the
server against the service name, which here is the nameserver's name, not the
target. A connection that authenticates on that basis would also make a
redirect trustworthy without DNSSEC on the signal. That is wanted, and it is a
later step with a strict profile, not part of this design. Today the resolver
does not verify certificates to authoritative servers, by design.

## 5. Where this meets the existing designs

- **Authoritative side (2026-10-04).** "A server speaks only about itself" is
  unchanged: the record is about the nameserver's own name, and the target is
  the operator's statement. An operator-authored ServiceMode record with any
  TargetName is zone content, served and injected like any stored signal. Not
  settled there, and to settle with the plan: whether the start-up pass leaves an
  operator-authored ServiceMode record at `_dns.<ns>` alone, as it does an
  alias.
- **Configuration (proposed).** `service.transport` keeps `signal` and gains a
  map from transport to port, `ports:`, and later one from transport to target,
  `targets:`. They replace #994's `records:` list and the `target:` key this
  note proposed in r3. The maps are keyed by transport because the model is one
  endpoint per transport, and their values are scalars, not lists, for the same
  reason. tdns-auth works out the records: one record per transport that has a
  port or a target, and one record with neither carrying the rest, so that every
  transport appears in exactly one record and a record never carries a transport
  it was not asked to move. Checks at load, each an error unless marked:
  `signal` parses; a key of a map is a transport the signal gives a weight; a
  port is 1 to 65535, and the transport's standard port counts as absent without
  a word; transports that clash on one socket are refused (section 2); a map with
  `type: tsync` or `none` is refused; and a warning when no listen address uses a
  published port. Until the token split lands `do53` is not a key, and after it
  `udp` and `tcp` are.
- **No target addresses in the response. Decided.** The server does not add the
  target's A and AAAA to the Additional section, even when it hosts the target's
  zone. Resolvers distrust out-of-bailiwick additional data, responses that carry
  signatures are already large, and the resolver looks the target up once per TTL
  like any nameserver name.
- **Resolver side (2026-09-26).** Its harvest rules (equal, different, unknown)
  stand for records with TargetName `.`. For a record with a target:
  - it is applied only after a Secure verdict for the whole path (R1, R5), in
    place when the RRSIG rides along, or through the verifying lookup. Until then
    the record counts as absent, including for a server in the unknown state,
    whose first signal is otherwise applied unvalidated;
  - an unsigned owner zone's answer, applied there as today, is applied for
    records with TargetName `.` only;
  - an equal harvest renews as before, since it is equal to a copy that was
    validated when it was applied.
- **#994.** The port is stored with the signal and joined at dial time. With an
  alternative endpoint the address is the target's, so the counters follow the
  endpoint, and backoff and RTT are keyed as section 3 says, while the signal
  itself stays under the nameserver's name. Four of #994's rules change: `do53`
  never takes a port flips, because `udp` and `tcp` take a port and a TargetName;
  the DoH-alone exception is dropped; the last record read no longer wins when a
  transport appears twice, and section 2 replaces that rule; and `records:` gives
  way to `ports:`. The selection treats `udp` and `tcp` as two transports, where
  it now has one `Do53`, and the `auth-transports` view would show them
  separately.
- **The OOTS draft text.** `draft-johani-dnsop-transport-signaling-03` fixes the
  SVCB target at `.` and tells resolvers to ignore other parameters, and the
  companion SvcParam draft names a single `do53` token. tdns would be ahead of
  both here, as an experiment.

## 6. Not covered

- Authenticated connections (section 4).
- DoH on an alternative host needs a path; how the signal conveys it is not
  designed here.
- An unequal weighted split of one transport between differently named hosts, or
  different ports for different hosts of one transport. A transport is spread
  over several hosts by giving its target several addresses or by anycast;
  nothing has asked for more.
- Steps, where each rule lands in the code, and their status. That is a plan, and
  it is written beside this note by whoever implements it.
- Signer-authored signals for the whole NS set (2026-10-04, section 8).

## 7. Questions and their outcomes

| # | Question | Outcome |
|---|---|---|
| 1 | A cleartext entry in a record with a non-`.` TargetName | Decided in r2: ignored. Reversed in r3: `udp` and `tcp` take a TargetName and a `port` like any transport. The deprecated `do53` shorthand does not |
| 2 | An unvalidated record with a non-`.` TargetName | Decided: ignored in whole (R2) |
| 3 | Must every RRset on an alias path validate | Decided: yes (R5) |
| 4 | A transport named in two records | Decided: use one. The tie-break is proposed (section 2) |
| 5 | The target's A and AAAA in the Additional section | Decided: no (section 5) |
| 6 | Nameserver zone signed, target zone not | Decided: operator guidance (section 4) |
| 7 | The cleartext token | Decided: `udp` and `tcp` replace `do53`; both default to 100. `do53` survives as a receive-only shorthand (section 2) |
| 8 | One transport spread over several hosts | Decided: a name with many addresses, or anycast (section 2) |
| 9 | Which TCP goes to the `tcp` endpoint | Decided: TCP the resolver initiates; a truncation retry goes to the address and port that truncated (section 3) |

Proposed and not yet confirmed: the tie-break for one transport named twice and
the warning at load for it (section 2); dropping the DoH-alone exception
(section 2); the socket-clash rules and the warning for an unused port
(section 2); the `ports:` and `targets:` maps in place of `records:` (section 5);
the log and counter for an ignored redirect (section 4). To settle with the
plan: whether the start-up pass leaves an operator-authored ServiceMode record
alone (section 5).

## 8. Mixed versions

The `oots` value is read by tdns nodes that also re-pack it: a secondary after a
transfer, a signer, the zone loader, the injection into the Additional section,
a resolver answering from its cache. Today the codec drops a token it does not
know when it decodes, so such a node serves different bytes than it received.
The RRSIG over the original no longer matches, and the RRset goes Bogus. A
record that holds only new tokens, such as `oots="tcp:30"`, re-packs to an empty
value, which every decoder rejects, and a single such record makes the whole
message unreadable. The new tokens cannot be published until this is fixed.

Rules:

- **The codec keeps every entry.** It carries each entry through decode, parse
  and encode, whether it knows the token or not, and never encodes an empty
  value. Duplicates are still refused, weights are still clamped to 100, and an
  empty value is still refused on decode.
- **Ignoring is for using the signal, never for re-encoding.** The companion
  draft says an unrecognized identifier is skipped and the rest processed. That
  is read as "do not act on it", not as "drop it when the record is written
  out again".
- **The tokens selection acts on are fixed by what the resolver implements.**
  Until the token split is built they are `do53`, `dot`, `doh` and `doq`, on every
  path a signal can arrive by, including received strings and the private TSYNC
  record. A received `udp` or `tcp` weight does not make a resolver choose TCP.
- **A publisher emits a new token, a `port` or a TargetName only when every tdns
  node that can re-pack the record is lossless and every resolver ignores, rather
  than misapplies, a record it cannot honor.** The second part means a resolver
  skips a record with SvcPriority 0 or a non-`.` TargetName, and the ServiceMode
  records of an RRset that holds an AliasMode one, before any publisher writes
  one.
- **Other software is unaffected.** BIND, Knot and NSD hold key 12 as opaque
  data. A resolver that predates the new tokens skips them and applies the
  default of 100 for `do53`, so it degrades without failing.

## 9. Delta 2026-11-18: a redirect target is a server of its own

Added after the ruling on F25 in the CodeRabbit review of #1118 (Johan: a
target other than `.` "is most likely a completely different auth
nameserver"). Tracked in #1129, built with #1128. Sections 2 to 8 stand as
written; this section says how section 3's rules apply at a target.

- **One server per target name.** The resolver keeps one server state per
  canonical target name, created when the target's addresses are first found
  and kept across later lookups of them, so that its backoff and RTT carry
  on. It is dropped once its addresses have run out and nothing has used it
  for as long as a backoff or RTT sample can stay in force.
- **It is not a nameserver.** It holds only the addresses of the target
  lookup (A and AAAA, CNAMEs followed, nothing Bogus, each family until its
  own records and the CNAME links run out). Each family is in one of three
  states, apart from the other:
  - *answered*: its addresses are used until they run out, and then it is
    looked up again while the other family's addresses are used;
  - *denied*: it has no addresses, and it is looked up again only along with
    the other family;
  - *failed*: its query got no answer to go by. It keeps the addresses it
    holds, used while they are live, and it is looked up again after the
    usual retry interval, whether or not it holds any. Until then it is not
    queried, even when a lookup refreshes the other family.

  Only an answer replaces what a family holds. A denial counts as an answer,
  so it clears the family even when the other family's query fails. A
  lookup is claimed only while a family is due, checked when it is claimed,
  so a query that found the target due just before another lookup refreshed
  it starts none. A family that is due is looked up even when a later
  lookup of the other family was denied and left the target without a live
  address a moment ago. The
  target never takes glue, a same-named nameserver's addresses or a stub's,
  and it never carries a signal. The
  transport and port of an attempt still come from the redirecting
  nameserver's endpoint, so a redirect of a redirect cannot happen. It is not
  in the shared nameserver map or any zone's server list, so nothing that
  installs a signal by name reaches it.
- **Several nameservers, one target.** Nameservers redirected to the same
  target share its state: a failure or an RTT sample through one is seen
  through the others. That is the provider case, reached through AliasMode.
- **A nameserver of the same name keeps its own state.** Its signal, glue,
  backoff and RTT are not the target's, nor the target's its. The two share
  only what is keyed by address: the zone's lameness and the address-family
  tracker. The cost is at most one extra failed dial per role.
- **What is kept where.** Server backoff (timeouts, refused connections,
  handshake failures) and RTT: on the target, at address, port and
  transport. Zone lameness (REFUSED, NOTAUTH): in the zone, at the address
  and port dialed, as at the nameserver's own address. The answers a target
  carries are counted on the target; the nameserver counts how many of its
  answers its targets carried.
- **Waiting for a target.** Until a target's addresses are known its
  transport goes to the default endpoint (section 3). When that attempt has
  failed and nothing else is left, a query waits, within its signal-wait
  allowance, for a lookup of the target's addresses that is running, as it
  waits for a server's signal lookup. It waits also when the default
  endpoint failed without a backoff (a refused DS query): the target is an
  endpoint the query has not tried. That includes a lookup the query's own
  server selection has just started, before or during the wait. It waits
  only for targets that a transport the query may use is sent to, by a
  nameserver it may query: a strict query never waits for a udp endpoint's
  target, nor any query for a target reached only through a nameserver on
  this host that it may not query. When nameservers with no signal yet are
  waited for too, the two waits run side by side within the allowance, so
  neither spends the other's time. An extra pass does not dial an endpoint
  the pass before tried, even if a signal that changed since its selection
  sends a tuple there. A query held to the default endpoints, as a target's
  address lookup is, never waits for a target.
- **The address family of an attempt.** Selection holds back a tuple whose
  address family is suspect, letting one through now and then as a probe,
  by the address the attempt would dial: a target's, not the glue's. If that
  changes before the attempt, as when a udp endpoint at a target whose
  address has gone into backoff gives way to the nameserver's own address,
  or that family turns suspect in the meantime, an address of a suspect
  family is dialed only as the probe selection reserved for that family. An
  attempt refused this way sends nothing and does not count as tried, so an
  extra pass decides on the family afresh. A target's address of a suspect
  family is used only when the target has no other: selection then lets the
  tuple through as that family's recovery probe, as it does a nameserver's
  own address.
- **Status output** lists each target on a line of its own, marked as a
  target.
