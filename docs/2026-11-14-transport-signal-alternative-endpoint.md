# The transport signal's alternative endpoint: a ServiceMode TargetName

**Date:** 2026-11-14. **Status:** proposal, r3.1, not implemented. Points marked
**Decided** were settled on 2026-11-14; everything else is proposed.

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

Here DoT and DoQ go to their own hosts on their own ports, discretionary TCP
(at most 30%) goes to `tcp-foo.example` on port 53, DoH stays on `foo.example`,
and UDP is not mentioned, so it stays on `foo.example` at weight 100.

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
  TargetName and `port` apply to every transport the record names, with one
  exception inherited from #994: `port` applies to `doh` only when `doh` is the
  only transport the record names. Writing one transport per record is the clear
  way to give transports different endpoints.
- **Cleartext is not special. Decided.** `udp` and `tcp` take a TargetName and a
  `port` like any other transport. The delegation guarantees only that the
  nameserver's own name answers on port 53, and that stays true whatever the
  signal says.
- **One endpoint per transport. Decided.** A transport named in two records with
  different endpoints is a misconfiguration. The resolver uses one of the two and
  never neither: ignoring both would take a working setup down. The rule for
  choosing is proposed: the lowest SvcPriority, then the lowest RDATA in DNSSEC
  canonical order (RFC 4034 section 6.3), so that the outcome does not depend on
  the order an RRset happens to arrive in. The other record is inert. It is not a
  standby. A warning when such an RRset is loaded would help the operator
  (proposed).
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
- **Delegating the whole signal is AliasMode, and only that.** `_dns.<ns>` holds
  one AliasMode record whose TargetName, written with its `_dns.` label (RFC 9460
  section 3 queries it as written), leads to an RRset that may itself hold
  ServiceMode records with targets. That composition needs no extra rule beyond
  the alias depth cap of the 2026-10-04 design and R5 below. It is how a provider
  publishes one multi-host signal for many customer names.

**With the weights and endpoints. Decided** (the model as confirmed):

- **The weight caps discretionary use.** A `udp` or `tcp` weight limits the share
  of queries the resolver chooses to send over that transport, so "only 30% TCP"
  is `tcp:30`. Truncation retries and any other protocol-required TCP are never
  gated by it. Neither `udp:0` nor `tcp:0` is a hard gate: cleartext on port 53 is
  mandatory, so it stays the last resort.
- **A signalled endpoint receives that share.** With no signalled endpoint for a
  transport, the resolver uses the nameserver's name at the transport's default
  port.
- **A truncation retry goes to the address that truncated.** If UDP went to
  `serverZ` and `serverZ` truncates, the TCP retry goes to `serverZ`.
- **A failing endpoint falls back.** An address that fails is backed off on, and
  the target's other addresses are tried. When none works, the resolver falls
  back to the nameserver's name on port 53 (proposed).
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
  alias. Records synthesized from configuration (#994's `records:`) would gain
  an optional `target:` beside `signal` and `port` (proposed).
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
- **#994.** The port is stored with the signal and joined at dial time, and
  backoff and RTT are keyed by the bare address. With an alternative endpoint
  the address is the target's, so backoff, RTT and the per-transport counters
  follow the endpoint and the alternative host is measured on its own, while the
  signal itself stays under the nameserver's name. #994's rule that `do53` never
  takes a port flips: `udp` and `tcp` take a port and a TargetName. #994 keeps
  the last record read when a transport appears twice; section 2 replaces that
  rule. The selection treats `udp` and `tcp` as two transports, where it now has
  one `Do53`, and the `auth-transports` view would show them separately.
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
- A plan: steps, where each rule lands in the code, mixed versions, tests. It is
  written when implementation is assigned.
- Signer-authored signals for the whole NS set (2026-10-04, section 8).

## 7. Questions and their outcomes

| # | Question | Outcome |
|---|---|---|
| 1 | A cleartext entry in a record with a non-`.` TargetName | Decided in r2: ignored. Reversed in r3: `udp` and `tcp` take a TargetName and a `port` like any transport. The deprecated `do53` shorthand, if kept, does not |
| 2 | An unvalidated record with a non-`.` TargetName | Decided: ignored in whole (R2) |
| 3 | Must every RRset on an alias path validate | Decided: yes (R5) |
| 4 | A transport named in two records | Decided: use one. The tie-break is proposed (section 2) |
| 5 | The target's A and AAAA in the Additional section | Decided: no (section 5) |
| 6 | Nameserver zone signed, target zone not | Decided: operator guidance (section 4) |
| 7 | The cleartext token | Decided: `udp` and `tcp` replace `do53`; both default to 100. `do53` survives as a receive-only shorthand (section 2) |
| 8 | One transport spread over several hosts | Decided: a name with many addresses, or anycast (section 2) |

Proposed and not yet confirmed: the tie-break for one transport named twice,
and a warning at load for it (section 2); the fallback to the nameserver's name
on port 53 (section 3); the optional `target:` configuration key (section 5); the
log and counter for an ignored redirect (section 4). To settle with the plan:
whether the start-up pass leaves an operator-authored ServiceMode record alone
(section 5).
