# IMR: QNAME minimisation (RFC 9156)

**Date:** 2026-10-22
**Status:** accepted design, not implemented. Scoped against main at `51eb0988`.
**Revision:** 3.

| Rev | Date | Change |
|---|---|---|
| 1 | 2026-10-22 | First version. |
| 2 | 2026-10-22 | After review. The original type goes only to a server known to hold the name (§4). A probe name is looked up in the cache first (§4). The ancestor is the zone of the servers asked (§4). DNAME, a failed probe, the counter's scope and a per-request cap are settled (§4, §6). The walk moves out of the tuple loop in a commit of its own (§3). Config spelling and limits (§5). |
| 3 | 2026-10-22 | Off by default, permanently; an operator opts in (§2). The five Deckard scenarios that ask for minimisation set the option themselves, apart from the default (§11). |

RFC 9156 is the specification. It obsoletes RFC 7816. This design follows
9156 and does not keep the 7816 behaviour (NS as the hiding type, one
label at a time, no query cap).

## 1. What and why

A cold iterative lookup today sends the client's full QNAME and QTYPE to
every server from the root down. The root and the TLD only need enough of
the name to return a delegation, and the QTYPE is irrelevant to them.
Sending the rest is a tradition, not a requirement of RFC 1034 §5.3.3 or
RFC 1035 §7.2.

QNAME minimisation is a unilateral resolver change. Authoritative servers
need no new behaviour. Until a server is known to be authoritative for the
original name, the resolver asks it for one label past the longest cached
delegation, with a QTYPE the resolver chose. The original name and type go
out only on the last query, to a server known to hold the name.

Cold cache, client query `www.foo.example.com` A, hiding type A:

| Hop | Today | Minimised |
|---|---|---|
| root | `www.foo.example.com` A | `com` A |
| `.com` | `www.foo.example.com` A | `example.com` A |
| `example.com` | `www.foo.example.com` A | `foo.example.com` A, then the original query |

For any other type the full name goes out as `A` first. The servers of
`example.com` are known to hold `www.foo.example.com` only once they have
answered it without a referral. For MX the last row is `foo.example.com` A,
`www.foo.example.com` A, then `www.foo.example.com` MX.

The zone that holds the record still learns the full name. It has to.
Hiding the type from that zone lasts for the probe rounds before the final
query. A warm cache already skips the root and the TLD, with or without
minimisation; the privacy gain there is what the remaining servers see on
the probes.

## 2. Decisions

| Question | Decision |
|---|---|
| Default | Off, permanently. An operator opts in with `qname-minimisation` in `imrengine.options`. There is no plan to turn it on by default. Most users of this resolver gain little from it and pay in queries and in failed lookups (§9): applications that embed it to look up their own peers, and test setups that need a predictable query stream. Existing test doubles match the full name and the original type, and the 95 Deckard scenarios that pin `query-minimization: off` need no template change. |
| Hiding QTYPE | `A`, fixed. RFC 9156 allows any type whose authority lies below the zone cut, as long as it has no relation to the client's type. `A` and `AAAA` are the types it names as least likely to raise issues. Not a setting. |
| Original QTYPE | Sent only to a server known to hold the name: the ancestor is the name itself (for `DS`, its parent). Before that the full name goes out as `A` (RFC 9156 §3 step 3). This costs one extra query, on a cold lookup of a type other than `A` at a name that is not a zone cut. It costs nothing when the name is a cut. |
| Query cap | `tuning.qmin-max-iterations` default 10 (`MAX_MINIMISE_COUNT`). `tuning.qmin-one-label` default 4 (`MINIMISE_ONE_LAB`). Per walk: one name and type being resolved, across its referrals (§6). A second cap counts the probes of one client request (§6). |
| Probe cache | A cached answer, NODATA or NXDOMAIN for the probe name and type `A` skips that probe (RFC 9156 §3 step 5). A cached referral, glue or hint entry does not. |
| Underscore labels | Collapsed. A run of labels that start with `_` counts as one label in the plan (§4), so it goes out in one query once the name above it is exposed (`_25._tcp.mail.example.org`). |
| NXDOMAIN below a probe | Continue the walk. tdns does not implement RFC 8020, and RFC 9156 says a resolver without 8020 does not stop the original query on a probe NXDOMAIN. |
| Full-name retry | None. Some deployed resolvers resend the original QNAME after NXDOMAIN or a strange RCODE. That sends the name this feature exists to hide, and RFC 9156 does not ask for it. A probe that every server fails fails the lookup (§4). |
| Forward zones | Excluded. The upstream resolver sees the full query on the final hop anyway (RFC 9156 §2.4). Minimising toward it only multiplies queries. |
| Own zones | Excluded. Answered in process, as today (`answerFromOwnZone`). |
| Stub zones | Included. A stub still iterates below its cut (RD=0, referrals followed). The stub's servers are the ancestor; the first probe is one label below the stub zone. |
| Reload | None. The option lives in `imrengine.options` and the two integers live in `tuning`. `imrRestartRequiredKeys` already treats both as restart-required. |
| RFC 8020 | Not in this change. See §10. |

## 3. Where it sits

The insertion point is the query built inside
`IterativeDNSQueryWithLoopDetection` (`v2/dnslookup.go`), after the five
short-circuits that keep sending the original question:

1. the resolver's own DS or DNSKEY question at a CNAME being validated
   (`cnameDeniesType` and `validatingCNAME`, #717),
2. a cache hit,
3. a CNAME already cached for the name,
4. a zone this process serves,
5. a forward zone (`forwardZoneForQuestion`).

Every consumer of the iterative path comes through this function:
`ImrResponder`, `ImrQuery`, the CNAME chase, NS-address resolution, and the
validator's `RRsetFetcher`. They all minimise when the option is on. A
DNSKEY at a zone apex does not generate a probe: the ancestor is the apex,
so the first query is the DNSKEY itself.

The tuple loop handles a response inline, and every handler is keyed to the
name it sent. `handleAnswer` chases a CNAME (`answerViaCNAME`).
`handleReferral` recurses with the name it was given, and its loop key is
`qname:zone`. `extractReferral`, `classifyResponse` and `handleNegative`
take that name too. A probe needs the question it sent to judge the
response, and the client's question for what follows. A call site in front
of the loop cannot give it both.

So the change is two commits:

1. **Move the walk.** The tuple loop, with its server ordering, lameness
   rcodes, upward-referral check and second pass for glueless NS names,
   moves out of `IterativeDNSQueryWithLoopDetection` into a function that
   sends one question to one server map. It hands each usable response to
   a dispatch function, which says "done, with this result" or "try the
   next server". The original query's dispatch is today's inline handling,
   unchanged. This commit changes no behaviour. It moves on the order of
   200 lines, and the existing iterative tests, `make check-all` and the
   Deckard run must pass on it alone.
2. **Add the probe loop.** `v2/imr_qmin.go` holds the probe dispatch (§4),
   the label plan, the counters, and the decision of probe name and probe
   type against the current ancestor. It calls the function from commit 1
   with the probe question.

With the option off, the IMR sends exactly the questions it sends today.

A probe response is cached under the probe name and type and is not
returned to the client. The existing answer, referral, and negative paths
run only for the client's question.

No cache schema change. `show options` already prints the options map, so
there is no new CLI command.

## 4. The walk

`ANCESTOR` is the zone of the servers the walk was handed: `serversZone`,
as `zoneOfServers` finds it when the caller gave none. It is usually the
closest cached delegation for the original name (`FindClosestKnownZoneFor`,
which for `DS` is already the parent side), but not always. `ServersFor`
hands out the root's servers for a cached cut whose server map is empty, and
a stub hands over the stub's servers. Labels are counted from the zone whose
servers are asked.

`TARGET` is the original name, or for `DS` the parent of the original name.

The walk does not minimise, and sends the original query as today, when
`serversZone` is `""`, or when ANCESTOR is not TARGET or above it (a
caller that handed over a child's servers for a `DS`).

While ANCESTOR is not TARGET:

1. Add the next labels toward TARGET to get `CHILD`. A run of labels that
   start with `_` counts as one label. The first `qmin-one-label` rounds
   of the walk add one label. After that, each round adds the labels still
   hidden divided by the rounds left (`qmin-max-iterations` minus the
   rounds used), rounded down, at least one. The remainder lands on the
   last rounds. An 18-label name from the root with the defaults adds
   `1, 1, 1, 1, 2, 2, 2, 2, 3, 3`.
2. If the cache holds an answer, a NODATA or an NXDOMAIN for CHILD and type
   `A`, or a CNAME link owned by CHILD, skip the query and treat the entry
   as the response (RFC 9156 §3 step 5). A referral, glue or hint entry
   does not count.
3. Otherwise query CHILD, type `A`, at ANCESTOR's servers.
4. Dispatch the response:

| Response | Action |
|---|---|
| Referral below ANCESTOR | Cache the NS RRset, the glue and the DS, and set the child's DNSSEC state, as the referral path does today. ANCESTOR becomes the referred zone. The walk continues from there with the same counter. |
| Answer or NODATA for CHILD and `A` | Cache it under CHILD and `A`, validated as the existing answer and negative paths do. |
| CNAME owned by CHILD | Cache the link, validated. Do not chase it (`answerViaCNAME` would). Keep building the original name. |
| DNAME above CHILD | Cache the DNAME, validated. Synthesise the target from the **original** name, not from CHILD (RFC 9156 §3 step 6b, RFC 6672 §2.2). Cache that link for the original name (`SynthesizedFrom` the DNAME) and chase it as `answerViaCNAME` does. New code: today's DNAME handling (`cacheCNAMELink`) synthesises only for the name that was asked. |
| NXDOMAIN | Cache it for CHILD and type `A`. Continue the walk. Do not fail the client's query. |
| Timeout, another RCODE, or a referral that does not lead below ANCESTOR | Try the next server of ANCESTOR, as the walk does today. A probe's error does not book lameness; the original query to the same servers still does. When every server has failed, the lookup fails as an unanswered lookup does today. No full-name retry (§2). |

After an answer, a NODATA, a CNAME or an NXDOMAIN, from the wire or the
cache: if CHILD is TARGET, the probing ends here; otherwise go to step 1.
After a referral, go to step 1 from the new ancestor. A DNAME and a failed
probe end the walk, as their rows say.

A referral is not followed under the probe name. Batching can put several
labels on one probe. Following that name into the child would show the
child labels the plan had not yet meant to reveal. The walk computes the
next CHILD from the new ancestor instead.

When the probing ends, or ANCESTOR is TARGET from the start, the original
query goes to ANCESTOR's servers: the original name and type, or for `DS`
the DS to the parent. From there the existing answer, referral, negative,
and lame-server paths apply, including DNSSEC validation, transport policy,
and the PRIVACY level. When the original type is `A` and TARGET is the
original name, the probe of TARGET is that query: it is sent once, and its
response takes the existing paths.

The plan reaches TARGET by round `qmin-max-iterations` at the latest. If a
referral leaves labels hidden with no rounds left, the next query is the
original query at the new ancestor. The cap exposes the remaining labels.
It does not fail the lookup.

## 5. Config

```yaml
imrengine:
  options:
    - qname-minimisation          # absent means off
  tuning:
    qmin-max-iterations: 10       # MAX_MINIMISE_COUNT
    qmin-one-label: 4             # MINIMISE_ONE_LAB
```

Spelling is the RFC's. Deckard's `query-minimization` is Knot Resolver's
key and is not accepted here. One spelling.

The option takes no value, like `revalidate-ns`. Absent means off. There
is no explicit-off form: in a YAML list, `- qname-minimisation: off` is a
mapping, not a string, and does not decode into `options`.

Both keys are read at startup. Changing either is reported by
`imrRestartRequiredKeys` and needs a restart, like every other behavioural
knob in the block. `imrTuningEqual` learns the two new fields so a reload
can see them.

The sample (`cmdv2/imr/tdns-imr.sample.yaml`) and
`guide/config-tdns-imr.md` document the option and the two tuning keys
when this is implemented. `cmd/` is out of scope.

Both tuning fields are pointers, as `nsec3-max-iterations` is: an absent
key gets the RFC's number, and an explicit `0` is a value. Valid values
are `qmin-max-iterations` at least 1, and `qmin-one-label` at least 0 and
less than `qmin-max-iterations`. Anything else is a config error at
startup. So the plan always has a round left to spread the hidden labels
over.

## 6. Query cap

**Per walk.** The round counter belongs to one walk: the lookup of one
name and type. It travels on the context, keyed by that name and type. The
referral path's recursion for the same name and type finds its own key and
continues the count. The labels still hidden below the new ancestor are
spread over the rounds left (§4 step 1); a referral does not restart the
plan at one label per round. A name across many cuts, such as one under
`ip6.arpa`, sends at most `qmin-max-iterations` probes in all.

Any other lookup started inside a walk finds a different key and starts
its own walk and counter:

- an out-of-bailiwick NS address,
- a CNAME or DNAME target,
- a DNSKEY or DS the validator fetches,
- a transport-signal lookup.

Sharing a single cap of 10 across those would let one deep glue name
expose the rest of the client's name early.

**Per request.** RFC 9156 §2.3 requires a limit on the outgoing queries per
user request, and walks multiply: each link of a CNAME chain and each
glueless NS name is a walk of its own. The outermost lookup puts a second
counter on the context, and every walk under it shares that counter. It
counts probes sent. Once it reaches 3 × `qmin-max-iterations` (30 with the
defaults), no walk in that request sends another probe: a walk in progress
sends its original query at its current ancestor, and every later walk
sends its original query without probing, as the IMR does today. Not a
setting.

The existing per-query wall clock (`tuning.query-budget`, default 8s)
still bounds the whole request in time, including validation of probe
NODATA and any transport-signal lookups the existing options already
trigger.

Neither cap counts original queries, validator fetches, NS address
lookups, or transport-signal queries. Those are unchanged, and they are
what can still multiply under the 8s budget on a cold signed name.

## 7. Tests

`v2/imr_qmin_test.go`, against local doubles in the style of
`imr_lame_referral_test.go`. The doubles record the question they were
asked.

Label plan, no network:

- 18 labels, defaults → `1, 1, 1, 1, 2, 2, 2, 2, 3, 3`.
- A name of 4 labels or fewer adds one label per round.
- `_25._tcp.mail.example.org`, once `mail.example.org` is known, goes out
  as one query.
- `sel._domainkey.example.com` from `example.com`: `_domainkey.example.com`,
  then `sel._domainkey.example.com`.
- After a referral, the hidden labels are spread over the rounds left.
- `qmin-max-iterations: 0`, a negative value, and `qmin-one-label` equal
  to `qmin-max-iterations` are rejected. Absent keys give 10 and 4.

Walk, option on:

- Cold lookup of `www.foo.example.com` MX. The root sees `com` A. `.com`
  sees `example.com` A. `example.com` sees `foo.example.com` A,
  `www.foo.example.com` A, and then the MX. The client receives the MX.
- Cold `example.com` MX with `com` cached. `.com` sees `example.com` A and
  never MX. The MX goes to `example.com`'s servers.
- The original type is `A`. The extra final query is skipped.
- A referral in the middle of a batched probe. The child server does not
  see the labels that belonged to later rounds.
- NODATA at an empty non-terminal. The walk continues and the client
  receives the original answer. The NODATA is cached for the probe name
  and type `A`.
- A second lookup below the same empty non-terminal sends no probe for it.
  A cached glue `A` for the name does not stop the probe.
- An intermediate CNAME is cached and not chased. The original name is
  still resolved.
- A DNAME above a probe name. The target is synthesised from the original
  name, and the client receives the original type at that target.
- A wildcard answer to a probe is not the client's answer.
- NXDOMAIN for an intermediate probe does not fail the client query.
  NXDOMAIN for the final name does.
- Every server fails a probe. The lookup fails, no full-name query is
  sent, and no lameness is booked for the probe.
- `DS` is sent only to the parent.
- A 100-label name under a wildcard stops at 10 rounds and then sends the
  original name.
- A name across several cuts sends at most 10 probes in all.
- Servers handed over by a fallback (the root's servers for a cached cut
  with no server map): labels are counted from the root.
- No `serversZone` can be found: no probe is sent.
- A glueless NS name gets its own walk. After 30 probes in one request,
  later walks send their original query without probing.
- Option off: one upstream query, the full name and the original type.
- A name in a forward zone, and a name in a zone this process serves, are
  sent in full.

Option off is the default, so the existing iterative tests keep the query
stream they have. They are also what holds the walk's move (§3) to no
change in behaviour.

## 8. Size

Estimates for the implementation diff. Nothing is deleted.

| File | Added | Changed | What |
|---|---:|---:|---|
| `v2/imr_qmin.go` | 420 | 0 | Label plan, underscore collapse, both counters, probe cache check, probe dispatch, DNAME from the original name |
| `v2/dnslookup.go` | 80 | 60 | Commit 1: the walk moves out of the tuple loop (about 200 lines moved, not counted). Commit 2: the probe loop's call |
| `v2/enums.go`, `v2/parseoptions.go`, `v2/config.go`, `v2/imr_reload.go` | 60 | 15 | The option, two tuning pointers, defaults and limits, tuning equality |
| `v2/imr_qmin_test.go` | 750 | 0 | §7 |
| `cmdv2/imr/tdns-imr.sample.yaml`, `guide/config-tdns-imr.md` | 40 | 10 | The option and the two tuning keys |
| **Production** | **560** | **75** | Tests, docs and the moved lines sit outside this row |

## 9. Risks

**A probe is returned to the client.** A NODATA, a wildcard `A`, or a
CNAME at an intermediate name must be cached under the probe and must not
complete the lookup. The dispatch in §4 treats a response as final only
for the client's question. This is the failure that ships a wrong answer,
and §7 exists to pin it.

**The walk's move.** Commit 1 changes the code every IMR consumer runs,
option on or off. It is its own commit with no change in behaviour, held
to the existing iterative tests, `make check-all` and the Deckard run.

**A batched probe leaks labels to a child.** The walk recomputes CHILD
from the new cut instead of following the referral under the probe name.
The test records the questions the child server sees.

**The original type reaches a parent.** It goes out only once ANCESTOR is
TARGET or ANCESTOR's servers answered TARGET without a referral (§4). The
two MX tests in §7 pin it.

**DS goes to the child.** The walk stops at the parent of the DS owner,
on top of `FindClosestKnownZoneFor`. The §7 DS test is the regression
check for #150.

**A broken empty non-terminal.** A parent that returns NXDOMAIN for a name
that exists as an empty non-terminal is wrong, and minimisation is what
provokes the query. The walk continues, so the client's query can still
succeed. The NXDOMAIN is cached for that name and type `A`, and a later
query for exactly that name and type will hit it. Accepted. The full-name
retry that would paper over it is declined in §2.

**Failed probes.** A zone whose servers all fail a type-`A` query at a
name above the client's name now fails the client's lookup, where today
it succeeds. RFC 9156 §5 cites up to 5% more failed lookups with
minimisation. There is no fallback, by §2. An operator who opts in accepts
that. It is one reason the default stays off (§2).

**The 8s budget.** Ten probe rounds plus a final query is the added
upstream work per name, and the per-request cap bounds the sum. Validating
a signed NODATA, and a transport-signal lookup where those options are on,
are extra and already part of ordinary resolution. `ip6.arpa` is the deep
name the cap is there for. A cold signed name can still spend the budget
on validation rather than on probes.

**Existing tests.** Low, since the default is off. Doubles that answer
only the full name and the original type (denial, DS parent, glue,
forward) keep seeing today's questions.

## 10. Left out

**RFC 8020.** Applying a cached NXDOMAIN to every name below it, and to
every type, is a change to every negative cache hit. RFC 9156 treats it as
optional: a resolver that lacks it continues the walk. The "one NXDOMAIN
at the root answers every name below it" saving in RFC 9156 §5 needs 8020,
so that saving is not a result of this design.

**Minimising queries to a forwarder.** Declined in §2.

**A configurable hiding type.** A setting that could track the client's
type would undo the hiding. `NS` is legal under RFC 9156 and has no value
over `A`: the parent returns a referral for any type, and some servers
refuse `NS`.

**Default on.** Declined in §2.

## 11. Follow-up

1. Implement §3–§7 on this design, as the two commits of §3. Update the
   sample and the guide in the same change.
2. Run the new tests, then `make check-all` from `tdns/`.
3. When those are green, wire the five Deckard scenarios that set
   `query-minimization: on`. They are skipped today because tdns-imr has
   no minimisation (`docs/2026-09-28-imr-deckard-test-clock-and-switches.md`
   §7). The template turns that scenario key into `qname-minimisation` in
   the scenario's own `imrengine.options`. The other 95 keep the default.
   A scenario that passes comes off the skip list. The default does not
   change.
