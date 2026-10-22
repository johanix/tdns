# IMR: QNAME minimisation (RFC 9156)

**Date:** 2026-10-22
**Status:** accepted design, not implemented. Scoped against main at `51eb0988`.

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
out only on the last query.

Cold cache, client query `www.foo.example.com` A, hiding type A:

| Hop | Today | Minimised |
|---|---|---|
| root | `www.foo.example.com` A | `com` A |
| `.com` | `www.foo.example.com` A | `example.com` A |
| `example.com` | `www.foo.example.com` A | `foo.example.com` A, then the original query |

The zone that holds the record still learns the full name. It has to.
Hiding the type from that zone lasts for the probe rounds before the final
query. A warm cache already skips the root and the TLD, with or without
minimisation; the privacy gain there is what the remaining servers see on
the probes.

## 2. Decisions

| Question | Decision |
|---|---|
| Default | Off. `qname-minimisation` is absent from `imrengine.options`. Existing test doubles match the full name and the original type, and the 95 Deckard scenarios that pin `query-minimization: off` need no template change. Default on is a follow-up (§11). |
| Hiding QTYPE | `A`, fixed. RFC 9156 allows any type whose authority lies below the zone cut, and forbids a relationship between the client's type and the probe type. `A` is the type it names as least likely to be refused. Not a setting. |
| Query cap | `tuning.qmin-max-iterations` default 10 (`MAX_MINIMISE_COUNT`). `tuning.qmin-one-label` default 4 (`MINIMISE_ONE_LAB`). Per name being resolved, not per client request. |
| Underscore labels | Collapsed. Once a normal label is exposed, a run of labels that start with `_` goes out in one query (`_25._tcp.mail.example.org`). |
| NXDOMAIN below a probe | Continue the walk. tdns does not implement RFC 8020, and RFC 9156 says a resolver without 8020 does not stop the original query on a probe NXDOMAIN. |
| Full-name retry | None. Some deployed resolvers resend the original QNAME after NXDOMAIN or a strange RCODE. That sends the name this feature exists to hide, and RFC 9156 does not ask for it. |
| Forward zones | Excluded. The upstream resolver sees the full query on the final hop anyway (RFC 9156 §2.4). Minimising toward it only multiplies queries. |
| Own zones | Excluded. Answered in process, as today (`answerFromOwnZone`). |
| Stub zones | Included. A stub still iterates below its cut (RD=0, referrals followed). The stub's servers are the ancestor; the first probe is one label below the stub zone. |
| Reload | None. The option lives in `imrengine.options` and the two integers live in `tuning`. `imrRestartRequiredKeys` already treats both as restart-required. |
| RFC 8020 | Not in this change. See §10. |

## 3. Where it sits

The insertion point is the query built inside
`IterativeDNSQueryWithLoopDetection` (`v2/dnslookup.go`), after the four
short-circuits that keep sending the original question:

1. a cache hit,
2. a CNAME already cached for the name,
3. a zone this process serves,
4. a forward zone (`forwardZoneForQuestion`).

Every consumer of the iterative path comes through this function:
`ImrResponder`, `ImrQuery`, the CNAME chase, NS-address resolution, and the
validator's `RRsetFetcher`. They all minimise when the option is on. A
DNSKEY at a zone apex does not generate a probe: the ancestor is the apex,
so the first query is the DNSKEY itself.

`FindClosestKnownZoneFor` (`v2/cache/rrset_cache.go`) already returns the
parent zone for `DS`. That is the ancestor RFC 9156 step 1a asks for. The
walk stops one label short of the DS owner and sends the real DS query.
This is the parent-side case that #150 fixed; the new tests cover it again.

New code is `v2/imr_qmin.go`:

- the label plan (how many labels each round adds, underscore collapse),
- the per-name iteration counter,
- the decision of probe name and probe type against the current ancestor,
- the dispatch of a probe response.

The server walk in `dnslookup.go` stays. It builds whatever question the
probe plan names. A probe response is cached under the probe name and type
and is not returned to the client. The existing answer, referral, and
negative paths run only when the question just sent was the client's name
and the client's type.

No cache schema change. `show options` already prints the options map, so
there is no new CLI command.

If the probe loop cannot sit in front of the server walk, the fallback is
to extract "ask this server map once" out of the tuple loop. That moves on
the order of 200 lines inside `dnslookup.go`. The net size stays in the
same range; the diff gets noisier. Prefer the thin call site.

## 4. The walk

`ANCESTOR` is the closest cached delegation for the original name, from
`FindClosestKnownZoneFor`. For `DS` that is already the parent.

While the name about to be queried is shorter than the original name
(or, for `DS`, shorter than the parent of the original name):

1. Add the next labels from the original name. The first
   `qmin-one-label` rounds add one label. The labels still hidden are
   then spread over the remaining rounds
   (`qmin-max-iterations - qmin-one-label`), remainder on the last
   rounds. An 18-label name with the defaults adds
   `1, 1, 1, 1, 2, 2, 2, 2, 3, 3`.
2. Query that name, type `A`, at `ANCESTOR`'s servers.
3. Dispatch the response:

| Response | Action |
|---|---|
| Referral | The existing referral path. The recursive call keeps the original name and type and minimises again from the new cut. |
| NODATA, or an address answer for the probe name | Cache it under the probe name and type `A`. Ask the same servers for the next probe. |
| CNAME at an intermediate name | Cache the link. Do not chase it (`answerViaCNAME` would). Keep building the original name. |
| DNAME | The existing DNAME handling (`imr_cname_chain.go`) restarts resolution at the synthesised target. |
| NXDOMAIN | Cache it for that name and type `A`. Continue the walk. Do not fail the client's query. |
| Timeout or another RCODE | The existing server walk retries another server for the same ancestor. |

A referral is not followed under the probe name. Batching can put several
labels on one probe. Following that name into the child would show the
child labels the plan had not yet meant to reveal.

When the probe name is the client's name, send the original type, unless
the original type is already `A`, in which case the probe is the final
query. From there the existing answer, referral, negative, and lame-server
paths apply, including DNSSEC validation, transport policy, and the
PRIVACY level.

The same rule covers the end of the cap. After `qmin-max-iterations`
rounds the next query is the original name and type at the current
ancestor. The cap exposes the remaining labels. It does not fail the
lookup.

## 5. Config

```yaml
imrengine:
  options:
    - qname-minimisation          # absent means off; "qname-minimisation: off" is explicit off
  tuning:
    qmin-max-iterations: 10       # MAX_MINIMISE_COUNT
    qmin-one-label: 4             # MINIMISE_ONE_LAB
```

Spelling is the RFC's. Deckard's `query-minimization` is Knot Resolver's
key and is not accepted here. One spelling.

Both keys are read at startup. Changing either is reported by
`imrRestartRequiredKeys` and needs a restart, like every other behavioural
knob in the block. `imrTuningEqual` learns the two new fields so a reload
can see them.

The sample (`cmdv2/imr/tdns-imr.sample.yaml`) and
`guide/config-tdns-imr.md` document the option and the two tuning keys
when this is implemented. `cmd/` is out of scope.

A value of `qmin-max-iterations` below 1, or a `qmin-one-label` greater
than `qmin-max-iterations`, is a config error at startup. The RFC's
recommended numbers are the defaults filled in when the keys are absent.

## 6. Query cap

The counter travels on the context of one name's minimisation walk.
A nested lookup creates its own walk and its own counter:

- an out-of-bailiwick NS address,
- a CNAME target,
- a DNSKEY or DS the validator fetches.

Sharing a single cap of 10 across those would let one deep glue name
expose the rest of the client's name early. Each walk is capped at 10
probe rounds plus its own final query. The existing per-query wall clock
(`tuning.query-budget`, default 8s) stays the bound on the whole client
request, including validation of probe NODATA and any transport-signal
lookups the existing options already trigger.

The cap counts minimisation rounds. It does not count validator fetches,
NS address lookups, or transport-signal queries. Those are unchanged, and
they are what can still multiply under the 8s budget on a cold signed
name.

## 7. Tests

`v2/imr_qmin_test.go`, against local doubles in the style of
`imr_lame_referral_test.go`. The doubles record the question they were
asked.

Label plan, no network:

- 18 labels, defaults → `1, 1, 1, 1, 2, 2, 2, 2, 3, 3`.
- A name of 4 labels or fewer adds one label per round.
- `_25._tcp.mail.example.org`, once `mail.example.org` is known, goes out
  as one query.
- Cap and one-label rejected when the numbers are impossible.

Walk, option on:

- Cold lookup of `www.foo.example.com` MX. The root sees `com` A. `.com`
  sees `example.com` A. `example.com` sees `foo.example.com` A and then
  the MX. The client receives the MX.
- The original type is `A`. The extra final query is skipped.
- A referral in the middle of a batched probe. The child server does not
  see the labels that belonged to later rounds.
- NODATA at an empty non-terminal. The walk continues and the client
  receives the original answer. The NODATA is cached for the probe name
  and type `A`.
- An intermediate CNAME is cached and not chased. The original name is
  still resolved.
- A wildcard answer to a probe is not the client's answer.
- NXDOMAIN for an intermediate probe does not fail the client query.
  NXDOMAIN for the final name does.
- `DS` is sent only to the parent.
- A 100-label name under a wildcard stops at 10 rounds and then sends the
  original name.
- Option off: one upstream query, the full name and the original type.
- A name in a forward zone, and a name in a zone this process serves, are
  sent in full.

Option off is the default, so the existing iterative tests keep the query
stream they have.

## 8. Size

Estimates for the implementation diff. Nothing is deleted.

| File | Added | Changed | What |
|---|---:|---:|---|
| `v2/imr_qmin.go` | 340 | 0 | Label plan, underscore collapse, per-name counter, probe dispatch |
| `v2/dnslookup.go` | 50 | 40 | Build the probe query; a probe is not the client's answer |
| `v2/enums.go`, `v2/parseoptions.go`, `v2/config.go`, `v2/imr_reload.go` | 55 | 15 | The option, two tuning fields, defaults, tuning equality |
| `v2/imr_qmin_test.go` | 550 | 0 | §7 |
| `cmdv2/imr/tdns-imr.sample.yaml`, `guide/config-tdns-imr.md` | 40 | 10 | The option and the two tuning keys |
| **Production** | **445** | **55** | Tests and docs sit outside this row |

The 200-line extraction in §3 is the ceiling on `dnslookup.go` if the thin
call site does not fit. It is not the plan.

## 9. Risks

**A probe is returned to the client.** A NODATA, a wildcard `A`, or a
CNAME at an intermediate name must be cached under the probe and must not
complete the lookup. The dispatch in §4 treats a response as final only
when the name and the type are the client's. This is the failure that
ships a wrong answer, and §7 exists to pin it.

**A batched probe leaks labels to a child.** The referral recursion keeps
the original name and minimises again from the new cut. The test records
the questions the child server sees.

**DS goes to the child.** The walk stops one label short, on top of
`FindClosestKnownZoneFor`. The §7 DS test is the regression check for #150.

**A broken empty non-terminal.** A parent that returns NXDOMAIN for a name
that exists as an empty non-terminal is wrong, and minimisation is what
provokes the query. The walk continues, so the client's query can still
succeed. The NXDOMAIN is cached for that name and type `A`, and a later
query for exactly that name and type will hit it. Accepted. The full-name
retry that would paper over it is declined in §2.

**The 8s budget.** Ten probe rounds plus a final query is the added
upstream work per name. Validating a signed NODATA, and a transport-signal
lookup where those options are on, are extra and already part of ordinary
resolution. `ip6.arpa` is the deep name the cap is there for. A cold
signed name can still spend the budget on validation rather than on
probes.

**Existing tests.** Low, while the default is off. Doubles that answer
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

**Default on, and the Deckard skip list.** Five Deckard scenarios set
`query-minimization: on` and are skipped because tdns-imr has no
minimisation (`docs/2026-09-28-imr-deckard-test-clock-and-switches.md`
§7). They come off that list when the template maps Knot's key onto
`qname-minimisation` and the scenarios pass. That is the same change as
flipping the default, and it waits until §7 is green.

## 11. Follow-up

1. Implement §3–§7 on this design. Update the sample and the guide in the
   same change.
2. Run the new tests, then `make check-all` from `tdns/`.
3. When those are green, decide default on. Wiring the five Deckard
   scenarios is part of that decision, not part of the first implementation.
