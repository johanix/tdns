# tdns-imr: DS and DNSKEY questions at a CNAME owner

**Written 2026-10-01.** Refs #875, #717. Line references are to main at
`995c15c6`, before this change. The design was written against main at
`9d9d34b3` with #870–#874 applied; #872 and #874, which change
`handleAnswer`, are not merged yet.

**Status:** implemented in PR #879 (branch `fix/imr-ds-dnskey-at-cname`),
with the changes in §13.

**Revisions:**
- **r1**, 2026-10-01: the proposal, approved the same day with the decisions
  in §12.
- **Amended 2026-10-01** (§13): how the implementation differs, Johan's
  decision on the API's `imr query`, and the live checks.

## Summary

- **Today.** `followsCNAME` (`v2/imr_cname_chain.go:44`) is false for DS and
  DNSKEY (#717), and nothing takes its place. `handleAnswer`
  (`v2/dnslookup.go:2872`) finds no record of the type owned by qname, logs
  `Got a CNAME RR when looking for …` and returns `ContextFailure` with
  `done=false`. The walk tries the next server, then every other one, and gives
  up with an error. Nothing is cached, so the next question repeats it all. A
  client gets SERVFAIL for `www.sidn.nl DS`, `www.sidn.nl DNSKEY` and
  `www.internetstiftelsen.se DS`.
- **Proposal.**
  1. Who asks decides. A DNS client's DS or DNSKEY question follows the CNAME
     like any other type, and is answered with the chain, as #717 answers A
     (§3). The resolver's own DS and DNSKEY questions still do not follow (§4).
  2. For the resolver's own question, a CNAME at the name is the answer: the
     name holds no DS and no DNSKEY. The link is validated and cached as #717
     caches any link. The question returns a NODATA at once, and later ones
     are answered from the cached link without a query (§4, §6).
  3. The validator reads that link where it reads the DS. A Secure CNAME at a
     name on the way down means "no zone cut here". Any other verdict proves
     nothing (§4.2).
  4. Inside a link's validation, the resolver never asks its own DS or DNSKEY
     question at that link's owner. A context mark does this, as `dsProofKey`
     and `cnameChainKey` do elsewhere. This mark, not `followsCNAME`, keeps the
     #717 recursion out (§5).
- **Size.** About 180 lines of code in five files, about 450 lines of tests
  (§11).

## 1. Who asks

`ImrResponder` (`v2/imrengine.go:1091`) marks its context as a client's
(`withClientQuery`, `v2/imr_traffic_class.go`). The mark stays on everything
that answers the client's question:

- the walk (`IterativeDNSQueryInZone`, `imrengine.go:1290`, `1331`);
- referral continuations (`dnslookup.go:1810`, `3294`);
- the chase (`chaseCNAME`, `dnslookup.go:4002`);
- the forward and own-zone paths, which call `handleAnswer` with the same
  context.

Every lookup the resolver makes for itself inside a client query marks its
context again, with `withOwnTraffic`. A context with no mark is not a client's.

The mark was made for the transport statistics (#857). This design adds one
more use for it, through a helper `isClientQuery(ctx)`. A second mark would
have to be set and cleared in exactly the same places.

Every place that asks DS or DNSKEY for itself, and what it gets when the name
owns a CNAME:

| Caller | Question | The name owns a CNAME when | Gets |
|---|---|---|---|
| `delegationEvidence` (`cache/unsigned_rrset.go:301`), from `belowSecureZone` (unsigned RRsets and unsigned denials) and `ReferralChildState` (`cache/delegation_proof.go`) | DS at each name from the closest Secure zone down to the owner | the CNAME being validated is unsigned (the #717 case); a CNAME owner above the data (legal, rare) | §4.2 |
| `backfillDS` (`cache/rrset_validate.go:1041`), from `ValidateDNSKEYs` and `recheckInsecureZone` | DS at a zone apex | never in valid data | no DS: what an unanswered question gives today |
| `validateRRsetWithRRSIG` (`cache/rrset_validate.go:191`) | DNSKEY at the RRSIG's signer | never in valid data; a CNAME whose RRSIG names its own owner as signer leads here | no DNSKEY: Indeterminate, as for a failed fetch |
| trust-anchor setup (`imrengine.go:2415`) | DNSKEY at an anchor | a configuration error | no DNSKEY: the error it reports today |
| `ImrQuery` (`imrengine.go:676`): the API's `imr query`, a child's DNSKEY (`delegation_coherence.go:460`), the scanner and the DSYNC code | any type | a child or a target that is a CNAME | a NODATA (`Denial` = `ContextNoErrNoAns`), no RRset, `ValidationState` = the link's verdict (§4.3) |
| `DefaultDNSKEYFetcher` (`dnslookup.go:4033`) | DNSKEY | — | no caller in v2; as the row above |

All of them go through the fetchers (`IterativeDNSQueryFetcher`,
`DefaultDNSKEYFetcher`, `DefaultRRsetFetcher`) or through `imrQuery`, and each
of these marks its context as own traffic. `handleReferral` asks no DS question
itself. It reads the DS from the referral's authority section, and leaves the
rest to `ReferralChildState`.

## 2. The rule

```go
// followsCNAME: as now, except that a DS or DNSKEY question follows when
// it is a client's (isClientQuery).
func followsCNAME(ctx context.Context, qtype uint16) bool

// cnameDeniesType: a DS or DNSKEY question the resolver asks for itself. A
// CNAME at the query name says the name holds neither: a CNAME owner is
// neither a delegation nor a zone apex (RFC 2181 §10.1).
func cnameDeniesType(ctx context.Context, qtype uint16) bool
```

`followsCNAME` gets the context. Its four callers (`dnslookup.go:1552`,
`2887`; `imrengine.go:1147`, `1380`) already have one. CNAME, RRSIG and NSEC
questions do not change.

## 3. A client's DS or DNSKEY question

Nothing new: once `followsCNAME` is true, the #717 code runs as it does for A.

- `handleAnswer` calls `answerViaCNAME`. The link is validated and cached at
  `<owner, CNAME>` (`cacheCNAMELink`), and `chaseCNAME` asks
  `<target, qtype>`.
- **The DS at the chain's end is asked at the parent side.** `chaseCNAME`
  picks servers with `FindClosestKnownZoneFor(target, DS)`, which starts from
  the target's parent (`cache/rrset_cache.go:1239`). For `www.sidn.nl DS`
  that is `nl.`. The DS that comes back is validated as any answer is
  (`ValidateAnswer`). Its signer must be a strict ancestor
  (`SignerHoldsRRset`), here `nl.`. It is cached at `<sidn.nl, DS>`. A
  denial goes through `handleNegative`, as any NODATA does.
- **The child's denial in the same response is not used.** `sidn.nl`'s
  servers answer `www.sidn.nl DS` with the CNAME. In AUTHORITY they add their
  own NODATA for `sidn.nl DS`, which is the child side's. `answerViaCNAME`
  takes only the CNAME, and a DNAME above it, from that response. The
  authority section is read only as a wildcard proof for the link.
- **A DNSKEY at the end** is asked of the target's own zone
  (`FindClosestKnownZoneFor(target, DNSKEY)`), the same zone a direct
  question goes to.
- **The answer** is put together by `serveChain`: fresh in
  `ProcessAuthDNSResponse` (`imrengine.go:1380`), cached at
  `imrengine.go:1147`. It has every link with its RRSIGs, then the DS or
  DNSKEY with its RRSIGs, or the denial with its proof. AD is set only if
  every part is Secure. A multi-hop chain, a target in another zone, an
  unsigned target (no AD) and a target without the type (NODATA) all work as
  they do for A.

`www.sidn.nl DS` is then answered with `www.sidn.nl CNAME sidn.nl` and its
RRSIG, `sidn.nl DS` and its RRSIG by `nl.`, and AD. 1.1.1.1 gives the same
answer.

## 4. The resolver's own DS or DNSKEY question

### 4.1 What is answered, and what is cached

In `handleAnswer`, after the branch that follows:

```go
if cnameDeniesType(ctx, qtype) {
	if cn := cnameAt(r, qname); cn != nil {
		return imr.cnameAsNoData(ctx, qname, qtype, r, cn, transport)
	}
}
```

`cnameAsNoData` (in `imr_cname_chain.go`) caches the link with
`cacheCNAMELink`, exactly as a client's question would. It returns
`(nil, NOERROR, ContextNoErrNoAns, transport, nil, done=true)`. The rcode is
NOERROR even when the server answered NXDOMAIN for the chain's end
(RFC 6604): the name asked about exists. If the link's validation fails with
an error, that error is returned, as `answerViaCNAME` returns it. Either way
the walk stops at the first server.

**Only the link is cached.** No entry is written under `<qname, DS>` or
`<qname, DNSKEY>`. "No DS here" is read from `<qname, CNAME>`:

- The context and lifetime are the link's: `ContextAnswer`, and the CNAME's
  TTL under the usual limits. The answer to the own question expires with the
  link.
- The verdict is the link's own. An Insecure, Indeterminate or Bogus CNAME
  never turns into a Secure "no DS".
- A link synthesized from a DNAME takes the DNAME's verdict, as in #717.

A NODATA stored under `<qname, DS>` was considered and rejected. The
responder and `IterativeDNSQuery` read `<qname, qtype>` before anything else.
A client's DS question would then get that NODATA instead of the chain, with
no SOA and no NSEC to show, and AD taken from the link. Two entries for one
fact would also have to expire, and change verdict, together.

### 4.2 The validator reads the link

In `delegationEvidence(name)`: when the cache holds no DS entry for `name`, a
cached link at `name` decides. It is checked before any question is asked,
and again after the fetch, which may just have cached it.

| Link verdict | Evidence | Why |
|---|---|---|
| Secure | `evidenceNoCut` | the zone above signs a CNAME at the name, so there is no delegation there |
| Bogus | `evidenceBogus` | |
| Insecure, Indeterminate | `evidenceUnjudged` if the zone above is not held Secure (`parentSideSecure`), `evidenceBogus` otherwise | the rule a DS RRset with that verdict gets today |
| none | `evidenceNone` | |

What this does in `belowSecureZone`:

- **An unsigned CNAME in a zone held Secure** (the #717 case). The walk reaches
  the CNAME's own owner only if it found no insecure cut above it, and the
  owner cannot be a cut itself. So the result is Bogus whatever the DS question
  at the owner would say. With §5 that question is not even asked. The verdict
  is the same as today's, without the storm.
- **Unsigned data below a CNAME owner, with an insecure cut further down.** An
  example: `alias.example.` is a signed CNAME, and `sub.alias.example.` is an
  insecure delegation. Today the DS question at `alias` fails, there is no
  evidence, and the data is Bogus. With the link, `alias` is "no cut", the walk
  goes on, and the data is Insecure.

`ReferralChildState` goes through `delegationEvidence` as well. A Secure link
at the child itself counts as "the parent denies the cut it has just referred
to", which is what it is.

### 4.3 `ImrQuery`

`imrQuery` gets `ContextNoErrNoAns` and reports a denial (`freshDenial`,
`imrengine.go:743`). For a DS or DNSKEY question with no entry under
`<qname, qtype>`, `freshDenial` takes the verdict from the link at qname. The
embedded users are told there is no DNSKEY at that name, with the CNAME's
verdict. They want the name's own records (#717).

**Amended:** the API's `imr query` is the exception (§12 item 2, §13.1). It
asks as a DNS client does, so `tdns-cli imr query www.sidn.nl DS` follows the
CNAME as `dig` does. It is also counted as client traffic without PRIVACY
(`none`), not as `internal`.

## 5. Why the #717 recursion cannot come back

The recursion went like this. Validating an unsigned link at X asks for the DS
at X. The answer at X is the link itself. Following it, or validating it
again, asks for the DS at X again.

- The resolver's own questions still do not follow (§2).
- **A mark for each link being validated.** `cacheCNAMELink` validates with
  `withCNAMEValidation(ctx, qname)`. `IterativeDNSQuery` checks the mark
  first, before the cache and before any query. An own DS or DNSKEY question
  at a marked name gets the NODATA of §4.1, and nothing is asked or cached.
  The link's validation then has no evidence at X, and goes on as §4.2 says.
- The mark also ends the DNSKEY form of the loop. `SignerHoldsRRset` accepts
  an RRSIG over a CNAME that names the CNAME's own owner as signer. The
  validator then fetches the DNSKEY at that owner, and the answer is the same
  CNAME.
- **Termination.** Inside a link's validation, the own DS and DNSKEY
  questions go either to the link's owner, which the mark now answers, or to
  names strictly above it (`proofNames`, the signer). Each nested validation
  is of a different link, higher up the tree, and the list of marks only
  grows. As before, the query budget is the backstop.

`cnameChainKey` (`dnslookup.go`, the chase) and `dsProofKey`
(`cache/delegation_proof.go`) are context marks of the same kind.

## 6. The retry storm

**Why it happens.** `handleAnswer` returns `ContextFailure, done=false,
err=nil` (`dnslookup.go:2947`). The walk then looks for a referral in the
response (`dnslookup.go:1800`), finds none, and moves on to the next (server,
address, transport) tuple. Once every tuple has been tried, it resolves the
nameservers that had no glue and tries again (`:1893`). Then it returns
`no Answers found` (`:1911`). Each tuple logs one `Got a CNAME RR` line, and
`sidn.nl` has three nameservers with IPv4 and IPv6 addresses each. Nothing is
cached, so the next question repeats it all: the client's retry, or the
validator's next DS question at that name.

**What stops it.** Both branches return `done=true` from the first server
that answers with the CNAME, and the link is cached. The cache step in
`IterativeDNSQuery` comes before any query (`dnslookup.go:1549`) and answers
from the link:

- for a client's DS or DNSKEY question, with `chaseCNAME` from the cached
  link (the existing branch, now also for DS and DNSKEY);
- for an own DS or DNSKEY question, with the NODATA of §4.1, and no query is
  sent.

The `Got a … RR` line stays for answers that hold neither the type nor a
CNAME at qname.

## 7. Cache interactions

- **A link cached by any question** (`www.sidn.nl A`, or an own DS question)
  serves the next DS or DNSKEY question of either kind. The link's server is
  not asked again.
- **A whole chain in the cache** answers a client's DS or DNSKEY question in
  the responder's first step (`serveChain` with no grace,
  `imrengine.go:1147`).
- **TTLs.** Each part keeps its own: the link has the CNAME's TTL, and the DS
  at the end has the parent's DS TTL. The answer is served with what remains
  of each, as #717 does. The own NODATA lasts exactly as long as the link
  (§4.1).
- **A later direct question for the target** (`sidn.nl DS`) reads
  `<sidn.nl, DS>`, the entry the chase wrote after asking the parent side and
  validating the answer. It also works the other way round: a DS already
  cached for the target ends the chain without a query. A DS known only from
  the parent's referral (`ContextReferral`) is asked again for the chain,
  because the walk upgrades any indirect entry (but see §12 for
  `upgrade-indirect-cache-hits: false`).
- **Nothing hides the chain.** This design writes nothing under
  `<owner, DS>` or `<owner, DNSKEY>`. The responder's first read
  (`imrengine.go:1134`) finds nothing there, and goes on to the chain.
- **Strict privacy.** A link is used only if it arrived encrypted, as in the
  existing branch.

## 8. Changes by file

| File | Change |
|---|---|
| `v2/imr_traffic_class.go` | `isClientQuery(ctx)`, which `trafficClass` uses. The comment says the mark now also decides §2 |
| `v2/imr_cname_chain.go` | `followsCNAME(ctx, qtype)`, `cnameDeniesType`, `cnameAsNoData`, and the validation mark (`withCNAMEValidation`, `validatingCNAME`), set in `cacheCNAMELink` |
| `v2/dnslookup.go` | `handleAnswer`: the branch for own questions. `IterativeDNSQueryWithLoopDetection`: the mark check, and the cache step for both kinds of question |
| `v2/imrengine.go` | the two `followsCNAME` calls pass ctx; `freshDenial` reads the link's verdict |
| `v2/cache/unsigned_rrset.go` | `delegationEvidence` reads a cached link, through a new `cnameCutEvidence` |

## 9. Tests

In `v2`, a new `imr_ds_dnskey_at_cname_test.go`. It uses the test doubles from
#717: `chainImr`, `sigChainImr`, `askChain`, `answerOrder`, and the query
counts of `chainDouble`. `startSigChainDouble` gets some new names. Its answers
for the existing names do not change. The new names:

- `top` → the zone apex, with the apex DNSKEY, signed;
- `self` → `s3`, with an RRSIG made by a key named `self` (signer = owner);
- `kid`, a signed child set up as `sidn.nl` is. Its DS is signed by the
  parent, its own DNSKEY is served, and `www.kid` → `kid` is signed by `kid`.
  The response with that CNAME carries `kid`'s own NODATA for `kid DS` in
  AUTHORITY.

A client's questions, through the responder, each asked fresh and then from
the cache:

1. `s1 DS` → `s1 CNAME`, `s2 CNAME`, `s3 DS`, three RRSIGs, AD. The double
   gets each of the three DS questions once in all.
2. `top DNSKEY` → `top CNAME`, the apex DNSKEY, AD. `s1 DNSKEY` → the two
   CNAMEs and the NODATA at `s3`, with the AD a direct `s3 DNSKEY` question
   gets.
3. `www.kid DS` (a signed target in another zone) → `www.kid CNAME`,
   `kid DS`, AD. The child's NODATA from the CNAME response is not what is
   served.
4. `out DS` (an unsigned target in another zone) → `out CNAME`, NOERROR, no
   AD.
5. `bad DS` (a link whose RRSIG was stripped) → SERVFAIL with EDE 6.

The resolver's own questions:

6. `IterativeDNSQuery(context.Background(), s1, DS)` → no RRset, NOERROR,
   `ContextNoErrNoAns`, no error. `s1 DS` is asked once, `s2 DS` and `s3 DS`
   never, and a second call asks nothing. This makes
   `TestDSQuestionDoesNotFollowACNAME` stricter. The same test for DNSKEY.
7. `bad A` (the #717 recursion) → SERVFAIL, quickly. `bad DS` is never asked,
   and neither is `s3 DS`: an own question inside a client query does not
   follow.
8. `self A` → SERVFAIL, quickly, and `self DNSKEY` is never asked.
9. `ImrQuery(s1, DS)` → `Denial` = NODATA, `ValidationState` Secure, no RRset,
   no error.
10. A table for `followsCNAME` and `cnameDeniesType`: client, own-traffic and
    unmarked contexts against DS, DNSKEY, A and CNAME.

Behaviour that must not change: the existing CNAME tests
(`imr_cname_chain_test.go`, `imr_cname_chain_answer_test.go`,
`imr_oob_cname_chase_test.go`, `wildcard_cname_test.go`, `cname_*_test.go`)
pass as they are. A new table checks `s1 SOA` and `s1 NS` through the
responder.

In `v2/cache`, in the style of `unsigned_rrset_test.go` (`secCache`,
`seedDSDenial`, `fetchCounter`): a link at `alias.sec.example.`, and a proven
insecure delegation at `sub.alias.sec.example.`. Unsigned data at
`www.sub.alias.sec.example.` is Insecure when the link is Secure, and Bogus
when the link is Bogus or unsigned. No DS question is asked at `alias`.

`go vet` and `go test` run in `v2` and in `v2/cache`.

## 10. Live checks

These run against my own build on DNS port 1199 and API port 8184, with a
copy of the running IMR's configuration. The resolver on port 1099 is not
touched. Each question is asked twice (the second time it comes from the
cache), and the answers are compared with `1.1.1.1`:

- `www.sidn.nl DS +dnssec`: NOERROR and AD, with `www.sidn.nl CNAME sidn.nl`
  and its RRSIG, and `sidn.nl DS 62949 13 2 …` with its RRSIG by `nl.`.
- `www.sidn.nl DNSKEY +dnssec`: the CNAME, and `sidn.nl`'s DNSKEYs with their
  RRSIGs, AD.
- `www.internetstiftelsen.se DS +dnssec`: the CNAME, and
  `internetstiftelsen.se DS 5452 …` with its RRSIG by `se.`, AD.
- Unchanged: `www.sidn.nl A`, `SOA` and `NS`; `sidn.nl DS`; `www.iis.se DS`
  (a secure NODATA).
- With debug logging: a cold `www.sidn.nl DS` sends one query to `sidn.nl`'s
  servers, and the second lookup sends none. No `Got a CNAME RR` line.
- `delv @127.0.0.1 -p 1199 www.sidn.nl DS`: fully validated.

## 11. Size

Code: about 180 lines in five files, much of it comments, in the style of the
surrounding code. Tests: about 450 lines, in one new file in each of the two
modules, plus the additions to the double. And this document.

## 12. Decisions wanted, and what is left out

1. **The test for a client** is the client-query mark from #857, not a new
   mark (§1). **Approved.**
2. **`ImrQuery` asks as the resolver does** (§4.3). `imr query www.sidn.nl DS`
   over the API answers NODATA with the CNAME's verdict, not the chain that
   `dig` gets. The alternative is to mark API queries as a client's, which
   also changes the transport statistics. Proposed: keep it as it is.
   **Decided otherwise:** the API's `imr query` asks as a client; the
   embedded users keep the resolver's behaviour (§13.1).
3. **No entry under `<owner, DS>`** (§4.1). The issue says "store it as such":
   here the link is stored, and the "no DS" is read from it. **Approved.**
4. Left out, now issues of their own:
   - #877: a forward zone with `trust-ad` (`acceptForwardedAnswer`,
     `imr_forward.go:1083`) still caches a chain as one mixed RRset under
     `<qname, qtype>`, for DS too. An own DS question there gets the target's
     DS. This is the pre-#717 behaviour, on that path only.
   - #878: with `upgrade-indirect-cache-hits: false`, a chain whose end is
     cached only as referral or glue data (a referral DS, for one) cannot be
     put together, because `chainAt` wants `ContextAnswer`, and the client
     gets SERVFAIL. This happens for every type. tdns-mp sets the option to
     false by default.

## 13. Amendment, 2026-10-01: as implemented

### 13.1 The API's `imr query` asks as a DNS client

Johan decided §12 item 2 the other way: `tdns-cli imr query` should answer
as `dig` does.

- `asClientQuery(ctx)` (`v2/imr_traffic_class.go`) marks a context for
  `ImrQuery`. With the mark, `imrQuery` runs its lookups as a client's query
  (`imrQueryContext`), and without it as the resolver's own, as before. The
  mark is taken off for the lookups themselves, so an `ImrQuery` nested inside
  is the resolver's own again.
- The API handler for `imr query` (`imr-resolve`, `v2/apihandler_imr.go:425`)
  uses the mark. That one line is the whole switch.
- **Transport statistics.** API queries are now counted as client traffic
  without PRIVACY (`none`), no longer as `internal`. The help for
  `imr stats auth-transports --privacy` (and its page in `reference/cli`) and
  `guide/app-tdns-imr.md` now say so.
- Everything else keeps the resolver's behaviour: the scanner, the
  delegation checks, the DSYNC code, the child DNSKEY fetch, and the
  in-process `imr query` of tdns-imr's own shell, which goes through
  `handleRecursorRequest`.
- The API returns one RRset, so it prints only the chain's end:
  `tdns-cli imr query www.sidn.nl DS` prints `sidn.nl DS`, as
  `www.sidn.nl A` already printed `sidn.nl A`. This is not changed here.

### 13.2 A link is "no cut" only when signed from above

Added in review. `cnameCutEvidence` gives `evidenceNoCut` only for a Secure
link whose RRSIGs all name a signer strictly above the name. For a link
synthesized from a DNAME, the DNAME's RRSIGs are the ones checked. A Secure
link signed by its own owner gives `evidenceBogus`, because that signer would
be a zone whose apex holds a CNAME. §4.2's table had Secure → no cut, with no
condition on the signer.

### 13.3 On main, before #872 and #874

This was implemented on main at `995c15c6`. On that main, `handleAnswer` and
`cacheCNAMELink` validate with `ValidateRRsetWithParentZone`, not
`ValidateAnswer` (§3), and nothing at all is read from the authority section
of the CNAME response. When #872 and #874 merge, main is merged forward into
the branch.

### 13.4 Smaller differences

- The cache step in `IterativeDNSQueryWithLoopDetection` reads the link
  through one helper, `cachedLink`, for both of its branches.
- `freshDenial` takes the link's verdict only for an own question
  (`cnameDeniesType` on the lookup's context).
- The cache tests are in a new file, `v2/cache/unsigned_rrset_cname_test.go`,
  not in `unsigned_rrset_test.go`.
- `TestDSQuestionDoesNotFollowACNAME` is left as it was. The stricter checks
  are in `TestOwnQuestionAtACNAMEOwnerIsAnsweredByTheLink`.
- For `s1 DNSKEY` (test 2), the test checks the answer and the NSEC, not the
  AD bit.
- Tests added beyond §9:
  - `TestOtherTypesAtACNAMEOwnerStillFollow` (A, SOA, NS);
  - `TestImrQueryContextByCaller`;
  - `TestAPIimrResolveFollowsACNAMEForDSAndDNSKEY`, against
    `TestImrQueryAtACNAMEOwnerIsNoData` for the embedded path;
  - in the cache: the signer condition of §13.2, a link synthesized from a
    DNAME, and the DS question still being asked when no link is cached.
- **The mark does matter.** With its check disabled,
  `TestValidatingAnUnsignedLinkDoesNotAskForItsDS` and
  `TestALinkSignedByItsOwnOwnerTerminates` were still running at the
  10-minute test timeout. With the check, they take milliseconds.

### 13.5 Size

- Code: about 275 lines, comments included, in seven Go files.
- Tests: about 500 lines, in two new files and in the test double.
- Plus the help text and guide lines of §13.1, and this document.

### 13.6 Live checks

Run with this branch's tdns-imr on port 1199 (API on 8184), and compared with
1.1.1.1. Each question was asked twice.

| Question | Answer | Upstream queries |
|---|---|---|
| `www.sidn.nl DS` | NOERROR, AD; `www.sidn.nl CNAME sidn.nl` with its RRSIG, `sidn.nl DS 62949 13 2 …` with its RRSIG by `nl.`, as 1.1.1.1 answers | cold: `www.sidn.nl DS` once each to a root, an `nl` and a `sidn.nl` server (the walk); `sidn.nl DS` once, to an `nl` server. Second ask: none |
| `www.sidn.nl DNSKEY` | NOERROR, AD; the CNAME, then `sidn.nl`'s two DNSKEYs and their RRSIG, as 1.1.1.1 answers | none: the link and the keys were already cached |
| `www.internetstiftelsen.se DS` | NOERROR, AD; the CNAME, then `internetstiftelsen.se DS 5452 …` with its RRSIG by `se.`, as 1.1.1.1 answers | cold: one per zone on the walk. Second ask: none |
| `www.sidn.nl A`, `SOA`, `NS`; `sidn.nl DS`; `www.iis.se DS` | unchanged, with the same rcode, AD and RRsets as 1.1.1.1 | — |

- `delv @127.0.0.1 -p 1199`: "fully validated" for `www.sidn.nl DS`,
  `www.sidn.nl DNSKEY` and `www.internetstiftelsen.se DS`.
- `tdns-cli imr query` over the API, built from this branch:
  - `www.sidn.nl DS` gives `sidn.nl DS` (secure);
  - `www.sidn.nl DNSKEY` gives `sidn.nl`'s DNSKEYs (secure);
  - `www.internetstiftelsen.se DS` gives its DS (secure).
- For comparison, the resolver without this change answered
  `imr query www.sidn.nl DS` with `no Answers found … (zone=sidn.nl.
  attempts=6 …)`.
- The log has no `Got a CNAME RR` lines.
