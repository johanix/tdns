# tdns-imr: proofs for answers synthesized from a wildcard

**Written 2026-10-01.** Line references are to `57b5a87e`, the head of
`feature/imr-nsec3-validation` (#871), which this builds on.

**Status:** implemented in three PRs: #872 (§4.1, the answer's owner), #873
(part B, §11) and #874 (part A). Part A is stage 3 of
`2026-09-30-imr-nsec3-validation.md` (its §2.7, §3, §10 and §12).

**Revisions:**
- **r1**, 2026-10-01: the proposal, approved the same day with the changes
  and decisions in §19.
- **Amended 2026-10-01** (§19): how the implementation differs, and the
  Deckard results.

## Summary

- **Part A.** An answer synthesized from a wildcard is validated together
  with the proof that the queried name does not exist, and the proof is kept
  and served.
  - The signature that validates the answer says whether it was
    synthesized: its Labels field is below the owner's label count (RFC 4035
    §5.3.2).
  - The proof is read from the response's authority section, from the zone
    that signed the answer, and must validate. RFC 4035 §5.3.4 for NSEC, RFC
    5155 §8.8 for NSEC3 (`NSEC3WildcardProof`, #871).
  - The proof holds: Secure. Through an NSEC3 Opt-Out span: Insecure, no AD.
    Over the NSEC3 iteration limit: Insecure, EDE 27. It does not hold, or
    is missing: Bogus.
  - Kept on the cache entry (`CachedRRset.WildcardProof`). Served to DO
    clients in the authority section, fresh and cached, and for every link of
    a CNAME chain.
- **Part B.** `ValidateDenial` reads two more NSEC NODATA shapes: wildcard
  NODATA and empty non-terminal NODATA. NXDOMAIN keeps its proof as it is.
- **Size.** About 1,450 lines in two PRs, two thirds of them tests (§17).
- **Deckard.** Six of the eight target scenarios are expected to pass: four
  after part A, two after part B. `val_nsec3_cnametocnamewctoposwc` also
  wants an NS RRset in the authority section of a fresh answer.
  `val_wild_pos_multi` needs a fix in the dns library (§16).

## 1. What the code does today

### 1.1 Positive answers

- `handleAnswer` (`dnslookup.go:2872`):
  - a CNAME owned by qname goes to `answerViaCNAME`
    (`imr_cname_chain.go:183`);
  - otherwise every record of qtype in the answer section, and every RRSIG,
    goes into one RRset named qname (`:2893-2903`);
  - that RRset is validated (`ValidateRRsetWithParentZone`, `:2915`) and
    cached with the verdict (`:2924-2934`);
  - the authority section is not read.
- `ValidateRRsetWithParentZone` (`cache/rrset_validate.go:365`):
  - reuses a cached verdict for the same RRs and RRSIGs, unless it is
    Indeterminate (`:385-420`);
  - hands a DNSKEY RRset to `ValidateDNSKEYs` (`:458-464`);
  - tries the RRSIGs in order and returns Secure at the first that validates
    (`:479-521`). It does not say which one.
- `validateRRsetWithRRSIG` (`:87`), for each signature:
  - `SignerHoldsRRset` (`:62`): the signer is an ancestor of the owner, and
    Labels is at least the signer's label count;
  - `secureHolderBelow` (`:32`);
  - a signer zone held Indeterminate or Insecure decides before any key is
    looked at (`:123-137`, and again around the DNSKEY fetch);
  - `RRSIG.Verify` rebuilds the signed owner from Labels (RFC 4035 §5.3.2):
    a signature made over `*.w.example` verifies for `a.z.w.example`.
- `cacheCNAMELink` (`imr_cname_chain.go:133`) validates a link, and the DNAME
  that synthesized one, the same way (`:140`, `:162`). Each link after the
  first comes from the response to its own query (`chaseCNAME`,
  `dnslookup.go:3978`).
- `NSEC3WildcardProof` (`rrset_validate.go:1332`) is in place. Nothing calls
  it.

### 1.2 Serving

- **Fresh.** `ProcessAuthDNSResponse` (`imrengine.go:1368`) builds the answer
  from the entry `handleAnswer` made (`Get`, `:1415`). It takes that entry's
  verdict, or validates again when the verdict is not reusable (`:1450-1471`).
- **Cached.** `serveCachedPositive` (`imr_answer_verdict.go:195`) validates
  again when the verdict is not reusable.
- **Chains.** `serveChain` (`imr_cname_chain.go:303`) judges each part
  (`judge`, `:322`).
- `dispositionFor` (`imr_answer_verdict.go:45`) maps a verdict to a response.
  Any EDE on a positive entry makes it SERVFAIL (`:53`). Today only Bogus
  entries carry one (`MarkRRsetBogus`).
- The authority section of a positive answer is empty.
- `Get` drops an expired entry, and an answer with TTL 0 is stored already
  expired. `serveChain` and `imrQuery`'s `freshDenial` read with `Peek` for
  that reason.

### 1.3 Forwarding and own zones

- `forwardQuery` (`imr_forward.go:713`) asks with DO=1, and with CD=1 unless
  the zone has `trust-ad` (`:742`). An answer goes to `handleAnswer` (`:905`).
  With `trust-ad`, `acceptForwardedAnswer` (`:1083`) takes the upstream's AD
  bit as the verdict.
- `answerFromOwnZone` (`imr_own_zone.go:303`) hands `handleAnswer` a response
  from the zone's own `QueryResponder`, asked with DO.
  - The authoritative side adds the NSEC proof to a signed wildcard answer
    (`addWildcardProof`, `wildcard_proof.go:45`): from the zone's NSEC chain,
    or synthesized for a zone signed here with black lies.
  - A zone signed elsewhere with NSEC3 gets none: NSEC3 is not served yet
    (`denial.go:94-101`).

### 1.4 NSEC denials

- `ValidateDenial`'s NSEC branch (`rrset_validate.go:1226-1289`) reads two
  shapes:
  1. an NSEC owned by qname: an RFC 9824 compact NXDOMAIN, or NODATA when
     its bitmap lacks qtype;
  2. an NSEC covering qname, and one covering the wildcard at the closest
     encloser that cover proves (RFC 4035 §5.4). Read for either rcode.
- Anything else is Bogus.
- The NSEC3 branch reads both NODATA shapes of part B (#871: `noData`
  steps 1 and 3).

## 2. Detecting an answer synthesized from a wildcard

- An RRSIG over an RRset is an **expansion signature** when its Labels field
  is below the owner's label count, a leading `*` label not counted (RFC
  4034 §3.1.3, RFC 4035 §5.3.2).
  - `*.w.example` asked for by name, with Labels 2: not an expansion.
    Deckard's `val_wild_pos` asks exactly that.
  - Only RRSIGs owned by the RRset's owner and covering its type count.
  - DNSKEY RRsets: never. `ValidateDNSKEYs` validates them against the DS,
    and a DNSKEY RRset sits at a zone apex.
- The signature that validates the RRset decides:
  - signatures whose Labels equals the owner's count are tried first;
  - one of those validates: the RRset is the owner's own, and no proof is
    needed;
  - an expansion signature validates: the RRset was synthesized from the
    wildcard `*.` + the owner's last Labels labels, in the zone its Signer's
    Name names, and the proof is needed.
- The wildcard's closest encloser (CE) is the owner's last Labels labels. The
  next closer name (NC) is its last Labels+1. `SignerHoldsRRset` already
  keeps CE at or below the signer.
- The name proven absent is the RRset's owner. For `handleAnswer` that is
  qname (§4.1).

## 3. The proof

A new file, `v2/cache/wildcard_answer.go`:

```go
// WildcardAnswerProof reports what the NSEC or NSEC3 RRsets in proof show
// about an answer for qname that zone synthesised from a wildcard: that qname
// does not exist, and nothing between it and the wildcard's closest encloser
// does (RFC 4035 section 5.3.4, RFC 5155 section 8.8). labels is the Labels
// field of the RRSIG that validated the answer. The EDE is 27 when the NSEC3
// records are over the iteration limit, else 0.
func (rrcache *RRsetCacheT) WildcardAnswerProof(ctx context.Context, zone, qname string,
    labels uint8, proof []*core.RRset, fetcher RRsetFetcher) (ValidationState, uint16)
```

### 3.1 Which records count

- NSEC and NSEC3 RRsets of the authority section, owned in `zone` (NSEC3:
  directly below its apex, as in #871), each with `zone`'s RRSIGs only
  (`signedBy`).
- Each must validate Secure. One that does not decides the verdict, as in
  `NSEC3WildcardProof` and `ValidateDenial`.
- Unsigned ones, and ones signed only by another zone, do not count.

### 3.2 NSEC (RFC 4035 §5.3.4)

An NSEC proves it when it:

- covers qname (`nsecCoversName`, strict at both ends);
- proves the wildcard's closest encloser: `closestEncloser(qname, nsec,
  zone)` is CE. A longer one means a name between CE and qname exists, and
  the wildcard does not apply;
- has a next name that is not below qname. Otherwise qname is an empty
  non-terminal, and exists;
- has neither DNAME nor NS without SOA, when its owner is an ancestor of
  qname.

### 3.3 NSEC3 (RFC 5155 §8.8)

- `wildcardAnswer` (`nsec3.go:464`) over the records of §3.1: a record covers
  NC.
- Covered through Opt-Out: Insecure (RFC 5155 §9.2).
- Records over the iteration limit (`imrengine.tuning.nsec3-max-iterations`)
  set aside, and the rest do not prove it: Insecure, EDE 27.
- Out of the hash budget: Indeterminate.
- `NSEC3WildcardProof` stays, a wrapper over the same code. Its tests stay.

### 3.4 Verdicts

| The proof | Verdict | EDE | AD |
|---|---|---|---|
| holds (an NSEC, or an NSEC3 without Opt-Out) | Secure | – | to a client that asks for it |
| holds through an NSEC3 Opt-Out span | Insecure | – | no |
| needs NSEC3 records over the iteration limit | Insecure | 27, beside the answer | no |
| runs out of the NSEC3 hash budget | Indeterminate | 5, with trust anchors | no |
| does not hold, or is missing | Bogus | 6 | – |

An NSEC that proves it decides first. Otherwise the NSEC3 verdict. Neither
NSEC nor NSEC3: Bogus.

## 4. Where it is validated

### 4.1 handleAnswer collects qname's records

- `handleAnswer` collects the records of qtype owned by qname, and the RRSIGs
  owned by qname that cover qtype (`sigsFor`, as `cacheCNAMELink` does).
- It matters here: the RRset is cached under qname, and the wildcard check
  reads the owner's labels and proves the owner absent.
- Records of qtype owned by another name are logged and left out, as records
  of other types are today. An answer with nothing left is not used, and the
  query goes to the next server, as one with no records of qtype does today.

### 4.2 ValidateAnswer

```go
// AnswerVerdict is what ValidateAnswer makes of a positive RRset.
type AnswerVerdict struct {
    State   ValidationState
    EDECode uint16 // 27 when the wildcard proof needs NSEC3 records over the limit
    EDEText string
    Proof   []*core.RRset // set when the RRset carries an expansion signature
}

// ValidateAnswer validates a positive RRset together with the authority
// section it arrived with.
func (rrcache *RRsetCacheT) ValidateAnswer(ctx context.Context, rrset *core.RRset,
    authority []*core.RRset, fetcher RRsetFetcher) (AnswerVerdict, error)
```

- No expansion signature: `ValidateRRsetWithParentZone`, as today. `Proof` is
  nil.
- With one:
  1. `Proof` is the records of §3.1 from `authority`, for the zone each
     expansion signature names. Kept whatever the verdict (§5).
  2. The signatures are tried by the loop `ValidateRRsetWithParentZone` uses,
     factored out so it returns the signature that validated. Equal Labels
     first. A cached verdict is not reused: the authority section is new.
  3. Not Secure: that verdict. No proof is checked (§10).
  4. Secure through an equal-Labels signature: Secure.
  5. Secure through an expansion signature: `WildcardAnswerProof` decides.
- Called by `handleAnswer`, and by `cacheCNAMELink` for a link and a DNAME,
  with `authorityRRsets(r.Ns)`. Called again with the entry's
  `WildcardProof` where a cached entry is validated again (§6).

### 4.3 ValidateRRset with the kept proof

- Other code validates RRsets the resolver has just looked up: `imrQuery`
  (`imrengine.go:721`), the DANE TLSA lookups (`xot.go:357`,
  `imr_helpers.go:275`), `revalidateGlueRR` (`dnslookup.go:3496`), the
  scanner (`scanner_trust.go:144`).
- `ValidateRRsetWithParentZone` treats an RRset with an expansion signature
  as `ValidateAnswer` does. Its authority section is the proof kept on the
  cache entry that holds the same RRs and RRSIGs, read with `Peek`, so an
  entry stored with TTL 0 still counts. No such entry: no proof.
- A cached verdict for the same RRset is reused, as today. It was reached
  with the proof.
- Every caller reaches the same verdict for the same answer, and none has a
  proof argument to pass.

## 5. Storing

- `CachedRRset` (`cache/cache_structs.go:31`) gets a field:

  ```go
  // WildcardProof is set on an answer whose RRSIGs include an expansion
  // signature (RFC 4035 section 5.3.2): the NSEC or NSEC3 RRsets, with their
  // RRSIGs, that the zone sent in the authority section to prove that the
  // name does not exist. Served beside the answer to DO clients, and read
  // when the answer is validated again.
  WildcardProof []*core.RRset
  ```

- `handleAnswer` and `cacheCNAMELink` store it, with `State`, `EDECode` and
  `EDEText` from `AnswerVerdict`.
- **Lifetime.** `Set` (`rrset_cache.go:174`) takes the lowest TTL over the
  RRset and the kept proof, then applies `cache-min-ttl` and `cache-max-ttl`
  as now. A proof is usually the zone's negative TTL (RFC 9077). Served from
  the entry, the proof never outlives its own TTL.
- `MarkRRsetBogus` and `SetVerdict` edit an existing entry and keep the field.
- `revalidateGlueRR` (`dnslookup.go:3500`) replaces the entry it has just
  looked up. It keeps that entry's proof when the RRset is the same.
- The proof's records are not cached under their own owners, and nothing is
  synthesized from them (RFC 8198, out of scope).

## 6. Serving

- **Fresh** (`ProcessAuthDNSResponse`): the entry is read with `Peek` within
  one query budget (`freshChainGrace`), as `serveChain` reads it. An answer
  whose lifetime the proof cut to 0 keeps its verdict and proof for the query
  that fetched it. A verdict that is not reusable is validated again with
  `ValidateAnswer` and the kept proof.
- **Cached** (`serveCachedPositive`): `ValidateAnswer` with the kept proof
  when the verdict is not reusable.
- **What goes out:**
  - DO set: the proof in the authority section, records and RRSIGs, TTLs set
    to the entry's remaining lifetime (`applyRemainingTTL`). With or without
    CD.
  - DO clear: nothing in authority (RFC 3225), as
    `appendNegAuthorityToMessage` does for denials.
  - AD per `dispositionFor`: Secure only.
  - No expansion signature: the authority section stays empty.
- **CD:** every verdict is served (`dispositionFor`), with the proof when DO
  is set. A client that validates for itself needs it.
- A helper appends a list of proof RRsets to `m.Ns`, each RRset (owner and
  type) once. The fresh, cached and chain paths share it.

## 7. CNAME chains and DNAME

- `cacheCNAMELink` validates each link with `ValidateAnswer` and the authority
  section of the response it came in. A CNAME synthesized from `*.wc.example
  CNAME …` is checked like any other answer.
- The data at the end is validated by `handleAnswer` for its own query, with
  its own response.
- A DNAME synthesized from a wildcard gets the same check. The CNAME it
  synthesizes takes its verdict, as today.
- `serveChain`:
  - `judge` validates a part again with `ValidateAnswer` and the part's kept
    proof when its verdict is not reusable;
  - with DO, every part's proof goes in the authority section, in chain
    order, each RRset once;
  - a chain that ends in a denial: the denial's records first
    (`serveNegativeResponse`), then the parts' proofs, each RRset once;
  - AD only when every part is Secure, as today. An Opt-Out link takes AD off
    the chain;
  - EDE 27 on any part goes out with the answer (§9).

## 8. Forwarded answers and own zones

- **Forward zones without `trust-ad`.** The upstream is asked with DO=1 and
  CD=1, and its answer goes through `handleAnswer`, as an iterative one does.
  The proof comes from the upstream's authority section.
  - No proof: Bogus. SERVFAIL with EDE 6 to a client without CD.
  - The next upstream is not tried: a verdict is not a transport failure, and
    the iterative path does not try another server on one either.
  - A security-aware recursive server returns the DNSSEC records an answer
    needs to a DO query (RFC 4035 §3.2.1). One that left the proof out would
    turn every wildcard answer from a signed zone into SERVFAIL (Q2).
- **`trust-ad`.** Unchanged: the upstream's AD bit is the verdict, and no
  proof is read or kept.
- **Own zones.** The authoritative side's proof (§1.3) is read like any
  other. A zone signed elsewhere with NSEC3 has none, so its wildcard answers
  validate Bogus where its chain is Secure (§12).

## 9. EDE

- **27, over the iteration limit.** Stored with the answer, which is
  Insecure. It goes out beside the answer, as on a denial:

  ```go
  // edeBeside reports whether an EDE on a positive entry is served beside
  // the answer rather than instead of it: 27 on an answer that is Insecure
  // because its wildcard proof needs NSEC3 records over the iteration limit
  // (RFC 9276).
  func edeBeside(state cache.ValidationState, ede uint16) bool
  ```

  - `dispositionFor`: an EDE on the entry makes it SERVFAIL unless
    `edeBeside` (`imr_answer_verdict.go:53`).
  - The fresh, cached and chain paths attach it when the query has EDNS, as
    `attachNegativeEDE` does for a denial.
  - Every other EDE on a positive entry makes it SERVFAIL, as today.
- **A proof that does not hold:** EDE 6 from `dispositionFor`, as for any
  Bogus answer. The NSEC3 design chose 6 over 12 (NSEC Missing) for denials
  (its Q5); the same here.
- **Out of the hash budget:** Indeterminate, EDE 5 on a resolver with trust
  anchors.

## 10. Zones held Insecure or Indeterminate

- **Signer zone held Insecure** (`rrset_validate.go:130-135`): the
  answer is Insecure before any signature is checked, and no proof is
  checked. Nothing proves anything in a zone without a chain of trust. The
  proof is kept and served to DO clients.
- **Held Indeterminate:** Indeterminate. The proof is kept, and checked when
  the entry is validated again (§6).
- **Unsigned RRset:** no expansion signature. The early check
  (`rrset_validate.go:444-455`) and `unsignedRRsetState`, as today.
- **`secureHolderBelow`:** unchanged. An expansion signed by a zone above one
  held Secure that holds the owner is Bogus before the proof matters.
- **`recheckInsecureZone`:** unchanged.
- **Proof records** are validated with `ValidateRRset`. Signed by the zone
  that signed the answer, they meet the same zone state.
- **`ValidateDenial`'s Insecure path** (`sawInsecure`,
  `rrset_validate.go:1221`): unchanged by part B.

## 11. Part B: two NSEC NODATA shapes

In `ValidateDenial`'s NSEC branch, after the compact denial check, for rcode
NOERROR only. Every NSEC used has validated Secure, as now.

1. **Empty non-terminal** (Deckard `val_mal_wc`): an NSEC covers qname, and
   its next name is a proper subdomain of qname. qname has a descendant and
   no records: Secure, for any qtype.
2. **Wildcard NODATA** (RFC 4035 §3.1.3.4, Deckard
   `nsec_wildcard_no_data_response`):
   - an NSEC covers qname; CE is `closestEncloser(qname, cover, zone)`;
   - an NSEC is owned by `*.CE`, and its bitmap has neither qtype nor CNAME,
     nor NS without SOA (a wildcard is not a delegation; #871's `noData`
     step 3 says the same);
   - Secure. One NSEC may be both: `*.nsec.example NSEC ns.nsec.example`
     covers `aaa.local.nsec.example` and is the wildcard's.
3. Then the name error shape, for either rcode, as today.

- NXDOMAIN keeps its proof: an NSEC owned by qname (RFC 9824), or the name
  error shape. The two new shapes show that qname exists, or that the
  wildcard matched; neither is a name error.
- The NSEC3 branch is unchanged: #871 reads both shapes.
- About 60 lines and 200 of tests. Independent of part A.

## 12. Side effects

What changes beyond the proof itself:

- **`handleAnswer` collects qname's records only** (§4.1).
  - An answer whose records of qtype are all owned by another name is not
    used; the query goes to the next server.
  - A CNAME query answered with a whole chain is validated as qname's CNAME
    alone. All the chain's CNAMEs went into one RRset before, and validated
    Bogus.
- **The fresh path reads the entry with `Peek`** (§6). An answer with TTL 0
  takes the verdict `handleAnswer` just reached, where it was validated a
  second time. Same verdict, one validation fewer.
- **A wildcard answer lives no longer than its proof** (§5).
- **Own zones signed elsewhere with NSEC3** (§8): wildcard answers validate
  Bogus where the zone is Secure, until the authoritative side serves NSEC3.
- **The scanner** (`scanner_trust.go:136`) validates child data without its
  authority section. Child data synthesized from a wildcard (an address of an
  in-bailiwick nameserver) validates Bogus unless the resolver's cache holds
  the same RRset with its proof. Under a delegation policy that requires
  DNSSEC it is refused (Q3).
- **Other RRsets validated without a response:** the NS RRset
  `revalidateReferralNS` fetches (`dnslookup.go:3378`) is the only other one.
  With an expansion signature it validates Bogus. RFC 4592 §4.2 advises
  against NS records at a wildcard.
- **Part B:** the scanner's denial check (`validateChildDenial`,
  `scanner_trust.go:149`) passes NOERROR, and reads the two new shapes too.

Not changed:

- Additional-section data, such as glue: not an answer, and asked for again
  before it is served as one (`upgrade-indirect-cache-hits`, on by default).
- `ZoneData.ValidateRRset` (`dnssec_validate.go`), the validator outside the
  resolver.
- `trust-ad` answers (§8).
- RFC 8198 aggressive use of NSEC and NSEC3.
- The name error shape for NOERROR (Q4), and for a cover whose next name is
  below qname (Q5).

## 13. Performance

- **Detection:** one pass over the RRset's RRSIGs per validation. An RRset
  without an expansion signature costs nothing more.
- **A fresh answer with one:**
  - no reused verdict: one signature check more when the same RRset is
    fetched while it is still cached (a forced lookup);
  - the proof: one signature check per proof RRset, one to three. NSEC:
    canonical comparisons. NSEC3: NC hashed once per parameter set, within
    #871's budget of 256.
- **Through `ValidateRRsetWithParentZone`:** one `Peek` for an RRset with an
  expansion signature.
- **Cached:** nothing new unless the verdict is not reusable, as today.
- **Serving:** the proof records copied for a DO client, as `NegAuthority`
  is for a denial.
- **Memory:** one to three RRsets with RRSIGs per wildcard entry, a few
  hundred octets, up to about 2 KB with RSA keys.
- No benchmark: the added work is one or two signature checks.

## 14. Test plan

### 14.1 The validator (`v2/cache/wildcard_answer_test.go`, new)

With the signing helpers of #871 (`newZoneKey`, `secCache`, `synthNSEC3`), and
an NSEC chain built in the test. The answer is `a.z.w.sec.example A`, signed
as `*.w.sec.example` (Labels 3).

- `TestWildcardExpansionSignatures`: Labels below the owner's count; a
  leading `*` not counted; RRSIGs owned elsewhere or covering another type
  ignored; DNSKEY never.
- `TestValidateAnswerWildcardNSEC`:
  - the proof holds: Secure, and `Proof` holds it;
  - no proof: Bogus;
  - the cover proves a longer closest encloser (`z.w.sec.example` exists):
    Bogus;
  - the cover's next name is below qname: Bogus;
  - the cover's owner is an ancestor of qname with DNAME, or with NS and no
    SOA: Bogus;
  - an NSEC owned by qname: Bogus;
  - the cover signed by the zone above: Bogus;
  - a good cover beside an NSEC with a broken signature: Bogus.
- `TestValidateAnswerWildcardNSEC3`: NC covered (Secure); through Opt-Out
  (Insecure); over the limit (Insecure, EDE 27); not covered (Bogus); covered
  by a record signed by another zone (Bogus).
- `TestValidateAnswerTheValidatingSignatureDecides`: a valid equal-Labels
  signature beside an expansion one: Secure, no proof needed. A broken
  equal-Labels signature beside a valid expansion one: the proof decides.
- `TestValidateAnswerTheWildcardItself`: `*.w.sec.example` asked for by
  name: Secure, no proof needed.
- `TestValidateAnswerDoesNotReuseAVerdictForAWildcard`: the entry is cached
  Secure; the same RRset with an authority section without the proof:
  Bogus.
- `TestValidateRRsetUsesTheKeptProof`: with the entry's proof, Secure, also
  when the entry has expired; with no entry, Bogus; a cached verdict reused.
- `TestValidateAnswerKeepsOnlyTheZonesProofRecords`: SOA, NS, the zone's
  NSEC3, another zone's NSEC3, an unsigned NSEC3: `Proof` is the zone's NSEC3
  with its RRSIGs only.
- `TestValidateAnswerZoneHeldInsecure`: no proof, Insecure; the proof kept.
- `TestValidateAnswerIndeterminateKeepsTheProof`: the signer's keys out of
  reach: Indeterminate, `Proof` set.
- `TestValidateAnswerDNSKEYIsNotAWildcard`: a DNSKEY RRset with a stray
  expansion RRSIG validates through its DS.
- `TestSetBoundsAWildcardAnswerByItsProof`: the entry's lifetime is the
  lower of the RRset's and the proof's TTL.
- Existing tests are unchanged: none uses an RRSIG whose Labels is below its
  owner's.

### 14.2 Part B (`v2/cache/negative_proof_test.go`)

- `TestNSECEmptyNonTerminalNoData`: Secure; with rcode NXDOMAIN, Bogus; the
  next name equal to qname, Bogus; the next name not below qname, Bogus.
- `TestNSECWildcardNoData`: two records, and one record in both roles,
  Secure; qtype, CNAME, or NS without SOA in the wildcard's bitmap, Bogus;
  the wildcard NSEC at another encloser, Bogus; with rcode NXDOMAIN, Bogus.
- Every existing NSEC test passes unchanged: `negative_proof_test.go`,
  `nsec_coverage_test.go`, `compact_denial_test.go`, and the resolver tests
  `imr_stripped_denial_test.go`, `imr_denial_answer_test.go`.

### 14.3 Through the resolver (`v2/imr_wildcard_answer_test.go`, new)

The rigs: the signed stub double of `imr_cname_chain_answer_test.go`
(`startSigChainDouble`, iterative through stubs) with a wildcard and an NSEC
chain; the forward rig of `imr_nsec3_test.go` (`n3Rig`) with NSEC3; the
own-zone rig of `imr_own_zone_test.go`.

- `TestWildcardAnswerThroughTheResolver`, fresh and cached, with and without
  DO, and with CD:
  - NSEC proof: AD with DO; the NSEC and its RRSIG in authority with DO,
    nothing without;
  - NSEC3 through Opt-Out: no AD;
  - over the limit: no AD, EDE 27, NOERROR;
  - no proof: SERVFAIL, EDE 6; with CD, served without AD.
- `TestWildcardAnswerWithAZeroTTLProof`: the proof has TTL 0; the fresh
  answer is Secure, with the proof.
- `TestAnIndeterminateWildcardAnswerIsValidatedAgainWithItsProof`: first
  Indeterminate (DNSKEY unreachable), then Secure from the cache with its
  kept proof.
- `TestCNAMEChainThroughWildcards`: a chain through two wildcards, as
  `val_nsec3_cnametocnamewctoposwc`: AD; each proof RRset once in authority;
  a link without its proof: SERVFAIL; an Opt-Out link: no AD.
- `TestAnAnswerOwnedByAnotherNameIsNotUsed`.
- `TestForwardedWildcardAnswer`: the proof from the upstream's authority
  section; without it, Bogus.
- `TestOwnZoneWildcardAnswerValidates`: the authoritative side's NSEC proof
  is read, Secure.
- `TestRevalidatedGlueKeepsItsProof`.
- `imr_answer_verdict_test.go`, `TestFreshAndCachedAnswersAgree`: new rows,
  Insecure with EDE 27 (served, EDE attached) and Insecure with EDE 9
  (SERVFAIL, as today).

### 14.4 Mutation checks

Each check is taken out, one at a time, and the named test must fail. The PR
lists the outcome for each, in #871's format.

| Check | Test that fails |
|---|---|
| expansion: Labels below the owner's count | `TestValidateAnswerWildcardNSEC` |
| a leading `*` not counted | `TestValidateAnswerTheWildcardItself` |
| only RRSIGs over the RRset | `TestWildcardExpansionSignatures` |
| DNSKEY is never an expansion | `TestValidateAnswerDNSKEYIsNotAWildcard` |
| equal-Labels signatures first | `TestValidateAnswerTheValidatingSignatureDecides` |
| the validating signature decides | `TestValidateAnswerTheValidatingSignatureDecides` |
| no reused verdict for a fresh expansion | `TestValidateAnswerDoesNotReuseAVerdictForAWildcard` |
| `ValidateRRset` reads the kept proof | `TestValidateRRsetUsesTheKeptProof` |
| the kept proof read with `Peek` | `TestValidateRRsetUsesTheKeptProof` |
| proof records signed by the zone | `TestValidateAnswerWildcardNSEC`, `…NSEC3` |
| every proof record validates | `TestValidateAnswerWildcardNSEC` |
| NSEC covers qname | `TestValidateAnswerWildcardNSEC` |
| NSEC proves the wildcard's closest encloser | `TestValidateAnswerWildcardNSEC` |
| NSEC next name not below qname | `TestValidateAnswerWildcardNSEC` |
| NSEC owner above qname: no DNAME, no delegation | `TestValidateAnswerWildcardNSEC` |
| NSEC3: NC covered | `TestValidateAnswerWildcardNSEC3` |
| NSEC3: Opt-Out is Insecure | `TestValidateAnswerWildcardNSEC3` |
| NSEC3: EDE 27 over the limit | `TestValidateAnswerWildcardNSEC3` |
| a verdict other than Secure stands (zone held Insecure) | `TestValidateAnswerZoneHeldInsecure` |
| the proof kept when not Secure | `TestValidateAnswerIndeterminateKeepsTheProof` |
| only the zone's NSEC and NSEC3 kept | `TestValidateAnswerKeepsOnlyTheZonesProofRecords` |
| `Set` bounds the lifetime by the proof | `TestSetBoundsAWildcardAnswerByItsProof` |
| `handleAnswer`: qname's records only | `TestAnAnswerOwnedByAnotherNameIsNotUsed` |
| `handleAnswer` passes the authority section | `TestWildcardAnswerThroughTheResolver` |
| the fresh path reads with `Peek` | `TestWildcardAnswerWithAZeroTTLProof` |
| the proof served with DO, fresh and cached | `TestWildcardAnswerThroughTheResolver` |
| no proof without DO | `TestWildcardAnswerThroughTheResolver` |
| EDE 27 beside the answer | `TestFreshAndCachedAnswersAgree` |
| EDE 27 attached | `TestWildcardAnswerThroughTheResolver` |
| validated again with the kept proof | `TestAnIndeterminateWildcardAnswerIsValidatedAgainWithItsProof` |
| each link checked | `TestCNAMEChainThroughWildcards` |
| `judge` with the kept proof | `TestCNAMEChainThroughWildcards` |
| each proof RRset served once | `TestCNAMEChainThroughWildcards` |
| `revalidateGlueRR` keeps the proof | `TestRevalidatedGlueKeepsItsProof` |
| B: empty non-terminal | `TestNSECEmptyNonTerminalNoData` |
| B: next name strictly below qname | `TestNSECEmptyNonTerminalNoData` |
| B: wildcard NODATA | `TestNSECWildcardNoData` |
| B: the wildcard's bitmap (qtype, CNAME, NS without SOA) | `TestNSECWildcardNoData` |
| B: the wildcard at the cover's closest encloser | `TestNSECWildcardNoData` |
| B: the new shapes for NOERROR only | both, the NXDOMAIN rows |

Each PR: `go vet ./...` and `go test ./...` in all seven v2 modules.

## 15. Not in scope: a wildcard directly below the root

- `rawSignatureData` in `github.com/johanix/dns` (`dnssec.go:636-646` in
  `v1.1.72-johanix.3`) rebuilds the wildcard owner as `"*." + last Labels
  labels + "."`. For Labels 0 that is `*..`, which does not pack, so an RRSIG
  over an RRset synthesized from `*.` cannot be verified.
- It affects Deckard's `val_wild_pos_multi` only, whose zone is the root. A
  fix belongs in the library.

## 16. Deckard

- The template keeps `nsec3-max-iterations: 150` (#871).
- Each build: one full set, and the scenarios below one at a time, before and
  after.

### 16.1 Targets

| Scenario | What it tests | Needs | Expected |
|---|---|---|---|
| `val_nsec3_b4_wild` | B.4: a wildcard answer through Opt-Out, no AD | A | pass |
| `val_nsec3_optout_ad` | steps 60–70: a wildcard answer through Opt-Out; MATCH all, both NSEC3 in authority, no AD | A | pass |
| `val_iter_high` | steps 31–32: a wildcard answer whose proof has 65535 iterations; no AD, no DO, empty authority | A | pass |
| `nsec_wildcard_answer_response` | an NSEC wildcard answer: AD and its proof, fresh and cached (step 11, 13); no proof: SERVFAIL (21, 23); a signature over another wildcard: SERVFAIL (31, 33); a name's own record: AD, empty authority (41, 43); records owned by another name: SERVFAIL (51, 55) | A | pass |
| `val_nsec3_cnametocnamewctoposwc` | a chain through two wildcards, AD, proofs in authority | A | fail at step 20 (§16.2) |
| `nsec_wildcard_no_data_response` | wildcard NODATA, one NSEC in both roles: AD | B | pass |
| `val_mal_wc` | DS at an empty non-terminal: NODATA, AD | B | pass |
| `val_wild_pos_multi` | a wildcard below the root: NODATA (steps 101–102, 131–132) and answers (110–121, 210–221) | A, B, the library (§15) | fail at step 110, was 102 |

### 16.2 Notes

- `val_nsec3_cnametocnamewctoposwc` step 20 compares the authority section
  and wants the zone's NS RRset and its RRSIG in it, beside the two NSEC3
  proofs. Step 40, the same answer from the cache, wants them absent.
  tdns-imr puts no NS records in a positive answer's authority section, and
  this design does not add them. A skip-list candidate after part A, with
  that reason. The NSEC3 design's 21 after stage 3 becomes 20.
- `nsec_wildcard_answer_response` gives its NSEC TTL 0. The answer then lives
  0 seconds (§5): step 12 asks the server again, which the scenario scripts.
  The fresh path reads with `Peek` (§6), so step 11 has its verdict and
  proof.
- `val_iter_high` step 31 asks without DO: the proof stays out of the
  authority section, and EDE 27 goes out only on an EDNS query.
- **Counts:** after part A, four more pass; after part B, two more.

### 16.3 Scenarios that could regress

Run one at a time, before and after:

- `val_wild_pos`: `*.example.com` asked for by name (the leading `*`).
- `val_unknown_algorithm_insecure`: DNSKEY RRsets with Labels 0 (never an
  expansion).
- `nsec_wildcard_no_data_response-part2`: an answer section holding only an
  SOA.
- `nsec3_aggr_cache`, `nsec_aggr_cache`: wildcard CNAMEs, failing today (RFC
  8198). Expected to fail at the same steps.
- NSEC denials that pass today: `val_nodata_hasdata`, `val_nodata_zonecut`,
  `val_bogus_nodata`, `val_nx`, `val_nx_nodeny`, `val_nx_nowc`,
  `val_nodatawc_badce`, `val_ans_nx`, `val_anchor_nx_nosig`,
  `iter_cname_nx`, `nsec_name_error_response-part2`,
  `nsec_ref_to_unsigned1` to `3`.
- The NSEC3 scenarios that pass with #871.
- Scenarios whose answer section holds records of qtype owned by another name
  (§12): no longer used. The full set shows them.
- `black_ent` fails today and is not expected to change: its denial for the
  empty non-terminal carries no SOA, so `ValidateDenial` never sees it.

## 17. Staging and size

| PR | Content | Lines, code + tests |
|---|---|---|
| 1 | Part B (§11) | ~60 + 200 |
| 2 | Part A: `wildcard_answer.go`, the signature loop factored out, `Set`, the resolver paths (§4–§9), `revalidateGlueRR` | ~390 + 800 |

- PR 1 touches `ValidateDenial`'s NSEC branch only, and can land first.
- PR 2 needs #871. If #871 has merged by then, `main` is merged into the
  branch.
- This document goes into PR 2 as its last commit, its status naming both
  PRs, with a dated amendment for anything the code does differently.
- About 1,450 lines, two thirds of them tests.

## 18. Open questions

- **Q1. Several expansion signatures** that name different signers, or
  disagree on Labels. Proposed: the one that validates decides. Unbound calls
  RRSIGs that disagree on Labels bogus.
- **Q2. A forwarder that leaves the proof out.** Proposed: Bogus, as from an
  authoritative server. A per-zone option would let an operator take such an
  upstream's verdict instead, as `trust-ad` does.
- **Q3. The scanner.** Its child data synthesized from a wildcard validates
  Bogus without the authority section (§12). Accept that, or have `askChild`
  return the authority section so the scanner can call `ValidateAnswer`?
- **Q4. NOERROR proved by the name error shape** stays Secure (§11, step 3).
  RFC 4035 §5.4 lists no such NODATA proof. Make it Bogus?
- **Q5. The name error shape and empty non-terminals.** It reads an NSEC
  whose next name is below qname as a cover. That NSEC shows qname is an
  empty non-terminal. Should an NXDOMAIN proved with it be Bogus, as the
  wildcard answer check (§3.2) has it?
- **Q6. Two PRs, B first,** or one PR with both parts.

## 19. Amendment, 2026-10-01: decisions and the implementation

The sections above are the design as proposed. This is what was decided,
and how the code differs.

### 19.1 Decided

- **Three PRs**, not two (§17):
  - #872: §4.1 alone, `handleAnswer` building the answer from the records
    owned by the name asked for. Based on `main`.
  - #873: part B (§11), with Q5. Based on `main`: it needs nothing from
    #871. Merged with #871, it conflicts in a few return statements of the
    NSEC branch, which #871 rewrites as `DenialVerdict`. The resolution is
    mechanical.
  - #874: part A, on #871, with #872 merged in. This document is its last
    commit.
- **Own zones are not held to the proof.** An answer the resolver takes from
  a zone the server is authoritative for is the server's own data
  (`AnsweredLocally`, which asks `ownZoneForQuestion`, as `answerFromOwnZone`
  does). The
  side effect of §8 and §12, wildcard answers from an own zone signed
  elsewhere with NSEC3 validating Bogus, does not happen.
  `TestOwnNSEC3ZoneWildcardAnswerValidates` serves such a zone.
- **Q1:** as designed. The signature that validates decides; signatures over
  the owner are tried first.
- **Q2:** a forwarder that leaves the proof out gets Bogus. No per-zone
  option.
- **Q3:** the scanner validates with the authority section (§19.2). The
  scanner side effect of §12 does not happen.
- **Q4:** left as it is.
- **Q5:** yes. An NXDOMAIN whose covering NSEC has a next name below the name
  asked for is no name error proof: the name is an empty non-terminal, and
  exists (#873).
- **`val_nsec3_cnametocnamewctoposwc`** is a skip-list candidate (§16.2).
  `skip.txt` is not changed in these PRs.
- #873 also removes the package-level `nsecCoversName` in
  `v2/dnslookup.go`, which nothing called.

### 19.2 How the code differs

- **#871 moved** to 03430fbc before #874 was built on it. The line
  references above are to 57b5a87e.
- **The scanner** (Q3): `AuthQueryEngine` keeps the authority section of
  every authoritative answer, not only of an empty one
  (`AuthQueryResponse.authority`, was `denial`). `securedChildRRsetFetcher`
  validates the glue it copies with it (`requireSecureAnswer`,
  `validateChildData` calls `ValidateAnswer`). The CDS, CDNSKEY, CSYNC and
  DNSKEY checks validate apex data, which no wildcard synthesizes, and pass
  none.
- **`ValidateRRsetWithParentZone`** has its verdict reuse and its signature
  loop factored out (`reusableVerdict`, `validateSignatures`), so the
  wildcard path can use both. Nothing else in it changes.
- **A CNAME chain answer** carries EDE 27 once, when both a part and the
  denial at its end carry it.
- **Tests, against §14:**
  - `TestForwardedWildcardAnswers` is §14.3's
    `TestWildcardAnswerThroughTheResolver` and `TestForwardedWildcardAnswer`
    in one: NSEC3 through a forwarder.
  - `TestWildcardAnswerWithAnNSECProof` is the NSEC half, iterative through
    a stub.
  - `TestOwnNSEC3ZoneWildcardAnswerValidates` replaces
    `TestOwnZoneWildcardAnswerValidates`.
  - `TestAnAnswerWithEDE27IsServedBesideIt` replaces the new rows in
    `TestFreshAndCachedAnswersAgree`.
  - New: `TestScannerValidatesWildcardGlueWithItsProof`, and in
    `TestCNAMEChainThroughWildcards` a link held Indeterminate that is
    validated again with its kept proof.
  - `TestAnAnswerOwnedByAnotherNameIsNotUsed` and the other owner tests are
    in #872. #872 also changes `TestResponderRefusesAnOutOfBailiwickSigner`:
    an answer owned by a name in the signer's zone is SERVFAIL without an
    EDE, as those records are not part of the answer.
  - `TestRRSIGSignerMustHoldTheOwner` judges its wildcard case by the
    signature alone, and `TestAuthQueryEngineKeepsTheProofOfANodata` expects
    an answer's authority section to be kept.
- **Mutation checks:** every check of §14.4 fails its test, and so do those
  for the scanner, the chain parts and own zones (the lists are in #872,
  #873 and #874). One line is not reached by a test with a different
  outcome: the fresh path validating again, with the kept proof, an entry
  whose verdict is not reusable. That entry's verdict has just been reached.

### 19.3 Deckard

Full resolver set, `nsec3-max-iterations: 150`, failing runs:

| Build | Failing runs |
|---|---|
| `main` (9d9d34b3) | 75 |
| #872 | 79; on reruns only `val_faildnskey` (both variants) differs from `main` |
| #873 | 74 |
| #871 (03430fbc) + #870 | 52 |
| #874 + #870 | 50 |
| #874 + #870 + #873 | 47 |

- **#872:** `val_faildnskey`'s answer section holds www's A next to an RRSIG
  owned by another name; www's own RRSIG is in the additional section. The A
  is now unsigned data in a zone under a trust anchor, and the resolver asks
  for www's DS, which the scenario does not script. The answer, SERVFAIL, is
  as it was.
- **#873:** `nsec_wildcard_no_data_response` (both variants) and
  `val_mal_wc` pass.
- **#874:** `val_nsec3_b4_wild`, `val_nsec3_optout_ad`, `val_iter_high` and
  `nsec_wildcard_answer_response` (both variants) pass, as §16.1 expects.
- **`val_wild_pos_multi`** fails at step 102 with #873, not at step 110 as
  §16.1 has it. The rcode is right now; the authority section is not. The
  scenario's denial has an SOA with TTL 0. Such a denial is stored already
  expired, and the fresh path reads a denial's entry with `Get`, which drops
  it, so the SOA is not served. That is outside these PRs. Step 110 then
  needs the library fix of §15.
- Every other difference between builds was a run that timed out
  (`iter_badglue`, `iter_timeouted_ns`) or failed on the harness (Errno 99
  or 22), and passes on a rerun.
