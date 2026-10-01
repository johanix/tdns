# tdns-imr: NSEC3 validation

**Written 2026-09-30.** Line references are to main at `9d9d34b3`.

**Status:** stages 1 and 2 implemented in #871; P0 in #870. Stage 3 is
not implemented.

**Revisions:**
- **r1**, 2026-09-30: the proposal, approved the same day with the decisions
  in §11.
- **Amended 2026-09-30** (§12): how the implementation differs, and the
  Deckard results.

## Summary

- **Today.** `ValidateNegativeResponse` validates NSEC denials only. A
  denial proved with NSEC3 comes out Indeterminate once its records'
  signatures validate (`v2/cache/rrset_validate.go:1224-1232`). It is served
  without AD, so denials from NSEC3-signed zones are not authenticated. Most
  TLDs sign with NSEC3.
- **Already there.** `nsec3CutProof` (`delegation_proof.go:185-276`) reads
  NSEC3 for one question: is there an insecure delegation at a name (RFC 5155
  §8.9)? Referrals and DS denials use it.
- **Proposal.**
  1. An NSEC3 core in `v2/cache/nsec3.go`: which records count, hashing,
     match and cover, the closest encloser proof, and the proofs of RFC 5155
     §8.4–§8.8 (§2).
  2. `ValidateNegativeResponse` uses it. A proof through an Opt-Out span is
     Insecure (no AD). A proof over the iteration limit is Insecure with EDE 27
     (§3, §4).
  3. `nsec3CutProof` moves onto the core, with the same rules (§2.8).
  4. The exception that serves Indeterminate denials goes. A signed denial
     that validates Indeterminate, on a resolver with trust anchors, is
     SERVFAIL with EDE 5, as a positive answer already is (§6). This applies to
     NSEC zones too (§7).
  5. §8.8, for wildcard answers, is a function the positive answer path can
     call. Calling it is a separate stage (§10).
- **Size.** About 2,000 lines in two PRs, a bit over half of it tests (§10).
- **Deckard.** 18 of the 23 target scenarios first need a small fix that is
  not NSEC3 work (P0, §9.5). With it, 17 are expected to pass after stages 1
  and 2, and 21 after stage 3. Two need aggressive use of cached denials (RFC
  8198), which tdns-imr does not have.

## 1. What the code does today

### 1.1 Denials

- `handleNegative` (`dnslookup.go:3685`) groups the authority section into
  RRsets (`authorityRRsets`, `:3652`) and calls `ValidateNegativeResponse`
  (`:3805`).
- `ValidateNegativeResponse` (`rrset_validate.go:1048`):
  - needs an SOA, and the qname must be at or below it (`:1092-1101`);
  - with no signatures at all, the verdict is `unsignedDenialState` (`:1106`);
  - validates every signed RRset. A Bogus or Indeterminate RRset decides. An
    Insecure one sends the denial to `unsignedDenialState` (`:1120-1157`);
  - NSEC: RFC 4035 §5.4 and RFC 9824 (`:1159-1222`);
  - NSEC3: Indeterminate once the records validate (`:1224-1232`);
  - neither: Insecure with an error, and `handleNegative` does not use the
    answer.
- The entry is cached with the SOA as its RRset and the whole authority
  section as `NegAuthority` (`dnslookup.go:3845-3858`).

### 1.2 Cut proofs

- `cutProof` (`delegation_proof.go:163`) and `nsec3CutProof` (`:197`) read
  what a referral or a DS denial proves about a zone cut at a name:
  - a matching NSEC3 with NS and neither DS nor SOA: an insecure delegation;
  - a closest encloser proof whose next closer name is covered by an Opt-Out
    NSEC3: an insecure delegation;
  - records over `maxNSEC3Iterations` (150, `:19`) and nothing else:
    unjudged, and the zone below is Indeterminate.
- Only records owned directly below a zone above the name, signed by that
  zone, and validating Secure, count.
- It uses `dns.NSEC3.Match` and `dns.NSEC3.Cover`.
- `denialEvidence` (`unsigned_rrset.go:342`) reads a cached DS denial with
  `cutProof` when its verdict is Secure or Indeterminate. A Bogus or Insecure
  one is bogus evidence.
- `ValidateDNSKEYs` gives a zone the state of its DS entry when that is not
  Secure, after `dsCacheIsInsecureCut` (`rrset_validate.go:720-745`).

### 1.3 Serving denials

- `bogusDenial` (`imr_answer_verdict.go:91`): SERVFAIL with EDE 6 for a Bogus
  denial, unless the client set CD.
- `negativeAD` (`:78`): AD only for Secure, and only to a client that can take
  it (`adWanted`).
- Indeterminate is served, without AD. The comment at `:73-77` gives the
  reason: every NSEC3 proof is Indeterminate, and SERVFAIL would fail every
  NXDOMAIN from an NSEC3-signed zone.
- Positive answers follow another rule (`dispositionFor`, `:45`): a signed
  RRset that is Indeterminate, on a resolver with trust anchors, is SERVFAIL
  with EDE 5.
- A DO client gets `NegAuthority` back (`appendNegAuthorityToMessage`,
  `imrengine.go:1588`). A client without DO gets the SOA only. The proof's
  TTLs are the entry's remaining lifetime.

## 2. RFC 5155 section 8

A new file, `v2/cache/nsec3.go`. Pure functions over records that have
already validated: no cache access, no network. `ValidateNegativeResponse` and
`nsec3CutProof` both use it.

### 2.1 Which records count

A record counts toward a proof only when all of these hold:

- Its RRset is owned directly below the zone Z the proof is about. For a
  denial Z is the SOA's owner. For a cut proof it is the zone above the name,
  as today.
- A signature made by Z validates it Secure (`signedBy`, then
  `ValidateRRset`, as `nsec3CutProof` does). Signatures by other signers do
  not count.
- Hash algorithm 1, SHA-1 (§8.1).
- Flags 0 or 1 (§8.2).
- Hash length 20, and the owner's first label and the next hashed owner both
  decode as base32hex to 20 bytes.
- Iterations at or below the limit (§3). Records above it are set aside, and
  the proof notes that it set them aside.

A record that fails one of these is ignored. That alone does not make the
proof Bogus, but a proof the remaining records do not make is. RFC 5155 §8.1
expects a response with only such records to end up bogus. Unsigned NSEC3
beside a signed SOA, and NSEC3 whose signatures fail, are handled by
`ValidateNegativeResponse`'s loop as today.

### 2.2 Hashing and comparison

- H(name) under a record's parameters is SHA-1 over the name's canonical wire
  form (RFC 4034 §6.2: ASCII upper case folded, nothing else) and the salt,
  then `iterations` more rounds over the digest and the salt (RFC 5155 §5). It
  is written in `nsec3.go` over `crypto/sha1`, and stays 20 bytes.
- Each record's owner hash and next hash are decoded once. Comparisons are
  `bytes.Compare` on digests. Case in the owner label or in `NextDomain` does
  not matter.
- **matches(name):** some record's owner hash equals H(name) under that
  record's parameters.
- **covers(name):** H(name) lies strictly between a record's owner hash and
  its next hash:
  - owner < H < next;
  - for the last record of the chain (next ≤ owner): H > owner or H < next;
  - for a chain of one record (owner = next): every hash but its own.
- `dns.NSEC3.Match` and `Cover` are not used:
  - each call hashes the name again;
  - `Cover`'s lower bound includes the owner, so a name that matches a record
    also reads as covered by it;
  - they compare presentation strings, with the owner folded to upper case
    and `NextDomain` taken as it comes.
- A memo per proof, keyed by canonical name and parameters (algorithm,
  iterations, salt): each name is hashed once per parameter set.
- The work is bounded (§8).

### 2.3 Several parameter sets in one response

- Each record is hashed with its own parameters. A response that mixes two
  parameter sets, from a zone changing its NSEC3PARAM, is read record by
  record.
- RFC 5155 §8.2 allows a validator to call such a response bogus. That is not
  proposed: each record is a signed statement about its own chain, and the
  only cost is hashing, which §8 bounds (Q4).
- The closest encloser search looks for a match before a cover. A name that
  one set matches and another covers is taken to exist.

### 2.4 Closest encloser proof (§8.3)

For qname in zone Z:

1. Walk from qname up to Z. The first name with a matching record is the
   closest encloser, CE. No match up to and including Z: no proof.
2. The next closer name, NC, is the name one label below CE on the way to
   qname. A record must cover it, or there is no proof. This is §8.3's
   algorithm: every name below CE on the way was not matched.
3. CE's record has DNAME: Bogus.
4. CE's record has NS and not SOA: CE is a delegation and qname lies below it.
   - Without DS: CE is an insecure delegation (§8.9, RFC 6840 §4.4), and the
     answer is Insecure. The proof ends there.
   - With DS: Bogus. The answer should have been a referral.
5. The result is CE, NC, and the record covering NC, with its Opt-Out flag.

A proof that qname does not exist (name error, wildcard answer) also needs
CE ≠ qname.

### 2.5 Name error (§8.4)

- A closest encloser proof for qname, with CE ≠ qname.
- A record covers the wildcard at CE, `*.CE`.
- The record covering NC has Opt-Out: Insecure (§9.2). Otherwise Secure.
- Anything missing: Bogus.

### 2.6 No data (§8.5, §8.6, §8.7)

In order:

1. **A record matches qname.**
   - Its bitmap has qtype or CNAME: Bogus.
   - qtype DS (§8.6): Secure.
   - Another qtype, and the bitmap has NS and not SOA: qname is a delegation,
     and the parent side answered for the child's data. Insecure without DS
     (an insecure delegation), Bogus with DS.
   - Otherwise Secure (§8.5). An empty bitmap is an empty non-terminal.
   - The matching record's own Opt-Out flag does not matter. It describes the
     span after the record, not the name it matches.
2. **No match.** A closest encloser proof for qname (§2.4). Without one:
   Bogus. If it ends at an insecure delegation: Insecure for a qtype other than
   DS, Bogus for DS.
3. **A record matches `*.CE`** (§8.7).
   - Its bitmap has qtype or CNAME: Bogus.
   - NS and not SOA: Bogus. A wildcard is not a delegation.
   - The record covering NC has Opt-Out: Insecure (§9.2). Otherwise Secure.
4. **The record covering NC has Opt-Out:** Insecure.
   - For DS this is §8.6's Opt-Out case.
   - For other types, qname may lie below an insecure delegation in the
     Opt-Out span, and its unsigned data can reach the resolver by other paths
     (a forwarder, a CNAME chain). The response proves nothing more, and gets
     no AD. Deckard's `val_nsec3_b5_wcnodata_nowc` and `val_nsec3_optout_ad`
     (step 10) expect exactly this: NOERROR without AD, not SERVFAIL.
5. Otherwise Bogus.

### 2.7 Wildcard answer (§8.8)

- Input: the zone Z (the answer's RRSIG signer), qname, and L, the RRSIG's
  Labels field, with L < labels(qname).
- CE is qname's last L labels, and NC its last L+1. CE is at or below Z.
- A record must cover NC. With Opt-Out: Insecure. Without: Secure. None:
  Bogus.
- Exported for the positive answer path:

  ```go
  // NSEC3WildcardProof reports what the NSEC3 RRsets in authority prove about
  // an answer for qname that zone synthesised from a wildcard (RFC 5155
  // section 8.8). labels is the Labels field of the answer's RRSIG. The
  // verdict comes with an EDE code: 27 over the iteration limit, else 0.
  func (rrcache *RRsetCacheT) NSEC3WildcardProof(ctx context.Context, zone, qname string,
      labels uint8, authority []*core.RRset, fetcher RRsetFetcher) (ValidationState, uint16)
  ```

  It validates the NSEC3 RRsets as §2.1 says, then runs the check.
- Calling it from the positive answer path is stage 3 (§10), outside this
  document.

### 2.8 Referrals and DS denials (§8.9)

- `nsec3CutProof` keeps its rules (§1.2). Its record filter, hashing and
  comparisons move onto §2.1 and §2.2.
- The only difference in what it concludes comes from §2.2: a strict lower
  bound on cover, and comparison independent of case.

### 2.9 Verdicts

| The proof | Verdict | EDE | AD |
|---|---|---|---|
| holds | Secure | – | to a client that asks for it |
| holds through an Opt-Out span | Insecure | – | no |
| ends at an insecure delegation | Insecure | – | no |
| needs records over the iteration limit | Insecure | 27 | no |
| runs out of the work budget (§8) | Indeterminate | 5, when §6 answers SERVFAIL | no |
| does not hold | Bogus | 6 | – |

## 3. Iterations (RFC 9276)

- **The limit** stays `maxNSEC3Iterations`, 150.
  - A new tuning key, `imrengine.tuning.nsec3-max-iterations`, sets it.
    Default 150. 0 is allowed: only zones with 0 iterations then validate.
  - It is applied as `zone-state-recheck` is: `cache.SetNSEC3MaxIterations` at
    start and on reload. `imrTuningEqual` and the tuning API learn the key.
- **Above the limit.** RFC 9276 §3.2 lets a validator answer insecure, or
  SERVFAIL. Proposed: insecure.
  - Records are set aside only after their signatures validate. RFC 9276
    requires that, so the iteration count is the zone's own.
  - Denial: when the remaining records prove it, their verdict stands. When
    they do not, and records were set aside: Insecure with EDE 27
    ("Unsupported NSEC3 Iterations Value"). When nothing was set aside: Bogus.
  - Cut proof: unchanged, unjudged, and the zone below is Indeterminate.
    §5.3 keeps `ValidateDNSKEYs` in step with that (Q2).
  - Wildcard answer: Insecure with EDE 27.
- **Why insecure.** A zone with many iterations keeps working, and its
  denials lose AD. Deckard's `val_iter_high` expects that.
- **EDE 27** joins the standard codes in `edns0_ede.go`. On a denial it is
  served beside the answer (`attachNegativeEDE`). `dispositionFor` treats any
  EDE on a positive entry as a failure, so stage 3 must carry EDE 27 on a
  positive answer some other way.

## 4. AD semantics

- AD only for Secure, as today (`negativeAD`, and the `State == Secure` tests
  in `serveNegativeResponse`).
- No AD when the proof relies on an NC covered by Opt-Out (RFC 5155 §9.2):
  name error, DS no data without a match, wildcard no data, §2.6 case 4, and
  wildcard answers.
- AD for a proof by a matching record, even when that record has Opt-Out set.
  `val_nsec3_b21_nodataent` expects AD from a matching record with flags 1.
- Opt-Out and over-limit denials are Insecure, rather than Secure with a
  separate "no AD" flag. Every place that sets AD on a denial tests for
  Secure: `imrengine.go:1196`, `:1232`, `:1712`, `:1728`, `:1739`, `:1750`,
  `:1780`, and the chain in `imr_cname_chain.go:385`. Insecure keeps AD off at
  all of them without touching any. A flag would have to reach every one.

## 5. Storing and serving

### 5.1 What is stored

- `handleNegative` already keeps the whole authority section, NSEC3 and
  RRSIGs included, as `NegAuthority`, and a DO client gets it back. That is
  what RFC 5155 §9.1 asks of a caching resolver. Nothing is added for NSEC3.
- New: an EDE (27) with the verdict. `ValidateNegativeResponse` gets a sibling
  that returns it, and `handleNegative` stores it in `EDECode` and `EDEText`:

  ```go
  type DenialVerdict struct {
      State   ValidationState
      Rcode   uint8
      EDECode uint16
      EDEText string
  }

  func (rrcache *RRsetCacheT) ValidateDenial(ctx context.Context, qname string, qtype uint16,
      rcode uint8, negAuthority []*core.RRset, fetcher RRsetFetcher) (DenialVerdict, error)
  ```

  `ValidateNegativeResponse` stays, as a wrapper, for its other callers and
  tests.
- NSEC3 records are not cached under their own hashed names, and nothing is
  synthesised from them (RFC 8198). Out of scope.

### 5.2 Validating again on a cache hit

- A positive entry held Indeterminate is validated again when it is served
  (`serveCachedPositive`, `imr_answer_verdict.go:127`). A denial is not.
  After §6 a signed denial held Indeterminate is SERVFAIL, so a chain that
  could not be followed when the denial was cached would fail the name for the
  whole negative TTL.
- Proposed: a signed denial held Indeterminate is validated again on a hit,
  unless the client set CD (`ValidateDenial` over `NegAuthority`). Its State
  and EDE are updated in place, without extending its life, as
  `MarkRRsetBogus` does (`rrset_cache.go:1365-1375`).
- Only Indeterminate. State None marks a DNSKEY denial that `handleNegative`
  did not validate, and it stays as it is.

### 5.3 Reading a DS denial

- `denialEvidence` (`unsigned_rrset.go:342`) calls an Insecure DS denial
  bogus evidence. An Opt-Out DS denial is now Insecure (§2.6 case 4), and it is
  the ordinary proof of an insecure delegation below an NSEC3 parent
  (`val_nsec3_b3_optout`). So:
  - Bogus: bogus evidence, as today.
  - Insecure: `nsec3CutProof` over `NegAuthority`. An Opt-Out span gives an
    insecure cut, records over the limit unjudged. Nothing: bogus evidence, as
    today.
  - Only `nsec3CutProof`, not `cutProof`: the NSEC branch keeps its reading of
    an Insecure denial.
  - An unsigned denial, or one whose records validated Insecure, has no
    records that validate Secure, so it ends as before.
  - `nsec3CutProof` validates the records itself, so the entry needs no flag.
- `ValidateDNSKEYs` (`rrset_validate.go:727-745`) gives a zone its DS entry's
  state when that is not Secure. An over-limit DS denial is now Insecure. That
  would make the zone Insecure, where `belowSecureZone` and
  `ReferralChildState` make it Indeterminate. `ValidateDNSKEYs` reads the
  evidence first, and unjudged keeps the zone Indeterminate, as today.

## 6. Indeterminate denials: what replaces the exception

- The reason in `negativeAD`'s comment goes away: NSEC3 proofs validate.
  Indeterminate then means for a denial what it means for a positive answer:
  the chain could not be followed.
- Proposed: denials follow `dispositionFor`'s rule. `bogusDenial` becomes
  `imr.denialDisposition(c, msgoptions) (servfail bool, ede uint16)`:
  - Bogus: SERVFAIL, EDE 6, as today.
  - Indeterminate, signed (an RRSIG anywhere in `NegAuthority`), on a resolver
    with trust anchors (`hasTrustAnchors`): SERVFAIL, EDE 5.
  - CD set: served, whatever the verdict, as today.
  - Everything else: served, with AD from `negativeAD`.
- `writeBogusDenial` takes the EDE. One helper serves the fresh path
  (`imrengine.go:1507-1540`), the cache (`:1178-1236`) and the end of a CNAME
  chain (`imr_cname_chain.go:374`), so fresh and cached answers still agree
  (`TestFreshAndCachedDenialsAgree`).

| Denial | Today | Proposed |
|---|---|---|
| Secure | served, AD if asked for | same |
| Insecure: unsigned zone, insecure delegation, Opt-Out, over the limit | served | same, with EDE 27 over the limit |
| Indeterminate, unsigned | served | same |
| Indeterminate, signed, no trust anchors | served | same |
| Indeterminate, signed, trust anchors | served, no AD | SERVFAIL, EDE 5 |
| Bogus | SERVFAIL, EDE 6 | same |
| any verdict, CD set | served | same |
| DNSKEY denial (State None, EDE 9) | served | same |

- After this work a signed denial is Indeterminate, on a resolver with trust
  anchors, when:
  - the signer's keys could not be obtained, or not followed to an anchor (a
    DNSKEY or DS fetch that failed, a zone held Indeterminate below a Secure
    one);
  - an NSEC3 proof ran out of the work budget (§8).

## 7. Behaviour changes for NSEC-signed zones

- **Changed**, because NSEC3 support removes the reason for the exception:
  - §6: a signed NSEC denial held Indeterminate, on a resolver with trust
    anchors, is SERVFAIL with EDE 5. It was served without AD.
  - §5.2: such a denial is validated again on a cache hit.
  - Both go in a commit of their own.
- **Unchanged:**
  - the NSEC rules in `ValidateNegativeResponse`;
  - `cutProof`'s NSEC branch;
  - `denialEvidence` for NSEC denials (§5.3 reads only NSEC3 for Insecure
    ones);
  - `ValidateDNSKEYs` for NSEC parents: unjudged only arises from NSEC3.
- **Differences left in place:**
  - No data at a delegation (a matching record with NS and not SOA): the NSEC3
    path answers Insecure or Bogus (§2.6), the NSEC path reads such an NSEC as
    ordinary no data.
  - A DS denial made at the child's own apex (the SOA's owner is the qname):
    both paths accept it as no data. For NSEC3 that is RFC 5155 §8.6 as
    written, which checks the DS and CNAME bits only (Q6).

## 8. Performance and limits

- **Hash cost**, measured with `dns.HashName` on the machine this document was
  written on: 0.27 µs per name at 0 iterations, 0.6 µs at 12, 5.7 µs at 150.
- **Names hashed per proof:**
  - no data by a matching record: 1;
  - name error: one per label from qname up to CE, plus the wildcard;
  - wildcard answer: 1.
- **Memo per proof** (§2.2). No hash cache across responses: at these costs it
  would not pay for its eviction.
- **Work budget:** at most 256 hash computations per proof, about 1.5 ms at
  150 iterations on the same machine. That covers a qname 127 labels deep
  under two parameter sets. Over the budget the proof is Indeterminate, and §6
  answers SERVFAIL with EDE 5 (Q3).
- **Iterations:** §3. **Parameter sets:** not counted, bounded by the budget.
- **Signatures:** one check per NSEC3 RRset, as today. At low iteration counts
  they cost more than the hashing.
- **Benchmark:** `BenchmarkNSEC3NameError` at 0, 12 and 150 iterations, in
  PR 1.

## 9. Test plan

### 9.1 The core, against RFC 5155 Appendix A and B

- **Hash vectors.** Every H() of Appendix A (salt `aabbccdd`, 12 iterations),
  among them H(example) = `0p9mhaveqvm6t7vbl5lop2u3t2rp3tom` and H(*.w.example)
  = `r53bq7cc2uvmubfu5ocmm6pers9tk9en`. Also the same name in upper case, and a
  label with an escaped octet that must not be folded.
- **The Appendix B responses.** The Appendix A chain as records in zone
  `example.`, all with Opt-Out as in the RFC:

  | Case | Question | Records | Verdict |
  |---|---|---|---|
  | B.1 | a.c.x.w.example A, name error | `0p9m` covers NC, `b4um` matches CE, `35mt` covers `*.x.w` | Insecure; Secure with flags 0 |
  | B.2 | ns1.example MX | `2t7b` | Secure |
  | B.2.1 | y.w.example A | `ji6n`, empty bitmap | Secure |
  | B.4 | a.z.w.example MX, wildcard answer, L = 2 | `q04j` covers z.w | Insecure; Secure with flags 0 |
  | B.5 | a.z.w.example AAAA | `k8ud` CE, `q04j` NC, `r53b` `*.w` | Insecure; Secure with flags 0 |
  | B.6 | example DS | `0p9m`, SOA set | Secure (§8.6 as written, Q6) |

  B.3, the referral to c.example through Opt-Out, runs through
  `nsec3CutProof`: an insecure cut.
- **Each case with one record taken out, altered or added.** Bogus unless
  noted:
  - B.1 without the CE record, without the NC cover, without the wildcard
    cover; with a record that matches qname;
  - B.2 with MX, or CNAME, in the bitmap; B.2.1 with the wrong record
    (`35mt`);
  - B.5 without CE, without NC; without the wildcard record: Insecure through
    Opt-Out, Bogus with flags 0;
  - DS no data with no match, and an NC cover without Opt-Out;
  - CE with DNAME; CE with NS and no SOA: Insecure, and Bogus with DS;
  - a no-data match with NS and no SOA: Insecure, and Bogus with DS;
  - the wildcard record with qtype, CNAME, or NS without SOA.
- **Which records count.** Hash algorithm 2, flags 2, hash length 19, an
  owner label that is not base32hex, a record owned in another zone: each is
  ignored, so the proof that needed it is Bogus.
- **Comparison.** A name whose hash equals an owner hash is matched, not
  covered. The last record of the chain covers past the wrap. A chain of one
  record. Owner and next hash in lower, upper and mixed case.
- **Iterations.** A proof at the limit validates. Above it: Insecure, EDE 27.
  Mixed records where those within the limit prove the case. The limit set
  to 0.
- **Parameter sets.** A proof from records of two sets. A name one set matches
  and the other covers.
- **Memo and budget.** Hashes are counted per proof: each name once per
  parameter set. A qname deep enough to run out at 150 iterations is
  Indeterminate, and the same qname at 0 iterations is not.

### 9.2 The validator (`v2/cache`)

With the existing signing helpers (`newZoneKey`, `secCache`, `soaFor`,
`nsec3In`):

- `ValidateDenial` on signed B-style denials: the verdicts of §9.1, and EDE 27.
- NSEC3 signed with a key the zone does not have: Bogus. Signed by the zone
  above the SOA's: ignored. Unsigned beside a signed SOA: ignored. From a zone
  held Insecure: `unsignedDenialState`, as today.
- An over-limit record signed with a key the zone does not have: Bogus, not
  Insecure. The signature is checked before the iteration count.
- `denialEvidence`: an Opt-Out DS denial (Insecure) is an insecure cut, an
  over-limit one unjudged, an unsigned Insecure one bogus evidence as today.
- `ValidateDNSKEYs` below an over-limit DS denial: Indeterminate.
- Existing tests whose comments say that NSEC3 validates Indeterminate
  (`rrset_validate_test.go:397`, `delegation_proof_test.go:155`,
  `imr_answer_verdict_test.go:284`) get new comments. Their expectations stay
  unless they relied on it.

### 9.3 Through the resolver (`v2`)

The rigs: the forward-validation rig of `imr_forward_validation_test.go` (a
signed upstream double, an anchor on `sec.example.`), and the referral doubles
of `imr_referral_ds_proof_test.go` for the iterative path. `sec.example.` is
NSEC3-signed, with a small chain built in the test.

- NXDOMAIN with a complete proof: NXDOMAIN, AD with DO. The NSEC3 and RRSIGs
  in the authority section with DO, the SOA only without. The same from the
  cache.
- NXDOMAIN through Opt-Out: no AD.
- NXDOMAIN without the wildcard cover: SERVFAIL, EDE 6. With CD: served.
- NODATA, an empty non-terminal, wildcard NODATA: AD.
- A DS denial through Opt-Out: the child is Insecure, its data served without
  AD (extends `TestForwardValidatesASignedZoneWithNoDSAsInsecure`).
- 151 iterations: NXDOMAIN, no AD, EDE 27.
- The signer's DNSKEY unreachable, with a trust anchor: SERVFAIL, EDE 5, fresh
  and cached. Without trust anchors: served. `TestFreshAndCachedDenialsAgree`
  splits its Indeterminate rows into signed and unsigned.
- Cache hit: the first ask is Indeterminate (DNSKEY unreachable). With the
  DNSKEY reachable again, the second ask is Secure, with AD.
- Every existing NSEC test passes unchanged: `imr_stripped_denial_test.go`,
  `imr_denial_answer_test.go`, `negative_proof_test.go`,
  `nsec_coverage_test.go`, the compact denial tests.

### 9.4 Mutation checks

Each check is taken out, one at a time, and the named test must fail. The PR
lists the outcome for each.

| Check | Test that fails |
|---|---|
| hash algorithm 1 only | which records count: algorithm 2 |
| flags 0 or 1 only | which records count: flags 2 |
| hash length, base32hex | which records count: length 19, bad label |
| owned directly below Z | which records count: another zone |
| signed by Z | validator: signed by the zone above |
| cover's strict lower bound | comparison: hash equal to owner |
| cover across the wrap | comparison: last record |
| case-independent digests | comparison: lower and mixed case |
| NC covered | B.1 without NC |
| wildcard covered (name error) | B.1 without the wildcard cover |
| CE ≠ qname (name error) | B.1 with a record matching qname |
| CE without DNAME | CE with DNAME |
| CE with NS needs SOA | CE with NS: Insecure / Bogus |
| qtype and CNAME bits (no data) | B.2 with MX, with CNAME |
| NS without SOA at a match | no-data match with NS |
| DS without a match needs Opt-Out | DS no data, cover without Opt-Out |
| wildcard record bits | wildcard record with qtype, CNAME, NS |
| Opt-Out makes it Insecure | B.1, B.4, B.5 with flags 1 against flags 0 |
| a match's Opt-Out flag is ignored | B.2.1 (flags 1, Secure) |
| over-limit set aside, EDE 27 | iterations tests |
| signature before iterations | over-limit record with a stray key |
| work budget | budget test |
| memo | hash count test |
| `denialEvidence` reads Insecure NSEC3 | Opt-Out DS denial |
| `ValidateDNSKEYs` keeps unjudged Indeterminate | below an over-limit DS denial |
| Indeterminate, signed, anchors: SERVFAIL | resolver: DNSKEY unreachable |
| unsigned, or no anchors: served | resolver: the split verdict rows |
| validate again on a hit | resolver: cache hit test |
| State None not validated again | `TestFreshAndCachedDenialsAgree`, DNSKEY missing |
| EDE 27 stored and served | resolver: 151 iterations |

### 9.5 Deckard

- **P0, a precondition that is not NSEC3 work.** 18 of the 23 scenarios give
  tdns-imr a DNSKEY trust anchor below the root (`example.`,
  `example.com.`). `ValidateDNSKEYs` looks for the anchored zone's DS before
  it tries the anchor's keys, and fetches it when it is not cached
  (`backfillDS`, `rrset_validate.go:713`). The scenarios script no answer to
  that question, so they fail on an unscripted query whatever the validator
  concludes. The proposed fix: a zone with a DNSKEY trust anchor tries the
  anchor's keys before any DS is looked up or fetched. `proofNames` already
  skips the DS of an anchored zone (`unsigned_rrset.go:156-166`). It changes
  behaviour for every zone anchored below the root, and so is its own small
  PR and issue.
- **The target scenarios.** Stage numbers are §10's.

  | Scenario | What it tests | Needs | Expected |
  |---|---|---|---|
  | `val_nsec3_b1_nameerror` | B.1 through Opt-Out: NXDOMAIN, no AD | P0; stage 2 keeps it | pass |
  | `val_nsec3_b1_nameerror_noce` | B.1 without CE: SERVFAIL | P0, stage 2 | pass |
  | `val_nsec3_b1_nameerror_nonc` | B.1 without NC: SERVFAIL | P0, stage 2 | pass |
  | `val_nsec3_b1_nameerror_nowc` | B.1 without the wildcard cover: SERVFAIL | P0, stage 2 | pass |
  | `val_nsec3_b21_nodataent` | B.2.1, empty non-terminal: AD | P0, stage 2 | pass |
  | `val_nsec3_b21_nodataent_wr` | B.2.1 with the wrong record: SERVFAIL | P0, stage 2 | pass |
  | `val_nsec3_b2_nodata` | B.2: AD | P0, stage 2 | pass |
  | `val_nsec3_b2_nodata_nons` | B.2 without NSEC3: SERVFAIL | P0 | pass |
  | `val_nsec3_b3_optout` | B.3 referral through Opt-Out | P0; stage 1 keeps it | pass |
  | `val_nsec3_b3_optout_negcache` | B.3; the DS query is not scripted | P0; stage 1 keeps it | pass |
  | `val_nsec3_b3_optout_noce` | B.3 without CE: SERVFAIL | P0; stage 1 keeps it | pass |
  | `val_nsec3_b3_optout_nonc` | B.3 without NC: SERVFAIL | P0; stage 1 keeps it | pass |
  | `val_nsec3_b4_wild` | B.4, wildcard answer through Opt-Out: no AD | P0, stage 3 | pass after stage 3 |
  | `val_nsec3_b5_wcnodata` | B.5 through Opt-Out: no AD | P0; stage 2 keeps it | pass |
  | `val_nsec3_b5_wcnodata_noce` | B.5 without CE: SERVFAIL | P0, stage 2 | pass |
  | `val_nsec3_b5_wcnodata_nonc` | B.5 without NC: SERVFAIL | P0, stage 2 | pass |
  | `val_nsec3_b5_wcnodata_nowc` | B.5 without the wildcard: no AD, not SERVFAIL | P0; stage 2 keeps it (§2.6 case 4) | pass |
  | `val_nsec3_cnametocnamewctoposwc` | a CNAME chain through two wildcards, proofs in the authority section, AD | P0, stage 3 | pass after stage 3 |
  | `val_nsec3_optout_ad` | Opt-Out: no AD on NODATA, DS, NXDOMAIN, wildcard answer, wildcard NODATA | stage 2 (steps 10–50, 80–90), stage 3 (60–70) | pass after stage 3 |
  | `val_iter_high` | 65535 iterations: NXDOMAIN and a wildcard answer without AD | stage 2 keeps step 22; stage 3 (31–32) | pass after stage 3 |
  | `nsec3_wildcard_no_data_response` | NXDOMAIN with a complete NSEC3 proof: AD | stage 2 | pass |
  | `nsec3_aggr_cache` | answers synthesised from cached NSEC3 (RFC 8198) | aggressive use | no: skip-list candidate |
  | `nsec_aggr_cache` | the same with NSEC | aggressive use | no: skip-list candidate |

- **Counts.** After P0 alone, 8 pass. After P0 and stages 1–2, 17. After
  stage 3, 21. `nsec_aggr_cache` is an NSEC scenario, listed for completeness.
- **Regressions.** Each run singly, before and after:
  - the NSEC3 scenarios that pass today: `val_deleg_nons`,
    `val_nsec3_entnodata_optout_badopt`, `val_nsec3_nods_badsig`,
    `val_nsec3_nods_soa`, `val_nsec3_noopt_ref`, `val_nsec3_optout_ns_ad`,
    `val_nsec3_optout_unsec_cache`;
  - the scenarios that pass today and end in a denial, because §6 changes
    when a denial is served (Q7).

## 10. Staging and size

| Stage | PR | Content | Lines, code + tests |
|---|---|---|---|
| P0 | its own | §9.5: a DNSKEY-anchored zone does not ask for its DS | ~30 + 60 |
| 1 | PR 1 | `nsec3.go` (§2.1–§2.7), `nsec3CutProof` on it (§2.8), the EDE 27 constant, the benchmark | ~400 + 650 |
| 2 | PR 2 | `ValidateDenial` (§2.5, §2.6, §3), the tuning key, §5, and §6 in a commit of its own | ~350 + 600 |
| 3 | separate | §2.7 on the positive answer path | outside this document |

- PR 1 changes no verdict except through §2.2, and can land first. It makes
  `nsec3CutProof` the core's first user.
- PR 2 is the visible change.
- Each PR: `go vet ./...` and `go test ./...` in all seven v2 modules, the
  mutation checks of §9.4, and the Deckard runs of §9.5.
- About 2,000 lines for PRs 1 and 2, a bit over half of them tests.

## 11. Open questions

- **Q1. The iteration limit.** 150 as today, configurable. RFC 9276 asks
  validators to lower their limits over time. A lower default, or a second,
  higher limit above which the answer is SERVFAIL?
- **Q2. Cut proofs over the limit.** They stay unjudged, and the zone below
  Indeterminate. RFC 9276 would allow calling the zone Insecure, which serves
  a signed child with no DS instead of failing it.
- **Q3. The work budget.** 256 hash computations per proof, and
  Indeterminate, so SERVFAIL, over it.
- **Q4. Mixed parameter sets.** Read record by record (§2.3), or Bogus as RFC
  5155 §8.2 allows?
- **Q5. EDE for a proof that does not hold.** 6 (DNSSEC Bogus), as the NSEC
  path, or 12 (NSEC Missing) when a record is missing?
- **Q6. A DS denial from the child's apex.** Accepted by both paths today, and
  by §2.6 (RFC 5155 §8.6 as written). Rejecting it, for NSEC and NSEC3 alike,
  would be a change of its own.
- **Q7. Deckard coverage for §6.** A single-scenario run of every scenario
  that passes today and ends in a denial, or one full run.
- **Out of scope:** stage 3; RFC 8198 aggressive use of NSEC and NSEC3; the
  NSEC3 form of RFC 9824 compact denial (an NSEC3 matching qname with only
  NXNAME reads as no data under §8.5, which is what the upstream rcode says,
  and `CompactDenialNXDOMAIN` stays NSEC only).

**Decided 2026-09-30:**
- Q1: configurable as proposed, with a default of 10, not 150 (§12).
- Q2: over-limit cut proofs stay unjudged, the zone below Indeterminate.
- Q3: 256 hash computations per proof.
- Q4: record by record.
- Q5: EDE 6.
- Q6: left as it is, out of scope.
- Q7: one full Deckard set per build, besides single scenarios.

## 12. Amendment, 2026-09-30: the implementation

Implemented in #871 (stages 1 and 2) and #870 (P0). The sections above
are the design as approved; this is how the code differs.

- **The iteration limit defaults to 10** (`cache.DefaultNSEC3MaxIterations`),
  not 150, and `imrengine.tuning.nsec3-max-iterations` raises it. RFC 9276
  asks zones for 0 iterations, and deployed zones rarely use more than a few.
  §3, §8 and Q1 read 150 as the default; everything else in them holds.
  - RFC 5155's example zone uses 12 iterations, so the tests built on
    Appendix A and B set their limit explicitly.
    `TestValidateDenialNSEC3DefaultLimit` keeps the default and finds a
    12-iteration proof Insecure with EDE 27.
  - The Deckard template sets the limit to 150: the scenarios predate RFC
    9276, and most NSEC3 ones use the example zone. `val_iter_high` (65535
    iterations) still takes the path over the limit.
  - The work budget (§8) is still 256 hash computations. With a limit of 10,
    it costs far less than the 1.5 ms §8 gives for 150.
- **§6: SERVFAIL only below a trust anchor.** A signed denial held
  Indeterminate is SERVFAIL when a trust anchor is at or above its zone, the
  SOA's owner (`UnderTrustAnchor`), not on any resolver with a trust anchor.
  Outside an island of security the chain has nothing to lead to, and such a
  denial is served, as before. Deckard's `val_anchor_nx_nosig` has the zone
  above an anchored `sub.example.com.` deny a name below it, and expects the
  NXDOMAIN. The first version of §6 made it SERVFAIL.
- **§2.1: NSEC3 signed by another zone.** In a denial, an NSEC3 RRset owned
  below the SOA's zone is validated with that zone's signatures alone, and
  counts. Any other NSEC3 RRset is validated as before, so a signature that
  fails still fails the denial, and never counts.
- **§8: one budget check per proof**, where the budget can run out: in the
  closest encloser walk and when a proof fails (finish), and after the walk in
  `nsec3CutProof`. The outcomes are as designed.
- **§9.1: the budget test** runs a deep qname under three parameter sets. The
  budget counts hash computations, not iterations, so "the same qname at 0
  iterations" does not make the difference.
- **§9.4: the mutation checks.** 51 checks, each taken out on its own; each
  fails its test. The list is in #871. The design's table maps onto it;
  the additions are the default limit, the tuning key (default, reload, the
  way to the cache), the anchor above the zone in §6, the Insecure DS denial
  without valid records, and `NSEC3WildcardProof`.
- **§2.7: `NSEC3WildcardProof`** is implemented as designed, and nothing
  calls it.
- **§9.5: Deckard**, against main's full run (75 failing runs), each build a
  full set; the NSEC3 builds with the template's limit of 150:

  | Build | Failing runs | Target scenarios passing |
  |---|---|---|
  | P0 alone | 65 | 8 |
  | NSEC3 alone | 72 | 1 (`nsec3_wildcard_no_data_response`) |
  | NSEC3 and P0 | 54 | 17 |

  - The 17 are the ones §9.5 expects after stages 1 and 2. `world_cz_rhybar`
    passes too.
  - Stage 3's four (`val_nsec3_b4_wild`, `val_nsec3_cnametocnamewctoposwc`,
    `val_nsec3_optout_ad`, `val_iter_high`) fail only at their wildcard answer
    steps. The steps before them, denials through Opt-Out and over the
    limit, pass. `nsec3_aggr_cache` and `nsec_aggr_cache` fail as expected.
  - The seven NSEC3 scenarios that passed before still pass.
  - Every other change against main's run failed on the harness (Errno 99)
    or on a timeout (`iter_timeouted_ns`, `iter_badglue`), and passes on a
    rerun.

