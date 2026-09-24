# Negative answers from the zone's own data: a design for #770

**Written 2026-09-25.** For #770 and #771. Line references are to main at
`0847c04e`.

**Status:** proposal, not reviewed. Nothing implemented.

## Summary

- **What goes wrong.** Every negative answer to a DO query is built by one
  function, `addCDEResponse`. It makes up an NSEC at the query name and signs
  it with the zone's key. A zone that this server does not sign has no key,
  so the made-up NSEC goes out unsigned. Two kinds of zone are hit today:
  - **A plain secondary of a zone signed elsewhere (#770).** It answers
    NOERROR for a name that does not exist, with an unsigned NSEC, while the
    signed chain it transferred sits unused. Validators answer SERVFAIL (§1.1).
  - **An unsigned zone.** It gets the same unsigned NSEC and the same NOERROR.
    Nothing is validated here, so a resolver caches NODATA for a name that
    does not exist. Filed as #771 (§1.2).
- **Two related gaps.**
  - A zone signed here without `black-lies` has a stored chain and does not
    use it either. The guide defines `black-lies` as the option that turns
    the chain off (§1.3).
  - A secondary of an NSEC3 zone has the §1.1 problem, and also treats every
    hashed NSEC3 owner name as a name that exists (§1.4).
- **One case already works.** A signed wildcard answer carries the stored
  NSEC that covers the query name (89199fa8). That NSEC goes out with the
  signature it arrived with, so this works on a secondary too (§2).
- **Proposal.** Decide once per response where the zone's denials come from,
  based on the zone's options and the pinned snapshot. Then build every
  negative answer from that source (§3):

  | Zone | Denial |
  |---|---|
  | signed here, with `black-lies` | compact denial, synthesized and signed per response, as today |
  | has a stored NSEC chain | the chain's own records, with their stored signatures (RFC 4035 §3.1.3) |
  | unsigned | no NSEC at all, and NXDOMAIN for a name that does not exist |
  | signed, but no chain this server can read | the rcode and the signed SOA, no proof, and one warning per serial |

- **Stages.**
  1. Zones not signed here: the #770 secondary and the unsigned zone.
  2. Zones signed here without `black-lies` answer from their chain.
  3. NSEC3 on secondaries (§4).

  Stages 1 and 2 are small. Stage 3 is about as big as the other two
  together.
- **Size:**
  - Stage 1: about 250 lines of non-test code and 500 of tests.
  - Stage 2: about 20 lines, plus a rework of existing tests.
  - Stage 3: about 400 lines and 600 of tests (§9).

## 1. What goes wrong

Measured on `0847c04e` with a throwaway test. It drives `QueryResponder`
with DO set and CO clear, against one zone of each kind. The RRSIGs in the
test zones are placeholders; the responder does not verify them.

### 1.1 A secondary of a pre-signed zone (#770)

The zone holds a complete NSEC chain with RRSIGs, as transferred.

| Query | Answer today | Should be |
|---|---|---|
| `nx A` | NOERROR; SOA + RRSIG; `nx NSEC \000.nx NSEC RRSIG NXNAME`, no RRSIG | NXDOMAIN; SOA + RRSIG; the stored NSEC that covers `nx`, and the one that covers `*.<apex>`, with their RRSIGs |
| `www TXT` | NOERROR; SOA + RRSIG; `www NSEC \000.www A RRSIG NSEC`, no RRSIG | NOERROR; SOA + RRSIG; `www`'s stored NSEC with its RRSIG |
| `foo A`, where `*` holds only TXT | NOERROR; an unsigned NSEC at `foo` listing TXT | NOERROR; the NSEC that covers `foo` and the wildcard's own NSEC |
| `foo TXT`, where `*` holds TXT | the expanded TXT, and the stored NSEC that covers `foo`, signed | unchanged, already right |

The chain is already in the snapshot, ready to use:
- zone load puts each NSEC and its RRSIG on the owner's `NSEC` property
  (`v2/dnsutils.go:927`, `:938`);
- IXFR keeps that property current (`v2/ixfr_in.go:285`, `:364`, `:449`).

### 1.2 An unsigned zone (#771)

| Query | Answer today | Should be |
|---|---|---|
| `nx A` | NOERROR; SOA; `nx NSEC \000.nx NSEC RRSIG NXNAME`, no RRSIG | NXDOMAIN; SOA |
| `www TXT` | NOERROR; SOA; `www NSEC \000.www A RRSIG NSEC`, no RRSIG | NOERROR; SOA |

A validator can prove this zone insecure, so it takes the rcode as it is. It
reads the NXDOMAIN as NODATA for the queried type and caches that for the
negative TTL. DNSSEC-aware resolvers set DO on every query they send (RFC
3225 §3, as RFC 9824 §5 notes). So this affects every nonexistent name in
every unsigned zone the server holds, seen through any modern resolver.

`TestUnsignedZoneWithoutKeyDBAnswersDO`
(`v2/negative_proof_signing_test.go:106`) asserts today's answer. That test
came with 0a705f6b, to stop an unsigned zone without a KeyDB from answering
SERVFAIL. Its denial assertion records the behaviour the author found; it
was not a design decision.

### 1.3 A zone signed here without `black-lies`

The signer builds an NSEC chain for such a zone (`v2/sign.go:733`, `:967`)
and keeps it correct at every publish (`v2/nsec_restitch.go`). Its
secondaries receive that chain. Its own negative answers ignore the chain:
they are compact denials, synthesized and signed per response. That is
valid DNSSEC, but:

- **It is not what the option says.** The guide
  (`guide/config-tdns-auth.md:450`) and the sample configuration
  (`cmdv2/auth/auth-templates.sample.yaml:146`) describe `black-lies` as
  synthesizing an NSEC "instead of returning the zone's precomputed NSEC
  records". So a zone without it should serve the precomputed records.
- **Every negative answer costs a signature.** That is expensive for a
  post-quantum algorithm.
- **The primary and its secondaries answer the same query differently.**
  And querying the primary shows nothing of the chain's defects
  (`docs/2026-08-22-nsec-chain-correctness.md` §1).

Neither this repository's sample configurations nor tdns-mp set
`black-lies`, so this is how every signing zone configured from them
behaves.

### 1.4 A secondary of an NSEC3 zone

Nothing in the authoritative code reads NSEC3. The records land in `RRtypes`
at their hashed owner names (the `default` arm, `v2/dnsutils.go:954`). As a
result:

- negative answers get the same unsigned synthesized NSEC as in §1.1;
- a hashed owner name answers as a name that exists. `<hash> A` is NODATA,
  with a synthesized NSEC whose bitmap lists NSEC3. RFC 5155 §7.2.8 requires
  a Name Error response.

## 2. Why

Every negative answer goes through `addCDEResponse`
(`v2/queryresponder.go:1421`) or its referral counterpart `addReferralNSEC`
(`:1369`):

| Site | Call |
|---|---|
| name does not exist, `sendNXDOMAIN` | `:525` |
| owner node with no records and no descendants | `:1262` |
| type does not exist, `sendTypeNodata` (also ANY with nothing to serve, and wildcard NODATA) | `:631` |
| empty non-terminal, `sendENTNodata` | `:548` |
| DS at an insecure delegation | `:350` |
| DS at an in-zone name | `:367` |
| DS at our apex, parent not hosted | `:444` |
| referral to an insecure delegation | `:484` |

`addCDEResponse` always builds its NSEC at the query name. Outside CO it
sets NOERROR (`:1442-1446`), under a TODO for "proper traditional NSEC
generation". It adds the NSEC to the message and then hands it to the
signing function. `signRRsetForZone` (`:167`) returns it unchanged for a
zone that has neither online- nor inline-signing (`:177-183`).

The wildcard proof is the exception (`addWildcardProof`,
`v2/wildcard_proof.go:39`, 89199fa8). For a zone without `black-lies`:
- it finds the stored NSEC that covers the query name, through an index of
  the chain's owners in canonical order;
- each snapshot builds that index the first time it is needed (`nsecOwners`
  and `nsecCoveringFrom`, `:86` and `:103`);
- it serves the NSEC with the signature it arrived with.

In the measurement above, a pre-signed zone's wildcard answer carried the
right NSEC and RRSIG. This design extends that mechanism to the other cases.

## 3. Design

### 3.1 Where a zone's denials come from

The source is decided once per response. For a zone this server signs, its
options decide. For any other zone, the pinned snapshot does:

| Row | Zone | Test | Denial source |
|---|---|---|---|
| A | signed here | `black-lies` | compact denial, synthesized and signed per response: today's `addCDEResponse` |
| B | signed here | no `black-lies` | its own NSEC chain (stage 2; until then, A) |
| B | not signed here | the apex has an NSEC | the chain's records, with their stored RRSIGs |
| C | not signed here | the apex has NSEC3PARAM | NSEC3 records (stage 3; until then, D) |
| D | not signed here | the apex SOA has RRSIGs | none: the rcode and the signed SOA |
| E | not signed here | none of the above | none: the rcode and the SOA |

- **"Signed here"** is the test `signRRsetForZone` already uses:
  `online-signing` or `inline-signing`.
  - `black-lies` on a zone not signed here changes nothing, because there is
    no key to sign a synthesized NSEC with.
  - A config-check warning for that combination costs little (Q6).
- **Row D** covers two cases, neither of which can be answered correctly:
  - a secondary of a zone whose primary uses compact denial: there is no
    chain to transfer, and without the key the secondary cannot synthesize
    one;
  - an NSEC3 zone before stage 3.

  In both, a non-validating client at least gets the right rcode.
- **Row E** is the unsigned zone. It answers a DO query exactly as it answers
  one without DO.
- **Cost:** the tests are lookups at the apex of the pinned snapshot, which
  the responder already holds. They are cheap enough to run on every
  response.

### 3.2 What each negative answer carries

For row B, following RFC 4035 §3.1.3:

| Case | Proof records | Rcode |
|---|---|---|
| name does not exist | the NSEC covering qname, and the NSEC covering `*.<closest encloser>`; once if they are the same record | NXDOMAIN |
| type does not exist | qname's own NSEC | NOERROR |
| empty non-terminal | the NSEC covering qname, whose next name lies below qname | NOERROR |
| wildcard match, type does not exist | the NSEC covering qname, and the wildcard owner's own NSEC; once if they are the same | NOERROR |
| wildcard answer | the NSEC covering qname (`addWildcardProof`, unchanged) | NOERROR |
| DS at an insecure delegation, or a referral to one | the parent chain's NSEC at the cut | NOERROR |
| DS at our apex, parent not hosted | the apex's own NSEC | NOERROR |

- **Signatures.** Each record goes out with the RRSIGs stored with it. Every
  negative answer also carries the SOA, with its RRSIGs in every row except
  E.
- **Empty non-terminal.** Validators accept an NSEC that covers the name and
  whose next name is a descendant of it as proof of an empty non-terminal.
  RFC 4035 §3.1.3.2 notes that empty non-terminals fall under this form, and
  RFC 9824 §3.2 contrasts it with the compact form.
- **Lookups.** Both already exist:
  - `wildcardSourceFrom` (`v2/zone_snapshot.go:106`) computes the closest
    encloser and returns `*.<closest encloser>` for a name that does not
    exist. It stops at empty non-terminals, as RFC 4592 requires.
  - `nsecCoveringFrom` finds the covering record, and is used unchanged.
- **Rows D and E** carry the SOA (with its RRSIGs in D) and nothing else.
- **Row A** keeps today's answers (see §7 on #593).

### 3.3 Rcode and CO

The rcode is set according to the denial source, no longer inside
`addCDEResponse`:

- **Row A:** as today. NOERROR for a name that does not exist, unless the
  query set CO (RFC 9824 §3.1, §5.1).
- **Rows B to E:** NXDOMAIN for a name that does not exist, whether or not CO
  is set. CO asks for NXDOMAIN to be restored next to a compact denial. These
  answers are not compact denials, so there is nothing to restore.

The CO flag in the response is echoed as today (`respondEDNS`).

### 3.4 A proof record that is not there

A chain can lack a record that an answer needs. Examples: a transfer that
omitted it, an NSEC without an RRSIG, a zone in the middle of a key or
denial transition.

- **Not signed here (rows B to D):** serve what the zone holds (the SOA and
  whichever proof records exist) and warn (§3.6).
  - This matches the positive path, which serves a stored RRset without
    RRSIGs as it is for such a zone (`:177-183`).
  - A SERVFAIL would also take the right rcode away from non-validating
    clients. A validator gets nothing from it that the missing proof does not
    already tell it: either way, the resolver treats this server's answer as
    bad.
- **Signed here (row B, stage 2):** the zone is ours and broken, so answer
  SERVFAIL, as `ErrZoneUnsigned` does for stored data without signatures
  (`v2/queryresponder.go:106`). Never synthesize an NSEC in its place: that
  would hide the defect again (Q3).

### 3.5 Code shape

- **A new file, `v2/denial.go`:**
  - `denialSourceFor(zd, snap)` implements the table in §3.1.
  - `addDenial(m, snap, apex, q, msgoptions, signFunc) error` is the single
    entry point for every negative answer.
    - `q` names the case from §3.2 and carries what that case needs: qname,
      the owner, the wildcard owner, or the cut.
    - It sets the rcode, adds the SOA's RRSIGs and adds the proof from the
      zone's source.
    - Its error keeps today's meaning: a denial that must be signed and
      cannot be. The caller turns it into a SERVFAIL with
      `failUnsignedDenial`, as now.
- **`addCDEResponse` and `addReferralNSEC`** become the row A builders and
  nothing else. The rcode handling moves out of `addCDEResponse` into
  `addDenial`.
- **The eight sites in §2** call `addDenial` instead.
- **`sendReferral`** takes the snapshot as a new argument, so it can find the
  NSEC at the cut. All three callers already have one (`:394`, `:1192`,
  `:1281`).
- **`addWildcardProof`** asks `denialSourceFor` instead of testing
  `black-lies` itself.
- **`signRRsetForZone` and `isSynthesizedDenial`** are unchanged. Stored
  records never pass through them: a stored NSEC carries its RRSIGs, or §3.4
  applies.

In stage 1, `denialSourceFor` returns A for every zone signed here. Stage 2
changes only that: it returns B when `black-lies` is off.

### 3.6 Warnings

- **When:** on a snapshot's first negative answer, if the source is row D,
  or if a proof record is missing (§3.4).
- **How often:** once per snapshot, guarded by a `sync.Once` on the snapshot,
  like the chain index. A warning per query would flood the log at resolver
  rates. Once per serial is enough to show that a zone is broken or not
  supported.
- **Contents:** the zone, the serial, and the reason: no chain, NSEC3 not yet
  supported, or the first name the zone could not prove.

## 4. NSEC3 (stage 3)

This is a sketch, to be worked out in detail when the stage is scheduled.

- **Parameters.** Take them from the apex NSEC3PARAM (RFC 5155 §7.3). If
  there are several, pick one, and use only the NSEC3 records with those
  parameters.
- **Index.** Build a per-snapshot index of hashed owners, sorted by hash, on
  first use, like the NSEC index. Once case is folded, the base32hex label
  sorts in the same order as the hash. The pinned `miekg/dns` fork has
  `HashName`, `(*NSEC3).Cover` and `(*NSEC3).Match`.
- **Responses** follow RFC 5155 §7.2.1 to 7.2.7:
  - the closest encloser proof;
  - Name Error with the wildcard cover;
  - NODATA with the matching NSEC3;
  - DS NODATA and insecure referrals, including the Opt-Out forms;
  - wildcard NODATA and wildcard answers.
- **Queries for NSEC3 owner names (§7.2.8).** A hashed owner name with
  nothing at or below it gets a Name Error response. The query path has to
  stop treating an owner that holds only NSEC3 as a name. The records stay in
  the owner map, so zone transfers, the zone file and ZONEMD still include
  them.
- **Hash collisions (§7.2.9).** A query name whose hash collides with an
  existing NSEC3 owner gets SERVFAIL.
- **Cost.** A negative answer hashes up to one name per label, each at the
  zone's iteration count. RFC 9276 recommends zero additional iterations. A
  zone with many is expensive to serve, as it is for every NSEC3 server.

## 5. Stages

| Stage | What | Changes answers for |
|---|---|---|
| 1 | §3 for zones not signed here: rows B, D and E, with C answered as D | secondaries of signed zones (#770), and unsigned zones (#771) |
| 2 | zones signed here without `black-lies` answer from their chain | every signing zone without `black-lies` |
| 3 | NSEC3 on secondaries | secondaries of NSEC3 zones |

- Each stage is one PR.
- Stage 1 depends on neither of the others.
- Stage 2 is separate so that its timing can be chosen. It is the documented
  behaviour, but it changes the answers of every signing primary configured
  without `black-lies`.

## 6. Alternatives

- **Serve stored NSECs on secondaries and change nothing else.** This
  covers the #770 case only. The unsigned zone would still answer NODATA for names that do
  not exist, and the signing zone would still contradict its own option. The
  source table costs no more than the special case would.
- **Synthesize on the secondary as well.** Impossible: a secondary has no
  private key, which is the whole issue.
- **SERVFAIL when a secondary cannot prove a denial.** This is consistent
  with the signing side, but it has the costs described in §3.4.
- **Synthesize an NSEC when a zone signed here has a gap in its chain.** This
  hides the gap. That is how the defects described in
  `2026-08-22-nsec-chain-correctness.md` stayed hidden (its §1).

## 7. Relation to other work

- **#593 (NXNAME in the bitmap regardless of CO).** Not changed here, and it
  should not be combined with this work.
  - RFC 9824 §3.1 says the bitmap of a compact denial for a nonexistent name
    "MUST only have the bits set for" RRSIG, NSEC and NXNAME. It sets no
    condition on CO; CO governs only the rcode (§5.1).
  - #593 asks for NXNAME to be left out when CO is clear, so it has to be
    settled against the RFC on its own.
  - Row A keeps today's bitmap either way.
- **The wildcard proof (89199fa8)** is reused as it stands. The only change
  is that it asks `denialSourceFor`.
- **`docs/2026-08-22-nsec-chain-correctness.md`.**
  - Its §1 says that a secondary answers denials from the chain it received.
    For a tdns-auth secondary, that is only true once stage 1 is in.
  - Stage 2 makes the primary serve its chain too. That document's point is
    that querying the primary proves nothing about the chain; after stage 2,
    it does.
- **#547 (restitch cost, owner storage order).**
  - The covering lookup needs the canonical-order index that each snapshot
    builds on first use: one sort of the chain's owners per published serial.
  - The wildcard proof already pays that cost. Stage 1 makes the first
    negative answer of every serial pay it.
  - An ordered snapshot (#547) would remove the cost.
- **The IMR** (`negativeRcode`, `v2/imrengine.go:1455`) chooses the rcode
  based on whether an answer is a compact denial. Answers from a chain do not
  affect it.
- **tdns-mp** runs signing zones without `black-lies`. After the re-pin that
  brings stage 2, those zones answer from their chain. The re-pin should say
  so.

## 8. Tests

Test what a validator gets, not just the function that builds the answer:
1. Sign a zone with the tdns signer (`signedProofZone`,
   `v2/wildcard_proof_test.go:104`).
2. Load its records into a second zone with no signing options: a secondary.
3. Check each negative answer the way a validator does:
   - the RRSIGs verify against the zone's DNSKEY;
   - the NSECs prove the claim. Extend the existing checks
     (`unboundProvesWildcard`, `:65`) to Name Error, NODATA and empty
     non-terminal proofs.

**Stage 1:**
1. Name does not exist: NXDOMAIN, with the qname cover and the wildcard cover
   each included once and signed. Include a case where the two are the same
   record.
2. Type does not exist: the owner's NSEC, and its bitmap does not list the
   qtype.
3. Empty non-terminal: NOERROR, with the covering NSEC whose next name is
   below qname.
4. Wildcard match, type does not exist: the qname cover and the wildcard's
   own NSEC.
5. DS at an insecure cut, a referral to an insecure delegation, DS at an
   in-zone name, and DS at our apex with the parent not hosted.
6. Each of 1 to 5 with CO set: the same proofs, NXDOMAIN where 1 has it, and
   the CO flag echoed.
7. Unsigned zone, with and without a KeyDB: NXDOMAIN with no NSEC, and NODATA
   with no NSEC. `TestUnsignedZoneWithoutKeyDBAnswersDO` changes to assert
   this.
8. Signed zone with no chain (row D): the rcode, the SOA and its RRSIG, no
   NSEC, and one warning per serial.
9. A secondary whose chain has a gap: what exists is served, the rcode is
   right, and one warning is logged.
10. Zones signed here are unchanged in stage 1: the existing compact-denial,
    empty non-terminal and unsignable-denial tests pass as they are.
11. On a running server, the #770 reproduction: a tdns-auth secondary of a
    zone signed by another signer, queried through a validating resolver.
    Name Error and NODATA answers validate instead of failing with SERVFAIL.

**Stage 2:**
- A zone signed here without `black-lies` answers cases 1 to 6 from its
  chain, with no signing at query time.
- With `black-lies`, the answers are unchanged.
- A gap in the zone's own chain gives SERVFAIL.
- Existing tests that build an online-signing zone and expect a synthesized
  denial either set `black-lies` or are changed to expect the chain.

**Stage 3:**
- Each RFC 5155 §7.2 case, with and without Opt-Out.
- A hashed owner name gets a Name Error response.
- A zone with two NSEC3PARAM records.

## 9. Size

| Stage | Non-test code | Tests |
|---|---|---|
| 1 | about 250 lines: `denial.go` about 180, the call sites about 60, the snapshot's warning about 10 | about 500 |
| 2 | about 20 | about 150 to 250, mostly changes to existing tests |
| 3 | about 400 | about 600 |

## 10. Questions

| # | Question | Recommendation |
|---|---|---|
| Q1 | Change the unsigned zone's DO answer (§1.2, #771) in stage 1, together with #770? | Yes. It is the same code and the same fix, and resolvers cache the wrong answer. |
| Q2 | Stage 2: should zones signed here without `black-lies` answer from their chain? | Yes. That is what the option is documented to mean. Make it a separate PR, timed apart from stage 1. |
| Q3 | A gap in the chain of a zone signed here: SERVFAIL, or synthesize? | SERVFAIL (§3.4). |
| Q4 | A gap in the chain on a secondary: serve what exists, or SERVFAIL? | Serve what exists, and warn (§3.4). |
| Q5 | NSEC3: stage 3 of #770, or an issue of its own? | An issue of its own. #770 is reproduced with NSEC, and the §7.2.8 defect (§1.4) exists today whatever happens here. |
| Q6 | `black-lies` on a zone not signed here? | Ignore it, as today, and add a config-check warning. |

## 11. Not in scope

- Row A's answers (compact denial), including #593's bitmap question (§7).
- Wildcard answers under compact denial. RFC 9824 §3.3 signs them as exact
  matches; tdns proves them with a synthesized cover instead (89199fa8). Both
  validate.
- TTLs. Stored proof records keep the TTLs they arrived with.
- Showing the denial source in `zone desc`. This is a small addition once
  `denialSourceFor` exists.
