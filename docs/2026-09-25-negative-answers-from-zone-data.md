# Negative answers from the zone's own data: a design for #770

**Written 2026-09-25.** For #770 and #771. Line references are to main at
`0847c04e`.

**Status:** merged as #772, after an external review (sound) and a
re-review (merge). Stage 1 is merged as #774 (1c82e9cd), after a review
(merge) (§12). Stage 2 is merged as #775, after a review (merge after
#774) (§13). #770 and #771 are closed; NSEC3 (#773) is still open.

**Revisions:**
- r1 2026-09-25: first version (PR #772).
- r2 2026-09-25: §7 gains the cost of the chain index and the relation to
  #547, and Q7 is new.
- r3 2026-09-25: the review's S1–S3 and C1–C3 are applied (§3.4–§3.6), and
  §10 records its answers. NSEC3 is now #773. §8 item 10 is corrected: the
  existing compact-denial tests run on unsigned zones, so stage 1 has to move
  them.
- r4 2026-09-25: the re-review's answer to Q7 is recorded, with where the
  index is built (§3.5, §10), and the §3.2 wildcard-answer row is corrected.

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
    hashed NSEC3 owner name as a name that exists (§1.4, #773).
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
  3. NSEC3 on secondaries, tracked as #773 (§4).

  Stages 1 and 2 are small. Stage 3 is about as big as the other two
  together.
- **Size:**
  - Stage 1: about 260 lines of non-test code and 600 of tests, including
    moving the existing compact-denial tests.
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

This is tracked as #773. Stage 1 already improves the first point: it
answers such a zone as row D (§3.1), so a missing name gets NXDOMAIN and the
signed SOA instead of an unsigned NSEC. The second point is left to #773.

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
| C | not signed here | the apex has NSEC3PARAM | NSEC3 records (#773; until then, D) |
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
  - an NSEC3 zone, until #773.

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
| wildcard answer | the NSEC covering qname (`addWildcardProof`, changed as in §3.5) | NOERROR |
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

The rcode follows the denial source:

- **Row A:** as today. NOERROR for a name that does not exist, unless the
  query set CO (RFC 9824 §3.1, §5.1). The rule stays where it is, in
  `addCDEResponse`.
- **Rows B to E:** NXDOMAIN for a name that does not exist, whether or not CO
  is set; `addDenial` sets it. CO asks for NXDOMAIN to be restored next to a
  compact denial. These answers are not compact denials, so there is nothing
  to restore.

The CO flag in the response is echoed as today (`respondEDNS`).

### 3.4 A proof record that is missing or wrong

A chain can lack a record that an answer needs. Examples: a transfer that
omitted it, or a zone in the middle of a key or denial transition.

A record that is there but does not prove the claim counts as missing, and
is not attached to the answer:
- a NODATA owner's NSEC whose bitmap lists the qtype, or CNAME;
- an empty non-terminal's cover whose next name is not below qname;
- a record that does not cover the name it is meant to cover.
  `nsecCoveringFrom` already refuses those.

A stored NSEC without RRSIGs is different. In a zone not signed here it is
served as stored, as a positive RRset without RRSIGs is in such a zone. In a
zone signed here it is broken data, as below.

- **Not signed here (rows B to D):** serve what the zone holds (the SOA and
  whichever proof records exist, as stored) and warn (§3.6).
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
    - It sets the rcode for rows B to E, adds the SOA's RRSIGs and adds the
      proof from the zone's source.
    - Its error keeps today's meaning: a denial that must be signed and
      cannot be. The caller turns it into a SERVFAIL with
      `failUnsignedDenial`, as now.
- **`sendTypeNodata` is two cases of §3.2.** It is called with the name that
  was asked and an owner. `addDenial` tells the two apart by that owner:
  - exact NODATA, where the owner is the query name: the owner's NSEC;
  - wildcard NODATA, where the owner is the wildcard node that matched
    (from `:1316`, `:1334`, and `answerRRSIG` at `:660`): the NSEC covering
    the query name, plus the owner's NSEC (RFC 4035 §3.1.3.4). If both are
    the same record, it goes out once.

  Looking up an NSEC at the query name, as compact denial does, is wrong for
  the wildcard case.
- **`addCDEResponse` and `addReferralNSEC`** become the row A builders and
  nothing else. `addCDEResponse` keeps row A's rcode rule, so
  `TestAddCDEResponseFollowsCO` still applies to it as it is.
- **The eight sites in §2** call `addDenial` instead.
- **The empty-owner NXDOMAIN** (`:1262`) calls `sendNXDOMAIN` instead of
  repeating it, so there is one NXDOMAIN builder.
  - Today that path also checks the SOA. It passes the SOA through the
    signing function, which answers SERVFAIL when a zone signed here has an
    SOA without RRSIGs.
  - `addDenial` makes that check for every negative answer in a zone signed
    here. For a zone whose SOA is signed, this changes nothing.
- **`sendReferral`** takes the snapshot as a new argument, so it can find the
  NSEC at the cut. All three callers already have one (`:394`, `:1192`,
  `:1281`).
- **`addWildcardProof`** asks `denialSourceFor` instead of testing
  `black-lies` itself.
  - It synthesizes a cover (`coverNextCloser`) for row A only. For rows B to
    E it serves the stored cover, and a missing one is handled as in §3.4.
  - Today a stored cover without RRSIGs is skipped, and a cover is
    synthesized in its place. On a secondary, that synthesized cover cannot
    be signed and is dropped (`v2/wildcard_proof.go:71`), so the answer goes
    out with no proof.
  - In a zone signed here without `black-lies` (stage 2), the synthesized
    cover would be signed. It would hide the gap that Q3 says must be a
    SERVFAIL.
- **`signRRsetForZone` and `isSynthesizedDenial`** are unchanged. Stored
  records never pass through them: a stored NSEC carries its RRSIGs, or §3.4
  applies.

- **The chain index is built at publish (Q7).** It is built for a snapshot
  whose apex has an NSEC, just before that snapshot is stored.
  - Snapshots are stored in two places: `publishWorkingSetLocked`
    (`v2/zone_mutation.go:723`) and `InstallInitialSnapshot` (`:1370`).
  - A secondary's refreshes go through the first (`v2/refresh_run.go:169`,
    `v2/refreshengine.go:266`), so the #770 case is covered.
  - Until the new snapshot is stored, queries read the previous one, so no
    query waits for the build.
  - The build runs under the zone lock, so a concurrent update waits instead:
    about 39 ms at 100k owners (§7). For a zone signed here, the restitch
    already does whole-zone work at that point.
  - `nsecOwners` keeps its `sync.Once` as a safety net for any snapshot built
    elsewhere.

In stage 1, `denialSourceFor` returns A for every zone signed here. Stage 2
changes only that: it returns B when `black-lies` is off.

### 3.6 Warnings

- **When:** only when there is something to warn about: the source is row D,
  or a proof record is missing or wrong (§3.4).
  - The snapshot's `sync.Once` is called at that point, not on every
    snapshot's first negative answer.
  - So a row D serial warns on its first negative answer. A row B serial
    whose first negative answers prove fine still warns at its first gap.
- **How often:** at most once per snapshot. A warning per query would flood
  the log at resolver rates. Once per serial is enough to show that a zone is
  broken or not supported.
- **Contents:** the zone, the serial, and the reason: no chain, NSEC3 not yet
  supported, or the first name the zone could not prove.

## 4. NSEC3 (stage 3, #773)

This stage is tracked as #773. What follows is a sketch, to be worked out in
detail there.

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
| 3 | NSEC3 on secondaries (#773) | secondaries of NSEC3 zones |

- Each stage is one PR. Stage 3 belongs to #773, not to #770.
- Stage 1 depends on neither of the others.
- Stage 2 is separate so that its timing can be chosen. It is the documented
  behaviour, but it changes the answers of every signing primary configured
  without `black-lies`:
  - its negative answers come from the stored chain, with no signature made
    at query time;
  - a primary that serves the zone alone can then be walked through its
    chain, as any of its secondaries already can after stage 1;
  - operators who want today's compact denials set `black-lies`. The sample
    configurations are not changed to set it in the same PR: that would keep
    the documentation and the configurations in contradiction.

## 6. Alternatives

- **Serve stored NSECs on secondaries and change nothing else.** This
  covers the #770 case only. The unsigned zone would still answer NODATA for
  names that do not exist, and the signing zone would still contradict its
  own option. The source table costs no more than the special case would.
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
- **The wildcard proof (89199fa8)** is reused. It asks `denialSourceFor`,
  and synthesizes a cover for row A only (§3.5).
- **`docs/2026-08-22-nsec-chain-correctness.md`.**
  - Its §1 says that a secondary answers denials from the chain it received.
    For a tdns-auth secondary, that is only true once stage 1 is in.
  - Stage 2 makes the primary serve its chain too. That document's point is
    that querying the primary proves nothing about the chain; after stage 2,
    it does.
- **#547 (owner storage order).**
  - The covering lookup needs the canonical-order index that each snapshot
    builds on first use. Measured on an Apple M4 with a synthetic zone:
    - 100k owners: 39 ms, 40 MB and 500k allocations;
    - 1M owners: 0.46 s, 400 MB and 5M allocations;
    - the lookup itself, once the index exists: about 0.5 µs.
  - The wildcard proof already pays that cost, but wildcard answers are rare.
    Stage 1 makes the first negative answer of every serial pay it, inside
    the query. Every other query that needs the index on that snapshot waits
    for it.
  - Stage 1 also brings the cost to secondaries, which never needed canonical
    order before.
  - Building the index at publish time, for zones with a chain, takes the
    wait out of the query path (Q7). It leaves the allocation. Removing that
    takes ordered storage shared between snapshots, as #547 proposes; the
    measurements are recorded in a comment there.
  - NSEC3 (#773) also needs an index in hash order, which canonical name
    order does not give.
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
   own NSEC, not an NSEC looked up at the query name (§3.5).
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
10. Zones signed here keep compact denial in stage 1. But several of the
    tests that check compact-denial answers run on unsigned zones, and
    stage 1 changes those zones' answers (#771):
    - the empty non-terminal tests (`v2/empty_nonterminal_test.go`);
    - `TestQueryResponderEchoesCO`, whose NXDOMAIN case for DO without CO
      expects NOERROR;
    - the DO case of `TestHandleDSQueryParentSelection`, which expects a
      synthesized NSEC at the child apex;
    - `TestUnsignedZoneWithoutKeyDBAnswersDO` (item 7).

    Each of these moves to a zone signed here with `black-lies`, signed so
    that its SOA carries RRSIGs (§3.5), and keeps checking what it checks.
    `TestAddCDEResponseFollowsCO` and `TestUnsignableDenialIsServfail` pass
    as they are.
11. On a running server, the #770 reproduction: a tdns-auth secondary of a
    zone signed by another signer, queried through a validating resolver.
    Name Error and NODATA answers validate instead of failing with SERVFAIL.
12. A wildcard answer on a secondary whose covering NSEC has no RRSIG: the
    stored NSEC goes out as it is, and no cover is synthesized (§3.5).
13. A stored record that contradicts the answer, such as a NODATA owner's
    NSEC that lists the qtype, is not attached, and a warning is logged
    (§3.4).
14. A row B serial whose first negative answers prove, and which later hits
    a gap: one warning, logged at the gap (§3.6).
15. The empty-owner name (`:1262`) is still NXDOMAIN after it goes through
    `sendNXDOMAIN`. A zone signed here whose SOA has no RRSIG answers
    SERVFAIL on every negative path (§3.5).

**Stage 2:**
- A zone signed here without `black-lies` answers cases 1 to 6 from its
  chain, with no signing at query time.
- With `black-lies`, the answers are unchanged.
- A gap in the zone's own chain gives SERVFAIL.
- Existing tests that build a zone signed here and expect a synthesized
  denial either set `black-lies` or are changed to expect the chain. No test
  zone may stay signed here without `black-lies` and still expect an NSEC
  owned by the query name. Two fixtures are known to be affected:
  - `qtypesSignedZone` (`v2/queryresponder_qtypes_test.go`): inline-signing
    with a chain, so its negative answers come from the chain;
  - the healthy zone in `TestWildcardAnswerFailClosed`
    (`v2/zone_snapshot_test.go`): online-signing with no chain, so its
    wildcard answer becomes a gap unless it sets `black-lies`.

**Stage 3 (#773):**
- Each RFC 5155 §7.2 case, with and without Opt-Out.
- A hashed owner name gets a Name Error response.
- A zone with two NSEC3PARAM records.

## 9. Size

| Stage | Non-test code | Tests |
|---|---|---|
| 1 | about 260 lines: `denial.go` about 180, the call sites about 60, the snapshot's warning about 10, the index at publish about 10 | about 600, including moving the existing compact-denial tests (§8, item 10) |
| 2 | about 20 | about 150 to 250, mostly changes to existing tests |
| 3 (#773) | about 400 | about 600 |

## 10. Questions

| # | Question | Recommendation | Review, 2026-09-25 |
|---|---|---|---|
| Q1 | Change the unsigned zone's DO answer (§1.2, #771) in stage 1, together with #770? | Yes. It is the same code and the same fix, and resolvers cache the wrong answer. | Agrees. |
| Q2 | Stage 2: should zones signed here without `black-lies` answer from their chain? | Yes. That is what the option is documented to mean. Make it a separate PR, timed apart from stage 1. | Agrees: its own PR, after stage 1. The consequences are in §5. |
| Q3 | A gap in the chain of a zone signed here: SERVFAIL, or synthesize? | SERVFAIL (§3.4). | Agrees. |
| Q4 | A gap in the chain on a secondary: serve what exists, or SERVFAIL? | Serve what exists, and warn (§3.4). | Agrees. |
| Q5 | NSEC3: stage 3 of #770, or an issue of its own? | An issue of its own. #770 is reproduced with NSEC, and the §7.2.8 defect (§1.4) exists today whatever happens here. | Agrees. Filed as #773. |
| Q6 | `black-lies` on a zone not signed here? | Ignore it, as today, and add a config-check warning. | Agrees. |
| Q7 | Build the chain index on first use, as today, or at publish? | At publish, for zones with a chain. Almost every public zone gets negative queries, so the index gets built either way, and at publish the build does not stall a query (§7). | Re-review: agrees. At publish, meaning the moment a snapshot becomes the one `QueryResponder` reads, including a secondary's refresh; for a snapshot whose apex has an NSEC; in stage 1, without waiting for #547. Where it goes is in §3.5. |

## 11. Not in scope

- Row A's answers (compact denial), including #593's bitmap question (§7).
- NSEC3 on secondaries, which is #773 (§4).
- Wildcard answers under compact denial. RFC 9824 §3.3 signs them as exact
  matches; tdns proves them with a synthesized cover instead (89199fa8). Both
  validate.
- TTLs. Stored proof records keep the TTLs they arrived with.
- Showing the denial source in `zone desc`. This is a small addition once
  `denialSourceFor` exists.

## 12. Amendment, 2026-09-25: stage 1 as implemented

Stage 1 follows §3 as written. What the code calls things, and what it
settled:

- `v2/denial.go` holds `denialSourceFor`, `addDenial` (with its `denial`
  descriptor: `denyName`, `denyType`, `denyENT`), `addChainProof`,
  `addReferralDenial` and `prepareDenialIndex`. Rows C and D are one source,
  `denialNoChain`; the warning says which of the two it is.
- `sendTypeNodata` gained the qtype, which the §3.4 check needs: a NODATA
  owner's NSEC must list neither it nor CNAME.
- A zone signed here stays on compact denial in stage 1, including in
  `addWildcardProof`, which keeps today's order for it: the stored cover when
  that is signed, otherwise a synthesized one. The chain branch, with its
  SERVFAIL for a gap, is in place for zones signed here but unreachable until
  stage 2 changes `denialSourceFor`.
- The warning goes through `logDenialGap`, a variable so that tests can count
  the calls.
- `config check` warns about `black-lies` on a zone that is not signed here
  (Q6).

Checked with a validator as well as with the unit tests: a pre-signed
secondary served through `QueryResponder`, queried with `delv` (BIND 9.20)
and the zone's KSK as trust anchor. On main, every negative answer failed
validation, and only the wildcard answer validated. With stage 1, NXDOMAIN
(with one covering NSEC and with two), NODATA, the empty non-terminal,
wildcard NODATA, the wildcard answer, and DS at an insecure cut and at an
in-zone name were all fully validated.

## 13. Amendment, 2026-09-25: stage 2 as implemented

Stage 2 is the change §3.5 describes: `denialSourceFor` returns the chain
(row B) for a zone signed here without `black-lies`, and compact denial only
with it.

- The chain branch that stage 1 put in place for zones signed here is now
  reached: a gap in their own chain is a SERVFAIL (`errDenialUnproven`), and
  it is logged as an error, not as a secondary's once-per-serial warning.
- `addWildcardProof` loses the branch that served a zone signed here its
  stored cover and synthesized one when that was missing. A zone signed here
  now either has a chain (row B, no synthesis) or has `black-lies` and no
  chain (row A, synthesis only).
- Of the existing tests, only the healthy zone in
  `TestWildcardAnswerFailClosed` needed a change: it is online-signing with
  no chain, so it now sets `black-lies`. `qtypesSignedZone` (inline-signing
  with a chain) answers from its chain and its assertions hold unchanged.
- New tests: a zone signed here answers every negative from its chain with no
  KeyDB at all (nothing is signed at query time); with `black-lies` it keeps
  compact denial; and gaps in its own chain are SERVFAILs.
- `guide/config-tdns-auth.md` gains a "Negative answers" section, with the
  source for each kind of zone and how to set `black-lies`.
