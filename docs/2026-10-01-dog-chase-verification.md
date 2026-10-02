# dog +sigchase: a chain walk that checks what a validator checks

**Written 2026-10-01.** Line references are to main at `995c15c6`.

**Status:** items 1-5 and 8 implemented in PR #881; items 6 and 7 implemented
in PR #887, stacked on #881.

**Revisions:**
- **r1**, 2026-10-01: the proposal, approved the same day with the decisions
  in §10 and the conditions in §11.1.
- **Amended 2026-10-01** (§11): how PR 1 differs from r1, its tests and the
  live checks.
- **Amended 2026-10-01** (§12): PR 2, items 6 and 7 and two review findings
  on #881: how it differs from r1, its tests and the live checks.

Refs #876 (all eight items) and #379 (items 3 and 8 cover it).

## Summary

- **Today.** `Chaser.Chase` (`v2/chase.go:112`) judges each candidate zone on
  its own DS/DNSKEY match, and the answer on its RRSIG alone. It keeps records
  of the query type whatever their owner, ignores the rcode, never verifies the
  DS RRset, never reads a denial, and guesses zone cuts from SOA and NS probes.
  Some names come out worse than a validator judges them (a CNAME owner, an
  unsigned delegation, a DS with an algorithm dog lacks), others better (an
  unsigned answer under a signed zone, a wildcard expansion).
- **Proposal.**
  1. One walk per name in the CNAME chain, the answer asked first (§2.2).
  2. A link is no better than the link above it, and its DS RRset is verified
     with that link's keys (§2.1).
  3. A zone cut is read from the DS answer: DS records, a proof of a
     delegation without DS (Insecure), or neither (not a cut). The SOA/NS
     probes go (§2.3).
  4. The answer is judged against the deepest link: its signatures and, for a
     denial or a wildcard expansion, the NSEC/NSEC3 proof (§2.4).
  5. The proof readings are the resolver's: `v2/cache` exports them as
     functions over records whose signatures the caller has checked, and the
     resolver calls the same functions (§4).
- **Staging.** PR 1, on main now: items 1-5 and 8. PR 2, after #873 and #874
  merge: items 6 and 7 (§9).
- **Size.** PR 1 about 1,600 changed lines (650 code, 950 tests); PR 2 about
  750 (300 code, 450 tests).

## 1. The walk today

1. `zoneCutsFromRoot` (`:411`) lists every label from the root to qname as a
   candidate zone; for a DS query qname is dropped (`:126`).
2. Per candidate, a DS query (`queryDSAtParent`, `:315`). With DS records: a
   DNSKEY query, and `cache.ValidateDNSKEYRRsetUsingDS` per DS (`:198-215`);
   no match is Bogus. The DS RRSIGs are fetched and dropped (`:181`). Without
   DS: `isZoneCut` (`:357`) asks SOA and NS; a record in either answer keeps
   the candidate as Indeterminate, "no DS record at parent (and no NSEC proof
   checked)" (`:175`); otherwise it is dropped.
3. The root's DNSKEY RRset is matched against the trust anchor DS (`:216`).
4. The leaf: no records is Indeterminate, "no answer RRs" (`:260`); no RRSIG
   is Insecure (`:271`); otherwise `verifyLeafSig` against the deepest
   candidate's keys (`:375`).
5. `queryRRset` (`:289`) keeps every answer record of the type, any owner,
   and does not look at the rcode. CD is not set.
6. The result is the worst verdict, each computed alone.

Measured on `www.sidn.nl AAAA` (a CNAME to `sidn.nl`): against tdns-imr the
walk ends Indeterminate (the issue's trace); against 1.1.1.1 it ends Bogus,
because the DS query at `www.sidn.nl` is answered with the CNAME and
`sidn.nl`'s DS, which `queryRRset` takes as `www.sidn.nl`'s.

## 2. The walk proposed

### 2.1 Verdicts

`ChainStatus` keeps its values and its order: Secure < Insecure <
Indeterminate < Bogus (`worstStatus`).

**A link** (a zone cut) is `worst(link above, own)`. The root has no link
above. A zone with a configured trust anchor is not capped: the anchor vouches
for it (as #870 has it for the resolver), and one that matches no key stays
Bogus. Own:

- **Secure:** the DS RRset verifies with the keys of the link above (signer is
  that zone, validity window; RFC 4035 §5.2, §5.3.1), and a DS matches a zone
  key that signs the DNSKEY RRset (as today).
- **Insecure:** the NSEC or NSEC3 in the DS denial, verified with the keys of
  the link above, proves a delegation without DS or an Opt-Out span that may
  hold one (item 3); or the verified DS RRset holds no DS dog can use (item 4).
- **Indeterminate:** a query failed (transport error, or an rcode other than
  NOERROR and NXDOMAIN); the link above has no keys; the proof needs NSEC3
  records over the iteration limit; no trust anchor at the root.
- **Bogus:** the DS RRset is unsigned or its signature fails; no usable DS
  matches; the DNSKEY RRset signature fails.

Below an Insecure link nothing is checked: deeper candidates are not asked
about (unless one has a trust anchor), and the answer is Insecure.

**The leaf** is Insecure under an Insecure deepest link. Otherwise it is
`worst(deepest link, own)`:

- An answer: Secure when an RRSIG by the deepest zone verifies with its keys;
  Bogus with no RRSIG (item 5) or none that verifies. A wildcard expansion
  also needs its proof (item 7).
- A denial (NXDOMAIN, NODATA): the proof's verdict (item 6). Secure; Insecure
  through Opt-Out or over the iteration limit; Indeterminate when the hash
  budget runs out; Bogus when the proof is missing, does not hold, or comes
  from another zone.

**The result** is the worst over every link and leaf of every name in the
CNAME chain (RFC 4035 §3.2.3: an answer is authentic only if every RRset in it
is).

### 2.2 Per name: the answer first, then the cuts

For each name in the chain (qname, then each CNAME target):

1. Ask `name qtype`. The answer is read by owner: records of qtype owned by
   name are the answer; failing that, a CNAME owned by name (qtype not CNAME)
   is an alias; failing that, NOERROR is NODATA and NXDOMAIN a name error.
   Any other rcode, or a transport error, is a failed query.
2. Candidates from the root down to name. Name itself is left out when qtype
   is DS (as today) and when name owns a CNAME: a CNAME owner holds no other
   data (RFC 2181 §10.1), so neither the NS of a delegation nor the SOA of an
   apex. That is why the answer comes first, and why the walk does not depend
   on how a resolver answers a DS query at a CNAME owner (#875).
3. Walk the candidates (§2.3), then judge the leaf (§2.4).
4. An alias is judged as the leaf of this name, with qtype CNAME, and the walk
   continues with its target. A loop, or more than `maxCNAMEChain` (11, the
   resolver's limit, `v2/dnslookup.go:3940`) CNAMEs, ends the chain
   Indeterminate.

Each target is asked again, not read from the first response: each hop then
has its own authority section and rcode (RFC 6604). A memo of decided
candidates is shared along the chain, so `www.sidn.nl` then `sidn.nl` asks
about `.`, `nl.` and `sidn.nl.` once.

A CNAME owned by name with no RRSIG, beside a DNAME owned by an ancestor that
synthesizes it, is reported Indeterminate, "synthesized from a DNAME at X;
not followed" (decision 4), not Bogus.

### 2.3 Candidates

The root: its DNSKEY RRset matched against the trust anchor (unchanged). Each
candidate C below the deepest link P so far:

| DS response for C | Decision |
|---|---|
| failed | a link, Indeterminate: "DS query failed: SERVFAIL" |
| a CNAME owned by C | not a cut; dropped, with a note on P |
| DS owned by C | a cut: DS RRset verified with P's keys (item 2), usable DS (item 4), DNSKEY query, match |
| a denial | its NSEC/NSEC3 verified with P's keys, then `cache.ProveDelegation(C, P, ...)`: Insecure is an Insecure link and the walk stops; Unjudged is an Indeterminate link; None or Unproven drops C, with a note on P |

Dropping a candidate without a proof is safe: if C is in fact a cut, the
answer is signed by C's keys or by none, and the leaf check against P comes
out Bogus, never Secure. This replaces `isZoneCut` and its two queries per
name that is not a cut (#379).

A failed DS query stays a link. With today's tdns-imr,
`_443._tcp.www.sidn.nl TLSA` reports "DS query failed: SERVFAIL" at
`www.sidn.nl` (#875); with #875 the CNAME in the DS answer drops it.

### 2.4 Signatures and queries

A signature is checked with one zone's keys in package tdns: `signedByOneOf`
(`v2/dnssec_validate.go:276`, already shared by `ValidateChildDnskeys` and the
delegation coherence check) over the zone's DNSKEYs that have the Zone flag,
plus `cache.SignerHoldsRRset`. Only signatures by that zone count. A leaf
signed by a zone the walk did not reach is Bogus, with the note "signed by X,
which the chain did not reach".

`query(name, qtype) (*dns.Msg, error)` replaces `queryRRset`: DO=1 and CD=1
(RFC 6840 §5.9: a validator sets CD, so the upstream returns what it has and
dog judges it; decision 2), and an error for a transport failure or an rcode
other than NOERROR and NXDOMAIN. Helpers take only the records owned by the
name asked for.

### 2.5 Data model

```go
type ChainLink struct {
	// as today, and:
	DSSigs []*dns.RRSIG // item 2
	// ParentZone becomes the link above, not the label above.
}
type ChainLeaf struct {
	// as today, and:
	Rcode int      // a denial's rcode
	Proof []dns.RR // the NSEC/NSEC3 records a denial or a wildcard answer was judged with
}
type ChainHop struct {
	Links []ChainLink
	Leaf  ChainLeaf
}
type ChainResult struct {
	Qname             string // what was asked
	Qtype             uint16
	TrustAnchorSource string     // item 8
	Aliases           []ChainHop // one per CNAME followed; its leaf is the CNAME
	Links             []ChainLink // the last name in the chain
	Leaf              ChainLeaf   // dog +tlsa reads Leaf.RRset: the final RRset
	Status            ChainStatus
}
// Chaser gains TrustAnchorSource; NewChaser keeps its signature.
```

## 3. The eight items

### Item 1: a CNAME owner taken for a zone cut

- **Now.** `queryRRset` keeps records of the type with any owner and ignores
  the rcode (`:289-312`). A DS SERVFAIL reads as "no DS"; the SOA query is
  answered with the CNAME and the target's SOA, so `isZoneCut` says yes; the
  target's AAAA is checked as the answer.
- **Must.** Count only records owned by the name asked for; any rcode but
  NOERROR and NXDOMAIN is a failed query; a CNAME owner is not a cut; verify
  the CNAME, then walk its target, with a hop limit; the result is the worst.
- **RFC.** RFC 1034 §3.6.2 and RFC 2181 §10.1 (a CNAME owner holds no other
  data); RFC 4035 §3.2.3; RFC 6604.
- **Change.** §2.2, §2.3 and §2.4: `query`, owner filters, the hop loop with
  `maxCNAMEChain` and loop detection, the candidate memo, hop rendering (§6).

### Item 2: the DS RRset is never verified

- **Now.** `_ = dsRRSIGs` (`:181`); every link is judged alone (`:198-249`).
- **Must.** Verify the DS RRset with the keys of the link above (signer, key
  tag and algorithm, validity window); a link is Secure only under a Secure
  link.
- **RFC.** RFC 4033 §3.1 (authentication chain), RFC 4035 §5.2 and §5.3.1.
- **Change.** `ChainLink.DSSigs`; `signedByOneOf` over the DS RRset with the
  keys of the link above; the cap of §2.1, with a note "zone X above is
  <status>; this link can be no better" when it applies.

### Item 3: a missing DS is never proven

- **Now.** No DS at a cut ends Indeterminate (`:171-178`); `ChainStatusInsecure`
  is never set on a link; cuts are guessed with SOA/NS queries (`:357`).
- **Must.** Read the DS denial: an NSEC at C with NS and neither DS nor SOA,
  or an NSEC3 that matches C with that bitmap or covers it in an Opt-Out span,
  is a delegation without DS: Insecure. An NSEC at C without NS shows C is no
  cut.
- **RFC.** RFC 4035 §5.2, RFC 6840 §4.4, RFC 5155 §8.6, §8.9 and §9.2,
  RFC 9276 (iteration limit).
- **Change.** §2.3. `cache.ProveDelegation` (§4) is the reading the resolver's
  `cutProof` and `nsec3CutProof` make (`delegation_proof.go:158`, `:194`).
  `isZoneCut` is removed.

### Item 4: a DS with an algorithm dog cannot verify

- **Now.** No DS can match, and the link is Bogus (`:211-214`).
- **Must.** A verified DS RRset with no DS of a supported algorithm and digest
  type is an insecure cut. Not for a trust anchor: the operator's anchor that
  matches no key stays Bogus (`ds_usable.go:20`).
- **RFC.** RFC 4035 §5.2, RFC 6840 §5.2.
- **Change.** `cache.DSUsable` (§4, §5) before matching; the note names each
  DS and why dog cannot use it.

### Item 5: an unsigned answer is Insecure whatever the chain says

- **Now.** No RRSIG is Insecure (`:271-273`).
- **Must.** Insecure only under an Insecure link; under a Secure one it is
  Bogus; under an Indeterminate or Bogus one it takes that verdict.
- **RFC.** RFC 4035 §4.3 and §5.
- **Change.** The leaf rule of §2.1.

### Item 6: negative answers are not validated (PR 2)

- **Now.** NXDOMAIN and NODATA end as "no answer RRs", Indeterminate (`:260`).
- **Must.** Validate the proof against the deepest zone's keys: the SOA owner
  is the deepest zone, every signed RRset in the authority section verifies,
  and the NSEC or NSEC3 records prove the denial.
- **RFC.** RFC 4035 §5.4; RFC 5155 §8.3-§8.7 and §9.2; RFC 9824 (compact
  denial); RFC 9276.
- **Change.** `cache.ProveDenial` (§4), which `ValidateDenial` then calls,
  #873's empty non-terminal and wildcard no data proofs included. A candidate
  whose DS denial proves a name error ends the walk (RFC 8020).

### Item 7: wildcard expansions are accepted on the signature alone (PR 2)

- **Now.** `verifyLeafSig` verifies the RRSIG, which is valid for the
  wildcard, and returns Secure (`:375-395`).
- **Must.** An RRSIG whose Labels field is below the owner's label count needs
  the proof that the name does not exist and nothing between it and the
  wildcard does.
- **RFC.** RFC 4034 §3.1.3, RFC 4035 §5.3.2 and §5.3.4, RFC 5155 §8.8.
- **Change.** `cache.ExpansionSignature` and `cache.ProveWildcardAnswer` (§4),
  over the NSEC/NSEC3 records of the authority section verified with the
  deepest zone's keys; also for a CNAME hop synthesized from a wildcard. In
  PR 1, an expansion is Indeterminate, "synthesized from *.X; proof not
  checked" (decision 3).

### Item 8: the trust-anchor source is not shown

- **Now.** `loadChaserAnchors` prints it only under `-v` (`cmdv2/dog/dog.go:695`).
- **Change.** `loadChaserAnchors` returns the source; dog sets
  `Chaser.TrustAnchorSource`; `RenderChain` prints it on every chase (§6).

## 4. What v2/cache exports

Each function reads records whose signatures by `zone` the caller has
checked. None looks at signatures, the cache or the network.

```go
// PR 1
func DSUsable(ds *dns.DS) bool // renamed from dsUsable

type DelegationProof uint8
const (
	DelegationUnproven DelegationProof = iota // the records show nothing about a cut at name
	DelegationNone                            // no delegation at name
	DelegationInsecure                        // a delegation without DS, or an Opt-Out span that may hold one
	DelegationUnjudged                        // needs NSEC3 records over the iteration limit, or ran out of hashes
)
func ProveDelegation(name, zone string, nsecs []*dns.NSEC, nsec3s []*dns.NSEC3) DelegationProof

// PR 2
func ProveDenial(qname string, qtype uint16, rcode uint8, zone string,
	nsecs []*dns.NSEC, nsec3s []*dns.NSEC3) DenialVerdict
func ProveWildcardAnswer(zone, qname string, labels uint8,
	nsecs []*dns.NSEC, nsec3s []*dns.NSEC3) (ValidationState, uint16) // state, EDE code
func ExpansionSignature(sig *dns.RRSIG, owner string) bool // renamed from isExpansion (#874)
```

The resolver's behaviour does not change: each function is code that moves
out of a resolver function, which then calls it.

- `cutProof` and `nsec3CutProof`: the loops that validate records against the
  cache stay. The NSEC bitmap reading and the NSEC3 reading after
  `newNSEC3Proof` (`delegation_proof.go:231-271`) move into two unexported
  functions, which they and `ProveDelegation` call.
- `ValidateDenial` (`rrset_validate.go:1120`): validating the authority
  section (`:1126-1250`) stays; the reading of the records that validated
  Secure (`:1252-1338`, with #873's `nsecNoData`) becomes `ProveDenial`,
  called from the same place. Its debug log lines stay in `ValidateDenial`.
  The branch with neither NSEC nor NSEC3 (`:1340`) stays there too.
- `WildcardAnswerProof` (#874, `wildcard_answer.go`): the validating loop
  stays; its tail (`nsecWildcardAnswer`, the NSEC3 `wildcardAnswer`) becomes
  `ProveWildcardAnswer`.
- The existing cache and resolver tests pass unchanged (`delegation_proof_test`,
  `nsec3_denial_test`, `negative_proof_test`, `nsec_coverage_test`,
  `compact_denial_test`, `ds_usable_test`, and #873's and #874's). New tests
  check that each exported function and its resolver caller agree on the same
  records.
- Not chosen: a throwaway `RRsetCacheT` seeded with the walk's keys, so the
  walk could call `ValidateDenial`. It brings ZoneMap state,
  `unsignedDenialState` and the fetcher with it.

## 5. Algorithms and digests in dog

- dog imports package tdns, whose `init` installs
  `cache.SetAlgorithmSupported(dnssecAlgorithmVerifiable)`
  (`v2/imr_algorithm_support.go:17`): an algorithm counts when the binary
  links a real implementation (`algorithms.CapsReal`), and RSASHA1 and
  RSASHA1-NSEC3-SHA1 always do. `DSUsable` adds the digest types: SHA-1,
  SHA-256, SHA-384. dog and tdns-imr thus apply one rule to their own
  registries.
- dog's real algorithms are the built-in ones (RSA, ECDSA, Ed25519, Ed448,
  ML-DSA-44) and those `registered_algs.go` registers, generated from
  `algs.list` against the libraries installed on the build host.
  `metadata_algs.go` names every algorithm in the registry, so `+algchase`
  names algorithms this binary cannot verify. The note says so: "no DS this
  binary can use (keytag=N alg=203 (FALCON512): algorithm not supported)".
- A dog built without the C libraries reports a zone signed only with such an
  algorithm Insecure, as RFC 4035 §5.2 asks and as a tdns-imr built the same
  way does. `dog --version` lists the set.
- The NSEC3 iteration limit is `cache.NSEC3MaxIterations()`, default 10, the
  same as tdns-imr's default. A resolver configured with another limit can
  disagree about such zones; the note names the limit.

## 6. Output

`RenderChain` keeps its tree and the final `Result:` line. New: the trust
anchor line, a note per candidate dropped (on the link above it), a section
per CNAME hop, and the denial or proof records of a leaf.

```
Trust anchor: compiled-in (2 DS)
Chain validation for www.sidn.nl. AAAA:

. (root)    [secure]
   ...
  nl.    [secure]
     DS at parent:   keytag=17153 alg=13 digest_type=2
     ...
     note:           DS RRset signed by . keytag=<k>: verified
     note:           DS keytag=17153 matches KSK; DNSKEY RRset signature OK

    sidn.nl.    [secure]
       ...
       note:           www.sidn.nl.: owns a CNAME, not a zone cut

      www.sidn.nl. CNAME    [secure]
         www.sidn.nl.  3600  IN  CNAME  sidn.nl.
         note:           sig keytag=30794 verified

CNAME target sidn.nl. AAAA:
    sidn.nl.    [secure]    (as above)
      sidn.nl. AAAA    [secure]
         sidn.nl.  3600  IN  AAAA  2600:1901:0:8ca2::
         note:           sig keytag=30794 verified

Result: secure
```

A hop does not repeat links already printed: the deepest of them is one line
marked `(as above)`, followed by any new links. Other new notes:

- link: "no DS; NSEC google.se. -> google-ads.se. NS RRSIG NSEC: a delegation
  without DS"; "no DS; an NSEC3 Opt-Out span covers it: a delegation without
  DS may be there"; "names below an insecure delegation are not checked";
  "NSEC3 iterations above the limit of 10: cannot judge"; "DS RRset: no RRSIG
  by X" / "signature by X keytag=N failed: ..."; "zone X above is
  indeterminate; this link can be no better".
- dropped candidate: "C: NSEC shows no NS, not a zone cut"; "C: no DS and no
  proof about a cut; taken as part of P".
- leaf: "no RRSIG, and zone X is signed"; "zone X is insecure"; "signed by
  X, which the chain did not reach"; PR 2: the rcode in the leaf line,
  "name error proven by NSEC", "no data proven by NSEC3", "proven through an
  Opt-Out span", "synthesized from *.X; proof holds".

The `-k` help text and `guide/app-dog.md` ("DNSSEC chain validation") get the
verdict rules, CD, the CNAME hops and the anchor line.

## 7. Tests

**Today.** `v2/chase_test.go`: `scriptedClient`, a `core.DNSClienter` that
answers the answer section from a map; `TestChaseDropsNonApexName`;
`TestAlgField`; `TestRenderChainAlgNames`. No test signs anything, and dog's
own tests (`cmdv2/dog/*_test.go`) do not run a chase. All three stay.

**Fixture** (`v2/chase_tree_test.go`): an in-memory signed tree that answers
like a validating resolver asked with CD set, and records each question and
its flags.

- One ED25519 key per zone, signing everything: `newFwdSecKey` and `sign`
  (`v2/imr_forward_validation_test.go:37`), as the IMR tests do.
- NSEC zones built from the names given: answers, NODATA (the NSEC at the
  owner), NXDOMAIN (the covering NSEC and the one covering the wildcard), DS
  or a DS denial at each cut, CNAMEs, wildcards. NSEC3 responses scripted per
  test with `n3RR` (`v2/imr_nsec3_test.go:25`).
- Hooks per response: strip the RRSIGs, drop the proof records, change one
  record after signing, answer SERVFAIL, answer a DS query at a CNAME owner in
  either shape (SERVFAIL as tdns-imr today, CNAME plus the target's DS as
  #875 and 1.1.1.1).

**Per item**, each with the proof present, missing, and one record changed
after signing (`v2/chase_verify_test.go`):

| Item | Present | Missing | Changed |
|---|---|---|---|
| 1 | CNAME in zone and to another zone, Secure, no link for the owner; intermediate CNAME owner dropped (#875 shape) | CNAME RRSIG stripped: Bogus | CNAME target changed: Bogus |
| 1 | also: loop and chain over the limit Indeterminate; SERVFAIL/REFUSED on DS, DNSKEY and the answer reported as failed; records of qtype owned by another name not taken as the answer | | |
| 2 | DS RRset signed by the parent: Secure | RRSIG(DS) stripped: Bogus | DS digest changed: Bogus |
| 2 | also: DS signed by a key not in the parent's set: Bogus; parent Indeterminate (no anchor) or Bogus caps a child whose own check passes | | |
| 3 | NSEC NS-only, NSEC3 match NS-only, NSEC3 Opt-Out cover: Insecure link, unsigned answer Insecure; NSEC without NS (#379): dropped, Secure, no SOA/NS asked | no proof: dropped; unsigned answer Bogus; answer signed by the child Bogus | NSEC bitmap changed: not counted, Bogus |
| 3 | also: NSEC3 over the iteration limit: Indeterminate | | |
| 4 | digest type 99 only, algorithm 250 only: Insecure; usable and unusable, usable matches: Secure | usable DS matching no key: Bogus | unusable DS RRset with a bad signature: Bogus |
| 5 | unsigned answer: Bogus under Secure, Insecure under Insecure, Indeterminate under Indeterminate | | |
| 6 | NSEC name error, NODATA at owner, empty non-terminal and wildcard no data (#873), NSEC3 name error and no data, DS leaf denial: Secure; Opt-Out: Insecure; iterations over the limit: Insecure | no wildcard cover, no NSEC at all: Bogus | NSEC next name changed: Bogus; SOA of another zone: Bogus |
| 7 | NSEC and NSEC3 wildcard proof: Secure; NSEC3 Opt-Out: Insecure; wildcard CNAME hop: Secure | proof dropped: Bogus | proof covering a closer encloser: Bogus |
| 8 | `RenderChain` prints the source; `loadChaserAnchors` returns `file <path>` for `-k` | | |

**The chains that work today** keep working: root to TLD to zone, Secure end
to end; the root via the trust anchor (a wrong anchor is Bogus, none is
Indeterminate); a DS query as the leaf; a DNSKEY query as the leaf. Every
question the chaser sends has DO and CD set.

**Cache** (`v2/cache/*_test.go`): `ProveDelegation` (PR 1), `ProveDenial` and
`ProveWildcardAnswer` (PR 2) against their resolver callers on the same
records, reusing the fixtures of `delegation_proof_test.go`,
`nsec3_denial_test.go`, `nsec_nodata_test.go` and `wildcard_answer_test.go`.

Run: vet and tests in `v2` and `v2/cache`, `make` in `cmdv2/dog`.

## 8. Live checks

After each PR, with the new dog against tdns-imr (127.0.0.1 port 1099, main
with #872-#874, without #875) and against 1.1.1.1. Expected:

| Query | tdns-imr | 1.1.1.1 |
|---|---|---|
| `www.sidn.nl AAAA` | secure, one CNAME hop | same |
| `www.sidn.nl DS` | indeterminate: the answer is SERVFAIL (#875) | secure: CNAME hop, then `sidn.nl` DS |
| `_443._tcp.www.sidn.nl TLSA` | indeterminate: DS query failed at `www.sidn.nl` | secure |
| `www.iis.se A`, `sidn.nl DS` | secure | secure |
| `google.se A` (NSEC, no DS) | insecure | insecure |
| `google.nl A` (NSEC3 match, no DS) | insecure | insecure |
| `<random>.com A` (Opt-Out) | insecure | insecure |
| `dnssec-failed.org A` | bogus: DS matches no key | bogus |
| `<random>.nl A`, `nl NAPTR`, `google.nl DS` (NSEC3) | PR 1 indeterminate; PR 2 secure | same |
| `<random>.sidn.nl A` (NSEC) | PR 1 indeterminate; PR 2 secure | same |
| an NSEC-signed live wildcard (test zone, not named here) | PR 1 indeterminate; PR 2 secure | same |

Also: `-k` with a wrong anchor (root and everything below Bogus, the source
line names the file); `+algchase` on a PQ-signed zone; the `www.sidn.nl` rows
again against a tdns-imr with #875 once it lands.

## 9. Staging, order and size

Items 1-5 and 8 touch `v2/chase.go`, `cmdv2/dog/dog.go`, `ds_usable.go` and
`delegation_proof.go`; none of these is changed by #873 or #874. Item 6 needs
#873's NSEC proofs and moves code in `ValidateDenial`, which #873 changes;
item 7 needs #874's `nsecWildcardAnswer` and moves code in `wildcard_answer.go`,
which #874 adds. Hence two PRs:

- **PR 1** (`fix/dog-chase-verification`, now): items 1-5 and 8. Denials stay
  Indeterminate and wildcard expansions become Indeterminate, each with a note.
- **PR 2** (after #873, #874 and PR 1 merge; a branch from main): items 6 and
  7. It updates this document's status line and adds a dated amendment.

One PR in two stages is possible too, opened once #873 and #874 have merged
and origin/main is merged forward; it holds items 1-5 and 8 back until then.

Order and size (lines added/removed, tests separately):

| Step | Item | PR | Files | Code | Tests |
|---|---|---|---|---|---|
| 1 | queries, owners, rcode, CD; walk per name; memo; data model | 1 | chase.go | +150 -70 | fixture +250 |
| 2 | 8: anchor source | 1 | chase.go, dog.go | +20 -5 | +25 |
| 3 | 2: DS RRset signature, cap | 1 | chase.go | +70 -10 | +140 |
| 4 | 4: usable DS | 1 | chase.go, ds_usable.go | +30 -5 | +70 |
| 5 | 3: cut proofs; `isZoneCut` goes | 1 | chase.go, delegation_proof.go | +150 -60 | +200 |
| 6 | 5: unsigned answer | 1 | chase.go | +25 -10 | +60 |
| 7 | 1: CNAME hops, rendering | 1 | chase.go | +170 -10 | +200 |
| 8 | guide, help text, this document | 1 | app-dog.md, dog.go, docs | +60 | |
| 9 | 6: denials | 2 | chase.go, rrset_validate.go | +170 -70 | +270 |
| 10 | 7: wildcard proofs | 2 | chase.go, wildcard_answer.go | +90 -25 | +180 |

`chase.go` grows to about 1,000 lines; `RenderChain` moves to
`chase_render.go` in step 1.

## 10. Decisions

1. **Two PRs** (§9), or one held for #873 and #874. Proposed: two.
2. **CD=1 on every query of the walk** (RFC 6840 §5.9). Without it a
   validating resolver answers SERVFAIL for bogus data, and dog can only say
   "query failed" (`dnssec-failed.org` is then Indeterminate, not Bogus).
   Proposed: always set.
3. **Wildcard expansions in PR 1**: Indeterminate with a note, or Secure on
   the signature (as today) until PR 2. Proposed: Indeterminate.
4. **DNAME**: report an answer synthesized from a DNAME Indeterminate, "not
   followed", or verify the DNAME and its synthesis and follow the target now
   (about 60 more lines). Proposed: report it; following it later, as #718 does
   for the resolver.
5. **Candidates without DS and without a proof are dropped** (§2.3), not
   reported. Safe by the argument there.
6. **The anchor line is printed on every chase**, not only when the result is
   not Secure.

## 11. Amendment, 2026-10-01: PR 1 as implemented

### 11.1 Decisions and conditions

All six decisions of §10 were taken as proposed. The note on the zone above
a dropped candidate (decision 5) is printed always, so a Bogus that follows
can be explained. The approval added conditions, all met:

- agreement tests for `ProveDelegation` against `cutProof` and
  `nsec3CutProof`, and for `DSUsable` against `dsUsable` (§11.3);
- `v2/cache/unsigned_rrset.go`, `v2/dnslookup.go`, `v2/imr_cname_chain.go`,
  `v2/imrengine.go` and `v2/imr_traffic_class.go` are not changed, nor are the
  signatures of `cutProof`, `nsec3CutProof` and `dsUsable`;
- the CNAME hop limit is the resolver's `maxCNAMEChain` itself (§11.2 f);
- one commit per step of §9, steps 1-8, and this document last.

The example in the comment on `zoneCutsFromRoot` now uses an example name.

### 11.2 Where the code differs from r1

a. **`signatureByOneOf`** (`v2/dnssec_validate.go`). `signedByOneOf` returns
   only the key; the walk needs the signature too, for its key tag in the
   notes and its Labels field for a wildcard. `signatureByOneOf` returns both,
   and `signedByOneOf` calls it; its callers are unchanged.
b. **`dsUsable` stays**, as a wrapper of `DSUsable`, so that the cache's own
   callers see no change.
c. **A zone with a trust anchor of its own is not asked for its DS at all**
   (r1 said only that it is not capped), as the resolver has it since #870.
d. **"names below an insecure delegation are not checked"** is noted only
   when a name below was in fact skipped.
e. **`ChainLeaf.Proof` is not added in PR 1**: nothing fills it before items 6
   and 7. `ChainLeaf.Rcode`, `ChainLink.DSSigs`, `ChainHop`,
   `ChainResult.Qname/Qtype/TrustAnchorSource/Aliases` and
   `Chaser.TrustAnchorSource` are as in §2.5.
f. **The hop limit** is `maxCNAMEChain` read directly: `chase.go` is in package
   tdns, like `v2/dnslookup.go`, which is not changed.
g. **A DNAME counts** only when it synthesizes the CNAME's target (RFC 6672
   section 2.2), and only for a CNAME without RRSIG. A signed CNAME beside a
   DNAME is judged as any CNAME.
h. **Notes** read slightly differently from §6, for example: "C: no DS, and
   the denial shows no delegation there"; "C: no DS and no proof about a cut;
   taken as part of P"; "zone X is insecure: no chain of trust leads to the
   answer"; "zone X is <status>; the answer can be no better"; "synthesized
   from *.X; the proof that the name does not exist is not checked";
   "NXDOMAIN: the proof of the denial is not checked". The trust anchor line
   is "Trust anchor: <source> (<n> DS)", or "Trust anchor: none".
i. **This document is a commit of its own**, after step 8 (guide and help
   text).
j. **Size**: code +985 -334, tests +1,455, guide +27 -4, against §9's 650
   code and 950 tests. The test fixture builds NSEC-signed zones itself
   (`chase_tree_test.go`, 463 lines), and the notes and the rendering of hops
   took more than estimated. `chase.go` is 944 lines, `chase_render.go` 139.

### 11.3 Tests

- `v2/chase_tree_test.go`: the signed tree of §7, answering as a validating
  resolver asked with CD does: NSEC zones built from the names given, CNAMEs
  followed, wildcards expanded, unsigned delegations, and edits per response
  (strip RRSIGs, drop the proof, change a record after signing, another
  rcode) or whole scripted responses (NSEC3 denials, DNAME answers).
- `v2/chase_verify_test.go`: the matrix of §7 for items 1-5 and 8, and the
  chains that worked before (root to TLD to zone, the trust anchor right,
  wrong and absent, a DS and a DNSKEY query as the leaf). Every question the
  chaser sends has DO and CD set.
- `v2/cache/delegation_proof_agree_test.go`: `ProveDelegation` and `cutProof`
  on the same records (NSEC with NS only, with NS and DS, without NS, with
  SOA, a covering NSEC; NSEC3 match with and without DS, without NS, Opt-Out
  cover, cover without Opt-Out, a closest encloser with no cover or that is a
  delegation, over the iteration limit, a proof that runs out of hashes;
  records signed by the child, with a stray key, or not at all).
  `ds_usable_test.go` checks `DSUsable` against the same table as `dsUsable`.
- `cmdv2/dog/chaseanchors_test.go`: `loadChaserAnchors` returns the source.

Results at the last code commit: `go vet ./...` and `go test ./...` pass in
`v2` (with `v2/algorithms` and `v2/algorithms/mldsa44`) and in `v2/cache`;
`go vet` and `go test` pass in `cmdv2/dog`, and `make` builds dog there.
staticcheck reports nothing in the files changed.

### 11.4 Live checks

dog built from this branch with `make`, against tdns-imr (main with #872,
#873 and #874, without #875) and 1.1.1.1. Every row came out as §8 expected:

| Query | tdns-imr | 1.1.1.1 |
|---|---|---|
| `www.sidn.nl AAAA` | secure, one CNAME hop | secure, one CNAME hop |
| `www.sidn.nl DS` | indeterminate: answer query failed: SERVFAIL (#875) | secure: CNAME hop, then `sidn.nl` DS signed by `nl.` |
| `_443._tcp.www.sidn.nl TLSA` | indeterminate: DS query failed at `www.sidn.nl`: SERVFAIL | secure |
| `www.iis.se A`, `sidn.nl DS` | secure | secure |
| `google.se A` | insecure: NSEC at `google.se.` with NS RRSIG NSEC | insecure |
| `google.nl A` | insecure: NSEC3 | insecure |
| `<random>.com A` | insecure: NSEC3 Opt-Out at the candidate | insecure |
| `dnssec-failed.org A` | bogus: DS has no matching DNSKEY | bogus |
| `<random>.nl A`, `nl NAPTR`, `google.nl DS` | indeterminate: proof not checked | indeterminate |
| `<random>.sidn.nl A` | indeterminate: proof not checked | indeterminate |
| an NSEC-signed live wildcard (test zone) | indeterminate: synthesized from the wildcard, proof not checked | indeterminate |

With `-k` naming a file whose DS matches no root key, the first line names the
file and every link is Bogus. With `-k` naming a missing file, dog says so on
stderr and the first line names the source it fell back to.

## 12. Amendment, 2026-10-01: PR 2 as implemented

PR #887, stacked on #881, after #873, #874 and #879 (the resolver's answer to
a DS or DNSKEY question at a CNAME owner) had merged.

### 12.1 Scope and commits

Items 6 and 7, and two findings of the review of #881:

- **C1**: below an unsigned delegation capped by a Bogus or Indeterminate
  zone above, the answer's note said "zone X is insecure". It now names the
  verdict.
- **C2**: the walk read the RRSIG Labels field with a check of its own
  (`expandedFrom`). #874's `isExpansion` is exported as
  `cache.ExpansionSignature`, and the walk asks it.

One commit each, in the order 6, C2, 7, C1, then the guide and this document.
C2 comes before 7, which builds on it.

### 12.2 Where the code differs from r1

a. **`ProveDenial` and `ValidateDenial`.** The reading moves into an
   unexported `proveDenial` that takes a log function: `ValidateDenial` passes
   its own when the cache debugs, so its debug lines are unchanged, and
   `ProveDenial` passes none. `ValidateDenial` keeps its branch for a denial
   with neither NSEC nor NSEC3 (`Insecure` with an error); `ProveDenial` given
   no records returns Bogus.
b. **`ProveWildcardAnswer` does not filter records by owner.** Its callers
   hand it records of the zone: the resolver filters the RRsets first
   (`proofOwnedIn`), and the walk passes only records the zone signed.
c. **A denial in the walk** (§2.1): RRsets signed only by other zones are
   passed over; one the zone signed that does not verify makes the answer
   Bogus, as a failing RRset decides in the resolver. A denial with no RRSIG
   at all takes the zone's verdict when the zone is not Secure, as an
   unsigned answer does. A denial without an SOA is read with the deepest
   zone's records; an SOA, when present, must be the deepest zone's.
d. **A proven DS denial at a candidate**: a name error stops the walk, as r1
   said (RFC 8020); any other proven denial of the DS, with nothing proven
   about a cut, shows the candidate is no delegation, as the resolver's
   `denialEvidence` reads it.
e. **No rcode in the leaf line** (r1 §6): the note names it ("NXDOMAIN
   proven by NSEC3"), and the proof records are printed under the leaf
   (`ChainLeaf.Proof`).
f. **Answers synthesized from a wildcard**: signatures over the owner are
   tried before expansion signatures, as `ValidateAnswer` tries them. What is
   left of the walk's own Labels code names the wildcard for the output
   (`wildcardOf`), and decides nothing.
g. **The test tree** also synthesizes CNAMEs from wildcards.
h. **Size**: code +323 -82, tests +581 -19. `chase.go` is 1,134 lines.

### 12.3 Tests

- `v2/cache/prove_denial_agree_test.go`: `ProveDenial` and `ValidateDenial` on
  the same records. NSEC3, 10 cases: name error, through Opt-Out, without the
  wildcard cover, no data, the type present, over the iteration limit, a
  cover owned in another zone, and the DS denials of a matching record, an
  Opt-Out span and a cover without Opt-Out. NSEC, 16 cases: name errors with
  and without a cover, no data at the name and at a delegation, empty
  non-terminals (no data, DS, name error), wildcard no data in six shapes,
  and RFC 9824 compact name error and no data. And `ProveDenial` with no
  records.
- `v2/cache/prove_wildcard_agree_test.go`: `ProveWildcardAnswer` and
  `WildcardAnswerProof` on the same records, 10 NSEC and 4 NSEC3 cases, and
  `ExpansionSignature` on its own. A record whose signature fails decides
  both verdicts before any proof is read, and is not compared.
- `v2/chase_verify_test.go`: denials and wildcard answers with the proof
  present, missing and changed after signing; NSEC3 Opt-Out and the iteration
  limit; an SOA from another zone; a denial with no RRSIG; nothing asked
  below a proven name error; a CNAME from a wildcard; the expansion rule
  (C2); the capped note (C1).
- `go vet` and `go test` pass in `v2`, `v2/cache`, `v2/cli` and `cmdv2/dog`
  (`TestStandbyAndAManualRollReachTheCds` failed once in the full `v2` run and
  passed on its own); `make` builds dog.

### 12.4 Live checks

dog from this branch, against a tdns-imr built from main at `df4f2caf` (with
#879), run on a port of its own with only the root hints and trust anchor
configured, and against 1.1.1.1. Every row came out as expected:

| Query | tdns-imr (main) | 1.1.1.1 |
|---|---|---|
| `www.sidn.nl AAAA` | secure | secure |
| `www.sidn.nl DS` | secure: CNAME hop, then the DS of `sidn.nl` | secure |
| `_443._tcp.www.sidn.nl TLSA` | secure | secure |
| `www.iis.se A`, `sidn.nl DS` | secure | secure |
| `google.se A` (NSEC), `google.nl A` (NSEC3) | insecure | insecure |
| `<random>.com A` (Opt-Out) | insecure | insecure |
| `dnssec-failed.org A` | bogus | bogus |
| `<random>.nl A` | secure: NXDOMAIN proven by NSEC3 | secure |
| `nl NAPTR`, `google.nl DS` | secure: NODATA proven by NSEC3 | secure |
| `<random>.sidn.nl A` | secure: NXDOMAIN proven by NSEC | secure |
| `<random>.codeberg.page A` | secure: synthesized from `*.codeberg.page.`, the NSEC3 proof holds | secure |
| an NSEC-signed wildcard test zone | secure: the NSEC proof holds | secure |

The `www.sidn.nl` rows now match 1.1.1.1. The first chase of the NSEC wildcard
test zone against the freshly started resolver came out Indeterminate once;
eight further runs, one of them right after a cold restart, were Secure.

