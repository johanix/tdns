# Query types the authoritative responder answers

Written 2026-09-14. Proposal, reviewed; not implemented.

Revisions:
- r1 2026-09-14: first version.
- r2 2026-09-14: added "Size".
- r3 2026-09-14: after review. Meta-TYPEs and reserved types are refused before
  the name lookup, and section 2 gives the full query order. RRSIG and NSEC
  queries at a CNAME-only owner are answered from the owner instead of following
  the CNAME. The minimal ANY answer never picks the NSEC. An invalid
  `allow-any-queries` value reads as off. The open questions are settled
  (section 7). Tests and size updated.

## Why

`QueryResponder` (`v2/queryresponder.go`) answers an exact-match query at a
name that exists only when the qtype is on one of two lists:

- `tdnsSpecialTypes`: DSYNC, NOTIFY, MSIGNER, DELEG, HSYNC, HSYNC2, HSYNC3,
  HSYNCPARAM, TSYNC, JWK.
- `standardDNSTypes`: SOA, MX, TLSA, SRV, A, AAAA, NS, TXT, ZONEMD, KEY, URI,
  SVCB, NSEC, NSEC3, NSEC3PARAM, RRSIG, DNSKEY, CSYNC, CDS, CDNSKEY.

Every other qtype reaches the final catch-all: REFUSED, with AA set and the apex
NS RRset and glue attached.

The lists gate one step, the exact match at an existing owner. Every step before
it answers whatever the qtype: a DS query is answered from the parent side, a
name at or below a zone cut gets a referral, an empty non-terminal NODATA, a name
that does not exist NXDOMAIN. Nothing else in the server filters by type
either: the zone loader (`dnsutils.go`) stores RRsets of every type, the signer
signs every authoritative RRset, and a zone transfer carries them all. So the
lists hide nothing. Their one effect is to refuse data the zone holds, and only
at names that exist.

They are also incomplete, and that breaks ordinary zones. PTR is missing, so
every PTR query to a reverse zone is refused. So are CAA, HTTPS, NAPTR, SSHFP,
HINFO, LOC, DNAME, OPENPGPKEY, SMIMEA and every type the build has no mnemonic
for (RFC 3597). JWK was missing until PR #616, which left multi-provider agent
identities served by tdns-auth undiscoverable. CHUNK (65288) is registered in
`core` and is still missing.

RFC 1034 section 4.3.2 matches the qtype against the data the server holds, and
RFC 3597 requires unknown types to be handled transparently. BIND, NSD and Knot
serve any stored type.

### Current behaviour

`QueryResponder` driven at main `d7ee7f4b`, unsigned zone, no DO:

| Query | Owner holds | Answer |
|---|---|---|
| `www A` | A, CAA, HINFO, HTTPS | NOERROR, the A |
| `www CAA` | A, CAA, HINFO, HTTPS | REFUSED |
| `nope CAA` | (no such name) | NXDOMAIN |
| `www HINFO`, `www HTTPS` | A, CAA, HINFO, HTTPS | REFUSED |
| `www MX` | A, CAA, HINFO, HTTPS | NODATA (MX is listed) |
| `www TYPE65000` | A, CAA, HINFO, HTTPS | REFUSED |
| `www CNAME` | A, CAA, HINFO, HTTPS | REFUSED |
| `www ANY` | A, CAA, HINFO, HTTPS | REFUSED |
| `www RRSIG` | A, CAA, HINFO, HTTPS | NODATA |
| `host PTR` | PTR | REFUSED |
| `dn DNAME` | DNAME | REFUSED |
| `x.wild TXT` | `*.wild`: TXT, CAA | NOERROR, the TXT |
| `x.wild CAA` | `*.wild`: TXT, CAA | REFUSED |

Every REFUSED carries AA=1 and the NS RRset in the authority section.

## Proposal

### 1. A rule over type ranges replaces both lists

An exact-match query is answered from the zone -- the RRset when the owner holds
it, NODATA otherwise -- for every qtype that RFC 6895 section 3.1 classes as a
data type or private use. Meta-TYPEs and reserved types are refused before the
name lookup (section 5).

| Range | RFC 6895 class | Treatment |
|---|---|---|
| 0 | reserved | refused |
| 1-127 | data TYPEs | served; OPT (41) is a Meta-TYPE and refused |
| 128-255 | Q-TYPEs and Meta-TYPEs | NXNAME gets FORMERR (RFC 9824), ANY has section 4, AXFR and IXFR go to zone transfer; the rest refused |
| 256-61439 | data TYPEs | served |
| 61440-65279 | reserved | refused |
| 65280-65534 | private use | served |
| 65535 | reserved | refused |

Two predicates go in `core`. The UPDATE parser already makes the first test
(`zone_update_verbs.go`: OPT or 128-255) and moves onto it:

```go
// IsMetaType reports whether t is a Q-TYPE or Meta-TYPE (RFC 6895 section
// 3.1): OPT and 128-255. No zone holds an RRset of such a type.
func IsMetaType(t uint16) bool {
	return t == dns.TypeOPT || (t >= 128 && t <= 255)
}

// IsReservedType reports whether t lies in a range RFC 6895 section 3.1
// reserves: 0, 61440-65279 and 65535.
func IsReservedType(t uint16) bool {
	return t == 0 || (t >= 61440 && t <= 65279) || t == 65535
}
```

The two maps in `queryresponder.go` give way to one test:

```go
// servableQtype reports whether qtype names data a zone can hold: the data
// and private-use ranges of RFC 6895 section 3.1.
func servableQtype(qtype uint16) bool {
	return !core.IsMetaType(qtype) && !core.IsReservedType(qtype)
}
```

The private types go by the same rule. A TYPE65285 RRset is served for the same
reason a PTR RRset is: the zone holds it, because a zone file or an UPDATE put
it there, and UPDATE has its own type policy. What private types keep is their
registration in `core` (`dns.PrivateHandle`, `dns.TypeToString`) and the
explicit DELEG test that suppresses the referral (`qtype != core.TypeDELEG`).
DSYNC sits on today's private list but is `core.TypeDSYNC` = 66, its IANA code
point.

### 2. Query order

`QueryResponder` takes these steps in order, and the first that applies answers.
Steps marked *new* or *changed* are this design; the others are today's.

1. NXNAME: FORMERR with EDE 30.
2. *New.* A Meta-TYPE or reserved type other than ANY, AXFR and IXFR: refused
   (section 5).
3. DS: answered from the parent side (`handleDSQuery`).
4. A name that does not exist: a referral at or below a zone cut, NODATA at an
   empty non-terminal, a wildcard match with the wildcard as owner from here on,
   otherwise NXDOMAIN.
5. An owner node with no RRsets: NODATA as an empty non-terminal, otherwise
   NXDOMAIN.
6. Below the apex, at or below a zone cut: a referral, except for DELEG.
7. *Changed.* Below the apex, a CNAME-only owner: `handleCNAMEChain`, for every
   qtype except RRSIG and NSEC. CNAME and ANY queries get the CNAME without
   following it.
8. *New.* RRSIG: the signatures stored at the owner (section 3).
9. *New.* ANY: section 4.
10. *Changed.* A servable qtype: the RRset, or NODATA. NSEC comes from the
    owner's `NSEC` property (`ownerRRsetForQuery`), and never through a wildcard.
11. AXFR and IXFR: a zone transfer at the apex, NOTAUTH elsewhere.
12. No qtype reaches the end of the function; it sends the section 5 refusal as
    a safeguard.

### 3. RRSIG and NSEC

RRSIG is on today's list and is answered wrongly. Signatures live inside the
RRset they cover (`core.RRset.RRSIGs`, filled by the zone loader and the
signer), so `RRtypes.Get(dns.TypeRRSIG)` finds nothing and every RRSIG query
gets NODATA. Under DO the NSEC synthesised for that NODATA lists RRSIG in its
bitmap: the denial contradicts itself.

An RRSIG query is answered with the signatures stored at the owner: the
`RRSIGs` of every RRset in `owner.RRtypes`, and those of `owner.NSEC`. The answer
is the same with and without DO, since the signatures are the data asked for.
An owner holding no signatures -- any owner in an unsigned zone -- gets NODATA.
The answer bypasses `signRRsetForZone`: an RRSIG RRset carries no signatures of
its own, and that function would read it as a must-be-signed RRset without them
and SERVFAIL. Through a wildcard the signatures are re-owned to the query name,
those of the wildcard's NSEC are left out (as the NSEC itself is), and under DO
the wildcard proof is added.

A CNAME-only owner is answered the same way. RFC 4035 section 2.5 requires RRSIG
and NSEC beside a CNAME in a signed zone, so an RRSIG or NSEC query there asks
for data the node holds, and the CNAME is not followed. Step 7 passes both
qtypes on: an RRSIG query gets the signatures over the CNAME and the NSEC, and
an NSEC query gets the NSEC. Today both follow the CNAME. The answer holds the
signatures alone; answered through `handleCNAMEChain`, a query without DO would
get the CNAME and none of them.

### 4. ANY, gated by `allow-any-queries`

An ANY answer shows everything a name holds in one round trip, which makes it
useful for diagnostics and inspection. It is also the largest answer a name can
produce, and RFC 8482 lets a responder answer with less. The choice is a
server-wide auth option:

```yaml
authengine:
   options:
      - allow-any-queries
```

**With `allow-any-queries`:** a conventional ANY response. The answer holds
every RRset at the owner and the owner's NSEC when it has one, and under DO
their RRSIGs. Each RRset goes through `signRRsetForZone`, so a must-be-signed
zone with an RRset lacking signatures answers SERVFAIL, as on any other positive
answer. At the apex a stored DS is left out: it is parent-side data, and the
apex NODATA bitmap already omits it (`sendChildApexDSNodata`). Through a wildcard
every RRset is re-owned to the query name, the NSEC is left out, and under DO
the wildcard proof is added. `minimal-responses` applies as to any positive
answer.

**Without it (the default):** a minimal response under RFC 8482 section 4.1 --
a single RRset from `owner.RRtypes`, with its RRSIGs under DO. The RRset is the
one with the lowest type code, so repeated queries get the same answer. The
NSEC is a property of the owner rather than an `RRtypes` entry, so it is never
the one chosen; it appears only in a full answer. At the apex NS (2) and SOA (6)
sort below a stored DS (43), so the DS is never chosen either. Section 4.2's
synthesised HINFO is not used: in a signed zone it would need signing at query
time, and the query path signs nothing but synthesised denial NSECs. Answering
with a stored RRset keeps that invariant.

In both modes steps 1 to 7 come first: ANY at or below a zone cut gets a
referral, at a name that does not exist NXDOMAIN, at an empty non-terminal
NODATA, and at a CNAME-only owner the CNAME without following it (RFC 1034
section 4.3.2 step 3a, pinned by `cname_exact_match_test.go`).

The option reads like `minimal-responses`: a bool, absent means off,
`allow-any-queries:false` turns it off explicitly, and a reload applies it
(`KeyDB.SetOptions`). An invalid value is logged and reads as off, where
`minimal-responses` reads one as on: a mistyped value must not enable the larger
answers. A server without a KeyDB, such as the KDC catalog zone, reads the
option as unset.

### 5. Refusing Meta-TYPEs and reserved types

Step 2 refuses 0, OPT, TSIG, TKEY, MAILA, MAILB, the unassigned codes 129-248,
61440-65279 and 65535 before the name lookup, so the answer is the same at a
name that exists, at one that does not, at or below a zone cut and at a
CNAME-only owner. Today a missing name answers them NXDOMAIN, a zone cut a
referral, a CNAME-only owner its CNAME, and only the remaining existing names
reach the catch-all.

The response is REFUSED with AA clear, no NS RRset or glue, EDE 30 (Invalid
Query Type), the code the NXNAME path attaches, and the response OPT. The
catch-all at the end of `QueryResponder`, which today answers REFUSED with AA set
and the apex NS RRset, sends the same refusal.

### 6. Unreachable SOA branch

The branch `qtype == dns.TypeSOA && core.EqualNames(qname, zd.ZoneName)` and
`handleSOAQuery`, its only caller, never run: SOA is on today's list, so the
exact-match branch answers every SOA query first (reading the SOA through
`soaForResponseFrom`). Under section 1 it still does. Both go.

### 7. Settled questions

1. **Transport.** This change adds no `allow-any-queries:tcp`. RFC 8482 section
   4.4 allows a full ANY answer over TCP only; that would come later as a value
   of the same option, the way `parent-update` takes one.
2. **RRSIG size.** RRSIG answers stay whole without the option. RFC 8482 covers
   ANY, RRSIG is a data type, and a large answer is truncated and retried over
   TCP like any other.
3. **Default.** Off, like `minimal-responses`. The sample configuration shows how
   to turn it on.

## Implementation

All in `v2/` unless named:

- `core/`: `IsMetaType` and `IsReservedType`.
- `zone_update_verbs.go`: its meta-type test calls `core.IsMetaType`.
- `queryresponder.go`: remove `tdnsSpecialTypes` and `standardDNSTypes`; add
  `servableQtype`; refuse Meta-TYPEs and reserved types beside the NXNAME check
  (section 5); skip `handleCNAMEChain` for RRSIG and NSEC; answer RRSIG
  (section 3) and ANY (section 4) ahead of the exact-match branch; gate that
  branch on `servableQtype`; send the section 5 refusal from the catch-all;
  remove the SOA branch and `handleSOAQuery` (section 6).
- `enums.go`: `AuthOptAllowAnyQueries`, spelled `allow-any-queries`.
- `parseoptions.go`: parse it as a bool whose invalid values read as off.
- `cmdv2/auth/tdns-auth.sample.yaml` and `guide/config-tdns-auth.md`: document
  the option.

## Tests

A table test driving `QueryResponder` with the harness of
`queryresponder_jwk_test.go` (`testSnapshotZone`, `fakeRW`), over an unsigned
zone and a signed one:

- PTR, CAA, HINFO, HTTPS and DNAME at owners holding them: NOERROR with the
  RRset; in the signed zone under DO, with its RRSIGs.
- The same types at an owner without them: NODATA; under DO a denial whose
  bitmap lists the owner's types.
- A stored unknown type (`TYPE65000 \# ...`), an unregistered private-use type,
  CHUNK and JWK: served.
- CNAME at an owner holding only A: NODATA.
- CAA at a wildcard owner: answered, re-owned to the query name.
- RRSIG in the signed zone: the signatures of every RRset at the owner, with and
  without DO; in the unsigned zone NODATA.
- RRSIG at a CNAME-only owner in the signed zone: the signatures over the CNAME
  and the NSEC, with and without DO, and the CNAME not followed. NSEC at the
  same owner: the NSEC.
- ANY without the option: one RRset, the lowest type code, never the NSEC. With
  it: every RRset, the NSEC, and under DO their RRSIGs. At a CNAME-only owner:
  the CNAME, not followed, in both modes.
- 0, OPT, TSIG, TKEY, MAILA, 61440 and 65535 at an existing name, at a name that
  does not exist and below a zone cut: REFUSED, AA clear, no NS RRset, EDE 30.
- As today: NXNAME gets FORMERR, AXFR at the apex reaches the zone transfer, and
  DELEG below a zone cut gets no referral.
- `allow-any-queries` with an invalid value: off. A reload that sets the option
  changes the ANY answer without a restart.

In `core`, a table over the range edges of `IsMetaType` and `IsReservedType`:
0, 1, 41, 127, 128, 255, 256, 61439, 61440, 65279, 65280, 65534 and 65535.

## Size

Estimated against main `d7ee7f4b` from the code each item replaces or mirrors:
the two lists are 36 lines, the exact-match branch 78, the SOA branch and
`handleSOAQuery` 21, and a signed-zone test fixture about 27 (`signedProofZone`
in `wildcard_proof_test.go`).

| Item | Added | Removed | Risk |
|---|---|---|---|
| `IsMetaType`, `IsReservedType`, `servableQtype` and the gate (section 1) | 19 | 37 | low |
| The early refusal, and the catch-all sending it (section 5) | 16 | 5 | low |
| `handleCNAMEChain` skipped for RRSIG and NSEC (sections 2 and 3) | 2 | 1 | low |
| The exact-match branch's positive-answer and NODATA arms, moved into helpers that sections 3 and 4 reuse | 50 | 42 | low: a move |
| RRSIG answer (section 3) | 45 | 0 | medium: re-owning through a wildcard, leaving out the NSEC's signatures |
| ANY answer in both modes, and reading the option (section 4) | 65 | 0 | medium: signing each RRset, one wildcard proof for the set, the apex DS |
| SOA branch and `handleSOAQuery` (section 6) | 0 | 21 | low |
| `zone_update_verbs.go` on `core.IsMetaType` | 1 | 1 | low |
| `enums.go`, `parseoptions.go` | 14 | 0 | low |
| `tdns-auth.sample.yaml`, `guide/config-tdns-auth.md` | 12 | 1 | none |
| Tests, one file in `v2/` and one in `v2/core/` | 450 | 0 | |
| **Total** | **674** | **108** | |

Production code in `v2/` grows by about 105 lines net (212 added, 107 removed);
most of the change is tests. The tests are a signed-zone fixture (~25), the
served, NODATA and refused table, with Meta-TYPEs at a missing name and below a
cut (~130), RRSIG and NSEC including the CNAME-only owner (~70), ANY in both
modes (~90), the NXNAME, AXFR, DELEG, CHUNK and JWK checks (~35), option parsing
and a live flip through `KeyDB.SetOptions` (~50), the `core` range table (~20),
and shared helpers (~30).

No existing test changes. The REFUSED assertions in `v2` cover UPDATE, NOTIFY,
transfer, IMR and agent paths, none of which reach the code changed here;
`cname_exact_match_test.go` pins ANY at a CNAME-only owner, which step 7 keeps;
and the UPDATE parser's meta-type test keeps its behaviour on the shared
predicate.

## Out of scope

- **DNAME substitution.** A DNAME query at the DNAME owner is served under
  section 1. Names below a DNAME are not rewritten (RFC 6672) and get NXDOMAIN.
- **Denials from unsigned zones.** A DO query to an unsigned zone gets a
  synthesised, unsigned NSEC in every NODATA and NXDOMAIN, with RRSIG in its
  bitmap; an RRSIG NODATA from such a zone is one of them. That predates this
  design.
- **The legacy `tdns/` module**, which carries its own copy of both lists.
