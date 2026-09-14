# Query types the authoritative responder answers

Written 2026-09-14. Proposal, not implemented.

Revisions:
- r1 2026-09-14: first version.

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
data type or private use:

| Range | RFC 6895 class | Treatment |
|---|---|---|
| 0 | reserved | refused (section 5) |
| 1-127 | data TYPEs | served, except OPT (41), a Meta-TYPE: refused |
| 128-255 | Q-TYPEs and Meta-TYPEs | ANY (section 4), AXFR and IXFR (zone transfer), NXNAME (FORMERR, RFC 9824) keep their own paths; the rest refused |
| 256-61439 | data TYPEs | served |
| 61440-65279 | reserved | refused |
| 65280-65534 | private use | served |
| 65535 | reserved | refused |

One predicate replaces the two maps:

```go
// servableQtype reports whether qtype names data a zone can hold: the data
// and private-use ranges of RFC 6895 section 3.1, less the Meta-TYPE OPT.
func servableQtype(qtype uint16) bool {
	switch {
	case qtype == dns.TypeOPT:
		return false
	case qtype >= 1 && qtype <= 127:
		return true
	case qtype >= 256 && qtype <= 61439:
		return true
	case qtype >= 65280 && qtype <= 65534:
		return true
	}
	return false
}
```

The private types go by the same rule. A TYPE65285 RRset is served for the same
reason a PTR RRset is: the zone holds it, because a zone file or an UPDATE put
it there, and UPDATE has its own type policy. What private types keep is their
registration in `core` (`dns.PrivateHandle`, `dns.TypeToString`) and the
explicit DELEG test that suppresses the referral (`qtype != core.TypeDELEG`).
DSYNC sits on today's private list but is `core.TypeDSYNC` = 66, its IANA code
point.

### 2. Paths that stay as they are

- **DS** is trapped ahead of the name lookup (`handleDSQuery`).
- **DELEG** skips the referral and is answered from the parent side.
- **NSEC** is read from the owner's `NSEC` property (`ownerRRsetForQuery`), and
  never through a wildcard.
- **CNAME** at a CNAME-only owner is answered by `handleCNAMEChain`. A CNAME
  query at an owner without a CNAME now gets NODATA.

### 3. RRSIG

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
a single RRset from the owner, with its RRSIGs under DO. The RRset is the one
with the lowest type code, so repeated queries get the same answer. Section
4.2's synthesised HINFO is not used: in a signed zone it would need signing at
query time, and the query path signs nothing but synthesised denial NSECs.
Answering with a stored RRset keeps that invariant.

In both modes the paths ahead of the answer are unchanged: ANY at or below a
zone cut gets a referral, at a name that does not exist NXDOMAIN, at an empty
non-terminal NODATA, and at a CNAME-only owner the CNAME without chasing it
(RFC 1034 section 4.3.2 step 3a, pinned by `cname_exact_match_test.go`).

The option behaves like `minimal-responses`: a bool, absent means false,
`allow-any-queries:false` disables it explicitly, and a reload applies it
(`KeyDB.SetOptions`). A server without a KeyDB, such as the KDC catalog zone,
reads it as unset.

### 5. The catch-all refusal

After section 1 the catch-all at the end of `QueryResponder` is reached only by
qtypes outside the served ranges: 0, OPT, TSIG, TKEY, MAILA, MAILB, the
unassigned Meta-TYPE range and the reserved ranges. It answers REFUSED with AA
clear, no NS RRset or glue, and EDE 30 (Invalid Query Type), the code the NXNAME
path already attaches. The response OPT stays.

### 6. Unreachable SOA branch

The branch `qtype == dns.TypeSOA && core.EqualNames(qname, zd.ZoneName)` and
`handleSOAQuery`, its only caller, never run: SOA is on today's list, so the
exact-match branch answers every SOA query first (reading the SOA through
`soaForResponseFrom`). Under section 1 it still does. Both go.

## Implementation

All in `v2/` unless named:

- `queryresponder.go`: remove `tdnsSpecialTypes` and `standardDNSTypes`; add
  `servableQtype`; answer RRSIG (section 3) and ANY (section 4) after the
  delegation and CNAME checks and ahead of the exact-match branch; gate that
  branch on `servableQtype`; rework the catch-all (section 5); remove the SOA
  branch and `handleSOAQuery` (section 6).
- `enums.go`: `AuthOptAllowAnyQueries`, spelled `allow-any-queries`.
- `parseoptions.go`: parse it as a bool, as `AuthOptMinimalResponses` is.
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
- A stored unknown type (`TYPE65000 \# ...`) and an unregistered private-use
  type: served.
- CNAME at an owner holding only A: NODATA.
- CAA at a wildcard owner: answered, re-owned to the query name.
- RRSIG in the signed zone: the signatures of every RRset at the owner, with and
  without DO; in the unsigned zone NODATA.
- ANY without the option: one RRset, the lowest type code. With it: every
  RRset, the NSEC, and under DO their RRSIGs. At a CNAME-only owner: the CNAME,
  in both modes.
- 0, OPT, TSIG, TKEY, MAILA, 61440 and 65535: REFUSED, AA clear, no NS RRset,
  EDE 30.
- NXNAME: FORMERR, as today.
- A reload that sets `allow-any-queries` changes the ANY answer without a
  restart.

## Out of scope

- **DNAME substitution.** A DNAME query at the DNAME owner is served under
  section 1. Names below a DNAME are not rewritten (RFC 6672) and get NXDOMAIN.
- **The legacy `tdns/` module**, which carries its own copy of both lists.

## Open questions

1. **Transport.** RFC 8482 section 4.4 allows a conventional ANY response over
   TCP only. A value `allow-any-queries:tcp` would give full answers where the
   size cannot be used for amplification.
2. **RRSIG size.** At a signed apex an RRSIG answer is nearly as large as an ANY
   answer. Without `allow-any-queries`, should RRSIG answers shrink to the
   signatures of one RRset as well?
3. **Default.** The option defaults to off, like `minimal-responses`. Whether
   tdns-auth should ship with full ANY answers on.
