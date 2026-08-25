/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// parseZoneRRs reads a zone fragment into a flat RR slice for the digest.
func parseZoneRRs(t *testing.T, origin, text string) []dns.RR {
	t.Helper()
	var out []dns.RR
	zp := dns.NewZoneParser(strings.NewReader(text), origin, "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		out = append(out, rr)
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("parsing the test zone: %v", err)
	}
	return out
}

// RFC 8976 Appendix A.1: the simple example zone, SIMPLE scheme, SHA-384.
//
// This is the gate on the whole implementation. A digest that is merely
// self-consistent would pass every other test in this file while disagreeing
// with every other implementation on earth; this one says we computed what the
// RFC says to compute.
func TestZoneDigestRFC8976AppendixA1(t *testing.T) {
	const zone = `
example.       86400  IN  SOA     ns1.example. admin.example. 2018031900 1800 900 604800 86400
example.       86400  IN  NS      ns1.example.
example.       86400  IN  NS      ns2.example.
example.       86400  IN  ZONEMD  2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c
ns1.example.   3600   IN  A       203.0.113.63
ns2.example.   3600   IN  AAAA    2001:db8::63
`
	const want = "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9" +
		"a9713b3c9ae5cc27777f98b8e730044c"

	got, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", zone),
		ZonemdSchemeSimple, ZonemdAlgSHA384)
	if err != nil {
		t.Fatalf("ZoneDigestHex: %v", err)
	}
	if got != want {
		t.Fatalf("digest mismatch\n got: %s\nwant: %s", got, want)
	}
}

// RFC 8976 Appendix A.2: the COMPLEX example zone, SIMPLE scheme, SHA-384.
//
// This is the vector that earns its keep. Every clause of §3.3.1 that an
// implementation can plausibly get wrong is represented in one zone:
//
//   - out-of-zone data (foo.test.) must be EXCLUDED;
//   - a ZONEMD at a non-apex owner must be INCLUDED -- only the apex RRset is
//     excluded, so excluding by type alone is wrong;
//   - a duplicated TXT must be digested exactly once;
//   - an uppercase owner (UPPERCASE, NS2) must be canonicalized;
//   - mixed-case domain names inside RDATA (MX targets MAIL1 and
//     Mail2.Example.) must be lowercased;
//   - five AAAA records at one owner must sort by RDATA;
//   - a wildcard owner and a name occluded by a delegation must both be
//     digested normally.
func TestZoneDigestRFC8976AppendixA2Complex(t *testing.T) {
	const zone = `
example.      86400  IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
example.      86400  IN  NS      ns1
example.      86400  IN  NS      ns2
example.      86400  IN  ZONEMD  2018031900 1 1 a3b69bad980a3504e1cffcb0fd6397f93848071c93151f552ae2f6b1711d4bd2d8b39808226d7b9db71e34b72077f8fe
ns1           3600   IN  A       203.0.113.63
NS2           3600   IN  AAAA    2001:db8::63
occluded.sub  7200   IN  TXT     "I'm occluded but must be digested"
sub           7200   IN  NS      ns1
duplicate     300    IN  TXT     "I must be digested just once"
duplicate     300    IN  TXT     "I must be digested just once"
foo.test.     555    IN  TXT     "out-of-zone data must be excluded"
UPPERCASE     3600   IN  TXT     "canonicalize uppercase owner names"
*             777    IN  PTR     dont-forget-about-wildcards
mail          3600   IN  MX      20 MAIL1
mail          3600   IN  MX      10 Mail2.Example.
sortme        3600   IN  AAAA    2001:db8::5:61
sortme        3600   IN  AAAA    2001:db8::3:62
sortme        3600   IN  AAAA    2001:db8::4:63
sortme        3600   IN  AAAA    2001:db8::1:65
sortme        3600   IN  AAAA    2001:db8::2:64
non-apex      900    IN  ZONEMD  2018031900 1 1 616c6c6f776564206275742069676e6f7265642e20616c6c6f776564206275742069676e6f7265642e20616c6c6f7765
`
	const want = "a3b69bad980a3504e1cffcb0fd6397f93848071c93151f552ae2f6b1711d4bd2" +
		"d8b39808226d7b9db71e34b72077f8fe"

	got, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", zone),
		ZonemdSchemeSimple, ZonemdAlgSHA384)
	if err != nil {
		t.Fatalf("ZoneDigestHex: %v", err)
	}
	if got != want {
		t.Fatalf("digest mismatch\n got: %s\nwant: %s", got, want)
	}
}

// RFC 8976 Appendix A.3: the multiple-digest zone, checked with both hash
// algorithms. Its apex carries FOUR ZONEMD records, so it catches an
// implementation that excludes only the first, or only the one it was asked
// about, rather than the whole apex RRset.
func TestZoneDigestRFC8976AppendixA3(t *testing.T) {
	const zone = `
example.      86400  IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
example.      86400  IN  NS      ns1.example.
example.      86400  IN  NS      ns2.example.
example.      86400  IN  ZONEMD  2018031900 1 1 62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637493daaf401c92c279dd10f0edb1c56f8080211f8480ee306
example.      86400  IN  ZONEMD  2018031900 1 2 08cfa1115c7b948c4163a901270395ea226a930cd2cbcf2fa9a5e6eb85f37c8a4e114d884e66f176eab121cb02db7d652e0cc4827e7a3204f166b47e5613fd27
example.      86400  IN  ZONEMD  2018031900 1 240 e2d523f654b9422a96c5a8f44607bbee
example.      86400  IN  ZONEMD  2018031900 241 1 e1846540e33a9e4189792d18d5d131f605fc283e
ns1.example.  3600   IN  A       203.0.113.63
ns2.example.  86400  IN  TXT     "This example has multiple digests"
NS2.EXAMPLE.  3600   IN  AAAA    2001:db8::63
`
	for _, tc := range []struct {
		name string
		alg  uint8
		want string
	}{
		{"sha384", ZonemdAlgSHA384,
			"62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637493daaf401c92c27" +
				"9dd10f0edb1c56f8080211f8480ee306"},
		{"sha512", ZonemdAlgSHA512,
			"08cfa1115c7b948c4163a901270395ea226a930cd2cbcf2fa9a5e6eb85f37c8a" +
				"4e114d884e66f176eab121cb02db7d652e0cc4827e7a3204f166b47e5613fd27"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", zone),
				ZonemdSchemeSimple, tc.alg)
			if err != nil {
				t.Fatalf("ZoneDigestHex: %v", err)
			}
			if got != tc.want {
				t.Fatalf("digest mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// A signed zone puts two RRSIGs at one owner with DIFFERENT TTLs: the one over
// the NSEC carries the SOA minimum, the rest carry the TTL of what they cover.
// They share an owner name and a type, so the sort has to break the tie on
// RDATA -- RFC 4034 §6.3 -- and the RRSIG RDATA starts with the type covered.
//
// Comparing whole wire records instead reaches the TTL field first and decides
// there, giving an order no other implementation reproduces. Nothing in RFC
// 8976's Appendix A catches it: every TTL in those vectors is the same, so the
// tiebreak never fires.
//
// The expected values below were produced by dnspython 2.8.0's independent
// RFC 8976 implementation (Zone.compute_digest), not by this code. That is the
// point of them: a digest this package agrees with itself about is worth
// nothing, because the whole purpose of publishing one is that somebody else
// can reproduce it.
const ttlOrderZone = `ttlorder.example.	3600	IN	SOA	ns.ttlorder.example. hostmaster.ttlorder.example. 7 7200 1800 604800 7200
ttlorder.example.	3600	IN	NS	ns.ttlorder.example.
ttlorder.example.	3600	IN	RRSIG	NS 15 2 3600 20260924000000 20260825000000 1111 ttlorder.example. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ttlorder.example.	3600	IN	RRSIG	SOA 15 2 3600 20260924000000 20260825000000 1111 ttlorder.example. BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
ttlorder.example.	3600	IN	DNSKEY	257 3 15 TeEjjb0sCAkP9wO/0UXAcdfRhfSdkUf9PnPkLklRR04=
ttlorder.example.	3600	IN	RRSIG	DNSKEY 15 2 3600 20260924000000 20260825000000 1111 ttlorder.example. CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
ttlorder.example.	7200	IN	NSEC	ns.ttlorder.example. NS SOA RRSIG NSEC DNSKEY ZONEMD
ttlorder.example.	7200	IN	RRSIG	NSEC 15 2 7200 20260924000000 20260825000000 1111 ttlorder.example. DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
ns.ttlorder.example.	3600	IN	A	192.0.2.1
ns.ttlorder.example.	3600	IN	RRSIG	A 15 3 3600 20260924000000 20260825000000 1111 ttlorder.example. EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
ns.ttlorder.example.	7200	IN	NSEC	ttlorder.example. A RRSIG NSEC
ns.ttlorder.example.	7200	IN	RRSIG	NSEC 15 3 7200 20260924000000 20260825000000 1111 ttlorder.example. FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
`

func TestZoneDigestSortsRRSIGsByRdataNotByTTL(t *testing.T) {
	rrs := parseZoneRRs(t, "ttlorder.example.", ttlOrderZone)

	for _, tc := range []struct {
		alg  uint8
		want string
	}{
		{ZonemdAlgSHA384, "b74b05422c040c5ebf74406eb5d310302b289f6c4dca1de9a8bb6818a08b4b18" +
			"a270f68476bc45c221149d16143ff2b2"},
		{ZonemdAlgSHA512, "3e07069316f394a904ec99ce0d753f33242df90f7e3f9937bb6317b846073134" +
			"8491c93226e3bb58311170156ef7ea13f531e8dbd3244eaa05f76785c54558f6"},
	} {
		got, err := ZoneDigestHex("ttlorder.example.", rrs, ZonemdSchemeSimple, tc.alg)
		if err != nil {
			t.Fatalf("%s: %v", zonemdAlgName(tc.alg), err)
		}
		if got != tc.want {
			t.Errorf("%s digest disagrees with dnspython\n  got:  %s\n  want: %s",
				zonemdAlgName(tc.alg), got, tc.want)
		}
	}
}
