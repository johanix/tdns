/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The digest and the verifier must fold names by the same rule.
 */
package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// ZoneDigest decides which records sit at the apex by EXCLUDING them;
// VerifyZonemd decides the same thing by SELECTING them. Both are exported.
// Folded by two different functions they agree on every ASCII name and part
// company on the first octet that is not valid UTF-8 -- at which point a zone
// digests one set of records and is verified against another, and a correct
// zone reports as broken.
//
// Computed with one, verified with the other, end to end.
func TestVerifyZonemdFoldsLikeTheDigest(t *testing.T) {
	for _, apex := range []string{
		"example.",
		"EXAMPLE.",     // ASCII case: both folders always agreed here
		"ex\xffample.", // a raw octet: this is where they parted company
	} {
		t.Run(strings.ToValidUTF8(apex, "?"), func(t *testing.T) {
			mk := func(text string) dns.RR {
				t.Helper()
				rr, err := dns.NewRR(text)
				if err != nil {
					t.Fatalf("building %q: %v", text, err)
				}
				return rr
			}
			// Built by hand so the owner carries the exact octets, without
			// going through presentation-format escaping.
			soa := mk("placeholder. 3600 IN SOA ns.example. hostmaster.example. 7 7200 1800 604800 7200")
			soa.Header().Name = apex
			ns := mk("placeholder. 3600 IN NS ns.example.")
			ns.Header().Name = apex
			a := mk("ns.example. 3600 IN A 192.0.2.1")

			rrs := []dns.RR{soa, ns, a}

			digest, err := ZoneDigestHex(apex, rrs, ZonemdSchemeSimple, ZonemdAlgSHA384)
			if err != nil {
				t.Fatalf("ZoneDigestHex: %v", err)
			}

			zonemd := &dns.ZONEMD{
				Hdr:    dns.RR_Header{Name: apex, Rrtype: dns.TypeZONEMD, Class: dns.ClassINET, Ttl: 3600},
				Serial: 7, Scheme: ZonemdSchemeSimple, Hash: ZonemdAlgSHA384, Digest: digest,
			}

			rep, err := VerifyZonemd(apex, append(rrs, zonemd), VerifyZonemdOpts{})
			if err != nil {
				t.Fatalf("VerifyZonemd: %v", err)
			}
			if len(rep.Checks) != 1 {
				t.Fatalf("verifier found %d ZONEMD records, want 1: it is not "+
					"selecting the apex the digest excluded", len(rep.Checks))
			}
			if !rep.Checks[0].DigestMatch {
				t.Errorf("a digest computed by ZoneDigest does not verify: "+
					"computed=%s published=%s", rep.Checks[0].Computed, rep.Checks[0].Published)
			}
		})
	}
}
