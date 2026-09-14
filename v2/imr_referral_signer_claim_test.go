/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A DS whose RRSIG merely names a zone the resolver holds Insecure is no DS.
 */
package tdns

import (
	"crypto"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// dsSignedInTheNameOf returns ds with an RRSIG made by a key nobody holds, whose
// Signer's Name is signer. Anyone on the path can make one.
func dsSignedInTheNameOf(ds dns.RR, signer string) []dns.RR {
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: signer, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	p, err := k.Generate(256)
	if err != nil {
		panic(err)
	}
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: k.KeyTag(), SignerName: signer,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(p.(crypto.Signer), []dns.RR{ds}); err != nil {
		panic(err)
	}
	return []dns.RR{ds, sig}
}

// The referral's DS is the parent's, genuine, but its RRSIG has been replaced by
// one naming a zone the resolver holds Insecure. The validator consulted the
// named signer's state before verifying anything, so the DS validated Insecure,
// and an Insecure DS made the child Insecure or unjudged: its answers were
// served.
func TestAReferralDSSignedInTheNameOfAnInsecureZoneIsNoDS(t *testing.T) {
	signers := []struct{ name, signer string }{
		{"an insecure ancestor", "example."},
		{"an unrelated insecure zone", "other."},
	}
	answers := []struct {
		name   string
		answer kidAnswer
	}{{"tampered", kidTampered}, {"stripped", kidStripped}}
	for _, s := range signers {
		for _, a := range answers {
			t.Run(s.name+"/"+a.name, func(t *testing.T) {
				imr, _ := newReferralImr(t, referralSetup{answer: a.answer, path: func(z *referralZones) referralPath {
					return referralPath{referral: dsSignedInTheNameOf(z.ds[0], s.signer), dsAnswer: z.ds}
				}})
				imr.Cache.ZoneMap.Set(s.signer, &cache.Zone{ZoneName: s.signer, State: cache.ValidationStateInsecure})
				for _, via := range []string{"fresh", "cached"} {
					m := askReferralImr(t, imr, refKidWWW)
					if state := zoneStateOf(imr, refKid); state == "insecure" {
						t.Errorf("%s: child zone is %s", via, state)
					}
					if m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 {
						t.Errorf("%s: rcode %s with answer %v; a %s answer from a signed child must be SERVFAIL",
							via, dns.RcodeToString[m.Rcode], m.Answer, a.name)
					}
				}
				if m := askReferralImr(t, imr, refKidMail); m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 {
					t.Errorf("then %s: rcode %s with answer %v; want SERVFAIL", refKidMail, dns.RcodeToString[m.Rcode], m.Answer)
				}
			})
		}
	}
}
