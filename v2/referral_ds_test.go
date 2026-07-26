package tdns

import (
	"fmt"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// TestSendReferral_SecureDelegationIncludesDS is the regression test for the
// tdns-auth secure-referral fix (RFC 4035 §3.1.4.1): a DO=1 referral for a
// secure delegation must carry the DS RRset and its RRSIG in the authority
// section, so a validating resolver can establish the child's chain of trust
// straight from the referral. Pre-fix, sendReferral added only NS + glue (and,
// wrongly, a no-DS NSEC), never the DS.
func TestSendReferral_SecureDelegationIncludesDS(t *testing.T) {
	zd := &ZoneData{ZoneName: "pq.axfr.net."}
	const child = "falcon512-mayo2.pq.axfr.net."

	nsRR := mustRR(t, child+" 3600 IN NS ns.pq.axfr.net.")
	dsRR := mustRR(t, child+" 3600 IN DS 23388 208 2 87C97FD4C8748E1507B76F098C398B47EBBC2145DBCEB45D004D650D537EF841")
	cdd := &ChildDelegationData{
		ChildName: child,
		NS_rrset:  &core.RRset{Name: child, RRtype: dns.TypeNS, Class: dns.ClassINET, RRs: []dns.RR{nsRR}},
		DS_rrset:  &core.RRset{Name: child, RRtype: dns.TypeDS, Class: dns.ClassINET, RRs: []dns.RR{dsRR}},
	}

	// Stub signer: attach a marker RRSIG(DS) so we can assert the DS was signed
	// and added, without needing a real signing key in the test.
	signFunc := func(rrset core.RRset, name string) (core.RRset, error) {
		rrset.RRSIGs = []dns.RR{mustRR(t, name+" 3600 IN RRSIG DS 15 4 3600 20260805122917 20260722122719 16089 pq.axfr.net. AA==")}
		return rrset, nil
	}

	w := &fakeRW{remote: udpAddr("127.0.0.1")}
	m := new(dns.Msg)
	zd.sendReferral(m, w, cdd, nil, &edns0.MsgOptions{DO: true}, signFunc)

	if w.written == nil {
		t.Fatal("sendReferral wrote no response")
	}
	var sawDS, sawDSSig bool
	for _, rr := range w.written.Ns {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDS {
				sawDSSig = true
			}
		default:
			if rr.Header().Rrtype == dns.TypeDS {
				sawDS = true
			}
		}
	}
	if !sawDS || !sawDSSig {
		t.Fatalf("secure referral must include DS (%v) and RRSIG(DS) (%v) in the authority section", sawDS, sawDSSig)
	}
}

// TestSendReferral_NonDNSSECHasNoDS confirms a plain (DO=0) referral carries no
// DNSSEC records — no DS, no NSEC.
func TestSendReferral_NonDNSSECHasNoDS(t *testing.T) {
	zd := &ZoneData{ZoneName: "pq.axfr.net."}
	const child = "falcon512-mayo2.pq.axfr.net."
	nsRR := mustRR(t, child+" 3600 IN NS ns.pq.axfr.net.")
	dsRR := mustRR(t, child+" 3600 IN DS 23388 208 2 87C97FD4C8748E1507B76F098C398B47EBBC2145DBCEB45D004D650D537EF841")
	cdd := &ChildDelegationData{
		ChildName: child,
		NS_rrset:  &core.RRset{Name: child, RRtype: dns.TypeNS, Class: dns.ClassINET, RRs: []dns.RR{nsRR}},
		DS_rrset:  &core.RRset{Name: child, RRtype: dns.TypeDS, Class: dns.ClassINET, RRs: []dns.RR{dsRR}},
	}
	signFunc := func(rrset core.RRset, name string) (core.RRset, error) { return rrset, nil }

	w := &fakeRW{remote: udpAddr("127.0.0.1")}
	m := new(dns.Msg)
	zd.sendReferral(m, w, cdd, nil, &edns0.MsgOptions{DO: false}, signFunc)

	if w.written == nil {
		t.Fatal("sendReferral wrote no response")
	}
	for _, rr := range w.written.Ns {
		if rr.Header().Rrtype == dns.TypeDS || rr.Header().Rrtype == dns.TypeNSEC {
			t.Fatalf("DO=0 referral must not carry DNSSEC records, got %s", dns.TypeToString[rr.Header().Rrtype])
		}
	}
}

// TestSendReferral_SignFailureIsNonFatal confirms the documented behavior that a
// DS signing failure does not abort the referral: the NS is still served and the
// DS is omitted (an unsigned DS would be useless), rather than SERVFAIL.
func TestSendReferral_SignFailureIsNonFatal(t *testing.T) {
	zd := &ZoneData{ZoneName: "pq.axfr.net."}
	const child = "falcon512-mayo2.pq.axfr.net."
	nsRR := mustRR(t, child+" 3600 IN NS ns.pq.axfr.net.")
	dsRR := mustRR(t, child+" 3600 IN DS 23388 208 2 87C97FD4C8748E1507B76F098C398B47EBBC2145DBCEB45D004D650D537EF841")
	cdd := &ChildDelegationData{
		ChildName: child,
		NS_rrset:  &core.RRset{Name: child, RRtype: dns.TypeNS, Class: dns.ClassINET, RRs: []dns.RR{nsRR}},
		DS_rrset:  &core.RRset{Name: child, RRtype: dns.TypeDS, Class: dns.ClassINET, RRs: []dns.RR{dsRR}},
	}
	signFunc := func(rrset core.RRset, name string) (core.RRset, error) {
		return core.RRset{}, fmt.Errorf("simulated signing failure")
	}

	w := &fakeRW{remote: udpAddr("127.0.0.1")}
	m := new(dns.Msg)
	zd.sendReferral(m, w, cdd, nil, &edns0.MsgOptions{DO: true}, signFunc)

	if w.written == nil {
		t.Fatal("sendReferral wrote no response")
	}
	var sawNS, sawDS bool
	for _, rr := range w.written.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeNS:
			sawNS = true
		case dns.TypeDS:
			sawDS = true
		}
	}
	if !sawNS {
		t.Fatal("referral must still carry NS after a DS signing failure")
	}
	if sawDS {
		t.Fatal("DS must be omitted when signing fails (an unsigned DS is useless)")
	}
}

// TestSendReferral_InsecureDelegationHasNSEC confirms the insecure branch: a DO=1
// referral for a delegation with no DS carries an NSEC proving no DS (RFC 9824
// §3.4) and no DS. addReferralNSEC reads apex.RRtypes for the SOA min-TTL, so a
// non-nil apex is required.
func TestSendReferral_InsecureDelegationHasNSEC(t *testing.T) {
	zd := &ZoneData{ZoneName: "pq.axfr.net."}
	const child = "insecure.pq.axfr.net."
	nsRR := mustRR(t, child+" 3600 IN NS ns.pq.axfr.net.")
	cdd := &ChildDelegationData{
		ChildName: child,
		NS_rrset:  &core.RRset{Name: child, RRtype: dns.TypeNS, Class: dns.ClassINET, RRs: []dns.RR{nsRR}},
		// DS_rrset nil → insecure delegation
	}
	apex := &OwnerData{Name: zd.ZoneName, RRtypes: NewRRTypeStore()}
	soa := mustRR(t, zd.ZoneName+" 3600 IN SOA ns.pq.axfr.net. hostmaster.pq.axfr.net. 1 3600 600 86400 600")
	apex.RRtypes.Set(dns.TypeSOA, core.RRset{Name: zd.ZoneName, RRtype: dns.TypeSOA, Class: dns.ClassINET, RRs: []dns.RR{soa}})

	// Stub signer that attaches a marker RRSIG(NSEC), so the test also proves
	// the NSEC's signature reaches the wire — an NSEC without its RRSIG proves
	// nothing to a validator.
	signFunc := func(rrset core.RRset, name string) (core.RRset, error) {
		if len(rrset.RRs) > 0 && rrset.RRs[0].Header().Rrtype == dns.TypeNSEC {
			rrset.RRSIGs = []dns.RR{mustRR(t, name+" 3600 IN RRSIG NSEC 15 3 3600 20260805122917 20260722122719 16089 pq.axfr.net. AA==")}
		}
		return rrset, nil
	}

	w := &fakeRW{remote: udpAddr("127.0.0.1")}
	m := new(dns.Msg)
	zd.sendReferral(m, w, cdd, apex, &edns0.MsgOptions{DO: true}, signFunc)

	if w.written == nil {
		t.Fatal("sendReferral wrote no response")
	}
	var sawNSEC, sawNSECSig, sawDS bool
	for _, rr := range w.written.Ns {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC {
				sawNSECSig = true
			}
		default:
			switch rr.Header().Rrtype {
			case dns.TypeNSEC:
				sawNSEC = true
			case dns.TypeDS:
				sawDS = true
			}
		}
	}
	if !sawNSEC {
		t.Fatal("insecure (no-DS) referral must carry an NSEC proving no DS")
	}
	if !sawNSECSig {
		t.Fatal("insecure (no-DS) referral must carry the RRSIG covering that NSEC")
	}
	if sawDS {
		t.Fatal("insecure delegation must not carry a DS")
	}
}
