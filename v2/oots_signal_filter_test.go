/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A received transport signal is acted on for the signal tokens only: udp
 * and tcp, dot, doh and doq, and do53, the shorthand for udp and tcp. Tokens
 * not yet defined are kept on the wire by the dns codec, so a record re-packs
 * to the bytes it was signed as, and selection never sees them. udp and tcp
 * are read, but neither makes the resolver choose TCP: a tcp weight caps only
 * the TCP chosen on its own, and tdns chooses none. Design: the
 * alternative-endpoint note, tdns #1043, sections 2, 3 and 8.
 */
package tdns

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	imrcore "github.com/johanix/tdns/v2/imr"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// tdns-auth refuses, at config load, a published signal naming a token that is
// not defined.
func TestPublishedTransportSignalRefusesOtherTokens(t *testing.T) {
	for _, tc := range []struct {
		typ, signal string
		ok          bool
	}{
		{"svcb", "doq:20,dot:10", true},
		{"tsync", "do53:0,doh:5", true},
		{"SVCB", "dot:10", true},
		{"svcb", "", true},
		// From S5 on the publisher emits udp and tcp.
		{"svcb", "dot:10,tcp:30", true},
		{"tsync", "udp:100", true},
		{"svcb", "dot:10,xyz:30", false},
		{"svcb", "xyz:1", false},
		{"svcb", "dot:10,", false},
		{"svcb", "dot", false},
		// Not published: not checked.
		{"none", "xyz:30", true},
		{"", "xyz:30", true},
	} {
		err := TransportConf{Type: tc.typ, Signal: tc.signal}.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("Validate(type %q, signal %q) = %v, want ok=%v", tc.typ, tc.signal, err, tc.ok)
		}
	}
}

// ootsZone carries _dns SVCBs that a tdns node of this version must keep as
// written: one mixing signal tokens with others, one whose only entry is tcp
// (which the old codec re-packed as an empty value), one naming only undefined
// tokens, and one naming only tcp at an alternative host. A node that loads, signs and serves the zone must
// serve the RDATA as written, and the RRSIG must still verify over what a
// receiver unpacks off the wire and packs again.
//
// The alternative-host record sits at a name that is not an NS's signal
// owner: tdns-auth today reads a ServiceMode record with a target as an alias
// (svcbHasAlias) and injects it only when vouched for, which is the auth-side
// step of the plan, not this one. It is checked by a direct query.
const ootsZone = `oots.example.	3600	IN	SOA	ns.oots.example. hostmaster.oots.example. 1 7200 1800 604800 7200
oots.example.	3600	IN	NS	ns.oots.example.
oots.example.	3600	IN	NS	ns2.oots.example.
oots.example.	3600	IN	NS	ns3.oots.example.
ns.oots.example.	3600	IN	A	127.0.0.1
ns2.oots.example.	3600	IN	A	127.0.0.2
ns3.oots.example.	3600	IN	A	127.0.0.3
www.oots.example.	3600	IN	A	192.0.2.1
_dns.ns.oots.example.	3600	IN	SVCB	1 . oots="do53:100,tcp:30,dot:50,udp:100,xyz:9"
_dns.ns2.oots.example.	3600	IN	SVCB	1 . oots="tcp:30"
_dns.ns3.oots.example.	3600	IN	SVCB	1 . oots="xyz:9,future-thing:42"
_dns.alt.oots.example.	3600	IN	SVCB	1 tcp-alt.oots.example. oots="tcp:30"
`

var ootsZoneSignals = map[string]string{
	"_dns.ns.oots.example.":  `1 . oots="do53:100,tcp:30,dot:50,udp:100,xyz:9"`,
	"_dns.ns2.oots.example.": `1 . oots="tcp:30"`,
	"_dns.ns3.oots.example.": `1 . oots="xyz:9,future-thing:42"`,
	"_dns.alt.oots.example.": `1 tcp-alt.oots.example. oots="tcp:30"`,
}

// rdataBytes is the uncompressed wire RDATA of rr: the last Rdlength octets
// PackRR writes (PackRR sets Rdlength).
func rdataBytes(t *testing.T, rr dns.RR) []byte {
	t.Helper()
	buf := make([]byte, dns.Len(rr)+256)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		t.Fatalf("PackRR(%s): %v", rr, err)
	}
	return append([]byte(nil), buf[off-int(rr.Header().Rdlength):off]...)
}

func ootsSignedZone(t *testing.T) (*ZoneData, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := testZone(t, "oots.example.", ootsZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptAddTransportSignal: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity: PolicySigValidity{
			Default: 30 * 86400, DNSKEY: 30 * 86400, DS: 30 * 86400,
		},
	}
	zd.InstallInitialSnapshot()
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	return zd, kdb
}

func zoneDNSKEYs(t *testing.T, zd *ZoneData, kdb *KeyDB) []*dns.DNSKEY {
	t.Helper()
	m := denialAsk(t, zd, kdb, "oots.example.", dns.TypeDNSKEY, false)
	var keys []*dns.DNSKEY
	for _, rr := range m.Answer {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		t.Fatal("the signed zone serves no DNSKEY")
	}
	return keys
}

// wireTrip packs m and unpacks it, as a receiver would get it.
func wireTrip(t *testing.T, m *dns.Msg) *dns.Msg {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got := new(dns.Msg)
	if err := got.Unpack(b); err != nil {
		t.Fatalf("Unpack of the served response: %v", err)
	}
	b2, err := got.Pack()
	if err != nil {
		t.Fatalf("Pack again: %v", err)
	}
	again := new(dns.Msg)
	if err := again.Unpack(b2); err != nil {
		t.Fatalf("Unpack of the re-packed response: %v", err)
	}
	return again
}

// A zone with such _dns SVCBs loads and is served with byte-identical RDATA,
// and the RRSIG still validates, also after a receiver re-packs the answer.
func TestOOTSOtherTokensServedLosslessAndSigned(t *testing.T) {
	zd, kdb := ootsSignedZone(t)
	keys := zoneDNSKEYs(t, zd, kdb)
	for owner, rdata := range ootsZoneSignals {
		want, err := dns.NewRR(owner + " 3600 IN SVCB " + rdata)
		if err != nil {
			t.Fatalf("NewRR: %v", err)
		}
		m := denialAsk(t, zd, kdb, owner, dns.TypeSVCB, false)
		for _, served := range []*dns.Msg{m, wireTrip(t, m)} {
			var svcbs []dns.RR
			var sigs int
			for _, rr := range served.Answer {
				switch rr.(type) {
				case *dns.SVCB:
					svcbs = append(svcbs, rr)
				case *dns.RRSIG:
					sigs++
				}
			}
			if len(svcbs) != 1 || sigs == 0 {
				t.Fatalf("%s: answer %v, want the SVCB and its RRSIG", owner, served.Answer)
			}
			if got := rdataBytes(t, svcbs[0]); !bytes.Equal(got, rdataBytes(t, want)) {
				t.Errorf("%s: served RDATA %x, want %x as written (%s)", owner, got, rdataBytes(t, want), svcbs[0])
			}
			if svcbs[0].String() != want.String() {
				t.Errorf("%s: served %q, want %q", owner, svcbs[0].String(), want.String())
			}
			verifySection(t, served.Answer, keys)
		}
	}
}

// The records whose only entry is tcp, or only undefined tokens, served in
// Additional beside a mixed one, do not break the response: they pack, unpack
// and keep their RRSIGs valid. The resolver reading them applies tcp:30, with
// udp at its default, and nothing from the undefined tokens, while the mixed
// record's signal tokens are applied as without the undefined one.
func TestOOTSOnlyOtherTokensInAdditional(t *testing.T) {
	zd, kdb := ootsSignedZone(t)
	keys := zoneDNSKEYs(t, zd, kdb)

	req := new(dns.Msg)
	req.SetQuestion("www.oots.example.", dns.TypeA)
	req.SetEdns0(4096, true)
	if err := edns0.AddOOTSToMessage(req); err != nil {
		t.Fatalf("AddOOTSToMessage: %v", err)
	}
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	rw := &fakeRW{}
	if err := zd.QueryResponder(context.Background(), rw, req, "www.oots.example.", dns.TypeA, msgo, kdb, nil); err != nil {
		t.Fatalf("QueryResponder: %v", err)
	}
	if rw.written == nil {
		t.Fatal("no response written")
	}
	served := wireTrip(t, rw.written)
	if len(served.Answer) == 0 {
		t.Fatalf("no answer: %v", served)
	}
	for owner, want := range map[string]string{
		"_dns.ns2.oots.example.": "_dns.ns2.oots.example.\t3600\tIN\tSVCB\t1 . oots=\"tcp:30\"",
		"_dns.ns3.oots.example.": "_dns.ns3.oots.example.\t3600\tIN\tSVCB\t1 . oots=\"xyz:9,future-thing:42\"",
	} {
		var found *dns.SVCB
		for _, rr := range served.Extra {
			if s, ok := rr.(*dns.SVCB); ok && strings.EqualFold(s.Hdr.Name, owner) {
				found = s
			}
		}
		if found == nil {
			t.Fatalf("the signal at %s is not in Additional: %v", owner, served.Extra)
		}
		if got := found.String(); got != want {
			t.Errorf("Additional holds %q, want %q", got, want)
		}
	}
	var extra []dns.RR
	signed := map[string]bool{}
	for _, rr := range served.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeSVCB {
			signed[strings.ToLower(sig.Hdr.Name)] = true
		}
	}
	// verifySection insists on signatures for NSEC and SOA only; an SVCB in
	// Additional that lost its RRSIG would pass it, so require one here.
	for _, rr := range served.Extra {
		if _, ok := rr.(*dns.SVCB); ok && !signed[strings.ToLower(rr.Header().Name)] {
			t.Errorf("Additional SVCB %s has no RRSIG", rr.Header().Name)
		}
	}
	verifySection(t, extra, keys)

	imr := &Imr{Imr: &imrcore.Imr{}}
	fromAdditional := func(name string) signalState {
		s := cache.NewAuthServer(name)
		imr.TransportSignalFromAdditional(context.Background(), s, served)
		return stateOf(s)
	}
	applied := func(name string, m map[string]uint8) signalState {
		s := cache.NewAuthServer(name)
		imrcore.ApplyTransportSignal(s, m)
		return stateOf(s)
	}
	if st := fromAdditional("ns3.oots.example."); st.Source != "" || len(st.Weights) != 0 {
		t.Errorf("a resolver applied the signal of undefined tokens only: %+v", st)
	}
	got2 := fromAdditional("ns2.oots.example.")
	assertTCPNotChosen(t, "ns2 from Additional", got2)
	if want := applied("ns2.oots.example.", map[string]uint8{"tcp": 30}); !reflect.DeepEqual(got2, want) || got2.Weights[core.TransportDo53TCP] != 30 || got2.Weights[core.TransportDo53] != 100 {
		t.Errorf("ns2 from Additional: %+v, want tcp:30 with udp at its default 100: %+v", got2, want)
	}
	got := fromAdditional("ns.oots.example.")
	assertTCPNotChosen(t, "ns from Additional", got)
	if want := applied("ns.oots.example.", map[string]uint8{"do53": 100, "tcp": 30, "dot": 50, "udp": 100}); !reflect.DeepEqual(got, want) {
		t.Errorf("ns from Additional: %+v, want its signal tokens alone: %+v", got, want)
	}
}

// config check refuses the signal too (ValidateConfig), and the message names
// the publishable tokens from the check's own set.
func TestValidateConfigRefusesOtherTokensInSignal(t *testing.T) {
	cfg := writeCfg(t, "service:\n   transport:\n      type: svcb\n      signal: \"dot:10,xyz:30\"\n")
	err := ValidateConfig(nil, cfg)
	if err == nil || !strings.Contains(err.Error(), "service.transport.signal") || !strings.Contains(err.Error(), "xyz") {
		t.Fatalf("ValidateConfig = %v, want a service.transport.signal error naming xyz", err)
	}
	if !strings.Contains(err.Error(), "do53, doh, doq, dot, tcp, udp") {
		t.Errorf("ValidateConfig = %v, want the publishable tokens named from the check's set", err)
	}
}
