/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A received transport signal is acted on for the signal tokens only (do53,
 * dot, doh, doq until the token split). Other tokens -- udp and tcp from the
 * split, or tokens not yet defined -- are kept on the wire by the dns codec, so
 * a record re-packs to the bytes it was signed as, and selection never sees
 * them. Design: the alternative-endpoint note, tdns #1043, section 8.
 */
package tdns

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// signalState is what selection holds for a server after a signal: the set of
// transports, their weights, and the signal as received. Transports are
// sorted: applyTransportMapToServer builds them from a map.
type signalState struct {
	Transports []core.Transport
	Weights    map[core.Transport]uint8
	Received   map[core.Transport]uint8
	Source     string
}

func stateOf(s *cache.AuthServer) signalState {
	ts, ws := s.GetTransportSignal()
	ts = append([]core.Transport(nil), ts...)
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	st := signalState{Transports: ts, Weights: ws}
	if r := s.GetReceivedSignal(); r != nil {
		st.Received, st.Source = r.Weights, r.Source
	}
	return st
}

func assertNoDo53TCP(t *testing.T, label string, st signalState) {
	t.Helper()
	for _, tr := range st.Transports {
		if tr == core.TransportDo53TCP {
			t.Errorf("%s: transports %v hold Do53TCP", label, st.Transports)
		}
	}
	if _, ok := st.Weights[core.TransportDo53TCP]; ok {
		t.Errorf("%s: weights %v hold a Do53TCP weight", label, st.Weights)
	}
	if _, ok := st.Received[core.TransportDo53TCP]; ok {
		t.Errorf("%s: received signal %v holds a Do53TCP weight", label, st.Received)
	}
}

const ootsTestNS = "ns.example."

func ootsSVCB(t *testing.T, target, oots string) *dns.SVCB {
	t.Helper()
	rr := mustSVCB(t, fmt.Sprintf(`_dns.%s 10800 IN SVCB 1 %s oots=%q`, ootsTestNS, target, oots))
	return rr.(*dns.SVCB)
}

func tsyncRR(t *testing.T, transports string) *dns.PrivateRR {
	t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf(`_dns.%s 10800 IN TSYNC . "transport=%s" "v4=" "v6="`, ootsTestNS, transports))
	if err != nil {
		t.Fatalf("TSYNC: %v", err)
	}
	return rr.(*dns.PrivateRR)
}

// The signal without the other tokens, and the same signal with them in every
// mix: udp, tcp (both at 0 and above), and an undefined token.
var (
	ootsPlain     = "do53:100,dot:50,doq:20"
	ootsWithOther = []string{
		"do53:100,dot:50,doq:20,tcp:30",
		"udp:100,do53:100,dot:50,doq:20",
		"do53:100,tcp:0,udp:0,dot:50,doq:20,xyz:9",
		"tcp:100,dot:50,udp:30,do53:100,doq:20,future-thing:42",
	}
)

// A signal carrying udp, tcp or unknown tokens yields the same selection as one
// without them, on the SVCB path: a direct answer, and Additional.
func TestReceivedSVCBSignalIgnoresOtherTokens(t *testing.T) {
	imr := &Imr{}
	ctx := context.Background()

	want := func(apply func(*cache.AuthServer)) signalState {
		s := cache.NewAuthServer(ootsTestNS)
		apply(s)
		return stateOf(s)
	}
	direct := func(oots string) func(*cache.AuthServer) {
		return func(s *cache.AuthServer) {
			imr.parseSVCBTransportSignal(ootsSVCB(t, ".", oots), ootsTestNS,
				map[string]*cache.AuthServer{cache.ServerKey(ootsTestNS): s}, ctx)
		}
	}
	additional := func(oots string) func(*cache.AuthServer) {
		return func(s *cache.AuthServer) {
			r := new(dns.Msg)
			r.SetQuestion("www.example.", dns.TypeA)
			r.Extra = []dns.RR{ootsSVCB(t, ".", oots)}
			imr.parseTransportForServerFromAdditional(ctx, s, r)
		}
	}

	for _, path := range []struct {
		name  string
		apply func(string) func(*cache.AuthServer)
	}{{"answer", direct}, {"additional", additional}} {
		base := want(path.apply(ootsPlain))
		if base.Source != "oots" || base.Weights[core.TransportDoT] != 50 {
			t.Fatalf("%s: the plain signal was not applied: %+v", path.name, base)
		}
		for _, oots := range ootsWithOther {
			got := want(path.apply(oots))
			label := path.name + " " + oots
			assertNoDo53TCP(t, label, got)
			if !reflect.DeepEqual(got, base) {
				t.Errorf("%s: selection %+v, want the same as without the other tokens: %+v", label, got, base)
			}
		}
	}
}

// The same on the TSYNC path: the transport= string of a TSYNC record, direct
// and in Additional, and the string alone.
func TestReceivedTSYNCSignalIgnoresOtherTokens(t *testing.T) {
	imr := &Imr{}
	ctx := context.Background()

	run := func(apply func(*cache.AuthServer)) signalState {
		s := cache.NewAuthServer(ootsTestNS)
		apply(s)
		return stateOf(s)
	}
	paths := []struct {
		name  string
		apply func(string) func(*cache.AuthServer)
	}{
		{"tsync-answer", func(tr string) func(*cache.AuthServer) {
			return func(s *cache.AuthServer) {
				imr.parseTSYNCTransportSignal(tsyncRR(t, tr), ootsTestNS,
					map[string]*cache.AuthServer{cache.ServerKey(ootsTestNS): s}, ctx)
			}
		}},
		{"tsync-additional", func(tr string) func(*cache.AuthServer) {
			return func(s *cache.AuthServer) {
				r := new(dns.Msg)
				r.SetQuestion("www.example.", dns.TypeA)
				r.Extra = []dns.RR{tsyncRR(t, tr)}
				imr.parseTransportForServerFromAdditional(ctx, s, r)
			}
		}},
		{"string", func(tr string) func(*cache.AuthServer) {
			return func(s *cache.AuthServer) { imr.applyTransportSignalToServer(s, tr) }
		}},
	}
	for _, path := range paths {
		base := run(path.apply(ootsPlain))
		if base.Source != "oots" || base.Weights[core.TransportDoT] != 50 {
			t.Fatalf("%s: the plain signal was not applied: %+v", path.name, base)
		}
		for _, tr := range ootsWithOther {
			got := run(path.apply(tr))
			label := path.name + " " + tr
			assertNoDo53TCP(t, label, got)
			if !reflect.DeepEqual(got, base) {
				t.Errorf("%s: selection %+v, want the same as without the other tokens: %+v", label, got, base)
			}
		}
	}
}

// A signal that names only other tokens is no signal: it is not applied, so it
// neither installs the absence defaults nor replaces what another record said.
func TestReceivedSignalWithOnlyOtherTokensIsNotApplied(t *testing.T) {
	imr := &Imr{}
	ctx := context.Background()
	s := cache.NewAuthServer(ootsTestNS)
	sm := map[string]*cache.AuthServer{cache.ServerKey(ootsTestNS): s}
	imr.parseSVCBTransportSignal(ootsSVCB(t, ".", ootsPlain), ootsTestNS, sm, ctx)
	before := stateOf(s)

	only := ootsSVCB(t, "tcp-ns.example.", "tcp:30")
	if m, ok, err := GetTransportParamRaw(only); ok || err != nil || m != nil {
		t.Errorf("GetTransportParamRaw(only tcp) = %v, %v, %v; want no oots to act on", m, ok, err)
	}
	if imr.parseSVCBTransportSignal(only, ootsTestNS, sm, ctx) {
		t.Error("parseSVCBTransportSignal applied a record naming only tcp")
	}
	r := new(dns.Msg)
	r.Extra = []dns.RR{only, ootsSVCB(t, ".", "udp:100,xyz:1")}
	imr.parseTransportForServerFromAdditional(ctx, s, r)
	if imr.applyTransportSignalToServer(s, "tcp:30,udp:100") {
		t.Error("applyTransportSignalToServer applied a string naming only tcp and udp")
	}
	// The TSYNC parser reports that it looked, not that it applied; what
	// matters is the state, checked below.
	_ = imr.parseTSYNCTransportSignal(tsyncRR(t, "tcp:30"), ootsTestNS, sm, ctx)
	if applyTransportMapToServer(s, map[string]uint8{"tcp": 30, "udp": 100}) {
		t.Error("applyTransportMapToServer applied a map naming only tcp and udp")
	}
	if got := stateOf(s); !reflect.DeepEqual(got, before) {
		t.Errorf("state changed by signals naming only other tokens:\n got %+v\nwant %+v", got, before)
	}
}

// The filter accepts exactly the four signal tokens; StringToTransport's
// operator aliases (tcp, do53-tcp, DoT, ...) are not signal tokens.
func TestSignalTokenFilter(t *testing.T) {
	for _, tok := range []string{"do53", "dot", "doh", "doq"} {
		if !core.IsSignalToken(tok) {
			t.Errorf("IsSignalToken(%q) = false", tok)
		}
	}
	for _, tok := range []string{"tcp", "udp", "do53-tcp", "DoT", "TCP", "h2", "xyz", ""} {
		if core.IsSignalToken(tok) {
			t.Errorf("IsSignalToken(%q) = true", tok)
		}
	}
	m, err := core.ParseReceivedTransportString("do53:100, TCP:30 ,dot:150,udp:0")
	if err != nil {
		t.Fatalf("ParseReceivedTransportString: %v", err)
	}
	if want := map[string]uint8{"do53": 100, "dot": 100}; !reflect.DeepEqual(m, want) {
		t.Errorf("ParseReceivedTransportString = %v, want %v", m, want)
	}
	if _, err := core.ParseReceivedTransportString("dot:5,dot:6"); err == nil {
		t.Error("ParseReceivedTransportString accepted a duplicate")
	}
	// The codec keeps a raw weight octet above 100; the reader clamps.
	if m := svcbOotsToRawMap(&dns.SVCBOots{Oots: []dns.SVCBOotsEntry{{Proto: "dot", Weight: 150}, {Proto: "tcp", Weight: 200}}}); !reflect.DeepEqual(m, map[string]uint8{"dot": 100}) {
		t.Errorf("svcbOotsToRawMap = %v, want dot:100 alone", m)
	}
}

// tdns-auth refuses, at config load, a published signal naming another token.
func TestPublishedTransportSignalRefusesOtherTokens(t *testing.T) {
	for _, tc := range []struct {
		typ, signal string
		ok          bool
	}{
		{"svcb", "doq:20,dot:10", true},
		{"tsync", "do53:0,doh:5", true},
		{"SVCB", "dot:10", true},
		{"svcb", "", true},
		{"svcb", "dot:10,tcp:30", false},
		{"tsync", "udp:100", false},
		{"svcb", "xyz:1", false},
		{"svcb", "dot:10,", false},
		{"svcb", "dot", false},
		// Not published: not checked.
		{"none", "tcp:30", true},
		{"", "tcp:30", true},
	} {
		err := TransportConf{Type: tc.typ, Signal: tc.signal}.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("Validate(type %q, signal %q) = %v, want ok=%v", tc.typ, tc.signal, err, tc.ok)
		}
	}
}

// ootsZone carries _dns SVCBs that a tdns node of this version must keep as
// written: one mixing signal tokens with others, one whose only entry is tcp
// (which the old codec re-packed as an empty value), and one naming only tcp
// at an alternative host. A node that loads, signs and serves the zone must
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
ns.oots.example.	3600	IN	A	127.0.0.1
ns2.oots.example.	3600	IN	A	127.0.0.2
www.oots.example.	3600	IN	A	192.0.2.1
_dns.ns.oots.example.	3600	IN	SVCB	1 . oots="do53:100,tcp:30,dot:50,udp:100,xyz:9"
_dns.ns2.oots.example.	3600	IN	SVCB	1 . oots="tcp:30"
_dns.alt.oots.example.	3600	IN	SVCB	1 tcp-alt.oots.example. oots="tcp:30"
`

var ootsZoneSignals = map[string]string{
	"_dns.ns.oots.example.":  `1 . oots="do53:100,tcp:30,dot:50,udp:100,xyz:9"`,
	"_dns.ns2.oots.example.": `1 . oots="tcp:30"`,
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

// The record whose only entry is tcp, served in Additional beside a mixed one,
// does not break the response: it packs, unpacks, keeps its RRSIG valid, and
// the resolver reading it applies nothing, while the mixed record's signal
// tokens are applied as without the others.
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
	var onlyTCP *dns.SVCB
	for _, rr := range served.Extra {
		if s, ok := rr.(*dns.SVCB); ok && strings.EqualFold(s.Hdr.Name, "_dns.ns2.oots.example.") {
			onlyTCP = s
		}
	}
	if onlyTCP == nil {
		t.Fatalf("the only-tcp signal is not in Additional: %v", served.Extra)
	}
	if got, want := onlyTCP.String(), "_dns.ns2.oots.example.\t3600\tIN\tSVCB\t1 . oots=\"tcp:30\""; got != want {
		t.Errorf("Additional holds %q, want %q", got, want)
	}
	var extra []dns.RR
	for _, rr := range served.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	verifySection(t, extra, keys)

	imr := &Imr{}
	s2 := cache.NewAuthServer("ns2.oots.example.")
	imr.parseTransportForServerFromAdditional(context.Background(), s2, served)
	if st := stateOf(s2); st.Source != "" || len(st.Weights) != 0 {
		t.Errorf("a resolver applied the only-tcp signal: %+v", st)
	}
	s1 := cache.NewAuthServer("ns.oots.example.")
	imr.parseTransportForServerFromAdditional(context.Background(), s1, served)
	want := cache.NewAuthServer("ns.oots.example.")
	applyTransportMapToServer(want, map[string]uint8{"do53": 100, "dot": 50})
	got := stateOf(s1)
	assertNoDo53TCP(t, "ns from Additional", got)
	if !reflect.DeepEqual(got, stateOf(want)) {
		t.Errorf("ns from Additional: selection %+v, want do53:100,dot:50 alone: %+v", got, stateOf(want))
	}
}
