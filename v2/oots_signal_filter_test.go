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
	"fmt"
	"log"
	"os"
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

// assertTCPNotChosen fails when Do53TCP is among the transports selection
// draws from. A tcp weight may be held, as a cap, but tdns never chooses
// optional TCP.
func assertTCPNotChosen(t *testing.T, label string, st signalState) {
	t.Helper()
	for _, tr := range st.Transports {
		if tr == core.TransportDo53TCP {
			t.Errorf("%s: transports %v hold Do53TCP", label, st.Transports)
		}
	}
}

// chosen is what selection acts on in a server's state: the transports it
// draws from and their weights. The cleartext weights, udp (Do53) and tcp
// (Do53TCP), are left out: Do53 gets what the encrypted weights leave, and
// tcp is not chosen at all, so neither changes a choice.
type chosen struct {
	Transports []core.Transport
	Weights    map[core.Transport]uint8
}

func chosenOf(st signalState) chosen {
	w := map[core.Transport]uint8{}
	for tr, v := range st.Weights {
		if core.IsEncryptedTransport(tr) {
			w[tr] = v
		}
	}
	return chosen{Transports: st.Transports, Weights: w}
}

const ootsTestNS = "ns.example."

// applySVCBForNS is what ParseAdditionalForNSAddrs does with one SVCB for a
// nameserver: collect it into the nameserver's set, then install the set. It
// reports whether a signal was installed.
func applySVCBForNS(imr *Imr, rr *dns.SVCB, serverName string, sm map[string]*cache.AuthServer) bool {
	pending := map[string]*svcbSignalSet{}
	imr.collectSVCBSignal(pending, serverName, rr)
	key := cache.ServerKey(serverName)
	installed, _ := imr.installSVCBSignal(sm[key], pending[key], notConfigured)
	return installed
}

// ootsTextSVCB is the _dns SVCB of ootsTestNS at target, parsed from its
// presentation form, so that tokens the codec only carries come through too.
func ootsTextSVCB(t *testing.T, target, oots string) *dns.SVCB {
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
// mix: udp, tcp (both at 0 and above), and an undefined token. ootsUnknown
// adds only undefined tokens, which leave the state exactly as without them.
var (
	ootsPlain     = "do53:100,dot:50,doq:20"
	ootsUnknown   = "do53:100,dot:50,doq:20,xyz:9,future-thing:42"
	ootsWithOther = []string{
		"do53:100,dot:50,doq:20,tcp:30",
		"udp:100,do53:100,dot:50,doq:20",
		"do53:100,tcp:0,udp:0,dot:50,doq:20,xyz:9",
		"tcp:100,dot:50,udp:30,do53:100,doq:20,future-thing:42",
	}
)

// A signal carrying udp, tcp or unknown tokens chooses what the same signal
// without them chooses, on the SVCB path: a direct answer, and Additional.
// Undefined tokens change nothing at all.
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
			applySVCBForNS(imr, ootsTextSVCB(t, ".", oots), ootsTestNS,
				map[string]*cache.AuthServer{cache.ServerKey(ootsTestNS): s})
		}
	}
	additional := func(oots string) func(*cache.AuthServer) {
		return func(s *cache.AuthServer) {
			r := new(dns.Msg)
			r.SetQuestion("www.example.", dns.TypeA)
			r.Extra = []dns.RR{ootsTextSVCB(t, ".", oots)}
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
			assertTCPNotChosen(t, label, got)
			if !reflect.DeepEqual(chosenOf(got), chosenOf(base)) {
				t.Errorf("%s: selection %+v, want the same as without the other tokens: %+v", label, chosenOf(got), chosenOf(base))
			}
		}
		if got := want(path.apply(ootsUnknown)); !reflect.DeepEqual(got, base) {
			t.Errorf("%s %s: state %+v, want the same as without the undefined tokens: %+v", path.name, ootsUnknown, got, base)
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
			assertTCPNotChosen(t, label, got)
			if !reflect.DeepEqual(chosenOf(got), chosenOf(base)) {
				t.Errorf("%s: selection %+v, want the same as without the other tokens: %+v", label, chosenOf(got), chosenOf(base))
			}
		}
		if got := run(path.apply(ootsUnknown)); !reflect.DeepEqual(got, base) {
			t.Errorf("%s %s: state %+v, want the same as without the undefined tokens: %+v", path.name, ootsUnknown, got, base)
		}
	}
}

// A signal that names only undefined tokens is no signal: it is not applied,
// so it neither installs the absence defaults nor replaces what another record
// said.
func TestReceivedSignalWithOnlyOtherTokensIsNotApplied(t *testing.T) {
	imr := &Imr{}
	ctx := context.Background()
	s := cache.NewAuthServer(ootsTestNS)
	sm := map[string]*cache.AuthServer{cache.ServerKey(ootsTestNS): s}
	applySVCBForNS(imr, ootsTextSVCB(t, ".", ootsPlain), ootsTestNS, sm)
	before := stateOf(s)

	only := ootsTextSVCB(t, ".", "xyz:30")
	if m, ok, err := GetTransportParamRaw(only); ok || err != nil || m != nil {
		t.Errorf("GetTransportParamRaw(only xyz) = %v, %v, %v; want no oots to act on", m, ok, err)
	}
	if applySVCBForNS(imr, only, ootsTestNS, sm) {
		t.Error("the NS-address path applied a record naming only xyz")
	}
	r := new(dns.Msg)
	r.Extra = []dns.RR{only, ootsTextSVCB(t, ".", "future-thing:100,xyz:1")}
	imr.parseTransportForServerFromAdditional(ctx, s, r)
	if imr.applyTransportSignalToServer(s, "xyz:30,future-thing:100") {
		t.Error("applyTransportSignalToServer applied a string naming only undefined tokens")
	}
	// The TSYNC parser reports that it looked, not that it applied; what
	// matters is the state, checked below.
	_ = imr.parseTSYNCTransportSignal(tsyncRR(t, "xyz:30"), ootsTestNS, sm, ctx)
	// do53-tcp is an operator alias of StringToTransport, not a token.
	if applyTransportMapToServer(s, map[string]uint8{"xyz": 30, "do53-tcp": 100}) {
		t.Error("applyTransportMapToServer applied a map naming no signal token")
	}
	if got := stateOf(s); !reflect.DeepEqual(got, before) {
		t.Errorf("state changed by signals naming only other tokens:\n got %+v\nwant %+v", got, before)
	}
}

// The filter accepts exactly the six signal tokens; StringToTransport's
// other operator aliases (do53-tcp, DoT, ...) are not signal tokens.
func TestSignalTokenFilter(t *testing.T) {
	for _, tok := range []string{"do53", "udp", "tcp", "dot", "doh", "doq"} {
		if !core.IsSignalToken(tok) {
			t.Errorf("IsSignalToken(%q) = false", tok)
		}
	}
	for _, tok := range []string{"do53-tcp", "DoT", "TCP", "UDP", "h2", "xyz", ""} {
		if core.IsSignalToken(tok) {
			t.Errorf("IsSignalToken(%q) = true", tok)
		}
	}
	m, err := core.ParseReceivedTransportString("do53:100, TCP:30 ,dot:150,udp:0,xyz:5")
	if err != nil {
		t.Fatalf("ParseReceivedTransportString: %v", err)
	}
	if want := map[string]uint8{"do53": 100, "tcp": 30, "udp": 0, "dot": 100}; !reflect.DeepEqual(m, want) {
		t.Errorf("ParseReceivedTransportString = %v, want %v", m, want)
	}
	if _, err := core.ParseReceivedTransportString("dot:5,dot:6"); err == nil {
		t.Error("ParseReceivedTransportString accepted a duplicate")
	}
	// The codec keeps a raw weight octet above 100; the reader clamps.
	if m := svcbOotsToRawMap(&dns.SVCBOots{Oots: []dns.SVCBOotsEntry{{Proto: "dot", Weight: 150}, {Proto: "tcp", Weight: 200}, {Proto: "xyz", Weight: 7}}}); !reflect.DeepEqual(m, map[string]uint8{"dot": 100, "tcp": 100}) {
		t.Errorf("svcbOotsToRawMap = %v, want dot:100 and tcp:100", m)
	}
}

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

	imr := &Imr{}
	fromAdditional := func(name string) signalState {
		s := cache.NewAuthServer(name)
		imr.parseTransportForServerFromAdditional(context.Background(), s, served)
		return stateOf(s)
	}
	applied := func(name string, m map[string]uint8) signalState {
		s := cache.NewAuthServer(name)
		applyTransportMapToServer(s, m)
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

// The ALPN fallback is a received path too: alpn tokens that are not signal
// tokens (do53-tcp, h2) are skipped, and an ALPN list naming none is not
// applied. A tcp in the list is read, and not chosen. Case does not matter.
func TestReceivedALPNSignalIgnoresOtherTokens(t *testing.T) {
	run := func(alpn string) signalState {
		s := cache.NewAuthServer(ootsTestNS)
		applyAlpnSignalToServer(s, alpn)
		return stateOf(s)
	}
	base := run("dot,doq")
	if base.Source != "alpn" || base.Weights[core.TransportDoT] != 100 {
		t.Fatalf("the plain ALPN signal was not applied: %+v", base)
	}
	for _, alpn := range []string{"do53-tcp,dot,doq,h2", "DoT,DoQ"} {
		if got := run(alpn); !reflect.DeepEqual(got, base) {
			t.Errorf("alpn %q: state %+v, want the same as dot,doq: %+v", alpn, got, base)
		}
	}
	for _, alpn := range []string{"dot,tcp,doq", "dot, TCP ,doq"} {
		got := run(alpn)
		assertTCPNotChosen(t, "alpn "+alpn, got)
		if !reflect.DeepEqual(chosenOf(got), chosenOf(base)) || got.Weights[core.TransportDo53TCP] != 100 {
			t.Errorf("alpn %q: %+v, want the choice of dot,doq and tcp at 100: %+v", alpn, got, base)
		}
	}
	// do53 in an ALPN list is udp and tcp, as in oots.
	if got := run("do53,dot"); got.Weights[core.TransportDo53] != 100 || got.Weights[core.TransportDo53TCP] != 100 ||
		!reflect.DeepEqual(got.Transports, []core.Transport{core.TransportDo53, core.TransportDoT}) {
		t.Errorf("alpn do53,dot: %+v, want udp and tcp at 100, Do53 and DoT chosen from", got)
	}
	if got := run("do53-tcp,h2,xyz"); got.Source != "" || len(got.Weights) != 0 {
		t.Errorf("an ALPN list naming no signal token was applied: %+v", got)
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

// An SVCB whose oots names no signal token is ignored whole: its alpn is not
// read in place of the oots, on any of the three paths an SVCB arrives by
// (direct answer, Additional, an answer RRset). An oots has always taken
// precedence over alpn in the same record. A record without oots still gets
// the alpn fallback.
func TestOOTSWithoutSignalTokenIgnoresALPN(t *testing.T) {
	ctx := context.Background()
	newImr := func() *Imr {
		return &Imr{Cache: cache.NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false), Quiet: true}
	}
	paths := []struct {
		name  string
		apply func(*Imr, *cache.AuthServer, *dns.SVCB)
	}{
		{"answer", func(imr *Imr, s *cache.AuthServer, rr *dns.SVCB) {
			applySVCBForNS(imr, rr, ootsTestNS, map[string]*cache.AuthServer{cache.ServerKey(ootsTestNS): s})
		}},
		{"additional", func(imr *Imr, s *cache.AuthServer, rr *dns.SVCB) {
			r := new(dns.Msg)
			r.SetQuestion("www.example.", dns.TypeA)
			r.Extra = []dns.RR{rr}
			imr.parseTransportForServerFromAdditional(ctx, s, r)
		}},
		{"rrset", func(imr *Imr, s *cache.AuthServer, rr *dns.SVCB) {
			imr.Cache.ServerMap.Set("example.", map[string]*cache.AuthServer{cache.ServerKey(ootsTestNS): s})
			imr.applyTransportRRsetFromAnswer("_dns."+ootsTestNS,
				&core.RRset{Name: "_dns." + ootsTestNS, RRtype: dns.TypeSVCB, RRs: []dns.RR{rr}},
				cache.ValidationStateInsecure)
		}},
	}
	svcb := func(params string) *dns.SVCB {
		return mustSVCB(t, fmt.Sprintf("_dns.%s 10800 IN SVCB 1 . %s", ootsTestNS, params)).(*dns.SVCB)
	}
	for _, path := range paths {
		for _, params := range []string{`alpn="dot" oots="xyz:30"`, `alpn="tcp" oots="xyz:30,future-thing:100"`} {
			imr := newImr()
			s := cache.NewAuthServer(ootsTestNS)
			applyTransportMapToServer(s, map[string]uint8{"do53": 100, "doq": 40})
			before := stateOf(s)
			path.apply(imr, s, svcb(params))
			got := stateOf(s)
			if !reflect.DeepEqual(got, before) {
				t.Errorf("%s %s: the server's signal changed to %+v, want it kept: %+v", path.name, params, got, before)
			}
		}
		// Without oots the alpn fallback still applies.
		imr := newImr()
		s := cache.NewAuthServer(ootsTestNS)
		path.apply(imr, s, svcb(`alpn="dot"`))
		if got := stateOf(s); got.Source != "alpn" || got.Weights[core.TransportDoT] != 100 {
			t.Errorf("%s: an alpn-only record was not applied: %+v", path.name, got)
		}
	}
}
