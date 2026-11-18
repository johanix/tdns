/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const pathNS = "ns.kid.p.test."
const pathOwner = "_dns." + pathNS

// signalOnEachPath runs one nameserver's SVCB RRs through each path a signal
// arrives by and returns the server each path left behind: the Additional
// section of a response from that server, the Additional section of a
// referral, and an answer to a direct query for the _dns name.
func signalOnEachPath(t *testing.T, texts []string) map[string]*cache.AuthServer {
	t.Helper()
	rrs := func() []dns.RR {
		out := make([]dns.RR, len(texts))
		for i, text := range texts {
			out[i] = mustRR(t, text)
		}
		return out
	}
	ctx := context.Background()
	out := map[string]*cache.AuthServer{}

	imr := newTestImr(t)
	imr.Quiet = true
	server := cache.NewAuthServer(pathNS)
	r := new(dns.Msg)
	r.SetQuestion("www.kid.p.test.", dns.TypeA)
	r.Extra = rrs()
	imr.parseTransportForServerFromAdditional(ctx, server, r)
	out["additional"] = server

	imr = newTestImr(t)
	imr.Quiet = true
	ref := new(dns.Msg)
	ref.SetQuestion("www.kid.p.test.", dns.TypeA)
	ref.Response = true
	ref.Ns = []dns.RR{mustRR(t, "kid.p.test. 3600 IN NS "+pathNS)}
	ref.Extra = rrs()
	nsrrset := &core.RRset{Name: "kid.p.test.", Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: ref.Ns}
	if _, err := imr.ParseAdditionalForNSAddrs(ctx, "authority", nsrrset, "kid.p.test.", "p.test.",
		map[string]bool{pathNS: true}, ref); err != nil {
		t.Fatalf("ParseAdditionalForNSAddrs: %v", err)
	}
	out["referral"] = imr.Cache.GetOrCreateAuthServer(pathNS)

	imr = newTestImr(t)
	imr.Quiet = true
	server = cache.NewAuthServer(pathNS)
	imr.Cache.ServerMap.Set("kid.p.test.", map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})
	imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB, RRs: rrs()},
		cache.ValidationStateIndeterminate)
	out["answer"] = server
	return out
}

// signalSnapshot renders what a server took from its signal: the source, the
// weights as received and the dial ports, by oots token (do53 read as udp and
// tcp). "none" when it has no signal.
func signalSnapshot(server *cache.AuthServer) string {
	rec := server.GetReceivedSignal()
	if rec == nil {
		return "none"
	}
	var w, p []string
	for tr, v := range rec.Weights {
		w = append(w, fmt.Sprintf("%s:%d", core.TransportToSignalToken[tr], v))
	}
	for tr, v := range server.GetTransportPorts() {
		p = append(p, fmt.Sprintf("%s:%d", core.TransportToSignalToken[tr], v))
	}
	sort.Strings(w)
	sort.Strings(p)
	return fmt.Sprintf("%s w=%s p=%s", rec.Source, strings.Join(w, ","), strings.Join(p, ","))
}

// checkEveryPathBothOrders runs the RRs in the order given and reversed, on
// each path, and wants the same snapshot every time.
func checkEveryPathBothOrders(t *testing.T, texts []string, want string) {
	t.Helper()
	reversed := slices.Clone(texts)
	slices.Reverse(reversed)
	for _, order := range [][]string{texts, reversed} {
		for path, server := range signalOnEachPath(t, order) {
			if got := signalSnapshot(server); got != want {
				t.Errorf("%s path, order %q:\n got  %s\n want %s", path, order, got, want)
			}
		}
	}
}

// A transport named in two records takes the tie-break winner's weight and
// port: the lower SvcPriority, then the lower RDATA. The loser still supplies
// the other transports it names. The outcome does not depend on RR order.
func TestOOTSTieBreakIsOrderFree(t *testing.T) {
	for _, tc := range []struct {
		name  string
		texts []string
		want  string
	}{
		{
			name: "a record that loses DoT keeps its DoH",
			texts: []string{
				pathOwner + ` 3600 IN SVCB 1 . port=1111 oots="dot:30"`,
				pathOwner + ` 3600 IN SVCB 1 . port=2222 oots="dot:40,doh:10"`,
			},
			want: "oots w=doh:10,dot:30 p=doh:2222,dot:1111",
		},
		{
			name: "the lower SvcPriority wins",
			texts: []string{
				pathOwner + ` 3600 IN SVCB 2 . port=1111 oots="dot:30,doq:20"`,
				pathOwner + ` 3600 IN SVCB 1 . port=2222 oots="dot:40"`,
			},
			want: "oots w=doq:20,dot:40 p=doq:1111,dot:2222",
		},
		{
			name: "one transport per record, as tdns-auth lays them out",
			texts: []string{
				pathOwner + ` 3600 IN SVCB 1 . oots="do53:100,doq:20"`,
				pathOwner + ` 3600 IN SVCB 1 . port=1234 oots="dot:10"`,
				pathOwner + ` 3600 IN SVCB 1 . port=8443 oots="doh:5"`,
			},
			want: "oots w=doh:5,doq:20,dot:10,tcp:100,udp:100 p=doh:8443,dot:1234",
		},
		{
			name: "ALPN-only records combine the same way, ports included",
			texts: []string{
				pathOwner + ` 3600 IN SVCB 1 . alpn=dot port=1234`,
				pathOwner + ` 3600 IN SVCB 1 . alpn=doq`,
			},
			want: "alpn w=doq:100,dot:100 p=dot:1234",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkEveryPathBothOrders(t, tc.texts, tc.want)
		})
	}
}

// A ServiceMode record whose TargetName is not "." names another endpoint.
// The resolver ignores it, oots, ALPN and port alike, and keeps what the
// other records say.
func TestOOTSTargetRecordIsIgnored(t *testing.T) {
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 dot-ns.kid.p.test. port=1234 oots="dot:30"`,
	}, "none")
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 dot-ns.kid.p.test. alpn=dot port=1234`,
	}, "none")
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 dot-ns.kid.p.test. port=1234 oots="dot:30"`,
		pathOwner + ` 3600 IN SVCB 1 . oots="doq:20"`,
	}, "oots w=doq:20 p=")
}

// The resolver ignores an RRset that holds an AliasMode record as a whole. It
// reads neither the AliasMode record's own SvcParams (RFC 9460 section 2.4.2)
// nor its ServiceMode siblings (section 2.4.1).
func TestOOTSAliasSetIsIgnored(t *testing.T) {
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 0 _dns.other.example.`,
		pathOwner + ` 3600 IN SVCB 1 . port=1235 oots="doq:50"`,
	}, "none")
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 0 _dns.other.example.`,
	}, "none")
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 0 _dns.other.example. port=1236 oots="dot:40"`,
	}, "none")
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 0 _dns.other.example. alpn=dot port=1236`,
	}, "none")
}

// An ignored set leaves the server's earlier signal alone.
func TestOOTSAliasSetKeepsEarlierSignal(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	server := cache.NewAuthServer(pathNS)
	r := new(dns.Msg)
	r.SetQuestion("www.kid.p.test.", dns.TypeA)
	r.Extra = []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 . port=1234 oots="dot:30"`)}
	imr.parseTransportForServerFromAdditional(context.Background(), server, r)
	r.Extra = []dns.RR{
		mustRR(t, pathOwner+` 3600 IN SVCB 0 _dns.other.example.`),
		mustRR(t, pathOwner+` 3600 IN SVCB 1 . oots="doq:50"`),
	}
	imr.parseTransportForServerFromAdditional(context.Background(), server, r)
	if got, want := signalSnapshot(server), "oots w=dot:30 p=dot:1234"; got != want {
		t.Errorf("after an AliasMode set: %s, want %s", got, want)
	}
}

// The tie-break order on records that differ only in TargetName or only in
// SvcPriority. S1a ignores every record with a target, so this pins the rule
// for the endpoint work: on equal priority "." comes first.
func TestCompareOOTSRecordsCanonicalOrder(t *testing.T) {
	rec := func(text string) ootsRecord {
		svcb := mustRR(t, text).(*dns.SVCB)
		m, _, _ := GetTransportParamRaw(svcb)
		return newOOTSRecord(svcb, m, nil)
	}
	self := rec(pathOwner + ` 3600 IN SVCB 1 . oots="dot:30"`)
	other := rec(pathOwner + ` 3600 IN SVCB 1 a.example. oots="dot:30"`)
	later := rec(pathOwner + ` 3600 IN SVCB 2 . oots="dot:30"`)
	if compareOOTSRecords(self, other) >= 0 || compareOOTSRecords(other, self) <= 0 {
		t.Error(`on equal priority "." does not come first`)
	}
	if compareOOTSRecords(other, later) >= 0 {
		t.Error("SvcPriority 1 with a target does not come before SvcPriority 2")
	}
	if compareOOTSRecords(self, self) != 0 {
		t.Error("a record does not tie with itself")
	}
	if len(self.rdata) == 0 || self.rdata[0] != 0 || self.rdata[1] != 1 || self.rdata[2] != 0 {
		t.Errorf("RDATA % x, want priority 0x0001 then the root name", self.rdata)
	}
	broken := ootsRecord{priority: 1}
	if compareOOTSRecords(broken, self) <= 0 {
		t.Error("a record without RDATA does not come last")
	}
}
