/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #757: a DSYNC with port 0 (or the null scheme, or the root as its target)
// names nowhere to send anything, and is never selected; and the root's DSYNC
// names are the RFC 9859 ones, _dsync. and <tld>._dsync.

func parsedDsync(t *testing.T, rdata string) *core.DSYNC {
	t.Helper()
	rr := mustRR(t, "_dsync.example. 3600 IN DSYNC "+rdata)
	return rr.(*dns.PrivateRR).Data.(*core.DSYNC)
}

func TestFindDsyncSkipsUnusableRecords(t *testing.T) {
	port0 := parsedDsync(t, "ANY UPDATE 0 upd0.example.")
	rootTarget := parsedDsync(t, "ANY UPDATE 53 .")
	usable := parsedDsync(t, "ANY UPDATE 53 upd.example.")
	notify0 := parsedDsync(t, "CDS NOTIFY 0 n0.example.")
	notify := parsedDsync(t, "CDS NOTIFY 53 n.example.")

	res := DsyncResult{Rdata: []*core.DSYNC{port0, rootTarget, usable}}
	if got := findDsync(res, core.SchemeUpdate, false); got != usable {
		t.Errorf("UPDATE: found %v, want %v", got, usable)
	}
	res = DsyncResult{Rdata: []*core.DSYNC{port0, rootTarget}}
	if got := findDsync(res, core.SchemeUpdate, false); got != nil {
		t.Errorf("UPDATE with no usable record: found %v, want none", got)
	}
	res = DsyncResult{Rdata: []*core.DSYNC{notify0, notify}}
	if got := findDsync(res, core.SchemeNotify, true); got != notify {
		t.Errorf("NOTIFY: found %v, want %v", got, notify)
	}
	res = DsyncResult{Rdata: []*core.DSYNC{notify0}}
	if got := findDsync(res, core.SchemeNotify, true); got != nil {
		t.Errorf("NOTIFY with port 0 only: found %v, want none", got)
	}
}

func TestRolloverSelectionSkipsUnusableRecords(t *testing.T) {
	res := DsyncResult{Validated: true, Rdata: []*core.DSYNC{
		parsedDsync(t, "ANY UPDATE 0 upd0.example."),
		parsedDsync(t, "CDS NOTIFY 0 n0.example."),
		parsedDsync(t, "CDS API 0 api0.example."),
		parsedDsync(t, "ANY UPDATE 53 upd.example."),
		parsedDsync(t, "CDS NOTIFY 53 n.example."),
		parsedDsync(t, "CDS API 8443 api.example."),
	}}
	u, n, a := selectRolloverDsyncRRs(res, "child.example.")
	if u == nil || u.Target != "upd.example." {
		t.Errorf("UPDATE: selected %v, want the one at upd.example.", u)
	}
	if n == nil || n.Target != "n.example." {
		t.Errorf("NOTIFY: selected %v, want the one at n.example.", n)
	}
	if a == nil || a.Target != "api.example." {
		t.Errorf("API: selected %v, want the one at api.example.", a)
	}

	res.Rdata = res.Rdata[:3]
	if u, n, a := selectRolloverDsyncRRs(res, "child.example."); u != nil || n != nil || a != nil {
		t.Errorf("port 0 only: selected %v, %v, %v; want none", u, n, a)
	}
}

// A parent whose own NOTIFY DSYNC has port 0 does not advertise NOTIFY.
func TestAdvertisesDsyncNotifyNeedsAUsableRecord(t *testing.T) {
	const zone = `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.1
_dsync.example. 7200 IN DSYNC CDS NOTIFY 0 notify.example.
_dsync.example. 7200 IN DSYNC CSYNC NOTIFY 5302 notify.example.
`
	zd := testZone(t, "example.", zone)
	if zd.advertisesDsyncNotify(dns.TypeCDS) {
		t.Error("NOTIFY(CDS) is advertised only with port 0, yet counted as advertised")
	}
	if !zd.advertisesDsyncNotify(dns.TypeCSYNC) {
		t.Error("NOTIFY(CSYNC) is advertised with a port, yet not counted")
	}
}

func TestDsyncNamesAtTheRoot(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{dsyncOwnerName("."), "_dsync."},
		{dsyncOwnerName("example."), "_dsync.example."},
		{dsyncOwnerName("example"), "_dsync.example."},
		{dsyncPerChildLookupName("se", "."), "se._dsync."},
		{dsyncPerChildLookupName("child", "example."), "child._dsync.example."},
		{dsyncPerChildLookupName("a.b", "example."), "a.b._dsync.example."},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

// A root zone publishes its DSYNC RRset at _dsync. and nothing at
// _dsync.root. A record an older build left at _dsync.root. is not the
// root's DSYNC: the scheme it names is published at _dsync. all the same.
func TestTheRootPublishesAtDsync(t *testing.T) {
	allSchemesChildSync(t)
	const root = `. 3600 IN SOA a.root. hostmaster.root. 1 7200 1800 604800 7200
. 3600 IN NS a.root.
a.root. 3600 IN A 192.0.2.1
_dsync.root. 7200 IN DSYNC ANY UPDATE 5302 updates.root.
`
	zd := testZone(t, ".", root)
	zd.KeyDB = &KeyDB{UpdateQ: make(chan UpdateRequest, 1)}
	p := DefaultDelegationPolicy()
	zd.DelegationPolicy = &p

	pub, err := zd.BuildDsyncPublication()
	if err != nil {
		t.Fatalf("BuildDsyncPublication: %v", err)
	}
	schemes := map[core.DsyncScheme]bool{}
	for _, rr := range pub.Actions() {
		if rr.Header().Rrtype != core.TypeDSYNC {
			continue
		}
		if rr.Header().Name != "_dsync." {
			t.Errorf("a DSYNC action at %q: %s", rr.Header().Name, rr)
			continue
		}
		schemes[rr.(*dns.PrivateRR).Data.(*core.DSYNC).Scheme] = true
	}
	for _, s := range []core.DsyncScheme{core.SchemeNotify, core.SchemeUpdate, core.SchemeAPI} {
		if !schemes[s] {
			t.Errorf("scheme %d is not published at _dsync.", s)
		}
	}
	for _, rr := range pub.Actions() {
		if strings.HasSuffix(strings.ToLower(rr.Header().Name), "_dsync.root.") {
			t.Errorf("an action at the old name: %s", rr)
		}
	}
}

// A root zone that still serves a DSYNC RRset at _dsync.root. is warned about
// on every build of its publication; the RRset is left alone. A root zone
// without one is not.
func TestTheRootWarnsAboutALeftoverDsyncRoot(t *testing.T) {
	allSchemesChildSync(t)
	var buf bytes.Buffer
	prev := lg
	lg = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lg = prev })

	const apex = `. 3600 IN SOA a.root. hostmaster.root. 1 7200 1800 604800 7200
. 3600 IN NS a.root.
a.root. 3600 IN A 192.0.2.1
`
	warnings := func(zone string) (int, *DsyncPublication) {
		t.Helper()
		buf.Reset()
		zd := testZone(t, ".", zone)
		p := DefaultDelegationPolicy()
		zd.DelegationPolicy = &p
		pub, err := zd.BuildDsyncPublication()
		if err != nil {
			t.Fatalf("BuildDsyncPublication: %v", err)
		}
		n := 0
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, "_dsync.root.") {
				n++
			}
		}
		return n, pub
	}

	n, pub := warnings(apex + "_dsync.root. 7200 IN DSYNC ANY UPDATE 5302 updates.root.\n")
	if n != 1 {
		t.Errorf("a leftover _dsync.root. RRset: %d warnings, want 1\n%s", n, buf.String())
	}
	for _, rr := range pub.Actions() {
		if strings.EqualFold(rr.Header().Name, "_dsync.root.") {
			t.Errorf("the publication touches the old RRset: %s", rr)
		}
	}
	if n, _ := warnings(apex); n != 0 {
		t.Errorf("no RRset at _dsync.root.: %d warnings, want none\n%s", n, buf.String())
	}
	if n, _ := warnings(apex + "_dsync.root. 7200 IN TXT \"not a DSYNC\"\n"); n != 0 {
		t.Errorf("only a TXT at _dsync.root.: %d warnings, want none\n%s", n, buf.String())
	}
}

// dsyncRoot is a root server for DSYNC discovery: it answers from its data,
// says NXDOMAIN with the root's SOA for any name it has no data at, and keeps
// every question it was asked.
type dsyncRoot struct {
	mu    sync.Mutex
	asked []string // "name TYPE"
}

func (d *dsyncRoot) questions() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.asked)
}

// dsyncRootImr is a resolver whose root is a dsyncRoot serving rrs.
func dsyncRootImr(t *testing.T, rrs ...string) (*Imr, *dsyncRoot) {
	t.Helper()
	key := func(name string, rrtype uint16) string {
		return core.CanonicalizeName(name) + " " + dns.TypeToString[rrtype]
	}
	data := map[string][]dns.RR{}
	names := map[string]bool{}
	for _, s := range rrs {
		rr := mustRR(t, s)
		data[key(rr.Header().Name, rr.Header().Rrtype)] = append(data[key(rr.Header().Name, rr.Header().Rrtype)], rr)
		names[core.CanonicalizeName(rr.Header().Name)] = true
	}
	soa := mustRR(t, ". 60 IN SOA a.root. hostmaster.root. 1 3600 600 86400 60")

	d := &dsyncRoot{}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		d.mu.Lock()
		d.asked = append(d.asked, key(q.Name, q.Qtype))
		d.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if ans := data[key(q.Name, q.Qtype)]; len(ans) > 0 {
			m.Answer = ans
		} else {
			if !names[core.CanonicalizeName(q.Name)] {
				m.Rcode = dns.RcodeNameError
			}
			m.Ns = []dns.RR{soa}
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("the root did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })

	port := strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
	imr := verdictImr(t, false)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	if err := imr.Cache.AddStub(".", []cache.AuthServer{
		{Name: "a.root.", Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	return imr, d
}

func dsyncQuestions(asked []string) []string {
	var out []string
	for _, q := range asked {
		if strings.HasSuffix(q, " DSYNC") {
			out = append(out, strings.TrimSuffix(q, " DSYNC"))
		}
	}
	return out
}

// Discovery for a TLD asks <tld>._dsync. and then _dsync., and never a name
// under _dsync.root.
func TestDsyncDiscoveryForATldUsesTheRfcNames(t *testing.T) {
	imr, root := dsyncRootImr(t, "_dsync. 3600 IN DSYNC CDS NOTIFY 5302 notify.")
	res, err := imr.DsyncDiscovery(context.Background(), "se.", false)
	if err != nil {
		t.Fatalf("DsyncDiscovery: %v", err)
	}
	if res.Qname != "_dsync." || res.Parent != "." || len(res.Rdata) != 1 {
		t.Errorf("found %d records at %q, parent %q; want 1 at _dsync., parent .", len(res.Rdata), res.Qname, res.Parent)
	}
	if got, want := dsyncQuestions(root.questions()), []string{"se._dsync.", "_dsync."}; !slices.Equal(got, want) {
		t.Errorf("DSYNC questions %v, want %v", got, want)
	}
	for _, q := range root.questions() {
		if strings.Contains(q, "_dsync.root.") {
			t.Errorf("asked %q", q)
		}
	}
}

// A per-child record at <tld>._dsync. is found there, first.
func TestDsyncDiscoveryForATldFindsItsOwnRecord(t *testing.T) {
	imr, root := dsyncRootImr(t,
		"se._dsync. 3600 IN DSYNC ANY UPDATE 5302 updates.",
		"_dsync. 3600 IN DSYNC CDS NOTIFY 5302 notify.")
	res, err := imr.DsyncDiscovery(context.Background(), "se.", false)
	if err != nil {
		t.Fatalf("DsyncDiscovery: %v", err)
	}
	if res.Qname != "se._dsync." || len(res.Rdata) != 1 || res.Rdata[0].Scheme != core.SchemeUpdate {
		t.Errorf("found %v at %q; want the UPDATE record at se._dsync.", res.Rdata, res.Qname)
	}
	if got, want := dsyncQuestions(root.questions()), []string{"se._dsync."}; !slices.Equal(got, want) {
		t.Errorf("DSYNC questions %v, want %v", got, want)
	}
}

// LookupDSYNCTarget passes over a port-0 record for the scheme and type it
// wants and takes the usable one after it.
func TestLookupDsyncTargetSkipsPortZero(t *testing.T) {
	imr, _ := dsyncRootImr(t,
		"_dsync. 3600 IN DSYNC CDS NOTIFY 0 dead.",
		"_dsync. 3600 IN DSYNC CDS NOTIFY 5302 notify.",
		"notify. 3600 IN A 192.0.2.53")
	tgt, err := imr.LookupDSYNCTarget(context.Background(), "se.", dns.TypeCDS, core.SchemeNotify)
	if err != nil {
		t.Fatalf("LookupDSYNCTarget: %v", err)
	}
	if tgt.Name != "notify." || tgt.Port != 5302 || !slices.Equal(tgt.Addresses, []string{"192.0.2.53:5302"}) {
		t.Errorf("target %q port %d at %v; want notify. port 5302 at 192.0.2.53:5302", tgt.Name, tgt.Port, tgt.Addresses)
	}

	imr, _ = dsyncRootImr(t, "_dsync. 3600 IN DSYNC CDS NOTIFY 0 dead.", "dead. 3600 IN A 192.0.2.99")
	if tgt, err := imr.LookupDSYNCTarget(context.Background(), "se.", dns.TypeCDS, core.SchemeNotify); err == nil {
		t.Errorf("a port-0 record alone was selected: %q port %d", tgt.Name, tgt.Port)
	}
}
