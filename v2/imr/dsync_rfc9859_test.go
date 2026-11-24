/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"context"
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

func TestDsyncNamesAtTheRoot(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{DsyncOwnerName("."), "_dsync."},
		{DsyncOwnerName("example."), "_dsync.example."},
		{DsyncOwnerName("example"), "_dsync.example."},
		{dsyncPerChildLookupName("se", "."), "se._dsync."},
		{dsyncPerChildLookupName("child", "example."), "child._dsync.example."},
		{dsyncPerChildLookupName("a.b", "example."), "a.b._dsync.example."},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
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
