/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func TestQminLabelPlan(t *testing.T) {
	got := qminBatches(18, 10, 4)
	want := []int{1, 1, 1, 1, 2, 2, 2, 2, 3, 3}
	if strings.Trim(strings.Join(ints(got), ","), "") != strings.Join(ints(want), ",") {
		t.Fatalf("18 labels: %v, want %v", got, want)
	}
	if got := qminBatches(4, 10, 4); len(got) != 4 || got[0] != 1 || got[3] != 1 {
		t.Fatalf("4 labels: %v, want one per round", got)
	}
	if got := qminBatches(3, 10, 4); len(got) != 3 {
		t.Fatalf("3 labels: %v, want one per round", got)
	}

	one, n := qminTake("mail.example.org.", "_25._tcp.mail.example.org.", 1)
	if n != 1 || one != "_25._tcp.mail.example.org." {
		t.Fatalf("underscore run: %s (%d labels), want one query for the whole run", one, n)
	}
	first, _ := qminTake("example.com.", "sel._domainkey.example.com.", 1)
	second, _ := qminTake("example.com.", "sel._domainkey.example.com.", 2)
	if first != "_domainkey.example.com." || second != "sel._domainkey.example.com." {
		t.Fatalf("sel._domainkey: %s then %s", first, second)
	}

	// Six rounds already spent, ten labels still hidden, four rounds left: two labels.
	if got := qminStep(10, 6, 10, 4); got != 2 {
		t.Fatalf("after a referral, next batch is %d, want 2", got)
	}
}

func TestQminTuning(t *testing.T) {
	var fresh ImrTuningConf
	LoadImrTuningDefaults(&fresh)
	if err := validateQminTuning(&fresh); err != nil {
		t.Fatalf("absent keys: %v", err)
	}
	if *fresh.QminMaxIterations != 10 || *fresh.QminOneLabel != 4 {
		t.Fatalf("defaults %d and %d, want 10 and 4", *fresh.QminMaxIterations, *fresh.QminOneLabel)
	}

	zero := 0
	kept := ImrTuningConf{QminMaxIterations: &zero, QminOneLabel: &zero}
	LoadImrTuningDefaults(&kept)
	if *kept.QminMaxIterations != 0 || *kept.QminOneLabel != 0 {
		t.Fatal("an explicit 0 was replaced with the default")
	}
	if err := validateQminTuning(&kept); err == nil || !strings.Contains(err.Error(), "qmin-max-iterations") {
		t.Fatalf("max 0: %v", err)
	}

	neg := -1
	negConf := ImrTuningConf{QminMaxIterations: &neg, QminOneLabel: &zero}
	LoadImrTuningDefaults(&negConf)
	if err := validateQminTuning(&negConf); err == nil {
		t.Fatal("a negative maximum was accepted")
	}

	ten, also := 10, 10
	eq := ImrTuningConf{QminMaxIterations: &ten, QminOneLabel: &also}
	LoadImrTuningDefaults(&eq)
	if err := validateQminTuning(&eq); err == nil || !strings.Contains(err.Error(), "qmin-one-label") {
		t.Fatalf("one-label equal to the maximum: %v", err)
	}
}

func ints(v []int) []string {
	out := make([]string, len(v))
	for i, n := range v {
		out[i] = strconv.Itoa(n)
	}
	return out
}

// qminRig is a resolver with minimisation on and one authoritative double
// per address, all on the same port. Each double records the questions it
// was asked.
type qminRig struct {
	imr  *Imr
	port int
	log  map[string]*asked
}

type asked struct {
	mu sync.Mutex
	qs []string
}

func (a *asked) note(r *dns.Msg) {
	if a == nil || len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	a.mu.Lock()
	a.qs = append(a.qs, dns.CanonicalName(q.Name)+" "+dns.TypeToString[q.Qtype])
	a.mu.Unlock()
}

func (a *asked) list() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.qs...)
}

func enableQmin(imr *Imr) {
	if imr.Options == nil {
		imr.Options = map[ImrOption]string{}
	}
	imr.Options[ImrOptQnameMinimisation] = "true"
}

func qminClients(imr *Imr, port int) {
	p := strconv.Itoa(port)
	timeout := 500 * time.Millisecond
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil, core.WithTimeout(timeout))
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil, core.WithTimeout(timeout))
}

func (g *qminRig) listen(t *testing.T, ip net.IP, h dns.HandlerFunc) *asked {
	t.Helper()
	rec := &asked{}
	port := startRefDouble(t, ip, g.port, func(w dns.ResponseWriter, r *dns.Msg) {
		rec.note(r)
		h(w, r)
	})
	if g.port == 0 {
		g.port = port
	}
	if g.log == nil {
		g.log = map[string]*asked{}
	}
	g.log[ip.String()] = rec
	return rec
}

func (g *qminRig) stub(t *testing.T, zone string, servers []cache.AuthServer) {
	t.Helper()
	if err := g.imr.Cache.AddStub(zone, servers); err != nil {
		t.Fatalf("AddStub %s: %v", zone, err)
	}
}

func (g *qminRig) servers(t *testing.T, qname string, qtype uint16) map[string]*cache.AuthServer {
	t.Helper()
	_, servers, err := g.imr.Cache.FindClosestKnownZoneFor(qname, qtype)
	if err != nil || len(servers) == 0 {
		t.Fatalf("no servers for %s %s: %v", qname, dns.TypeToString[qtype], err)
	}
	return servers
}

func (g *qminRig) query(t *testing.T, qname string, qtype uint16) (*core.RRset, int, cache.CacheContext, error) {
	t.Helper()
	rrset, rcode, cctx, _, err := g.imr.IterativeDNSQuery(context.Background(), qname, qtype, g.servers(t, qname, qtype), false, edns0.PrivacyNone)
	return rrset, rcode, cctx, err
}

func newQminRig(t *testing.T) *qminRig {
	t.Helper()
	imr := verdictImr(t, false)
	enableQmin(imr)
	g := &qminRig{imr: imr}
	return g
}

func (g *qminRig) ready(t *testing.T) {
	t.Helper()
	qminClients(g.imr, g.port)
}

func qminSOA(t *testing.T, zone string) dns.RR {
	t.Helper()
	if zone == "." {
		return mustRR(t, ". 300 IN SOA ns. hostmaster. 1 7200 1800 604800 300")
	}
	return mustRR(t, zone+" 300 IN SOA ns."+zone+" hostmaster."+zone+" 1 7200 1800 604800 300")
}

func nodata(t *testing.T, r *dns.Msg, zone string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Ns = []dns.RR{qminSOA(t, zone)}
	return m
}

func nxdomain(t *testing.T, r *dns.Msg, zone string) *dns.Msg {
	t.Helper()
	m := nodata(t, r, zone)
	m.Rcode = dns.RcodeNameError
	return m
}

func qminReferral(t *testing.T, r *dns.Msg, zone, ns, glue string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Ns = []dns.RR{mustRR(t, zone+" 300 IN NS "+ns)}
	m.Extra = []dns.RR{mustRR(t, ns+" 300 IN A "+glue)}
	return m
}

func answerA(t *testing.T, r *dns.Msg, name, addr string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = []dns.RR{mustRR(t, name+" 300 IN A "+addr)}
	return m
}

func wantQuestions(t *testing.T, where string, got, want []string) {
	t.Helper()
	if strings.Join(got, " | ") != strings.Join(want, " | ") {
		t.Errorf("%s saw %v, want %v", where, got, want)
	}
}

func TestQminColdMX(t *testing.T) {
	const (
		qname = "www.foo.example.com."
		root  = "127.0.0.1"
		com   = "127.0.0.2"
		ex    = "127.0.0.3"
	)
	g := newQminRig(t)
	rootLog := g.listen(t, net.ParseIP(root), func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(qminReferral(t, r, "com.", "ns.com.", com))
	})
	comLog := g.listen(t, net.ParseIP(com), func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(qminReferral(t, r, "example.com.", "ns.example.com.", ex))
	})
	exLog := g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := nodata(t, r, "example.com.")
		if q.Qtype == dns.TypeMX && dns.CanonicalName(q.Name) == qname {
			m = new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, qname+" 300 IN MX 10 mail.example.com.")}
		}
		_ = w.WriteMsg(m)
	})
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{root}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeMX)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || len(rrset.RRs) != 1 || rrset.RRs[0].Header().Rrtype != dns.TypeMX {
		t.Fatalf("client answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	wantQuestions(t, "root", rootLog.list(), []string{"com. A"})
	wantQuestions(t, ".com", comLog.list(), []string{"example.com. A"})
	wantQuestions(t, "example.com", exLog.list(), []string{
		"foo.example.com. A", qname + " A", qname + " MX",
	})
}

func TestQminWarmComNeverSeesMX(t *testing.T) {
	const (
		qname = "example.com."
		com   = "127.0.0.2"
		ex    = "127.0.0.3"
	)
	g := newQminRig(t)
	comLog := g.listen(t, net.ParseIP(com), func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(qminReferral(t, r, "example.com.", "ns.example.com.", ex))
	})
	exLog := g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{mustRR(t, qname+" 300 IN MX 10 mail.example.com.")}
		_ = w.WriteMsg(m)
	})
	g.ready(t)
	g.stub(t, "com.", []cache.AuthServer{{Name: "ns.com.", Addrs: []string{com}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeMX)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || rrset.RRs[0].Header().Rrtype != dns.TypeMX {
		t.Fatalf("client answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	wantQuestions(t, ".com", comLog.list(), []string{"example.com. A"})
	wantQuestions(t, "example.com", exLog.list(), []string{qname + " MX"})
}

func TestQminTypeASkipsTheExtraQuery(t *testing.T) {
	const (
		qname = "www.foo.example.com."
		ex    = "127.0.0.3"
	)
	g := newQminRig(t)
	exLog := g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if dns.CanonicalName(q.Name) == qname {
			_ = w.WriteMsg(answerA(t, r, qname, "192.0.2.80"))
			return
		}
		_ = w.WriteMsg(nodata(t, r, "example.com."))
	})
	g.ready(t)
	g.stub(t, "example.com.", []cache.AuthServer{{Name: "ns.example.com.", Addrs: []string{ex}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeA)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || rrset.RRs[0].(*dns.A).A.String() != "192.0.2.80" {
		t.Fatalf("client answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	wantQuestions(t, "example.com", exLog.list(), []string{"foo.example.com. A", qname + " A"})
}

func TestQminBatchedReferralDoesNotLeakToTheChild(t *testing.T) {
	const (
		qname = "www.foo.example.com."
		root  = "127.0.0.1"
		com   = "127.0.0.2"
		ex    = "127.0.0.3"
	)
	g := newQminRig(t)
	maxIter, one := 2, 0
	g.imr.Tuning.QminMaxIterations = &maxIter
	g.imr.Tuning.QminOneLabel = &one
	g.listen(t, net.ParseIP(root), func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(qminReferral(t, r, "com.", "ns.com.", com))
	})
	comLog := g.listen(t, net.ParseIP(com), func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(qminReferral(t, r, "example.com.", "ns.example.com.", ex))
	})
	exLog := g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{mustRR(t, qname+" 300 IN MX 10 mail.example.com.")}
		_ = w.WriteMsg(m)
	})
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{root}, Alpn: []string{"do53"}}})

	if _, _, _, err := g.query(t, qname, dns.TypeMX); err != nil {
		t.Fatal(err)
	}
	for _, q := range exLog.list() {
		if strings.HasPrefix(q, "www.foo.") && strings.HasSuffix(q, " A") {
			t.Errorf("example.com saw the batched probe %s", q)
		}
	}
	if len(comLog.list()) == 0 || !strings.Contains(comLog.list()[0], "www.foo.example.com. A") {
		t.Fatalf(".com saw %v, want the batched full name as A", comLog.list())
	}
}

func TestQminNODATAAtAnEmptyNonTerminal(t *testing.T) {
	const (
		ent   = "foo.example.com."
		qname = "www.foo.example.com."
		ex    = "127.0.0.3"
	)
	g := newQminRig(t)
	var log *asked
	log = g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if dns.CanonicalName(q.Name) == qname {
			_ = w.WriteMsg(answerA(t, r, qname, "192.0.2.80"))
			return
		}
		_ = w.WriteMsg(nodata(t, r, "example.com."))
	})
	g.ready(t)
	g.stub(t, "example.com.", []cache.AuthServer{{Name: "ns.example.com.", Addrs: []string{ex}, Alpn: []string{"do53"}}})

	rrset, _, _, err := g.query(t, qname, dns.TypeA)
	if err != nil || rrset == nil || rrset.RRs[0].(*dns.A).A.String() != "192.0.2.80" {
		t.Fatalf("first answer: %v %v", rrset, err)
	}
	if c := g.imr.Cache.Get(ent, dns.TypeA); c == nil || c.Context != cache.ContextNoErrNoAns {
		t.Fatalf("probe NODATA cached as %v", c)
	}
	before := len(log.list())
	if _, _, _, err := g.query(t, qname, dns.TypeA); err != nil {
		t.Fatal(err)
	}
	again := log.list()[before:]
	for _, q := range again {
		if q == ent+" A" {
			t.Errorf("second lookup probed %s again", ent)
		}
	}

	glueName := "bar.example.com."
	g.imr.Cache.Set(glueName, dns.TypeA, &cache.CachedRRset{
		Name: glueName, RRtype: dns.TypeA, Rcode: dns.RcodeSuccess,
		Context: cache.ContextGlue, State: cache.ValidationStateInsecure,
		RRset:      &core.RRset{Name: glueName, RRtype: dns.TypeA, RRs: []dns.RR{mustRR(t, glueName+" 300 IN A 192.0.2.9")}},
		Expiration: time.Now().Add(time.Hour), Transport: core.TransportDo53,
	})
	before = len(log.list())
	if _, _, _, err := g.query(t, "www.bar.example.com.", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	sawGlueProbe := false
	for _, q := range log.list()[before:] {
		if q == glueName+" A" {
			sawGlueProbe = true
		}
	}
	if !sawGlueProbe {
		t.Fatalf("a cached glue A suppressed the probe; questions %v", log.list()[before:])
	}
}

func TestQminIntermediateCNAMEIsNotChased(t *testing.T) {
	const (
		mid   = "foo.example.com."
		qname = "www.foo.example.com."
		ex    = "127.0.0.3"
	)
	g := newQminRig(t)
	log := g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := dns.CanonicalName(q.Name)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		switch name {
		case mid:
			m.Answer = []dns.RR{mustRR(t, mid+" 300 IN CNAME elsewhere.example.net.")}
		case qname:
			m.Answer = []dns.RR{mustRR(t, qname+" 300 IN A 192.0.2.80")}
		default:
			m = nodata(t, r, "example.com.")
		}
		_ = w.WriteMsg(m)
	})
	g.ready(t)
	g.stub(t, "example.com.", []cache.AuthServer{{Name: "ns.example.com.", Addrs: []string{ex}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeA)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || rrset.RRs[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("client answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	if c := g.imr.Cache.Get(mid, dns.TypeCNAME); c == nil || c.Context != cache.ContextAnswer {
		t.Fatalf("intermediate CNAME not cached: %v", c)
	}
	for _, q := range log.list() {
		if strings.Contains(q, "elsewhere.example.net.") {
			t.Errorf("the intermediate CNAME was chased: %s", q)
		}
	}
}

func TestQminDNAMEUsesTheOriginalName(t *testing.T) {
	const (
		qname = "www.example.com."
		want  = "www.example.net."
		ex    = "127.0.0.3"
		netIP = "127.0.0.4"
	)
	g := newQminRig(t)
	g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{mustRR(t, "example.com. 300 IN DNAME example.net.")}
		_ = w.WriteMsg(m)
	})
	netLog := g.listen(t, net.ParseIP(netIP), func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{mustRR(t, want+" 300 IN MX 10 mail.example.net.")}
		_ = w.WriteMsg(m)
	})
	g.ready(t)
	g.stub(t, "example.com.", []cache.AuthServer{{Name: "ns.example.com.", Addrs: []string{ex}, Alpn: []string{"do53"}}})
	g.stub(t, "example.net.", []cache.AuthServer{{Name: "ns.example.net.", Addrs: []string{netIP}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeMX)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || rrset.RRs[0].Header().Rrtype != dns.TypeMX {
		t.Fatalf("client answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	if !core.EqualNames(rrset.RRs[0].Header().Name, want) {
		t.Fatalf("MX owner %s, want %s", rrset.RRs[0].Header().Name, want)
	}
	sawMX := false
	for _, q := range netLog.list() {
		if q == want+" MX" {
			sawMX = true
		}
		if strings.Contains(q, "example.com.") {
			t.Errorf("example.net was asked about the original zone: %s", q)
		}
	}
	if !sawMX {
		t.Fatalf("example.net saw %v, want %s MX", netLog.list(), want)
	}
}

func TestQminWildcardProbeIsNotTheClientAnswer(t *testing.T) {
	const (
		qname = "www.foo.example.com."
		ex    = "127.0.0.3"
	)
	g := newQminRig(t)
	g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if q.Qtype == dns.TypeMX && dns.CanonicalName(q.Name) == qname {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, qname+" 300 IN MX 10 mail.example.com.")}
			_ = w.WriteMsg(m)
			return
		}
		_ = w.WriteMsg(answerA(t, r, dns.Fqdn(q.Name), "192.0.2.1"))
	})
	g.ready(t)
	g.stub(t, "example.com.", []cache.AuthServer{{Name: "ns.example.com.", Addrs: []string{ex}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeMX)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || rrset.RRs[0].Header().Rrtype != dns.TypeMX {
		t.Fatalf("client answer: rcode %s rrset %v err %v, want the MX", dns.RcodeToString[rcode], rrset, err)
	}
}

func TestQminNXDOMAINDoesNotFailAnIntermediateName(t *testing.T) {
	const (
		mid   = "foo.example.com."
		qname = "www.foo.example.com."
		ex    = "127.0.0.3"
	)
	g := newQminRig(t)
	g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if dns.CanonicalName(q.Name) == mid {
			_ = w.WriteMsg(nxdomain(t, r, "example.com."))
			return
		}
		_ = w.WriteMsg(answerA(t, r, qname, "192.0.2.80"))
	})
	g.ready(t)
	g.stub(t, "example.com.", []cache.AuthServer{{Name: "ns.example.com.", Addrs: []string{ex}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeA)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil {
		t.Fatalf("intermediate NXDOMAIN failed the client query: rcode %s err %v", dns.RcodeToString[rcode], err)
	}
	if c := g.imr.Cache.Get(mid, dns.TypeA); c == nil || c.Context != cache.ContextNXDOMAIN {
		t.Fatalf("intermediate NXDOMAIN cached as %v", c)
	}

	// The final name's NXDOMAIN is the client's answer.
	g2 := newQminRig(t)
	g2.port = g.port
	g2.listen(t, net.ParseIP("127.0.0.5"), func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(nxdomain(t, r, "example.com."))
	})
	g2.ready(t)
	g2.stub(t, "example.com.", []cache.AuthServer{{Name: "ns.example.com.", Addrs: []string{"127.0.0.5"}, Alpn: []string{"do53"}}})
	_, rcode, cctx, err := g2.query(t, "nosuch.example.com.", dns.TypeA)
	if err != nil || rcode != dns.RcodeNameError || cctx != cache.ContextNXDOMAIN {
		t.Fatalf("final NXDOMAIN: rcode %s context %s err %v", dns.RcodeToString[rcode], cache.CacheContextToString[cctx], err)
	}
}

func TestQminFailedProbeSendsTheOriginalQuery(t *testing.T) {
	const (
		qname = "www.example.com."
		a     = "127.0.0.1"
		b     = "127.0.0.2"
		c     = "127.0.0.3"
	)
	g := newQminRig(t)
	probe := func(w dns.ResponseWriter, r *dns.Msg, kind string) {
		q := r.Question[0]
		if q.Qtype == dns.TypeA && dns.CanonicalName(q.Name) != qname {
			switch kind {
			case "servfail":
				m := new(dns.Msg)
				m.SetReply(r)
				m.Rcode = dns.RcodeServerFailure
				_ = w.WriteMsg(m)
			case "refused":
				m := new(dns.Msg)
				m.SetReply(r)
				m.Rcode = dns.RcodeRefused
				_ = w.WriteMsg(m)
			default:
				// No answer: the client times out.
			}
			return
		}
		if kind == "servfail" {
			_ = w.WriteMsg(answerA(t, r, qname, "192.0.2.80"))
		}
	}
	g.listen(t, net.ParseIP(a), func(w dns.ResponseWriter, r *dns.Msg) { probe(w, r, "servfail") })
	g.listen(t, net.ParseIP(b), func(w dns.ResponseWriter, r *dns.Msg) { probe(w, r, "refused") })
	g.listen(t, net.ParseIP(c), func(w dns.ResponseWriter, r *dns.Msg) { probe(w, r, "timeout") })
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{
		{Name: "a.root-servers.net.", Addrs: []string{a}, Alpn: []string{"do53"}},
		{Name: "b.root-servers.net.", Addrs: []string{b}, Alpn: []string{"do53"}},
		{Name: "c.root-servers.net.", Addrs: []string{c}, Alpn: []string{"do53"}},
	})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeA)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || rrset.RRs[0].(*dns.A).A.String() != "192.0.2.80" {
		t.Fatalf("client answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	z, ok := g.imr.Cache.ZoneMap.Get(".")
	if !ok {
		t.Fatal("root zone was not cached")
	}
	if !z.IsZoneAddrXportAvailable(b, core.TransportDo53) {
		t.Error("REFUSED on the probe booked lameness")
	}

	// Probes succeed. The original query is REFUSED, and that is booked.
	g2 := newQminRig(t)
	g2.listen(t, net.ParseIP("127.0.0.8"), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if dns.CanonicalName(q.Name) == qname {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		_ = w.WriteMsg(nodata(t, r, "."))
	})
	g2.ready(t)
	g2.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{"127.0.0.8"}, Alpn: []string{"do53"}}})
	if _, _, _, err := g2.query(t, qname, dns.TypeA); err == nil {
		t.Fatal("expected the original query to fail")
	}
	z, ok = g2.imr.Cache.ZoneMap.Get(".")
	if !ok || z.IsZoneAddrXportAvailable("127.0.0.8", core.TransportDo53) {
		t.Fatalf("the original query's REFUSED was not booked: zone %v", z)
	}
}

func TestQminDSGoesToTheParent(t *testing.T) {
	const (
		qname = "example.com."
		root  = "127.0.0.1"
		com   = "127.0.0.2"
		ex    = "127.0.0.3"
	)
	g := newQminRig(t)
	g.listen(t, net.ParseIP(root), func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(qminReferral(t, r, "com.", "ns.com.", com))
	})
	comLog := g.listen(t, net.ParseIP(com), func(w dns.ResponseWriter, r *dns.Msg) {
		m := nodata(t, r, "com.")
		if r.Question[0].Qtype == dns.TypeDS {
			m = new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, qname+" 300 IN DS 12345 13 2 AAAAAAAAAAAAAAAA")}
		}
		_ = w.WriteMsg(m)
	})
	exLog := g.listen(t, net.ParseIP(ex), func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
	})
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{root}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeDS)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || rrset.RRs[0].Header().Rrtype != dns.TypeDS {
		t.Fatalf("DS answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	for _, q := range comLog.list() {
		if strings.HasSuffix(q, " DS") && !strings.HasPrefix(q, qname) {
			t.Errorf(".com saw a DS for the wrong name: %s", q)
		}
	}
	saw := false
	for _, q := range comLog.list() {
		if q == qname+" DS" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf(".com saw %v, want %s DS", comLog.list(), qname)
	}
	if len(exLog.list()) != 0 {
		t.Errorf("the child saw %v; a DS is the parent's", exLog.list())
	}
}

func TestQminLongNameStopsAtTheCap(t *testing.T) {
	labels := make([]string, 100)
	for i := range labels {
		labels[i] = "a"
	}
	qname := dns.Fqdn(strings.Join(labels, "."))
	g := newQminRig(t)
	log := g.listen(t, net.ParseIP("127.0.0.1"), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if q.Qtype == dns.TypeMX && dns.CanonicalName(q.Name) == qname {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = []dns.RR{mustRR(t, qname+" 300 IN MX 10 mail.")}
			_ = w.WriteMsg(m)
			return
		}
		_ = w.WriteMsg(answerA(t, r, dns.Fqdn(q.Name), "192.0.2.1"))
	})
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, qname, dns.TypeMX)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || rrset.RRs[0].Header().Rrtype != dns.TypeMX {
		t.Fatalf("client answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	var probes int
	for _, q := range log.list() {
		if strings.HasSuffix(q, " A") {
			probes++
		}
	}
	if probes > 10 {
		t.Fatalf("%d probes, want at most 10: %v", probes, log.list())
	}
	if probes < 1 || log.list()[len(log.list())-1] != qname+" MX" {
		t.Fatalf("questions %v, want probes and then the original name", log.list())
	}
}

func TestQminManyCutsShareOneCap(t *testing.T) {
	labels := make([]string, 30)
	for i := range labels {
		labels[i] = "b"
	}
	qname := dns.Fqdn(strings.Join(labels, "."))
	g := newQminRig(t)
	log := g.listen(t, net.ParseIP("127.0.0.1"), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := dns.CanonicalName(q.Name)
		if name == qname && q.Qtype == dns.TypeA {
			_ = w.WriteMsg(answerA(t, r, qname, "192.0.2.30"))
			return
		}
		_ = w.WriteMsg(qminReferral(t, r, name, "ns."+name, "127.0.0.1"))
	})
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}}})

	rrset, _, _, err := g.query(t, qname, dns.TypeA)
	if err != nil || rrset == nil || rrset.RRs[0].(*dns.A).A.String() != "192.0.2.30" {
		t.Fatalf("answer: %v %v", rrset, err)
	}
	var probes int
	for _, q := range log.list() {
		if q != qname+" A" {
			probes++
		}
	}
	if probes > 10 {
		t.Fatalf("%d probes across the cuts, want at most 10: %v", probes, log.list())
	}
}

func TestQminLabelsCountedFromTheServersAsked(t *testing.T) {
	g := newQminRig(t)
	log := g.listen(t, net.ParseIP("127.0.0.1"), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if dns.CanonicalName(q.Name) == "www.example.com." {
			_ = w.WriteMsg(answerA(t, r, "www.example.com.", "192.0.2.7"))
			return
		}
		_ = w.WriteMsg(nodata(t, r, "."))
	})
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}}})
	servers := g.servers(t, "www.example.com.", dns.TypeA)
	g.imr.Cache.ZoneMap.Set("example.com.", &cache.Zone{ZoneName: "example.com."})
	g.imr.Cache.ServerMap.Set("example.com.", map[string]*cache.AuthServer{})

	if _, _, _, _, err := g.imr.IterativeDNSQuery(context.Background(), "www.example.com.", dns.TypeA, servers, false, edns0.PrivacyNone); err != nil {
		t.Fatal(err)
	}
	if len(log.list()) == 0 || log.list()[0] != "com. A" {
		t.Fatalf("first question %v, want com. A counted from the root", log.list())
	}
}

func TestQminNoZoneSendsTheOriginalQuery(t *testing.T) {
	g := newQminRig(t)
	log := g.listen(t, net.ParseIP("127.0.0.1"), func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(answerA(t, r, "www.example.com.", "192.0.2.7"))
	})
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}}})
	zone, servers, err := g.imr.Cache.FindClosestKnownZoneFor("www.example.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	g.imr.Cache.ServerMap.Set(zone, map[string]*cache.AuthServer{})
	rrset, _, _, _, qerr := g.imr.IterativeDNSQuery(context.Background(), "www.example.com.", dns.TypeA, servers, false, edns0.PrivacyNone)
	if qerr != nil || rrset == nil {
		t.Fatalf("query: %v %v", rrset, qerr)
	}
	wantQuestions(t, "the only server", log.list(), []string{"www.example.com. A"})
}

func TestQminRequestCapStopsLaterWalks(t *testing.T) {
	g := newQminRig(t)
	maxIter, one := 2, 0
	g.imr.Tuning.QminMaxIterations = &maxIter
	g.imr.Tuning.QminOneLabel = &one
	names := make([]string, 4)
	for i := range names {
		labels := make([]string, 8)
		for j := range labels {
			labels[j] = "w" + strconv.Itoa(i) + "x" + strconv.Itoa(j)
		}
		names[i] = dns.Fqdn(strings.Join(labels, "."))
	}
	log := g.listen(t, net.ParseIP("127.0.0.1"), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := dns.CanonicalName(q.Name)
		if q.Qtype == dns.TypeA {
			_ = w.WriteMsg(nodata(t, r, "."))
			return
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		switch name {
		case names[0]:
			m.Answer = []dns.RR{mustRR(t, names[0]+" 300 IN CNAME "+names[1])}
		case names[1]:
			m.Answer = []dns.RR{mustRR(t, names[1]+" 300 IN CNAME "+names[2])}
		case names[2]:
			m.Answer = []dns.RR{mustRR(t, names[2]+" 300 IN CNAME "+names[3])}
		case names[3]:
			m.Answer = []dns.RR{mustRR(t, names[3]+" 300 IN MX 10 mail.")}
		default:
			m = nodata(t, r, ".")
		}
		_ = w.WriteMsg(m)
	})
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}}})

	rrset, rcode, _, err := g.query(t, names[0], dns.TypeMX)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil || rrset.RRs[0].Header().Rrtype != dns.TypeMX {
		t.Fatalf("chain answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	var fourth []string
	for _, q := range log.list() {
		if strings.Contains(q, "w3x") {
			fourth = append(fourth, q)
		}
	}
	// The fourth walk is past 3×max probes, so it sends the original query only.
	var probes int
	for _, q := range fourth {
		if strings.HasSuffix(q, " A") {
			probes++
		}
	}
	if probes != 0 || len(fourth) != 1 || fourth[0] != names[3]+" MX" {
		t.Fatalf("fourth walk saw %v, want only the original MX", fourth)
	}
}

func TestQminOffSendsTheOriginalQuery(t *testing.T) {
	g := newQminRig(t)
	delete(g.imr.Options, ImrOptQnameMinimisation)
	log := g.listen(t, net.ParseIP("127.0.0.1"), func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{mustRR(t, "www.example.com. 300 IN MX 10 mail.example.com.")}
		_ = w.WriteMsg(m)
	})
	g.ready(t)
	g.stub(t, ".", []cache.AuthServer{{Name: "ns.", Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}}})
	if _, _, _, err := g.query(t, "www.example.com.", dns.TypeMX); err != nil {
		t.Fatal(err)
	}
	wantQuestions(t, "option off", log.list(), []string{"www.example.com. MX"})
}

func TestQminForwardAndOwnZoneSendTheFullName(t *testing.T) {
	rec := &asked{}
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, func(w dns.ResponseWriter, r *dns.Msg) {
		rec.note(r)
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		m.Answer = []dns.RR{mustRR(t, "www.fwd.example. 300 IN A 192.0.2.9")}
		_ = w.WriteMsg(m)
	})
	imr := newForwardTestImr(t, []ImrForwardConf{{
		Zone:      "fwd.example.",
		Upstreams: []ImrUpstreamConf{{Addr: "127.0.0.1", Port: uint16(port)}},
	}})
	enableQmin(imr)
	rrset, rcode, _, _, err := imr.IterativeDNSQuery(context.Background(), "www.fwd.example.", dns.TypeA, nil, false, edns0.PrivacyNone)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil {
		t.Fatalf("forwarded answer: rcode %s rrset %v err %v", dns.RcodeToString[rcode], rrset, err)
	}
	wantQuestions(t, "forward", rec.list(), []string{"www.fwd.example. A"})

	rig := newOwnZoneRig(t)
	enableQmin(rig.imr)
	resp, err := rig.imr.ImrQuery(context.Background(), "www."+ownParent, dns.TypeA, dns.ClassINET, nil)
	if err != nil || resp.RRset == nil || rdataOf(resp.RRset.RRs[0]) != "192.0.2.2" {
		t.Fatalf("own zone: %+v err %v", resp, err)
	}
	requireUpstreamNotAsked(t, rig.upLog, ownParent)
}

// A glueless referral carries the NS name and no address. The probe must not
// mark that delegation seen for the original question, and it must not ask
// every parent server for the same referral.
func TestQminGluelessReferralDoesNotLoop(t *testing.T) {
	const (
		qname = "www.example.com."
		com1  = "127.0.0.2"
		com2  = "127.0.0.3"
		netNS = "127.0.0.4"
		child = "127.0.0.5"
		ns    = "ns.example.net."
	)
	g := newQminRig(t)
	parent := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Ns = []dns.RR{mustRR(t, "example.com. 300 IN NS "+ns)}
		_ = w.WriteMsg(m)
	}
	p1 := g.listen(t, net.ParseIP(com1), parent)
	p2 := g.listen(t, net.ParseIP(com2), parent)
	g.listen(t, net.ParseIP(netNS), func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if q.Qtype == dns.TypeA && dns.CanonicalName(q.Name) == ns {
			_ = w.WriteMsg(answerA(t, r, ns, child))
			return
		}
		_ = w.WriteMsg(nodata(t, r, "example.net."))
	})
	childLog := g.listen(t, net.ParseIP(child), func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(answerA(t, r, qname, "192.0.2.80"))
	})
	g.ready(t)
	g.stub(t, "com.", []cache.AuthServer{
		{Name: "a.ns.com.", Addrs: []string{com1}, Alpn: []string{"do53"}},
		{Name: "b.ns.com.", Addrs: []string{com2}, Alpn: []string{"do53"}},
	})
	g.stub(t, "example.net.", []cache.AuthServer{
		{Name: "ns.net.", Addrs: []string{netNS}, Alpn: []string{"do53"}},
	})

	rrset, _, _, err := g.query(t, qname, dns.TypeA)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	var probes, originals int
	for _, q := range append(p1.list(), p2.list()...) {
		switch q {
		case "example.com. A":
			probes++
		case qname + " A":
			originals++
		}
	}
	if probes != 1 || originals != 1 {
		t.Fatalf("parents saw probe %d times and the original query %d times, want 1 and 1: %v | %v",
			probes, originals, p1.list(), p2.list())
	}
	if rrset == nil {
		deadline := time.Now().Add(2 * time.Second)
		for {
			zone, servers, _ := g.imr.Cache.FindClosestKnownZone(qname)
			if core.EqualNames(zone, "example.com.") && len(servers) > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("example.com never got a server (closest %s)", zone)
			}
			time.Sleep(20 * time.Millisecond)
		}
		rrset, _, _, err = g.query(t, qname, dns.TypeA)
		if err != nil {
			t.Fatalf("retry: %v", err)
		}
	}
	if rrset == nil || len(rrset.RRs) != 1 || rrset.RRs[0].Header().Rrtype != dns.TypeA || rrset.RRs[0].(*dns.A).A.String() != "192.0.2.80" {
		t.Fatalf("client answer: %v", rrset)
	}
	if got := childLog.list(); len(got) != 1 || got[0] != qname+" A" {
		t.Errorf("child saw %v, want [%s A]", got, qname)
	}
}
