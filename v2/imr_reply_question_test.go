/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A reply is used only if it answers the question that was asked: exactly one
// question, with the query's name, type and class.

func TestReplyMatchesQuery(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("www.example.", dns.TypeA)
	reply := func(qs ...dns.Question) *dns.Msg {
		r := new(dns.Msg)
		r.Question = qs
		return r
	}
	q := func(name string, qtype, qclass uint16) dns.Question {
		return dns.Question{Name: name, Qtype: qtype, Qclass: qclass}
	}
	for _, tc := range []struct {
		name string
		r    *dns.Msg
		ok   bool
	}{
		{"same question", reply(q("www.example.", dns.TypeA, dns.ClassINET)), true},
		{"name in another case", reply(q("WWW.Example.", dns.TypeA, dns.ClassINET)), true},
		{"no question", reply(), false},
		{"two questions", reply(q("www.example.", dns.TypeA, dns.ClassINET), q("www.example.", dns.TypeA, dns.ClassINET)), false},
		{"another name", reply(q("evil.example.", dns.TypeA, dns.ClassINET)), false},
		{"another type", reply(q("www.example.", dns.TypeAAAA, dns.ClassINET)), false},
		{"another class", reply(q("www.example.", dns.TypeA, dns.ClassCHAOS)), false},
	} {
		if err := replyMatchesQuery(tc.r, query); (err == nil) != tc.ok {
			t.Errorf("%s: replyMatchesQuery = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

const (
	rqZone = "rq.test."
	rqName = "www.rq.test."
)

// rqImr is a resolver whose only route to rqZone is a stub with the given
// servers, each a test double answering with handler. Transport signals are
// left on, as they are by default.
func rqImr(t *testing.T, servers map[string]dns.HandlerFunc) *Imr {
	t.Helper()
	port := 0
	var stub []cache.AuthServer
	for _, ip := range []string{"127.0.0.1", "::1"} {
		h, ok := servers[ip]
		if !ok {
			continue
		}
		port = startRefDouble(t, net.ParseIP(ip), port, h)
		stub = append(stub, cache.AuthServer{Name: "ns" + strconv.Itoa(len(stub)) + "." + rqZone, Addrs: []string{ip}, Alpn: []string{"do53"}})
	}
	imr := verdictImr(t, false)
	if imr.Options[ImrOptUseTransportSignals] == "false" {
		t.Fatal("precondition: transport signals are off")
	}
	p := strconv.Itoa(port)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
	if err := imr.Cache.AddStub(rqZone, stub); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.Cache.ZoneMap.Set(".", &cache.Zone{ZoneName: ".", State: cache.ValidationStateIndeterminate})
	return imr
}

// answering replies with an A record for rqName, and lets shape change the
// reply before it is sent.
func answering(t *testing.T, addr string, shape func(*dns.Msg)) dns.HandlerFunc {
	a := mustRR(t, rqName+" 300 IN A "+addr)
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{a}
		if shape != nil {
			shape(m)
		}
		_ = w.WriteMsg(m)
	}
}

func noQuestion(m *dns.Msg) { m.Question = nil }

func otherQuestion(m *dns.Msg) {
	m.Question = []dns.Question{{Name: "evil." + rqZone, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
}

// A reply with an answer and no question section used to reach the
// transport-signal parser, which read its question and panicked, taking the
// resolver down. It is now discarded: the client gets SERVFAIL, and nothing
// is cached for the name.
func TestReplyWithoutQuestionIsDiscarded(t *testing.T) {
	for name, shape := range map[string]func(*dns.Msg){
		"no question":    noQuestion,
		"other question": otherQuestion,
	} {
		t.Run(name, func(t *testing.T) {
			imr := rqImr(t, map[string]dns.HandlerFunc{"127.0.0.1": answering(t, "192.0.2.66", shape)})
			got := askReferralImr(t, imr, rqName)
			if got.Rcode != dns.RcodeServerFailure || len(got.Answer) != 0 {
				t.Fatalf("got %s with %d answers, want SERVFAIL and none:\n%s",
					dns.RcodeToString[got.Rcode], len(got.Answer), got)
			}
			if c := imr.Cache.Get(rqName, dns.TypeA); c != nil && c.RRset != nil && len(c.RRset.RRs) > 0 {
				t.Errorf("the discarded reply's answer was cached: %v", c.RRset.RRs)
			}
		})
	}
}

// A discarded reply is a failed attempt at that server: another server of the
// zone is still asked, and its answer is served.
func TestReplyWithoutQuestionFallsThroughToAnotherServer(t *testing.T) {
	imr := rqImr(t, map[string]dns.HandlerFunc{
		"127.0.0.1": answering(t, "192.0.2.66", noQuestion),
		"::1":       answering(t, "192.0.2.80", nil),
	})
	got := askReferralImr(t, imr, rqName)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("got %s with %d answers, want the good server's answer:\n%s",
			dns.RcodeToString[got.Rcode], len(got.Answer), got)
	}
	if a, ok := got.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.80" {
		t.Fatalf("answer %v, want 192.0.2.80 from the server that answered the question", got.Answer[0])
	}
}

// The client handler answers a query without a question with FORMERR instead
// of reading an empty question section.
func TestImrHandlerAnswersFormerrWithoutQuestion(t *testing.T) {
	imr := verdictImr(t, false)
	h := imr.createImrHandler(context.Background(), &Config{})
	cw := &captureWriter{}
	r := new(dns.Msg)
	r.Id = 4711
	h(cw, r)
	if cw.got == nil {
		t.Fatal("the handler wrote nothing")
	}
	if cw.got.Rcode != dns.RcodeFormatError || cw.got.Id != 4711 || !cw.got.Response {
		t.Fatalf("got rcode %s id %d response %v, want FORMERR to id 4711",
			dns.RcodeToString[cw.got.Rcode], cw.got.Id, cw.got.Response)
	}
}
