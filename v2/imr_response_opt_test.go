/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A response to an EDNS query carries an OPT. RFC 6891 §6.1.1.
 */
package tdns

import (
	"context"
	"testing"
	"time"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// edns0Query is what dig sends: a question plus an OPT, DO as asked.
func edns0Query(qname string, qtype uint16, do bool) *dns.Msg {
	r := new(dns.Msg)
	r.SetQuestion(qname, qtype)
	r.SetEdns0(4096, do)
	return r
}

// serveFromCache answers out of a seeded cache, so nothing touches the network.
func serveFromCache(t *testing.T, imr *Imr, r *dns.Msg, qname string, qtype uint16, opts *edns0.MsgOptions) *dns.Msg {
	t.Helper()
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, opts)
	if cw.got == nil {
		t.Fatal("responder wrote no response")
	}
	return cw.got
}

// THE REGRESSION. imr answered DO-bit queries with ADDITIONAL: 0 and no OPT,
// and got one only where something else -- an EDE, a PRIVACY status -- happened
// to build it. A client answered without an OPT has been told the server does
// not speak EDNS, so a strict resolver downgrades to plain DNS, drops DO, and
// stops validating.
func TestEdnsQueryIsAnsweredWithAnOPT(t *testing.T) {
	imr := newTestImr(t)
	seedAnswer(t, imr, "host.example. 300 IN A 192.0.2.1", 300*time.Second)

	m := serveFromCache(t, imr, edns0Query("host.example.", dns.TypeA, true),
		"host.example.", dns.TypeA, &edns0.MsgOptions{RD: true, DO: true})

	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("no OPT in the response to an EDNS query")
	}
	if !opt.Do() {
		t.Error("the response OPT does not mirror the query's DO bit (RFC 3225 §3)")
	}
}

// A cached NODATA is answered by a different branch, and had the same hole.
func TestNegativeAnswerCarriesAnOPT(t *testing.T) {
	imr := newTestImr(t)
	seedNodata(t, imr, "ns1.example.", dns.TypeSOA, "example.")

	m := serveFromCache(t, imr, edns0Query("ns1.example.", dns.TypeSOA, true),
		"ns1.example.", dns.TypeSOA, &edns0.MsgOptions{RD: true, DO: true})

	if m.IsEdns0() == nil {
		t.Fatal("no OPT in the response to an EDNS query for a name with no data")
	}
}

// A plain-DNS query gets a plain-DNS reply. Attaching an OPT unasked would be
// its own protocol error.
func TestPlainQueryIsAnsweredWithoutAnOPT(t *testing.T) {
	imr := newTestImr(t)
	seedAnswer(t, imr, "host.example. 300 IN A 192.0.2.1", 300*time.Second)

	r := new(dns.Msg)
	r.SetQuestion("host.example.", dns.TypeA)
	m := serveFromCache(t, imr, r, "host.example.", dns.TypeA, &edns0.MsgOptions{RD: true})

	if m.IsEdns0() != nil {
		t.Error("a query that carried no OPT was answered with one")
	}
}

// Exactly one OPT. The paths that attach an option build an OPT of their own
// when there is none, so attaching one up front must not produce a second --
// a message with two OPTs does not pack.
func TestOnlyOneOPTWhenAnOptionIsAlsoAttached(t *testing.T) {
	imr := newTestImr(t)
	seedAnswer(t, imr, "host.example. 300 IN A 192.0.2.1", 300*time.Second)

	m := serveFromCache(t, imr, edns0Query("host.example.", dns.TypeA, true),
		"host.example.", dns.TypeA,
		&edns0.MsgOptions{RD: true, DO: true, HasPrivacy: true, Privacy: edns0.PrivacyOpportunistic})

	var opts int
	for _, rr := range m.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			opts++
		}
	}
	if opts != 1 {
		t.Fatalf("response carries %d OPT records, want exactly 1", opts)
	}
	if _, err := m.Pack(); err != nil {
		t.Errorf("response does not pack: %v", err)
	}
}

// Every response must pack. A response that cannot be packed is what a client
// reports as a malformed message.
func TestResponsePacks(t *testing.T) {
	imr := newTestImr(t)
	seedAnswer(t, imr, "host.example. 300 IN A 192.0.2.1", 300*time.Second)

	m := serveFromCache(t, imr, edns0Query("host.example.", dns.TypeA, true),
		"host.example.", dns.TypeA, &edns0.MsgOptions{RD: true, DO: true})

	if _, err := m.Pack(); err != nil {
		t.Fatalf("response does not pack: %v", err)
	}
}

// A CHAOS query for a name this server does not serve is refused, not
// recursed. ImrResponder takes a qname and a qtype and no qclass at all, so a
// CHAOS query reaching it is resolved in class IN and answered with IN data
// under a CHAOS question.
func TestUnhandledChaosQueryIsRefused(t *testing.T) {
	imr := newTestImr(t)
	handler := imr.createImrHandler(context.Background(), &Config{})

	r := new(dns.Msg)
	r.SetQuestion("version.bind.", dns.TypeTXT)
	r.Question[0].Qclass = dns.ClassCHAOS
	r.SetEdns0(4096, false)
	r.RecursionDesired = true

	cw := &captureWriter{}
	handler(cw, r)

	if cw.got == nil {
		t.Fatal("handler wrote no response")
	}
	if cw.got.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED for a CHAOS name this server does not serve",
			dns.RcodeToString[cw.got.Rcode])
	}
	if len(cw.got.Answer) != 0 {
		t.Errorf("a refused CHAOS query was answered with %d records", len(cw.got.Answer))
	}
	if cw.got.IsEdns0() == nil {
		t.Error("the refusal carries no OPT although the query did")
	}
	if _, err := cw.got.Pack(); err != nil {
		t.Errorf("response does not pack: %v", err)
	}
}

// The CHAOS names it DOES serve keep working, and now carry an OPT too.
func TestServerChaosQueryStillAnswered(t *testing.T) {
	imr := newTestImr(t)
	handler := imr.createImrHandler(context.Background(), &Config{})

	r := new(dns.Msg)
	r.SetQuestion("version.server.", dns.TypeTXT)
	r.Question[0].Qclass = dns.ClassCHAOS
	r.SetEdns0(4096, false)

	cw := &captureWriter{}
	handler(cw, r)

	if cw.got == nil {
		t.Fatal("handler wrote no response")
	}
	if cw.got.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[cw.got.Rcode])
	}
	if len(cw.got.Answer) != 1 {
		t.Fatalf("got %d answer records, want the version TXT", len(cw.got.Answer))
	}
	if cw.got.IsEdns0() == nil {
		t.Error("the CHAOS answer carries no OPT although the query did")
	}
	if _, err := cw.got.Pack(); err != nil {
		t.Errorf("response does not pack: %v", err)
	}
}
