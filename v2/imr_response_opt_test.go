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
