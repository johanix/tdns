/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeParentAgent serves one canned answer to every DS query, over TCP.
func fakeParentAgent(t *testing.T, answer func(q *dns.Msg) *dns.Msg) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		w.WriteMsg(answer(q))
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return ln.Addr().String()
}

func soaRR(t *testing.T, owner string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(owner + " 3600 IN SOA ns." + owner + " hostmaster." + owner + " 1 3600 600 86400 60")
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// An empty DS answer counts as "the parent holds no DS" only when it is
// authoritative and comes from a zone above the child. Anything else is a
// failed poll: a resolver, or the child's own server, which says "no DS" for
// every query.
func TestQueryParentAgentDSRefusesAnswersNotFromTheParent(t *testing.T) {
	const child = "child.parent.example."
	ds, err := dns.NewRR(child + " 3600 IN DS 12345 15 2 3F92C5D1")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		aa      bool
		answer  []dns.RR
		soa     string // "" = no SOA in the authority section
		wantDS  int
		wantErr string
	}{
		{"parent says no DS", true, nil, "parent.example.", 0, ""},
		{"grandparent says no DS", true, nil, "example.", 0, ""},
		{"parent holds DS", true, []dns.RR{ds}, "", 1, ""},
		{"not authoritative", false, nil, "parent.example.", 0, "authoritatively"},
		{"the child's own server", true, nil, child, 0, "not from its parent"},
		{"an unrelated zone", true, nil, "other.example.", 0, "not from its parent"},
		{"no SOA", true, nil, "", 0, "without an SOA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := fakeParentAgent(t, func(q *dns.Msg) *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(q)
				m.Authoritative = tc.aa
				m.Answer = tc.answer
				if tc.soa != "" {
					m.Ns = []dns.RR{soaRR(t, tc.soa)}
				}
				return m
			})
			got, err := QueryParentAgentDS(context.Background(), child, addr)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("QueryParentAgentDS: %v", err)
			}
			if len(got) != tc.wantDS {
				t.Errorf("got %d RRs, want %d", len(got), tc.wantDS)
			}
		})
	}
}
