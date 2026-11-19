/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// captureLog sends the log package's output to a buffer for the rest of
// the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// RemoveRR says nothing through the log package, debug or not: what it did
// is its result.
func TestRemoveRRDoesNotLog(t *testing.T) {
	global := captureLog(t)
	rr := mustRR(t, "rm.example. 60 IN A 192.0.2.1")
	rrset := &RRset{Name: "rm.example.", RRtype: dns.TypeA, RRs: []dns.RR{rr}}
	if !rrset.RemoveRR(dns.Copy(rr), true, true) {
		t.Fatalf("RemoveRR: want the RR removed")
	}
	if global.Len() != 0 {
		t.Errorf("the log package got %q", global.String())
	}
}

// panickyRR is an A record whose String panics.
type panickyRR struct{ *dns.A }

func (panickyRR) String() string { panic("boom") }

// A panic part-way through RRset.String is in the result, after what was
// rendered before it, and nothing goes to the log package.
func TestRRsetStringReportsAPanicInTheResult(t *testing.T) {
	global := captureLog(t)
	ok := mustRR(t, "p.example. 60 IN A 192.0.2.1")
	bad := panickyRR{mustRR(t, "p.example. 60 IN A 192.0.2.2").(*dns.A)}
	rrset := &RRset{Name: "p.example.", RRtype: dns.TypeA, RRs: []dns.RR{ok, bad}}

	out := rrset.String(0)
	if !strings.HasPrefix(out, ok.String()+"\n") {
		t.Errorf("String = %q; want the RR before the panic first", out)
	}
	if !strings.Contains(out, "(RRset.String panic: boom)") {
		t.Errorf("String = %q; want the panic reported", out)
	}
	if global.Len() != 0 {
		t.Errorf("the log package got %q", global.String())
	}
}
