package tdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// startRcodeResponder brings up a TCP UPDATE responder that answers every
// request with a fixed rcode, and returns its addr:port. It attaches an OPT RR
// because the extended rcodes (BADKEY 17, BADSIG 16, BADTIME 18) do not fit the
// 4-bit header field: without an OPT, packing a message with Rcode > 0xF fails
// with ErrExtendedRcode and the response is never sent.
func startRcodeResponder(t *testing.T, answer int) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	srv := &dns.Server{
		Listener: ln,
		Net:      "tcp",
		// The default MsgAcceptFunc rejects the UPDATE opcode as NOTIMP before
		// the handler runs; use tdns's own accept func, as the real server does.
		MsgAcceptFunc: MsgAcceptFunc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.SetEdns0(4096, false)
			m.Rcode = answer
			_ = w.WriteMsg(m)
		}),
	}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	<-started

	return ln.Addr().String()
}

func testUpdateMsg(t *testing.T) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate("child.parent.example.")
	rr, err := dns.NewRR("child.parent.example. 3600 IN NS ns1.child.parent.example.")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	m.Insert([]dns.RR{rr})
	m.SetEdns0(1232, true)
	return m
}

// TestSendUpdateReportsRejectionRcode pins SendUpdate's return contract: a
// response carrying a rejection RCODE is a successful exchange and must be
// reported through the rcode with a NIL error. Only a transport failure is an
// error.
//
// This is the regression guard for a bug that made the entire delegation-sync
// RCODE policy of draft-ietf-dnsop-delegation-mgmt-via-ddns-02 unreachable:
// SendUpdate returned the rcode only on the NOERROR path and folded every
// rejection into a generic "all target addresses responded with errors" error
// carrying rcode 0. sendUpdateWithRetry short-circuits on a non-nil error, so
// its `case dns.RcodeBadKey` (re-bootstrap) and `case dns.RcodeRefused`
// (bounded retry) arms could never fire against a real receiver — they were
// exercised only by the injected send closure in delsync_retry_test.go.
func TestSendUpdateReportsRejectionRcode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer int
	}{
		{"NOERROR", dns.RcodeSuccess},
		{"BADKEY", dns.RcodeBadKey},
		{"REFUSED", dns.RcodeRefused},
		{"SERVFAIL", dns.RcodeServerFailure},
		{"NOTAUTH", dns.RcodeNotAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := startRcodeResponder(t, tc.answer)

			rcode, ur, err := SendUpdate(testUpdateMsg(t), "child.parent.example.", []string{addr})
			if err != nil {
				t.Fatalf("SendUpdate returned an error for a responding target: %v "+
					"(a rejection RCODE is not a transport failure)", err)
			}
			if rcode != tc.answer {
				t.Errorf("rcode = %d (%s), want %d (%s)",
					rcode, dns.RcodeToString[rcode], tc.answer, dns.RcodeToString[tc.answer])
			}
			// The per-target detail must agree with the headline rcode.
			ts, ok := ur.TargetStatus[addr]
			if !ok {
				t.Fatalf("UpdateResult has no TargetStatus for %s", addr)
			}
			if ts.Rcode != tc.answer {
				t.Errorf("TargetStatus[%s].Rcode = %d, want %d", addr, ts.Rcode, tc.answer)
			}
		})
	}
}

// TestSendUpdateUnreachableIsTransportError asserts the other half of the
// contract: when NO address produces a DNS response, that IS an error, and the
// rcode is meaningless (0).
func TestSendUpdateUnreachableIsTransportError(t *testing.T) {
	// Bind and immediately close, so the port is (almost certainly) refusing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()

	rcode, _, err := SendUpdate(testUpdateMsg(t), "child.parent.example.", []string{dead})
	if err == nil {
		t.Fatal("SendUpdate returned nil error for an unreachable target; a transport failure must be an error")
	}
	if rcode != 0 {
		t.Errorf("rcode = %d, want 0 for a transport failure", rcode)
	}
}

// TestSendUpdatePrefersRespondingTarget asserts that an unreachable address
// does not mask a rejection from a later one: the caller still learns the
// RCODE, which is what drives the BADKEY -> re-bootstrap decision.
func TestSendUpdatePrefersRespondingTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()

	live := startRcodeResponder(t, dns.RcodeBadKey)

	rcode, _, err := SendUpdate(testUpdateMsg(t), "child.parent.example.", []string{dead, live})
	if err != nil {
		t.Fatalf("SendUpdate: %v", err)
	}
	if rcode != dns.RcodeBadKey {
		t.Errorf("rcode = %d (%s), want BADKEY — a dead first address must not hide the second's rejection",
			rcode, dns.RcodeToString[rcode])
	}
}

// TestSendUpdateSucceedsPastRejectingTarget asserts the converse: a rejecting
// address does not stop the search, and a later NOERROR still wins.
func TestSendUpdateSucceedsPastRejectingTarget(t *testing.T) {
	rejecting := startRcodeResponder(t, dns.RcodeRefused)
	accepting := startRcodeResponder(t, dns.RcodeSuccess)

	rcode, _, err := SendUpdate(testUpdateMsg(t), "child.parent.example.", []string{rejecting, accepting})
	if err != nil {
		t.Fatalf("SendUpdate: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d (%s), want NOERROR", rcode, dns.RcodeToString[rcode])
	}
}
