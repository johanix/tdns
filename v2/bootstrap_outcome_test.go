/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// TestTheParentsAnswerDecidesWhetherBootstrapRetries drives each answer over a
// real socket through the real SendUpdate, then through bootstrapOutcome.
//
// The ceremony hands back the parent's rcode and EDE with a nil error, by
// design, so its caller can apply per-rcode, per-EDE policy. DelegationSyncSetup
// never applied it: every non-NOERROR answer was logged as "bootstrap complete"
// and taken as done, so a parent that said "not yet" left the zone
// unbootstrapped until the next reload. Going through SendUpdate rather than
// hand-built UpdateResults tests the join too -- that the producer fills the
// fields the classifier reads.
func TestTheParentsAnswerDecidesWhetherBootstrapRetries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rcode     int
		ede       uint16 // 0 = no EDE
		transient bool
		manual    bool
	}{
		{name: "NOERROR is done", rcode: dns.RcodeSuccess},
		{name: "SERVFAIL retries", rcode: dns.RcodeServerFailure, transient: true},
		{name: "key known, not yet trusted, retries", rcode: dns.RcodeRefused,
			ede: edns0.EDESig0KeyKnownButNotTrusted, transient: true},
		{name: "manual bootstrap required waits for the operator", rcode: dns.RcodeRefused,
			ede: edns0.EDESig0ManualBootstrapRequired, manual: true},
		{name: "validation failed is final", rcode: dns.RcodeRefused,
			ede: edns0.EDESig0KeyValidationFailed},
		{name: "a bare REFUSED is final", rcode: dns.RcodeRefused},
		{name: "NOTAUTH is final", rcode: dns.RcodeNotAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addr string
			if tc.ede != 0 {
				addr = startRcodeEDEResponder(t, tc.rcode, tc.ede)
			} else {
				addr = startRcodeResponder(t, tc.rcode)
			}
			_, ur, sendErr := SendUpdate(context.Background(), testUpdateMsg(t),
				"child.parent.example.", []string{addr})

			err := bootstrapOutcome(ur, sendErr)

			switch {
			case tc.rcode == dns.RcodeSuccess:
				if err != nil {
					t.Errorf("a NOERROR bootstrap was reported as %v", err)
				}
			case tc.transient:
				if !errors.Is(err, errBootstrapTransient) {
					t.Errorf("got %v, want errBootstrapTransient: this answer is not final, and"+
						" treating it as done leaves the zone unbootstrapped until reload", err)
				}
			case tc.manual:
				if !errors.Is(err, errBootstrapManual) {
					t.Errorf("got %v, want errBootstrapManual: the operator has to act, and"+
						" that is a wait, not a failure", err)
				}
			default:
				if err == nil {
					t.Error("a refusal was reported as success; it used to be logged as" +
						" \"bootstrap complete\"")
				}
				if errors.Is(err, errBootstrapTransient) {
					t.Errorf("a final refusal (%v) would be retried; it would only get the"+
						" same answer", err)
				}
			}
		})
	}
}

// A parent that cannot be reached at all is the most transient answer of the
// lot, and it used to be an unmatchable string -- so it was final too.
func TestAnUnreachableParentRetriesTheBootstrap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()

	_, ur, sendErr := SendUpdate(context.Background(), testUpdateMsg(t), "child.parent.example.", []string{dead})
	if !errors.Is(sendErr, ErrUpdateUnreachable) {
		t.Fatalf("SendUpdate's transport failure %v does not match ErrUpdateUnreachable", sendErr)
	}
	if err := bootstrapOutcome(ur, sendErr); !errors.Is(err, errBootstrapTransient) {
		t.Errorf("got %v, want errBootstrapTransient for an unreachable parent", err)
	}
}

// And the setup arm acts on it: a transient outcome schedules one retry, and
// the retries stop at the same limit as every other non-final failure.
func TestTheSetupArmRetriesATransientBootstrapWithinItsLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conf, q := setupRig(t, true)

	transient := func() error { return errors.Join(errBootstrapTransient, errors.New("SERVFAIL")) }

	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example."}
	done := handleDelegationSyncSetupWith(ctx, conf, q, ds, transient)
	if done == nil {
		t.Error("a transient bootstrap outcome scheduled no retry; the zone waits for a reload")
	}
	// Scheduled, and also stoppable: the retry is asleep in its backoff, and a
	// shutdown has to wake it rather than wait the backoff out.
	defer awaitExit(t, cancel, done)

	last := ds
	last.Attempt = delegationSyncMaxRetries - 1
	if handleDelegationSyncSetupWith(ctx, conf, q, last, transient) != nil {
		t.Error("still retrying past the limit; a parent that never answers finally would be" +
			" asked for the life of the process")
	}
}

// The wiring. DelegationSyncSetup tail-calls finishDelegationSyncSetup with the
// ceremony's result; this goes through it with the real SendUpdate result, so
// deleting the call to bootstrapOutcome -- which is the whole fix -- fails here.
// Before, the tests above called bootstrapOutcome directly and stayed green
// with the fix disconnected.
func TestSetupReportsTheParentsAnswerRatherThanCompletion(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.parent.example."}

	send := func(rcode int, ede uint16) (UpdateResult, error) {
		var addr string
		if ede != 0 {
			addr = startRcodeEDEResponder(t, rcode, ede)
		} else {
			addr = startRcodeResponder(t, rcode)
		}
		_, ur, err := SendUpdate(context.Background(), testUpdateMsg(t), zd.ZoneName, []string{addr})
		return ur, err
	}

	ur, err := send(dns.RcodeServerFailure, 0)
	if got := zd.finishDelegationSyncSetup("", ur, err); !errors.Is(got, errBootstrapTransient) {
		t.Errorf("SERVFAIL: setup returned %v, want errBootstrapTransient; it used to return nil"+
			" and log \"bootstrap complete\"", got)
	}

	ur, err = send(dns.RcodeRefused, edns0.EDESig0KeyValidationFailed)
	if got := zd.finishDelegationSyncSetup("", ur, err); got == nil || errors.Is(got, errBootstrapTransient) {
		t.Errorf("a failed validation: setup returned %v, want a final error", got)
	}

	ur, err = send(dns.RcodeSuccess, 0)
	if got := zd.finishDelegationSyncSetup("", ur, err); got != nil {
		t.Errorf("NOERROR: setup returned %v, want nil", got)
	}
}
