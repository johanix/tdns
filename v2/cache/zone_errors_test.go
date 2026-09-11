/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A zone server that answers SERVFAIL gets the ordinary failure schedule, not
// the lame-delegation backoff. The case that found it: a secondary that has the
// zone configured but has not loaded it yet answers SERVFAIL for a few seconds,
// and booking that as lame shut every server of the zone out for an hour.
// REFUSED and NOTAUTH are still lameness.
func TestZoneRcodeBackoff_ServfailIsNotLame(t *testing.T) {
	prev := GetBackoffPolicy()
	t.Cleanup(func() { SetBackoffPolicy(prev) })
	SetBackoffPolicy(BackoffPolicy{
		FirstFailure:   15 * time.Second,
		MaxFailure:     time.Hour,
		Multiplier:     3.0,
		JitterFraction: 0,
		RoutingFailure: time.Hour,
		LameDelegation: 5 * time.Minute,
	})

	for _, tc := range []struct {
		name  string
		rcode int
		want  time.Duration
	}{
		{"SERVFAIL takes the first-failure backoff", dns.RcodeServerFailure, 15 * time.Second},
		{"REFUSED is a lame delegation", dns.RcodeRefused, 5 * time.Minute},
		{"NOTAUTH is a lame delegation", dns.RcodeNotAuth, 5 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := &Zone{ZoneName: "example."}
			const addr = "192.0.2.1:53"
			before := time.Now()
			z.RecordZoneAddressFailureForRcode(addr, core.TransportDo53, uint8(tc.rcode), false)
			b := z.AddressBackoffs[AddrXport{Addr: addr, Transport: core.TransportDo53}]
			if b == nil {
				t.Fatal("no backoff recorded")
			}
			got := b.NextTry.Sub(before)
			if got < tc.want-time.Second || got > tc.want+time.Second {
				t.Errorf("backoff = %v, want %v", got.Round(time.Second), tc.want)
			}
		})
	}
}
