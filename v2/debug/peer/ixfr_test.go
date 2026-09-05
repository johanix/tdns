/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The parser is the inverse of the upstream's emitter, so round-tripping
// through both is the test that matters: it proves the rig can read its own
// wire format before it judges anybody else's.
func TestParseTransferRoundTripsTheEmittedIXFR(t *testing.T) {
	u := startUpstream(t, 8)
	var changes []Change
	for i := 0; i < 3; i++ {
		c := Change{
			Label: "add-" + strconv.Itoa(i),
			Add:   []dns.RR{mustRR(t, "r"+strconv.Itoa(i)+".relay.test. 3600 IN A 10.0.6."+strconv.Itoa(i))},
		}
		if _, err := u.Apply(c); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
		changes = append(changes, c)
	}

	rrs := transferIn(t, u.Addr(), ixfrMsg("relay.test.", 1))
	res, err := ParseTransfer("relay.test.", rrs, true)
	if err != nil {
		t.Fatalf("ParseTransfer: %v", err)
	}
	if res.Kind != KindIXFR || res.Serial != 4 {
		t.Fatalf("Kind=%s Serial=%d, want ixfr/4", res.Kind, res.Serial)
	}
	if len(res.Deltas) != 3 {
		t.Fatalf("parsed %d deltas, want 3", len(res.Deltas))
	}
	for i, d := range res.Deltas {
		if d.From != uint32(i+1) || d.To != uint32(i+2) {
			t.Fatalf("delta %d framed %d->%d, want %d->%d", i, d.From, d.To, i+1, i+2)
		}
		if len(d.Added) != 1 || len(d.Removed) != 0 {
			t.Fatalf("delta %d = +%d/-%d, want +1/-0", i, len(d.Added), len(d.Removed))
		}
	}

	// And the net of all three is the sum of the three authored changes.
	all := Change{Label: "all"}
	for _, c := range changes {
		all.Add = append(all.Add, c.Add...)
	}
	if d := CompareDelta(all, res.Deltas); !d.Equal() {
		t.Fatalf("round-tripped deltas do not express the authored changes:\n%s", d)
	}
}

func TestParseTransferClassifiesEachAnswerShape(t *testing.T) {
	u := startUpstream(t, 2)

	t.Run("uptodate", func(t *testing.T) {
		rrs := transferIn(t, u.Addr(), ixfrMsg("relay.test.", 1))
		res, err := ParseTransfer("relay.test.", rrs, true)
		if err != nil {
			t.Fatalf("ParseTransfer: %v", err)
		}
		if res.Kind != KindUpToDate {
			t.Fatalf("Kind = %s, want uptodate", res.Kind)
		}
	})

	t.Run("axfr", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetAxfr("relay.test.")
		res, err := ParseTransfer("relay.test.", transferIn(t, u.Addr(), m), false)
		if err != nil {
			t.Fatalf("ParseTransfer: %v", err)
		}
		if res.Kind != KindAXFR {
			t.Fatalf("Kind = %s, want axfr", res.Kind)
		}
		if res.Zone == nil || res.Zone.Serial() != 1 {
			t.Fatalf("Zone = %v", res.Zone)
		}
	})

	// The same bytes as above, but asked for incrementally. Classifying these
	// identically would make a broken delta path indistinguishable from a
	// working one.
	t.Run("fallback", func(t *testing.T) {
		for i := 0; i < 4; i++ {
			if _, err := u.Apply(Change{
				Label: "add",
				Add:   []dns.RR{mustRR(t, "f"+strconv.Itoa(i)+".relay.test. 3600 IN A 10.0.7."+strconv.Itoa(i))},
			}); err != nil {
				t.Fatalf("Apply %d: %v", i, err)
			}
		}
		res, err := ParseTransfer("relay.test.", transferIn(t, u.Addr(), ixfrMsg("relay.test.", 1)), true)
		if err != nil {
			t.Fatalf("ParseTransfer: %v", err)
		}
		if res.Kind != KindFallback {
			t.Fatalf("Kind = %s, want fallback", res.Kind)
		}
	})
}

func TestParseTransferRejectsMalformedStreams(t *testing.T) {
	a := mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1")
	soa1 := mustRR(t, "relay.test. 3600 IN SOA ns.relay.test. hostmaster.relay.test. 1 7200 1800 604800 3600")
	soa2 := mustRR(t, "relay.test. 3600 IN SOA ns.relay.test. hostmaster.relay.test. 2 7200 1800 604800 3600")

	tests := []struct {
		name string
		rrs  []dns.RR
		want string
	}{
		{"empty", nil, "carried no records"},
		{"no opening SOA", []dns.RR{a, soa1}, "does not open with an SOA"},
		{"no closing SOA", []dns.RR{soa2, soa1, a, soa2, a}, "does not close with an SOA"},
		{"mismatched framing", []dns.RR{soa2, soa1, a, soa2, a, soa1}, "mismatched serials"},
		{"sequence with no closing SOA", []dns.RR{soa2, soa1, a, soa2}, "no closing SOA"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTransfer("relay.test.", tc.rrs, true)
			if err == nil {
				t.Fatal("parser accepted a malformed stream")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the defect (want %q)", err, tc.want)
			}
		})
	}
}
