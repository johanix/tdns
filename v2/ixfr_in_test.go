/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Inbound IXFR: the difference-sequence parser (§4.3 of
 * docs/2026-07-25-inbound-ixfr-plan.md).
 *
 * Every malformed case here has to come out as an error rather than as a
 * partly-parsed stream, because the caller's response to an error is a full
 * AXFR -- wasteful and correct -- while its response to a wrong answer is to
 * apply it.
 */
package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

func ixSOA(t *testing.T, serial uint32) dns.RR {
	t.Helper()
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns.example.",
		Mbox:    "hostmaster.example.",
		Serial:  serial,
		Refresh: 7200, Retry: 1800, Expire: 604800, Minttl: 7200,
	}
}

func ixA(t *testing.T, name, addr string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(name + "\t3600\tIN\tA\t" + addr)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	return rr
}

func TestParseIxfrDeltas(t *testing.T) {
	for _, tc := range []struct {
		what         string
		rrs          func(t *testing.T) []dns.RR
		clientSerial uint32
		wantSteps    int
		wantErr      bool
	}{
		{
			what:         "single difference sequence",
			clientSerial: 7,
			wantSteps:    1,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "old.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "new.example.", "10.0.0.2"),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "multi-step, contiguous",
			clientSerial: 7,
			wantSteps:    2,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 9),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"),
					ixSOA(t, 9),
				}
			},
		},
		{
			// A primary is allowed to condense several changes into one
			// sequence spanning the whole range. Nothing special is needed:
			// it is a single step whose from/to are the endpoints.
			what:         "condensed into a single sequence",
			clientSerial: 5,
			wantSteps:    1,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 9),
					ixSOA(t, 5), ixA(t, "a.example.", "10.0.0.1"), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"),
					ixSOA(t, 9),
				}
			},
		},
		{
			what:         "empty add section is legal",
			clientSerial: 7,
			wantSteps:    1,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "gone.example.", "10.0.0.1"),
					ixSOA(t, 8),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "bookend serials disagree",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9),
				}
			},
		},
		{
			what:         "does not start where we are",
			clientSerial: 6,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "non-contiguous sequences",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 10),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"), // gap: 8 -> 9
					ixSOA(t, 10), ixA(t, "d.example.", "10.0.0.4"),
					ixSOA(t, 10),
				}
			},
		},
		{
			what:         "sequences do not reach the bookend serial",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 9),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 9),
				}
			},
		},
		{
			what:         "delete section not followed by an add section",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "missing trailing bookend",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
				}
			},
		},
		{
			what:         "adds an out-of-bailiwick name",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
					ixSOA(t, 8), ixA(t, "elsewhere.test.", "10.0.0.2"),
					ixSOA(t, 8),
				}
			},
		},
		{
			// The AXFR-shaped reply. IsIxfr routes this away before the
			// parser sees it; if it ever does see one, it must refuse rather
			// than invent sections.
			what:         "full-zone reply (SOA, then non-SOA)",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{
					ixSOA(t, 8),
					ixA(t, "a.example.", "10.0.0.1"),
					ixA(t, "b.example.", "10.0.0.2"),
					ixSOA(t, 8),
				}
			},
		},
		{
			what:         "too short to be a difference stream",
			clientSerial: 7,
			wantErr:      true,
			rrs: func(t *testing.T) []dns.RR {
				return []dns.RR{ixSOA(t, 8), ixSOA(t, 8)}
			},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			steps, err := parseIxfrDeltas("example.", tc.rrs(t), tc.clientSerial)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %d steps", len(steps))
				}
				if steps != nil {
					t.Errorf("returned %d steps alongside an error; the caller must get nothing to apply", len(steps))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(steps) != tc.wantSteps {
				t.Fatalf("%d steps, want %d", len(steps), tc.wantSteps)
			}
			// Boundary SOAs are delimiters: nothing in a section is an SOA.
			for _, st := range steps {
				for _, rr := range append(append([]dns.RR{}, st.removed...), st.added...) {
					if _, isSOA := rr.(*dns.SOA); isSOA {
						t.Errorf("step %d→%d carries an SOA inside a section; boundary SOAs are delimiters",
							st.from, st.to)
					}
				}
			}
		})
	}
}

// TestParseIxfrDeltasChainsToTheBookend pins the contiguity guarantee the apply
// depends on: steps run from the serial we hold to the serial the primary says
// it has, with no gaps.
func TestParseIxfrDeltasChainsToTheBookend(t *testing.T) {
	rrs := []dns.RR{
		ixSOA(t, 10),
		ixSOA(t, 7), ixA(t, "a.example.", "10.0.0.1"),
		ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
		ixSOA(t, 8), ixA(t, "b.example.", "10.0.0.2"),
		ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"),
		ixSOA(t, 9), ixA(t, "c.example.", "10.0.0.3"),
		ixSOA(t, 10), ixA(t, "d.example.", "10.0.0.4"),
		ixSOA(t, 10),
	}
	steps, err := parseIxfrDeltas("example.", rrs, 7)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := ixfrTargetSerial(steps); got != 10 {
		t.Errorf("target serial %d, want 10", got)
	}
	prev := uint32(7)
	for _, st := range steps {
		if st.from != prev {
			t.Errorf("step starts at %d, previous ended at %d", st.from, prev)
		}
		prev = st.to
	}
	if removed, added := countIxfrRRs(steps); removed != 3 || added != 3 {
		t.Errorf("counted %d removed / %d added, want 3 / 3", removed, added)
	}
}
