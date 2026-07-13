/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Checkers consume observation streams and evaluate the invariants (design
// doc §8). M2 implements the DNS-only, capability-independent gate:
// I2/I3/I5/I6/I7/I9. The txlog-dependent I1/I4 and the cadence-timing I8 are
// M3.
//
// Design principle: the tool's verdicts must be trustworthy, so every checker
// here is engineered to be FALSE-POSITIVE-FREE against a correct server. The
// tolerance δ absorbs the two unavoidable orderings we cannot control:
//   1. the server may commit an update to its working set (and start serving
//      it) slightly before we finish processing the NOERROR that accepts it;
//   2. we observe a publish (serial change) on our poll cadence, not at the
//      instant it happens.
// Anything within δ of those edges is left unasserted; everything outside is
// asserted. This is the §8 "δ-tolerance" rule, pinned by the synthetic-stream
// tests.

// Observation is one thing a poller saw. Full=true carries the complete churn
// set (an AXFR); Full=false carries a single name's presence (a query).
type Observation struct {
	Stream  string // "axfr" | "query"
	At      time.Time
	Serial  uint32
	Full    bool
	Churn   []ChurnRecord // Full: the complete churn set
	Name    string        // !Full: the queried owner
	Present bool          // !Full: whether Name had any churn TXT
	Rec     ChurnRecord   // !Full: the specific record, when Present
	// AXFR framing (Full only): opening and closing SOA serials.
	OpenSOA  uint32
	CloseSOA uint32
	HasSOA   bool
}

type Checker struct {
	mu     sync.Mutex
	ledger *Ledger
	report *Report
	delta  time.Duration

	maxSerial   uint32
	haveSerial  bool
	serialFP    map[uint32]string    // I6: serial → full-content fingerprint (from AXFR)
	firstSeen   map[uint32]time.Time // when each serial was first observed
	lastFullCut int                  // I3: content cut must not regress
}

func NewChecker(ledger *Ledger, report *Report, delta time.Duration) *Checker {
	return &Checker{
		ledger:      ledger,
		report:      report,
		delta:       delta,
		serialFP:    map[uint32]string{},
		firstSeen:   map[uint32]time.Time{},
	}
}

// serialLT reports a < b in RFC 1982 serial-number arithmetic (wrap-safe).
func serialLT(a, b uint32) bool {
	if a == b {
		return false
	}
	return (a < b && b-a < 1<<31) || (a > b && a-b > 1<<31)
}

// Observe feeds one observation through every applicable invariant.
func (c *Checker) Observe(o Observation) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.checkSerialMonotonic(o) // I5
	if _, ok := c.firstSeen[o.Serial]; !ok {
		c.firstSeen[o.Serial] = o.At
	}

	if o.Full {
		c.observeFull(o)
	} else {
		c.observeName(o)
	}
}

// I5 — served serial never regresses (per stream and globally).
func (c *Checker) checkSerialMonotonic(o Observation) {
	// Only the single, ordered AXFR poller gives a reliable serial timeline.
	// Concurrent query workers can have their Observe() calls processed out of
	// order relative to the server's actual responses, so their serials must not
	// drive the monotonicity check — that produced false I5s. A real serial
	// regression still shows up on the AXFR stream.
	if !o.Full {
		return
	}
	if c.haveSerial && serialLT(o.Serial, c.maxSerial) {
		c.report.Violate("I5",
			fmt.Sprintf("serial regressed: observed %d after %d", o.Serial, c.maxSerial),
			fmt.Sprintf("stream=%s at=%s", o.Stream, o.At.Format(time.RFC3339Nano)))
		return
	}
	if !c.haveSerial || serialLT(c.maxSerial, o.Serial) {
		c.maxSerial = o.Serial
		c.haveSerial = true
	}
}

func (c *Checker) observeFull(o Observation) {
	// I7 — AXFR self-consistency: opening SOA == closing SOA.
	if o.HasSOA && o.OpenSOA != o.CloseSOA {
		c.report.Violate("I7",
			fmt.Sprintf("AXFR framing torn: opened at SOA %d, closed at %d", o.OpenSOA, o.CloseSOA),
			fmt.Sprintf("stream=%s at=%s", o.Stream, o.At.Format(time.RFC3339Nano)))
	}

	// I2 — no premature visibility: a churn record present in served content
	// whose add was accepted more than δ AFTER this observation cannot be
	// legitimate (we served data we had not yet added).
	c.checkPremature(o.Churn, o.At)

	// I9 — content is some real prefix state.
	cut, ok := c.ledger.MatchesPrefixState(o.Churn)
	if !ok {
		c.report.Violate("I9",
			"served content matches no consistent prefix state (torn/mixed content)",
			c.tornContext(o))
		return
	}

	// I3 (online half) — the content cut must not regress as serials advance.
	// (The full "no permanently lost update" check is the end-of-run
	// reconciliation in Finalize.)
	if cut < c.lastFullCut {
		c.report.Violate("I3",
			fmt.Sprintf("content regressed: prefix cut %d after %d at serial %d", cut, c.lastFullCut, o.Serial),
			fmt.Sprintf("stream=%s at=%s %s", o.Stream, o.At.Format(time.RFC3339Nano), c.ledger.contextAround(cut)))
	} else {
		c.lastFullCut = cut
	}

	// I6 — same serial ⇒ same content. Store/compare the fingerprint and
	// cross-check any per-name facts already seen for this serial.
	fp := fingerprint(o.Churn)
	if prev, seen := c.serialFP[o.Serial]; seen {
		if prev != fp {
			c.report.Violate("I6",
				fmt.Sprintf("serial %d served two different contents (tearing/rollback)", o.Serial),
				c.tornContext(o))
		}
	} else {
		c.serialFP[o.Serial] = fp
	}
}

func (c *Checker) observeName(o Observation) {
	// The query stream's (serial, name-presence) pair is NOT atomic — the SOA
	// (serial) and the TXT (name) come from separate queries, so a publish
	// between them pins the wrong serial to the presence fact. It therefore
	// cannot drive serial-pinned checks (I6) without false positives. The query
	// stream's role is (1) concurrent read load that induces tearing the AXFR
	// poller catches, and (2) I2 premature-visibility, which needs only the
	// observation time, not the serial. (A serial-reliable query cross-check
	// would need an SOA-sandwich, SOA/TXT/SOA with a stable serial — a later
	// enhancement.)
	if o.Present {
		c.checkPremature([]ChurnRecord{o.Rec}, o.At)
	}
}

// checkPremature implements I2: any present record whose add was accepted more
// than δ after this observation is impossible on a correct server.
func (c *Checker) checkPremature(recs []ChurnRecord, at time.Time) {
	for _, r := range recs {
		if b := c.ledger.birthTime(r.key()); !b.IsZero() && at.Add(c.delta).Before(b) {
			c.report.Violate("I2",
				fmt.Sprintf("record %s served before it was accepted (premature visibility)", r.Owner),
				fmt.Sprintf("observed=%s accepted=%s δ=%s", at.Format(time.RFC3339Nano), b.Format(time.RFC3339Nano), c.delta))
		}
	}
}

func (c *Checker) tornContext(o Observation) string {
	owners := make([]string, 0, len(o.Churn))
	for _, r := range o.Churn {
		owners = append(owners, r.Owner)
	}
	sort.Strings(owners)
	return fmt.Sprintf("serial=%d stream=%s at=%s content={%v} accepted-ops=%d",
		o.Serial, o.Stream, o.At.Format(time.RFC3339Nano), owners, c.ledger.AcceptedCount())
}

// Finalize runs the end-of-run reconciliation (I3): after the actors have
// stopped and the zone has settled past one publish cadence, a final full
// observation must equal the entire accepted op log (nothing permanently
// lost). settled is that final AXFR content.
func (c *Checker) Finalize(settled []ChurnRecord, settledSerial uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cut, ok := c.ledger.MatchesPrefixState(settled)
	if !ok {
		c.report.Violate("I3",
			"final settled content matches no prefix state",
			fmt.Sprintf("serial=%d accepted-ops=%d", settledSerial, c.ledger.AcceptedCount()))
		return
	}
	if want := c.ledger.AcceptedCount(); cut != want {
		c.report.Violate("I3",
			fmt.Sprintf("lost updates: final content is prefix %d of %d accepted ops", cut, want),
			fmt.Sprintf("serial=%d %s", settledSerial, c.ledger.contextAround(cut+1)))
	}
}
