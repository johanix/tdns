package debug

import (
	"testing"
	"time"
)

func rec(owner string) ChurnRecord { return ChurnRecord{Owner: owner, Rdata: "payload-" + owner} }

func has(rep *Report, invariant string) bool {
	for _, v := range rep.Violations {
		if v.Invariant == invariant {
			return true
		}
	}
	return false
}

// A correct server never trips a checker. This is the false-positive guard:
// if this test ever goes red, the tool's verdicts cannot be trusted.
func TestCleanStreamNoViolations(t *testing.T) {
	l := NewLedger()
	rep := NewReport("test", "churn")
	c := NewChecker(l, rep, 2*time.Second)

	t0 := time.Unix(1_700_000_000, 0)
	serial := uint32(100)

	// Simulate: accept a batch of adds, publish (new serial, content = full
	// accepted set), interleave a query that agrees, repeat with a delete.
	fullAt := func(recs []ChurnRecord, at time.Time) {
		serial++
		c.Observe(Observation{Stream: "axfr", At: at, Serial: serial, Full: true,
			Churn: recs, HasSOA: true, OpenSOA: serial, CloseSOA: serial})
	}

	a, b, d := rec("1._churn.z."), rec("2._churn.z."), rec("3._churn.z.")
	l.RecordAccepted(OpAdd, a, t0)
	l.RecordAccepted(OpAdd, b, t0.Add(1*time.Second))
	fullAt([]ChurnRecord{a, b}, t0.Add(5*time.Second))
	// query agreeing with the same serial
	c.Observe(Observation{Stream: "query", At: t0.Add(6 * time.Second), Serial: serial,
		Name: a.Owner, Present: true, Rec: a})

	l.RecordAccepted(OpAdd, d, t0.Add(21*time.Second))
	l.RecordAccepted(OpDel, a, t0.Add(22*time.Second))
	fullAt([]ChurnRecord{b, d}, t0.Add(25*time.Second))
	c.Observe(Observation{Stream: "query", At: t0.Add(26 * time.Second), Serial: serial,
		Name: a.Owner, Present: false})

	c.Finalize([]ChurnRecord{b, d}, serial)

	if len(rep.Violations) != 0 {
		t.Fatalf("clean stream produced %d violation(s): %+v", len(rep.Violations), rep.Violations)
	}
}

// I9: content that mixes a pre-delete record with a post-later-add record is
// no prefix state — the shared-pointer tearing signature this project fixes.
func TestI9DetectsTornContent(t *testing.T) {
	l := NewLedger()
	rep := NewReport("test", "churn")
	c := NewChecker(l, rep, 2*time.Second)

	a, b, d := rec("1._churn.z."), rec("2._churn.z."), rec("3._churn.z.")
	t0 := time.Unix(1_700_000_000, 0)
	l.RecordAccepted(OpAdd, a, t0)              // prefix {a}
	l.RecordAccepted(OpAdd, b, t0.Add(1))       // prefix {a,b}
	l.RecordAccepted(OpDel, a, t0.Add(2))       // prefix {b}
	l.RecordAccepted(OpAdd, d, t0.Add(3))       // prefix {b,d}

	// Torn: {a, b, d} — 'a' was deleted before 'd' was added; no prefix holds
	// all three. A correct server can never serve this set.
	c.Observe(Observation{Stream: "axfr", At: t0.Add(10 * time.Second), Serial: 5, Full: true,
		Churn: []ChurnRecord{a, b, d}, HasSOA: true, OpenSOA: 5, CloseSOA: 5})
	if !has(rep, "I9") {
		t.Fatalf("expected I9 violation for torn content; got %+v", rep.Violations)
	}

	// And the valid prefix {b,d} at another serial must NOT fire.
	rep2 := NewReport("test", "churn")
	c2 := NewChecker(l, rep2, 2*time.Second)
	c2.Observe(Observation{Stream: "axfr", At: t0.Add(11 * time.Second), Serial: 6, Full: true,
		Churn: []ChurnRecord{b, d}, HasSOA: true, OpenSOA: 6, CloseSOA: 6})
	if has(rep2, "I9") {
		t.Fatalf("valid prefix {b,d} wrongly flagged: %+v", rep2.Violations)
	}
}

// I6: the same serial serving two different contents (the direct C1 detector).
func TestI6DetectsSameSerialDifferentContent(t *testing.T) {
	l := NewLedger()
	rep := NewReport("test", "churn")
	c := NewChecker(l, rep, 2*time.Second)

	a, b := rec("1._churn.z."), rec("2._churn.z.")
	t0 := time.Unix(1_700_000_000, 0)
	l.RecordAccepted(OpAdd, a, t0)
	l.RecordAccepted(OpAdd, b, t0.Add(1))

	c.Observe(Observation{Stream: "axfr", At: t0.Add(5 * time.Second), Serial: 42, Full: true,
		Churn: []ChurnRecord{a}, HasSOA: true, OpenSOA: 42, CloseSOA: 42})
	c.Observe(Observation{Stream: "axfr", At: t0.Add(6 * time.Second), Serial: 42, Full: true,
		Churn: []ChurnRecord{a, b}, HasSOA: true, OpenSOA: 42, CloseSOA: 42})
	if !has(rep, "I6") {
		t.Fatalf("expected I6 for same-serial content divergence; got %+v", rep.Violations)
	}
}

// I6 cross-stream: query says present, AXFR at the same serial says absent.
func TestI6DetectsCrossStreamDivergence(t *testing.T) {
	l := NewLedger()
	rep := NewReport("test", "churn")
	c := NewChecker(l, rep, 2*time.Second)
	a := rec("1._churn.z.")
	t0 := time.Unix(1_700_000_000, 0)
	l.RecordAccepted(OpAdd, a, t0)

	c.Observe(Observation{Stream: "query", At: t0.Add(5 * time.Second), Serial: 7,
		Name: a.Owner, Present: true, Rec: a})
	c.Observe(Observation{Stream: "axfr", At: t0.Add(6 * time.Second), Serial: 7, Full: true,
		Churn: nil, HasSOA: true, OpenSOA: 7, CloseSOA: 7})
	if !has(rep, "I6") {
		t.Fatalf("expected cross-stream I6; got %+v", rep.Violations)
	}
}

// I5: a serial that goes backwards (RFC 1982 wrap-safe).
func TestI5DetectsSerialRegression(t *testing.T) {
	l := NewLedger()
	rep := NewReport("test", "churn")
	c := NewChecker(l, rep, 2*time.Second)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(Observation{Stream: "axfr", At: t0, Serial: 100, Full: true, HasSOA: true, OpenSOA: 100, CloseSOA: 100})
	c.Observe(Observation{Stream: "axfr", At: t0.Add(time.Second), Serial: 99, Full: true, HasSOA: true, OpenSOA: 99, CloseSOA: 99})
	if !has(rep, "I5") {
		t.Fatalf("expected I5 for serial regression; got %+v", rep.Violations)
	}
	// wrap-around: 4294967295 -> 1 is an INCREASE, must not fire.
	rep2 := NewReport("test", "churn")
	c2 := NewChecker(l, rep2, 2*time.Second)
	c2.Observe(Observation{Stream: "axfr", At: t0, Serial: 4294967295, Full: true, HasSOA: true, OpenSOA: 4294967295, CloseSOA: 4294967295})
	c2.Observe(Observation{Stream: "axfr", At: t0.Add(time.Second), Serial: 1, Full: true, HasSOA: true, OpenSOA: 1, CloseSOA: 1})
	if has(rep2, "I5") {
		t.Fatalf("serial wrap wrongly flagged as regression: %+v", rep2.Violations)
	}
}

// I7: an AXFR whose opening and closing SOA differ (torn transfer).
func TestI7DetectsTornAXFR(t *testing.T) {
	l := NewLedger()
	rep := NewReport("test", "churn")
	c := NewChecker(l, rep, 2*time.Second)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(Observation{Stream: "axfr", At: t0, Serial: 10, Full: true,
		HasSOA: true, OpenSOA: 10, CloseSOA: 11})
	if !has(rep, "I7") {
		t.Fatalf("expected I7 for open!=close SOA; got %+v", rep.Violations)
	}
}

// I2: a record served before its add was accepted (beyond δ).
func TestI2DetectsPrematureVisibility(t *testing.T) {
	l := NewLedger()
	rep := NewReport("test", "churn")
	c := NewChecker(l, rep, 2*time.Second)
	a := rec("1._churn.z.")
	tAccept := time.Unix(1_700_000_100, 0)
	l.RecordAccepted(OpAdd, a, tAccept)

	// observed 10s BEFORE acceptance → premature
	c.Observe(Observation{Stream: "axfr", At: tAccept.Add(-10 * time.Second), Serial: 5, Full: true,
		Churn: []ChurnRecord{a}, HasSOA: true, OpenSOA: 5, CloseSOA: 5})
	if !has(rep, "I2") {
		t.Fatalf("expected I2 for premature visibility; got %+v", rep.Violations)
	}

	// within δ (1s before) → tolerated
	rep2 := NewReport("test", "churn")
	c2 := NewChecker(l, rep2, 2*time.Second)
	c2.Observe(Observation{Stream: "axfr", At: tAccept.Add(-1 * time.Second), Serial: 6, Full: true,
		Churn: []ChurnRecord{a}, HasSOA: true, OpenSOA: 6, CloseSOA: 6})
	if has(rep2, "I2") {
		t.Fatalf("within-δ visibility wrongly flagged: %+v", rep2.Violations)
	}
}

// I3: end-of-run reconciliation catches permanently lost updates.
func TestI3DetectsLostUpdates(t *testing.T) {
	l := NewLedger()
	rep := NewReport("test", "churn")
	c := NewChecker(l, rep, 2*time.Second)
	t0 := time.Unix(1_700_000_000, 0)
	a, b, d := rec("1._churn.z."), rec("2._churn.z."), rec("3._churn.z.")
	l.RecordAccepted(OpAdd, a, t0)
	l.RecordAccepted(OpAdd, b, t0.Add(1))
	l.RecordAccepted(OpAdd, d, t0.Add(2))

	// settled content is only {a,b} — op3 (add d) was lost.
	c.Finalize([]ChurnRecord{a, b}, 50)
	if !has(rep, "I3") {
		t.Fatalf("expected I3 for lost update; got %+v", rep.Violations)
	}

	// settled content == all accepted → no violation.
	rep2 := NewReport("test", "churn")
	c2 := NewChecker(l, rep2, 2*time.Second)
	c2.Finalize([]ChurnRecord{a, b, d}, 51)
	if has(rep2, "I3") {
		t.Fatalf("complete settled content wrongly flagged: %+v", rep2.Violations)
	}
}

func TestLedgerPrefixStates(t *testing.T) {
	l := NewLedger()
	t0 := time.Unix(1_700_000_000, 0)
	a, b := rec("1._churn.z."), rec("2._churn.z.")
	l.RecordAccepted(OpAdd, a, t0)
	l.RecordAccepted(OpAdd, b, t0.Add(1))
	l.RecordAccepted(OpDel, a, t0.Add(2))

	// {b} is prefix 3; {a,b} is prefix 2; {a} is prefix 1; {} is prefix 0.
	if idx, ok := l.MatchesPrefixState([]ChurnRecord{b}); !ok || idx != 3 {
		t.Errorf("prefix {b}: idx=%d ok=%v want 3,true", idx, ok)
	}
	if idx, ok := l.MatchesPrefixState([]ChurnRecord{a, b}); !ok || idx != 2 {
		t.Errorf("prefix {a,b}: idx=%d ok=%v want 2,true", idx, ok)
	}
	if _, ok := l.MatchesPrefixState([]ChurnRecord{a, b, rec("9._churn.z.")}); ok {
		t.Errorf("fabricated set should not match any prefix")
	}
	if l.AcceptedCount() != 3 {
		t.Errorf("AcceptedCount=%d want 3", l.AcceptedCount())
	}
}
