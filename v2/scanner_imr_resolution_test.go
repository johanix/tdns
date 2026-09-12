package tdns

import (
	"testing"
)

// #503: the scanner latched conf.Internal.ImrEngine into a field of its own,
// and did so only inside the SCAN arm of the engine loop -- which is reached
// only on receipt of a generalized NOTIFY. Every other entry point therefore
// depended on an unrelated NOTIFY having arrived first. On a freshly started
// parent the UPDATE-scheme coherence check refused every child update as
// incoherent, reporting an IMR that was initialized and usable all along.
//
// So the property is: a scanner that has processed NO commands resolves the
// IMR as soon as one is published.
func TestScannerResolvesTheImrWithoutHavingRunAScan(t *testing.T) {
	prevGlobal := Globals.ImrEngine
	t.Cleanup(func() { Globals.ImrEngine = prevGlobal })

	conf := &Config{}
	conf.Internal.ImrReady = NewImrReadiness()
	sc := NewScanner(nil, false, false)
	sc.conf = conf

	if got := sc.imr(); got != nil {
		t.Errorf("resolved an IMR before one was published: %p", got)
	}

	// The production announce: stores the pointer, then publishes it.
	want := newTestImr(t)
	conf.publishImr(want)

	// No SCAN, no NOTIFY, no engine loop -- exactly the state a parent is in
	// when the first child UPDATE arrives.
	if got := sc.imr(); got != want {
		t.Fatal("the scanner still reports no IMR after one was published;" +
			" the UPDATE-scheme coherence check refuses every child update in this state," +
			" and only an unrelated NOTIFY would have fixed it")
	}
}

// A nil return has to keep meaning "genuinely not usable", or the guards that
// depend on it start lying again -- which is what made #503 so hard to read:
// the error said the IMR was not initialized while it was.
func TestScannerReportsNoImrOnlyWhenThereIsNone(t *testing.T) {
	for _, tc := range []struct {
		name string
		sc   func(t *testing.T) *Scanner
	}{
		{"a nil scanner", func(*testing.T) *Scanner { return nil }},
		{"a scanner with no conf", func(*testing.T) *Scanner { return NewScanner(nil, false, false) }},
		{"a conf whose IMR was never published", func(*testing.T) *Scanner {
			conf := &Config{}
			conf.Internal.ImrReady = NewImrReadiness()
			sc := NewScanner(nil, false, false)
			sc.conf = conf
			return sc
		}},
		{"a conf with an IMR stored but not announced", func(t *testing.T) *Scanner {
			// publishImr stores and THEN announces, so this half-state is not
			// reachable through it. Built by hand: a reader that ignored the
			// readiness signal would accept this, and the memory model does not
			// promise it a fully constructed value.
			conf := &Config{}
			conf.Internal.ImrReady = NewImrReadiness()
			conf.Internal.ImrEngine = newTestImr(t)
			sc := NewScanner(nil, false, false)
			sc.conf = conf
			return sc
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sc(t).imr(); got != nil {
				t.Errorf("resolved %p, want nil", got)
			}
		})
	}
}
