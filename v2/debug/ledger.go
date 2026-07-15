/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// The ledger is the oracle (design doc §7). The churn actor mutates a zone
// with a stream of adds/deletes of UNIQUELY-NAMED TXT records; the ledger
// records every accepted op in acceptance order and, from that, derives the
// exact set of possible correct served states.
//
// The load-bearing idea: because the server applies accepted updates to its
// working set in order and publishes an ATOMIC snapshot of that working set,
// every correctly-served content must equal the working set after some
// PREFIX of the accepted op log ("a prefix state"). So:
//
//   - content that matches no prefix state is torn / mixed          → I9
//   - two observations at the same serial with different content    → I6
//   - a prefix that regresses as the serial advances                → I5
//
// The tearing bug this project fixes (a query/transfer reading a half-mutated
// published zone) manifests precisely as content matching no prefix state, or
// as two same-serial observations disagreeing.

// ChurnRecord is one uniquely-named churn TXT record (owner + rdata payload).
type ChurnRecord struct {
	Owner string // "<seq>._churn.<zone>"
	Rdata string // TXT payload (seq + timestamp + seed)
}

func (r ChurnRecord) key() string { return r.Owner + "\x00" + r.Rdata }

type OpKind int

const (
	OpAdd OpKind = iota
	OpDel
)

// LedgerOp is one accepted mutation, in acceptance order (Index is 1-based).
type LedgerOp struct {
	Index      int
	Kind       OpKind
	Rec        ChurnRecord
	AcceptedAt time.Time
}

// Ledger is safe for concurrent use: the update-sender appends while pollers'
// observations are reconciled against it.
type Ledger struct {
	mu  sync.Mutex
	ops []LedgerOp

	// present is the accepted-state churn set (after every op so far). It is
	// what the update-sender deletes from when choosing a delete target — the
	// accepted state, which may run ahead of what the server has published.
	present map[string]ChurnRecord

	// prefixFP[k] is the content fingerprint of the prefix state after op k
	// (prefixFP[0] = empty state). fpIndex maps a fingerprint to the LARGEST
	// prefix index that produces it (a fingerprint can recur, e.g. add-then-
	// delete returns to a prior state); the largest index is used for cut
	// resolution under the monotonicity constraint.
	prefixFP []string
	fpIndex  map[string]int

	// birth/death: op index that added / deleted a record key (death 0 = still
	// present in the accepted state). Used by the boundary reconciliation
	// (I2/I3) to reason about which ops "should" be visible.
	birth map[string]int
	death map[string]int
}

func NewLedger() *Ledger {
	l := &Ledger{
		present: map[string]ChurnRecord{},
		fpIndex: map[string]int{},
		birth:   map[string]int{},
		death:   map[string]int{},
	}
	// Prefix 0 is the empty state (nothing accepted yet).
	empty := fingerprint(nil)
	l.prefixFP = []string{empty}
	l.fpIndex[empty] = 0
	return l
}

// fingerprint is a stable hash of a churn record set (order-independent).
func fingerprint(recs []ChurnRecord) string {
	keys := make([]string, 0, len(recs))
	for _, r := range recs {
		keys = append(keys, r.key())
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fingerprintSet hashes a set given as a map (the accepted present-set).
func fingerprintSet(m map[string]ChurnRecord) string {
	recs := make([]ChurnRecord, 0, len(m))
	for _, r := range m {
		recs = append(recs, r)
	}
	return fingerprint(recs)
}

// RecordAccepted appends an accepted op and advances the derived state. It is
// called only after the server returns NOERROR for the update.
func (l *Ledger) RecordAccepted(kind OpKind, rec ChurnRecord, at time.Time) LedgerOp {
	l.mu.Lock()
	defer l.mu.Unlock()

	idx := len(l.ops) + 1
	op := LedgerOp{Index: idx, Kind: kind, Rec: rec, AcceptedAt: at}
	l.ops = append(l.ops, op)

	k := rec.key()
	switch kind {
	case OpAdd:
		l.present[k] = rec
		l.birth[k] = idx
		delete(l.death, k) // (re-add of a previously-deleted key: reborn)
	case OpDel:
		delete(l.present, k)
		l.death[k] = idx
	}

	fp := fingerprintSet(l.present)
	l.prefixFP = append(l.prefixFP, fp)
	l.fpIndex[fp] = idx // largest index producing this fingerprint

	return op
}

// PickPresent returns a currently-accepted-present record (for the deleter to
// target), or ok=false if the accepted state is empty. Deterministic given
// the same state so a seeded run is reproducible: returns the record with the
// smallest key.
func (l *Ledger) PickPresent() (ChurnRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.present) == 0 {
		return ChurnRecord{}, false
	}
	minKey := ""
	for k := range l.present {
		if minKey == "" || k < minKey {
			minKey = k
		}
	}
	return l.present[minKey], true
}

// AcceptedCount / snapshot helpers -----------------------------------------

func (l *Ledger) AcceptedCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ops)
}

// MatchesPrefixState reports whether the given observed churn set equals some
// prefix state (I9's core question). Returns the largest matching prefix
// index and true, or (0,false) if the content matches no historical state.
func (l *Ledger) MatchesPrefixState(observed []ChurnRecord) (int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fp := fingerprint(observed)
	idx, ok := l.fpIndex[fp]
	return idx, ok
}

// OpsAcceptedBefore returns the highest op index whose acceptance time is at
// or before t. Ops [1..k] were all accepted by then. Used by the boundary
// reconciliation for I3 (everything accepted before a boundary must appear).
func (l *Ledger) OpsAcceptedBefore(t time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := 0
	for _, op := range l.ops {
		if op.AcceptedAt.After(t) {
			break
		}
		k = op.Index
	}
	return k
}

// OpsAcceptedAfter returns the lowest op index whose acceptance time is
// strictly after t (or 0 if none). Ops [that index ..] were accepted after t.
// Used for I2 (an op accepted clearly after a boundary must not be in it).
func (l *Ledger) OpsAcceptedAfter(t time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, op := range l.ops {
		if op.AcceptedAt.After(t) {
			return op.Index
		}
	}
	return 0
}

// birthTime returns the acceptance time of the op that added recKey (zero if
// the key was never added). Used by the I2 premature-visibility check.
func (l *Ledger) birthTime(recKey string) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.birth[recKey]
	if !ok || b < 1 || b > len(l.ops) {
		return time.Time{}
	}
	return l.ops[b-1].AcceptedAt
}

// PresentInPrefix reports whether a record key is present in prefix state k.
// (birth ≤ k < death, with death 0 meaning "never deleted".)
func (l *Ledger) PresentInPrefix(recKey string, k int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.birth[recKey]
	if !ok || b > k {
		return false
	}
	if d, dead := l.death[recKey]; dead && d <= k {
		return false
	}
	return true
}

// String renders a compact op-log tail for violation context.
func (l *Ledger) contextAround(idx int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	lo, hi := idx-3, idx+3
	if lo < 1 {
		lo = 1
	}
	if hi > len(l.ops) {
		hi = len(l.ops)
	}
	s := ""
	for i := lo; i <= hi; i++ {
		op := l.ops[i-1]
		kind := "add"
		if op.Kind == OpDel {
			kind = "del"
		}
		s += fmt.Sprintf("[op%d %s %s@%s] ", op.Index, kind, op.Rec.Owner,
			op.AcceptedAt.Format("15:04:05.000"))
	}
	return s
}
