package tdns

import (
	"fmt"
	"time"
)

// Zone transactions: a publish hold on one zone, declared by the writer.
//
//	{start tx  <zone> <id> <flags>}
//	   ... changes ...
//	{commit tx <zone> <id>}
//
// See docs/2026-09-17-publish-gate-and-transactions.md. While a zone has an
// open transaction nothing publishes it; what any writer stages in the
// meantime goes out with the commit that closes the hold. A transaction is not
// isolation, and there is no rollback: a writer that fails part way commits
// what it has, or lets the hold run out.
//
// The hold is enforced in publishWorkingSetLocked, where every publish passes.
// SignZone, StageBatch, the catalog and the update appliers all call
// publishLocked directly, so a check in the publisher's loop alone would let
// each of them through.
//
// A zone that opens no transaction is untouched by all of this: every test
// below is one comparison that is false for it.

// TxID names one transaction on one zone. A writer that queues its markers
// chooses the id; BeginTx allocates one.
type TxID string

// TxFlags are the flags of a transaction's start marker.
type TxFlags uint8

const (
	// TxUrgent asks for the commit that closes the hold to publish at once
	// instead of through the gate. It is sticky for the hold: if any
	// transaction of the hold carried it, the closing commit is urgent. No
	// automated path sets it without a stated reason, or wrapping every change
	// in a transaction brings per-record publishing back.
	TxUrgent TxFlags = 1 << iota
)

// The UpdateRequest commands of the two markers.
const (
	UpdateCmdTxBegin  = "TX-BEGIN"
	UpdateCmdTxCommit = "TX-COMMIT"
)

// txHoldLimit is how long a transaction may stay open before its commit is
// taken for lost: a full queue, a writer that failed, a bug. A constant as far
// as configuration goes; there is no knob until something needs one. A variable
// only so that a test does not have to wait thirty seconds. Read when a
// transaction begins and kept with it, so the limit's timer never reads it.
var txHoldLimit = 30 * time.Second

// zoneTx is one open transaction.
type zoneTx struct {
	start time.Time
	limit time.Duration
	// overdue: the limit ran out on a zone that has never published. Such a
	// hold is not released; the transaction stays open, reported once.
	overdue bool
}

// zoneTxState is ZoneData.tx. Guarded by zd.mu.
type zoneTxState struct {
	// open is the hold: the zone is held while it is not empty.
	open map[TxID]*zoneTx
	seq  uint64
	// urgent: some transaction of the current hold carried TxUrgent.
	urgent bool
	// publishWanted: the hold stopped a publish. Deliberately NOT
	// publishQueued. runPublisher republishes for as long as publishQueued is
	// set and the cadence has run out, and a publish that a hold stopped would
	// leave both true: a hot loop on zd.mu for the length of the hold, the one
	// clearQueuedPublishAfterRefusalLocked exists to stop. The want lives here,
	// the publisher stands down, and the closing commit delivers.
	publishWanted bool
	// stopped counts the publishes holds have stopped on this zone.
	stopped uint64
	// commitWaiters are the commits waiting to learn that their transaction is
	// published: those that left other transactions open, and the one that
	// closed the hold and had to ask the gate. Answered by the publish that
	// carries them, or by the refusal that does not. The seed of the design's
	// "waiters on the zone"; in this step it holds commits only.
	commitWaiters []chan ZoneUpdateResult
	// timer is the hold's limit, one per zone, armed for the open transaction
	// whose limit runs out first. timerGen tells a callback that was already
	// on its way when the timer was stopped that it is stale.
	timer    *time.Timer
	timerGen uint64

	// createdHeld: the zone's first content is a transaction
	// (CreateAutoZoneHeld). Set once, never cleared. It is what makes the zone
	// not a draft, and what puts its first snapshot under the signed-or-none
	// rule. A flag, and not "has an open hold": a first content that could not
	// be signed leaves the zone with no hold and no snapshot, and the zone is
	// still neither a draft nor free to publish unsigned.
	createdHeld bool
	// createTx is the creation's transaction, which its creator may commit
	// again while firstPending is set.
	createTx TxID
	// firstPending: the hold of a zone created held has closed and the zone
	// still has no snapshot. Its first content could not be signed yet.
	firstPending bool
	// firstErr is why, for the commit's Resp.
	firstErr error
}

func (zd *ZoneData) txHeldLocked() bool {
	return len(zd.tx.open) > 0
}

// txOpenCount reports how many transactions are open on the zone.
func (zd *ZoneData) txOpenCount() int {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return len(zd.tx.open)
}

// txStoppedPublishes reports how many publishes the zone's holds have stopped.
func (zd *ZoneData) txStoppedPublishes() uint64 {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.tx.stopped
}

// BeginTx opens a transaction on the zone, in-process, and returns its id.
//
// For a writer that also stages in-process, StageBatch's kind. It is not a
// shortcut for a writer that queues its changes: that writer queues its
// markers too (TX-BEGIN, TX-COMMIT), or its commit overtakes its changes and
// publishes an empty hold.
//
// Refused, as a queued TX-BEGIN is, on a zone that may not originate content:
// it has nothing of ours to group, and a hold would stop its refresh publishes
// until the hold's limit released them. No transaction is opened then.
func (zd *ZoneData) BeginTx(flags TxFlags) (TxID, error) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if !zoneMayOriginateContent(zd) {
		return "", fmt.Errorf("zone %s may not originate content", zd.ZoneName)
	}
	return zd.beginTxAutoLocked(flags), nil
}

func (zd *ZoneData) beginTxAutoLocked(flags TxFlags) TxID {
	for {
		zd.tx.seq++
		id := TxID(fmt.Sprintf("tx-%d", zd.tx.seq))
		if _, taken := zd.tx.open[id]; taken || id == zd.tx.createTx {
			continue
		}
		// Cannot fail: the id is non-empty and not open.
		_ = zd.beginTxLocked(id, flags)
		return id
	}
}

// beginTxLocked opens the transaction id. Caller holds zd.mu.
func (zd *ZoneData) beginTxLocked(id TxID, flags TxFlags) error {
	if id == "" {
		return fmt.Errorf("zone %s: a transaction needs an id", zd.ZoneName)
	}
	if _, open := zd.tx.open[id]; open {
		return fmt.Errorf("zone %s: transaction %q is already open", zd.ZoneName, id)
	}
	if zd.tx.open == nil {
		zd.tx.open = map[TxID]*zoneTx{}
	}
	zd.tx.open[id] = &zoneTx{start: time.Now(), limit: txHoldLimit}
	if flags&TxUrgent != 0 {
		zd.tx.urgent = true
	}
	zd.txArmTimerLocked()
	lg.Debug("transaction opened", "zone", zd.ZoneName, "tx", id,
		"urgent", flags&TxUrgent != 0, "open", len(zd.tx.open))
	return nil
}

// CommitTx commits an in-process transaction.
//
// When the commit closes the hold on a zone that is not Ready, or the hold was
// urgent, the publish happens here, in the caller, and its outcome is the
// return value. Otherwise the commit leaves other transactions open, or has
// asked the gate; nil then means accepted, and the publish follows.
func (zd *ZoneData) CommitTx(id TxID) error {
	resp := make(chan ZoneUpdateResult, 1)
	zd.mu.Lock()
	err := zd.commitTxLocked(id, resp)
	zd.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case res := <-resp:
		return res.Err
	default:
		return nil
	}
}

// commitTxLocked commits the transaction id. The error says the commit was not
// accepted, and nothing will arrive on resp. Otherwise resp, when not nil, is
// answered once the transaction is published or the publish that carried it
// was refused: before this returns when the publish is in the caller, later
// when it is not. resp must be buffered; the answer is a non-blocking send.
// Caller holds zd.mu.
func (zd *ZoneData) commitTxLocked(id TxID, resp chan ZoneUpdateResult) error {
	neverPublished := zd.snapshot.Load() == nil
	if _, open := zd.tx.open[id]; open {
		delete(zd.tx.open, id)
	} else if !(zd.tx.firstPending && neverPublished && id == zd.tx.createTx && !zd.txHeldLocked()) {
		// Not open, and not the one repeat this accepts: the creator of a zone
		// whose first content is committed and unsigned, committing again to
		// try the publish again.
		return fmt.Errorf("zone %s: no open transaction %q", zd.ZoneName, id)
	}
	if resp != nil {
		zd.tx.commitWaiters = append(zd.tx.commitWaiters, resp)
	}
	if zd.txHeldLocked() {
		// Several may be open on one zone, and it publishes when the last one
		// commits: a commit must not publish another transaction's half. This
		// one's waiter learns the outcome from the commit that closes the hold.
		lg.Debug("transaction committed; the zone is still held", "zone", zd.ZoneName,
			"tx", id, "open", len(zd.tx.open))
		return nil
	}
	zd.txHoldClosedLocked(string(id), true)
	return nil
}

// txHoldClosedLocked runs when the zone's last open transaction goes: by its
// commit, or released by the hold's limit. by names it for the log.
//
// A commit publishes in the caller when the zone is not Ready (a zone that is
// not Ready has no downstreams and is not rate-limited, and a zone's first
// content always is such a zone) or when the hold was urgent. Otherwise, and
// always for a release, the publish goes through the gate: at once on an idle
// zone, else at lastPublish + cadence. Caller holds zd.mu.
func (zd *ZoneData) txHoldClosedLocked(by string, committed bool) {
	zd.txStopTimerLocked()
	urgent := zd.tx.urgent
	zd.tx.urgent = false
	zd.tx.publishWanted = false

	neverPublished := zd.snapshot.Load() == nil
	if zd.workingSet == nil {
		if !neverPublished {
			// An empty hold on a published zone: nothing was staged, so there
			// is nothing to publish and no serial to spend on it.
			zd.txAnswerCommitWaitersLocked(ZoneUpdateResult{Applied: true})
			return
		}
		// A first content nobody added to is still a first content: the zone
		// as it was created.
		zd.ensureWorkingSet()
	}
	if zd.tx.createdHeld && neverPublished {
		zd.tx.firstPending = true
	}

	if committed && (!zd.Ready || urgent) {
		lg.Debug("the hold is closed; publishing in the caller", "zone", zd.ZoneName,
			"tx", by, "urgent", urgent, "ready", zd.Ready)
		zd.publishLocked(zd.generation.Load())
		// This publish was this commit's own. A journal refusal has been
		// reported to the commit's waiter; left behind, an update's applier
		// would later read it as its own.
		zd.wsPersistErr = nil
		return
	}
	lg.Debug("the hold is closed; asking the gate", "zone", zd.ZoneName, "tx", by,
		"committed", committed)
	zd.requestPublishLocked()
}

// requestPublishLocked is requestPublish(false) for a caller that holds zd.mu.
func (zd *ZoneData) requestPublishLocked() {
	zd.startPublisher()
	zd.publishQueued = true
	zd.wakePublisher()
}

// txStopPublishLocked is the hold, at the choke point. It reports whether the
// zone is held, and if it is, records that a publish is wanted. Nothing else
// moves: not the serial, not lastPublish, not one ws* flag, and the caller's
// changes stay staged. publishQueued is taken over (see publishWanted).
// Caller holds zd.mu.
func (zd *ZoneData) txStopPublishLocked() bool {
	if !zd.txHeldLocked() {
		return false
	}
	zd.tx.publishWanted = true
	zd.tx.stopped++
	zd.publishQueued = false
	lg.Debug("publish stopped: the zone has an open transaction", "zone", zd.ZoneName,
		"open", len(zd.tx.open))
	return true
}

// txPublishDoneLocked answers the waiting commits after a publish attempt.
// before is the snapshot the attempt started from. A publish that a hold
// stopped answers nobody: those transactions are not published yet, and the
// commit that closes the new hold will carry them. Caller holds zd.mu.
func (zd *ZoneData) txPublishDoneLocked(before *zoneSnapshot) {
	if len(zd.tx.commitWaiters) == 0 || zd.txHeldLocked() {
		return
	}
	res := ZoneUpdateResult{}
	switch {
	case zd.snapshot.Load() != before:
		res.Applied = true
	case zd.wsPersistErr != nil:
		// Read, not cleared: the applier whose publish this may have been
		// reads it too.
		res.Err = fmt.Errorf("zone %s: the transaction was not published: could not persist the change: %w",
			zd.ZoneName, zd.wsPersistErr)
	case zd.tx.firstErr != nil:
		res.Err = zd.tx.firstErr
	case zd.ErrorMsg != "":
		res.Err = fmt.Errorf("zone %s: the transaction was not published: %s", zd.ZoneName, zd.ErrorMsg)
	default:
		res.Err = fmt.Errorf("zone %s: the transaction was not published: the publish was refused", zd.ZoneName)
	}
	zd.txAnswerCommitWaitersLocked(res)
}

func (zd *ZoneData) txAnswerCommitWaitersLocked(res ZoneUpdateResult) {
	for _, ch := range zd.tx.commitWaiters {
		// Non-blocking, like UpdateRequest.respond: a waiter that gave up must
		// never hold up a publish.
		select {
		case ch <- res:
		default:
		}
	}
	zd.tx.commitWaiters = nil
}

// ---------------------------------------------------------------------------
// The first snapshot of a zone created held.

// txFirstSnapshotMustBeSignedLocked reports whether the publish now running
// would install the first snapshot of a zone created held that signs its own
// content. Keyed on the zone, not on the commit: after a commit that could not
// sign, the hold is closed, and the next publisher to arrive is the one that
// reaches the first snapshot -- an update's own publish, for one. Caller holds
// zd.mu.
func (zd *ZoneData) txFirstSnapshotMustBeSignedLocked() bool {
	return zd.tx.createdHeld && zd.snapshot.Load() == nil &&
		zd.signsItsOwnContent() && zoneMayOriginateContent(zd)
}

// refuseUnsignedFirstContentLocked is "signed or none", the none half. For any
// other zone "cannot sign yet" means "publish unsigned and stay not Ready", and
// queries follow the snapshot, not Ready: an unsigned snapshot is queryable.
// A zone created held installs nothing instead. The working set stays staged,
// the serial goes back, and no publish stays queued.
//
// What retries it is an event, never the publisher's loop, which
// clearQueuedPublishAfterRefusalLocked turns off on purpose: the next signing
// pass, which ends in a publish and runs when the missing thing arrives (a
// policy binding, the policy apply, the resigner), or the creator committing
// again.
//
// NOT DnssecError. SignZone, ResignZone and RenewZoneSignatures all refuse a
// zone that carries it, and only the policy and rollover validation clear it:
// a "not yet" recorded there would switch its own retry off.
// FirstPublishError gates nothing, and the publish that installs the first
// snapshot clears it. Caller holds zd.mu.
func (zd *ZoneData) refuseUnsignedFirstContentLocked(prevSerial uint32) {
	zd.CurrentSerial = prevSerial
	zd.clearQueuedPublishAfterRefusalLocked()
	why := "its signing keys are not available yet"
	switch {
	case zd.DnssecPolicy == nil:
		why = "no DNSSEC policy is bound yet"
	case zd.KeyDB == nil:
		why = "it has no key store"
	}
	zd.tx.firstErr = fmt.Errorf("zone %s: first content not published: the zone signs its own content and %s",
		zd.ZoneName, why)
	lg.Error("publish: not installing an unsigned first snapshot of a zone that signs"+
		" its own content; the zone stays unpublished (SERVFAIL) and its content"+
		" stays staged, until a signing pass or a repeated commit can sign it",
		"zone", zd.ZoneName, "reason", why)
	zd.setErrorLocked(FirstPublishError, "first content not published: the zone signs its own content and %s", why)
}

// txFirstSnapshotInstalledLocked runs when a zone created held has published
// for the first time. Caller holds zd.mu.
func (zd *ZoneData) txFirstSnapshotInstalledLocked() {
	zd.tx.firstPending = false
	zd.tx.firstErr = nil
	if _, set := zd.Errors[FirstPublishError]; set {
		zd.clearErrorLocked(FirstPublishError)
	}
}

// ---------------------------------------------------------------------------
// The hold's limit.

func (zd *ZoneData) txStopTimerLocked() {
	if zd.tx.timer != nil {
		zd.tx.timer.Stop()
		zd.tx.timer = nil
	}
	// Stop does not wait for a callback that has already fired and is waiting
	// for zd.mu. Outdate it.
	zd.tx.timerGen++
}

// txArmTimerLocked arms the limit's timer for the open transaction whose limit
// runs out first. One timer per zone. Caller holds zd.mu.
func (zd *ZoneData) txArmTimerLocked() {
	if zd.tx.timer != nil {
		return
	}
	var next time.Time
	for _, tx := range zd.tx.open {
		if tx.overdue {
			continue
		}
		if due := tx.start.Add(tx.limit); next.IsZero() || due.Before(next) {
			next = due
		}
	}
	if next.IsZero() {
		return
	}
	zd.tx.timerGen++
	gen := zd.tx.timerGen
	zd.tx.timer = time.AfterFunc(max(time.Until(next), 0), func() { zd.txLimitReached(gen) })
}

// txLimitReached deals with the transactions whose commit did not come in time.
//
// On a zone that has published before, the transaction is released with a WARN
// and what is staged publishes through the gate: the zone's previous content
// was valid, and so is each change added to it.
//
// On a zone that has never published the hold FAILS CLOSED. Releasing it would
// publish exactly the partial zone that a first content as a transaction exists
// to prevent. The transaction stays open, the zone stays unpublished, logs an
// ERROR and carries the error in its status until a commit arrives. Its creator
// is local start-up code; if that never commits, start-up failed.
func (zd *ZoneData) txLimitReached(gen uint64) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if gen != zd.tx.timerGen {
		return
	}
	zd.tx.timer = nil
	// A zone that has been removed or replaced since: leave it alone. Its
	// error registry in particular, which re-registers the zone it is set on.
	if cur, live := Zones.Get(zd.ZoneName); !live || cur != zd {
		return
	}
	now := time.Now()
	neverPublished := zd.snapshot.Load() == nil
	released := ""
	for id, tx := range zd.tx.open {
		if tx.overdue || now.Sub(tx.start) < tx.limit {
			continue
		}
		if neverPublished {
			tx.overdue = true
			lg.Error("a transaction on a zone that has never published is past the hold's limit"+
				" and its commit has not come; the zone stays unpublished (SERVFAIL)"+
				" until it does", "zone", zd.ZoneName, "tx", string(id), "limit", tx.limit)
			zd.setErrorLocked(FirstPublishError,
				"first content not published: transaction %q has been open for more than %v without a commit",
				string(id), tx.limit)
			continue
		}
		lg.Warn("a transaction is past the hold's limit and its commit has not come;"+
			" releasing it, what is staged publishes through the gate",
			"zone", zd.ZoneName, "tx", string(id), "limit", tx.limit)
		delete(zd.tx.open, id)
		released = string(id)
	}
	if released != "" && !zd.txHeldLocked() {
		zd.txHoldClosedLocked(released, false)
		return
	}
	zd.txArmTimerLocked()
}
