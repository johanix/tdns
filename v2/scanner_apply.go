/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Applying what a CDS or CSYNC scan of a hosted parent's child finds.
//
// Scans of one child are serialised, from before a scan reads anything until
// its change has been applied. Scans run in their own goroutines, and two of
// the same child -- NOTIFYs in quick succession, say -- used to run side by
// side: both passed the processed-serial check, and the older one's change
// could be applied after the newer one's and restore a stale delegation.
// Waiting until the change is applied, not merely queued, also means the next
// scan of the child reads a delegation that already includes it.
//
// A scan that gives up waiting leaves its change queued, and the zone updater
// may still apply it. The next scan of that child first waits for that change
// (awaitPendingApply): until the updater has taken it the delegation does not
// show it, and a scan working from that delegation could keep a record the
// change adds and the child has since dropped, or miss one the change removes
// and the child has since put back.

// scanApplyTimeout bounds how long a scan waits for its CHILD-UPDATE to be
// queued and applied, and how long the next scan of the child waits for one
// still queued. A variable so tests can shorten it.
var scanApplyTimeout = UpdateApplyTimeout

// childKey is the name the per-child scan state is kept under.
func childKey(child string) string { return core.CanonicalizeName(dns.Fqdn(child)) }

// childLock returns the mutex that serialises the scans of child. There is one
// per child ever scanned, and they are kept.
func (scanner *Scanner) childLock(child string) *sync.Mutex {
	mu, _ := scanner.childLocks.LoadOrStore(childKey(child), &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// pollScan marks a scan a poll round started. The round decided whether to
// scan the child from the DS it had when the round read it; the scan decides
// again, under the child's lock, from the DS it has now.
type pollScan struct {
	bootstrap bool // scanner.poll.bootstrap for the round
}

// scanChildAndApply runs one CDS or CSYNC scan of a child of parent and hands a
// change it finds to OnDelegationChange, all under the child's lock. poll is
// nil for a scan a NOTIFY started.
//
// A CDS scan, and every scan a poll started, reads the child's current DS from
// the delegation backend inside the lock, so it sees what an earlier scan of
// the child has just applied. A backend that cannot be read stops the scan: an
// unreadable delegation is not one without a DS (see DelegationBackend), and
// taken for one it would send a child that has a DS down the first-DS path.
//
// A poll scans a child without a DS for nothing but a first DS, and for that
// only with scanner.poll.bootstrap set. A child that had a DS when the round
// listed it and has lost it since -- a NOTIFY-started scan applied a CDS delete
// first, say -- is held to that rule here.
//
// A panic in the scan, reached from the child's data, fails this scan alone
// (see scanner_panic.go).
func (scanner *Scanner) scanChildAndApply(ctx context.Context, parent *ZoneData, scanType ScanType, tuple ScanTuple, options *edns0.MsgOptions, poll *pollScan) (resp ScanTupleResponse) {
	mu := scanner.childLock(tuple.Zone)
	mu.Lock()
	defer mu.Unlock()
	// Deferred after the unlock, so it runs first: a scan that panicked is
	// recorded under the child's lock, like every other.
	defer func() {
		if rec := recover(); rec != nil {
			resp = scanPanicResponse(parentZoneName(parent), scanType, tuple, rec)
			recordPanickedScan(parent, scanType, resp, poll != nil)
		}
	}()

	// A scan that stops before it reads the child is recorded too. The child
	// that sent the NOTIFY got NOERROR, and "I notified and the parent did
	// nothing" is what the log is there to answer. A poll's repeats of the same
	// failure are rate-limited by AddPoll.
	failed := func(format string, args ...any) ScanTupleResponse {
		resp := ScanTupleResponse{Qname: tuple.Zone, ScanType: scanType, Options: tuple.Options,
			Error: true, ErrorMsg: fmt.Sprintf(format, args...)}
		recordScan(scanSyncLogEvent(parent, scanType, resp, poll != nil), poll != nil)
		return resp
	}

	if err := scanner.awaitPendingApply(ctx, tuple.Zone); err != nil {
		lg.Warn("ScannerEngine: not scanning the child", "parent", parent.ZoneName, "child", tuple.Zone, "error", err)
		return failed("%v", err)
	}

	var ds *core.RRset
	readDS := parent.DelegationBackend != nil && (scanType == ScanCDS || poll != nil)
	if readDS {
		var err error
		if ds, err = currentDelegationDS(parent, tuple.Zone); err != nil {
			lg.Error("ScannerEngine: cannot read the current delegation, not scanning", "parent", parent.ZoneName, "child", tuple.Zone, "error", err)
			return failed("cannot read the current delegation of %s: %v", tuple.Zone, err)
		}
	}
	if poll != nil && ds == nil && (scanType == ScanCSYNC || !poll.bootstrap) {
		lg.Debug("ScannerEngine: scan result", "parent", parent.ZoneName, "child", tuple.Zone, "type", ScanTypeToString[scanType],
			"outcome", "nothing to do", "reason", "polled, and the child no longer has a DS")
		return ScanTupleResponse{Qname: tuple.Zone, ScanType: scanType, Options: tuple.Options}
	}

	// Both scan functions send exactly one response on every path.
	ch := make(chan ScanTupleResponse, 1)
	switch scanType {
	case ScanCSYNC:
		scanner.ProcessCSYNCNotify(ctx, tuple, parent, scanType, options, ch)
	case ScanCDS:
		if readDS {
			tuple.CurrentData.DS = ds
		}
		scanner.ProcessCDSNotify(ctx, tuple, parent, scanType, options, ch)
	default:
		return failed("a %s scan does not change a delegation", ScanTypeToString[scanType])
	}
	resp = <-ch
	logScanResult(parent, scanType, resp)
	ev := scanSyncLogEvent(parent, scanType, resp, poll != nil)
	if scanResponseChangesDelegation(resp) {
		// The scan decided on a change; the event says what became of it.
		// "applied" only once the CHILD-UPDATE has landed.
		if scanner.OnDelegationChange == nil {
			ev.Outcome = SyncApplyFailed
			ev.Reason = "no delegation updater"
		} else {
			res := scanner.OnDelegationChange(parent.ZoneName, parent, resp)
			switch {
			case res.Applied:
				ev.Outcome = SyncApplied
			case res.Pending:
				ev.Outcome = SyncQueued
				ev.Reason = res.Reason
				// The late answer is recorded by awaitPendingApply, with
				// this event's details.
				scanner.pendingEvents.Store(childKey(resp.Qname), ev)
			default:
				ev.Outcome = SyncApplyFailed
				ev.Reason = res.Reason
			}
		}
	}
	recordScan(ev, poll != nil)
	return resp
}

// delegationApplyResult is what became of a change a scan handed to
// OnDelegationChange: applied, still queued at the zone updater (Pending), or
// neither, with the reason.
type delegationApplyResult struct {
	Applied bool
	Pending bool
	Reason  string
}

// logScanResult logs what one scan of a child decided, in one line: at Info
// when the scan found a change or did not process the child's data, at Debug
// when there was nothing to do. A CSYNC without the immediate flag counts as
// nothing to do: it is not processed here, and a poll would otherwise report it
// on every round. How a scan got to its result is in the scan log, which is
// silent unless scanner.verbose is set.
//
// Glue a CSYNC scan left as it is (GlueSkipped) is named on the line, which is
// then at Info even without a change: that glue may be stale, and the scan log
// that says why is off by default (#779).
func logScanResult(parent *ZoneData, scanType ScanType, resp ScanTupleResponse) {
	args := []any{"parent", parent.ZoneName, "child", resp.Qname, "type", ScanTypeToString[scanType]}
	if resp.Validation != "" {
		args = append(args, "validation", string(resp.Validation))
	}
	if len(resp.GlueSkipped) > 0 {
		args = append(args, "glue-skipped", strings.Join(resp.GlueSkipped, "; "))
	}
	switch {
	case resp.Error && resp.ErrorMsg == errCsyncNotImmediate.Error():
		lg.Debug("ScannerEngine: scan result", append(args, "outcome", "nothing to do", "reason", resp.ErrorMsg)...)
	case resp.Error:
		lg.Info("ScannerEngine: scan result", append(args, "outcome", "not processed", "reason", resp.ErrorMsg)...)
	case scanResponseChangesDelegation(resp):
		lg.Info("ScannerEngine: scan result", append(args, "outcome", "change",
			"ds", fmt.Sprintf("+%d -%d", len(resp.DSAdds), len(resp.DSRemoves)),
			"ns", fmt.Sprintf("+%d -%d", len(resp.NSAdds), len(resp.NSRemoves)),
			"glue", fmt.Sprintf("+%d -%d", len(resp.GlueAdds), len(resp.GlueRemoves)),
			"reason", resp.ValidationReason)...)
	case len(resp.GlueSkipped) > 0:
		lg.Info("ScannerEngine: scan result", append(args, "outcome", "no change")...)
	default:
		lg.Debug("ScannerEngine: scan result", append(args, "outcome", "no change")...)
	}
}

// currentDelegationDS returns the DS RRset the parent's delegation backend
// holds for child, or nil when it holds none. An error means the backend could
// not be read.
func currentDelegationDS(parent *ZoneData, child string) (*core.RRset, error) {
	data, err := parent.DelegationBackend.GetDelegationData(parent.ZoneName, child)
	if err != nil {
		return nil, err
	}
	var ds []dns.RR
	for _, byType := range data {
		ds = append(ds, byType[dns.TypeDS]...)
	}
	if len(ds) == 0 {
		return nil, nil
	}
	return &core.RRset{Name: child, RRtype: dns.TypeDS, RRs: ds}, nil
}

// applyDelegationChange applies what a scan of a child of parentZone found, as
// a CHILD-UPDATE through the zone's updater: DS adds and removes from a CDS
// scan, NS and glue adds and removes from a CSYNC scan. ScannerEngine wires it
// as OnDelegationChange, so it runs under the child's scan lock.
func (scanner *Scanner) applyDelegationChange(ctx context.Context, parentZone string, zd *ZoneData, resp ScanTupleResponse) delegationApplyResult {
	if zd.KeyDB == nil || zd.KeyDB.UpdateQ == nil {
		lg.Error("ScannerEngine: OnDelegationChange: no UpdateQ for zone", "zone", parentZone)
		return delegationApplyResult{Reason: "no update queue for the zone"}
	}
	var actions []dns.RR
	// DS changes (from CDS scan)
	for _, rr := range resp.DSAdds {
		cp := dns.Copy(rr)
		cp.Header().Class = dns.ClassINET
		actions = append(actions, cp)
	}
	for _, rr := range resp.DSRemoves {
		cp := dns.Copy(rr)
		cp.Header().Class = dns.ClassNONE
		actions = append(actions, cp)
	}
	// NS changes (from CSYNC scan)
	for _, rr := range resp.NSAdds {
		cp := dns.Copy(rr)
		cp.Header().Class = dns.ClassINET
		actions = append(actions, cp)
	}
	for _, rr := range resp.NSRemoves {
		cp := dns.Copy(rr)
		cp.Header().Class = dns.ClassNONE
		actions = append(actions, cp)
	}
	// Glue changes (from CSYNC scan)
	for _, rr := range resp.GlueAdds {
		cp := dns.Copy(rr)
		cp.Header().Class = dns.ClassINET
		actions = append(actions, cp)
	}
	for _, rr := range resp.GlueRemoves {
		cp := dns.Copy(rr)
		cp.Header().Class = dns.ClassNONE
		actions = append(actions, cp)
	}

	// Determine update type from which fields are populated
	updateType := "CDS"
	description := fmt.Sprintf("CDS scan: DS update for %s", resp.Qname)
	if len(resp.NSAdds) > 0 || len(resp.NSRemoves) > 0 || len(resp.GlueAdds) > 0 || len(resp.GlueRemoves) > 0 {
		updateType = "CSYNC"
		description = fmt.Sprintf("CSYNC scan: delegation update for %s", resp.Qname)
	}

	lg.Info("ScannerEngine: OnDelegationChange: enqueuing CHILD-UPDATE", "parent", parentZone, "child", resp.Qname, "type", updateType, "actions", len(actions))
	// Waits until the change is applied: the caller holds the child's scan
	// lock, and the next scan of the child has to read a delegation that
	// includes it (scanChildAndApply). A change still queued when the wait
	// ends is waited for by that next scan.
	applied, pending, reason := queueScanChildUpdate(ctx, zd.KeyDB.UpdateQ, UpdateRequest{
		Cmd:            "CHILD-UPDATE",
		UpdateType:     updateType,
		ZoneName:       parentZone,
		Actions:        actions,
		Trusted:        true,
		InternalUpdate: true,
		Description:    description,
	})
	if pending != nil {
		scanner.notePendingApply(resp.Qname, pending)
	}
	return delegationApplyResult{Applied: applied, Pending: pending != nil, Reason: reason}
}

// applyScanChildUpdate queues a scan's CHILD-UPDATE and waits until the zone
// updater has applied or refused it, ctx ends, or scanApplyTimeout passes. It
// reports whether the change was applied. When the change was queued but not
// answered in time, pending is where the answer will arrive; the updater may
// still apply it.
func applyScanChildUpdate(ctx context.Context, updateq chan UpdateRequest, ur UpdateRequest) (applied bool, pending <-chan ZoneUpdateResult) {
	applied, pending, _ = queueScanChildUpdate(ctx, updateq, ur)
	return applied, pending
}

// queueScanChildUpdate is applyScanChildUpdate, with the reason a change was not
// applied, for the delegation-sync log.
func queueScanChildUpdate(ctx context.Context, updateq chan UpdateRequest, ur UpdateRequest) (applied bool, pending <-chan ZoneUpdateResult, reason string) {
	resp := make(chan ZoneUpdateResult, 1)
	ur.Resp = resp
	timeout := time.NewTimer(scanApplyTimeout)
	defer timeout.Stop()

	select {
	case updateq <- ur:
	case <-ctx.Done():
		return false, nil, "not queued: " + ctx.Err().Error()
	case <-timeout.C:
		lg.Error("ScannerEngine: timed out queueing a CHILD-UPDATE", "zone", ur.ZoneName, "description", ur.Description, "timeout", scanApplyTimeout)
		return false, nil, fmt.Sprintf("timed out after %s queueing the CHILD-UPDATE", scanApplyTimeout)
	}

	select {
	case res := <-resp:
		if res.Err != nil {
			lg.Error("ScannerEngine: CHILD-UPDATE not applied", "zone", ur.ZoneName, "description", ur.Description, "error", res.Err)
			return res.Applied, nil, res.Err.Error()
		}
		if !res.Applied {
			return false, nil, "the zone updater did not apply the CHILD-UPDATE"
		}
		return true, nil, ""
	case <-ctx.Done():
		return false, nil, "stopped waiting: " + ctx.Err().Error()
	case <-timeout.C:
		// Not cancelled: it is queued, and the updater may still apply it.
		lg.Warn("ScannerEngine: CHILD-UPDATE not confirmed in time; it is still queued", "zone", ur.ZoneName, "description", ur.Description, "timeout", scanApplyTimeout)
		return false, resp, fmt.Sprintf("not confirmed within %s; still queued at the zone updater", scanApplyTimeout)
	}
}

// recordLateApply records what became of a change that was recorded as queued:
// the same event, with the outcome the zone updater gave late.
func (scanner *Scanner) recordLateApply(key string, res ZoneUpdateResult) {
	v, ok := scanner.pendingEvents.LoadAndDelete(key)
	if !ok {
		return
	}
	ev := v.(SyncLogEvent)
	ev.Time = time.Time{}
	switch {
	case res.Err != nil:
		ev.Outcome, ev.Reason = SyncApplyFailed, "answered late: "+res.Err.Error()
	case res.Applied:
		ev.Outcome, ev.Reason = SyncApplied, "answered late"
	default:
		ev.Outcome, ev.Reason = SyncApplyFailed, "answered late: not applied"
	}
	syncLog().Add(ev)
}

// notePendingApply records that a change to child is still queued, with the
// channel its answer will arrive on. The caller holds the child's lock.
func (scanner *Scanner) notePendingApply(child string, pending <-chan ZoneUpdateResult) {
	scanner.pendingApplies.Store(childKey(child), pending)
}

// awaitPendingApply waits for a change to child that an earlier scan queued and
// gave up waiting for, until the zone updater answers, ctx ends, or
// scanApplyTimeout passes. An error means the change is still queued, and the
// child is not to be scanned yet. The caller holds the child's lock.
func (scanner *Scanner) awaitPendingApply(ctx context.Context, child string) error {
	key := childKey(child)
	v, ok := scanner.pendingApplies.Load(key)
	if !ok {
		return nil
	}
	timeout := time.NewTimer(scanApplyTimeout)
	defer timeout.Stop()

	select {
	case res := <-v.(<-chan ZoneUpdateResult):
		scanner.pendingApplies.Delete(key)
		if res.Err != nil {
			lg.Info("ScannerEngine: an earlier CHILD-UPDATE was answered late: not applied", "child", child, "error", res.Err)
		} else {
			lg.Info("ScannerEngine: an earlier CHILD-UPDATE was answered late", "child", child, "applied", res.Applied)
		}
		scanner.recordLateApply(key, res)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timeout.C:
		return fmt.Errorf("an earlier change to %s is still queued at the zone updater", child)
	}
}
