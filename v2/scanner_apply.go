/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
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

// scanApplyTimeout bounds how long a scan waits for its CHILD-UPDATE to be
// queued and applied. A variable so tests can shorten it.
var scanApplyTimeout = UpdateApplyTimeout

// childLock returns the mutex that serialises the scans of child. There is one
// per child ever scanned, and they are kept.
func (scanner *Scanner) childLock(child string) *sync.Mutex {
	mu, _ := scanner.childLocks.LoadOrStore(core.CanonicalizeName(dns.Fqdn(child)), &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// scanChildAndApply runs one CDS or CSYNC scan of a child of parent and hands a
// change it finds to OnDelegationChange, all under the child's lock.
//
// A CDS scan reads the child's current DS from the delegation backend inside
// the lock, so it sees what an earlier scan of the child has just applied. A
// backend that cannot be read stops the scan: an unreadable delegation is not
// one without a DS (see DelegationBackend), and taken for one it would send a
// child that has a DS down the first-DS path.
func (scanner *Scanner) scanChildAndApply(ctx context.Context, parent *ZoneData, scanType ScanType, tuple ScanTuple, options *edns0.MsgOptions) ScanTupleResponse {
	mu := scanner.childLock(tuple.Zone)
	mu.Lock()
	defer mu.Unlock()

	failed := func(format string, args ...any) ScanTupleResponse {
		return ScanTupleResponse{Qname: tuple.Zone, ScanType: scanType, Options: tuple.Options,
			Error: true, ErrorMsg: fmt.Sprintf(format, args...)}
	}

	// Both scan functions send exactly one response on every path.
	ch := make(chan ScanTupleResponse, 1)
	switch scanType {
	case ScanCSYNC:
		scanner.ProcessCSYNCNotify(ctx, tuple, parent, scanType, options, ch)
	case ScanCDS:
		if parent.DelegationBackend != nil {
			ds, err := currentDelegationDS(parent, tuple.Zone)
			if err != nil {
				lg.Error("ScannerEngine: cannot read the current delegation, not scanning", "parent", parent.ZoneName, "child", tuple.Zone, "error", err)
				return failed("cannot read the current delegation of %s: %v", tuple.Zone, err)
			}
			tuple.CurrentData.DS = ds
		}
		scanner.ProcessCDSNotify(ctx, tuple, parent, scanType, options, ch)
	default:
		return failed("a %s scan does not change a delegation", ScanTypeToString[scanType])
	}
	resp := <-ch
	logScanResult(parent, scanType, resp)
	if scanner.OnDelegationChange != nil && scanResponseChangesDelegation(resp) {
		scanner.OnDelegationChange(parent.ZoneName, parent, resp)
	}
	return resp
}

// logScanResult logs what one scan of a child decided, in one line: at Info
// when the scan found a change or did not process the child's data, at Debug
// when there was nothing to do. A CSYNC without the immediate flag counts as
// nothing to do: it is not processed here, and a poll would otherwise report it
// on every round. How a scan got to its result is in the scan log, which is
// silent unless scanner.verbose is set.
func logScanResult(parent *ZoneData, scanType ScanType, resp ScanTupleResponse) {
	args := []any{"parent", parent.ZoneName, "child", resp.Qname, "type", ScanTypeToString[scanType]}
	if resp.Validation != "" {
		args = append(args, "validation", string(resp.Validation))
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

// applyScanChildUpdate queues a scan's CHILD-UPDATE and waits until the zone
// updater has applied or refused it, ctx ends, or scanApplyTimeout passes. It
// reports whether the change was applied.
func applyScanChildUpdate(ctx context.Context, updateq chan UpdateRequest, ur UpdateRequest) bool {
	ur.Resp = make(chan ZoneUpdateResult, 1)
	timeout := time.NewTimer(scanApplyTimeout)
	defer timeout.Stop()

	select {
	case updateq <- ur:
	case <-ctx.Done():
		return false
	case <-timeout.C:
		lg.Error("ScannerEngine: timed out queueing a CHILD-UPDATE", "zone", ur.ZoneName, "description", ur.Description, "timeout", scanApplyTimeout)
		return false
	}

	select {
	case res := <-ur.Resp:
		if res.Err != nil {
			lg.Error("ScannerEngine: CHILD-UPDATE not applied", "zone", ur.ZoneName, "description", ur.Description, "error", res.Err)
		}
		return res.Applied
	case <-ctx.Done():
		return false
	case <-timeout.C:
		// Not cancelled: it is queued, and the updater may still apply it.
		lg.Warn("ScannerEngine: CHILD-UPDATE not confirmed in time; it is still queued", "zone", ur.ZoneName, "description", ur.Description, "timeout", scanApplyTimeout)
		return false
	}
}
