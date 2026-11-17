/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"runtime/debug"
	"sync"
)

// Panic recovery in the scanner.
//
// Scans work on data from child zones, which the parent does not control, in
// the scanner's own goroutines. The recover() the DNS handler (do53.go) and the
// IMR engine's request goroutine (imrengine.go) put around each query does not
// cover them: a scan calls the IMR's ImrQuery and its validator directly. A
// panic reached from a child's data -- a malformed key, say -- used to end the
// process: for tdns-auth, the parent serving every child (#801).
//
// Each unit of work now recovers: one scan of one child. The panic is logged
// with the parent, the child, the scan type and the stack, the scan fails, and
// the scanner carries on with the other children. scanChildAndApply recovers
// under the child's lock, so the failed scan is recorded like any other;
// runScanJob covers the scans with no parent zone; the poll round recovers per
// child, in its workers and where it reads a child's DS.
//
// The ScannerEngine loop does not recover, and neither does StartEngine. The
// loop handles no child data, and a loop that stopped quietly would be worse
// than a crash: the NOTIFY handler waits to hand each NOTIFY(CDS) and
// NOTIFY(CSYNC) to the loop, and would wait for good.

// logScanPanic logs a panic the scanner recovered from, with args naming what
// panicked, and the stack a crash would have printed. Called from the deferred
// function that recovered, it still sees the stack of the panic.
func logScanPanic(msg string, rec any, args ...any) {
	lg.Error(msg, append(args, "panic", fmt.Sprintf("%v", rec), "stack", string(debug.Stack()))...)
}

// parentZoneName is the name of parent, or "" when there is none. For use while
// recovering, where a nil dereference would panic again.
func parentZoneName(parent *ZoneData) string {
	if parent == nil {
		return ""
	}
	return parent.ZoneName
}

// scanPanicResponse logs a panic recovered from one scan of tuple.Zone and
// returns the failed response that stands in for the scan's own. parent is
// empty for a scan with no parent zone.
func scanPanicResponse(parent string, scanType ScanType, tuple ScanTuple, rec any) ScanTupleResponse {
	logScanPanic("ScannerEngine: PANIC recovered in a scan; the scan failed, the scanner carries on", rec,
		"parent", parent, "child", tuple.Zone, "type", ScanTypeToString[scanType])
	return ScanTupleResponse{Qname: tuple.Zone, ScanType: scanType, Options: tuple.Options,
		Error: true, ErrorMsg: fmt.Sprintf("internal error: the scan panicked: %v", rec)}
}

// recordPanickedScan records a scan that panicked in the delegation-sync log.
// Best effort: recording may be what panicked.
func recordPanickedScan(parent *ZoneData, scanType ScanType, resp ScanTupleResponse, polled bool) {
	defer func() {
		if rec := recover(); rec != nil {
			lg.Error("ScannerEngine: cannot record a scan that panicked", "child", resp.Qname, "panic", fmt.Sprintf("%v", rec))
		}
	}()
	recordScan(scanSyncLogEvent(parent, scanType, resp, polled), polled)
}

// runScanJob runs the scan of one scan-job goroutine, which sends its one
// response on responseCh, and then marks it done on wg. A panic fails that scan
// alone. The failed response is sent without blocking: the panic may follow the
// scan's own response, and a send into a full channel would hold wg.Done back,
// so that the job never completed.
func runScanJob(wg *sync.WaitGroup, responseCh chan<- ScanTupleResponse, parent string, scanType ScanType, tuple ScanTuple, scan func()) {
	defer wg.Done()
	defer func() {
		if rec := recover(); rec != nil {
			select {
			case responseCh <- scanPanicResponse(parent, scanType, tuple, rec):
			default:
			}
		}
	}()
	scan()
}
