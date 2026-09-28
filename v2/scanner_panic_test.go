package tdns

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Panic recovery in the scanner (scanner_panic.go): a panic reached from a
// child's data fails that scan alone, and the scanner carries on. Without the
// recovery these tests do not fail, they end the test binary.

const scanPanicMsg = "malformed child data"

// panickingBackend is a delegation backend whose reads panic, as a bug reached
// from a child's stored delegation data would.
type panickingBackend struct{ trustBackend }

func (b *panickingBackend) GetDelegationData(string, string) (map[string]map[uint16][]dns.RR, error) {
	panic(scanPanicMsg)
}

// panickingPollBackend is pollBackend, listing its children, with reads that
// panic.
type panickingPollBackend struct{ *pollBackend }

func (b *panickingPollBackend) GetDelegationData(string, string) (map[string]map[uint16][]dns.RR, error) {
	panic(scanPanicMsg)
}

// A scan that panics fails and is recorded, and it leaves the child's lock
// free: the next scan of the child runs.
func TestScanThatPanicsFailsThatScanAlone(t *testing.T) {
	const child = "panics.example."
	l := withSyncLog(t, 100)
	zd := trustParent(t, child, trustLax())
	zd.DelegationBackend.(*trustBackend).data[child][dns.TypeDS] = rrs(t, child+" 3600 IN DS 1111 13 2 "+strings.Repeat("cd", 32))
	n := cdsNet(t, child)
	n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeCDS), trustKey(child, dns.TypeDNSKEY))
	sc := trustScanner(n)
	var applied int
	sc.OnDelegationChange = func(string, *ZoneData, ScanTupleResponse) delegationApplyResult {
		applied++
		return delegationApplyResult{Applied: true}
	}
	sc.queryChild = func(context.Context, string, uint16, *core.RRset) (*core.RRset, []*core.RRset, bool, error) {
		panic(scanPanicMsg)
	}

	resp := sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil, nil)

	if !resp.Error || !strings.Contains(resp.ErrorMsg, "panicked") || !strings.Contains(resp.ErrorMsg, scanPanicMsg) || applied != 0 {
		t.Fatalf("error %v %q, applied %d; want the scan failed with the panic and nothing applied", resp.Error, resp.ErrorMsg, applied)
	}
	rep := l.Query(SyncLogQuery{Child: child})
	if len(rep.Events) != 1 || rep.Events[0].Outcome != SyncNotProcessed || !strings.Contains(rep.Events[0].Reason, "panicked") {
		t.Errorf("events %+v, want the scan recorded as not processed: panicked", rep.Events)
	}

	sc.queryChild = n.query
	done := make(chan ScanTupleResponse, 1)
	go func() {
		done <- sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil, nil)
	}()
	select {
	case resp = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the next scan of the child did not finish: the scan that panicked kept the child's lock")
	}
	if resp.Error || applied != 1 {
		t.Errorf("next scan: error %q, applied %d; want it run and its change applied", resp.ErrorMsg, applied)
	}
}

// A poll round carries on past a child whose scan panics and past one whose
// delegation panics when read, and finishes. With one worker, a worker that
// died would leave the round waiting for good.
func TestPollRoundCarriesOnPastChildrenThatPanic(t *testing.T) {
	const scanPanics, readPanics, fine = "scanpanics.example.", "readpanics.example.", "fine.example."
	t.Cleanup(func() {
		for _, child := range []string{scanPanics, readPanics, fine} {
			forgetCsyncProcessed(child)
		}
	})
	var parents []*ZoneData
	for _, child := range []string{scanPanics, readPanics, fine} {
		zd, b := pollParent(t, child, true)
		if child == readPanics {
			zd.DelegationBackend = &panickingPollBackend{b}
		}
		parents = append(parents, zd)
	}
	n := pollNet(t, scanPanics, readPanics, fine)
	sc, applied := pollScanner(n)
	query := sc.queryChild
	sc.queryChild = func(ctx context.Context, qname string, qtype uint16, ns *core.RRset) (*core.RRset, []*core.RRset, bool, error) {
		if dns.IsSubDomain(scanPanics, qname) {
			panic(scanPanicMsg)
		}
		return query(ctx, qname, qtype, ns)
	}

	done := make(chan struct{})
	go func() {
		sc.pollRound(context.Background(), parents, scannerPollConf{Enabled: true, Concurrency: 1})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the poll round did not finish")
	}

	if applied.count(fine, ScanCSYNC) != 1 || applied.count(fine, ScanCDS) != 1 {
		t.Errorf("%s: applied %d CSYNC and %d CDS change(s), want 1 and 1",
			fine, applied.count(fine, ScanCSYNC), applied.count(fine, ScanCDS))
	}
	if c := applied.count(scanPanics, ScanCSYNC) + applied.count(scanPanics, ScanCDS); c != 0 {
		t.Errorf("%s: applied %d change(s) from scans that panicked", scanPanics, c)
	}
	if q := n.queried[trustKey(readPanics, dns.TypeCSYNC)] + n.queried[trustKey(readPanics, dns.TypeCDS)]; q != 0 {
		t.Errorf("%s: queried %d time(s), although its delegation could not be read", readPanics, q)
	}
}

// runScanJob answers for a scan that panics, and marks the job done even when
// the panic follows the scan's own response into a full channel.
func TestRunScanJobAnswersForAScanThatPanics(t *testing.T) {
	tuple := ScanTuple{Zone: "panics.example."}
	wait := func(wg *sync.WaitGroup) {
		t.Helper()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the scan job was never marked done")
		}
	}
	ch := make(chan ScanTupleResponse, 1)
	var wg sync.WaitGroup

	wg.Add(1)
	go runScanJob(&wg, ch, "example.", ScanCDS, tuple, func() { panic(scanPanicMsg) })
	wait(&wg)
	if resp := <-ch; !resp.Error || resp.Qname != tuple.Zone || !strings.Contains(resp.ErrorMsg, scanPanicMsg) {
		t.Errorf("response %+v, want the scan failed with the panic", resp)
	}

	wg.Add(1)
	go runScanJob(&wg, ch, "example.", ScanCDS, tuple, func() {
		ch <- ScanTupleResponse{Qname: tuple.Zone}
		panic(scanPanicMsg)
	})
	wait(&wg)
	if resp := <-ch; resp.Error {
		t.Errorf("response %+v, want the scan's own", resp)
	}
}

// The engine carries on after a NOTIFY-started scan that panics: that scan's
// job completes with the scan failed, and the next request is taken and run.
func TestScannerEngineCarriesOnAfterAScanPanics(t *testing.T) {
	conf := &Config{}
	conf.Internal.ScannerQ = make(chan ScanRequest) // unbuffered: a send returns once the engine has taken it
	conf.Internal.AuthQueryQ = make(chan AuthQueryRequest, 1)
	conf.Internal.ImrReady = NewImrReadiness()
	ctx, cancel := context.WithCancel(context.Background())
	engineDone := make(chan error, 1)
	go func() { engineDone <- ScannerEngine(ctx, conf) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-engineDone:
		case <-time.After(5 * time.Second):
			t.Error("ScannerEngine did not return within 5s of being cancelled")
		}
	})

	const panics, next = "panics.example.", "next.example."
	zd := trustParent(t, panics, trustLax())
	zd.DelegationBackend = &panickingBackend{}
	conf.Internal.ScannerQ <- ScanRequest{Cmd: "SCAN", ChildZone: panics, ZoneData: zd, RRtype: dns.TypeCDS}
	zd = trustParent(t, next, trustLax())
	zd.DelegationBackend = &unreadableBackend{}
	conf.Internal.ScannerQ <- ScanRequest{Cmd: "SCAN", ChildZone: next, ZoneData: zd, RRtype: dns.TypeCDS}

	sc := conf.Internal.GetScanner()
	result := func(child string) (string, bool) {
		sc.JobsMutex.RLock()
		defer sc.JobsMutex.RUnlock()
		for _, job := range sc.Jobs {
			for _, r := range job.Responses {
				if r.Qname == child && job.Status == "completed" {
					return r.ErrorMsg, true
				}
			}
		}
		return "", false
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		panicMsg, panicDone := result(panics)
		nextMsg, nextDone := result(next)
		if panicDone && nextDone {
			if !strings.Contains(panicMsg, "panicked") {
				t.Errorf("%s: scan error %q, want the scan failed with the panic", panics, panicMsg)
			}
			if !strings.Contains(nextMsg, "cannot read the current delegation") {
				t.Errorf("%s: scan error %q, want the next scan run", next, nextMsg)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("scan jobs not completed: %s %v, %s %v", panics, panicDone, next, nextDone)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
