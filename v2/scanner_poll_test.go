package tdns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The poll round (scanner_poll.go), through the real ProcessCSYNCNotify and
// ProcessCDSNotify, with the network replaced as in scanner_trust_test.go.

const (
	pollOldDigest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	pollNewDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// pollBackend is trustBackend with children to list and, when readErr is set,
// a delegation it cannot read.
type pollBackend struct {
	trustBackend
	children []string
	readErr  error
}

func (b *pollBackend) ListChildren(string) ([]string, error) { return b.children, nil }

func (b *pollBackend) GetDelegationData(parent, child string) (map[string]map[uint16][]dns.RR, error) {
	if b.readErr != nil {
		return nil, b.readErr
	}
	return b.trustBackend.GetDelegationData(parent, child)
}

// pollParent is trustParent under the lax policy, allowing child updates, with
// a delegation backend that lists child and, when withDS, holds a DS for it.
func pollParent(t *testing.T, child string, withDS bool) (*ZoneData, *pollBackend) {
	t.Helper()
	zd := trustParent(t, child, trustLax())
	zd.Options[OptAllowChildUpdates] = true
	b := &pollBackend{trustBackend: *zd.DelegationBackend.(*trustBackend), children: []string{child}}
	if withDS {
		b.data[child][dns.TypeDS] = rrs(t, child+" 3600 IN DS 1111 13 2 "+pollOldDigest)
	}
	zd.DelegationBackend = b
	return zd, b
}

// pollNet serves, for each child, what csyncMove serves and a CDS for a new key.
func pollNet(t *testing.T, children ...string) *trustNet {
	t.Helper()
	n := &trustNet{served: map[string][]dns.RR{}, verdict: map[string]cache.ValidationState{}}
	for _, child := range children {
		for k, v := range csyncMove(t, child).served {
			n.served[k] = v
		}
		n.served[trustKey(child, dns.TypeCDS)] = rrs(t, child+" 3600 IN CDS 2371 13 2 "+pollNewDigest)
	}
	return n
}

// appliedChanges records what OnDelegationChange would have applied.
type appliedChanges struct {
	mu        sync.Mutex
	responses []ScanTupleResponse
}

func (a *appliedChanges) record(_ string, _ *ZoneData, resp ScanTupleResponse) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.responses = append(a.responses, resp)
}

func (a *appliedChanges) count(child string, scanType ScanType) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, r := range a.responses {
		if r.Qname == child && r.ScanType == scanType {
			n++
		}
	}
	return n
}

// pollScanner is trustScanner made safe for the concurrent scans of a round,
// recording the changes it would apply.
func pollScanner(n *trustNet) (*Scanner, *appliedChanges) {
	sc := trustScanner(n)
	var mu sync.Mutex
	sc.queryChild = func(ctx context.Context, qname string, qtype uint16, ns *core.RRset) (*core.RRset, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		return n.query(ctx, qname, qtype, ns)
	}
	sc.validateRRset = func(ctx context.Context, rrset *core.RRset) (cache.ValidationState, error) {
		mu.Lock()
		defer mu.Unlock()
		return n.validate(ctx, rrset)
	}
	applied := &appliedChanges{}
	sc.OnDelegationChange = applied.record
	return sc, applied
}

func TestPollScansCSYNCAndCDSOfAChildWithADS(t *testing.T) {
	const child = "withds.example."
	t.Cleanup(func() { forgetCsyncProcessed(child) })
	zd, _ := pollParent(t, child, true)
	n := pollNet(t, child)
	sc, applied := pollScanner(n)

	sc.pollRound(context.Background(), []*ZoneData{zd}, scannerPollConf{Enabled: true, Concurrency: 2})

	if n.queried[trustKey(child, dns.TypeCSYNC)] == 0 || n.queried[trustKey(child, dns.TypeCDS)] == 0 {
		t.Fatalf("queried %v; want the CSYNC and the CDS scanned", n.queried)
	}
	if applied.count(child, ScanCSYNC) != 1 || applied.count(child, ScanCDS) != 1 {
		t.Errorf("applied %d CSYNC and %d CDS change(s); want the NS move and the new DS",
			applied.count(child, ScanCSYNC), applied.count(child, ScanCDS))
	}
}

func TestPollLeavesAChildWithoutADSAlone(t *testing.T) {
	const child = "nods.example."
	zd, _ := pollParent(t, child, false)
	n := pollNet(t, child)
	sc, applied := pollScanner(n)

	sc.pollRound(context.Background(), []*ZoneData{zd}, scannerPollConf{Enabled: true, Concurrency: 1})

	if len(n.queried) != 0 || applied.count(child, ScanCDS)+applied.count(child, ScanCSYNC) != 0 {
		t.Fatalf("queried %v; a child without a DS is not polled unless bootstrap is set", n.queried)
	}
}

func TestPollBootstrapScansOnlyTheCDSOfAChildWithoutADS(t *testing.T) {
	const child = "bootstrap.example."
	zd, _ := pollParent(t, child, false)
	n := pollNet(t, child)
	sc, applied := pollScanner(n)

	sc.pollRound(context.Background(), []*ZoneData{zd}, scannerPollConf{Enabled: true, Bootstrap: true, Concurrency: 1})

	if n.queried[trustKey(child, dns.TypeCSYNC)] != 0 {
		t.Error("a child without a DS was scanned for CSYNC")
	}
	if n.queried[trustKey(child, dns.TypeCDS)] == 0 || applied.count(child, ScanCDS) != 1 {
		t.Errorf("queried %v, applied %d CDS change(s); want the first DS from the CDS", n.queried, applied.count(child, ScanCDS))
	}
}

// With bootstrap set, a delegation that could not be read and was taken for
// one without a DS would have its CDS scanned as a first DS.
func TestPollSkipsAChildWhoseDelegationCannotBeRead(t *testing.T) {
	const child = "unreadable.example."
	zd, b := pollParent(t, child, true)
	b.readErr = errors.New("store unavailable")
	n := pollNet(t, child)
	sc, _ := pollScanner(n)

	sc.pollRound(context.Background(), []*ZoneData{zd}, scannerPollConf{Enabled: true, Bootstrap: true, Concurrency: 1})

	if len(n.queried) != 0 {
		t.Fatalf("queried %v for a child whose delegation could not be read", n.queried)
	}
}

// The scans of a round share the scanner, the processed-serial memory and the
// change callback; run under -race.
func TestPollRoundScansChildrenConcurrently(t *testing.T) {
	var parents []*ZoneData
	var children []string
	for i := 0; i < 6; i++ {
		child := fmt.Sprintf("many%d.example.", i)
		zd, _ := pollParent(t, child, true)
		children = append(children, child)
		parents = append(parents, zd)
	}
	t.Cleanup(func() {
		for _, child := range children {
			forgetCsyncProcessed(child)
		}
	})
	sc, applied := pollScanner(pollNet(t, children...))

	sc.pollRound(context.Background(), parents, scannerPollConf{Enabled: true, Concurrency: 3})

	for _, child := range children {
		if applied.count(child, ScanCSYNC) != 1 || applied.count(child, ScanCDS) != 1 {
			t.Errorf("%s: applied %d CSYNC and %d CDS change(s), want 1 and 1",
				child, applied.count(child, ScanCSYNC), applied.count(child, ScanCDS))
		}
	}
}

func TestPollParents(t *testing.T) {
	allowed, _ := pollParent(t, "a.example.", true)
	noOption, _ := pollParent(t, "b.example.", true)
	noOption.Options[OptAllowChildUpdates] = false
	noBackend, _ := pollParent(t, "c.example.", true)
	noBackend.DelegationBackend = nil

	got := pollParents(map[string]*ZoneData{"allowed": allowed, "no-option": noOption, "no-backend": noBackend, "nil": nil})

	if len(got) != 1 || got[0] != allowed {
		t.Fatalf("got %d parent(s); want only the zone that allows child updates and has a delegation backend", len(got))
	}
}

func TestPollRoundsDoNotOverlap(t *testing.T) {
	sc := NewScanner(nil, false, false)
	sc.poll.running.Store(true)
	if sc.startPollRound(context.Background(), nil, scannerPollConf{Concurrency: 1}) {
		t.Fatal("a round started while the previous one was still running")
	}
	sc.poll.running.Store(false)
	if !sc.startPollRound(context.Background(), nil, scannerPollConf{Concurrency: 1}) {
		t.Fatal("no round started with none running")
	}
	deadline := time.Now().Add(5 * time.Second)
	for sc.poll.running.Load() {
		if time.Now().After(deadline) {
			t.Fatal("an empty round did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCurrentDelegationDS(t *testing.T) {
	withDS, _ := pollParent(t, "ds.example.", true)
	if ds, err := currentDelegationDS(withDS, "ds.example."); err != nil || ds == nil || len(ds.RRs) != 1 {
		t.Errorf("with a DS: %v, %v", ds, err)
	}
	withoutDS, _ := pollParent(t, "nods.example.", false)
	if ds, err := currentDelegationDS(withoutDS, "nods.example."); err != nil || ds != nil {
		t.Errorf("without a DS: %v, %v", ds, err)
	}
	unreadable, b := pollParent(t, "broken.example.", true)
	b.readErr = errors.New("store unavailable")
	if _, err := currentDelegationDS(unreadable, "broken.example."); err == nil {
		t.Error("an unreadable delegation was reported as readable")
	}
}

// The NOTIFY path reads the current DS through the same helper. A delegation it
// cannot read is no reason to scan; before, it was scanned as one without a DS.
func TestNotifyScanSkipsAChildWhoseDelegationCannotBeRead(t *testing.T) {
	conf := &Config{}
	conf.Internal.ScannerQ = make(chan ScanRequest) // unbuffered: a send returns once the engine has taken it
	conf.Internal.AuthQueryQ = make(chan AuthQueryRequest, 1)
	conf.Internal.ImrReady = NewImrReadiness()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engineDone := make(chan error, 1)
	go func() { engineDone <- ScannerEngine(ctx, conf) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-engineDone:
		case <-time.After(5 * time.Second):
			t.Error("ScannerEngine did not return after its context was cancelled")
		}
	})

	broken, b := pollParent(t, "broken.example.", true)
	b.readErr = errors.New("store unavailable")
	fine, _ := pollParent(t, "fine.example.", true)

	conf.Internal.ScannerQ <- ScanRequest{Cmd: "SCAN", ChildZone: "broken.example.", ZoneData: broken, RRtype: dns.TypeCDS}
	conf.Internal.ScannerQ <- ScanRequest{Cmd: "SCAN", ChildZone: "fine.example.", ZoneData: fine, RRtype: dns.TypeCDS}

	// The broken request was handled before the fine one was taken, so once the
	// fine one's job has completed, a job for the broken one would exist too.
	sc := conf.Internal.GetScanner()
	deadline := time.Now().Add(10 * time.Second)
	for {
		sc.JobsMutex.RLock()
		var jobs, fineDone int
		var qnames []string
		for _, job := range sc.Jobs {
			jobs++
			for _, r := range job.Responses {
				qnames = append(qnames, r.Qname)
				if r.Qname == "fine.example." && job.Status == "completed" {
					fineDone++
				}
			}
		}
		sc.JobsMutex.RUnlock()
		if fineDone > 0 {
			if jobs != 1 {
				t.Fatalf("%d scan jobs (responses for %v); want only the readable child scanned", jobs, qnames)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the readable child's scan did not complete (jobs %d, responses for %v)", jobs, qnames)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A poll asks every child with a DS for its CSYNC, and most publish none. Under
// require-dnssec that is a quiet no-op, not an error on every round: a child
// that publishes no CSYNC asks for nothing, and nothing needs no authentication.
func TestScanCSYNCWithoutACSYNCIsANoOpUnderRequireDnssec(t *testing.T) {
	const child = "nocsync.example."
	n := csyncMove(t, child)
	delete(n.served, trustKey(child, dns.TypeCSYNC))
	n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeSOA))

	resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustStrict()), child)

	if resp.Error || resp.DataChanged || resp.Validation != "" {
		t.Errorf("error %v %q, changed %v, validation %q; want a quiet no-op",
			resp.Error, resp.ErrorMsg, resp.DataChanged, resp.Validation)
	}
}
