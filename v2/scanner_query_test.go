package tdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// How the scanner asks a child's nameservers and applies what it finds: what
// AuthQueryEngine makes of one response, how the answers of all of them
// combine, the per-child memory of processed CSYNC serials, and the per-child
// serialisation of scanning and applying.

// testAuthServer answers every query over TCP with NOERROR, the given answer
// records, an OPT record when the query had one, and the given AA bit.
func testAuthServer(t *testing.T, authoritative bool, answer ...string) string {
	t.Helper()
	var records []dns.RR
	for _, s := range answer {
		records = append(records, mustRR(t, s))
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &dns.Server{
		Listener:          ln,
		Net:               "tcp",
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = authoritative
			m.Answer = records
			if opt := r.IsEdns0(); opt != nil {
				m.SetEdns0(opt.UDPSize(), opt.Do())
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() {
			_ = srv.Shutdown()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the test DNS server did not shut down within 5s")
		}
	})
	return ln.Addr().String()
}

// startAuthQueryEngine runs AuthQueryEngine for the rest of the test, and fails
// the test if it has not returned within 5s of being cancelled.
func startAuthQueryEngine(t *testing.T) chan AuthQueryRequest {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	q := make(chan AuthQueryRequest)
	done := make(chan struct{})
	go func() {
		defer close(done)
		AuthQueryEngine(ctx, q)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("AuthQueryEngine did not return within 5s of being cancelled")
		}
	})
	return q
}

// Only an authoritative reply counts, with or without data. An authoritative
// NODATA is an answer.
func TestAuthQueryEngineRequiresAuthority(t *testing.T) {
	sc := NewScanner(startAuthQueryEngine(t), false, false)
	const name = "ns1.child.example."
	aaaa := name + " 3600 IN AAAA 2001:db8::1"

	rrset, err := sc.AuthQueryNG(name, testAuthServer(t, true), dns.TypeAAAA, "tcp")
	if err != nil || rrset == nil || len(rrset.RRs) != 0 {
		t.Errorf("authoritative NODATA: %v, %v; want an empty RRset", rrset, err)
	}
	rrset, err = sc.AuthQueryNG(name, testAuthServer(t, true, aaaa), dns.TypeAAAA, "tcp")
	if err != nil || rrset == nil || len(rrset.RRs) != 1 {
		t.Errorf("authoritative data: %v, %v; want the AAAA", rrset, err)
	}
	for _, answer := range [][]string{nil, {aaaa}} {
		_, err := sc.AuthQueryNG(name, testAuthServer(t, false, answer...), dns.TypeAAAA, "tcp")
		if err == nil || !strings.Contains(err.Error(), "not authoritative") {
			t.Errorf("non-authoritative reply with %d record(s): err = %v; want it refused", len(answer), err)
		}
	}
}

func TestCompareChildAnswers(t *testing.T) {
	const name = "ns1.child.example."
	none := func() *core.RRset { return &core.RRset{Name: name, RRtype: dns.TypeAAAA} }
	some := func() *core.RRset {
		return &core.RRset{Name: name, RRtype: dns.TypeAAAA, RRs: rrs(t, name+" 3600 IN AAAA 2001:db8::1")}
	}

	t.Run("every nameserver says there is none: an empty RRset they agree on", func(t *testing.T) {
		got, inSync, err := compareChildAnswers(name, dns.TypeAAAA, []*core.RRset{none(), none()}, nil, nil, false, false)
		if err != nil || !inSync || got == nil || len(got.RRs) != 0 {
			t.Fatalf("got %v, in sync %v, err %v; want an empty RRset in sync", got, inSync, err)
		}
	})

	t.Run("one serves it and another says there is none: they disagree", func(t *testing.T) {
		for _, answers := range [][]*core.RRset{{some(), none()}, {none(), some()}} {
			_, inSync, err := compareChildAnswers(name, dns.TypeAAAA, answers, nil, nil, false, false)
			if err != nil || inSync {
				t.Fatalf("in sync %v, err %v; want a disagreement", inSync, err)
			}
		}
	})

	t.Run("a nameserver that did not answer is left out", func(t *testing.T) {
		got, inSync, err := compareChildAnswers(name, dns.TypeAAAA, []*core.RRset{some()},
			[]string{"ns2.child.example. (192.0.2.2:53): i/o timeout"}, nil, false, false)
		if err != nil || !inSync || len(got.RRs) != 1 {
			t.Fatalf("got %v, in sync %v, err %v", got, inSync, err)
		}
	})

	t.Run("no nameserver answered: the error says why", func(t *testing.T) {
		_, _, err := compareChildAnswers(name, dns.TypeAAAA, nil,
			[]string{"ns1.child.example.: no addresses", "ns2.child.example. (192.0.2.2:53): i/o timeout"}, nil, false, false)
		if err == nil || !strings.Contains(err.Error(), "no addresses") || !strings.Contains(err.Error(), "i/o timeout") {
			t.Fatalf("err = %v", err)
		}
	})
}

// End to end through ProcessCSYNCNotify (helpers in scanner_trust_test.go).

// A bitmap type this parent does not process refuses the CSYNC before the
// child's NS is asked for, and nothing is recorded, so a corrected CSYNC with
// the same serial is processed when it comes.
func TestScanCSYNCRefusesAnUnsupportedBitmapType(t *testing.T) {
	const child = "txt.example."
	n := csyncMove(t, child)
	n.served[trustKey(child, dns.TypeCSYNC)] = rrs(t, child+" 3600 IN CSYNC 7 1 A NS AAAA TXT")

	resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

	if !resp.Error || !strings.Contains(resp.ErrorMsg, "lists TXT") {
		t.Fatalf("error %v %q; want the CSYNC refused for TXT", resp.Error, resp.ErrorMsg)
	}
	if scanResponseChangesDelegation(resp) {
		t.Error("a refused CSYNC would be applied")
	}
	if n.queried[trustKey(child, dns.TypeNS)] != 0 {
		t.Error("the child's NS was asked for, but the CSYNC is not acted on")
	}
	if _, marked := csyncProcessedSerial(child); marked {
		t.Error("a refused CSYNC was recorded as processed")
	}
}

// The child stops serving the only address of a nameserver it keeps. The
// empty A is an answer now, so the scan sees it -- and refuses the CSYNC
// rather than publish an in-bailiwick nameserver without glue.
func TestScanCSYNCRefusesToLeaveANameserverWithoutGlue(t *testing.T) {
	const child = "bare.example."
	n := csyncMove(t, child)
	delete(n.served, trustKey("ns1."+child, dns.TypeA))

	resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

	if !resp.Error || !strings.Contains(resp.ErrorMsg, "no A or AAAA glue") {
		t.Fatalf("error %v %q; want the CSYNC refused for leaving ns1 without glue", resp.Error, resp.ErrorMsg)
	}
	if scanResponseChangesDelegation(resp) {
		t.Error("a refused CSYNC would be applied")
	}
	if _, marked := csyncProcessedSerial(child); marked {
		t.Error("a refused CSYNC was recorded as processed")
	}
}

func TestScanCSYNCWithoutSOAIsNotProcessed(t *testing.T) {
	const child = "nosoa.example."
	n := csyncMove(t, child)
	delete(n.served, trustKey(child, dns.TypeSOA))

	resp := runCSYNC(t, trustScanner(n), trustParent(t, child, trustLax()), child)

	if !resp.Error || !strings.Contains(resp.ErrorMsg, "serve no SOA") {
		t.Fatalf("error %v %q; want a CSYNC without a child SOA not processed", resp.Error, resp.ErrorMsg)
	}
}

func forgetCsyncProcessed(zone string) {
	csyncProcessed.Lock()
	defer csyncProcessed.Unlock()
	delete(csyncProcessed.serials, csyncProcessedKey(zone))
}

// Every scan runs in its own goroutine. Unsynchronised, these writes were a
// fatal "concurrent map writes"; under -race a regression also shows as a race.
func TestCsyncProcessedSerialsAreSafeForConcurrentScans(t *testing.T) {
	zones := []string{"race0.example.", "race1.example.", "race2.example.", "race3.example."}
	t.Cleanup(func() {
		for _, z := range zones {
			forgetCsyncProcessed(z)
		}
	})
	sc := NewScanner(nil, false, false)

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			zone := zones[i%len(zones)]
			recordCsyncProcessed(zone, uint32(i))
			sc.ZoneCSYNCKnown(zone, &dns.CSYNC{Serial: uint32(i)})
		}(i)
	}
	wg.Wait()
	for _, z := range zones {
		if _, ok := csyncProcessedSerial(z); !ok {
			t.Errorf("%s: no serial recorded", z)
		}
	}

	recordCsyncProcessed("Race0.Example", 100)
	if serial, ok := csyncProcessedSerial("race0.example."); !ok || serial != 100 {
		t.Errorf("serial %d, recorded %v; names are compared canonically", serial, ok)
	}
	if !sc.ZoneCSYNCKnown("race0.example.", &dns.CSYNC{Serial: 99}) {
		t.Error("a CSYNC older than the last one processed is processed again")
	}
	if sc.ZoneCSYNCKnown("race0.example.", &dns.CSYNC{Serial: 100}) {
		t.Error("the CSYNC last processed is not processed again")
	}
}

// Two scans of one child run one after the other, each from before it asks the
// child anything until its change has been applied. Unserialised, the second
// scan runs while the first one's slow apply is still in progress.
func TestScansOfOneChildAreSerialised(t *testing.T) {
	const child = "serial.example."
	t.Cleanup(func() { forgetCsyncProcessed(child) })
	n := csyncMove(t, child)
	zd := trustParent(t, child, trustLax())
	sc := trustScanner(n)

	var mu sync.Mutex
	var events []string
	sc.queryChild = func(ctx context.Context, qname string, qtype uint16, ns *core.RRset) (*core.RRset, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if qtype == dns.TypeCSYNC {
			events = append(events, "scan")
		}
		return n.query(ctx, qname, qtype, ns)
	}
	sc.OnDelegationChange = func(string, *ZoneData, ScanTupleResponse) {
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		events = append(events, "applied")
	}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc.scanChildAndApply(context.Background(), zd, ScanCSYNC, ScanTuple{Zone: child}, nil)
		}()
	}
	wg.Wait()

	if got := strings.Join(events, ","); got != "scan,applied,scan,applied" {
		t.Fatalf("events %s; want each scan to finish applying before the next one starts", got)
	}
}

func TestApplyScanChildUpdateWaitsForTheUpdater(t *testing.T) {
	q := make(chan UpdateRequest)
	var applied atomic.Bool
	go func() {
		ur := <-q
		time.Sleep(30 * time.Millisecond)
		applied.Store(true)
		ur.respond(true, nil)
	}()
	if !applyScanChildUpdate(context.Background(), q, UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: "example."}) {
		t.Fatal("an applied update was reported as not applied")
	}
	if !applied.Load() {
		t.Fatal("returned before the updater had applied the change")
	}

	prev := scanApplyTimeout
	scanApplyTimeout = 50 * time.Millisecond
	t.Cleanup(func() { scanApplyTimeout = prev })
	go func() { <-q }() // takes the request and never answers
	if applyScanChildUpdate(context.Background(), q, UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: "example."}) {
		t.Fatal("an update the updater never answered was reported as applied")
	}
}

// unreadableBackend is a delegation backend whose delegation data cannot be read.
type unreadableBackend struct{ trustBackend }

func (b *unreadableBackend) GetDelegationData(string, string) (map[string]map[uint16][]dns.RR, error) {
	return nil, errors.New("store unavailable")
}

func cdsNet(t *testing.T, child string) *trustNet {
	t.Helper()
	return &trustNet{
		served:  map[string][]dns.RR{trustKey(child, dns.TypeCDS): rrs(t, child+" 3600 IN CDS 2371 13 2 "+strings.Repeat("ab", 32))},
		verdict: map[string]cache.ValidationState{},
	}
}

// A CDS scan takes the current DS from the delegation backend, inside the lock.
func TestCDSScanReadsTheCurrentDSFromTheBackend(t *testing.T) {
	const child = "hasds.example."
	zd := trustParent(t, child, trustLax())
	zd.DelegationBackend.(*trustBackend).data[child][dns.TypeDS] = rrs(t, child+" 3600 IN DS 1111 13 2 "+strings.Repeat("cd", 32))
	sc := trustScanner(cdsNet(t, child))
	var applied int
	sc.OnDelegationChange = func(string, *ZoneData, ScanTupleResponse) { applied++ }

	resp := sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil)

	if resp.Error || len(resp.DSRemoves) != 1 || len(resp.DSAdds) != 1 || applied != 1 {
		t.Fatalf("error %q, DS adds %v removes %v, applied %d; want the backend's DS replaced once",
			resp.ErrorMsg, names(resp.DSAdds), names(resp.DSRemoves), applied)
	}
}

// A delegation that cannot be read is not scanned: taken for one without a DS,
// a child that has one would be scanned as waiting for its first.
func TestCDSScanOfAnUnreadableDelegationIsNotRun(t *testing.T) {
	const child = "unreadable.example."
	zd := trustParent(t, child, trustLax())
	zd.DelegationBackend = &unreadableBackend{}
	n := cdsNet(t, child)
	sc := trustScanner(n)
	applied := false
	sc.OnDelegationChange = func(string, *ZoneData, ScanTupleResponse) { applied = true }

	resp := sc.scanChildAndApply(context.Background(), zd, ScanCDS, ScanTuple{Zone: child}, nil)

	if !resp.Error || !strings.Contains(resp.ErrorMsg, "cannot read the current delegation") {
		t.Fatalf("error %v %q; want the scan stopped", resp.Error, resp.ErrorMsg)
	}
	if len(n.queried) != 0 || applied {
		t.Fatalf("queried %v, applied %v, although the delegation could not be read", n.queried, applied)
	}
}

// A NOTIFY-started scan goes through scanChildAndApply: the error only it gives
// for an unreadable delegation comes back in the scan job.
func TestNotifyScansGoThroughScanChildAndApply(t *testing.T) {
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

	const child = "notified.example."
	zd := trustParent(t, child, trustLax())
	zd.DelegationBackend = &unreadableBackend{}
	conf.Internal.ScannerQ <- ScanRequest{Cmd: "SCAN", ChildZone: child, ZoneData: zd, RRtype: dns.TypeCDS}

	sc := conf.Internal.GetScanner()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var msg string
		var completed bool
		sc.JobsMutex.RLock()
		for _, job := range sc.Jobs {
			for _, r := range job.Responses {
				if r.Qname == child && job.Status == "completed" {
					msg, completed = r.ErrorMsg, true
				}
			}
		}
		sc.JobsMutex.RUnlock()
		if completed {
			if !strings.Contains(msg, "cannot read the current delegation") {
				t.Fatalf("scan error %q; want the scan to have gone through scanChildAndApply", msg)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the scan job did not complete")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
