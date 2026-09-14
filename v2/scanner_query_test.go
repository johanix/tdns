package tdns

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// How the scanner asks a child's nameservers: what AuthQueryEngine makes of
// one response, how the answers of all of them combine, and the per-child
// memory of processed CSYNC serials that concurrent scans share.

// noDataServer answers every query over TCP with NOERROR, no records, an OPT
// record when the query had one, and the given AA bit.
func noDataServer(t *testing.T, authoritative bool) string {
	t.Helper()
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
			if opt := r.IsEdns0(); opt != nil {
				m.SetEdns0(opt.UDPSize(), opt.Do())
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr().String()
}

func TestAuthQueryEngineCountsNoDataOnlyWithAuthority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := make(chan AuthQueryRequest)
	go AuthQueryEngine(ctx, q)
	sc := NewScanner(q, false, false)

	rrset, err := sc.AuthQueryNG("ns1.child.example.", noDataServer(t, true), dns.TypeAAAA, "tcp")
	if err != nil {
		t.Fatalf("an authoritative NODATA is an answer: %v", err)
	}
	if rrset == nil || len(rrset.RRs) != 0 {
		t.Fatalf("rrset %v, want an empty RRset", rrset)
	}

	_, err = sc.AuthQueryNG("ns1.child.example.", noDataServer(t, false), dns.TypeAAAA, "tcp")
	if err == nil || !strings.Contains(err.Error(), "not authoritative") {
		t.Fatalf("err = %v, want a non-authoritative response to be an error", err)
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
