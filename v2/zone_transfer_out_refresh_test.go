package tdns

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A refresh of a zone that is already loaded keeps serving the published
// snapshot until the replacement is swapped in. Outbound transfers have to do
// the same: a downstream that asks while the refresh runs gets the published
// copy, not REFUSED. Only a zone with nothing to offer (first load, withheld)
// or one in a service-impacting error refuses.

// rrStrings renders RRs in a comparable, order-free form.
func rrStrings(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, rr.String())
	}
	sort.Strings(out)
	return out
}

// firstAndLastSerial returns the serials of the leading and trailing SOA of a
// transfer, failing the test when either end is not a SOA.
func firstAndLastSerial(t *testing.T, rrs []dns.RR) (uint32, uint32) {
	t.Helper()
	if len(rrs) < 2 {
		t.Fatalf("transfer carried %d RRs, want at least the two SOA bookends", len(rrs))
	}
	first, ok := rrs[0].(*dns.SOA)
	if !ok {
		t.Fatalf("first RR is %T, want SOA", rrs[0])
	}
	last, ok := rrs[len(rrs)-1].(*dns.SOA)
	if !ok {
		t.Fatalf("last RR is %T, want SOA", rrs[len(rrs)-1])
	}
	return first.Serial, last.Serial
}

// TestZoneTransferOut_ServesPublishedSnapshotWhileRefreshing: the refresh sets
// the status to loading for its whole length, with the published snapshot
// untouched. An AXFR asked in that window must be answered with the published
// serial and zone, and an IXFR from the published serial with the single-SOA
// "you are current" answer -- neither REFUSED.
func TestZoneTransferOut_ServesPublishedSnapshotWhileRefreshing(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)
	snapSerial := zd.publishedSnapshot().Serial
	want := rrStrings(func() []dns.RR {
		srv := startTestAXFRServer(t, zd)
		defer srv.shutdown()
		rrs, err := axfrClient(t, srv.addr, zd.ZoneName)
		if err != nil {
			t.Fatalf("AXFR before the refresh: %v", err)
		}
		return rrs
	}())

	// Exactly what fetchFromUpstream and FetchFromFile do on entry.
	zd.SetStatus(ZoneStatusLoading)

	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	t.Run("AXFR", func(t *testing.T) {
		rrs, err := axfrClient(t, srv.addr, zd.ZoneName)
		if err != nil {
			t.Fatalf("AXFR during the refresh was refused: %v", err)
		}
		first, last := firstAndLastSerial(t, rrs)
		if first != snapSerial || last != snapSerial {
			t.Errorf("AXFR bookends carry serials %d and %d, want the published %d", first, last, snapSerial)
		}
		if got := rrStrings(rrs); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("AXFR during the refresh is not the published zone\n got: %v\nwant: %v", got, want)
		}
	})

	t.Run("IXFR from the published serial", func(t *testing.T) {
		rrs, err := ixfrClient(t, srv.addr, zd.ZoneName, snapSerial)
		if err != nil {
			t.Fatalf("IXFR during the refresh was refused: %v", err)
		}
		if got := soaSerials(rrs); !serialsEqual(got, []uint32{snapSerial}) {
			t.Errorf("IXFR from the current serial answered SOA serials %v, want the single published %d", got, snapSerial)
		}
	})

	t.Run("IXFR from an older serial", func(t *testing.T) {
		rrs, err := ixfrClient(t, srv.addr, zd.ZoneName, snapSerial-1)
		if err != nil {
			t.Fatalf("IXFR during the refresh was refused: %v", err)
		}
		// No chain behind this zone, so the answer is the full zone.
		first, last := firstAndLastSerial(t, rrs)
		if first != snapSerial || last != snapSerial {
			t.Errorf("IXFR fallback bookends carry serials %d and %d, want the published %d", first, last, snapSerial)
		}
	})
}

// TestZoneTransferOut_RefusesWithNothingToOffer: the refusals that stay. A zone
// that is not Ready (a first load, or one registered and not yet loaded; a
// withheld zone is not Ready either) has nothing servable to offer, and a zone
// in a service-impacting error is refused as its queries are.
func TestZoneTransferOut_RefusesWithNothingToOffer(t *testing.T) {
	for _, tc := range []struct {
		what  string
		setup func(zd *ZoneData)
	}{
		{"first load, status loading", func(zd *ZoneData) {
			zd.Ready = false
			zd.Status = ZoneStatusLoading
		}},
		{"registered and enqueued, status pending", func(zd *ZoneData) {
			zd.Ready = false
			zd.Status = ZoneStatusPending
		}},
		{"service-impacting error on a ready zone", func(zd *ZoneData) {
			zd.SetError(DnssecError, "signing failed")
		}},
		{"service-impacting error during a refresh", func(zd *ZoneData) {
			zd.SetError(ConfigError, "bad config")
			zd.SetStatus(ZoneStatusLoading)
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			zd := loadTestTransferZone(t, basicZone)
			// SetError republishes the zone into the global map.
			t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
			tc.setup(zd)
			w := &fakeRW{remote: udpAddr("127.0.0.1")}
			r := new(dns.Msg)
			r.SetAxfr(zd.ZoneName)
			sent, err := zd.ZoneTransferOut(context.Background(), w, r, nil)
			if err != nil {
				t.Fatalf("ZoneTransferOut: %v", err)
			}
			if sent != 0 {
				t.Fatalf("expected 0 RRs sent, got %d", sent)
			}
			if w.written == nil || w.written.Rcode != dns.RcodeRefused {
				t.Fatalf("expected REFUSED, got %v", w.written)
			}
		})
	}
}

// TestZoneTransferOut_RefreshErrorDoesNotRefuse: a failed refresh leaves
// RefreshError on a zone that still holds and serves its published copy; the
// transfer follows the queries and is served.
func TestZoneTransferOut_RefreshErrorDoesNotRefuse(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) }) // SetError republishes the zone into the global map
	zd.SetError(RefreshError, "upstream unreachable")
	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()
	if _, err := axfrClient(t, srv.addr, zd.ZoneName); err != nil {
		t.Fatalf("AXFR of a zone with only a RefreshError was refused: %v", err)
	}
}

// ---------------------------------------------------------------- end to end

const refreshOldZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 7 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
gone.example.	3600	IN	A	10.0.0.9
`

const refreshNewZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 20 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.33
fresh.example.	3600	IN	A	10.0.0.8
`

// refreshHold parks a refresh at its last step before publication: the
// transfer is done and the replacement zone is complete, but the published
// snapshot is still the old one and the status is still loading. It is a
// pre-refresh callback, which fetchFromUpstream runs at exactly that point.
type refreshHold struct {
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func newRefreshHold() *refreshHold {
	return &refreshHold{reached: make(chan struct{}), release: make(chan struct{})}
}

func (h *refreshHold) callback(_, _ *ZoneData) {
	h.once.Do(func() { close(h.reached) })
	<-h.release
}

// TestZoneTransferOut_ConsistentCopyDuringAnUpstreamRefresh drives the real
// refresh: a secondary holding serial 7 pulls serial 20 from its primary, and
// is held at the last step before it publishes. A downstream that transfers
// from the secondary then must get serial 7 -- the whole of it, with nothing of
// serial 20 mixed in -- and after the refresh publishes, serial 20 whole.
func TestZoneTransferOut_ConsistentCopyDuringAnUpstreamRefresh(t *testing.T) {
	for _, tc := range []struct {
		what string
		opts map[ZoneOption]bool
	}{
		{"AXFR in", map[ZoneOption]bool{OptNoRequestIxfr: true}},
		{"IXFR in", nil},
	} {
		t.Run(tc.what, func(t *testing.T) {
			authApp(t)
			primaryAddr, stopPrimary := startTestPrimary(t, refreshNewZone)
			defer stopPrimary()

			sec := ixfrTestSecondary(t, refreshOldZone, primaryAddr, tc.opts)
			sec.IncomingSerial = 7
			sec.CurrentSerial = 7
			sec.Ready = true
			sec.Status = ZoneStatusReady
			sec.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}}
			if got := sec.publishedSnapshot().Serial; got != 7 {
				t.Fatalf("precondition: the secondary publishes serial %d, want 7", got)
			}

			secAddr, stopSec := serveTestPrimary(t, sec)
			defer stopSec()

			oldCopy, err := axfrClient(t, secAddr, sec.ZoneName)
			if err != nil {
				t.Fatalf("AXFR of the loaded secondary: %v", err)
			}
			if first, last := firstAndLastSerial(t, oldCopy); first != 7 || last != 7 {
				t.Fatalf("precondition: the secondary serves serials %d and %d, want 7", first, last)
			}

			hold := newRefreshHold()
			sec.OnZonePreRefresh = append(sec.OnZonePreRefresh, hold.callback)

			type result struct {
				updated bool
				err     error
			}
			done := make(chan result, 1)
			go func() {
				updated, err := sec.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{})
				done <- result{updated, err}
			}()
			released, finished := false, false
			release := func() {
				if !released {
					released = true
					close(hold.release)
				}
			}
			// A failed assertion must not leave the refresh parked.
			defer func() {
				release()
				if !finished {
					<-done
				}
			}()

			select {
			case <-hold.reached:
			case r := <-done:
				finished = true
				t.Fatalf("the refresh ended before the hold was reached: updated=%v err=%v", r.updated, r.err)
			case <-time.After(10 * time.Second):
				t.Fatal("the refresh did not reach the hold")
			}
			if got := sec.GetStatus(); got != ZoneStatusLoading {
				t.Fatalf("precondition: status is %s during the refresh, want loading", ZoneStatusToString[got])
			}

			// The downstream transfers now.
			during, err := axfrClient(t, secAddr, sec.ZoneName)
			if err != nil {
				t.Fatalf("AXFR during the refresh was refused: %v", err)
			}
			first, last := firstAndLastSerial(t, during)
			if first != 7 || last != 7 {
				t.Errorf("AXFR during the refresh carries serials %d and %d, want the published 7", first, last)
			}
			if got, want := strings.Join(rrStrings(during), "\n"), strings.Join(rrStrings(oldCopy), "\n"); got != want {
				t.Errorf("AXFR during the refresh is not the published zone\n got: %s\nwant: %s", got, want)
			}
			for _, rr := range during {
				if strings.Contains(rr.String(), "fresh.example.") || strings.Contains(rr.String(), "10.0.0.33") {
					t.Errorf("serial 20 content in the copy served at serial 7: %s", rr)
				}
			}

			ix, err := ixfrClient(t, secAddr, sec.ZoneName, 7)
			if err != nil {
				t.Fatalf("IXFR during the refresh was refused: %v", err)
			}
			if got := soaSerials(ix); !serialsEqual(got, []uint32{7}) {
				t.Errorf("IXFR from 7 during the refresh answered SOA serials %v, want the single published 7", got)
			}

			// Publish. The next transfer is the new zone, whole.
			release()
			r := <-done
			finished = true
			if r.err != nil || !r.updated {
				t.Fatalf("FetchFromUpstream: updated=%v err=%v", r.updated, r.err)
			}
			after, err := axfrClient(t, secAddr, sec.ZoneName)
			if err != nil {
				t.Fatalf("AXFR after the refresh: %v", err)
			}
			first, last = firstAndLastSerial(t, after)
			if first != 20 || last != 20 {
				t.Errorf("AXFR after the refresh carries serials %d and %d, want 20", first, last)
			}
			sawFresh := false
			for _, rr := range after {
				if strings.Contains(rr.String(), "gone.example.") {
					t.Errorf("serial 7 content still served after the refresh: %s", rr)
				}
				if strings.Contains(rr.String(), "fresh.example.") {
					sawFresh = true
				}
			}
			if !sawFresh {
				t.Error("the new zone is not served after the refresh")
			}
		})
	}
}

// pausingRW is a response writer that stops the transfer behind it inside its
// first envelope: the producer is then blocked on the next, part-way through
// the zone, until the test lets it go.
type pausingRW struct {
	fakeRW
	mu      sync.Mutex
	answers []dns.RR
	first   chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func newPausingRW() *pausingRW {
	return &pausingRW{
		fakeRW: fakeRW{remote: udpAddr("127.0.0.1")},
		first:  make(chan struct{}),
		resume: make(chan struct{}),
	}
}

func (p *pausingRW) WriteMsg(m *dns.Msg) error {
	p.mu.Lock()
	p.answers = append(p.answers, m.Answer...)
	p.mu.Unlock()
	p.once.Do(func() {
		close(p.first)
		<-p.resume
	})
	return nil
}

// TestZoneTransferOut_InFlightAcrossAPublish: a transfer that started before
// the refresh publishes finishes with the serial and content it started with,
// whatever the publish does under it. The transfer is parked in its first
// envelope, so the zone is half sent when the replacement is published.
func TestZoneTransferOut_InFlightAcrossAPublish(t *testing.T) {
	authApp(t)
	var old strings.Builder
	old.WriteString(`example.	3600	IN	SOA	ns.example. hostmaster.example. 7 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
`)
	// Enough payload to span several envelopes.
	pad := strings.Repeat("x", 200)
	for i := 0; i < 600; i++ {
		old.WriteString("h" + strconv.Itoa(i) + ".example.\t3600\tIN\tTXT\t\"old " + pad + "\"\n")
	}
	newer := strings.Replace(old.String(), " 7 7200", " 20 7200", 1)
	newer = strings.ReplaceAll(newer, "\"old ", "\"new ")

	primaryAddr, stopPrimary := startTestPrimary(t, newer)
	defer stopPrimary()
	sec := ixfrTestSecondary(t, old.String(), primaryAddr, map[ZoneOption]bool{OptNoRequestIxfr: true})
	sec.IncomingSerial = 7
	sec.CurrentSerial = 7
	sec.Ready = true
	sec.Status = ZoneStatusReady
	sec.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}}

	w := newPausingRW()
	r := new(dns.Msg)
	r.SetAxfr(sec.ZoneName)
	type sent struct {
		n   int
		err error
	}
	out := make(chan sent, 1)
	go func() {
		n, err := sec.ZoneTransferOut(context.Background(), w, r, nil)
		out <- sent{n, err}
	}()
	defer func() {
		// A failed assertion must not leave the transfer parked.
		select {
		case <-w.resume:
		default:
			close(w.resume)
		}
	}()

	select {
	case <-w.first:
	case <-time.After(10 * time.Second):
		t.Fatal("the transfer sent no envelope")
	}

	// The transfer is half sent. The refresh now runs to completion.
	updated, err := sec.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{})
	if err != nil || !updated {
		t.Fatalf("FetchFromUpstream: updated=%v err=%v", updated, err)
	}
	if got := sec.publishedSnapshot().Serial; got != 20 {
		t.Fatalf("precondition: the refresh published serial %d, want 20", got)
	}

	close(w.resume)
	select {
	case s := <-out:
		if s.err != nil || s.n == 0 {
			t.Fatalf("the in-flight transfer: sent=%d err=%v", s.n, s.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight transfer did not finish")
	}

	w.mu.Lock()
	rrs := append([]dns.RR(nil), w.answers...)
	w.mu.Unlock()
	if first, last := firstAndLastSerial(t, rrs); first != 7 || last != 7 {
		t.Errorf("the in-flight transfer carries serials %d and %d, want 7 at both ends", first, last)
	}
	if got := len(rrs); got < 600 {
		t.Errorf("the in-flight transfer carried %d RRs, want the whole zone", got)
	}
	for _, rr := range rrs {
		if strings.Contains(rr.String(), "\"new ") {
			t.Fatalf("serial 20 content in a transfer that began at serial 7: %s", rr)
		}
	}
}
