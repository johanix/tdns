package tdns

import (
	"context"
	"fmt"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// --- helpers (mustRR comes from childsync_replace_test.go) ---

// loadIxfrTestZone loads the shared transfer-test zone AND registers it in the
// global Zones map so publishWorkingSetLocked's zoneStillLive gate passes for
// re-publishes (the retention path under test).
func loadIxfrTestZone(t *testing.T, zoneData string) *ZoneData {
	t.Helper()
	zd := loadTestTransferZone(t, zoneData)
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
	return zd
}

// stageAndPublish stages changes through the production staging API and
// publishes with a serial bump, exactly like the UPDATE/publisher path.
func stageAndPublish(t *testing.T, zd *ZoneData, stage func(*ZoneData)) {
	t.Helper()
	zd.mu.Lock()
	zd.ensureWorkingSet()
	if stage != nil {
		stage(zd)
	}
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()
}

func stageAddA(t *testing.T, zd *ZoneData, owner, addr string) func(*ZoneData) {
	t.Helper()
	rr := mustRR(t, fmt.Sprintf("%s 60 IN A %s", owner, addr))
	return func(zd *ZoneData) {
		zd.stageRRsetLocked(owner, core.RRset{
			Name: owner, Class: dns.ClassINET, RRtype: dns.TypeA, RRs: []dns.RR{rr},
		})
	}
}

func chainOf(zd *ZoneData) []Ixfr {
	snap := zd.publishedSnapshot()
	if snap == nil {
		return nil
	}
	return snap.IxfrChain
}

func soaSerials(rrs []dns.RR) []uint32 {
	var out []uint32
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			out = append(out, soa.Serial)
		}
	}
	return out
}

func serialsEqual(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ixfrClientCore(t *testing.T, provider dns.TsigProvider, addr, zone string, serial uint32) ([]dns.RR, error) {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetIxfr(zone, serial, ".", ".")
	tr := new(dns.Transfer)
	if provider != nil {
		tr.TsigProvider = provider
	}
	ch, err := tr.In(msg, addr)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			return rrs, env.Error
		}
		rrs = append(rrs, env.RR...)
	}
	return rrs, nil
}

func ixfrClient(t *testing.T, addr, zone string, serial uint32) ([]dns.RR, error) {
	t.Helper()
	return ixfrClientCore(t, nil, addr, zone, serial)
}

func ixfrClientTSIG(t *testing.T, conf *Config, addr, zone, keyName string, serial uint32) ([]dns.RR, error) {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetIxfr(zone, serial, ".", ".")
	provider, err := SignForPeer(msg, keyName, conf)
	if err != nil {
		t.Fatalf("SignForPeer: %v", err)
	}
	tr := &dns.Transfer{TsigProvider: provider}
	ch, err := tr.In(msg, addr)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			return rrs, env.Error
		}
		rrs = append(rrs, env.RR...)
	}
	return rrs, nil
}

// --- serial arithmetic ---

func TestSerialNewer(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{2, 1, true},
		{1, 2, false},
		{1, 1, false},
		{0, 0xFFFFFFFF, true},  // wrap: 0 is newer than 2^32-1
		{0xFFFFFFFF, 0, false}, // and not vice versa
		{5, 0x80000006, true},  // distance 2^31-1: still comparable
		{0x80000000, 0, false}, // distance exactly 2^31: undefined => not newer
		{0, 0x80000000, false}, // ... in both directions
		{0x80000001, 1, false}, // distance exactly 2^31 again, off-origin
		{1, 0x80000001, false}, // symmetric check
	}
	for _, c := range cases {
		if got := serialNewer(c.a, c.b); got != c.want {
			t.Errorf("serialNewer(%#x, %#x) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// --- retention ---

func TestIxfrChain_PublishAppendsDelta(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone) // serial 1
	if got := chainOf(zd); len(got) != 0 {
		t.Fatalf("fresh zone should have empty chain, got %d links", len(got))
	}

	add := stageAddA(t, zd, "added.example.test.", "192.0.2.9")
	stageAndPublish(t, zd, func(zd *ZoneData) {
		add(zd)
		zd.stageDeleteLocked("www.example.test.", dns.TypeA)
	})

	chain := chainOf(zd)
	if len(chain) != 1 {
		t.Fatalf("expected 1 chain link, got %d", len(chain))
	}
	link := chain[0]
	if link.FromSerial != 1 || link.ToSerial != 2 {
		t.Fatalf("link serials = %d->%d, want 1->2", link.FromSerial, link.ToSerial)
	}
	if link.FromSOA == nil || link.FromSOA.Serial != 1 {
		t.Fatalf("FromSOA = %v, want serial 1", link.FromSOA)
	}
	if link.ToSOA == nil || link.ToSOA.Serial != 2 {
		t.Fatalf("ToSOA = %v, want serial 2", link.ToSOA)
	}
	if len(link.Removed) != 1 || link.Removed[0].Name != "www.example.test." || len(link.Removed[0].RRs) != 1 {
		t.Fatalf("Removed = %+v, want exactly the www A RRset", link.Removed)
	}
	if len(link.Added) != 1 || link.Added[0].Name != "added.example.test." || len(link.Added[0].RRs) != 1 {
		t.Fatalf("Added = %+v, want exactly the added A RRset", link.Added)
	}
	// The apex SOA change must NOT appear as diff content (brackets carry it).
	for _, rs := range append(append([]core.RRset{}, link.Removed...), link.Added...) {
		for _, rr := range rs.RRs {
			if rr.Header().Rrtype == dns.TypeSOA {
				t.Fatalf("bare SOA leaked into diff content: %v", rr)
			}
		}
	}
	if link.EstBytes <= 0 {
		t.Fatalf("EstBytes = %d, want > 0", link.EstBytes)
	}
}

func TestIxfrChain_EmptyDeltaAppendsEmptyLink(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, nil) // serial-only publish: 1 -> 2

	chain := chainOf(zd)
	if len(chain) != 1 {
		t.Fatalf("expected 1 link after serial-only publish, got %d", len(chain))
	}
	if chain[0].FromSerial != 1 || chain[0].ToSerial != 2 {
		t.Fatalf("link serials = %d->%d, want 1->2", chain[0].FromSerial, chain[0].ToSerial)
	}
	if len(chain[0].Removed) != 0 || len(chain[0].Added) != 0 {
		t.Fatalf("expected empty delta, got removed=%v added=%v", chain[0].Removed, chain[0].Added)
	}
}

func TestIxfrChain_MultiplePublishesStayContiguous(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	stageAndPublish(t, zd, stageAddA(t, zd, "two.example.test.", "192.0.2.12"))

	chain := chainOf(zd)
	if len(chain) != 2 {
		t.Fatalf("expected 2 links, got %d", len(chain))
	}
	if chain[0].ToSerial != chain[1].FromSerial {
		t.Fatalf("chain not contiguous: %d->%d then %d->%d",
			chain[0].FromSerial, chain[0].ToSerial, chain[1].FromSerial, chain[1].ToSerial)
	}
	if chain[1].ToSerial != zd.publishedSnapshot().Serial {
		t.Fatalf("chain tail %d != snapshot serial %d", chain[1].ToSerial, zd.publishedSnapshot().Serial)
	}
}

func TestIxfrChain_SameSerialContentChangeResets(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	if len(chainOf(zd)) != 1 {
		t.Fatal("setup: expected 1 link")
	}

	// Content change WITHOUT a serial bump (the tsignal/catalog-shaped publish).
	add := stageAddA(t, zd, "sneaky.example.test.", "192.0.2.66")
	zd.mu.Lock()
	zd.ensureWorkingSet()
	add(zd)
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
	zd.mu.Unlock()

	if got := chainOf(zd); len(got) != 0 {
		t.Fatalf("same-serial content change must reset the chain, got %d links", len(got))
	}
}

func TestIxfrChain_SameSerialNoChangeKeepsChain(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))

	// A no-op publish at the same serial (signalSynth-style) keeps history.
	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
	zd.mu.Unlock()

	if got := chainOf(zd); len(got) != 1 {
		t.Fatalf("no-op same-serial publish must keep the chain, got %d links", len(got))
	}
}

func TestIxfrChain_EpochResetOnRefreshReplacement(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	if len(chainOf(zd)) != 1 {
		t.Fatal("setup: expected 1 link")
	}

	newZone := strings.Replace(basicZone, "1 ; serial", "10 ; serial", 1)
	newZd := &ZoneData{
		ZoneName:  zd.ZoneName,
		ZoneStore: MapZone,
		ZoneType:  Primary,
		Logger:    zd.Logger,
	}
	if _, _, err := newZd.ReadZoneData(newZone, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}

	zd.mu.Lock()
	err := zd.applyRefreshReplacementLocked(newZd, nil, false, false)
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked: %v", err)
	}

	if got := chainOf(zd); len(got) != 0 {
		t.Fatalf("wholesale replacement must reset the chain, got %d links", len(got))
	}
}

// TestIxfrChain_DroppedEpochResetDoesNotLeak is the regression test for the
// CodeRabbit round-1 finding: a staged wsIxfrEpochReset whose publish is
// dropped (here: the apex-less refusal path) must NOT survive and wipe the
// chain on the next, unrelated successful publish.
func TestIxfrChain_DroppedEpochResetDoesNotLeak(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	if len(chainOf(zd)) != 1 {
		t.Fatal("setup: expected 1 link")
	}

	// A wholesale-replace publish that gets REFUSED (apex-less working set),
	// with the epoch-reset flag staged the way applyRefreshReplacementLocked
	// stages it.
	zd.mu.Lock()
	zd.wsIxfrEpochReset = true
	zd.workingSet = map[string]*OwnerData{}
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
	leaked := zd.wsIxfrEpochReset
	zd.mu.Unlock()
	if leaked {
		t.Fatal("refused publish left wsIxfrEpochReset set")
	}
	if len(chainOf(zd)) != 1 {
		t.Fatalf("refused publish must not touch the served chain, got %d links", len(chainOf(zd)))
	}

	// The next ordinary incremental publish must EXTEND the chain, not wipe it.
	stageAndPublish(t, zd, stageAddA(t, zd, "two.example.test.", "192.0.2.12"))
	if got := chainOf(zd); len(got) != 2 {
		t.Fatalf("stale epoch reset leaked into an unrelated publish: got %d links, want 2", len(got))
	}
}

func TestIxfrChain_InstallInitialSnapshotResets(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	zd.mu.Lock()
	zd.IxfrChain = append([]Ixfr(nil), zd.IxfrChain...) // ensure non-nil
	zd.mu.Unlock()

	// Re-baseline from zd.Data (the restart / test-utility path).
	zd.InstallInitialSnapshot()

	if got := chainOf(zd); len(got) != 0 {
		t.Fatalf("InstallInitialSnapshot must reset the chain, got %d links", len(got))
	}
}

func TestIxfrChain_ByteBudgetTrimsOldest(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	// Budget fits roughly one small link (two bracket SOAs ~ 2x86B + one A
	// ~ 205B estimated) but not two.
	zd.ixfrChainMaxBytes = 300

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	first := chainOf(zd)
	if len(first) != 1 {
		t.Fatalf("expected 1 link within budget, got %d", len(first))
	}
	stageAndPublish(t, zd, stageAddA(t, zd, "two.example.test.", "192.0.2.12"))

	chain := chainOf(zd)
	if len(chain) != 1 {
		t.Fatalf("expected budget to trim to 1 link, got %d", len(chain))
	}
	if chain[0].FromSerial != 2 || chain[0].ToSerial != 3 {
		t.Fatalf("surviving link = %d->%d, want the newest (2->3)", chain[0].FromSerial, chain[0].ToSerial)
	}
}

func TestIxfrChain_OversizeSingleDeltaResets(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	zd.ixfrChainMaxBytes = 50 // smaller than even the two bracket SOAs

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	if got := chainOf(zd); len(got) != 0 {
		t.Fatalf("oversize single delta must reset the chain, got %d links", len(got))
	}
}

func TestIxfrChain_NegativeBudgetDisablesRetention(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	zd.ixfrChainMaxBytes = -1

	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	if got := chainOf(zd); len(got) != 0 {
		t.Fatalf("negative budget must disable retention, got %d links", len(got))
	}
}

// --- delta planning ---

func TestIxfrDeltaSteps(t *testing.T) {
	soa := func(serial uint32) *dns.SOA {
		return &dns.SOA{Hdr: dns.RR_Header{Name: "z.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Serial: serial}
	}
	link := func(from, to uint32) Ixfr {
		return Ixfr{FromSerial: from, ToSerial: to, FromSOA: soa(from), ToSOA: soa(to)}
	}
	snap := &zoneSnapshot{Serial: 4, IxfrChain: []Ixfr{link(1, 2), link(2, 3), link(3, 4)}}

	if steps, ok := ixfrDeltaSteps(snap, 1); !ok || len(steps) != 3 {
		t.Fatalf("from 1: ok=%v len=%d, want ok/3", ok, len(steps))
	}
	if steps, ok := ixfrDeltaSteps(snap, 3); !ok || len(steps) != 1 {
		t.Fatalf("from 3: ok=%v len=%d, want ok/1", ok, len(steps))
	}
	if _, ok := ixfrDeltaSteps(snap, 0); ok {
		t.Fatal("unknown serial must not plan a delta")
	}

	gap := &zoneSnapshot{Serial: 4, IxfrChain: []Ixfr{link(1, 2), link(3, 4)}}
	if _, ok := ixfrDeltaSteps(gap, 1); ok {
		t.Fatal("non-contiguous chain must not plan a delta")
	}
	// A gapped chain can still serve from AFTER the gap.
	if steps, ok := ixfrDeltaSteps(gap, 3); !ok || len(steps) != 1 {
		t.Fatalf("from 3 across gap start: ok=%v len=%d, want ok/1", ok, len(steps))
	}

	stale := &zoneSnapshot{Serial: 9, IxfrChain: []Ixfr{link(1, 2)}}
	if _, ok := ixfrDeltaSteps(stale, 1); ok {
		t.Fatal("chain tail != snapshot serial must not plan a delta")
	}

	nilSOA := &zoneSnapshot{Serial: 2, IxfrChain: []Ixfr{{FromSerial: 1, ToSerial: 2}}}
	if _, ok := ixfrDeltaSteps(nilSOA, 1); ok {
		t.Fatal("nil bracket SOAs must not plan a delta")
	}
}

// --- serving ---

func TestZoneTransferOut_IXFRUpToDate(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone) // serial 1
	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := ixfrClient(t, srv.addr, zd.ZoneName, 1)
	if err != nil {
		t.Fatalf("IXFR: %v", err)
	}
	if len(rrs) != 1 {
		t.Fatalf("up-to-date IXFR must answer a single SOA, got %d RRs: %v", len(rrs), rrs)
	}
	soa, ok := rrs[0].(*dns.SOA)
	if !ok || soa.Serial != 1 {
		t.Fatalf("expected SOA serial 1, got %v", rrs[0])
	}
}

func TestZoneTransferOut_IXFRClientAhead(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := ixfrClient(t, srv.addr, zd.ZoneName, 7)
	if err != nil {
		t.Fatalf("IXFR: %v", err)
	}
	if len(rrs) != 1 {
		t.Fatalf("client-ahead IXFR must answer a single SOA, got %d RRs", len(rrs))
	}
}

func TestZoneTransferOut_IXFRFallbackNoHistory(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone) // fresh zone: chain empty
	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := ixfrClient(t, srv.addr, zd.ZoneName, 0)
	if err != nil {
		t.Fatalf("IXFR: %v", err)
	}
	if len(rrs) < 5 {
		t.Fatalf("fallback must serve the full zone, got %d RRs", len(rrs))
	}
	if _, ok := rrs[0].(*dns.SOA); !ok {
		t.Fatalf("first RR must be SOA, got %T", rrs[0])
	}
	if _, ok := rrs[1].(*dns.SOA); ok {
		t.Fatal("second RR is SOA: response is not AXFR-shaped")
	}
	if _, ok := rrs[len(rrs)-1].(*dns.SOA); !ok {
		t.Fatalf("last RR must be SOA, got %T", rrs[len(rrs)-1])
	}
}

func TestZoneTransferOut_IXFRFallbackUnknownSerialWithHistory(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11")) // chain: 1->2
	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	// Serial 0 is older than current but not in the chain: full transfer.
	rrs, err := ixfrClient(t, srv.addr, zd.ZoneName, 0)
	if err != nil {
		t.Fatalf("IXFR: %v", err)
	}
	if len(rrs) < 5 {
		t.Fatalf("fallback must serve the full zone, got %d RRs", len(rrs))
	}
	if _, ok := rrs[1].(*dns.SOA); ok {
		t.Fatal("second RR is SOA: response is not AXFR-shaped")
	}
}

func TestZoneTransferOut_IXFRDeltaSingleStep(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone) // serial 1
	stageAndPublish(t, zd, func(z *ZoneData) {
		stageAddA(t, zd, "added.example.test.", "192.0.2.9")(z)
		z.stageDeleteLocked("www.example.test.", dns.TypeA)
	}) // serial 2

	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := ixfrClient(t, srv.addr, zd.ZoneName, 1)
	if err != nil {
		t.Fatalf("IXFR: %v", err)
	}
	// SOA(2) | SOA(1) www-A SOA(2) added-A | SOA(2)
	if len(rrs) != 6 {
		t.Fatalf("expected 6 RRs in the delta stream, got %d: %v", len(rrs), rrs)
	}
	if got, want := soaSerials(rrs), []uint32{2, 1, 2, 2}; !serialsEqual(got, want) {
		t.Fatalf("SOA serial sequence = %v, want %v", got, want)
	}
	if rrs[2].Header().Name != "www.example.test." || rrs[2].Header().Rrtype != dns.TypeA {
		t.Fatalf("removed section: got %v, want www.example.test. A", rrs[2])
	}
	if rrs[4].Header().Name != "added.example.test." || rrs[4].Header().Rrtype != dns.TypeA {
		t.Fatalf("added section: got %v, want added.example.test. A", rrs[4])
	}
}

func TestZoneTransferOut_IXFRDeltaMultiStep(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone) // serial 1
	stageAndPublish(t, zd, func(z *ZoneData) {
		stageAddA(t, zd, "added.example.test.", "192.0.2.9")(z)
		z.stageDeleteLocked("www.example.test.", dns.TypeA)
	}) // serial 2
	stageAndPublish(t, zd, stageAddA(t, zd, "second.example.test.", "192.0.2.10")) // serial 3

	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := ixfrClient(t, srv.addr, zd.ZoneName, 1)
	if err != nil {
		t.Fatalf("IXFR from 1: %v", err)
	}
	// SOA(3) | SOA(1) www-A SOA(2) added-A | SOA(2) SOA(3) second-A | SOA(3)
	if got, want := soaSerials(rrs), []uint32{3, 1, 2, 2, 3, 3}; !serialsEqual(got, want) {
		t.Fatalf("SOA serial sequence = %v, want %v", got, want)
	}
	if len(rrs) != 9 {
		t.Fatalf("expected 9 RRs, got %d: %v", len(rrs), rrs)
	}

	rrs, err = ixfrClient(t, srv.addr, zd.ZoneName, 2)
	if err != nil {
		t.Fatalf("IXFR from 2: %v", err)
	}
	// SOA(3) | SOA(2) SOA(3) second-A | SOA(3)
	if got, want := soaSerials(rrs), []uint32{3, 2, 3, 3}; !serialsEqual(got, want) {
		t.Fatalf("SOA serial sequence = %v, want %v", got, want)
	}
	if len(rrs) != 5 {
		t.Fatalf("expected 5 RRs, got %d: %v", len(rrs), rrs)
	}
}

func TestZoneTransferOut_IXFRDeltaSpansEnvelopes(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, func(z *ZoneData) {
		for i := 0; i < 80; i++ {
			owner := fmt.Sprintf("pad%d.example.test.", i)
			rr := mustRR(t, fmt.Sprintf("%s 60 IN TXT \"%s\"", owner, strings.Repeat("x", 900)))
			z.stageRRsetLocked(owner, core.RRset{
				Name: owner, Class: dns.ClassINET, RRtype: dns.TypeTXT, RRs: []dns.RR{rr},
			})
		}
	})

	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := ixfrClient(t, srv.addr, zd.ZoneName, 1)
	if err != nil {
		t.Fatalf("IXFR: %v", err)
	}
	if len(rrs) != 80+4 {
		t.Fatalf("expected 84 RRs (4 SOAs + 80 TXT), got %d", len(rrs))
	}
	if len(srv.sizes) < 2 {
		t.Fatalf("expected the delta to span multiple envelopes, got %d", len(srv.sizes))
	}
	assertTransferEnvelopeSizes(t, srv.sizes)
}

func TestZoneTransferOut_IXFRUDPSingleSOA(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11")) // serial 2, history exists

	w := &fakeRW{remote: udpAddr("127.0.0.1")}
	r := new(dns.Msg)
	r.SetIxfr(zd.ZoneName, 1, ".", ".")
	sent, err := zd.ZoneTransferOut(context.Background(), w, r, nil)
	if err != nil {
		t.Fatalf("ZoneTransferOut: %v", err)
	}
	if sent != 1 {
		t.Fatalf("expected 1 RR sent over UDP, got %d", sent)
	}
	if w.written == nil || len(w.written.Answer) != 1 {
		t.Fatalf("expected a single-SOA answer, got %v", w.written)
	}
	soa, ok := w.written.Answer[0].(*dns.SOA)
	if !ok || soa.Serial != 2 {
		t.Fatalf("expected SOA serial 2, got %v", w.written.Answer[0])
	}
}

// failingRW is a fakeRW whose WriteMsg always errors, for asserting that
// single-message reply paths propagate transport write failures.
type failingRW struct {
	fakeRW
	writeErr error
}

func (f *failingRW) WriteMsg(m *dns.Msg) error { return f.writeErr }

func TestZoneTransferOut_IXFRSingleSOAWriteErrorPropagates(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)

	w := &failingRW{fakeRW: fakeRW{remote: udpAddr("127.0.0.1")}, writeErr: fmt.Errorf("boom")}
	r := new(dns.Msg)
	r.SetIxfr(zd.ZoneName, 1, ".", ".") // up-to-date: single-SOA reply path
	sent, err := zd.ZoneTransferOut(context.Background(), w, r, nil)
	if err == nil {
		t.Fatal("expected the WriteMsg failure to propagate, got nil error")
	}
	if sent != 0 {
		t.Fatalf("expected 0 RRs reported on write failure, got %d", sent)
	}
}

func TestZoneTransferOut_IXFRNoSOAInQueryServesFullZone(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	// Hand-rolled malformed IXFR query: no SOA in the authority section.
	q := new(dns.Msg)
	q.SetQuestion(zd.ZoneName, dns.TypeIXFR)
	c := &dns.Client{Net: "tcp"}
	in, _, err := c.Exchange(q, srv.addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(in.Answer) < 5 {
		t.Fatalf("expected the full zone in one message, got %d RRs", len(in.Answer))
	}
	if _, ok := in.Answer[0].(*dns.SOA); !ok {
		t.Fatalf("first RR must be SOA, got %T", in.Answer[0])
	}
}

func TestZoneTransferOut_IXFRDeltaTSIG(t *testing.T) {
	conf := testXfrConf(t)
	zd := loadIxfrTestZone(t, basicZone)
	zd.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: "tkey"}}
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11")) // serial 2

	srv := startTestAXFRServerTSIG(t, zd, conf)
	defer srv.shutdown()

	rrs, err := ixfrClientTSIG(t, conf, srv.addr, zd.ZoneName, "tkey", 1)
	if err != nil {
		t.Fatalf("IXFR/TSIG: %v", err)
	}
	// SOA(2) | SOA(1) SOA(2) one-A | SOA(2)
	if got, want := soaSerials(rrs), []uint32{2, 1, 2, 2}; !serialsEqual(got, want) {
		t.Fatalf("SOA serial sequence = %v, want %v", got, want)
	}
}

func TestZoneTransferOut_IXFRUpToDateTSIG(t *testing.T) {
	conf := testXfrConf(t)
	zd := loadIxfrTestZone(t, basicZone)
	zd.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: "tkey"}}

	srv := startTestAXFRServerTSIG(t, zd, conf)
	defer srv.shutdown()

	rrs, err := ixfrClientTSIG(t, conf, srv.addr, zd.ZoneName, "tkey", 1)
	if err != nil {
		t.Fatalf("IXFR/TSIG: %v", err)
	}
	if len(rrs) != 1 {
		t.Fatalf("up-to-date IXFR must answer a single SOA, got %d RRs", len(rrs))
	}
}

// AXFR must be wholly unaffected by the presence of IXFR history.
func TestZoneTransferOut_AXFRIgnoresChain(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))

	srv := startTestAXFRServer(t, zd)
	defer srv.shutdown()

	rrs, err := axfrClient(t, srv.addr, zd.ZoneName)
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	if got := soaSerials(rrs); len(got) != 2 || got[0] != 2 || got[1] != 2 {
		t.Fatalf("AXFR SOA serials = %v, want [2 2]", got)
	}
	for _, rr := range rrs[1 : len(rrs)-1] {
		if rr.Header().Rrtype == dns.TypeSOA {
			t.Fatalf("AXFR body contains an SOA: %v", rr)
		}
	}
}
