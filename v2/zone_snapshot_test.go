package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func testSnapshotZone(t *testing.T, name, zoneStr string) *ZoneData {
	t.Helper()
	zd := &ZoneData{
		ZoneName:  name,
		ZoneStore: MapZone,
		Logger:    log.New(os.Stderr, "", 0),
	}
	if _, _, err := zd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	Zones.Set(name, zd)
	t.Cleanup(func() { Zones.Remove(name) })
	zd.InstallInitialSnapshot()
	return zd
}

func TestSnapshotImmutability(t *testing.T) {
	zone := `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
`
	zd := testSnapshotZone(t, "example.", zone)
	before := zd.snapshot.Load()
	if before == nil {
		t.Fatal("expected initial snapshot")
	}

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.2"))
	zd.mu.Unlock()

	after := zd.snapshot.Load()
	if after != before {
		t.Fatal("published snapshot pointer changed without publish")
	}
	owner, _ := zd.GetOwner("www.example.")
	if owner == nil {
		t.Fatal("missing www owner in published snapshot")
	}
	a := owner.RRtypes.GetOnlyRRSet(dns.TypeA)
	if len(a.RRs) == 0 || a.RRs[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatalf("published snapshot mutated during staging: %v", a.RRs)
	}
}

func TestPublishedSnapshotAfterPublish(t *testing.T) {
	zone := `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
`
	zd := testSnapshotZone(t, "example.", zone)

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.99"))
	zd.mu.Unlock()
	zd.testPublishNow()

	owner, err := zd.GetOwner("www.example.")
	if err != nil || owner == nil {
		t.Fatal("missing www owner after publish")
	}
	a := owner.RRtypes.GetOnlyRRSet(dns.TypeA)
	if len(a.RRs) == 0 || a.RRs[0].(*dns.A).A.String() != "192.0.2.99" {
		t.Fatalf("published A = %v, want 192.0.2.99", a.RRs)
	}
	if zd.CurrentSerial != 2 {
		t.Fatalf("serial = %d, want 2", zd.CurrentSerial)
	}
	snap := zd.snapshot.Load()
	if snap == nil || snap.Serial != 2 {
		t.Fatalf("snapshot serial = %v, want 2", snap)
	}
}

func TestCurrentSerialMatchesSnapshot(t *testing.T) {
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
www.example. 3600 IN A 192.0.2.1
`)
	if snap := zd.snapshot.Load(); snap == nil || snap.Serial != zd.CurrentSerial {
		t.Fatalf("initial serial mirror drift: snap=%v current=%d", snap, zd.CurrentSerial)
	}

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.55"))
	zd.mu.Unlock()
	zd.testPublishNow()

	snap := zd.snapshot.Load()
	if snap == nil || snap.Serial != zd.CurrentSerial || snap.Serial != 2 {
		t.Fatalf("post-publish serial mirror drift: snap=%v current=%d", snap, zd.CurrentSerial)
	}
	if soa := snap.SOA; soa == nil || soa.Serial != snap.Serial {
		t.Fatalf("SOA serial != snapshot serial: soa=%v snap=%d", soa, snap.Serial)
	}
}

func TestInitialSnapshotBeforeReady(t *testing.T) {
	zd := &ZoneData{
		ZoneName:      "example.",
		ZoneStore:     MapZone,
		Logger:        log.New(os.Stderr, "", 0),
		CurrentSerial: 1,
	}
	if _, _, err := zd.ReadZoneData(`example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
`, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	if zd.Ready {
		t.Fatal("Ready before InstallInitialSnapshot")
	}
	zd.InstallInitialSnapshot()
	if !zd.Ready {
		t.Fatal("Ready not set after InstallInitialSnapshot")
	}
	if zd.snapshot.Load() == nil {
		t.Fatal("snapshot not installed")
	}
}

func TestPublishCoalescing(t *testing.T) {
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
www.example. 3600 IN A 192.0.2.1
`)
	zd.publishCadence = 200 * time.Millisecond

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.2"))
	zd.mu.Unlock()
	zd.requestPublish(false)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if zd.snapshotGeneration() == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	first := zd.snapshotGeneration()
	if first != 2 {
		t.Fatalf("first publish serial = %d, want 2", first)
	}

	for i := 0; i < 5; i++ {
		zd.mu.Lock()
		zd.ensureWorkingSet()
		zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, fmt.Sprintf("192.0.2.%d", 10+i)))
		zd.mu.Unlock()
		zd.requestPublish(false)
		time.Sleep(15 * time.Millisecond)
	}

	time.Sleep(350 * time.Millisecond)
	second := zd.snapshotGeneration()
	if second != first+1 {
		t.Fatalf("coalesced publishes: serial went %d -> %d, want one bump", first, second)
	}

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.99"))
	zd.mu.Unlock()
	zd.requestPublish(true)
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if zd.snapshotGeneration() == second+1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("urgent publish did not bump serial from %d", second)
}

func TestPublishGenerationGuard(t *testing.T) {
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
`)

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.1"))
	staleGen := zd.generation.Load()
	zd.generation.Add(1)
	zd.publishLocked(staleGen)
	zd.mu.Unlock()

	if zd.workingSet != nil {
		t.Fatal("working set should be cleared when generation guard drops publish")
	}
	if zd.snapshotGeneration() != 1 {
		t.Fatalf("serial = %d, want 1 (publish dropped)", zd.snapshotGeneration())
	}
}

func TestParsePublishCadence(t *testing.T) {
	d, err := parsePublishCadence("")
	if err != nil || d != DefaultPublishCadence {
		t.Fatalf("default: d=%v err=%v", d, err)
	}
	if _, err := parsePublishCadence("500ms"); err == nil {
		t.Fatal("expected error for sub-1s cadence")
	}
	d, err = parsePublishCadence("10s")
	if err != nil || d != 10*time.Second {
		t.Fatalf("10s: d=%v err=%v", d, err)
	}
}

func TestPendingChanges(t *testing.T) {
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
www.example. 3600 IN A 192.0.2.1
`)
	serialBefore := zd.snapshotGeneration()

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.50"))
	zd.mu.Unlock()

	pc := zd.pendingChanges()
	if pc == nil {
		t.Fatal("expected pending changes after staging")
	}
	if pc.PublishedSerial != serialBefore {
		t.Fatalf("published serial = %d, want %d", pc.PublishedSerial, serialBefore)
	}
	if len(pc.Replaced) != 1 || pc.Replaced[0].Owner != "www.example." {
		t.Fatalf("replaced = %+v, want www.example.", pc.Replaced)
	}

	zd.testPublishNow()
	if pc2 := zd.pendingChanges(); pc2 != nil {
		t.Fatalf("expected nil pending changes after publish, got %+v", pc2)
	}
	if zd.snapshotGeneration() != serialBefore+1 {
		t.Fatalf("serial = %d, want %d", zd.snapshotGeneration(), serialBefore+1)
	}

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRset("new.example.", coreRRset("new.example.", dns.TypeA, "192.0.2.2"))
	zd.mu.Unlock()
	pc = zd.pendingChanges()
	if pc == nil || len(pc.Added) != 1 || pc.Added[0] != "new.example." {
		t.Fatalf("added = %+v, want new.example.", pc)
	}
}

func TestConcurrentServeAndUpdate(t *testing.T) {
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
www.example. 3600 IN A 192.0.2.1
`)
	zd.publishCadence = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				owner, err := zd.GetOwner("www.example.")
				if err != nil || owner == nil {
					continue
				}
				_ = owner.RRtypes.GetOnlyRRSet(dns.TypeA)
			}
		}()
	}

	for i := 0; i < 30; i++ {
		zd.mu.Lock()
		zd.ensureWorkingSet()
		zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, fmt.Sprintf("192.0.2.%d", 20+i%80)))
		zd.mu.Unlock()
		if i%5 == 0 {
			zd.requestPublish(true)
		} else {
			zd.requestPublish(false)
		}
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			zd.mu.Lock()
			idle := zd.workingSet == nil
			zd.mu.Unlock()
			if !idle {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			snap := zd.snapshot.Load()
			if snap == nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if snap.Serial != zd.snapshotGeneration() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			got, err := zd.GetOwner("www.example.")
			if err != nil || got == nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			snapOwner := snap.Data["www.example."]
			if snapOwner == nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			aSnap := snapOwner.RRtypes.GetOnlyRRSet(dns.TypeA)
			aGet := got.RRtypes.GetOnlyRRSet(dns.TypeA)
			if len(aSnap.RRs) > 0 && len(aGet.RRs) > 0 &&
				aSnap.RRs[0].(*dns.A).A.String() == aGet.RRs[0].(*dns.A).A.String() {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		snap := zd.snapshot.Load()
		got, err := zd.GetOwner("www.example.")
		if snap == nil || err != nil || got == nil {
			t.Fatalf("snapshot reader mismatch after publish cycle %d", i)
		}
		snapOwner := snap.Data["www.example."]
		if snapOwner == nil {
			t.Fatalf("missing www in snapshot after publish cycle %d", i)
		}
		aSnap := snapOwner.RRtypes.GetOnlyRRSet(dns.TypeA)
		aGet := got.RRtypes.GetOnlyRRSet(dns.TypeA)
		if len(aSnap.RRs) == 0 || len(aGet.RRs) == 0 ||
			aSnap.RRs[0].(*dns.A).A.String() != aGet.RRs[0].(*dns.A).A.String() {
			t.Fatalf("GetOwner != snapshot after publish cycle %d", i)
		}
		if snap.Serial != zd.snapshotGeneration() {
			t.Fatalf("serial invariant broken after publish cycle %d: snap=%d gen=%d", i, snap.Serial, zd.snapshotGeneration())
		}
	}

	cancel()
	wg.Wait()
}

// TestQueryResponderNoIntraResponseTearing (m3) drives the real QueryResponder
// under concurrent publishes and asserts that a single response is internally
// consistent: the publisher keeps www.example. A and the apex-NS glue
// (ns.example. A) in lockstep, so within any one published snapshot they carry
// the same octet. A response therefore has matching answer/glue octets only if
// the whole response is served from ONE pinned snapshot (C1). Before C1 the
// answer and the glue were independent snapshot loads and could straddle two
// publishes.
func TestQueryResponderNoIntraResponseTearing(t *testing.T) {
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 10.0.0.1
www.example. 3600 IN A 10.0.0.1
`)
	zd.publishCadence = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for v := 2; ctx.Err() == nil; v++ {
			ip := fmt.Sprintf("10.0.0.%d", v%250+1)
			zd.mu.Lock()
			zd.ensureWorkingSet()
			zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, ip))
			zd.stageRRset("ns.example.", coreRRset("ns.example.", dns.TypeA, ip))
			zd.mu.Unlock()
			zd.requestPublish(true)
			time.Sleep(time.Millisecond)
		}
	}()

	msgo := &edns0.MsgOptions{}
	checks := 0
	for i := 0; i < 5000 && ctx.Err() == nil; i++ {
		req := new(dns.Msg)
		req.SetQuestion("www.example.", dns.TypeA)
		rw := &fakeRW{}
		if err := zd.QueryResponder(ctx, rw, req, "www.example.", dns.TypeA, msgo, nil, nil); err != nil {
			continue
		}
		resp := rw.written
		if resp == nil {
			continue
		}
		ans := lastOctetOf(resp.Answer, "www.example.")
		glue := lastOctetOf(resp.Extra, "ns.example.")
		if ans < 0 || glue < 0 {
			continue
		}
		checks++
		if ans != glue {
			t.Fatalf("intra-response tearing: answer www A .%d != authority glue ns A .%d", ans, glue)
		}
	}
	cancel()
	wg.Wait()
	if checks == 0 {
		t.Fatal("test exercised no comparable responses (answer+glue never both present)")
	}
}

func lastOctetOf(rrs []dns.RR, name string) int {
	for _, rr := range rrs {
		a, ok := rr.(*dns.A)
		if !ok || a.Hdr.Name != name {
			continue
		}
		if ip := a.A.To4(); ip != nil {
			return int(ip[3])
		}
	}
	return -1
}

func coreRRset(name string, rrtype uint16, ip string) core.RRset {
	if rrtype == dns.TypeA {
		return core.RRset{
			Name:   name,
			Class:  dns.ClassINET,
			RRtype: dns.TypeA,
			RRs: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP(ip).To4(),
			}},
		}
	}
	return core.RRset{}
}
