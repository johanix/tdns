package tdns

import (
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
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
		t.Fatal("missing www owner in legacy store")
	}
	a := owner.RRtypes.GetOnlyRRSet(dns.TypeA)
	if len(a.RRs) == 0 || a.RRs[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatalf("legacy store mutated during staging: %v", a.RRs)
	}
}

func TestDualWriteConsistency(t *testing.T) {
	zone := `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
`
	zd := testSnapshotZone(t, "example.", zone)
	if !zd.legacyMatchesSnapshot() {
		t.Fatal("initial dual-write mismatch")
	}

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.99"))
	zd.mu.Unlock()
	zd.testPublishNow()

	if !zd.legacyMatchesSnapshot() {
		t.Fatal("dual-write mismatch after publish")
	}
	if zd.CurrentSerial != 2 {
		t.Fatalf("serial = %d, want 2", zd.CurrentSerial)
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
