package tdns

import (
	"context"
	"errors"
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
	t.Cleanup(zd.stopPublisher)
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

// TestQueryServfailForUnsignedMustBeSignedZone is the regression test for
// Finding 1 / Decision 1: a zone that MUST be signed (online/inline-signing) but
// whose published snapshot carries no RRSIGs for a served RRset is broken. A DO
// query must SERVFAIL rather than ephemeral-sign the answer (which masked the
// failure — the zone looked signed to DO queries while its AXFR was unsigned) or
// serve it unsigned (a silent downgrade).
func TestQueryServfailForUnsignedMustBeSignedZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "broken.example.", `broken.example. 3600 IN SOA ns.broken.example. hostmaster.broken.example. 1 7200 1800 604800 7200
broken.example. 3600 IN NS ns.broken.example.
ns.broken.example. 3600 IN A 10.0.0.1
www.broken.example. 3600 IN A 10.0.0.2
`)
	// The zone must be signed, but nothing in the snapshot is signed (SignZone
	// never ran / failed) — a broken signed zone.
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.KeyDB = kdb

	ctx := context.Background()

	// A DO query for the stored, unsigned A RRset must SERVFAIL...
	req := new(dns.Msg)
	req.SetQuestion("www.broken.example.", dns.TypeA)
	rw := &fakeRW{}
	if err := zd.QueryResponder(ctx, rw, req, "www.broken.example.", dns.TypeA, &edns0.MsgOptions{DO: true}, kdb, nil); err != nil {
		t.Fatalf("QueryResponder (DO): %v", err)
	}
	resp := rw.written
	if resp == nil {
		t.Fatal("no response written for DO query")
	}
	if resp.MsgHdr.Rcode != dns.RcodeServerFailure {
		t.Fatalf("DO query on a broken signed zone: expected SERVFAIL, got %s", dns.RcodeToString[resp.MsgHdr.Rcode])
	}
	// ...and must NOT serve a fabricated RRSIG.
	for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
		if _, ok := rr.(*dns.RRSIG); ok {
			t.Fatalf("SERVFAIL must not carry a synthesized RRSIG: %s", rr.String())
		}
	}

	// Control: without DO, the same unsigned data answers normally (NOERROR) —
	// an unsigned answer is fine when DNSSEC is not requested.
	req2 := new(dns.Msg)
	req2.SetQuestion("www.broken.example.", dns.TypeA)
	rw2 := &fakeRW{}
	if err := zd.QueryResponder(ctx, rw2, req2, "www.broken.example.", dns.TypeA, &edns0.MsgOptions{}, kdb, nil); err != nil {
		t.Fatalf("QueryResponder (non-DO): %v", err)
	}
	if rw2.written == nil || rw2.written.MsgHdr.Rcode != dns.RcodeSuccess {
		t.Fatalf("non-DO query should be NOERROR, got %+v", rw2.written)
	}
	if len(rw2.written.Answer) == 0 {
		t.Fatal("non-DO query should still carry the A answer")
	}
}

// TestSignRRsetForZoneBrokenZone locks the two branches of signRRsetForZone's
// must-be-signed / no-stored-RRSIG decision directly: a stored RRset yields
// ErrZoneUnsigned (→ SERVFAIL) with no fabricated signature, while the
// synthesized-denial NSEC carve-out (the one legitimate query-time ephemeral
// case) is preserved.
func TestSignRRsetForZoneBrokenZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := &ZoneData{
		ZoneName: "broken.example.",
		Options:  map[ZoneOption]bool{OptOnlineSigning: true},
		Logger:   log.New(os.Stderr, "", 0),
	}

	a, err := dns.NewRR("www.broken.example. 3600 IN A 10.0.0.2")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	stored := core.RRset{RRtype: dns.TypeA, RRs: []dns.RR{a}}

	// Stored, unsigned RRset on a must-be-signed zone → ErrZoneUnsigned, no
	// fabricated signature.
	got, err := zd.signRRsetForZone(stored, "www.broken.example.", &edns0.MsgOptions{DO: true}, kdb, nil)
	if !errors.Is(err, ErrZoneUnsigned) {
		t.Fatalf("stored unsigned RRset on a must-be-signed zone: want ErrZoneUnsigned, got %v", err)
	}
	if len(got.RRSIGs) != 0 {
		t.Fatalf("broken-zone path must not fabricate a signature, got %d RRSIG(s)", len(got.RRSIGs))
	}

	// Non-DO query returns the RRset unsigned without error (DNSSEC not asked).
	if _, err := zd.signRRsetForZone(stored, "www.broken.example.", &edns0.MsgOptions{}, kdb, nil); err != nil {
		t.Fatalf("non-DO signRRsetForZone should not error, got %v", err)
	}

	// The synthesized-denial carve-out: an NSEC is exempt from the broken-zone
	// SERVFAIL (it is signed on the fly), a stored A RRset is not.
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "broken.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "\000.broken.example.",
		TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG, dns.TypeNXNAME},
	}
	if !isSynthesizedDenial(core.RRset{RRs: []dns.RR{nsec}}) {
		t.Fatal("a synthesized NSEC must be treated as ephemeral-signable")
	}
	if isSynthesizedDenial(stored) {
		t.Fatal("a stored A RRset must not be treated as ephemeral")
	}
}

// answerHasRRSIG reports whether any RRSIG (optionally covering a specific type,
// 0 = any) sits in the Answer section.
func answerHasRRSIG(m *dns.Msg, typeCovered uint16) bool {
	for _, rr := range m.Answer {
		if s, ok := rr.(*dns.RRSIG); ok {
			if typeCovered == 0 || s.TypeCovered == typeCovered {
				return true
			}
		}
	}
	return false
}

// answerHasA reports whether the Answer section carries an A RR with the given
// owner name.
func answerHasA(m *dns.Msg, owner string) bool {
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok && a.Hdr.Name == owner {
			return true
		}
	}
	return false
}

// TestWildcardAnswerFailClosed extends Finding 1 / Decision 1 to the wildcard-
// answer path. A wildcard match (qname != origqname) builds its answer via
// WildcardReplace and previously served stored RRSIGs directly, bypassing the
// must-be-signed fail-closed check that the exact-match arm performs. A broken
// (must-be-signed, unsigned) zone therefore served a wildcard-covered name
// UNSIGNED — a silent downgrade. The wildcard arm must now SERVFAIL exactly like
// the exact-match arm, while genuinely-signed and unsigned-by-design wildcards
// keep answering.
func TestWildcardAnswerFailClosed(t *testing.T) {
	ctx := context.Background()

	// Case 1: broken zone — must be signed, but nothing carries RRSIGs. A DO
	// query for a wildcard-covered name must SERVFAIL, with no fabricated RRSIG.
	t.Run("broken_wildcard_servfail", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := testSnapshotZone(t, "broken-wild.example.", `broken-wild.example. 3600 IN SOA ns.broken-wild.example. hostmaster.broken-wild.example. 1 7200 1800 604800 7200
broken-wild.example. 3600 IN NS ns.broken-wild.example.
ns.broken-wild.example. 3600 IN A 10.0.0.1
*.broken-wild.example. 3600 IN A 10.0.0.5
`)
		zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
		zd.KeyDB = kdb

		req := new(dns.Msg)
		req.SetQuestion("nothere.broken-wild.example.", dns.TypeA)
		rw := &fakeRW{}
		if err := zd.QueryResponder(ctx, rw, req, "nothere.broken-wild.example.", dns.TypeA, &edns0.MsgOptions{DO: true}, kdb, nil); err != nil {
			t.Fatalf("QueryResponder (DO wildcard): %v", err)
		}
		resp := rw.written
		if resp == nil {
			t.Fatal("no response written for DO wildcard query")
		}
		if resp.MsgHdr.Rcode != dns.RcodeServerFailure {
			t.Fatalf("broken-zone wildcard DO query: expected SERVFAIL, got %s", dns.RcodeToString[resp.MsgHdr.Rcode])
		}
		for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
			if _, ok := rr.(*dns.RRSIG); ok {
				t.Fatalf("SERVFAIL must not carry a synthesized RRSIG: %s", rr.String())
			}
			if _, ok := rr.(*dns.A); ok {
				t.Fatalf("SERVFAIL must not serve the unsigned wildcard answer: %s", rr.String())
			}
		}
	})

	// Case 2: healthy signed zone — the wildcard RRset carries a stored RRSIG. A
	// DO query for a covered name must answer NOERROR with the wildcard-replaced
	// A record and its wildcard-replaced RRSIG, both owned by the queried name.
	t.Run("signed_wildcard_answers", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := testSnapshotZone(t, "signed-wild.example.", `signed-wild.example. 3600 IN SOA ns.signed-wild.example. hostmaster.signed-wild.example. 1 7200 1800 604800 7200
signed-wild.example. 3600 IN NS ns.signed-wild.example.
ns.signed-wild.example. 3600 IN A 10.0.0.1
*.signed-wild.example. 3600 IN A 10.0.0.5
*.signed-wild.example. 3600 IN RRSIG A 13 2 3600 20260801000000 20260701000000 12345 signed-wild.example. AwEAAcBadDummySignatureBytesForTestingWildcardRRSIGPresence0000000000000000000000000000AA==
`)
		zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
		zd.KeyDB = kdb

		req := new(dns.Msg)
		req.SetQuestion("host.signed-wild.example.", dns.TypeA)
		rw := &fakeRW{}
		if err := zd.QueryResponder(ctx, rw, req, "host.signed-wild.example.", dns.TypeA, &edns0.MsgOptions{DO: true}, kdb, nil); err != nil {
			t.Fatalf("QueryResponder (DO signed wildcard): %v", err)
		}
		resp := rw.written
		if resp == nil {
			t.Fatal("no response written for signed wildcard query")
		}
		if resp.MsgHdr.Rcode != dns.RcodeSuccess {
			t.Fatalf("signed wildcard DO query: expected NOERROR, got %s", dns.RcodeToString[resp.MsgHdr.Rcode])
		}
		if !answerHasA(resp, "host.signed-wild.example.") {
			t.Fatalf("signed wildcard answer missing A owned by the queried name; answer=%v", resp.Answer)
		}
		if !answerHasRRSIG(resp, dns.TypeA) {
			t.Fatalf("signed wildcard answer must carry the (wildcard-replaced) A RRSIG; answer=%v", resp.Answer)
		}
		// The wildcard-replaced RRSIG must be re-owned by the queried name.
		for _, rr := range resp.Answer {
			if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeA && s.Hdr.Name != "host.signed-wild.example." {
				t.Fatalf("wildcard A RRSIG owner = %s, want host.signed-wild.example.", s.Hdr.Name)
			}
		}
	})

	// Case 3: unsigned-by-design zone — no signing configured. A DO query for a
	// wildcard-covered name still answers NOERROR, served unsigned (as before);
	// the fail-closed check applies only to must-be-signed zones.
	t.Run("unsigned_wildcard_answers", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := testSnapshotZone(t, "plain-wild.example.", `plain-wild.example. 3600 IN SOA ns.plain-wild.example. hostmaster.plain-wild.example. 1 7200 1800 604800 7200
plain-wild.example. 3600 IN NS ns.plain-wild.example.
ns.plain-wild.example. 3600 IN A 10.0.0.1
*.plain-wild.example. 3600 IN A 10.0.0.5
`)
		// No OptOnlineSigning / OptInlineSigning — legitimately unsigned.
		zd.KeyDB = kdb

		req := new(dns.Msg)
		req.SetQuestion("host.plain-wild.example.", dns.TypeA)
		rw := &fakeRW{}
		if err := zd.QueryResponder(ctx, rw, req, "host.plain-wild.example.", dns.TypeA, &edns0.MsgOptions{DO: true}, kdb, nil); err != nil {
			t.Fatalf("QueryResponder (DO unsigned wildcard): %v", err)
		}
		resp := rw.written
		if resp == nil {
			t.Fatal("no response written for unsigned wildcard query")
		}
		if resp.MsgHdr.Rcode != dns.RcodeSuccess {
			t.Fatalf("unsigned-by-design wildcard DO query: expected NOERROR, got %s", dns.RcodeToString[resp.MsgHdr.Rcode])
		}
		if !answerHasA(resp, "host.plain-wild.example.") {
			t.Fatalf("unsigned wildcard answer missing A owned by the queried name; answer=%v", resp.Answer)
		}
		if answerHasRRSIG(resp, 0) {
			t.Fatalf("unsigned-by-design zone must not fabricate an RRSIG; answer=%v", resp.Answer)
		}
	})
}
