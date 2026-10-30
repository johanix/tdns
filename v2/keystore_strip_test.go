package tdns

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// rrsigTags counts the RRSIGs in data by keytag.
func rrsigTags(data map[string]*OwnerData) map[uint16]int {
	tags := map[uint16]int{}
	for _, owner := range data {
		if owner == nil {
			continue
		}
		for _, rrt := range owner.RRtypes.Keys() {
			for _, sig := range owner.RRtypes.GetOnlyRRSet(rrt).RRSIGs {
				if s, ok := sig.(*dns.RRSIG); ok {
					tags[s.KeyTag]++
				}
			}
		}
	}
	return tags
}

// servedRRSIGTags counts the RRSIGs zd serves by keytag.
func servedRRSIGTags(zd *ZoneData) map[uint16]int {
	snap := zd.snapshot.Load()
	if snap == nil {
		return map[uint16]int{}
	}
	return rrsigTags(snap.Data)
}

// stagedRRSIGTags counts the RRSIGs in zd's working set by keytag; nil when
// nothing is staged.
func stagedRRSIGTags(zd *ZoneData) map[uint16]int {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.workingSet == nil {
		return nil
	}
	return rrsigTags(zd.workingSet)
}

func countRRSIGs(tags map[uint16]int) int {
	n := 0
	for _, c := range tags {
		n += c
	}
	return n
}

func servesNoneOf(zd *ZoneData, tags map[uint16]int) bool {
	served := servedRRSIGTags(zd)
	for tag := range tags {
		if served[tag] > 0 {
			return false
		}
	}
	return true
}

// idleZone makes zd's next publish run in its writer, as on a zone that has
// not published within its cadence: the case where clear's and
// policy-cleanup's publish ran inside their keystore transaction.
func idleZone(zd *ZoneData) {
	zd.mu.Lock()
	zd.lastPublish = time.Now().Add(-time.Hour)
	zd.mu.Unlock()
}

// checkSerialRecorded fails unless zd's current serial is the one recorded in
// the keystore, with no warning that a record failed.
func checkSerialRecorded(t *testing.T, kdb *KeyDB, zd *ZoneData) {
	t.Helper()
	zd.mu.Lock()
	cur := zd.CurrentSerial
	warn, warned := zd.Errors[ConfigWarning]
	zd.mu.Unlock()
	if warned && strings.HasPrefix(warn.Msg, serialRecordWarning) {
		t.Errorf("the published serial was not recorded: %s", warn.Msg)
	}
	rec, err := kdb.LoadOutgoingSerial(zd.ZoneName)
	if err != nil || rec != cur {
		t.Errorf("recorded serial %d (err %v), want the published %d", rec, err, cur)
	}
}

// expireHold makes the zone's open transactions run out now, as if their limit
// had passed: the hold's release runs at once, in the timer's goroutine.
func expireHold(zd *ZoneData) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	for _, tx := range zd.tx.open {
		tx.start = time.Now().Add(-tx.limit)
	}
	zd.txStopTimerLocked()
	zd.txArmTimerLocked()
}

func clearPost(zone string) KeystorePost {
	return KeystorePost{Command: "dnssec-mgmt", SubCommand: "clear", Zone: zone}
}

// TestClearPublishesItsStripAfterTheCommit: clear's strip used to publish
// inside clear's keystore transaction, and the publish's write of its serial
// waited for that transaction until the busy timeout (5 s), then failed with
// "database is locked" (#985).
func TestClearPublishesItsStripAfterTheCommit(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	old := servedRRSIGTags(zd)
	if len(old) == 0 {
		t.Fatal("the test zone serves no RRSIGs")
	}
	idleZone(zd)

	start := time.Now()
	resp, err := kdb.DnssecKeyMgmt(context.Background(), nil, clearPost(zd.ZoneName))
	took := time.Since(start)
	if err != nil || resp.Error {
		t.Fatalf("clear: %v %s", err, resp.ErrorMsg)
	}
	if took > 2*time.Second {
		t.Errorf("clear took %v: its publish waited for its own keystore transaction", took)
	}
	waitFor(t, 5*time.Second, "the strip to be published", func() bool { return servesNoneOf(zd, old) })
	checkSerialRecorded(t, kdb, zd)
}

// TestPolicyCleanupStripsEveryRetiredKeyInOnePublish: policy-cleanup stripped
// and published each retired key's RRSIGs inside its keystore transaction, so
// its publish waited there too (#985). Now one strip, published after the
// commit, takes all of them.
func TestPolicyCleanupStripsEveryRetiredKeyInOnePublish(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	// Enough signature validity that the zone may be signed again.
	zd.DnssecPolicy.SigValidity = PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400}
	zd.ClearError(DnssecError)

	// Two more active ZSKs, which sign the zone, then retire.
	retired := map[uint16]int{}
	for range 2 {
		pkc, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil)
		if err != nil {
			t.Fatalf("generate a ZSK: %v", err)
		}
		retired[pkc.KeyId] = 0
	}
	if err := republishSigningKeysForZone(kdb, zd.ZoneName); err != nil {
		t.Fatalf("republish the signing keys: %v", err)
	}
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	served := servedRRSIGTags(zd)
	for tag := range retired {
		if served[tag] == 0 {
			t.Fatalf("key %d signs nothing in the served zone", tag)
		}
		if err := UpdateDnssecKeyState(kdb, zd.ZoneName, tag, DnskeyStateRetired); err != nil {
			t.Fatalf("retire key %d: %v", tag, err)
		}
	}
	idleZone(zd)

	start := time.Now()
	resp, err := kdb.DnssecKeyMgmt(context.Background(), nil,
		KeystorePost{Command: "dnssec-mgmt", SubCommand: "policy-cleanup", Zone: zd.ZoneName})
	took := time.Since(start)
	if err != nil || resp.Error {
		t.Fatalf("policy-cleanup: %v %s", err, resp.ErrorMsg)
	}
	if took > 2*time.Second {
		t.Errorf("policy-cleanup took %v: its publish waited for its own keystore transaction", took)
	}
	waitFor(t, 5*time.Second, "the strip to be published", func() bool { return servesNoneOf(zd, retired) })
	checkSerialRecorded(t, kdb, zd)
	for tag := range retired {
		dk, err := GetDnssecKeysByState(kdb, zd.ZoneName, DnskeyStateRemoved)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, k := range dk {
			found = found || k.KeyTag == tag
		}
		if !found {
			t.Errorf("key %d is not removed", tag)
		}
	}
}

// TestARefusedPublishAfterTheCommitLeavesTheStripStaged: a publish after the
// commit that is refused leaves the strip staged, not dropped, and the next
// publish carries it.
func TestARefusedPublishAfterTheCommitLeavesTheStripStaged(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	old := servedRRSIGTags(zd)
	idleZone(zd)

	// As APIkeystore runs it: an external transaction, ended by the caller.
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := kdb.DnssecKeyMgmt(context.Background(), tx, clearPost(zd.ZoneName))
	if err != nil || resp.Error {
		t.Fatalf("clear: %v %s", err, resp.ErrorMsg)
	}
	if resp.stagedStrip == nil {
		t.Fatal("clear handed its caller no strip to finish")
	}

	// A fault that refuses the next publish: an RRset that cannot be signed,
	// in the publish's signing scope.
	const bad = "alpha.inv.example."
	zd.mu.Lock()
	zd.stageRRsetLocked(bad, core.RRset{Name: bad, RRtype: dns.TypeTXT, Class: dns.ClassINET})
	zd.wsSignOwners = map[string]bool{bad: true}
	zd.mu.Unlock()

	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := republishSigningKeysForZone(kdb, zd.ZoneName); err != nil {
		t.Fatal(err)
	}
	resp.stagedStrip.finish(true)

	waitFor(t, 5*time.Second, "the publish to be refused", func() bool {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		_, refused := zd.Errors[DnssecError]
		return refused
	})
	if served := servedRRSIGTags(zd); len(served) != len(old) {
		t.Errorf("a refused publish served the strip: %v, was %v", served, old)
	}
	staged := stagedRRSIGTags(zd)
	if staged == nil {
		t.Fatal("the refused publish dropped the working set, and the strip with it")
	}
	for tag := range old {
		if staged[tag] > 0 {
			t.Errorf("the strip is no longer staged: key %d has %d RRSIGs in the working set", tag, staged[tag])
		}
	}

	// The next publish, without the fault, carries the strip.
	zd.mu.Lock()
	zd.stageDeleteLocked(bad, dns.TypeTXT)
	zd.wsSignOwners = nil
	zd.mu.Unlock()
	if _, err := zd.publishSync(); err != nil {
		t.Fatal(err)
	}
	if !servesNoneOf(zd, old) {
		t.Errorf("the next publish did not carry the strip: %v", servedRRSIGTags(zd))
	}
}

// TestAStripIsPutBackWhenItsKeyChangeRollsBack: when the transaction that the
// strip was made for does not commit, the keys stay, and so do their RRSIGs.
func TestAStripIsPutBackWhenItsKeyChangeRollsBack(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	old := servedRRSIGTags(zd)

	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := kdb.DnssecKeyMgmt(context.Background(), tx, clearPost(zd.ZoneName))
	if err != nil || resp.Error {
		t.Fatalf("clear: %v %s", err, resp.ErrorMsg)
	}
	if staged := stagedRRSIGTags(zd); staged == nil || len(staged) >= len(old) {
		t.Fatalf("clear staged no strip: %v, served %v", staged, old)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	resp.stagedStrip.finish(false)

	if staged := stagedRRSIGTags(zd); staged != nil {
		for tag, n := range old {
			if staged[tag] != n {
				t.Errorf("key %d: %d RRSIGs staged after the rollback, the zone had %d", tag, staged[tag], n)
			}
		}
	}
	waitFor(t, 5*time.Second, "the hold to close", func() bool { return zd.txOpenCount() == 0 })
	if _, err := zd.publishSync(); err != nil {
		t.Fatal(err)
	}
	served := servedRRSIGTags(zd)
	for tag, n := range old {
		if served[tag] != n {
			t.Errorf("key %d: %d RRSIGs served after the rollback, the zone had %d", tag, served[tag], n)
		}
	}
}

// TestARolledBackStripIsPublishedAfterItsHoldRanOut: when the zone's hold runs
// out before the keystore transaction ends, its release publishes the strip.
// If the transaction then rolls back, the RRSIGs put back must be published
// too, not left staged: the hold is gone, and closing it publishes nothing.
func TestARolledBackStripIsPublishedAfterItsHoldRanOut(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	old := servedRRSIGTags(zd)
	// A cadence, so that the release's publish waits until the transaction has
	// rolled back instead of meeting it.
	zd.mu.Lock()
	zd.publishCadence = 300 * time.Millisecond
	zd.lastPublish = time.Now()
	zd.mu.Unlock()

	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := kdb.DnssecKeyMgmt(context.Background(), tx, clearPost(zd.ZoneName))
	if err != nil || resp.Error {
		t.Fatalf("clear: %v %s", err, resp.ErrorMsg)
	}
	// The hold runs out now that the strip is staged.
	expireHold(zd)
	waitFor(t, 5*time.Second, "the hold to run out", func() bool { return zd.txOpenCount() == 0 })
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	// The release's publish re-signs the SOA with the keys still in the
	// keystore, the old ones: the strip shows as fewer RRSIGs.
	waitFor(t, 5*time.Second, "the release to publish the strip", func() bool { return countRRSIGs(servedRRSIGTags(zd)) < countRRSIGs(old) })

	resp.stagedStrip.finish(false)
	defer func() {
		if t.Failed() {
			t.Logf("served %v, the zone had %v", servedRRSIGTags(zd), old)
		}
	}()
	waitFor(t, 5*time.Second, "the RRSIGs put back to be published", func() bool {
		served := servedRRSIGTags(zd)
		for tag, n := range old {
			if served[tag] != n {
				return false
			}
		}
		return true
	})
}

// TestARollbackPutsNoRRSIGBackOverChangedRecords: a writer that changes an
// RRset between the strip and the rollback leaves records that the RRSIGs the
// strip took do not cover. Those are not put back; an RRset left as it was
// gets its RRSIGs back.
func TestARollbackPutsNoRRSIGBackOverChangedRecords(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	// A cadence, so that nothing publishes the working set while the test
	// reads it.
	zd.mu.Lock()
	zd.publishCadence = time.Hour
	zd.lastPublish = time.Now()
	zd.mu.Unlock()
	const changed, kept = "alpha.inv.example.", "charlie.inv.example."
	sigsOf := func(name string) int {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		owner := zd.workingSet[name]
		if owner == nil {
			owner = zd.snapshot.Load().Data[name]
		}
		return len(owner.RRtypes.GetOnlyRRSet(dns.TypeA).RRSIGs)
	}
	keptBefore := sigsOf(kept)
	if keptBefore == 0 || sigsOf(changed) == 0 {
		t.Fatal("the test zone's A RRsets are not signed")
	}

	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := kdb.DnssecKeyMgmt(context.Background(), tx, clearPost(zd.ZoneName))
	if err != nil || resp.Error {
		t.Fatalf("clear: %v %s", err, resp.ErrorMsg)
	}

	// Another writer adds a record to one RRset while the zone is held.
	extra, err := dns.NewRR(changed + " 3600 IN A 10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	zd.mu.Lock()
	rrset := zd.workingSet[changed].RRtypes.GetOnlyRRSet(dns.TypeA)
	rrset.RRs = append(slices.Clip(rrset.RRs), extra)
	zd.stageRRsetLocked(changed, rrset)
	zd.mu.Unlock()

	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	resp.stagedStrip.finish(false)

	if n := sigsOf(changed); n != 0 {
		t.Errorf("%s A: %d RRSIGs put back over records they do not cover", changed, n)
	}
	if n := sigsOf(kept); n != keptBefore {
		t.Errorf("%s A: %d RRSIGs after the rollback, it had %d", kept, n, keptBefore)
	}
}
