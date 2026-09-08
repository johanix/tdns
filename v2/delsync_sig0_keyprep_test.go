package tdns

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #538: Sig0KeyPreparation gated its INTERNAL publish on allow-updates, the
// option that governs inbound RFC 2136 DDNS. A delegation-sync parent that
// (correctly) refuses DDNS therefore published a DSYNC record advertising an
// UPDATE target and never generated the SIG(0) key that target names, so its
// KeyState responses went out unsigned.
//
// The zone below is the shape that broke: a primary offering the UPDATE
// scheme, with allow-updates off.
const sig0KeyPrepZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	192.0.2.1
updates.example.	3600	IN	A	192.0.2.1
`

// sig0KeyPrepZone with a KEY already at the UPDATE target, so the "already
// published" branch is exercised against real data rather than a nil owner.
// newSig0KeyPrepZone builds a Ready MapZone zone wired to a real keystore and a
// buffered UpdateQ, which is what PublishKeyRRs posts the internal update to.
func newSig0KeyPrepZone(t *testing.T, zonestr string, ztype ZoneType) (*ZoneData, *KeyDB, chan UpdateRequest) {
	t.Helper()
	withAppType(t, AppTypeAuth)
	zd := testZone(t, "example.", zonestr)
	zd.ZoneType = ztype
	zd.Options = map[ZoneOption]bool{OptChildSync: true}
	kdb := newTestKeyDB(t)
	q := make(chan UpdateRequest, 4)
	kdb.UpdateQ = q
	zd.KeyDB = kdb
	return zd, kdb, q
}

// keyRRsFor returns the KEY RRs for name across every queued update request.
func keyRRsFor(q chan UpdateRequest, name string) []*dns.KEY {
	var out []*dns.KEY
	for {
		select {
		case ur, ok := <-q:
			if !ok {
				return out
			}
			if !ur.InternalUpdate {
				continue
			}
			for _, rr := range ur.Actions {
				if k, ok := rr.(*dns.KEY); ok && k.Header().Name == name {
					out = append(out, k)
				}
			}
		default:
			return out
		}
	}
}

// The bug, stated as a test: no allow-updates, and the key must still appear.
func TestSig0KeyPreparationDoesNotRequireAllowUpdates(t *testing.T) {
	zd, kdb, q := newSig0KeyPrepZone(t, sig0KeyPrepZone, Primary)
	if zd.Options[OptAllowUpdates] {
		t.Fatal("test zone must start without allow-updates")
	}

	if err := zd.Sig0KeyPreparation("updates.example.", dns.ED25519, kdb); err != nil {
		t.Fatalf("Sig0KeyPreparation: %v", err)
	}

	sak, err := kdb.GetSig0Keys("updates.example.", Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if len(sak.Keys) != 1 {
		t.Fatalf("active SIG(0) keys for updates.example. = %d, want 1", len(sak.Keys))
	}
	if got := sak.Keys[0].KeyRR.Algorithm; got != dns.ED25519 {
		t.Errorf("key algorithm = %d, want ED25519 (%d)", got, dns.ED25519)
	}

	published := keyRRsFor(q, "updates.example.")
	if len(published) != 1 {
		t.Fatalf("KEY RRs posted for publication = %d, want 1", len(published))
	}
	if published[0].KeyTag() != sak.Keys[0].KeyRR.KeyTag() {
		t.Errorf("published keytag = %d, keystore keytag = %d",
			published[0].KeyTag(), sak.Keys[0].KeyRR.KeyTag())
	}
}

// A zone with neither childsync nor parentsync asked for no key, and the
// callers do not call this for one. Restated here so the function cannot be
// wired into publishing for a zone that wants neither.
func TestSig0KeyPreparationRequiresADelegationSyncOption(t *testing.T) {
	zd, kdb, q := newSig0KeyPrepZone(t, sig0KeyPrepZone, Primary)
	zd.Options = map[ZoneOption]bool{}

	if err := zd.Sig0KeyPreparation("updates.example.", dns.ED25519, kdb); err != nil {
		t.Fatalf("Sig0KeyPreparation: %v", err)
	}
	sak, err := kdb.GetSig0Keys("updates.example.", Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if len(sak.Keys) != 0 {
		t.Errorf("no delegation-sync option: %d SIG(0) keys generated, want 0", len(sak.Keys))
	}
	if rrs := keyRRsFor(q, "updates.example."); len(rrs) != 0 {
		t.Errorf("no delegation-sync option: %d KEY RRs posted, want 0", len(rrs))
	}
}

// The child side reaches the same function with parentsync and the zone apex.
func TestSig0KeyPreparationParentsyncPublishesApexKey(t *testing.T) {
	zd, kdb, q := newSig0KeyPrepZone(t, sig0KeyPrepZone, Primary)
	zd.Options = map[ZoneOption]bool{OptParentSync: true}

	if err := zd.Sig0KeyPreparation("example.", dns.ED25519, kdb); err != nil {
		t.Fatalf("Sig0KeyPreparation: %v", err)
	}
	if rrs := keyRRsFor(q, "example."); len(rrs) != 1 {
		t.Errorf("parentsync: %d apex KEY RRs posted, want 1", len(rrs))
	}
}

// dont-publish-key is the opt-out that survives: it stops the publish, and it
// is the ONLY thing that does on a primary that asked for a key.
func TestSig0KeyPreparationDontPublishKeyStillOptsOut(t *testing.T) {
	zd, kdb, q := newSig0KeyPrepZone(t, sig0KeyPrepZone, Primary)
	zd.SetOption(OptDontPublishKey, true)

	if err := zd.Sig0KeyPreparation("updates.example.", dns.ED25519, kdb); err != nil {
		t.Fatalf("Sig0KeyPreparation: %v", err)
	}
	if rrs := keyRRsFor(q, "updates.example."); len(rrs) != 0 {
		t.Errorf("dont-publish-key: %d KEY RRs posted, want 0", len(rrs))
	}
}

// The replacement gate: a tdns-auth secondary serves what it received and may
// not originate content, so it neither generates nor publishes a key. Without
// this the allow-updates removal would have let a secondary write into a zone
// it does not own.
func TestSig0KeyPreparationSecondaryDoesNotOriginate(t *testing.T) {
	zd, kdb, q := newSig0KeyPrepZone(t, sig0KeyPrepZone, Secondary)
	// Options set directly, not through normalizeOptionsForRole, which strips
	// both childsync and parentsync from a tdns-auth secondary. That is the
	// point: this pins the backstop itself, on the ZoneData shape the
	// normalizer never saw.
	zd.Options = map[ZoneOption]bool{OptParentSync: true}

	if err := zd.Sig0KeyPreparation("updates.example.", dns.ED25519, kdb); err != nil {
		t.Fatalf("Sig0KeyPreparation: %v", err)
	}

	sak, err := kdb.GetSig0Keys("updates.example.", Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if len(sak.Keys) != 0 {
		t.Errorf("secondary generated %d SIG(0) keys, want 0", len(sak.Keys))
	}
	if rrs := keyRRsFor(q, "updates.example."); len(rrs) != 0 {
		t.Errorf("secondary posted %d KEY RRs, want 0", len(rrs))
	}
}

// An already-published KEY is left alone: no second key, no second publish.
// This is what makes the function safe to re-run on every zone load, which it
// is -- SetupZoneSync calls it on every load of every delegation-sync parent.
//
// The apex assertion is the second defect's regression guard. The verify step
// used to look at the zone APEX rather than at name, so on a parent it found no
// KEY, concluded the zone had none, and minted an apex SIG(0) key nothing had
// asked for -- when it did not simply fail, which is what it did whenever the
// child half of the delegationsync config had no keygen algorithm. Unreachable
// before, because the allow-updates gate meant a parent never got a published
// KEY in the first place; the #538 fix is what makes this the ordinary path.
func TestSig0KeyPreparationExistingKeyNotRepublished(t *testing.T) {
	// The published KEY has to be one this server can actually SIGN with, or
	// the test does not test what its name says.
	//
	// It used to publish a literal KEY into a zone whose keystore was empty --
	// which is an orphaned record, the state #576 is about, and the assertion
	// "nothing is republished" was pinning exactly the behaviour that made a
	// zone unable to sign or bootstrap until an operator deleted the record by
	// hand. Generating the key and publishing that one keeps the subject
	// ("an existing key is not republished") and drops the accident.
	zd, kdb, q := newSig0KeyPrepZone(t, sig0KeyPrepZone, Primary)
	registerZones(t, zd)

	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "generate",
		Zone:       zd.ZoneName,
		Keyname:    "updates.example.",
		Algorithm:  dns.ED25519,
		State:      Sig0StateActive,
		Creator:    "test",
	}); err != nil {
		t.Fatalf("generating the key that is already published: %v", err)
	}
	sak, err := kdb.GetSig0Keys("updates.example.", Sig0StateActive)
	if err != nil || len(sak.Keys) == 0 {
		t.Fatalf("no active key after generating one: %v", err)
	}
	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked("updates.example.", core.RRset{
		Name: "updates.example.", RRtype: dns.TypeKEY, Class: dns.ClassINET,
		RRs: []dns.RR{&sak.Keys[0].KeyRR},
	})
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()
	drainUpdateQ(q)

	if err := zd.Sig0KeyPreparation("updates.example.", dns.ED25519, kdb); err != nil {
		t.Fatalf("Sig0KeyPreparation: %v", err)
	}
	if rrs := keyRRsFor(q, "updates.example."); len(rrs) != 0 {
		t.Errorf("KEY already published: %d KEY RRs posted for the target, want 0", len(rrs))
	}
	if rrs := keyRRsFor(q, "example."); len(rrs) != 0 {
		t.Errorf("%d KEY RRs posted for the apex, want 0: the verify step must look at"+
			" the UPDATE target, not the apex", len(rrs))
	}
	apex, err := kdb.GetSig0Keys("example.", Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if len(apex.Keys) != 0 {
		t.Errorf("%d apex SIG(0) keys generated, want 0", len(apex.Keys))
	}
}
