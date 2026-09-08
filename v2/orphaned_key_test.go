package tdns

import (
	"context"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #576: a KEY published at the apex with no private key behind it in the
// keystore. The daemon diagnosed it exactly -- "no active private key for the
// published KEY" -- and then concluded there was nothing to do, because the
// generation step asks only whether a KEY RRset EXISTS. The zone could neither
// sign updates nor bootstrap, and did not recover on restart.
func TestAnOrphanedPublishedKeyIsNotMistakenForAUsableOne(t *testing.T) {
	kdb := newTestKeyDB(t)

	const zone = `orphan.example.	3600	IN	SOA	ns.orphan.example. h.orphan.example. 1 3600 600 604800 300
orphan.example.	3600	IN	NS	ns.orphan.example.
orphan.example.	3600	IN	KEY	256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=
`
	zd := testZone(t, "orphan.example.", zone)
	zd.KeyDB = kdb

	// The keystore holds nothing: exactly the reported state, a record that has
	// outlived its private half.
	if usable := zd.sig0KeyIsUsable(zd.ZoneName); usable {
		t.Fatal("a published KEY with no private key behind it was reported as usable;" +
			" the zone then skips key generation and can neither sign nor bootstrap")
	}
}

// The other side of it: a published KEY that IS backed must not trigger a
// pointless regeneration on every load.
func TestABackedPublishedKeyIsUsable(t *testing.T) {
	kdb := newTestKeyDB(t)

	const zone = `backed.example.	3600	IN	SOA	ns.backed.example. h.backed.example. 1 3600 600 604800 300
backed.example.	3600	IN	NS	ns.backed.example.
`
	zd := testZone(t, "backed.example.", zone)
	registerZones(t, zd)
	zd.KeyDB = kdb

	resp, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "generate",
		Zone:       zd.ZoneName,
		Keyname:    zd.ZoneName,
		Algorithm:  dns.ED25519,
		State:      Sig0StateActive,
		Creator:    "test",
	})
	if err != nil {
		t.Fatalf("generating a key: %v (%v)", err, resp)
	}

	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil || len(sak.Keys) == 0 {
		t.Fatalf("no active key after generating one: %v", err)
	}

	// Publish exactly the key the keystore holds.
	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked(zd.ZoneName, core.RRset{
		Name: zd.ZoneName, RRtype: dns.TypeKEY, Class: dns.ClassINET,
		RRs: []dns.RR{&sak.Keys[0].KeyRR},
	})
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()

	if !zd.sig0KeyIsUsable(zd.ZoneName) {
		t.Error("a published KEY that the keystore does hold the private half of was reported" +
			" as unusable; the zone would regenerate and republish on every load")
	}
}

// The wiring: knowing the key is unusable has to change what Sig0KeyPreparation
// DOES. Before this, the answer was computed, logged as a warning naming the
// exact problem, and then discarded -- the generation step asks only whether a
// KEY RRset exists, so it was skipped and the zone stayed unable to sign.
func TestSig0KeyPreparationReplacesAnOrphanedKey(t *testing.T) {
	kdb := newTestKeyDB(t)

	const zone = `orphanprep.example.	3600	IN	SOA	ns.orphanprep.example. h.orphanprep.example. 1 3600 600 604800 300
orphanprep.example.	3600	IN	NS	ns.orphanprep.example.
orphanprep.example.	3600	IN	KEY	256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=
`
	zd := testZone(t, "orphanprep.example.", zone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.ZoneType = Primary
	zd.Options = map[ZoneOption]bool{OptParentSync: true, OptAllowUpdates: true}

	if sak, _ := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive); sak != nil && len(sak.Keys) != 0 {
		t.Fatal("fixture: the keystore already holds a key")
	}

	// Sig0KeyPreparation publishes through the updater queue and waits for the
	// answer, so the engine has to be running or this blocks forever.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = kdb.ZoneUpdaterEngine(ctx) }()

	if err := zd.Sig0KeyPreparation(zd.ZoneName, dns.ED25519, kdb); err != nil {
		t.Fatalf("Sig0KeyPreparation: %v", err)
	}

	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if len(sak.Keys) == 0 {
		t.Fatal("no key was generated for a zone whose published KEY has no private half." +
			" The zone can neither sign updates nor bootstrap, says so in its own log," +
			" and does not recover on restart")
	}
}
