package tdns

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

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

// runUpdaterEngine starts the zone updater and asserts it stops when the root
// context is cancelled.
//
// Sig0KeyPreparation publishes through the updater queue, so the engine has to
// be running for the publish to land. Discarding its result meant a shutdown
// regression could leave the goroutine running and this test would still pass.
func runUpdaterEngine(t *testing.T, kdb *KeyDB) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- kdb.ZoneUpdaterEngine(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ZoneUpdaterEngine did not return within 5s of its context being" +
				" cancelled; it would outlive shutdown holding the update queue")
		}
	})
}

// waitForUsableKey waits for the published KEY at name to be backed by a
// private key this server holds.
//
// Polled, because PublishKeyRRs is fire-and-forget: it posts to the update
// queue and returns, so the record appears a moment later on the updater's
// goroutine.
func waitForUsableKey(t *testing.T, zd *ZoneData, name string) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if zd.sig0KeyIsUsable(name) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// The wiring: knowing the key is unusable has to change what Sig0KeyPreparation
// DOES. Before this, the answer was computed, logged as a warning naming the
// exact problem, and then discarded -- the generation step asks only whether a
// KEY RRset exists, so it was skipped and the zone stayed unable to sign.
//
// The assertion is that the zone can SIGN again, not merely that a key landed
// in the keystore. Generation happens before the publish, so a keystore-only
// check stayed green with the publish dropped -- and a private key nobody has
// published leaves the child exactly as unable to bootstrap as the orphan did.
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
	if zd.sig0KeyIsUsable(zd.ZoneName) {
		t.Fatal("fixture: the published KEY is already usable, so there is no orphan to replace")
	}

	runUpdaterEngine(t, kdb)

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
	if !waitForUsableKey(t, zd, zd.ZoneName) {
		t.Error("a replacement key was generated but never published; the zone still cannot" +
			" prove to the parent which key it holds, which is the whole point of recovering")
	}
}

// TestSig0KeyPreparationReplacesAnOrphanedKeyAtTheUpdateTarget is the parent
// path, and it is the shape the bug was originally found in: on a
// delegation-sync parent the name is the DSYNC UPDATE target, not the apex.
//
// Production threads one `name` through verify, generate and publish, so the
// logic is shared -- but the apex is the easy case, and it was the only one
// covered. A regression that reintroduced the apex assumption (#538) would pass
// the test above.
func TestSig0KeyPreparationReplacesAnOrphanedKeyAtTheUpdateTarget(t *testing.T) {
	kdb := newTestKeyDB(t)

	const target = "updates.orphanparent.example."
	const zone = `orphanparent.example.	3600	IN	SOA	ns.orphanparent.example. h.orphanparent.example. 1 3600 600 604800 300
orphanparent.example.	3600	IN	NS	ns.orphanparent.example.
updates.orphanparent.example.	3600	IN	KEY	256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=
`
	zd := testZone(t, "orphanparent.example.", zone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.ZoneType = Primary
	zd.Options = map[ZoneOption]bool{OptChildSync: true, OptAllowUpdates: true}

	runUpdaterEngine(t, kdb)

	if err := zd.Sig0KeyPreparation(target, dns.ED25519, kdb); err != nil {
		t.Fatalf("Sig0KeyPreparation: %v", err)
	}

	sak, err := kdb.GetSig0Keys(target, Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if len(sak.Keys) == 0 {
		t.Fatalf("no key was generated for %s, whose published KEY has no private half", target)
	}
	if apex, _ := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive); apex != nil && len(apex.Keys) > 0 {
		t.Errorf("a key was minted at the apex %s instead of at the UPDATE target %s; that is"+
			" #538, and on a parent the child-half algorithm is usually unset so the call"+
			" fails outright", zd.ZoneName, target)
	}
	if !waitForUsableKey(t, zd, target) {
		t.Errorf("a replacement key was generated for %s but never published", target)
	}
}

// TestAKeytagCollisionDoesNotMakeAnOrphanLookUsable.
//
// A key tag is sixteen bits and is not unique. The published-key check matched
// on the tag alone, so an active keystore key colliding with an orphaned
// published KEY reported the orphan as usable -- the zone looks prepared, signs
// with a key nobody can find, and every signature fails against the published
// record. That is #576 again by a different route, and with no warning, because
// the tag matched.
func TestAKeytagCollisionDoesNotMakeAnOrphanLookUsable(t *testing.T) {
	published := mustRR(t, "collide.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=").(*dns.KEY)

	// Same tag, different key. Constructed rather than found: a natural
	// collision is a 1-in-65536 search, and the point is the comparison.
	other := *published
	other.PublicKey = "zLDk2H1Pktp2vPvj8vc33odOoFzR0o7iGsZcMePXqnY="

	if published.KeyTag() == other.KeyTag() {
		if sameKeyRdata(published, &other) {
			t.Fatal("the two fixtures are the same key; nothing is being tested")
		}
	}
	if sameKeyRdata(published, &other) {
		t.Error("two KEYs with different public keys compared equal; a tag collision would" +
			" report an orphaned published key as usable and skip publishing the real one")
	}
	if !sameKeyRdata(published, published) {
		t.Error("a key did not compare equal to itself")
	}

	// The fields that are part of the key's identity.
	for _, tc := range []struct {
		name string
		mut  func(k *dns.KEY)
	}{
		{"flags", func(k *dns.KEY) { k.Flags ^= 0x0100 }},
		{"protocol", func(k *dns.KEY) { k.Protocol++ }},
		{"algorithm", func(k *dns.KEY) { k.Algorithm++ }},
		{"public key", func(k *dns.KEY) { k.PublicKey = "AAAA" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := *published
			tc.mut(&m)
			if sameKeyRdata(published, &m) {
				t.Errorf("keys differing in %s compared equal", tc.name)
			}
		})
	}

	// Owner and TTL are not identity: the published record and the keystore
	// copy legitimately differ there.
	m := *published
	m.Hdr.Name = "elsewhere.example."
	m.Hdr.Ttl = 60
	if !sameKeyRdata(published, &m) {
		t.Error("the same key at a different owner or TTL compared unequal; the published" +
			" record and the keystore copy always differ that way")
	}
}

// keyWithSameTag returns a copy of k whose key tag is identical but whose
// public key is not.
//
// Constructed rather than searched for. RFC 4034 Appendix B computes the tag as
// a sum over the RDATA octets, with even offsets landing in the high byte of
// the accumulator and odd offsets in the low one, so adjusting two octets at
// the SAME parity by +1 and -1 leaves the tag unchanged. Hunting for a natural
// collision would be a 1-in-65536 search for something this constructs exactly.
func keyWithSameTag(t *testing.T, k *dns.KEY) *dns.KEY {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		t.Fatalf("decoding the public key: %v", err)
	}
	if len(raw) < 5 {
		t.Fatalf("public key too short to perturb: %d bytes", len(raw))
	}
	// Two octets at the same parity, one up and one down, avoiding wrap.
	i, j := -1, -1
	for n := 0; n+2 < len(raw); n += 2 {
		if raw[n] < 0xff && raw[n+2] > 0x00 {
			i, j = n, n+2
			break
		}
	}
	if i < 0 {
		t.Skip("no suitable octet pair in this key to perturb without wrapping")
	}
	perturbed := append([]byte(nil), raw...)
	perturbed[i]++
	perturbed[j]--

	out := *k
	out.PublicKey = base64.StdEncoding.EncodeToString(perturbed)
	if out.KeyTag() != k.KeyTag() {
		t.Fatalf("construction failed: tags %d vs %d", out.KeyTag(), k.KeyTag())
	}
	if out.PublicKey == k.PublicKey {
		t.Fatal("construction failed: the keys are identical")
	}
	return &out
}

// TestAnOrphanWithACollidingKeytagIsStillAnOrphan drives the real check, not
// the comparison helper. Reverting the call site to a key-tag match must fail
// HERE -- a test that only exercises sameKeyRdata stays green through exactly
// the regression it is meant to catch.
func TestAnOrphanWithACollidingKeytagIsStillAnOrphan(t *testing.T) {
	kdb := newTestKeyDB(t)

	const zone = `collide.example.	3600	IN	SOA	ns.collide.example. h.collide.example. 1 3600 600 604800 300
collide.example.	3600	IN	NS	ns.collide.example.
`
	zd := testZone(t, "collide.example.", zone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.ZoneType = Primary
	zd.Options = map[ZoneOption]bool{OptParentSync: true, OptAllowUpdates: true}

	// The key this server actually holds.
	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command: "sig0-mgmt", SubCommand: "generate", Zone: zd.ZoneName,
		Keyname: zd.ZoneName, Algorithm: dns.ED25519, State: Sig0StateActive, Creator: "test",
	}); err != nil {
		t.Fatalf("generating the active key: %v", err)
	}
	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil || len(sak.Keys) == 0 {
		t.Fatalf("no active key: %v", err)
	}
	active := &sak.Keys[0].KeyRR

	// Publish a DIFFERENT key that happens to share its tag.
	orphan := keyWithSameTag(t, active)
	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked(zd.ZoneName, core.RRset{
		Name: zd.ZoneName, RRtype: dns.TypeKEY, Class: dns.ClassINET, RRs: []dns.RR{orphan},
	})
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()

	if zd.sig0KeyIsUsable(zd.ZoneName) {
		t.Error("a published KEY whose private half this server does NOT hold was reported" +
			" usable because its key tag collided with an active one; the zone looks" +
			" prepared, signs with a key nobody can find, and every signature fails to" +
			" validate against the published record")
	}
}
