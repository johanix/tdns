/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// ceremonyUpdateFrom builds the child's bootstrap ceremony, "DEL <child> ANY
// KEY" + "ADD <child> KEY", signed (as far as stubSig0Verify is concerned) by
// the key it adds.
func ceremonyUpdateFrom(t *testing.T, zone string, key *dns.KEY) *dns.Msg {
	t.Helper()
	add := dns.Copy(key)
	del := dns.Copy(key)
	del.Header().Class = dns.ClassANY
	del.Header().Ttl = 0

	m := new(dns.Msg)
	m.SetUpdate(zone)
	m.Ns = []dns.RR{del, add}
	sig := new(dns.SIG)
	sig.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY}
	sig.RRSIG.KeyTag = key.KeyTag()
	sig.RRSIG.SignerName = key.Hdr.Name
	sig.RRSIG.Algorithm = key.Algorithm
	sig.RRSIG.Inception = uint32(time.Now().Add(-time.Minute).Unix())
	sig.RRSIG.Expiration = uint32(time.Now().Add(time.Hour).Unix())
	m.Extra = []dns.RR{sig}
	return m
}

// rebootstrapParent is a parent that takes unvalidated uploads (as the child's
// first upload needed) and holds the child's key untrusted; failed says whether
// a verification has already run out of attempts on it.
func rebootstrapParent(t *testing.T, failed bool) (*ZoneData, *dns.KEY) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)
	pol := compiledDefaultDelegationPolicy()
	pol.AllowUnvalidatedUpload = true
	zd.DelegationPolicy = &pol

	key := discoveredTestKey(t).Key
	// A verification of this key in an earlier test leaves a cooldown behind.
	clearChildKeyCooldown(t, key.Hdr.Name, key.KeyTag())
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), KeyRR: key.String(), Validated: true,
	}); err != nil {
		t.Fatalf("storing the child's key: %v", err)
	}
	if failed {
		if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
			Command: "child-sig0-mgmt", SubCommand: "validation-failed",
			Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), ValidationError: "5 attempts via [at-apex]: KEY not found",
		}); err != nil {
			t.Fatalf("recording the failure: %v", err)
		}
	}
	return zd, &key
}

// THE DEFECT, through the real update path. The parent told the child "validation
// failed; re-bootstrap after fixing the key's publication", the child did, and
// the parent refused the re-bootstrap with the same EDE: ValidateUpdate found the
// key in the TrustStore and never looked at what the update was. The storage
// half ("a re-upload replaces the row") had its own test, which called the
// truststore directly and so could not see that nothing ever reached it.
func TestAReBootstrapAfterAFailedVerificationStartsOver(t *testing.T) {
	zd, key := rebootstrapParent(t, true)
	stubSig0Verify(t)

	r := ceremonyUpdateFrom(t, zd.ZoneName, key)
	us := &UpdateStatus{Type: "TRUSTSTORE-UPDATE"}
	if err := zd.ValidateUpdate(context.Background(), r, us); err != nil {
		t.Fatalf("ValidateUpdate: %v", err)
	}
	if err := zd.TrustUpdate(r, us); err != nil {
		t.Fatalf("the child re-bootstrapped as the parent told it to and was refused again (EDE %d): %v",
			us.RejectionEDE, err)
	}
	if us.SignatureType != "self-signed" {
		t.Errorf("SignatureType %q, want self-signed: the re-upload must take the first upload's path", us.SignatureType)
	}
	approved, updateZone, err := zd.ApproveTrustUpdate(zd.ZoneName, us, r)
	if err != nil || !approved {
		t.Fatalf("re-bootstrap not approved (approved=%v): %v", approved, err)
	}
	if updateZone {
		t.Error("an approved key upload asked for the parent zone to be written")
	}
}

// A restart in the middle of a verification leaves the row "in progress" with
// nothing running. The child's re-bootstrap has to be able to start it again.
func TestAReBootstrapOfARowLeftInProgressStartsOver(t *testing.T) {
	zd, key := rebootstrapParent(t, false)
	stubSig0Verify(t)

	r := ceremonyUpdateFrom(t, zd.ZoneName, key)
	us := &UpdateStatus{Type: "TRUSTSTORE-UPDATE"}
	if err := zd.ValidateUpdate(context.Background(), r, us); err != nil {
		t.Fatalf("ValidateUpdate: %v", err)
	}
	if err := zd.TrustUpdate(r, us); err != nil {
		t.Fatalf("re-bootstrap of an abandoned in-progress row refused (EDE %d): %v", us.RejectionEDE, err)
	}
}

// While a verification of the key is running, a re-upload changes nothing and
// is answered as before: known, not yet trusted -- waiting will help.
func TestAReBootstrapWhileVerifyingIsStillKnownButNotTrusted(t *testing.T) {
	zd, key := rebootstrapParent(t, false)
	stubSig0Verify(t)
	id := childKeyVerificationID(key.Hdr.Name, key.KeyTag())
	childKeyVerifications.Store(id, struct{}{})
	t.Cleanup(func() { childKeyVerifications.Delete(id) })

	r := ceremonyUpdateFrom(t, zd.ZoneName, key)
	us := &UpdateStatus{Type: "TRUSTSTORE-UPDATE"}
	if err := zd.ValidateUpdate(context.Background(), r, us); err != nil {
		t.Fatalf("ValidateUpdate: %v", err)
	}
	if err := zd.TrustUpdate(r, us); err == nil {
		t.Fatal("a re-upload started over underneath a running verification")
	}
	if us.RejectionEDE != edns0.EDESig0KeyKnownButNotTrusted {
		t.Errorf("EDE %d, want %d (known, not yet trusted)", us.RejectionEDE, edns0.EDESig0KeyKnownButNotTrusted)
	}
}

// Only the stored key re-uploading itself counts. A different key under the
// same name and tag, a trusted key, or an update that is not the ceremony all
// keep the old path.
func TestReBootstrapOfKnownKeyAcceptsOnlyTheStoredKeyReuploadingItself(t *testing.T) {
	key := discoveredTestKey(t).Key
	r := ceremonyUpdateFrom(t, "example.", &key)
	sig := r.Extra[0].(*dns.SIG)
	stored := &Sig0Key{Name: key.Hdr.Name, Keyid: key.KeyTag(), Key: key, ValidationFailed: true}

	if got := reBootstrapOfKnownKey(r.Ns, sig, stored); got == nil || got.Source != "child-key-upload" || got.ValidationFailed {
		t.Fatalf("the stored key re-uploading itself: %+v", got)
	}

	other := key
	other.PublicKey = "AAAA" + key.PublicKey[4:]
	if got := reBootstrapOfKnownKey(r.Ns, sig, &Sig0Key{Name: key.Hdr.Name, Keyid: key.KeyTag(), Key: other}); got != nil {
		t.Error("an upload was accepted as a re-bootstrap of a different stored key")
	}

	trusted := *stored
	trusted.Trusted = true
	if got := reBootstrapOfKnownKey(r.Ns, sig, &trusted); got != nil {
		t.Error("a trusted key's upload was treated as a re-bootstrap")
	}

	plain := mustRR(t, "child.example. 3600 IN NS ns2.child.example.")
	if got := reBootstrapOfKnownKey([]dns.RR{plain}, sig, stored); got != nil {
		t.Error("an update that is not the bootstrap ceremony was treated as a re-bootstrap")
	}
}

// One verification per key: a second trigger while the first is running starts
// nothing, and the key is free again once the first has exited.
func TestTriggerChildKeyVerificationRunsOnePerKey(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)
	pol := compiledDefaultDelegationPolicy()
	pol.RetryMaxAttempts = 2
	pol.RetryInterval = time.Hour // the first verifier waits here until cancelled
	zd.DelegationPolicy = &pol

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := discoveredTestKey(t)

	first := kdb.TriggerChildKeyVerification(ctx, key.Name, zd.ZoneName, key.Keyid, key.Key.String())
	if first == nil {
		t.Fatal("no verification started")
	}
	if second := kdb.TriggerChildKeyVerification(ctx, key.Name, zd.ZoneName, key.Keyid, key.Key.String()); second != nil {
		cancel()
		<-second
		t.Error("a second verifier started for a key already being verified")
	}
	cancel()
	<-first
	if childKeyVerificationRunning(key.Name, key.Keyid) {
		t.Error("the key is still marked as being verified after its verifier exited")
	}
}
