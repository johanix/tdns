package tdns

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// #574: a child SIG(0) key the parent finds in DNS and validates was refused
// forever. TriggerChildKeyVerification had one caller -- the updater's
// TRUSTSTORE-UPDATE arm, after a key has been STORED -- and the DNS-discovery
// path stores nothing, so no verification ever ran and the key stayed
// untrusted. Neither delegation policy offered a way out.
//
// A row has to exist before any of that machinery can do anything: promotion is
// an UPDATE of the TrustStore row.
func TestADiscoveredChildKeyIsRecordedForVerification(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb

	key := mustRR(t, "child.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=").(*dns.KEY)
	discovered := &Sig0Key{
		Name:      "child.example.",
		Keyid:     key.KeyTag(),
		Validated: true,
		Source:    "dns",
		Key:       *key,
	}

	if _, err := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid); err == nil {
		// Nothing stored yet is the precondition; a hit here would mean the
		// fixture already had the row and the test proves nothing.
		if sk, _ := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid); sk != nil {
			t.Fatal("fixture: the key is already in the truststore")
		}
	}

	ctx := boundedVerification(t, zd)
	zd.rememberDiscoveredChildKey(ctx, discovered)

	sk, err := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid)
	if err != nil || sk == nil {
		t.Fatalf("the discovered key was not recorded (err=%v); with no row there is nothing"+
			" for a verification to promote, so the child is refused forever", err)
	}
	if sk.Trusted {
		t.Error("a key found in DNS was recorded as TRUSTED; discovery is not verification," +
			" and trusting it here would let any child that publishes a KEY update the parent")
	}
	if !sk.Validated {
		t.Error("the DNSSEC validation result from the lookup was not carried onto the row")
	}
	if !sk.DnssecValidated {
		t.Error("dnssecvalidated was not persisted; it is what childKeyAcceptable reads to" +
			" decide whether the key may be promoted, so losing it stalls the bootstrap")
	}
}

// Any signer at all can publish a KEY and send a signed UPDATE. Only names this
// zone actually delegates get a row.
func TestADiscoveredKeyForANonChildIsNotRecorded(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb

	key := mustRR(t, "stranger.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=").(*dns.KEY)
	zd.rememberDiscoveredChildKey(context.Background(), &Sig0Key{
		Name:      "stranger.example.",
		Keyid:     key.KeyTag(),
		Validated: true,
		Source:    "dns",
		Key:       *key,
	})

	if sk, _ := kdb.FindSig0TrustedKey("stranger.example.", key.KeyTag()); sk != nil {
		t.Error("recorded a key for a name this zone does not delegate")
	}
}

// The second update from the same child must not start a second verification.
// ValidateUpdate consults the truststore first and returns on a hit whether or
// not the row is trusted, so once the row exists this path is not reached again
// -- which is what keeps one verification per key rather than one per update.
func TestARecordedKeyIsFoundBeforeTheDiscoveryPath(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb

	key := mustRR(t, "child.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=").(*dns.KEY)
	discovered := &Sig0Key{Name: "child.example.", Keyid: key.KeyTag(), Validated: true, Source: "dns", Key: *key}

	zd.rememberDiscoveredChildKey(boundedVerification(t, zd), discovered)

	sk, err := zd.FindSig0TrustedKey(discovered.Name, discovered.Keyid)
	if err != nil || sk == nil {
		t.Fatalf("the row is not visible to the lookup ValidateUpdate does first: err=%v", err)
	}
	if sk.Trusted {
		t.Error("the row became trusted without any verification")
	}
}

// The trust rule itself, pinned.
//
// A child KEY found where the policy allows and DNSSEC-validated there is
// SUFFICIENT for promotion to trusted. Nothing further is required, and
// nothing further should ever be added quietly: without this rule holding,
// both bootstrap mechanisms are impossible, because DNSSEC validation of the
// published KEY is the only evidence either of them produces.
//
// require-dnssec makes that evidence NECESSARY. This asserts the other half --
// that it is also enough.
func TestDnssecValidationIsSufficientForTrust(t *testing.T) {
	pol := DefaultDelegationPolicy()
	if !pol.RequireDnssec {
		t.Fatal("the default policy no longer requires DNSSEC; the necessary half is gone")
	}
	if len(pol.Mechanisms) == 0 {
		t.Fatal("the default policy has no mechanisms, so it never bootstraps at all")
	}

	for _, tc := range []struct {
		name          string
		verified      bool
		dnssec        bool
		requireDnssec bool
		wantAccepted  bool
		why           string
	}{
		{
			name: "found and DNSSEC-validated", verified: true, dnssec: true,
			requireDnssec: true, wantAccepted: true,
			why: "this is the whole of the at-apex and at-ns bootstrap: if it does not " +
				"promote, neither mechanism can ever complete",
		},
		{
			name: "found but not DNSSEC-validated, and required", verified: true, dnssec: false,
			requireDnssec: true, wantAccepted: false,
			why: "require-dnssec means the evidence is necessary",
		},
		{
			name: "found, not validated, not required", verified: true, dnssec: false,
			requireDnssec: false, wantAccepted: true,
			why: "an operator who turned require-dnssec off asked for exactly this",
		},
		{
			name: "not found where the policy looks", verified: false, dnssec: true,
			requireDnssec: true, wantAccepted: false,
			why: "mechanisms are the scope of the search; a key validated somewhere " +
				"the parent was not asked to look is not evidence for this parent",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accepted := tc.verified && !(tc.requireDnssec && !tc.dnssec)
			if accepted != tc.wantAccepted {
				t.Fatalf("the rule this test encodes disagrees with itself; fix the test")
			}
			// And the rule as the code applies it, through the same predicate
			// imrChildKeyVerifier uses.
			got := childKeyAcceptable(tc.verified, tc.dnssec, DelegationPolicy{
				Mechanisms:    []string{"at-apex", "at-ns"},
				RequireDnssec: tc.requireDnssec,
			})
			if got != tc.wantAccepted {
				t.Errorf("accepted=%v, want %v: %s", got, tc.wantAccepted, tc.why)
			}
		})
	}
}

// stubDnsDiscovery makes ValidateUpdate's DNS-discovery arm return key for the
// given signer, without an IMR. Same seam and same discipline as
// stubSig0Verify.
func stubDnsDiscovery(t *testing.T, key *Sig0Key) {
	t.Helper()
	orig := findSig0KeyViaDNS
	t.Cleanup(func() { findSig0KeyViaDNS = orig })
	findSig0KeyViaDNS = func(zd *ZoneData, signer string, keyid uint16) (*Sig0Key, error) {
		if key != nil && signer == key.Name && keyid == key.Keyid {
			k := *key
			return &k, nil
		}
		return nil, fmt.Errorf("no key for %s keyid %d", signer, keyid)
	}
}

// signedUpdateFrom builds an UPDATE carrying a SIG(0) from the named signer.
// The signature bytes are not real -- stubSig0Verify decides the outcome --
// because what is under test is what ValidateUpdate DOES with the verdict.
func signedUpdateFrom(t *testing.T, zone, signer string, keyid uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(zone)
	m.Ns = []dns.RR{mustRR(t, "child.example. 3600 IN NS ns2.child.example.")}
	sig := new(dns.SIG)
	sig.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY}
	sig.RRSIG.KeyTag = keyid
	sig.RRSIG.SignerName = signer
	sig.RRSIG.Algorithm = dns.ED25519
	sig.RRSIG.Inception = uint32(time.Now().Add(-time.Minute).Unix())
	sig.RRSIG.Expiration = uint32(time.Now().Add(time.Hour).Unix())
	m.Extra = []dns.RR{sig}
	return m
}

// boundedVerification keeps the verifier that rememberDiscoveredChildKey
// starts from outliving the test.
//
// The default policy is five attempts ten seconds apart, doubling, and with no
// IMR every attempt fails -- so the goroutine sits in waitOrDone for a minute
// and a half, writing to a t.TempDir database that has gone. One attempt, on a
// context cancelled at cleanup, exits at once and records no verdict (a
// cancelled context is a shutdown, not a judgement on the key).
//
// Returns the context to hand to whatever starts the verification. It used to
// stash it on the KeyDB, which is what the production path did too -- and that
// was the race the threading removed.
func boundedVerification(t *testing.T, zd *ZoneData) context.Context {
	t.Helper()
	pol := compiledDefaultDelegationPolicy()
	pol.RetryMaxAttempts = 1
	zd.DelegationPolicy = &pol

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

func discoveredTestKey(t *testing.T) *Sig0Key {
	t.Helper()
	key := mustRR(t, "child.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=").(*dns.KEY)
	return &Sig0Key{
		Name:      "child.example.",
		Keyid:     key.KeyTag(),
		Validated: true,
		Source:    "dns",
		Key:       *key,
	}
}

// TestValidateUpdateRecordsAKeyItDiscoveredInDns is the WIRING.
//
// The tests above call rememberDiscoveredChildKey directly, so deleting the
// call from ValidateUpdate -- which IS the #574 fix -- left every one of them
// green. This one drives ValidateUpdate itself.
func TestValidateUpdateRecordsAKeyItDiscoveredInDns(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)
	ctx := boundedVerification(t, zd)

	discovered := discoveredTestKey(t)
	stubDnsDiscovery(t, discovered)
	stubSig0Verify(t) // the signature verifies

	us := &UpdateStatus{}
	if err := zd.ValidateUpdate(ctx, signedUpdateFrom(t, zd.ZoneName, discovered.Name, discovered.Keyid), us); err != nil {
		t.Fatalf("ValidateUpdate: %v", err)
	}

	sk, err := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid)
	if err != nil || sk == nil {
		t.Fatalf("ValidateUpdate discovered the key in DNS but recorded nothing (err=%v);"+
			" with no row there is nothing for a verification to promote, so the child"+
			" is refused forever", err)
	}
	if sk.Trusted {
		t.Error("the discovered key was recorded as trusted; discovery is not verification")
	}
}

// TestValidateUpdateDoesNotRecordAKeyWhoseSignatureFailed.
//
// Recording is a database transaction plus a goroutine that makes IMR queries
// with backoff. It used to run inside the discovery loop, before any signature
// had been checked -- so anyone able to send an UPDATE naming a child of this
// zone could buy that work, repeatedly, from off-net.
func TestValidateUpdateDoesNotRecordAKeyWhoseSignatureFailed(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)
	ctx := boundedVerification(t, zd)

	discovered := discoveredTestKey(t)
	stubDnsDiscovery(t, discovered)
	stubSig0Verify(t, discovered.Keyid) // this signature does NOT verify

	us := &UpdateStatus{}
	if err := zd.ValidateUpdate(ctx, signedUpdateFrom(t, zd.ZoneName, discovered.Name, discovered.Keyid), us); err != nil {
		t.Fatalf("ValidateUpdate: %v", err)
	}

	if sk, _ := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid); sk != nil {
		t.Error("a key was recorded for an UPDATE whose signature did not verify; a stream" +
			" of spoofed updates would each cost a transaction and a verifier goroutine")
	}
}

// TestTheDiscoveredKeyVerifierExitsOnShutdown.
//
// rememberDiscoveredChildKey starts a goroutine that retries with exponential
// backoff -- five attempts ten seconds apart by default, doubling -- so by the
// time the process is asked to stop it is usually asleep, and it writes to the
// database on the way out. It has to notice.
//
// Driven through runChildKeyVerification with an injected verifier so the
// cancellation lands inside the retry wait, which is where the goroutine
// actually spends its life.
func TestTheDiscoveredKeyVerifierExitsOnShutdown(t *testing.T) {
	kdb := newTestKeyDB(t)

	pol := compiledDefaultDelegationPolicy()
	pol.RetryMaxAttempts = 5
	pol.RetryInterval = time.Hour // asleep until cancelled, or the test hangs

	attempted := make(chan struct{}, 1)
	verify := func(ctx context.Context) (bool, bool, error) {
		select {
		case attempted <- struct{}{}:
		default:
		}
		return false, false, errors.New("not yet")
	}

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan bool, 1)
	go func() {
		returned <- kdb.runChildKeyVerification(ctx, "child.example.", 4711, pol, verify)
	}()

	select {
	case <-attempted:
	case <-time.After(5 * time.Second):
		t.Fatal("the verifier never made its first attempt")
	}
	cancel()

	select {
	case accepted := <-returned:
		if accepted {
			t.Error("a verifier abandoned at shutdown reported the key as accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the verifier did not return after its context was cancelled; it would go on" +
			" sleeping through shutdown and then write to a closing database")
	}

	// A cancel is a shutdown, not a verdict: nothing may be recorded against
	// the key, or a child would be told that waiting will not help when
	// nothing was concluded.
	if sk, _ := kdb.FindSig0TrustedKey("child.example.", 4711); sk != nil && sk.ValidationFailed {
		t.Error("shutdown recorded a validation failure; the key was never judged")
	}
}

// TestRediscoveringATrustedKeyDoesNotDemoteIt.
//
// The add was INSERT OR REPLACE and discovery writes trusted=0, so a second
// discovery of a key that verification had already promoted put it straight
// back to untrusted -- and started a second verification of a key that was
// already trusted. Two concurrent first updates from the same child are enough
// to reach it: ValidateUpdate's truststore lookup only short-circuits once a
// row exists.
func TestRediscoveringATrustedKeyDoesNotDemoteIt(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)
	ctx := boundedVerification(t, zd)

	discovered := discoveredTestKey(t)
	zd.rememberDiscoveredChildKey(ctx, discovered)

	// Verification concludes: the key is trusted.
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		SubCommand:      "verify",
		Keyname:         discovered.Name,
		Keyid:           int(discovered.Keyid),
		DnssecValidated: true,
	}); err != nil {
		t.Fatalf("promoting the key: %v", err)
	}
	if sk, _ := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid); sk == nil || !sk.Trusted {
		t.Fatal("fixture: the key was not promoted, so there is no demotion to test")
	}

	// A second discovery of the same key.
	if zd.rememberDiscoveredChildKey(ctx, discovered) {
		t.Error("rediscovering a key that is already in the truststore started another" +
			" verification; the row already says everything the discovery does, and the" +
			" key may by now be trusted")
	}

	sk, err := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid)
	if err != nil || sk == nil {
		t.Fatalf("the row disappeared: %v", err)
	}
	if !sk.Trusted {
		t.Error("rediscovering a key that was already trusted demoted it to untrusted;" +
			" every update from that child is refused again until a second verification" +
			" happens to complete")
	}
}

// TestAZoneThatWillNotVerifyRecordsNothing.
//
// A delegation policy with no mechanisms is an operator declining automatic
// bootstrap. Recording a row anyway leaves an untrusted entry that nothing can
// ever promote, and no log line saying so -- the same dead end #574 was, only
// now it looks like progress in the truststore listing.
func TestAZoneThatWillNotVerifyRecordsNothing(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)

	pol := compiledDefaultDelegationPolicy()
	pol.Mechanisms = nil
	zd.DelegationPolicy = &pol

	discovered := discoveredTestKey(t)
	zd.rememberDiscoveredChildKey(context.Background(), discovered)

	if sk, _ := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid); sk != nil {
		t.Error("a row was stored for a zone whose policy has no verification mechanisms;" +
			" nothing will ever promote it, so it is an entry that only looks like progress")
	}
}

// TestTheUpdatePathCarriesItsOwnShutdownContext.
//
// The verification a discovered key starts used to take its context from
// KeyDB.engineCtx, a plain field written by ZoneUpdaterEngine's goroutine and
// read from the UPDATE path on another. Two failures in one: an unsynchronised
// write against a concurrent read, and -- before the updater had got round to
// storing it -- a nil field, which lifetimeCtx turned into context.Background(),
// so a verification started then could outlive shutdown entirely.
//
// The context now comes down the call chain. This asserts it arrives: cancel it
// and the verification must not survive.
func TestTheUpdatePathCarriesItsOwnShutdownContext(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)

	pol := compiledDefaultDelegationPolicy()
	pol.RetryMaxAttempts = 5
	pol.RetryInterval = time.Hour // asleep until cancelled
	zd.DelegationPolicy = &pol

	discovered := discoveredTestKey(t)
	stubDnsDiscovery(t, discovered)
	stubSig0Verify(t)

	ctx, cancel := context.WithCancel(context.Background())
	us := &UpdateStatus{}
	if err := zd.ValidateUpdate(ctx, signedUpdateFrom(t, zd.ZoneName, discovered.Name, discovered.Keyid), us); err != nil {
		t.Fatalf("ValidateUpdate: %v", err)
	}
	if sk, _ := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid); sk == nil {
		t.Fatal("the key was not recorded, so no verification was started to cancel")
	}

	// Cancelling the UPDATE path's context must reach the verifier it started.
	// A verifier holding context.Background() would sit out its hour instead.
	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sk, _ := kdb.FindSig0TrustedKey(discovered.Name, discovered.Keyid)
		if sk != nil && sk.ValidationFailed {
			t.Fatal("cancellation was recorded as a validation failure; a shutdown is not a" +
				" verdict on the key")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
