package tdns

import (
	"testing"

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

	zd.rememberDiscoveredChildKey(discovered)

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
}

// Any signer at all can publish a KEY and send a signed UPDATE. Only names this
// zone actually delegates get a row.
func TestADiscoveredKeyForANonChildIsNotRecorded(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb

	key := mustRR(t, "stranger.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=").(*dns.KEY)
	zd.rememberDiscoveredChildKey(&Sig0Key{
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

	zd.rememberDiscoveredChildKey(discovered)

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
