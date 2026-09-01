/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"
	"testing"
	"time"
)

func TestDsyncApiKeyIsGeneratedAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		k, err := GenerateDsyncApiKey()
		if err != nil {
			t.Fatalf("GenerateDsyncApiKey: %v", err)
		}
		if seen[k] {
			t.Fatalf("generated the same key twice: %q", k)
		}
		seen[k] = true
		// 32 bytes in unpadded base64url. Shorter would mean the entropy
		// assumption behind hashing with plain SHA-256 no longer holds.
		if len(k) < 40 {
			t.Errorf("key %q is only %d chars; want >= 40", k, len(k))
		}
	}
}

func TestDsyncApiCredentialRoundTrip(t *testing.T) {
	kdb := newTestKeyDB(t)

	key, err := kdb.AddDsyncApiCredential("example.", "child1.example.", "", "test cred", time.Time{})
	if err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}
	if key == "" {
		t.Fatal("no key returned")
	}

	cred, err := kdb.VerifyDsyncApiCredential("example.", "child1.example.", key)
	if err != nil {
		t.Fatalf("VerifyDsyncApiCredential with the right key: %v", err)
	}
	// The principal defaults to the username, which is what makes
	// updatepolicy.child mean the same thing on this transport as on DDNS.
	if cred.Principal != "child1.example." {
		t.Errorf("principal = %q, want %q", cred.Principal, "child1.example.")
	}

	if _, err := kdb.VerifyDsyncApiCredential("example.", "child1.example.", key+"x"); err == nil {
		t.Error("a wrong key authenticated")
	}
	if _, err := kdb.VerifyDsyncApiCredential("example.", "nosuchuser.example.", key); err == nil {
		t.Error("an unknown username authenticated")
	}
	// The credential is scoped to one parent zone. A registrant holding a
	// credential for one parent must not be able to use it against another
	// parent served by the same daemon.
	if _, err := kdb.VerifyDsyncApiCredential("other.example.", "child1.example.", key); err == nil {
		t.Error("a credential authenticated against a different parent zone")
	}
}

// The key must exist in plaintext exactly once: in the return value. Nothing
// that reads the store may hand it back.
func TestDsyncApiCredentialKeyIsNotRecoverable(t *testing.T) {
	kdb := newTestKeyDB(t)

	key, err := kdb.AddDsyncApiCredential("example.", "child1.example.", "", "", time.Time{})
	if err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}

	creds, err := kdb.ListDsyncApiCredentials("example.")
	if err != nil {
		t.Fatalf("ListDsyncApiCredentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d credentials, want 1", len(creds))
	}

	// The struct has no key field at all; this asserts the stored row does not
	// leak it through some other column either.
	for _, s := range []string{creds[0].Username, creds[0].Principal, creds[0].Comment, creds[0].ParentZone} {
		if s == key {
			t.Errorf("the plaintext key came back out of the store in %q", s)
		}
	}
}

func TestDsyncApiCredentialExplicitPrincipal(t *testing.T) {
	kdb := newTestKeyDB(t)

	// A human-readable account name mapped to the DNS name the policy is
	// evaluated against.
	key, err := kdb.AddDsyncApiCredential("example.", "acme-registrar", "child1.example.", "", time.Time{})
	if err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}
	cred, err := kdb.VerifyDsyncApiCredential("example.", "acme-registrar", key)
	if err != nil {
		t.Fatalf("VerifyDsyncApiCredential: %v", err)
	}
	if cred.Principal != "child1.example." {
		t.Errorf("principal = %q, want the explicit one", cred.Principal)
	}

	// A principal that is not a domain name cannot be compared against an
	// owner name, so it is refused at provisioning rather than becoming a 403
	// on every request later.
	if _, err := kdb.AddDsyncApiCredential("example.", "bob", "not a domain name", "", time.Time{}); err == nil {
		t.Error("a non-domain-name principal was accepted")
	}
}

func TestDsyncApiCredentialDisabledAndExpired(t *testing.T) {
	kdb := newTestKeyDB(t)

	key, err := kdb.AddDsyncApiCredential("example.", "child1.example.", "", "", time.Time{})
	if err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}

	if ok, err := kdb.SetDsyncApiCredentialDisabled("example.", "child1.example.", true); err != nil || !ok {
		t.Fatalf("SetDsyncApiCredentialDisabled: ok=%v err=%v", ok, err)
	}
	if _, err := kdb.VerifyDsyncApiCredential("example.", "child1.example.", key); err == nil {
		t.Error("a disabled credential authenticated")
	}
	// Disabling keeps the row, so the audit trail survives revocation.
	if creds, _ := kdb.ListDsyncApiCredentials("example."); len(creds) != 1 || !creds[0].Disabled {
		t.Errorf("disabling lost the row or the flag: %+v", creds)
	}

	if ok, err := kdb.SetDsyncApiCredentialDisabled("example.", "child1.example.", false); err != nil || !ok {
		t.Fatalf("re-enabling: ok=%v err=%v", ok, err)
	}
	if _, err := kdb.VerifyDsyncApiCredential("example.", "child1.example.", key); err != nil {
		t.Errorf("a re-enabled credential was refused: %v", err)
	}

	// Expiry.
	expKey, err := kdb.AddDsyncApiCredential("example.", "temp.example.", "", "", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}
	if _, err := kdb.VerifyDsyncApiCredential("example.", "temp.example.", expKey); err == nil {
		t.Error("an expired credential authenticated")
	}
}

// Failure must not tell an unauthenticated client which of the several ways it
// failed. Same error text for every case, so a handler cannot accidentally
// forward a distinguishing message into a response body.
func TestDsyncApiCredentialFailuresAreIndistinguishable(t *testing.T) {
	kdb := newTestKeyDB(t)

	good, err := kdb.AddDsyncApiCredential("example.", "child1.example.", "", "", time.Time{})
	if err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}
	if _, err := kdb.AddDsyncApiCredential("example.", "off.example.", "", "", time.Time{}); err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}
	if _, err := kdb.SetDsyncApiCredentialDisabled("example.", "off.example.", true); err != nil {
		t.Fatalf("SetDsyncApiCredentialDisabled: %v", err)
	}

	var msgs []string
	for _, tc := range []struct{ user, key string }{
		{"child1.example.", "wrong-key"},
		{"nosuchuser.example.", good},
		{"off.example.", good},
	} {
		_, err := kdb.VerifyDsyncApiCredential("example.", tc.user, tc.key)
		if err == nil {
			t.Fatalf("%s authenticated when it should not have", tc.user)
		}
		msgs = append(msgs, err.Error())
	}
	for _, m := range msgs[1:] {
		if m != msgs[0] {
			t.Errorf("failure messages differ: %q vs %q", msgs[0], m)
		}
	}
}

func TestDsyncApiCredentialNormalisation(t *testing.T) {
	kdb := newTestKeyDB(t)

	// The zone is a domain name and is normalised as one: written here
	// without the trailing dot and in mixed case, looked up canonically.
	key, err := kdb.AddDsyncApiCredential("Example", "Child1.Example", "", "", time.Time{})
	if err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}
	if _, err := kdb.VerifyDsyncApiCredential("example.", "child1.example", key); err != nil {
		t.Errorf("zone normalisation failed: %v", err)
	}

	// Usernames get domain-name normalisation too, so all four spellings are
	// one account. In a DNS system "bob" and "bob." naming different things
	// would be a trap: provisioned one way, typed the other, and the failure
	// is an indistinguishable 401 that says nothing about why.
	for _, spelling := range []string{"child1.example", "child1.example.", "CHILD1.EXAMPLE", "CHILD1.EXAMPLE."} {
		if _, err := kdb.VerifyDsyncApiCredential("example.", spelling, key); err != nil {
			t.Errorf("username spelling %q did not resolve to the same account: %v", spelling, err)
		}
		_, err := kdb.AddDsyncApiCredential("example.", spelling, "", "", time.Time{})
		if err == nil {
			t.Errorf("username spelling %q was accepted as a second account", spelling)
			continue
		}
		// And says so in a way an operator can act on. The raw sqlite message
		// names columns and does not mention that normalisation is why two
		// apparently different usernames collided.
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("duplicate of %q reported as %q; want a message about it already existing", spelling, err)
		}
	}

	creds, err := kdb.ListDsyncApiCredentials("example.")
	if err != nil || len(creds) != 1 {
		t.Fatalf("ListDsyncApiCredentials: %v (%d creds)", err, len(creds))
	}
	if creds[0].Username != "child1.example." {
		t.Errorf("username = %q, want the canonical form %q", creds[0].Username, "child1.example.")
	}
	if creds[0].Principal != "child1.example." {
		t.Errorf("principal = %q, want the FQDN form %q", creds[0].Principal, "child1.example.")
	}
}

// A username that is not a domain name still works: it just gets the same
// normalisation, so "acme-registrar" is stored and matched as
// "acme-registrar.". Not every deployment names accounts after zones.
func TestDsyncApiCredentialNonDomainUsername(t *testing.T) {
	kdb := newTestKeyDB(t)

	key, err := kdb.AddDsyncApiCredential("example.", "acme-registrar", "child1.example.", "", time.Time{})
	if err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}
	// Either spelling authenticates; the client need not know which form was
	// used at provisioning.
	for _, spelling := range []string{"acme-registrar", "acme-registrar."} {
		cred, err := kdb.VerifyDsyncApiCredential("example.", spelling, key)
		if err != nil {
			t.Fatalf("VerifyDsyncApiCredential(%q): %v", spelling, err)
		}
		if cred.Username != "acme-registrar." {
			t.Errorf("username = %q, want the canonical %q", cred.Username, "acme-registrar.")
		}
	}

	// An opaque username with no explicit principal cannot work: it would
	// have to serve as the principal, and it is not a domain name the policy
	// could compare against. Refused at provisioning.
	if _, err := kdb.AddDsyncApiCredential("example.", "acme registrar", "", "", time.Time{}); err == nil {
		t.Error("a username with spaces and no explicit principal was accepted")
	}
}

func TestDsyncApiCredentialDelete(t *testing.T) {
	kdb := newTestKeyDB(t)

	key, err := kdb.AddDsyncApiCredential("example.", "child1.example.", "", "", time.Time{})
	if err != nil {
		t.Fatalf("AddDsyncApiCredential: %v", err)
	}
	ok, err := kdb.DeleteDsyncApiCredential("example.", "child1.example.")
	if err != nil || !ok {
		t.Fatalf("DeleteDsyncApiCredential: ok=%v err=%v", ok, err)
	}
	if _, err := kdb.VerifyDsyncApiCredential("example.", "child1.example.", key); err == nil {
		t.Error("a deleted credential authenticated")
	}
	if ok, _ := kdb.DeleteDsyncApiCredential("example.", "child1.example."); ok {
		t.Error("deleting a nonexistent credential reported success")
	}
}
