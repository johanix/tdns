/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"
	"testing"
	"time"
)

func TestDsyncApiCertCredentialRoundTrip(t *testing.T) {
	kdb := newTestKeyDB(t)
	_, parsed := newTestTLSCert(t, []string{"child1.example"}, nil)
	pin := SPKISHA256(parsed)

	if err := kdb.AddDsyncApiCertCredential("example.", "tls-pin", pin, "child1.example.", "pin cred", time.Time{}); err != nil {
		t.Fatalf("Add tls-pin: %v", err)
	}
	if err := kdb.AddDsyncApiCertCredential("example.", "tls-pkix", "Child1.Example", "", "pkix cred", time.Time{}); err != nil {
		t.Fatalf("Add tls-pkix: %v", err)
	}

	pinRow, err := kdb.LookupDsyncApiCertCredential("example.", "tls-pin", pin)
	if err != nil || pinRow == nil {
		t.Fatalf("lookup pin: %v %#v", err, pinRow)
	}
	if pinRow.Principal != "child1.example." || pinRow.AuthMech != DsyncApiAuthTLSPin {
		t.Errorf("pin row = %+v", pinRow)
	}

	pkixRow, err := kdb.LookupDsyncApiCertCredential("EXAMPLE", "TLS-PKIX", "child1.example")
	if err != nil || pkixRow == nil {
		t.Fatalf("lookup pkix: %v %#v", err, pkixRow)
	}
	if pkixRow.Identity != "child1.example." || pkixRow.Principal != "child1.example." {
		t.Errorf("pkix row = %+v", pkixRow)
	}

	all, err := kdb.ListDsyncApiAllCredentials("example.")
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("list all: got %d, want 2", len(all))
	}
}

func TestDsyncApiCertCredentialPinFormatRefused(t *testing.T) {
	kdb := newTestKeyDB(t)
	hexPin := strings.Repeat("ab", 32) // 64 hex chars, a TLSA 3-1-1 spelling
	err := kdb.AddDsyncApiCertCredential("example.", "tls-pin", hexPin, "child1.example.", "", time.Time{})
	if err == nil {
		t.Fatal("a hex pin was accepted")
	}
	if !strings.Contains(err.Error(), "44-character") {
		t.Errorf("error = %v, want a format explanation", err)
	}

	err = kdb.AddDsyncApiCertCredential("example.", "tls-pin", "short", "child1.example.", "", time.Time{})
	if err == nil {
		t.Fatal("a short pin was accepted")
	}
}

func TestDsyncApiCertCredentialUnknownMechRefused(t *testing.T) {
	kdb := newTestKeyDB(t)
	if err := kdb.AddDsyncApiCertCredential("example.", "tls-dane", "child1.example.", "child1.example.", "", time.Time{}); err == nil {
		t.Fatal("tls-dane was accepted")
	}
	if err := kdb.AddDsyncApiCertCredential("example.", "mtls", "child1.example.", "child1.example.", "", time.Time{}); err == nil {
		t.Fatal("an unknown mechanism was accepted")
	}
}

func TestDsyncApiCertCredentialUnusablePrincipalRefused(t *testing.T) {
	kdb := newTestKeyDB(t)
	_, parsed := newTestTLSCert(t, []string{"child1.example"}, nil)
	pin := SPKISHA256(parsed)
	if err := kdb.AddDsyncApiCertCredential("example.", "tls-pin", pin, "not a domain name", "", time.Time{}); err == nil {
		t.Fatal("an unusable principal was accepted")
	}
	if err := kdb.AddDsyncApiCertCredential("example.", "tls-pin", pin, "", "", time.Time{}); err == nil {
		t.Fatal("tls-pin with no principal was accepted")
	}
}

func TestDsyncApiCertCredentialDuplicate(t *testing.T) {
	kdb := newTestKeyDB(t)
	if err := kdb.AddDsyncApiCertCredential("example.", "tls-pkix", "child1.example.", "child1.example.", "", time.Time{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	err := kdb.AddDsyncApiCertCredential("example.", "tls-pkix", "CHILD1.EXAMPLE", "child1.example.", "", time.Time{})
	if err == nil {
		t.Fatal("a normalised duplicate was accepted")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v, want the capitalisation hint", err)
	}
}

func TestDsyncApiCertCredentialDisabledAndExpired(t *testing.T) {
	kdb := newTestKeyDB(t)
	if err := kdb.AddDsyncApiCertCredential("example.", "tls-pkix", "child1.example.", "", "", time.Time{}); err != nil {
		t.Fatalf("add: %v", err)
	}
	ok, err := kdb.SetDsyncApiCertCredentialDisabled("example.", "tls-pkix", "child1.example.", true)
	if err != nil || !ok {
		t.Fatalf("disable: ok=%v err=%v", ok, err)
	}
	row, err := kdb.LookupDsyncApiCertCredential("example.", "tls-pkix", "child1.example.")
	if err != nil || row == nil || row.Usable(time.Now()) {
		t.Fatalf("disabled row still usable: %+v err=%v", row, err)
	}

	if err := kdb.AddDsyncApiCertCredential("example.", "tls-pkix", "temp.example.", "", "", time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("add expired: %v", err)
	}
	exp, err := kdb.LookupDsyncApiCertCredential("example.", "tls-pkix", "temp.example.")
	if err != nil || exp == nil || exp.Usable(time.Now()) {
		t.Fatalf("expired row still usable: %+v err=%v", exp, err)
	}

	ok, err = kdb.DeleteDsyncApiCertCredential("example.", "tls-pkix", "child1.example.")
	if err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	gone, err := kdb.LookupDsyncApiCertCredential("example.", "tls-pkix", "child1.example.")
	if err != nil || gone != nil {
		t.Fatalf("deleted row still present: %+v err=%v", gone, err)
	}
}

func TestDsyncApiAllCredentialsUnionsKinds(t *testing.T) {
	kdb := newTestKeyDB(t)
	if _, err := kdb.AddDsyncApiCredential("example.", "child1.example.", "", "", time.Time{}); err != nil {
		t.Fatalf("add basic: %v", err)
	}
	if err := kdb.AddDsyncApiCertCredential("example.", "tls-pkix", "child2.example.", "", "", time.Time{}); err != nil {
		t.Fatalf("add cert: %v", err)
	}
	all, err := kdb.ListDsyncApiAllCredentials("example.")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d credentials, want 2", len(all))
	}
	methods := map[string]bool{}
	for _, c := range all {
		methods[c.AuthMethod] = true
	}
	if !methods[DsyncApiAuthBasic] || !methods[DsyncApiAuthTLSPkix] {
		t.Errorf("methods = %v, want basic and tls-pkix", methods)
	}
}
