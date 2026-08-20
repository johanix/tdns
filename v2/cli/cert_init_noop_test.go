package cli

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// The no-op path must only trigger for a pair the DAEMON would accept.
//
// "Both files exist" is not that: a certificate and a key from different
// issuances each load fine alone and fail together, so reporting nothing to do
// would hand back success and let the daemon fail later with a TLS error that
// names none of this. That is the same shape as the bug this command's no-op
// was added to fix, just pointing the other way.
func TestExistingPairMustActuallyLoad(t *testing.T) {
	dir := t.TempDir()

	a, err := tdns.CreateCA(tdns.CAOptions{Name: "test-a", Alg: tdns.CertAlgorithm("ed25519")})
	if err != nil {
		t.Fatalf("CreateCA a: %v", err)
	}
	b, err := tdns.CreateCA(tdns.CAOptions{Name: "test-b", Alg: tdns.CertAlgorithm("ed25519")})
	if err != nil {
		t.Fatalf("CreateCA b: %v", err)
	}

	// Premise: a genuine pair loads, so a no-op for it is legitimate.
	if _, err := tls.X509KeyPair(a.CertPEM, a.KeyPEM); err != nil {
		t.Fatalf("a genuine pair failed to load, the test premise is wrong: %v", err)
	}

	// The case that must NOT be reported as fine: a's cert with b's key,
	// written to disk and read back exactly as the check does it.
	certFile := filepath.Join(dir, "srv.crt")
	keyFile := filepath.Join(dir, "srv.key")
	if err := os.WriteFile(certFile, a.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, b.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	certPEM, certErr := os.ReadFile(certFile)
	keyPEM, keyErr := os.ReadFile(keyFile)
	if certErr != nil || keyErr != nil {
		t.Fatalf("reading back: %v / %v", certErr, keyErr)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err == nil {
		t.Error("a mismatched cert/key loaded as a pair; cert init would report a false no-op")
	}
}
