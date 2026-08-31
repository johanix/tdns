package cli

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
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

// The no-op must return BEFORE anything is provisioned -- which is a property
// of runCertInit, not of tls.X509KeyPair, so it needs the command itself.
//
// The specific fault: with the check placed after the CA block, a host that
// already had a server cert and key but no CA would mint a fresh CA and only
// then report nothing to do, leaving a stray CA that signs nothing and whose
// private key is exactly what should not be lying around. Asserting on the
// output alone would not catch that -- the message is identical either way.
// The CA directory staying absent is what pins the ordering.
func TestNoOpReturnsBeforeProvisioningACA(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca") // deliberately does not exist

	// A genuine matching pair. A CA's own cert and key are one, which saves
	// parsing a signer back out of PEM just to issue a leaf.
	pair, err := tdns.CreateCA(tdns.CAOptions{Name: "server", Alg: tdns.CertAlgorithm("ed25519")})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	certFile := filepath.Join(dir, "srv.crt")
	keyFile := filepath.Join(dir, "srv.key")
	if err := os.WriteFile(certFile, pair.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pair.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := filepath.Join(dir, "tdns-auth.yaml")
	cfgBody := "listeners:\n   certfile: " + certFile + "\n   keyfile: " + keyFile + "\n"
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o644); err != nil {
		t.Fatal(err)
	}

	// Package-level flag state; restore so tests stay order-independent.
	oldCfg, oldCADir, oldCAName, oldForce := certInitServerConfig, certInitCADir, certInitCAName, certForce
	defer func() {
		certInitServerConfig, certInitCADir, certInitCAName, certForce = oldCfg, oldCADir, oldCAName, oldForce
	}()
	certInitServerConfig, certInitCADir, certInitCAName, certForce = cfg, caDir, "tdns-ca", false

	out := captureStdout(t, runCertInit)

	if !strings.Contains(out, "Nothing to do") {
		t.Errorf("expected a no-op, got:\n%s", out)
	}
	// The assertion that pins the ordering.
	if _, err := os.Stat(caDir); err == nil {
		t.Errorf("a CA was provisioned before the no-op return: %s exists", caDir)
	}
	if _, err := os.Stat(filepath.Join(caDir, "tdns-ca.key")); err == nil {
		t.Errorf("a CA private key was written on a path that had nothing to do")
	}
}
