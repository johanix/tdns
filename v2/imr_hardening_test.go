/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadImrListenerCert: mutually exclusive checks, one accurate reason each.
func TestLoadImrListenerCert(t *testing.T) {
	dir := t.TempDir()

	// Valid pair, from the shared test-cert generator.
	cert, _ := newUpstreamTestCert(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	garbageFile := filepath.Join(dir, "garbage.pem")
	for file, data := range map[string][]byte{
		certFile:    certPEM,
		keyFile:     keyPEM,
		garbageFile: []byte("not a pem file"),
	} {
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatalf("write %s: %v", file, err)
		}
	}

	cases := []struct {
		name       string
		cert, key  string
		ok         bool
		reasonPart string
	}{
		{"valid pair", certFile, keyFile, true, ""},
		{"unconfigured", "", "", false, "not configured"},
		{"half configured", certFile, "", false, "not configured"},
		{"missing certfile", filepath.Join(dir, "nope.crt"), keyFile, false, "certfile"},
		{"missing keyfile", certFile, filepath.Join(dir, "nope.key"), false, "keyfile"},
		{"unparseable pair", garbageFile, keyFile, false, "loading"},
	}
	for _, c := range cases {
		loaded, reason, ok := loadImrListenerCert(c.cert, c.key)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v (reason=%q)", c.name, ok, c.ok, reason)
			continue
		}
		if c.ok {
			if len(loaded.Certificate) == 0 {
				t.Errorf("%s: no certificate loaded", c.name)
			}
			continue
		}
		if !strings.Contains(reason, c.reasonPart) {
			t.Errorf("%s: reason %q does not mention %q", c.name, reason, c.reasonPart)
		}
	}
}
