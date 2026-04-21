/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Bootstrap-configure library: generation of missing material.
 *
 * Apps invoke these from their GenerateMissingMaterial callback
 * in the Spec. Generation is reuse-by-default: if the target
 * file already exists, the function is a no-op. Rotation is out
 * of scope for this library.
 *
 *   - EnsureApiKey     — in-memory random string, caller persists.
 *   - EnsureJoseKeypair — writes priv + pub to disk.
 *   - EnsureTLSCert    — self-signed via openssl.
 */
package configure

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose"
)

// GenerateApiKey returns a hex-encoded 32-byte random key.
func GenerateApiKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// EnsureApiKey returns `current` if non-empty, else a freshly
// generated key. The caller is responsible for persisting the
// returned value into the rendered config.
func EnsureApiKey(current string) (string, error) {
	if current != "" {
		return current, nil
	}
	return GenerateApiKey()
}

// EnsureJoseKeypair generates a JOSE keypair at privPath (and a
// matching pubPath derived by substituting ".priv." → ".pub.")
// if privPath does not already exist. Returns the pub path, the
// KeyID for display, and a bool indicating whether generation
// actually ran.
func EnsureJoseKeypair(privPath string) (pubPath, keyID string, generated bool, err error) {
	pubPath = DerivePubPath(privPath)

	if _, statErr := os.Stat(privPath); statErr == nil {
		return pubPath, "", false, nil
	} else if !os.IsNotExist(statErr) {
		return "", "", false, fmt.Errorf("stat %s: %w", privPath, statErr)
	}

	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return "", "", false, fmt.Errorf("mkdir %s: %w", filepath.Dir(privPath), err)
	}

	backend, err := crypto.GetBackend("jose")
	if err != nil {
		return "", "", false, fmt.Errorf("jose backend: %w", err)
	}
	priv, pub, err := backend.GenerateKeypair()
	if err != nil {
		return "", "", false, fmt.Errorf("generate jose keypair: %w", err)
	}
	privBytes, err := backend.SerializePrivateKey(priv)
	if err != nil {
		return "", "", false, fmt.Errorf("serialize priv: %w", err)
	}
	pubBytes, err := backend.SerializePublicKey(pub)
	if err != nil {
		return "", "", false, fmt.Errorf("serialize pub: %w", err)
	}
	defer zero(privBytes)

	keyID = joseKeyID(pubBytes)

	privPretty, err := prettyJSON(privBytes)
	if err != nil {
		return "", "", false, err
	}
	defer zero(privPretty)
	pubPretty, err := prettyJSON(pubBytes)
	if err != nil {
		return "", "", false, err
	}

	header := fmt.Sprintf(`# JOSE Private Key
# KeyID: %s
# Config: long_term_jose_priv_key: %s
# WARNING: This is a PRIVATE KEY. Keep it secret.
#
`, keyID, privPath)
	content := []byte(header + string(privPretty) + "\n")
	defer zero(content)

	f, err := os.OpenFile(privPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", false, fmt.Errorf("create %s: %w", privPath, err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return "", "", false, fmt.Errorf("write %s: %w", privPath, err)
	}
	if err := f.Close(); err != nil {
		return "", "", false, fmt.Errorf("close %s: %w", privPath, err)
	}

	if err := os.WriteFile(pubPath, append(pubPretty, '\n'), 0o644); err != nil {
		return "", "", false, fmt.Errorf("write %s: %w", pubPath, err)
	}
	return pubPath, keyID, true, nil
}

// DerivePubPath turns "…/foo.jose.priv.json" into
// "…/foo.jose.pub.json". If ".priv." is absent the path is
// returned with ".pub" inserted before the extension.
func DerivePubPath(priv string) string {
	if strings.Contains(priv, ".priv.") {
		return strings.Replace(priv, ".priv.", ".pub.", 1)
	}
	ext := filepath.Ext(priv)
	return strings.TrimSuffix(priv, ext) + ".pub" + ext
}

func joseKeyID(pubBytes []byte) string {
	const n = 8
	if len(pubBytes) < n {
		return "jose_" + hex.EncodeToString(pubBytes)
	}
	h := hex.EncodeToString(pubBytes)
	if len(h) < n {
		return "jose_" + h
	}
	return "jose_" + h[:n]
}

func prettyJSON(raw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	return json.MarshalIndent(v, "", "  ")
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EnsureTLSCert writes a self-signed cert + key to certPath /
// keyPath if certPath does not already exist.
//
// SAN = DNS:<cn>, DNS:localhost, IP:<listenIP>, IP:127.0.0.1
// (deduped). CN is the identity with trailing dot stripped.
//
// Requires `openssl` on PATH. Non-interactive.
func EnsureTLSCert(certPath, keyPath, identity, listenHostPort string) (generated bool, err error) {
	if _, statErr := os.Stat(certPath); statErr == nil {
		return false, nil
	} else if !os.IsNotExist(statErr) {
		return false, fmt.Errorf("stat %s: %w", certPath, statErr)
	}

	if _, err := exec.LookPath("openssl"); err != nil {
		return false, fmt.Errorf("openssl not found on PATH: %w", err)
	}

	cn := strings.TrimSuffix(identity, ".")
	if cn == "" {
		return false, fmt.Errorf("identity is required for cert CN")
	}

	host, _, splitErr := net.SplitHostPort(listenHostPort)
	if splitErr != nil {
		host = ""
	}

	dnsNames := dedup([]string{cn, "localhost"})
	ips := dedup(trimEmpty([]string{host, "127.0.0.1"}))
	san := buildSAN(dnsNames, ips)

	for _, p := range []string{certPath, keyPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(p), err)
		}
	}

	tmp, err := os.CreateTemp("", "openssl-san-*.cnf")
	if err != nil {
		return false, fmt.Errorf("tempfile: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	cnf := fmt.Sprintf(`[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
x509_extensions    = v3_req
prompt             = no

[ req_distinguished_name ]
CN = %s

[ v3_req ]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = %s
`, cn, san)

	if _, err := tmp.WriteString(cnf); err != nil {
		tmp.Close()
		return false, fmt.Errorf("write openssl cnf: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close openssl cnf: %w", err)
	}

	cmd := exec.Command(
		"openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath,
		"-out", certPath,
		"-days", "3650",
		"-config", tmpName,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("openssl req: %w", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return false, fmt.Errorf("chmod %s: %w", keyPath, err)
	}
	return true, nil
}

func buildSAN(dns, ips []string) string {
	var parts []string
	for _, n := range dns {
		parts = append(parts, "DNS:"+n)
	}
	for _, ip := range ips {
		parts = append(parts, "IP:"+ip)
	}
	return strings.Join(parts, ",")
}

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func trimEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
