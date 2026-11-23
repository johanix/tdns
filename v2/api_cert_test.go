package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The default pair is named after the config file, next to it: one per
// config, so daemons whose configs share a directory get keys of their own.
func TestApiCertPaths(t *testing.T) {
	for _, tc := range []struct{ cfg, cert, key string }{
		{"/etc/tdns/tdns-auth.yaml", "/etc/tdns/certs/tdns-auth-api.crt", "/etc/tdns/certs/tdns-auth-api.key"},
		{"/etc/tdns/tdns-imr.yaml", "/etc/tdns/certs/tdns-imr-api.crt", "/etc/tdns/certs/tdns-imr-api.key"},
		{"/etc/tdns/auth-enc.yaml", "/etc/tdns/certs/auth-enc-api.crt", "/etc/tdns/certs/auth-enc-api.key"},
		{"/etc/tdns-site/tdns-auth.yaml", "/etc/tdns-site/certs/tdns-auth-api.crt", "/etc/tdns-site/certs/tdns-auth-api.key"},
		{"", "", ""},
	} {
		if c, k := ApiCertPaths(tc.cfg); c != tc.cert || k != tc.key {
			t.Errorf("ApiCertPaths(%q) = %q %q, want %q %q", tc.cfg, c, k, tc.cert, tc.key)
		}
	}
}

// With no certfile/keyfile in the config: the default pair, written
// self-signed at the daemon's first start, never overwritten, and pending
// (not written) for a config check. Paths the config names are its own.
func TestApplyCertDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-auth.yaml")
	cert, key := ApiCertPaths(cfg)

	named := ApiServerConf{CertFile: "/x.crt", KeyFile: "/x.key", Addresses: []string{"127.0.0.1:8989"}}
	named.applyCertDefaults(cfg, true)
	if named.CertFile != "/x.crt" || named.KeyFile != "/x.key" || named.CertPending {
		t.Errorf("named paths changed: %+v", named)
	}
	if _, err := os.Stat(cert); err == nil {
		t.Fatal("a pair was written for a config that names its own")
	}

	none := ApiServerConf{}
	none.applyCertDefaults(cfg, true)
	if none.CertFile != "" || none.CertPending {
		t.Errorf("no TCP listener: %+v, want nothing written, nothing pending", none)
	}

	check := ApiServerConf{Addresses: []string{"127.0.0.1:8989"}}
	check.applyCertDefaults(cfg, false)
	if check.CertFile != "" || !check.CertPending {
		t.Errorf("config check: %+v, want pending and no paths", check)
	}
	if _, err := os.Stat(cert); err == nil {
		t.Fatal("a config check wrote the pair")
	}

	start := ApiServerConf{Addresses: []string{"192.0.2.53:8989", "[::]:8989"}}
	start.applyCertDefaults(cfg, true)
	if start.CertFile != cert || start.KeyFile != key || start.CertPending {
		t.Fatalf("first start: %+v, want the default pair", start)
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode: %v %v, want 0600", fi.Mode().Perm(), err)
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatalf("the pair does not load: %v", err)
	}
	data, _ := os.ReadFile(cert)
	b, _ := pem.Decode(data)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ips := map[string]bool{}
	for _, ip := range c.IPAddresses {
		ips[ip.String()] = true
	}
	if !ips["127.0.0.1"] || !ips["::1"] || !ips["192.0.2.53"] || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || c.IsCA {
		t.Errorf("certificate: IPs %v, EKU %v, CA %v", c.IPAddresses, c.ExtKeyUsage, c.IsCA)
	}
	if !strings.Contains(strings.Join(c.DNSNames, " "), "localhost") || c.Subject.CommonName != "tdns-auth-api" {
		t.Errorf("certificate: DNS %v, CN %q", c.DNSNames, c.Subject.CommonName)
	}

	// The next start uses it, and writes nothing.
	again := ApiServerConf{Addresses: []string{"127.0.0.1:8989"}}
	again.applyCertDefaults(cfg, true)
	if after, _ := os.ReadFile(cert); string(after) != string(data) || again.CertFile != cert {
		t.Errorf("the second start rewrote the pair or did not use it: %+v", again)
	}

	// Half a pair: used as it is, so that the validator refuses it; the
	// remaining key is not overwritten.
	os.Remove(cert)
	keyBefore, _ := os.ReadFile(key)
	half := ApiServerConf{Addresses: []string{"127.0.0.1:8989"}}
	half.applyCertDefaults(cfg, true)
	if keyAfter, _ := os.ReadFile(key); half.CertFile != cert || half.CertPending || string(keyAfter) != string(keyBefore) {
		t.Errorf("half a pair: %+v, key rewritten %v", half, string(keyAfter) != string(keyBefore))
	}
}

// A pending default pair passes validation (the daemon writes it at start);
// a missing named pair does not.
func TestPendingCertValidates(t *testing.T) {
	v, err := NewCustomValidator()
	if err != nil {
		t.Fatal(err)
	}
	pending := ApiServerConf{Addresses: []string{"127.0.0.1:8989"}, ApiKey: "k", CertPending: true}
	if err := v.Struct(pending); err != nil {
		t.Errorf("pending: %v", err)
	}
	missing := ApiServerConf{Addresses: []string{"127.0.0.1:8989"}, ApiKey: "k"}
	if err := v.Struct(missing); err == nil {
		t.Error("no certfile, not pending: validated")
	}
}

// The default certificate covers every address the API listens on, a loopback
// address other than 127.0.0.1 and ::1 included, once each; wildcards are no
// names.
func TestApiCertSANs(t *testing.T) {
	dns, ips := apiCertSANs("ns1.example", []string{"127.0.0.1:8989", "127.0.0.2:8989", "[::1]:8989", "0.0.0.0:8989", "192.0.2.1:8989", "api.example:8989"})
	var got []string
	for _, ip := range ips {
		got = append(got, ip.String())
	}
	if w := "127.0.0.1 ::1 127.0.0.2 192.0.2.1"; strings.Join(got, " ") != w {
		t.Errorf("IP SANs %v, want %s", got, w)
	}
	if w := "localhost ns1.example api.example"; strings.Join(dns, " ") != w {
		t.Errorf("DNS SANs %v, want %s", dns, w)
	}
}
