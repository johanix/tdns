package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
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
	pending := ApiServerConf{Addresses: []string{"127.0.0.1:8989"}, CertPending: true}
	if err := v.Struct(pending); err != nil {
		t.Errorf("pending: %v", err)
	}
	missing := ApiServerConf{Addresses: []string{"127.0.0.1:8989"}}
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

// EnsureDefaultApiCert is how the daemon makes its default pair at its
// first start (tdns-ncli never makes it): the certs directory
// made 0755, the key 0600, the certificate 0644, the pin returned; a pair
// that is there left alone; half a pair refused, its file not touched.
func TestEnsureDefaultApiCert(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-auth.yaml")
	cert, key := ApiCertPaths(cfg)
	pin, created, err := EnsureDefaultApiCert(cfg, []string{"192.0.2.1:8989"})
	if err != nil || !created || len(pin) != 44 {
		t.Fatalf("first: %q %v %v", pin, created, err)
	}
	// The umask narrows the modes asked for (077 leaves 0700 and 0600): no
	// bit outside them, and the key no group or other bit at all, and
	// readable and writable by its owner.
	for p, want := range map[string]os.FileMode{filepath.Dir(cert): 0o755, cert: 0o644} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got&^want != 0 {
			t.Errorf("%s: mode %v, want %v or narrower", p, got, want)
		}
	}
	fi, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got&0o077 != 0 || got&0o600 != 0o600 {
		t.Errorf("%s: mode %v, want 0600", key, got)
	}
	data, _ := os.ReadFile(cert)
	block, _ := pem.Decode(data)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || SPKISHA256(leaf) != pin {
		t.Fatalf("the certificate does not have the pin returned: %v", err)
	}
	if !slices.ContainsFunc(leaf.IPAddresses, net.ParseIP("192.0.2.1").Equal) {
		t.Errorf("SANs %v lack the listen address", leaf.IPAddresses)
	}
	before, _ := os.ReadFile(key)
	if pin, created, err := EnsureDefaultApiCert(cfg, nil); err != nil || created || pin != "" {
		t.Errorf("again: %q %v %v, want nothing done", pin, created, err)
	}
	os.Remove(cert)
	if _, _, err := EnsureDefaultApiCert(cfg, nil); err == nil || err.Error() != HalfApiCertPairError(cert, key, false).Error() || !strings.Contains(err.Error(), "without its certificate") {
		t.Errorf("half a pair: err = %v", err)
	}
	if after, _ := os.ReadFile(key); string(after) != string(before) {
		t.Error("the remaining key was rewritten")
	}
}

// A daemon that could not write its default pair starts no TCP listener, and
// config status says so, with the certificate. The status takes it from the
// dispatcher's record, not from the config, which a reload re-reads while the
// listeners stay off until a restart.
func TestConfigStatusReportsListenersNotStartedForWantOfACert(t *testing.T) {
	resetApiDispatch(t)
	e := newAuthEnv(t, "-", nil)
	addrs := []string{freeTCPAddr(t), freeTCPAddr(t)}
	dc := &Config{}
	dc.ApiServer = ApiServerConf{Addresses: addrs, CertPending: true}
	dc.Internal.CfgFile = filepath.Join(t.TempDir(), "tdns-auth.yaml")
	dc.Internal.ServerErrors = NewServerErrorRegistry()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	if err := APIdispatcher(dc, mux.NewRouter(), done); err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if listening(a) {
			t.Errorf("%s listens without a certificate", a)
		}
	}
	cert, _ := ApiCertPaths(dc.Internal.CfgFile)
	st, body := e.callSocket(t, "/api/v1/config", `{"Command":"status"}`)
	var cr ConfigResponse
	if err := json.Unmarshal([]byte(body), &cr); st != http.StatusOK || err != nil {
		t.Fatalf("config status: %d %v %q", st, err, body)
	}
	if !slices.Equal(cr.ApiTCPNotStarted, addrs) || cr.ApiTCPNoCert != cert {
		t.Errorf("status: not started %v for want of %q; want %v and %s", cr.ApiTCPNotStarted, cr.ApiTCPNoCert, addrs, cert)
	}
	if len(cr.ApiTCPListening) != 0 || len(cr.ApiTCPFailed) != 0 {
		t.Errorf("status: listening %v, failed %+v; want none (nothing was started)", cr.ApiTCPListening, cr.ApiTCPFailed)
	}
}
