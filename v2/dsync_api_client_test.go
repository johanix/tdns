/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func txtRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("cannot parse %q: %v", s, err)
	}
	return rr
}

func TestPickDsyncApiDialect(t *testing.T) {
	for _, tc := range []struct {
		name string
		rrs  []string
		want string
		ok   bool
	}{
		{"the only dialect we speak", []string{
			`dsync-api.example. 7200 IN TXT "tdns-child-api-v1.0"`}, DsyncApiDialectV1, true},
		// Parameters after the dialect are ignored, which is what makes the
		// format extensible without a version bump.
		{"dialect with parameters", []string{
			`dsync-api.example. 7200 IN TXT "tdns-child-api-v1.0 maxrrs=64 batch=yes"`}, DsyncApiDialectV1, true},
		// Several TXT records is how a parent advertises more than one
		// dialect: the version-migration story.
		{"several dialects, one we speak", []string{
			`dsync-api.example. 7200 IN TXT "some-other-api-v3"`,
			`dsync-api.example. 7200 IN TXT "tdns-child-api-v1.0"`}, DsyncApiDialectV1, true},
		// Character-strings within one TXT concatenate with no separator, as
		// SPF and DKIM do.
		{"split character-strings", []string{
			`dsync-api.example. 7200 IN TXT "tdns-child-api" "-v1.0"`}, DsyncApiDialectV1, true},

		{"a dialect we do not speak", []string{
			`dsync-api.example. 7200 IN TXT "tdns-child-api-v2.0"`}, "", false},
		{"empty TXT", []string{`dsync-api.example. 7200 IN TXT ""`}, "", false},
		{"no TXT at all", nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rrs []dns.RR
			for _, s := range tc.rrs {
				rrs = append(rrs, txtRR(t, s))
			}
			got, err := pickDsyncApiDialect(rrs)
			if tc.ok && err != nil {
				t.Fatalf("pickDsyncApiDialect: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("accepted %q; a dialect we do not speak must fail closed", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("dialect = %q, want %q", got, tc.want)
			}
		})
	}
}

// A version bump must not be half-understood. The match is on the whole token,
// so v1.0 does not accept v1.1 and vice versa.
func TestDsyncApiDialectMatchIsExact(t *testing.T) {
	for _, s := range []string{"tdns-child-api-v1", "tdns-child-api-v1.00", "TDNS-CHILD-API-V1.0", "tdns-child-api-v10"} {
		rrs := []dns.RR{txtRR(t, `dsync-api.example. 7200 IN TXT "`+s+`"`)}
		if got, err := pickDsyncApiDialect(rrs); err == nil {
			t.Errorf("%q was accepted as %q; the match must be on the whole token", s, got)
		}
	}
}

// The credential is a bearer token, so it goes over TLS or not at all. This is
// the one exposure the UPDATE scheme does not have: a misdirected signed DNS
// UPDATE leaks nothing, a misdirected POST hands over a working credential.
func TestDsyncApiRefusesPlaintextEndpoint(t *testing.T) {
	ep := &DsyncApiEndpoint{
		Target: "dsync-api.example.", Url: "http://dsync-api.example:8080/dsync/v1", Dialect: DsyncApiDialectV1,
	}
	cred := DsyncApiClientCredential{Parent: "example.", Username: "child1.example.", Key: "secret"}

	_, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.", []DsyncApiRRset{
		{Owner: "child1.example.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns1.child1.example."}},
	}, false, "")
	if err == nil {
		t.Fatal("a plaintext endpoint was used")
	}
	if !strings.Contains(err.Error(), "not https") {
		t.Errorf("error = %q; want it to name the missing https", err)
	}
}

// Refusing must happen BEFORE the credential is sent, not merely instead of
// succeeding. Asserted by observing that no request carrying Authorization
// ever arrived.
func TestDsyncApiSendsNoCredentialToAPlaintextEndpoint(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep := &DsyncApiEndpoint{Target: "t.example.", Url: srv.URL + "/dsync/v1", Dialect: DsyncApiDialectV1}
	cred := DsyncApiClientCredential{Parent: "example.", Username: "child1.example.", Key: "secret"}
	rrsets := []DsyncApiRRset{{Owner: "child1.example.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns1.child1.example."}}}

	if _, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.", rrsets, false, ""); err == nil {
		t.Fatal("the plaintext endpoint was used")
	}
	if sawAuth {
		t.Error("a credential reached a plaintext endpoint before the refusal")
	}

	// With allow-insecure the request does go through -- the lab escape hatch
	// is real, which is exactly why it is named after what it costs.
	if _, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.", rrsets, true, ""); err != nil {
		t.Fatalf("allow-insecure did not permit the request: %v", err)
	}
	if !sawAuth {
		t.Error("allow-insecure was set but no credential was sent")
	}
}

// Go strips Authorization across hosts, which makes a cross-host redirect a
// silent auth failure rather than a leak -- but a SAME-host redirect still
// carries it, and a redirect on this endpoint means something is wrong either
// way.
func TestDsyncApiRefusesRedirects(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	ep := &DsyncApiEndpoint{Target: "t.example.", Url: srv.URL + "/dsync/v1", Dialect: DsyncApiDialectV1}
	cred := DsyncApiClientCredential{Parent: "example.", Username: "child1.example.", Key: "secret"}

	_, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.", []DsyncApiRRset{
		{Owner: "child1.example.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns1.child1.example."}},
	}, true, "")
	if err == nil {
		t.Fatal("a redirect was followed")
	}
	if hits != 1 {
		t.Errorf("the redirect was followed: %d requests, want 1", hits)
	}
}

func TestDsyncApiPostSendsTheDeclaredDelegation(t *testing.T) {
	var gotUser, gotKey, gotPath string
	var gotBody DsyncApiDelegation

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotKey, _ = r.BasicAuth()
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"child":"child1.example.","rrsets":[]}`))
	}))
	defer srv.Close()

	ep := &DsyncApiEndpoint{Target: "t.example.", Url: srv.URL + "/dsync/v1", Dialect: DsyncApiDialectV1}
	cred := DsyncApiClientCredential{Parent: "example.", Username: "child1.example.", Key: "s3cret"}
	rrsets := []DsyncApiRRset{
		{Owner: "child1.example.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns1.child1.example."}},
	}

	out, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.", rrsets, true, "")
	if err != nil {
		t.Fatalf("DsyncApiPostDelegationRequest: %v", err)
	}
	if out == nil {
		t.Fatal("no delegation returned")
	}
	if gotUser != "child1.example." || gotKey != "s3cret" {
		t.Errorf("basic auth = %q/%q, want the configured credential", gotUser, gotKey)
	}
	if !strings.HasSuffix(gotPath, "/delegation/child1.example.") {
		t.Errorf("path = %q, want it to end in /delegation/child1.example.", gotPath)
	}
	if gotBody.Child != "child1.example." || len(gotBody.RRsets) != 1 {
		t.Errorf("body = %+v, want the declared delegation", gotBody)
	}
}

// A non-200 is a refusal and must be reported as one, with the parent's reason
// carried through so an operator can act on it.
func TestDsyncApiReportsParentRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("the parent zone's update policy does not place this name under your principal\n"))
	}))
	defer srv.Close()

	ep := &DsyncApiEndpoint{Target: "t.example.", Url: srv.URL + "/dsync/v1", Dialect: DsyncApiDialectV1}
	cred := DsyncApiClientCredential{Parent: "example.", Username: "child1.example.", Key: "k"}

	_, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.", []DsyncApiRRset{
		{Owner: "child1.example.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns1.child1.example."}},
	}, true, "")
	if err == nil {
		t.Fatal("a 403 was treated as success")
	}
	if !strings.Contains(err.Error(), "under your principal") {
		t.Errorf("error = %q; want the parent's own reason carried through", err)
	}
}

func TestDsyncApiRRsetsFromSyncStatus(t *testing.T) {
	mk := func(t *testing.T, s string) dns.RR { return txtRR(t, s) }

	syncstate := DelegationSyncStatus{
		NewNS: []dns.RR{
			mk(t, "child1.example. 3600 IN NS ns1.child1.example."),
			mk(t, "child1.example. 3600 IN NS ns2.child1.example."),
		},
		NewA: []dns.RR{
			mk(t, "ns1.child1.example. 3600 IN A 192.0.2.1"),
			mk(t, "ns2.child1.example. 3600 IN A 192.0.2.2"),
		},
		NewDS: []dns.RR{
			mk(t, "child1.example. 3600 IN DS 12345 15 2 "+strings.Repeat("ab", 32)),
		},
	}

	sets := DsyncApiRRsetsFromSyncStatus("child1.example.", syncstate)

	byKey := map[string]DsyncApiRRset{}
	for _, s := range sets {
		byKey[s.Owner+"/"+s.Type] = s
	}
	// Glue is grouped per nameserver name: each is its own RRset and the
	// endpoint addresses RRsets, so two A records at two owners cannot travel
	// as one entry.
	for _, key := range []string{
		"child1.example./NS", "child1.example./DS",
		"ns1.child1.example./A", "ns2.child1.example./A",
	} {
		if _, ok := byKey[key]; !ok {
			t.Errorf("no entry for %s; got %v", key, keysOfRRsets(sets))
		}
	}
	if n := len(byKey["child1.example./NS"].RRs); n != 2 {
		t.Errorf("NS entry has %d records, want 2", n)
	}
	if n := len(byKey["ns1.child1.example./A"].RRs); n != 1 {
		t.Errorf("ns1 A entry has %d records, want 1", n)
	}

	// Nothing to declare produces nothing. An empty entry would mean "remove
	// this RRset", so a child with no opinion must send no entry at all.
	if sets := DsyncApiRRsetsFromSyncStatus("child1.example.", DelegationSyncStatus{}); len(sets) != 0 {
		t.Errorf("an empty sync status produced %d entries; that would remove RRsets", len(sets))
	}
}

func keysOfRRsets(sets []DsyncApiRRset) []string {
	out := make([]string, 0, len(sets))
	for _, s := range sets {
		out = append(out, s.Owner+"/"+s.Type)
	}
	return out
}

// The child credential list is a list rather than a map keyed by parent name,
// for the viper reason. This is the regression guard.
func TestDsyncApiChildCredentialsRoundTripThroughViper(t *testing.T) {
	const y = `
delegationsync:
   child:
      schemes: [ update, notify, api ]
      api:
         allow-insecure: false
         credentials:
            - parent:   example.
              username: child1.example.
              key:      s3cret
            - parent:   other.example.
              username: acme-registrar
              key:      other-secret
`
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(y)); err != nil {
		t.Fatalf("read: %v", err)
	}
	var conf Config
	if err := v.Unmarshal(&conf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	api := conf.DelegationSync.Child.Api
	if len(api.Credentials) != 2 {
		t.Fatalf("got %d credentials, want 2: %+v", len(api.Credentials), api.Credentials)
	}
	if api.AllowInsecure {
		t.Error("allow-insecure decoded as true from an explicit false")
	}

	// The dotted parent name must survive, and the lookup must find it.
	cred, ok := api.CredentialFor("example.")
	if !ok {
		t.Fatal("no credential found for example.")
	}
	if cred.Username != "child1.example." || cred.Key != "s3cret" {
		t.Errorf("credential = %+v, want the configured one", cred)
	}
	// Written with or without the trailing dot must both work.
	if _, ok := api.CredentialFor("example"); !ok {
		t.Error("a parent written without the trailing dot was not matched")
	}
	if _, ok := api.CredentialFor("nosuch.example."); ok {
		t.Error("a credential was returned for a parent that has none")
	}
}

func TestDsyncApiChildTLSCredentialRoundTripThroughViper(t *testing.T) {
	const y = `
delegationsync:
   child:
      api:
         credentials:
            - parent: example.
              tls:
                 cert: /etc/tdns/child.crt
                 key:  /etc/tdns/child.key
`
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(y)); err != nil {
		t.Fatalf("read: %v", err)
	}
	var conf Config
	if err := v.Unmarshal(&conf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cred, ok := conf.DelegationSync.Child.Api.CredentialFor("example.")
	if !ok {
		t.Fatal("tls credential not found")
	}
	if cred.Username != "" || cred.Key != "" {
		t.Errorf("bearer fields populated: %+v", cred)
	}
	if cred.CertFile != "/etc/tdns/child.crt" || cred.KeyFile != "/etc/tdns/child.key" {
		t.Errorf("tls paths = cert %q key %q", cred.CertFile, cred.KeyFile)
	}
	if !cred.Usable() {
		t.Error("tls-only credential must be Usable")
	}
}

func TestDsyncApiClientCredentialUsable(t *testing.T) {
	if (DsyncApiClientCredential{Username: "u", Key: "k"}).Usable() != true {
		t.Error("bearer pair must be usable")
	}
	if (DsyncApiClientCredential{CertFile: "c", KeyFile: "k"}).Usable() != true {
		t.Error("cert pair must be usable")
	}
	if (DsyncApiClientCredential{Username: "u"}).Usable() {
		t.Error("username without key must not be usable")
	}
	if (DsyncApiClientCredential{CertFile: "c"}).Usable() {
		t.Error("cert without key must not be usable")
	}
	if (DsyncApiClientCredential{}).Usable() {
		t.Error("empty credential must not be usable")
	}
}

func TestDsyncApiPostDelegationRequestCertOnlyOmitsBasicAuth(t *testing.T) {
	var sawAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DsyncApiDelegation{Child: "child1.example."})
	}))
	defer srv.Close()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := writeCertPEM(caPath, srv.Certificate().Raw); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	leaf, _ := newTestTLSCert(t, []string{"child1.example"}, nil)
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	if err := writeCertPEM(certPath, leaf.Certificate[0]); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("write key: %v", err)
	}
	keyOut.Close()

	ep := &DsyncApiEndpoint{Url: srv.URL + "/dsync/v1", Dialect: DsyncApiDialectV1}
	cred := DsyncApiClientCredential{CertFile: certPath, KeyFile: keyPath}
	if _, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.",
		[]DsyncApiRRset{{Owner: "child1.example.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns1.child1.example."}}},
		false, caPath); err != nil {
		t.Fatalf("post: %v", err)
	}
	if sawAuth != "" {
		t.Errorf("Authorization = %q, want empty on a cert-only credential", sawAuth)
	}
}

// TestDsyncApiRRsetsIncludesAAAAGlue covers the IPv6 half of
// DsyncApiRRsetsFromSyncStatus. It loops over both A and AAAA and groups glue
// per owner; the A path was tested and the AAAA path was not, so a regression
// in the v6 grouping would have gone unnoticed.
func TestDsyncApiRRsetsIncludesAAAAGlue(t *testing.T) {
	mustRR := func(s string) dns.RR {
		t.Helper()
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("parsing %q: %v", s, err)
		}
		return rr
	}

	status := DelegationSyncStatus{
		NewNS: []dns.RR{
			mustRR("child1.example. 3600 IN NS ns1.child1.example."),
			mustRR("child1.example. 3600 IN NS ns2.child1.example."),
		},
		NewA: []dns.RR{
			mustRR("ns1.child1.example. 3600 IN A 192.0.2.1"),
		},
		NewAAAA: []dns.RR{
			mustRR("ns1.child1.example. 3600 IN AAAA 2001:db8::1"),
			mustRR("ns1.child1.example. 3600 IN AAAA 2001:db8::2"),
			mustRR("ns2.child1.example. 3600 IN AAAA 2001:db8::3"),
		},
	}

	sets := DsyncApiRRsetsFromSyncStatus("child1.example.", status)
	byKey := map[string]DsyncApiRRset{}
	for _, s := range sets {
		byKey[s.Owner+"/"+s.Type] = s
	}

	// Grouped per owner, not lumped into one AAAA entry.
	for key, want := range map[string]int{
		"ns1.child1.example./AAAA": 2,
		"ns2.child1.example./AAAA": 1,
		"ns1.child1.example./A":    1,
	} {
		got, ok := byKey[key]
		if !ok {
			t.Errorf("no entry for %s; got %v", key, keysOfRRsets(sets))
			continue
		}
		if len(got.RRs) != want {
			t.Errorf("%s has %d records, want %d", key, len(got.RRs), want)
		}
	}

	// ns2 has no A record, so there must be no empty A entry for it: an empty
	// entry means "remove this RRset".
	if e, ok := byKey["ns2.child1.example./A"]; ok {
		t.Errorf("an A entry was emitted for a name with no A glue: %+v", e)
	}
}

// TestDsyncApiListenerBlocksUntilShutdown asserts the property the engine
// wiring actually depends on: StartDsyncApiListener must NOT return while its
// listeners are serving, and must return once shutdown is requested.
//
// Both halves are needed. StartEngine marks the engine done when this function
// returns and Shutdowner waits on engineWg before exiting, so a version that
// starts the listeners and returns immediately makes the wait cover nothing:
// os.Exit can run mid-drain, killing a request that has queued a CHILD-UPDATE
// and is waiting for the updater's answer, and the child cannot tell whether
// its delegation update was applied.
//
// Asserting only "it returns within N seconds" does not catch that -- the
// broken version returns in microseconds and passes. The first version of this
// test made exactly that mistake.
func TestDsyncApiListenerBlocksUntilShutdown(t *testing.T) {
	for _, tc := range []struct {
		name string
		// stopIt triggers shutdown by whichever mechanism is under test.
		stopIt func(cancel context.CancelFunc, stop chan struct{})
	}{
		{"stop channel", func(_ context.CancelFunc, stop chan struct{}) { close(stop) }},
		// A plain context cancellation (SIGTERM) does not close APIStopCh, so a
		// wait on the stop channel alone leaks the goroutine and leaves the
		// listeners up.
		{"context cancel", func(cancel context.CancelFunc, _ chan struct{}) { cancel() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, router, certOK := dsyncApiTestListener(t)
			if !certOK {
				t.Skip("no test certificate available")
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := make(chan struct{})
			done := make(chan error, 1)
			go func() { done <- conf.StartDsyncApiListener(ctx, router, stop) }()

			// It must still be running: nothing has asked it to stop.
			select {
			case err := <-done:
				t.Fatalf("StartDsyncApiListener returned (%v) while its listeners were"+
					" still serving; engineWg would not cover the drain and os.Exit"+
					" could run mid-shutdown", err)
			case <-time.After(500 * time.Millisecond):
			}

			tc.stopIt(cancel, stop)

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("listener returned an error: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("StartDsyncApiListener did not return within 10s of shutdown being requested")
			}
		})
	}
}

// dsyncApiTestListener builds a Config whose delegationsync.parent.api points
// at a free loopback port and a freshly written self-signed cert/key pair, plus
// a router to serve. Reuses newTestTLSCert so there is one certificate
// generator in the package rather than two.
func dsyncApiTestListener(t *testing.T) (*Config, *mux.Router, bool) {
	t.Helper()

	cert, _ := newTestTLSCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("creating cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	certOut.Close()

	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	keyOut.Close()

	// A port the kernel just handed out is one nothing else is on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	conf := &Config{}
	conf.DelegationSync.Parent.Api.Listen = []string{addr}
	conf.DelegationSync.Parent.Api.CertFile = certPath
	conf.DelegationSync.Parent.Api.KeyFile = keyPath
	SetDelegationSyncConfig(conf.DelegationSync)

	return conf, mux.NewRouter(), true
}

// TestPickDsyncApiUrlHonoursPriorityAndWeight pins RFC 7553 selection.
//
// The assertions are chosen to be deterministic despite the selection being
// random: priority is absolute, a zero-weight candidate can never win while a
// positive weight is present (the running-sum algorithm gives it no interval),
// and over many draws every positive-weight candidate must appear at least
// once -- the probability of a false failure there is 2^-199.
func TestPickDsyncApiUrlHonoursPriorityAndWeight(t *testing.T) {
	uri := func(prio, weight uint16, target string) dns.RR {
		return &dns.URI{
			Hdr:      dns.RR_Header{Name: "_dsync.example.", Rrtype: dns.TypeURI, Class: dns.ClassINET},
			Priority: prio, Weight: weight, Target: target,
		}
	}

	t.Run("lowest priority always wins", func(t *testing.T) {
		rrs := []dns.RR{
			uri(20, 100, "https://backup.example/api"),
			uri(10, 1, "https://primary.example/api"),
		}
		for i := 0; i < 200; i++ {
			got, err := pickDsyncApiUrl(rrs)
			if err != nil {
				t.Fatalf("pickDsyncApiUrl: %v", err)
			}
			// Priority beats weight: the backup has 100x the weight and must
			// still never be chosen while the primary is present.
			if got != "https://primary.example/api" {
				t.Fatalf("draw %d picked %q; a higher-numbered priority must not be used", i, got)
			}
		}
	})

	t.Run("a zero weight never wins against a positive one", func(t *testing.T) {
		rrs := []dns.RR{
			uri(10, 0, "https://never.example/api"),
			uri(10, 5, "https://always.example/api"),
		}
		for i := 0; i < 200; i++ {
			got, _ := pickDsyncApiUrl(rrs)
			if got != "https://always.example/api" {
				t.Fatalf("draw %d picked the zero-weight candidate %q", i, got)
			}
		}
	})

	t.Run("equal priorities distribute over weights", func(t *testing.T) {
		rrs := []dns.RR{
			uri(10, 1, "https://a.example/api"),
			uri(10, 1, "https://b.example/api"),
		}
		seen := map[string]int{}
		for i := 0; i < 200; i++ {
			got, _ := pickDsyncApiUrl(rrs)
			seen[got]++
		}
		// Deterministic selection -- the previous implementation -- puts 200 in
		// one bucket and 0 in the other. That is the regression this catches.
		if len(seen) != 2 {
			t.Fatalf("200 draws produced %d distinct endpoints (%v);"+
				" weighted selection must not always return the same one", len(seen), seen)
		}
	})

	t.Run("a single candidate is returned as-is", func(t *testing.T) {
		got, err := pickDsyncApiUrl([]dns.RR{uri(10, 0, "https://only.example/api")})
		if err != nil || got != "https://only.example/api" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("no usable target is an error", func(t *testing.T) {
		if _, err := pickDsyncApiUrl([]dns.RR{uri(10, 5, "   ")}); err == nil {
			t.Fatal("an empty target was accepted")
		}
	})
}
