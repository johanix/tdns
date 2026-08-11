/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	}, false)
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

	if _, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.", rrsets, false); err == nil {
		t.Fatal("the plaintext endpoint was used")
	}
	if sawAuth {
		t.Error("a credential reached a plaintext endpoint before the refusal")
	}

	// With allow-insecure the request does go through -- the lab escape hatch
	// is real, which is exactly why it is named after what it costs.
	if _, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.", rrsets, true); err != nil {
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
	}, true)
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

	out, err := DsyncApiPostDelegationRequest(context.Background(), ep, cred, "child1.example.", rrsets, true)
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
	}, true)
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
