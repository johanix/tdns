/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * delegation-sync-proxy, API path. Everything here is post-network: discovery
 * and the POST are exercised on the testbed (and by dsync_api_client_test.go
 * against a real listener). What is unit-tested is the logic that decides WHAT
 * gets sent and WHETHER a credential exists to send it with -- which is where
 * the proxy differs from the tdns-auth child path.
 */
package tdns

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const proxyApiZone = "api.example."

// A served zone as the proxy sees it after a transfer: apex NS, in-bailiwick
// glue, and (optionally) a SEP DNSKEY to derive a DS from.
func proxyApiBaseZone() string {
	return `api.example.	3600 IN SOA ns1.api.example. hostmaster.api.example. 1 7200 1800 604800 3600
api.example.	3600 IN NS ns1.api.example.
api.example.	3600 IN NS ns2.api.example.
ns1.api.example.	3600 IN A 192.0.2.1
ns2.api.example.	3600 IN AAAA 2001:db8::2
`
}

func proxyApiSignedZone() string {
	return proxyApiBaseZone() +
		"api.example.	3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=\n"
}

func setChildApiCredentials(t *testing.T, creds ...DsyncApiChildCredentialConf) {
	t.Helper()
	prev := DelegationSyncConfig()
	SetDelegationSyncConfig(DelegationSyncConf{
		Child: DelegationSyncChildConf{
			Api: DsyncApiChildConf{Credentials: creds},
		},
	})
	t.Cleanup(func() { SetDelegationSyncConfig(*prev) })
}

// setChildApiAllowInsecure flips delegationsync.child.api.allow-insecure while
// preserving whatever credentials the test already configured.
func setChildApiAllowInsecure(t *testing.T, v bool) {
	t.Helper()
	prev := DelegationSyncConfig()
	next := *prev
	next.Child.Api.AllowInsecure = v
	SetDelegationSyncConfig(next)
	t.Cleanup(func() { SetDelegationSyncConfig(*prev) })
}

// ---------------------------------------------------------------------------
// Credential selection
// ---------------------------------------------------------------------------

// The whole reason the child field exists: one agent, two proxied zones, one
// parent. Parent alone cannot say which credential is which.
func TestCredentialForChildPrefersTheChildSpecificEntry(t *testing.T) {
	conf := DsyncApiChildConf{Credentials: []DsyncApiChildCredentialConf{
		{Parent: "example.", Child: "a.example.", Username: "a-user", Key: "a-key"},
		{Parent: "example.", Child: "b.example.", Username: "b-user", Key: "b-key"},
	}}

	for _, tc := range []struct{ child, wantUser string }{
		{"a.example.", "a-user"},
		{"b.example.", "b-user"},
	} {
		cred, ok := conf.CredentialForChild("example.", tc.child)
		if !ok {
			t.Fatalf("no credential for child %s", tc.child)
		}
		if cred.Username != tc.wantUser {
			t.Errorf("child %s: username = %q, want %q", tc.child, cred.Username, tc.wantUser)
		}
	}

	// A child nobody named, and no generic entry to fall back to.
	if _, ok := conf.CredentialForChild("example.", "c.example."); ok {
		t.Error("an unnamed child matched a credential belonging to a different child")
	}
}

// Every config written before the field existed looks like this. It must keep
// working, and it must keep working for ANY child under that parent.
func TestCredentialForChildFallsBackToTheGenericEntry(t *testing.T) {
	conf := DsyncApiChildConf{Credentials: []DsyncApiChildCredentialConf{
		{Parent: "example.", Username: "generic", Key: "k"},
	}}
	for _, child := range []string{"a.example.", "b.example.", ""} {
		cred, ok := conf.CredentialForChild("example.", child)
		if !ok || cred.Username != "generic" {
			t.Errorf("child %q: got (%q, %v), want the generic entry", child, cred.Username, ok)
		}
	}
	if _, ok := conf.CredentialForChild("other.example.", "a.example."); ok {
		t.Error("a credential for one parent matched a different parent")
	}
}

// Most specific wins even when the generic entry comes first in the list.
func TestCredentialForChildSpecificBeatsGenericRegardlessOfOrder(t *testing.T) {
	conf := DsyncApiChildConf{Credentials: []DsyncApiChildCredentialConf{
		{Parent: "example.", Username: "generic", Key: "k"},
		{Parent: "example.", Child: "a.example.", Username: "a-user", Key: "a-key"},
	}}
	cred, ok := conf.CredentialForChild("example.", "a.example.")
	if !ok || cred.Username != "a-user" {
		t.Fatalf("got (%q, %v), want the child-specific entry", cred.Username, ok)
	}
	// ...and a child with no entry of its own still gets the generic one.
	cred, ok = conf.CredentialForChild("example.", "z.example.")
	if !ok || cred.Username != "generic" {
		t.Fatalf("got (%q, %v), want the generic entry", cred.Username, ok)
	}
}

// A config may be written with or without trailing dots, in any case.
func TestCredentialForChildNormalisesNames(t *testing.T) {
	conf := DsyncApiChildConf{Credentials: []DsyncApiChildCredentialConf{
		{Parent: "EXAMPLE", Child: "A.Example", Username: "a-user", Key: "a-key"},
	}}
	cred, ok := conf.CredentialForChild("example.", "a.example.")
	if !ok || cred.Username != "a-user" {
		t.Fatalf("got (%q, %v), want a match despite case and trailing dots", cred.Username, ok)
	}
}

// CredentialFor is CredentialForChild with no child: it must still find a
// generic entry, and must not accidentally match a child-specific one.
func TestCredentialForWithoutChildOnlyMatchesGeneric(t *testing.T) {
	specific := DsyncApiChildConf{Credentials: []DsyncApiChildCredentialConf{
		{Parent: "example.", Child: "a.example.", Username: "a-user", Key: "a-key"},
	}}
	if _, ok := specific.CredentialFor("example."); ok {
		t.Error("a child-specific credential matched a lookup that named no child")
	}
	generic := DsyncApiChildConf{Credentials: []DsyncApiChildCredentialConf{
		{Parent: "example.", Username: "generic", Key: "k"},
	}}
	if cred, ok := generic.CredentialFor("example."); !ok || cred.Username != "generic" {
		t.Errorf("got (%q, %v), want the generic entry", cred.Username, ok)
	}
}

// ---------------------------------------------------------------------------
// The declarative payload
// ---------------------------------------------------------------------------

func rrsetFor(rrsets []DsyncApiRRset, owner, rrtype string) (DsyncApiRRset, bool) {
	for _, s := range rrsets {
		if strings.EqualFold(s.Owner, owner) && s.Type == rrtype {
			return s, true
		}
	}
	return DsyncApiRRset{}, false
}

// The payload comes from the SERVED zone, not from the analysis deltas. This
// is the regression guard for the bug the API case was added to fix: feeding
// DsyncApiRRsetsFromSyncStatus a ProxyDelegationAnalysis produces an empty
// request, because DelegationDataChangedNG never fills the New* fields.
func TestProxyApiRRsetsAreBuiltFromTheServedZone(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiSignedZone())

	rrsets := zd.proxyApiRRsets()
	if len(rrsets) == 0 {
		t.Fatal("no rrsets built from a zone that plainly has a delegation")
	}

	ns, ok := rrsetFor(rrsets, proxyApiZone, "NS")
	if !ok {
		t.Fatal("no NS rrset in the request")
	}
	if len(ns.RRs) != 2 {
		t.Errorf("NS rrset has %d RRs, want 2: %v", len(ns.RRs), ns.RRs)
	}

	// Glue is grouped per owner, because each nameserver name is its own RRset.
	if a, ok := rrsetFor(rrsets, "ns1.api.example.", "A"); !ok || len(a.RRs) != 1 {
		t.Errorf("A glue for ns1 = %v (present=%v), want exactly 1 RR", a.RRs, ok)
	}
	if aaaa, ok := rrsetFor(rrsets, "ns2.api.example.", "AAAA"); !ok || len(aaaa.RRs) != 1 {
		t.Errorf("AAAA glue for ns2 = %v (present=%v), want exactly 1 RR", aaaa.RRs, ok)
	}

	// A signed zone declares NO DS. The proxy cannot know what the parent
	// should hold: a multi-DS rollover places the new DS before its DNSKEY is
	// published, so anything derived from the served zone is missing exactly
	// the record the rollover just placed. Omitting DS leaves the parent with
	// what it has, which is right until the child's own CDS is forwarded (B1).
	if _, ok := rrsetFor(rrsets, proxyApiZone, "DS"); ok {
		t.Error("a DS rrset was declared for a signed child;" +
			" the proxy has no way to know what the parent should hold")
	}
}

// A child with no SEP DNSKEYs declares an EMPTY DS, so the parent removes what
// it holds. This is the un-signing case and the never-signed case at once: the
// request states what the child's DS is, and for an unsigned child that is
// nothing.
//
// It used to require a witness -- proof that the DNSKEY RRset changed in the
// transfer that left the zone unsigned -- so that a never-signed zone would not
// wipe a DS placed out of band. That protected the wrong state. A DS in the
// parent for an unsigned child makes every validator declare the child bogus,
// so removing it is the repair; and the witness never appears at all on the
// steady-state path for a zone that was never signed, so the DS stayed.
func TestProxyApiRRsetsDeclareEmptyDSWhenTheChildIsUnsigned(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())

	rrsets := zd.proxyApiRRsets()
	ds, ok := rrsetFor(rrsets, proxyApiZone, "DS")
	if !ok {
		t.Fatal("no DS rrset for an unsigned child; the parent would keep a DS that makes the child bogus")
	}
	if len(ds.RRs) != 0 {
		t.Errorf("DS rrset has %d RRs, want 0 (empty means remove): %v", len(ds.RRs), ds.RRs)
	}

	// The rest of the delegation still goes out.
	if _, ok := rrsetFor(rrsets, proxyApiZone, "NS"); !ok {
		t.Error("no NS rrset")
	}
}

// ---------------------------------------------------------------------------
// Failure classification: what may fall back to NOTIFY, and what may not
// ---------------------------------------------------------------------------

// A missing credential is a configuration gap. It is reported with a sentinel
// so the dispatcher can fall back to NOTIFY -- and, just as importantly, so a
// security refusal cannot be mistaken for one.
func TestProxyApiParentReportsMissingCredentialAsSuch(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	zd.Parent = "example."
	target := &DsyncTarget{Name: "dsync-api.example."}

	// No credentials configured at all.
	setChildApiCredentials(t)
	_, err := zd.ProxyApiParent(context.Background(), &Imr{}, target, &ProxyDelegationAnalysis{NsOrGlueChanged: true})
	if err == nil {
		t.Fatal("no error with no credential configured")
	}
	if !errors.Is(err, ErrProxyApiNoCredential) {
		t.Errorf("error %v does not wrap ErrProxyApiNoCredential, so the dispatcher cannot fall back", err)
	}

	// A credential for a DIFFERENT parent must not be borrowed.
	setChildApiCredentials(t, DsyncApiChildCredentialConf{
		Parent: "other.example.", Username: "u", Key: "k"})
	_, err = zd.ProxyApiParent(context.Background(), &Imr{}, target, &ProxyDelegationAnalysis{NsOrGlueChanged: true})
	if !errors.Is(err, ErrProxyApiNoCredential) {
		t.Errorf("a credential for another parent was accepted or misreported: %v", err)
	}
}

// A present-but-unusable credential is the same class of problem as an absent
// one: the operator has to fix the config, and no request should be attempted.
func TestProxyApiParentTreatsIncompleteCredentialAsMissing(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	zd.Parent = "example."
	target := &DsyncTarget{Name: "dsync-api.example."}

	for name, cred := range map[string]DsyncApiChildCredentialConf{
		"no username": {Parent: "example.", Key: "k"},
		"no key":      {Parent: "example.", Username: "u"},
	} {
		setChildApiCredentials(t, cred)
		_, err := zd.ProxyApiParent(context.Background(), &Imr{}, target,
			&ProxyDelegationAnalysis{NsOrGlueChanged: true})
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if !errors.Is(err, ErrProxyApiNoCredential) {
			t.Errorf("%s: error %v does not wrap ErrProxyApiNoCredential", name, err)
		}
	}
}

// Guard rails that do not depend on config: without a target or an IMR there
// is nothing to discover, and neither may be reported as a credential problem
// (which would send the dispatcher down the fallback path for a bug).
func TestProxyApiParentRefusesWithoutTargetOrImr(t *testing.T) {
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	zd.Parent = "example."
	setChildApiCredentials(t, DsyncApiChildCredentialConf{
		Parent: "example.", Username: "u", Key: "k"})

	analysis := &ProxyDelegationAnalysis{NsOrGlueChanged: true}

	for name, call := range map[string]func() (string, error){
		"no target": func() (string, error) { return zd.ProxyApiParent(context.Background(), &Imr{}, nil, analysis) },
		"empty target": func() (string, error) {
			return zd.ProxyApiParent(context.Background(), &Imr{}, &DsyncTarget{}, analysis)
		},
		"no imr": func() (string, error) {
			return zd.ProxyApiParent(context.Background(), nil, &DsyncTarget{Name: "x.example."}, analysis)
		},
	} {
		_, err := call()
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if errors.Is(err, ErrProxyApiNoCredential) {
			t.Errorf("%s: reported as a credential problem, which would trigger a NOTIFY fallback: %v", name, err)
		}
	}
}

// The DSYNC API dialect the client speaks must be the one the parent side
// publishes; a mismatch would fail closed at discovery with a confusing error.
func TestDsyncApiSupportedDialectMatchesTheParentSide(t *testing.T) {
	if len(dsyncApiSupportedDialects) == 0 {
		t.Fatal("the client speaks no dialects at all")
	}
	found := false
	for _, d := range dsyncApiSupportedDialects {
		if d == DsyncApiDialectV1 {
			found = true
		}
	}
	if !found {
		t.Errorf("supported dialects %v do not include %q", dsyncApiSupportedDialects, DsyncApiDialectV1)
	}
}


// The one DS statement a proxy may make, and the predicate that decides it.
//
// A child with no DNSKEY RRset at all is unambiguously broken if the parent
// holds a DS, and it cannot say so itself -- RFC 8078 CDS-delete needs a
// validation it has no key to provide. But the test is the ABSENCE OF THE
// RRSET, not an empty derived DS set: SEP is advisory, so a zone signed with a
// flags-256 CSK derives nothing while being perfectly signed, and conflating
// the two would tell the parent to delete a working child's DS.
func TestProxyApiDSStatementDependsOnTheDnskeyRRsetNotTheSEPBit(t *testing.T) {
	cskZone := proxyApiBaseZone() +
		"api.example.	3600 IN DNSKEY 256 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=\n"

	tests := []struct {
		name      string
		zone      string
		wantEmpty bool
	}{
		{"no DNSKEY RRset at all: declare an empty DS", proxyApiBaseZone(), true},
		{"SEP-flagged KSK: say nothing about DS", proxyApiSignedZone(), false},
		{"flags-256 CSK is signed too: say nothing about DS", cskZone, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zd := testZone(t, proxyApiZone, tc.zone)
			rrsets := zd.proxyApiRRsets()

			ds, ok := rrsetFor(rrsets, proxyApiZone, "DS")
			if tc.wantEmpty {
				if !ok {
					t.Fatal("no DS rrset for a child with no DNSKEY RRset;" +
						" the parent would keep a DS that makes it bogus")
				}
				if len(ds.RRs) != 0 {
					t.Errorf("DS rrset has %d RRs, want 0 (empty means remove)", len(ds.RRs))
				}
				return
			}
			if ok {
				t.Errorf("a DS rrset was declared for a signed child: %v", ds.RRs)
			}
		})
	}

	// The rest of the delegation goes out either way.
	zd := testZone(t, proxyApiZone, proxyApiBaseZone())
	if _, ok := rrsetFor(zd.proxyApiRRsets(), proxyApiZone, "NS"); !ok {
		t.Error("no NS rrset")
	}
}
