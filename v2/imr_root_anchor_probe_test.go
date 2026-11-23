/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// testRoot is a root of its own: a KSK and a ZSK, the DNSKEY RRset signed by
// the KSK, and the DS that anchors the KSK. It stands in for the IANA root, so
// that the match can be tested without the real root's keys.
type testRoot struct {
	ksk   *dns.DNSKEY
	zsk   *dns.DNSKEY
	kskCS crypto.Signer
	ds    *dns.DS
	rrset *core.RRset
}

func newTestRoot(t *testing.T, now time.Time) *testRoot {
	t.Helper()
	gen := func(flags uint16) (*dns.DNSKEY, crypto.Signer) {
		k := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     flags,
			Protocol:  3,
			Algorithm: dns.ED25519,
		}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		cs, ok := priv.(crypto.Signer)
		if !ok {
			t.Fatalf("generated key %T is not a crypto.Signer", priv)
		}
		return k, cs
	}
	tr := &testRoot{}
	tr.ksk, tr.kskCS = gen(257)
	tr.zsk, _ = gen(256)
	tr.ds = tr.ksk.ToDS(dns.SHA256)
	if tr.ds == nil {
		t.Fatal("ToDS returned nil")
	}
	tr.rrset = &core.RRset{
		Name: ".", Class: dns.ClassINET, RRtype: dns.TypeDNSKEY,
		RRs:    []dns.RR{tr.ksk, tr.zsk},
		RRSIGs: []dns.RR{tr.sign(t, tr.ksk, tr.kskCS, now.Add(-time.Hour), now.Add(time.Hour))},
	}
	return tr
}

// sign makes an RRSIG over the root's DNSKEY RRset in the key's name.
func (tr *testRoot) sign(t *testing.T, key *dns.DNSKEY, cs crypto.Signer, from, to time.Time) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  key.Algorithm,
		Inception:  uint32(from.Unix()),
		Expiration: uint32(to.Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: ".",
	}
	if err := sig.Sign(cs, []dns.RR{tr.ksk, tr.zsk}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sig
}

// The match is what validation would make with the anchor loaded: a root key
// hashes to the DS and signs the DNSKEY RRset, within its validity period.
func TestRootKeysMatchAnchor(t *testing.T) {
	now := time.Now()
	root := newTestRoot(t, now)
	other := newTestRoot(t, now) // another root, with other keys

	tampered := *root.ds
	tampered.Digest = strings.Repeat("0", len(tampered.Digest))

	expired := &core.RRset{Name: ".", RRtype: dns.TypeDNSKEY, RRs: root.rrset.RRs,
		RRSIGs: []dns.RR{root.sign(t, root.ksk, root.kskCS, now.Add(-3*time.Hour), now.Add(-2*time.Hour))}}

	// Signed by the ZSK only: the KSK that the DS anchors signed nothing.
	zskOnly := &core.RRset{Name: ".", RRtype: dns.TypeDNSKEY, RRs: root.rrset.RRs,
		RRSIGs: []dns.RR{root.sign(t, root.zsk, root.kskCS, now.Add(-time.Hour), now.Add(time.Hour))}}

	// The RRSIG was made over a smaller RRset than the one served.
	extra := *other.zsk
	grown := &core.RRset{Name: ".", RRtype: dns.TypeDNSKEY,
		RRs: append(append([]dns.RR{}, root.rrset.RRs...), &extra), RRSIGs: root.rrset.RRSIGs}

	notRoot := &core.RRset{Name: "example.", RRtype: dns.TypeDNSKEY, RRSIGs: root.rrset.RRSIGs}
	for _, rr := range root.rrset.RRs {
		k := *rr.(*dns.DNSKEY)
		k.Hdr.Name = "example."
		notRoot.RRs = append(notRoot.RRs, &k)
	}

	for _, tc := range []struct {
		name  string
		rrset *core.RRset
		dss   []*dns.DS
		want  bool
		why   string // part of the reason when not
	}{
		{"the root the DS anchors", root.rrset, []*dns.DS{root.ds}, true, ""},
		{"one of several DS", root.rrset, []*dns.DS{other.ds, root.ds}, true, ""},
		{"another root's keys", other.rrset, []*dns.DS{root.ds}, false, "hashes to a compiled-in root DS"},
		{"a DS with another digest", root.rrset, []*dns.DS{&tampered}, false, "hashes to a compiled-in root DS"},
		{"signature expired", expired, []*dns.DS{root.ds}, false, "is valid from"},
		{"no signature by the anchored key", zskOnly, []*dns.DS{root.ds}, false, "does not verify"},
		{"RRset changed after it was signed", grown, []*dns.DS{root.ds}, false, "does not verify"},
		{"keys of another zone", notRoot, []*dns.DS{root.ds}, false, "hashes to a compiled-in root DS"},
		{"no RRset", nil, []*dns.DS{root.ds}, false, "no DNSKEY RRset"},
		{"an empty RRset", &core.RRset{Name: "."}, []*dns.DS{root.ds}, false, "no DNSKEY RRset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag, ok, why := rootKeysMatchAnchor(tc.rrset, tc.dss, now)
			if ok != tc.want {
				t.Fatalf("match = %v (%s), want %v", ok, why, tc.want)
			}
			if ok {
				if tag != root.ksk.KeyTag() {
					t.Errorf("key tag = %d, want the KSK's %d", tag, root.ksk.KeyTag())
				}
				return
			}
			if !strings.Contains(why, tc.why) {
				t.Errorf("reason = %q, want it to say %q", why, tc.why)
			}
		})
	}
}

// newAnchorTestImr is a resolver with what initializeImrTrustAnchors needs and
// nothing that reaches the network: a cache of its own, with its own DNSKEY
// cache, wired in as InitImrEngine does.
func newAnchorTestImr(t *testing.T) *Imr {
	t.Helper()
	imr := newForwardTestImr(t, nil)
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache
	return imr
}

// useTestRootAnchor makes the compiled-in anchor the test root's, for the rest
// of the test.
func useTestRootAnchor(t *testing.T, root *testRoot) {
	t.Helper()
	prev := rootAnchorSource
	rootAnchorSource = func() ([]*dns.DS, []*dns.DNSKEY, error) { return []*dns.DS{root.ds}, nil, nil }
	t.Cleanup(func() { rootAnchorSource = prev })
}

// fetchesRoot makes the resolver's fetch of an anchor zone's keys serve rrset
// for the root, and counts the fetches.
func fetchesRoot(imr *Imr, rrset *core.RRset) *atomic.Int32 {
	var n atomic.Int32
	imr.anchorKeysFetch = func(ctx context.Context, name string) (*core.RRset, map[string]*cache.AuthServer, string, error) {
		n.Add(1)
		return rrset, nil, "", nil
	}
	return &n
}

var nonDefaultRoots = []struct {
	name   string
	ic     ImrEngineConf
	reason string
}{
	{"root-hints file", ImrEngineConf{RootHints: "/etc/tdns/root.hints"}, "root-hints is set"},
	{"forwarded root", ImrEngineConf{Forward: []ImrForwardConf{fwdConf(".", "192.0.2.53", 0)}}, "root is forwarded"},
	{"stubbed root", ImrEngineConf{Stubs: []ImrStubConf{stubConf(".", "a.root.test.", "192.0.2.1")}}, "root is a stub zone"},
}

// A root reached by a hints file, a forward or a stub that serves the keys the
// compiled-in anchor anchors gets that anchor: it is the IANA root, however it
// is reached.
func TestNonDefaultRootServingTheAnchoredKeysGetsTheAnchor(t *testing.T) {
	for _, tc := range nonDefaultRoots {
		t.Run(tc.name, func(t *testing.T) {
			logbuf := captureImrLog(t)
			root := newTestRoot(t, time.Now())
			useTestRootAnchor(t, root)
			imr := newAnchorTestImr(t)
			fetches := fetchesRoot(imr, root.rrset)

			if probe, why := tc.ic.RootAnchorProbe(); !probe || !strings.Contains(why, tc.reason) {
				t.Fatalf("RootAnchorProbe = %v, %q; want a probe because %q", probe, why, tc.reason)
			}
			if err := imr.initializeImrTrustAnchors(t.Context(), tc.ic); err != nil {
				t.Fatalf("initializeImrTrustAnchors: %v", err)
			}
			if fetches.Load() == 0 {
				t.Error("the root's keys were never fetched")
			}
			crr := imr.Cache.Peek(".", dns.TypeDS)
			if crr == nil || crr.RRset == nil || len(crr.RRset.RRs) != 1 {
				t.Fatalf("the root DS RRset was not seeded from the compiled-in anchor: %+v", crr)
			}
			if crr.State != cache.ValidationStateSecure {
				t.Errorf("seeded root DS RRset is %s, want secure", cache.ValidationStateToString[crr.State])
			}
			logged := logbuf.String()
			if !strings.Contains(logged, "the root serves the IANA root keys") || !strings.Contains(logged, tc.reason) {
				t.Errorf("want an INFO saying the root serves the IANA root keys, reached through %q; got:\n%s", tc.reason, logged)
			}
			if strings.Contains(logged, "nothing will validate") {
				t.Errorf("warned that nothing will validate:\n%s", logged)
			}
		})
	}
}

// A root that serves other keys is another root: no anchor, as before, and a
// warning that says why.
func TestNonDefaultRootServingOtherKeysGetsNoAnchor(t *testing.T) {
	for _, tc := range nonDefaultRoots {
		t.Run(tc.name, func(t *testing.T) {
			logbuf := captureImrLog(t)
			iana := newTestRoot(t, time.Now())
			lab := newTestRoot(t, time.Now())
			useTestRootAnchor(t, iana)
			imr := newAnchorTestImr(t)
			fetchesRoot(imr, lab.rrset)

			if err := imr.initializeImrTrustAnchors(t.Context(), tc.ic); err != nil {
				t.Fatalf("initializeImrTrustAnchors: %v", err)
			}
			if crr := imr.Cache.Peek(".", dns.TypeDS); crr != nil {
				t.Errorf("a root DS RRset was seeded for a root that does not match: %+v", crr)
			}
			logged := logbuf.String()
			for _, want := range []string{"level=WARN", "does not serve the IANA root keys", "nothing will validate", tc.reason} {
				if !strings.Contains(logged, want) {
					t.Errorf("want %q in the log, got:\n%s", want, logged)
				}
			}
		})
	}
}

// A root that does not answer is not a root that does not match: the keys are
// fetched again until they come, and then the anchor is used.
func TestRootProbeRetriesAnUnreachableRoot(t *testing.T) {
	logbuf := captureImrLog(t)
	root := newTestRoot(t, time.Now())
	useTestRootAnchor(t, root)
	prev := rootProbeRetry
	rootProbeRetry = []time.Duration{time.Millisecond}
	t.Cleanup(func() { rootProbeRetry = prev })

	imr := newAnchorTestImr(t)
	var n atomic.Int32
	imr.anchorKeysFetch = func(ctx context.Context, name string) (*core.RRset, map[string]*cache.AuthServer, string, error) {
		// Two attempts fail; the probe's third and processTrustAnchorZone's
		// fetch after it succeed.
		if n.Add(1) <= 2 {
			return nil, nil, "", errors.New("no route to the root")
		}
		return root.rrset, nil, "", nil
	}
	ic := ImrEngineConf{Stubs: []ImrStubConf{stubConf(".", "a.root.test.", "192.0.2.1")}}
	if err := imr.initializeImrTrustAnchors(t.Context(), ic); err != nil {
		t.Fatalf("initializeImrTrustAnchors: %v", err)
	}
	if crr := imr.Cache.Peek(".", dns.TypeDS); crr == nil || crr.RRset == nil {
		t.Fatal("no root DS RRset after the root became reachable")
	}
	logged := logbuf.String()
	if got := strings.Count(logged, "cannot be fetched to check it"); got != 2 {
		t.Errorf("warned %d times about the unreachable root, want 2:\n%s", got, logged)
	}
	if strings.Contains(logged, "does not serve the IANA root keys") {
		t.Errorf("an unreachable root was called a different root:\n%s", logged)
	}
}

// A root that answers and has no DNSKEY RRset (a private root that is not
// signed) is another root, not an unreachable one: no anchor, one warning, and
// no second attempt.
func TestRootServingNoKeysIsAnotherRoot(t *testing.T) {
	logbuf := captureImrLog(t)
	root := newTestRoot(t, time.Now())
	useTestRootAnchor(t, root)
	prev := rootProbeRetry
	rootProbeRetry = []time.Duration{time.Millisecond}
	t.Cleanup(func() { rootProbeRetry = prev })

	imr := newAnchorTestImr(t)
	var n atomic.Int32
	imr.anchorKeysFetch = func(context.Context, string) (*core.RRset, map[string]*cache.AuthServer, string, error) {
		n.Add(1)
		return nil, nil, "", noAnchorKeysError{zone: "."}
	}
	ic := ImrEngineConf{Stubs: []ImrStubConf{stubConf(".", "a.root.test.", "192.0.2.1")}}
	done := make(chan error, 1)
	go func() { done <- imr.initializeImrTrustAnchors(t.Context(), ic) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("initializeImrTrustAnchors: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an unsigned root is being retried as if it were unreachable")
	}
	if got := n.Load(); got != 1 {
		t.Errorf("the root's keys were fetched %d times, want 1", got)
	}
	if crr := imr.Cache.Peek(".", dns.TypeDS); crr != nil {
		t.Errorf("a root DS RRset was seeded for an unsigned root: %+v", crr)
	}
	logged := logbuf.String()
	for _, want := range []string{"does not serve the IANA root keys", "served no DNSKEY RRset", "nothing will validate"} {
		if !strings.Contains(logged, want) {
			t.Errorf("want %q in the log, got:\n%s", want, logged)
		}
	}
	if strings.Contains(logged, "cannot be fetched to check it") {
		t.Errorf("an unsigned root was reported as unreachable:\n%s", logged)
	}
}

// Waiting for a root that never answers ends with the resolver, and leaves no
// anchor.
func TestRootProbeEndsWithTheContext(t *testing.T) {
	captureImrLog(t)
	root := newTestRoot(t, time.Now())
	useTestRootAnchor(t, root)
	prev := rootProbeRetry
	rootProbeRetry = []time.Duration{time.Hour}
	t.Cleanup(func() { rootProbeRetry = prev })

	imr := newAnchorTestImr(t)
	ctx, cancel := context.WithCancel(t.Context())
	imr.anchorKeysFetch = func(context.Context, string) (*core.RRset, map[string]*cache.AuthServer, string, error) {
		cancel() // the resolver is stopped while the first attempt fails
		return nil, nil, "", errors.New("no route to the root")
	}
	ic := ImrEngineConf{Stubs: []ImrStubConf{stubConf(".", "a.root.test.", "192.0.2.1")}}
	done := make(chan error, 1)
	go func() { done <- imr.initializeImrTrustAnchors(ctx, ic) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("initializeImrTrustAnchors: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("initializeImrTrustAnchors is still waiting for the root after its context ended")
	}
	if crr := imr.Cache.Peek(".", dns.TypeDS); crr != nil {
		t.Errorf("a root DS RRset was seeded: %+v", crr)
	}
}

// The root is only asked where the config leaves the choice to it: a
// configured anchor is used as it stands, and the default root is the IANA root
// without asking.
func TestRootIsNotProbedWhenTheConfigDecides(t *testing.T) {
	captureImrLog(t)
	root := newTestRoot(t, time.Now())
	useTestRootAnchor(t, root)

	configured := ImrEngineConf{
		TrustAnchorDS: rootDS20326,
		Stubs:         []ImrStubConf{stubConf(".", "a.root.test.", "192.0.2.1")},
	}
	if probe, _ := configured.RootAnchorProbe(); probe {
		t.Error("a configured anchor is probed for")
	}
	plain := ImrEngineConf{}
	if probe, why := plain.RootAnchorProbe(); probe {
		t.Errorf("the default root is probed for: %s", why)
	}
	below := ImrEngineConf{Stubs: []ImrStubConf{stubConf("stub.example.", "ns.stub.example.", "192.0.2.1")}}
	if probe, why := below.RootAnchorProbe(); probe {
		t.Errorf("a stub below the root is probed for: %s", why)
	}

	// With the default root, initializeImrTrustAnchors asks nobody for the
	// root's keys before it loads the anchor; processTrustAnchorZone does,
	// as it always has, and that is one fetch.
	imr := newAnchorTestImr(t)
	fetches := fetchesRoot(imr, root.rrset)
	if err := imr.initializeImrTrustAnchors(t.Context(), ImrEngineConf{}); err != nil {
		t.Fatalf("initializeImrTrustAnchors: %v", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("the default root's keys were fetched %d times, want 1 (processTrustAnchorZone's)", got)
	}
}
