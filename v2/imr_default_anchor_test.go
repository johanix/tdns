/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// The IANA root DS records, as an operator would paste them.
const (
	rootDS20326 = ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
	rootDS38696 = ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
)

// captureImrLog sends the slog default, which the subsystem loggers write
// through, to a buffer for the rest of the test.
func captureImrLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func dsKeyTags(dss []*dns.DS) []uint16 {
	tags := make([]uint16, 0, len(dss))
	for _, ds := range dss {
		tags = append(tags, ds.KeyTag)
	}
	slices.Sort(tags)
	return tags
}

// No anchor configured and the compiled-in root hints: the resolver gets the
// compiled-in IANA root anchor, both KSK DS records, and says so once -- both
// NewImr and Start read the anchors.
func TestNoAnchorCompiledInHintsUsesCompiledInRootAnchor(t *testing.T) {
	logbuf := captureImrLog(t)
	imr := newForwardTestImr(t, nil)
	ic := ImrEngineConf{}

	for range 2 {
		dsByName, keysByName, err := imr.parseTrustAnchorsFromConfig(ic)
		if err != nil {
			t.Fatalf("parseTrustAnchorsFromConfig: %v", err)
		}
		if got, want := dsKeyTags(dsByName["."]), []uint16{20326, 38696}; !slices.Equal(got, want) {
			t.Fatalf("root DS key tags = %v, want %v", got, want)
		}
		if len(dsByName) != 1 || len(keysByName) != 0 {
			t.Errorf("want DS anchors for the root only, got DS %v, DNSKEY %v", dsByName, keysByName)
		}
	}
	logged := logbuf.String()
	if n := strings.Count(logged, "compiled-in IANA root trust anchor"); n != 1 {
		t.Errorf("the compiled-in anchor was announced %d times, want once:\n%s", n, logged)
	}
	if !strings.Contains(logged, "level=INFO") || !strings.Contains(logged, "20326,38696") {
		t.Errorf("want an INFO line naming both key tags, got:\n%s", logged)
	}

	// The preload before priming reads the same anchors: the root's DS RRset
	// is seeded, Secure, with both records.
	imr.loadConfiguredTrustAnchors(ic)
	crr := imr.Cache.Peek(".", dns.TypeDS)
	if crr == nil || crr.RRset == nil || len(crr.RRset.RRs) != 2 {
		t.Fatalf("root DS RRset not seeded from the compiled-in anchor: %+v", crr)
	}
	if crr.State != cache.ValidationStateSecure {
		t.Errorf("seeded root DS RRset is %s, want secure", cache.ValidationStateToString[crr.State])
	}
}

// No anchor configured, and the root may be another one: a root-hints file, a
// forward for "." or a stub for ".". Which anchor it gets is the root's to say,
// by the keys it serves (imr_root_anchor_probe.go), so parsing the config loads
// none, before priming or at Start, and the log says that the choice is made
// once the root has been fetched. It does not say that nothing will validate:
// that is only known when the root's keys do not match.
func TestNoAnchorNonDefaultRootLeavesTheChoiceToTheRoot(t *testing.T) {
	for _, tc := range nonDefaultRoots {
		t.Run(tc.name, func(t *testing.T) {
			logbuf := captureImrLog(t)
			imr := newForwardTestImr(t, nil)
			dsByName, keysByName, err := imr.parseTrustAnchorsFromConfig(tc.ic)
			if err != nil {
				t.Fatalf("parseTrustAnchorsFromConfig: %v", err)
			}
			if len(dsByName) != 0 || len(keysByName) != 0 {
				t.Fatalf("want no anchor, got DS %v, DNSKEY %v", dsByName, keysByName)
			}
			logged := logbuf.String()
			if !strings.Contains(logged, "level=INFO") || !strings.Contains(logged, "may not be the IANA root") ||
				!strings.Contains(logged, tc.reason) {
				t.Errorf("want an INFO saying the choice is the root's, because %q; got:\n%s", tc.reason, logged)
			}
			if strings.Contains(logged, "nothing will validate") {
				t.Errorf("said that nothing will validate before the root was asked:\n%s", logged)
			}
			// The preload before priming reads the same anchors: none, so no
			// root DS RRset is seeded.
			imr.loadConfiguredTrustAnchors(tc.ic)
			if crr := imr.Cache.Peek(".", dns.TypeDS); crr != nil {
				t.Errorf("a root DS RRset was seeded before the root was asked: %+v", crr)
			}
		})
	}

	// A forward or stub below the root leaves the IANA root in place.
	ic := ImrEngineConf{
		Forward: []ImrForwardConf{fwdConf("fwd.example.", "192.0.2.53", 0)},
		Stubs:   []ImrStubConf{stubConf("stub.example.", "ns.stub.example.", "192.0.2.1")},
	}
	if use, why := ic.RootAnchorFallback(); !use {
		t.Errorf("a forward and a stub below the root turned the compiled-in anchor off: %s", why)
	}
	// And a configured anchor is never replaced by it.
	ic = ImrEngineConf{TrustAnchorDS: rootDS20326}
	if use, _ := ic.RootAnchorFallback(); use {
		t.Error("the compiled-in anchor is used although the config names one")
	}
}

// trust-anchor-ds takes several DS records, one per line, as a YAML block
// scalar gives them; a single record reads exactly as before.
func TestTrustAnchorDSRecords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  []uint16
	}{
		{"one DS", rootDS20326, []uint16{20326}},
		{"one DS, trailing newline", rootDS20326 + "\n", []uint16{20326}},
		{"two DS, one per line", rootDS20326 + "\n" + rootDS38696 + "\n", []uint16{20326, 38696}},
		{"two DS, comments and blank lines", "; KSK-2017\n" + rootDS20326 + "\n\n; KSK-2024\n" + rootDS38696, []uint16{20326, 38696}},
		{"with a TTL", ". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", []uint16{20326}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := newForwardTestImr(t, nil)
			dsByName, _, err := imr.parseTrustAnchorsFromConfig(ImrEngineConf{TrustAnchorDS: tc.value})
			if err != nil {
				t.Fatalf("parseTrustAnchorsFromConfig: %v", err)
			}
			if got := dsKeyTags(dsByName["."]); !slices.Equal(got, tc.want) {
				t.Errorf("root DS key tags = %v, want %v", got, tc.want)
			}
		})
	}

	// The single record parses to what dns.NewRR made of it.
	rr, err := dns.NewRR(rootDS20326)
	if err != nil {
		t.Fatal(err)
	}
	dss, err := parseInlineDSAnchors(rootDS20326)
	if err != nil || len(dss) != 1 || dss[0].String() != rr.String() {
		t.Errorf("single DS: got %v (err %v), want %s", dss, err, rr)
	}
}

// Anything in trust-anchor-ds that is not a DS fails the whole setting, as a
// single bad record always did -- and no compiled-in anchor stands in for it.
func TestTrustAnchorDSRejectsBadEntries(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"not a record", "this is not a DS record"},
		{"a DNSKEY", ". IN DNSKEY 257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA="},
		{"a DS, then an A", rootDS20326 + "\nwww.example. IN A 192.0.2.1\n"},
		{"a DS, then a broken DS", rootDS20326 + "\n. IN DS keytag 8 2 683D2D0ACB8C9B71\n"},
		{"comments only", "; nothing here\n"},
		{"$INCLUDE", "$INCLUDE /etc/tdns/root.key\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := newForwardTestImr(t, nil)
			dsByName, keysByName, err := imr.parseTrustAnchorsFromConfig(ImrEngineConf{TrustAnchorDS: tc.value})
			if err == nil {
				t.Fatalf("no error; got DS %v, DNSKEY %v", dsByName, keysByName)
			}
			if !strings.Contains(err.Error(), "trust-anchor-ds") {
				t.Errorf("error does not name the setting: %v", err)
			}
		})
	}
}

// trust-anchor-dnskey goes through the same parser, so it takes several too.
func TestTrustAnchorDNSKEYRecords(t *testing.T) {
	const k1 = ". IN DNSKEY 257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA="
	const k2 = ". IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
	imr := newForwardTestImr(t, nil)
	_, keysByName, err := imr.parseTrustAnchorsFromConfig(ImrEngineConf{TrustAnchorDNSKEY: k1 + "\n" + k2})
	if err != nil {
		t.Fatalf("parseTrustAnchorsFromConfig: %v", err)
	}
	if len(keysByName["."]) != 2 {
		t.Errorf("want 2 root DNSKEY anchors, got %v", keysByName)
	}
	if _, _, err := imr.parseTrustAnchorsFromConfig(ImrEngineConf{TrustAnchorDNSKEY: rootDS20326}); err == nil {
		t.Error("a DS in trust-anchor-dnskey was accepted")
	}
}

// One zone spelled in different case is one anchor zone: every DS and DNSKEY
// for it lands in one group, under the canonical name, whichever setting it
// came from. The caches fold case, so two groups would seed one entry and
// the last written would replace the other.
func TestTrustAnchorsGroupedByCanonicalOwner(t *testing.T) {
	const (
		dsUpper = "Example.Test. IN DS 11111 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
		dsLower = "example.test. IN DS 22222 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
		dsFile  = "EXAMPLE.TEST. IN DS 33333 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
		dkMixed = "eXample.tEst. IN DNSKEY 257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA="
	)
	file := filepath.Join(t.TempDir(), "anchors")
	if err := os.WriteFile(file, []byte(dsFile+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	imr := newForwardTestImr(t, nil)
	dsByName, keysByName, err := imr.parseTrustAnchorsFromConfig(ImrEngineConf{
		TrustAnchorDS:     dsUpper + "\n" + dsLower,
		TrustAnchorDNSKEY: dkMixed,
		TrustAnchorFile:   file,
	})
	if err != nil {
		t.Fatalf("parseTrustAnchorsFromConfig: %v", err)
	}
	if len(dsByName) != 1 {
		t.Errorf("DS anchors in %d groups, want 1: %v", len(dsByName), dsByName)
	}
	if got, want := dsKeyTags(dsByName["example.test."]), []uint16{11111, 22222, 33333}; !slices.Equal(got, want) {
		t.Errorf("example.test. DS key tags = %v, want %v", got, want)
	}
	if len(keysByName) != 1 || len(keysByName["example.test."]) != 1 {
		t.Errorf("DNSKEY anchors = %v, want one, under example.test.", keysByName)
	}
}

// A block scalar reaches the field intact through viper, the daemons' path,
// and both its records load.
func TestViperTrustAnchorDSBlockScalar(t *testing.T) {
	doc := "imrengine:\n   trust-anchor-ds: |\n      " + rootDS20326 + "\n      " + rootDS38696 + "\n"
	f := filepath.Join(t.TempDir(), "imr.yaml")
	if err := os.WriteFile(f, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	v.SetConfigFile(f)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}
	var c Config
	if err := v.Unmarshal(&c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	dss, err := parseInlineDSAnchors(c.Imr.TrustAnchorDS)
	if err != nil {
		t.Fatalf("parseInlineDSAnchors(%q): %v", c.Imr.TrustAnchorDS, err)
	}
	if got, want := dsKeyTags(dss), []uint16{20326, 38696}; !slices.Equal(got, want) {
		t.Errorf("key tags = %v, want %v", got, want)
	}
}

// dog reads the IMR config the way the IMR does: two DS records in
// trust-anchor-ds are two anchors, and a value the IMR refuses is ignored
// whole.
func TestImrConfigAnchorsReadsSeveralDS(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return f
	}

	f := write("two.yaml", "imrengine:\n   trust-anchor-ds: |\n      "+rootDS20326+"\n      "+rootDS38696+"\n")
	ds, keys, src := imrConfigAnchors(f, func(string, ...any) {})
	if got, want := dsKeyTags(ds), []uint16{20326, 38696}; !slices.Equal(got, want) || len(keys) != 0 {
		t.Fatalf("got DS key tags %v and %d DNSKEY, want %v and none", got, len(keys), want)
	}
	if !strings.Contains(src, "trust-anchor-ds") {
		t.Errorf("source %q does not name trust-anchor-ds", src)
	}

	f = write("bad.yaml", "imrengine:\n   trust-anchor-ds: |\n      "+rootDS20326+"\n      www.example. IN A 192.0.2.1\n")
	var logged []string
	ds, keys, src = imrConfigAnchors(f, func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	})
	if len(ds) != 0 || len(keys) != 0 || src != "" {
		t.Errorf("a trust-anchor-ds with a non-DS in it: got %d DS, %d DNSKEY, source %q; want it ignored", len(ds), len(keys), src)
	}
	if !strings.Contains(strings.Join(logged, "\n"), "trust-anchor-ds") {
		t.Errorf("the ignored setting was not reported: %v", logged)
	}
}

// Forwards and stubs are reloadable, the anchors are not: a reload that adds
// or removes a "." forward or stub changes which anchor an anchorless config
// would get, and says that a restart applies it.
func TestRestartRequiredWhenTheDefaultRootAnchorChanges(t *testing.T) {
	const key = "the compiled-in root trust anchor"
	hasKey := func(keys []string) bool {
		return slices.ContainsFunc(keys, func(k string) bool { return strings.HasPrefix(k, key) })
	}
	plain := ImrEngineConf{}
	fwdRoot := ImrEngineConf{Forward: []ImrForwardConf{fwdConf(".", "192.0.2.53", 0)}}
	stubRoot := ImrEngineConf{Stubs: []ImrStubConf{stubConf(".", "a.root.test.", "192.0.2.1")}}
	fwdBelow := ImrEngineConf{Forward: []ImrForwardConf{fwdConf("fwd.example.", "192.0.2.53", 0)}}

	if keys := imrRestartRequiredKeys(plain, fwdRoot); !hasKey(keys) {
		t.Errorf("adding a . forward: restart-required keys %v, want %q", keys, key)
	}
	if keys := imrRestartRequiredKeys(stubRoot, plain); !hasKey(keys) {
		t.Errorf("removing a . stub: restart-required keys %v, want %q", keys, key)
	}
	if keys := imrRestartRequiredKeys(plain, fwdBelow); len(keys) != 0 {
		t.Errorf("a forward below the root: restart-required keys %v, want none", keys)
	}
	// A "." forward replaced by a "." stub leaves the anchor chosen the same way
	// (from the root's keys) but names other servers for ".", and the choice was
	// about the first (TestRestartRequiredWhenTheRootServersChange): a restart,
	// and not for the reason that the compiled-in anchor changed.
	keys := imrRestartRequiredKeys(fwdRoot, stubRoot)
	if len(keys) != 1 || !strings.HasPrefix(keys[0], "the root the compiled-in trust anchor was checked against") {
		t.Errorf("a . forward replaced by a . stub: restart-required keys %v, want only the root-servers key", keys)
	}
	anchored := ImrEngineConf{TrustAnchorDS: rootDS20326}
	anchoredFwd := anchored
	anchoredFwd.Forward = fwdRoot.Forward
	if keys := imrRestartRequiredKeys(anchored, anchoredFwd); len(keys) != 0 {
		t.Errorf("a . forward with an anchor configured: restart-required keys %v, want none", keys)
	}
}
