/*
 * Regression tests for the fixes to the 2026-07-21 adversarial review of
 * feature/peers-xfr-auth (docs/2026-07-21-peers-xfr-auth-adversarial-review.md).
 *
 * Each test began life as a PROOF test that failed against the pre-fix code;
 * it now asserts the design-correct behavior and PASSES. Keep them: they guard
 * the specific config/wiring gaps the review found from silently regressing.
 */
package tdns

import (
	"strings"
	"testing"
)

// F1: a transfer-list spelling conflict recorded under a TEMPLATE name must
// quarantine every zone that uses that template (not just a zone with a direct
// conflict). ParseZones resolves this via zoneOrTemplateAliasConflict.
func TestReview_TemplateAliasConflictQuarantinesDependentZones(t *testing.T) {
	cm := map[string]interface{}{
		"templates": []interface{}{
			map[string]interface{}{
				"name": "served",
				// Broad unsigned ACL (canonical spelling)...
				"downstreams": []interface{}{
					map[string]interface{}{"prefix": "0.0.0.0/0", "key": "NOKEY"},
				},
				// ...vs restrictive intended ACL (alias spelling): CONFLICT.
				"provide-xfr": []interface{}{
					map[string]interface{}{"prefix": "192.0.2.0/24", "key": "xfr-key"},
				},
			},
		},
	}
	conflicts := NormalizeXfrAliases(cm)
	if _, ok := conflicts["served"]; !ok {
		t.Fatalf("expected conflict recorded under template name 'served', got %v", conflicts)
	}

	// A zone with no direct conflict but a conflicting template must resolve to
	// the template's conflict (the pre-fix code only checked the zone name).
	if c := zoneOrTemplateAliasConflict(conflicts, "example.", "served"); c == "" {
		t.Fatal("zone using a conflicted template must be quarantined, got no conflict")
	}
	// A zone with neither a direct nor a template conflict must stay clean.
	if c := zoneOrTemplateAliasConflict(conflicts, "clean.", "other"); c != "" {
		t.Fatalf("unexpected conflict for unrelated zone: %q", c)
	}
	// No template reference at all: only the zone's own name matters.
	if c := zoneOrTemplateAliasConflict(conflicts, "served", ""); c == "" {
		t.Fatal("a zone literally named like the conflicted template still conflicts on its own name")
	}
}

// F3: a peers: reference entry must not carry inline TLS fields — silently
// discarding transport/tls-auth/pins would turn intended XoT into plaintext
// Do53. expandPeerRefs now rejects the mixed entry.
func TestReview_PeerRefRejectsInlineTLSFields(t *testing.T) {
	conf := &Config{Peers: map[string]PeerDef{
		"primary": {Addr: "192.0.2.1:53", Keys: []string{NOKEY}}, // plain Do53 peer
	}}
	zc := ZoneConf{Primaries: []PeerConf{{
		PeersRef:  []string{"primary"},
		Transport: TransportDoT,
		TLSAuth:   TLSAuthPin,
		Pins:      []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}}}
	err := conf.expandPeerRefs(&zc, nil)
	if err == nil {
		t.Fatalf("expected rejection of TLS fields on a reference entry, expansion succeeded: %+v", zc.Primaries)
	}
	if !strings.Contains(err.Error(), "TLS fields") && !strings.Contains(err.Error(), "not both") {
		t.Fatalf("want rejection naming the TLS fields / reference-vs-inline rule, got %v", err)
	}
}

// F6: PublishTlsaRR must reject an out-of-zone owner on a LABEL boundary
// ("notexample.com." is not a subdomain of "example.com."), before touching
// the certificate. dns.IsSubDomain replaced the bare strings.HasSuffix.
func TestReview_PublishTlsaRRRejectsLabelBoundaryCollision(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.com."}
	err := zd.PublishTlsaRR("notexample.com.", 853, "not-a-cert")
	if err == nil {
		t.Fatal("expected error for out-of-zone owner")
	}
	if !strings.Contains(err.Error(), "not a subdomain") {
		t.Fatalf("want a not-a-subdomain rejection before cert parsing, got %v", err)
	}
}

// F4a: peerUsesDoT is case-insensitive, so an API/dynamic PeerConf with
// transport:"DoT" (never normalized through validatePeerXoT) still builds a
// verifying TLS config instead of silently falling back to plaintext.
func TestReview_PeerUsesDoTRequiresNormalizedCase(t *testing.T) {
	conf := &Config{}
	p := PeerConf{
		Addr: "192.0.2.1:853", Key: NOKEY,
		Transport: "DoT", TLSAuth: TLSAuthPin,
		Pins: []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}
	cfg, err := conf.ClientTLSConfigForPeer(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("transport \"DoT\" (non-normalized case) must still yield a TLS config, got nil — plaintext fallback with pins unused")
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("pinned peer must install a VerifyConnection callback")
	}
}

// F4b: the ZoneConf<->ZoneData round-trip used by the dynamic (API-provisioned)
// load/reload path must preserve DownstreamAuth; dropping it would silently
// widen a tls-pkix zone to unauthenticated AXFR.
func TestReview_DynamicRoundTripPreservesDownstreamAuth(t *testing.T) {
	zd := &ZoneData{
		ZoneName:       "dyn.example.",
		Downstreams:    []AclEntry{{Prefix: "192.0.2.0/24", Key: NOKEY}},
		DownstreamAuth: []string{MechTLSPkix},
	}
	zc := zoneDataToZoneConf(zd, "")
	if len(zc.DownstreamAuth) != 1 || zc.DownstreamAuth[0] != MechTLSPkix {
		t.Fatalf("dynamic round-trip dropped DownstreamAuth: got %v, want [%s]", zc.DownstreamAuth, MechTLSPkix)
	}
}

// F7: config check must flag transfer-list keys that are correct except for
// letter case — the daemon decodes YAML case-sensitively and silently drops
// them, so a mis-cased key must not read as "configured".
func TestReview_FindMiscasedXfrKeys(t *testing.T) {
	cm := map[string]interface{}{
		"zones": []interface{}{
			map[string]interface{}{
				"name":        "bad.",
				"Provide-Xfr": []interface{}{}, // mis-cased alias: daemon ignores it
			},
			map[string]interface{}{
				"name":        "good.",
				"downstreams": []interface{}{}, // canonical, correct case
			},
		},
	}
	got := FindMiscasedXfrKeys(cm)
	if len(got) != 1 {
		t.Fatalf("want exactly one mis-cased key, got %v", got)
	}
	if got[0].Zone != "bad." || got[0].Key != "Provide-Xfr" || got[0].Canonical != "downstreams" {
		t.Fatalf("unexpected mis-cased key report: %+v", got[0])
	}
}
