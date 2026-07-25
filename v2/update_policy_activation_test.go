package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Tests for activateUpdatePolicy, the helper extracted from ParseZones and
// shared with the dynamic-primary add/load paths. The error strings are part
// of the contract (they were ConfigError texts surfaced by zone list) — the
// assertions pin them.

func TestActivateUpdatePolicy_HappyPath(t *testing.T) {
	zconf := &ZoneConf{Name: "p.example."}
	zconf.UpdatePolicy.Zone.Type = "selfsub"
	zconf.UpdatePolicy.Zone.RRtypes = []string{"txt", "A"}
	zconf.UpdatePolicy.Child.Type = ""
	options := map[ZoneOption]bool{OptAllowUpdates: true, OptAllowChildUpdates: true}

	policy, err := activateUpdatePolicy(zconf, options)
	if err != nil {
		t.Fatalf("activateUpdatePolicy: %v", err)
	}
	if !options[OptAllowUpdates] {
		t.Error("OptAllowUpdates must survive a selfsub zone policy")
	}
	if options[OptAllowChildUpdates] {
		t.Error("OptAllowChildUpdates must be forced off by an unset child policy")
	}
	if !policy.Zone.RRtypes[dns.TypeTXT] || !policy.Zone.RRtypes[dns.TypeA] {
		t.Errorf("RRtypes not mapped (case-insensitively): %v", policy.Zone.RRtypes)
	}
	if policy.Zone.TTL != 120 || policy.Child.TTL != 120 {
		t.Errorf("TTL defaults = %d/%d, want 120/120", policy.Zone.TTL, policy.Child.TTL)
	}
}

func TestActivateUpdatePolicy_UnknownTypes(t *testing.T) {
	zconf := &ZoneConf{Name: "p.example."}
	zconf.UpdatePolicy.Child.Type = "bogus"
	if _, err := activateUpdatePolicy(zconf, map[ZoneOption]bool{}); err == nil ||
		!strings.Contains(err.Error(), "unknown child update policy type: bogus") {
		t.Errorf("child policy error drifted: %v", err)
	}

	zconf = &ZoneConf{Name: "p.example."}
	zconf.UpdatePolicy.Zone.Type = "bogus"
	if _, err := activateUpdatePolicy(zconf, map[ZoneOption]bool{}); err == nil ||
		!strings.Contains(err.Error(), "unknown update policy type: bogus") {
		t.Errorf("zone policy error drifted: %v", err)
	}
}

func TestActivateUpdatePolicy_ChildUpdatesRequireBackend(t *testing.T) {
	zconf := &ZoneConf{Name: "p.example."}
	zconf.UpdatePolicy.Child.Type = "selfsub"
	options := map[ZoneOption]bool{OptAllowChildUpdates: true}
	if _, err := activateUpdatePolicy(zconf, options); err == nil ||
		!strings.Contains(err.Error(), "allow-child-updates requires delegationbackend") {
		t.Errorf("backend requirement error drifted: %v", err)
	}

	zconf.DelegationBackend = "direct"
	if _, err := activateUpdatePolicy(zconf, options); err != nil {
		t.Errorf("with a backend the same config must activate: %v", err)
	}

	// Unknown RRtype names are silently dropped (preserved behavior).
	zconf.UpdatePolicy.Child.RRtypes = []string{"NS", "NOTATYPE"}
	policy, err := activateUpdatePolicy(zconf, options)
	if err != nil {
		t.Fatalf("activateUpdatePolicy: %v", err)
	}
	if !policy.Child.RRtypes[dns.TypeNS] || len(policy.Child.RRtypes) != 1 {
		t.Errorf("unknown RRtype handling drifted: %v", policy.Child.RRtypes)
	}
}
