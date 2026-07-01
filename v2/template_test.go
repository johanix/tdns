package tdns

import "testing"

// TestExpandTemplatePropagatesAllFields pins the D3 contract: every config field
// a template sets is propagated to a zone that didn't set it. ExpandTemplate is
// reflection-based so new fields are covered automatically; this test fails if a
// settable, template-set field is dropped.
func TestExpandTemplatePropagatesAllFields(t *testing.T) {
	tmpl := &ZoneConf{
		Name:              "TEMPLATE", // must NOT be copied
		Type:              "secondary",
		Store:             "map",
		Primaries:         []PeerConf{{Addr: "192.0.2.1:53", Key: "NOKEY"}},
		Notify:            []PeerConf{{Addr: "192.0.2.2:53", Key: "NOKEY"}},
		AllowNotify:       []AclEntry{{Prefix: "192.0.2.0/24", Key: "NOKEY"}},
		Downstreams:       []AclEntry{{Prefix: "0.0.0.0/0", Key: "NOKEY"}},
		Zonefile:          "/zones/%s.zone",
		OptionsStrs:       []string{"online-signing"},
		DelegationBackend: "deleg-be",
		MultiSigner:       "msigner",
		DnssecPolicy:      "default",
	}

	z, err := ExpandTemplate(ZoneConf{Name: "child.example"}, tmpl, AppTypeAuth)
	if err != nil {
		t.Fatalf("ExpandTemplate: %v", err)
	}

	if z.Type != "secondary" {
		t.Errorf("Type = %q, want secondary", z.Type)
	}
	if z.Store != "map" {
		t.Errorf("Store = %q, want map", z.Store)
	}
	if len(z.Primaries) != 1 || z.Primaries[0].Addr != "192.0.2.1:53" {
		t.Errorf("Primaries not propagated: %+v", z.Primaries)
	}
	if len(z.Notify) != 1 || z.Notify[0].Addr != "192.0.2.2:53" {
		t.Errorf("Notify not propagated: %+v", z.Notify)
	}
	if len(z.AllowNotify) != 1 || z.AllowNotify[0].Prefix != "192.0.2.0/24" {
		t.Errorf("AllowNotify not propagated: %+v", z.AllowNotify)
	}
	if len(z.Downstreams) != 1 || z.Downstreams[0].Prefix != "0.0.0.0/0" {
		t.Errorf("Downstreams not propagated: %+v", z.Downstreams)
	}
	if z.DelegationBackend != "deleg-be" {
		t.Errorf("DelegationBackend = %q", z.DelegationBackend)
	}
	if z.MultiSigner != "msigner" {
		t.Errorf("MultiSigner = %q", z.MultiSigner)
	}
	// Bespoke: Zonefile is %-expanded with the zone name.
	if z.Zonefile != "/zones/child.example.zone" {
		t.Errorf("Zonefile = %q, want %%-expanded path", z.Zonefile)
	}
	// Bespoke: OptionsStrs unioned.
	if len(z.OptionsStrs) != 1 || z.OptionsStrs[0] != "online-signing" {
		t.Errorf("OptionsStrs = %+v", z.OptionsStrs)
	}
	if z.DnssecPolicy != "default" {
		t.Errorf("DnssecPolicy = %q, want default", z.DnssecPolicy)
	}
	// Name must NOT be copied from the template.
	if z.Name != "child.example" {
		t.Errorf("Name = %q, must not be overwritten by template", z.Name)
	}
	// Slices must be cloned, not aliased to the template's backing array.
	z.Primaries[0].Addr = "mutated"
	if tmpl.Primaries[0].Addr == "mutated" {
		t.Error("Primaries aliased the template's backing array")
	}
}

// TestExpandTemplateZoneWins verifies a zone's own value is never overwritten.
func TestExpandTemplateZoneWins(t *testing.T) {
	tmpl := &ZoneConf{Type: "secondary", Store: "map", MultiSigner: "tmpl-ms"}
	z, err := ExpandTemplate(
		ZoneConf{Name: "z.", Type: "primary", Store: "slice", MultiSigner: "zone-ms"},
		tmpl, AppTypeAuth)
	if err != nil {
		t.Fatal(err)
	}
	if z.Type != "primary" || z.Store != "slice" || z.MultiSigner != "zone-ms" {
		t.Errorf("zone values overwritten: type=%q store=%q multisigner=%q", z.Type, z.Store, z.MultiSigner)
	}
}

// TestExpandTemplateAgentSkipsDnssec verifies the agent gate on DnssecPolicy.
func TestExpandTemplateAgentSkipsDnssec(t *testing.T) {
	tmpl := &ZoneConf{DnssecPolicy: "default"}
	z, err := ExpandTemplate(ZoneConf{Name: "z."}, tmpl, AppTypeAgent)
	if err != nil {
		t.Fatal(err)
	}
	if z.DnssecPolicy != "" {
		t.Errorf("DnssecPolicy = %q, agent must not inherit a policy", z.DnssecPolicy)
	}
}
