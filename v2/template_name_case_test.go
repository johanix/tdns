package tdns

import "testing"

// The daemon's side of the config-check contract: template names are map keys,
// keyed exactly, so two names differing only in case are two templates and both
// load. config check must not call that a duplicate — it did, and told the
// operator the daemon would refuse to start on a config the daemon accepts.
//
// Pinned here as well as in the checker's own test because the divergence is
// only visible when both halves are stated.
func TestBuildTemplateMapKeysTemplatesExactly(t *testing.T) {
	savedTemplates, savedApp := Templates, Globals.App.Type
	t.Cleanup(func() { Templates, Globals.App.Type = savedTemplates, savedApp })
	Globals.App.Type = AppTypeAuth

	conf := &Config{Templates: []ZoneConf{{Name: "Signing-Primary"}, {Name: "signing-primary"}}}
	if err := conf.buildTemplateMap(); err != nil {
		t.Fatalf("case variants must be accepted as distinct templates, got: %v", err)
	}
	for _, want := range []string{"Signing-Primary", "signing-primary"} {
		if _, ok := Templates[want]; !ok {
			t.Errorf("template %q missing; the daemon keys by exact name", want)
		}
	}

	// And a genuine duplicate is still refused, which is what the checker's
	// FAIL claims on the operator's behalf.
	dup := &Config{Templates: []ZoneConf{{Name: "signing-primary"}, {Name: "signing-primary"}}}
	if err := dup.buildTemplateMap(); err == nil {
		t.Error("an exact duplicate template name must be an error")
	}
}
