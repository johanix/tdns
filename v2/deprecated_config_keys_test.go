package tdns

import "testing"

// TestClassifyUnusedConfigKeys documents and verifies the deprecated-key
// classifier: mapstructure's unused-key list is split into known-deprecated
// keys (with migration advice) and genuinely unknown keys (typos). This is
// the regression guard for the 2026-06-16 config restructure, where the
// testbed config silently lost every zone's DNSSEC policy because the loader
// no longer read the old top-level keys.
func TestClassifyUnusedConfigKeys(t *testing.T) {
	unused := []string{
		// deprecated — top-level keys moved under dnssec:
		"dnssecpolicies",
		"kasp",
		// deprecated — per-key sigvalidity scalar, reported in Go-field case
		// with a parent path, must still match the ".sigvalidity" substring
		"dnssec.policies[fastroll].KSK.sigvalidity",
		"dnssec.policies[default].ZSK.sigvalidity",
		// genuine typos — not deprecated, should land in unknown
		"servce", // misspelled "service"
		"dnsengine.adresses",
	}

	deprecated, unknown := classifyUnusedConfigKeys(unused)

	gotDep := map[string]bool{}
	for _, d := range deprecated {
		gotDep[d.key] = true
		if d.advice == "" {
			t.Errorf("deprecated key %q has empty advice", d.key)
		}
	}
	for _, want := range []string{
		"dnssecpolicies", "kasp",
		"dnssec.policies[fastroll].KSK.sigvalidity",
		"dnssec.policies[default].ZSK.sigvalidity",
	} {
		if !gotDep[want] {
			t.Errorf("expected %q classified as deprecated, was not", want)
		}
	}

	gotUnknown := map[string]bool{}
	for _, u := range unknown {
		gotUnknown[u] = true
	}
	for _, want := range []string{"servce", "dnsengine.adresses"} {
		if !gotUnknown[want] {
			t.Errorf("expected %q classified as unknown (typo), was not", want)
		}
	}

	// A deprecated key must NOT also appear in unknown, and vice versa.
	if gotUnknown["dnssecpolicies"] || gotUnknown["kasp"] {
		t.Errorf("a deprecated key leaked into the unknown bucket")
	}
	if gotDep["servce"] {
		t.Errorf("a typo leaked into the deprecated bucket")
	}
}

// TestClassifyUnusedConfigKeys_ExactVsSubstring guards the exact/substring
// matching contract: an exact entry (top-level key) must not match a nested
// path that merely contains the same word, while a substring entry must.
func TestClassifyUnusedConfigKeys_ExactVsSubstring(t *testing.T) {
	// "kasp" is exact: a hypothetical nested "dnssec.kasp.foo" (the NEW,
	// valid location) would never be reported as unused, but if some other
	// path contained "kasp" as a fragment it must NOT trip the exact rule.
	dep, unknown := classifyUnusedConfigKeys([]string{"service.kasptimeout"})
	if len(dep) != 0 {
		t.Errorf("exact match 'kasp' wrongly matched substring path; got %+v", dep)
	}
	if len(unknown) != 1 {
		t.Errorf("expected the non-deprecated path in unknown, got %v", unknown)
	}
}
