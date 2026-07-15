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
		// deprecated — the hyphenated spelling of the same key, which the
		// guide used for a long time. Must NOT be shadowed by ".sigvalidity",
		// which it does not contain.
		"dnssec.policies[p1].KSK.sig-validity",
		// deprecated — zone-level leaves whose misspelling silently disables
		// signing rather than failing loudly
		"zones[0].dnssec_policy",
		"zones[1].dnssec-policy",
		"zones[0].multi_signer",
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
		"dnssec.policies[p1].KSK.sig-validity",
		"zones[0].dnssec_policy",
		"zones[1].dnssec-policy",
		"zones[0].multi_signer",
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

	// A non-exact entry names a deprecated LEAF and must match only at the END
	// of the path. A typo INSIDE the valid `sigvalidity:` subtree produces a
	// path that contains ".sigvalidity" but is really a misspelled `default`;
	// reporting it as the deprecated per-key scalar would send the operator
	// chasing the wrong migration.
	dep, unknown = classifyUnusedConfigKeys([]string{"dnssec.policies[p1].SigValidity.defualt"})
	if len(dep) != 0 {
		t.Errorf("typo inside a valid sigvalidity: block wrongly reported as deprecated: %+v", dep)
	}
	if len(unknown) != 1 {
		t.Errorf("expected the typo in unknown, got %v", unknown)
	}

	// Likewise the correctly-spelled keys, should one ever reach the classifier.
	for _, valid := range []string{
		"zones[0].dnssecpolicy",
		"zones[0].multisigner",
		"dnssec.policies[p1].SigValidity.default",
	} {
		dep, _ := classifyUnusedConfigKeys([]string{valid})
		if len(dep) != 0 {
			t.Errorf("valid key %q wrongly classified as deprecated: %+v", valid, dep)
		}
	}
}

// TestDeprecatedConfigKeysAdviceNamesReplacement is a cheap quality guard on the
// registry itself: the whole point of an entry is to tell the operator what to
// write instead, so every advice string must be non-trivial.
func TestDeprecatedConfigKeysAdviceNamesReplacement(t *testing.T) {
	for _, d := range deprecatedConfigKeys {
		if d.match == "" {
			t.Error("deprecated entry with empty match pattern")
		}
		if len(d.advice) < 20 {
			t.Errorf("deprecated entry %q has uselessly short advice %q", d.match, d.advice)
		}
	}
}
