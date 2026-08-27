/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func yml(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	return m
}

// merge is the harness: fold src into dst and hand back the bookkeeping.
func merge(t *testing.T, dst, src map[string]interface{}, doMerge bool) *mergeState {
	t.Helper()
	st := newMergeState()
	if err := mergeConfigMaps(dst, src, "", "inc.yaml", doMerge, st, nil); err != nil {
		t.Fatalf("mergeConfigMaps: %v", err)
	}
	return st
}

func TestMergeZonesConcatenates(t *testing.T) {
	dst := yml(t, "zones:\n  - name: a.example.\n")
	src := yml(t, "zones:\n  - name: b.example.\n")
	merge(t, dst, src, true)

	got := dst["zones"].([]interface{})
	if len(got) != 2 {
		t.Fatalf("zones = %d entries, want 2 (%v)", len(got), got)
	}
	if itemName(got[0]) != "a.example." || itemName(got[1]) != "b.example." {
		t.Errorf("order should be including file first, then the include: %v", got)
	}
}

// The default is unchanged, and that is the whole point of opt-in.
func TestWithoutOptInZonesStillReplace(t *testing.T) {
	dst := yml(t, "zones:\n  - name: a.example.\n")
	src := yml(t, "zones:\n  - name: b.example.\n")
	st := merge(t, dst, src, false)

	got := dst["zones"].([]interface{})
	if len(got) != 1 || itemName(got[0]) != "b.example." {
		t.Fatalf("a bare include must still replace, got %v", got)
	}
	// ...but it stops being silent.
	if len(st.Clobbers()) != 1 || st.Clobbers()[0].Path != "zones" || st.Clobbers()[0].Lost != 1 {
		t.Errorf("replacing a non-empty allowlisted key must be recorded: %+v", st.Clobbers())
	}
}

func TestClobberNotReportedWhenNothingWasLost(t *testing.T) {
	dst := yml(t, "zones: []\n")
	src := yml(t, "zones:\n  - name: b.example.\n")
	st := merge(t, dst, src, false)
	if len(st.Clobbers()) != 0 {
		t.Errorf("replacing an empty key is not a clobber: %+v", st.Clobbers())
	}
}

// dnssec.policies is the case a top-level-only dispatcher would miss: dnssec
// takes the map branch and policies is assigned by the inner loop.
func TestMergeNestedPoliciesByName(t *testing.T) {
	dst := yml(t, "dnssec:\n  completeness: relaxed\n  policies:\n    alpha:\n      algorithm: ED25519\n")
	src := yml(t, "dnssec:\n  policies:\n    beta:\n      algorithm: ED25519\n")
	merge(t, dst, src, true)

	d := dst["dnssec"].(map[string]interface{})
	pol := d["policies"].(map[string]interface{})
	if len(pol) != 2 || pol["alpha"] == nil || pol["beta"] == nil {
		t.Fatalf("policies should merge by name, got %v", sortedStringKeys(pol))
	}
	if d["completeness"] != "relaxed" {
		t.Errorf("a sibling of a merged nested key must survive: %v", d)
	}
}

func TestNonAllowlistedNestedKeysStillReplace(t *testing.T) {
	// The loader has always merged exactly ONE level: two top-level maps have
	// their children assigned wholesale. So an include carrying a partial
	// dnssec.kasp replaces the whole kasp map and the siblings it omits are
	// gone -- decoder defaults then apply.
	//
	// This must hold whether or not the include opted in, because opting in
	// buys the ALLOWLIST, not a deeper merge. An earlier version of this file
	// recursed unconditionally, which quietly made those siblings survive; and
	// this test, written against that behaviour, asserted they survived while
	// its name said they should not.
	for _, doMerge := range []bool{false, true} {
		name := "bare include"
		if doMerge {
			name = "merge: true"
		}
		t.Run(name, func(t *testing.T) {
			dst := yml(t, "dnssec:\n  kasp:\n    check_interval: 1m\n    propagation_delay: 1h\n")
			src := yml(t, "dnssec:\n  kasp:\n    check_interval: 5m\n")
			merge(t, dst, src, doMerge)

			kasp := dst["dnssec"].(map[string]interface{})["kasp"].(map[string]interface{})
			if kasp["check_interval"] != "5m" {
				t.Errorf("included file should win for a non-allowlisted key: %v", kasp)
			}
			if _, survived := kasp["propagation_delay"]; survived {
				t.Errorf("a non-allowlisted nested map must be REPLACED, not deep-merged; "+
					"the sibling should be gone: %v", kasp)
			}
		})
	}
}

// TestAllowlistedNestedKeyIsStillReachable is the other half: the recursion
// that F1 restricted must still go deep enough to reach dnssec.policies, which
// is the case the whole feature exists for. Restricting it to "no recursion at
// all" would compile, keep the test above green, and silently break the
// motivating example.
func TestAllowlistedNestedKeyIsStillReachable(t *testing.T) {
	dst := yml(t, "dnssec:\n  policies:\n    alpha:\n      algorithm: ED25519\n")
	src := yml(t, "dnssec:\n  policies:\n    beta:\n      algorithm: ED25519\n")
	merge(t, dst, src, true)

	policies := dst["dnssec"].(map[string]interface{})["policies"].(map[string]interface{})
	for _, want := range []string{"alpha", "beta"} {
		if _, ok := policies[want]; !ok {
			t.Errorf("policy %q lost; an opted-in dnssec.policies must union: %v", want, policies)
		}
	}
}

// The allowlist binds even an include that asked to merge. Concatenating
// listen addresses would silently widen what the server answers on.
func TestListenAddressesNeverConcatenate(t *testing.T) {
	dst := yml(t, "dnsengine:\n  addresses: [ 127.0.0.1:53 ]\n")
	src := yml(t, "dnsengine:\n  addresses: [ 192.0.2.1:53 ]\n")
	merge(t, dst, src, true)

	addrs := dst["dnsengine"].(map[string]interface{})["addresses"].([]interface{})
	if len(addrs) != 1 || addrs[0] != "192.0.2.1:53" {
		t.Fatalf("dnsengine.addresses must replace even when opted in, got %v", addrs)
	}
}

func TestLargeAlgorithmsUnionDeduplicates(t *testing.T) {
	dst := yml(t, "dnssec:\n  large_algorithms: [ MLDSA87, FALCON512 ]\n")
	src := yml(t, "dnssec:\n  large_algorithms: [ FALCON512, MLDSA44 ]\n")
	merge(t, dst, src, true)

	got := dst["dnssec"].(map[string]interface{})["large_algorithms"].([]interface{})
	if len(got) != 3 {
		t.Fatalf("union should deduplicate, got %v", got)
	}
}

func TestSplitAlgorithmsUnionsLeafLists(t *testing.T) {
	dst := yml(t, "dnssec:\n  split_algorithms:\n    MLDSA87: [ ED25519 ]\n")
	src := yml(t, "dnssec:\n  split_algorithms:\n    MLDSA87: [ FALCON512 ]\n    MLDSA44: [ ED25519 ]\n")
	merge(t, dst, src, true)

	split := dst["dnssec"].(map[string]interface{})["split_algorithms"].(map[string]interface{})
	m87 := split["MLDSA87"].([]interface{})
	if len(m87) != 2 {
		t.Fatalf("a KSK present in both files should allow both ZSKs, got %v", m87)
	}
	if split["MLDSA44"] == nil {
		t.Error("a KSK present in only one file should survive")
	}
}

func TestCollisionNamesBothFiles(t *testing.T) {
	dst := yml(t, "zones:\n  - name: a.example.\n")
	src := yml(t, "zones:\n  - name: a.example.\n")
	st := newMergeState()
	// The including file's own items have to be recorded before it merges,
	// which is what processConfigFile does for the file it just read.
	recordOrigins("zones", dst["zones"], "main.yaml", st, nil, false)
	if err := mergeConfigMaps(dst, src, "", "inc.yaml", true, st, nil); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(st.Collisions()) != 1 {
		t.Fatalf("collisions = %+v, want 1", st.Collisions())
	}
	c := st.Collisions()[0]
	if c.First != "main.yaml" || c.Again != "inc.yaml" {
		t.Errorf("a collision must name both files, got %+v", c)
	}
	if !strings.Contains(c.Error(), "a.example.") {
		t.Errorf("collision message should name the item: %s", c.Error())
	}
}

func TestPolicyCollisionKeepsNeitherDefinition(t *testing.T) {
	dst := yml(t, "dnssec:\n  policies:\n    alpha:\n      algorithm: ED25519\n")
	src := yml(t, "dnssec:\n  policies:\n    alpha:\n      algorithm: RSASHA256\n")
	st := merge(t, dst, src, true)

	if len(st.Collisions()) != 1 {
		t.Fatalf("collisions = %+v, want 1", st.Collisions())
	}
	// NEITHER survives. A zone naming this policy then fails to resolve it and
	// is quarantined by the existing unusable-policy path, which is the right
	// outcome: the server keeps serving every other zone, and no zone is
	// signed by a policy nobody wrote down.
	pol := dst["dnssec"].(map[string]interface{})["policies"].(map[string]interface{})
	if _, still := pol["alpha"]; still {
		t.Errorf("a collided policy must not survive under either definition: %v", pol)
	}
}

func TestTypeMismatchIsAHardError(t *testing.T) {
	dst := yml(t, "zones:\n  - name: a.example.\n")
	src := yml(t, "zones:\n  a.example.:\n    type: primary\n")
	st := newMergeState()
	err := mergeConfigMaps(dst, src, "", "inc.yaml", true, st, nil)
	if err == nil {
		t.Fatal("a list/mapping disagreement must be an error, not a silent replace")
	}
	if !strings.Contains(err.Error(), "zones") {
		t.Errorf("the error should name the path: %v", err)
	}
}
