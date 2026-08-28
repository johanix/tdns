/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package core

import (
	"sort"
	"testing"
)

// THE WHOLE POINT: stored under one spelling, found under any other. This is
// the property that sixty-odd raw map lookups in tdns did not have.
func TestNameMapFindsAnySpelling(t *testing.T) {
	nm := NewNameMap[int]()
	nm.Set("NS1.Example.COM.", 42)

	for _, spelling := range []string{
		"NS1.Example.COM.", "ns1.example.com.", "NS1.EXAMPLE.COM.", "nS1.eXaMpLe.CoM.",
	} {
		got, ok := nm.Get(spelling)
		if !ok || got != 42 {
			t.Errorf("Get(%q) = (%v, %v), want (42, true)", spelling, got, ok)
		}
		if !nm.Has(spelling) {
			t.Errorf("Has(%q) = false", spelling)
		}
	}

	// And a name that merely looks similar is still a different name.
	if _, ok := nm.Get("ns2.example.com."); ok {
		t.Error("Get on an absent name reported present")
	}
	// Case folding is not suffix matching.
	if _, ok := nm.Get("ns1.example.com"); ok {
		t.Error("a relative name matched an absolute one; NameMap must not absolutise")
	}
}

// Two spellings of one name are ONE entry, not two. A zone file naming the same
// owner both ways must not produce two owners, one of which shadows the other.
func TestNameMapSpellingsCollapseToOneEntry(t *testing.T) {
	nm := NewNameMap[string]()
	nm.Set("WWW.example.com.", "first")
	nm.Set("www.example.com.", "second")

	if n := nm.Count(); n != 1 {
		t.Errorf("Count = %d after storing two spellings of one name, want 1", n)
	}
	got, _ := nm.Get("WwW.ExAmPlE.cOm.")
	if got != "second" {
		t.Errorf("later Set did not overwrite the earlier spelling: got %q", got)
	}
	if keys := nm.Keys(); len(keys) != 1 || keys[0] != "www.example.com." {
		t.Errorf("Keys = %v, want exactly the canonical spelling", keys)
	}
}

// Remove has to fold too. A delete that misses leaves a record served after the
// operator was told it was gone -- the worst direction for this bug to fail in.
func TestNameMapRemoveFolds(t *testing.T) {
	nm := NewNameMap[int]()
	nm.Set("ns1.example.com.", 1)
	nm.Remove("NS1.EXAMPLE.COM.")

	if nm.Has("ns1.example.com.") {
		t.Error("Remove with a different spelling left the entry behind")
	}
	if !nm.IsEmpty() {
		t.Errorf("IsEmpty = false, Count = %d", nm.Count())
	}
}

// Iteration exposes canonical keys, and every view of the map agrees on them.
// A caller that builds one list from Keys and another from Iter must not get
// two different sets of names.
func TestNameMapViewsAgree(t *testing.T) {
	nm := NewNameMap[int]()
	for i, n := range []string{"A.example.", "b.EXAMPLE.", "Cc.Example."} {
		nm.Set(n, i)
	}
	want := []string{"a.example.", "b.example.", "cc.example."}

	keys := nm.Keys()
	sort.Strings(keys)
	if len(keys) != 3 {
		t.Fatalf("Keys = %v, want 3 entries", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("Keys[%d] = %q, want %q", i, keys[i], want[i])
		}
	}

	var fromIter []string
	for tuple := range nm.IterBuffered() {
		fromIter = append(fromIter, tuple.Key)
	}
	sort.Strings(fromIter)
	for i := range want {
		if fromIter[i] != want[i] {
			t.Errorf("IterBuffered key %d = %q, want %q", i, fromIter[i], want[i])
		}
	}

	items := nm.Items()
	for _, n := range want {
		if _, ok := items[n]; !ok {
			t.Errorf("Items is missing %q; Keys and Items disagree", n)
		}
	}
}

// Non-UTF-8 octets survive as keys and stay distinct from one another. This is
// the property dns.CanonicalName does not have, and the reason NameMap folds
// with CanonicalizeName rather than with it.
func TestNameMapKeepsRawOctetsDistinct(t *testing.T) {
	nm := NewNameMap[string]()
	nm.Set("ns\xfe1.example.", "fe")
	nm.Set("ns\xff1.example.", "ff")

	if n := nm.Count(); n != 2 {
		t.Fatalf("Count = %d, want 2: two distinct names collided into one key", n)
	}
	if got, _ := nm.Get("NS\xfe1.EXAMPLE."); got != "fe" {
		t.Errorf("Get on the 0xfe name returned %q", got)
	}
	if got, _ := nm.Get("NS\xff1.EXAMPLE."); got != "ff" {
		t.Errorf("Get on the 0xff name returned %q", got)
	}
}
