package tdns

import (
	"bytes"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

// canonicalSortKey replaces a pairwise comparator that the NSEC chain order
// depends on. The two must agree on EVERY pair, not on the pairs someone
// thought to write down -- a name ordering that is subtly wrong produces a
// chain no validator accepts, and no query against the signer reveals it.
func TestCanonicalSortKeyAgreesWithTheComparator(t *testing.T) {
	names := []string{
		"example.", "a.example.", "z.example.", "a.b.example.", "b.a.example.",
		"clean.example.", "alpha.clean.example.", "ns.clean.example.",
		"A.EXAMPLE.", "a.example",
		"*.example.", "_dns.ns.example.",
		"aa.example.", "ab.example.", "b.example.",
		"x.y.z.example.", "y.z.example.", "z.z.example.",
		".", "com.", "example.com.", "www.example.com.",
		// A zero octet inside a label: legal, and the case the escape exists
		// for. Without it this collides with the label separator.
		"a\x00b.example.", "a.b.example.",
		"\x00.example.", "\x01.example.",
	}
	for _, a := range names {
		for _, b := range names {
			want := canonicalOwnerLess(a, b)
			got := bytes.Compare(canonicalSortKey(a), canonicalSortKey(b)) < 0
			if want != got {
				t.Errorf("%q vs %q: comparator says less=%v, key order says less=%v\n"+
					"  key(a)=%q\n  key(b)=%q", a, b, want, got,
					canonicalSortKey(a), canonicalSortKey(b))
			}
		}
	}
}

// ...and they must produce the same SORT, not merely agree pairwise: a
// comparator and a key can agree on every pair and still be sorted differently
// if the key order is not a total order.
func TestCanonicalSortKeyProducesTheSameOrderAsTheComparator(t *testing.T) {
	rng := rand.New(rand.NewSource(20260825))
	labels := []string{"a", "b", "z", "aa", "ab", "ns", "clean", "example", "x"}

	for round := 0; round < 200; round++ {
		n := 2 + rng.Intn(12)
		names := make([]string, 0, n)
		for i := 0; i < n; i++ {
			depth := 1 + rng.Intn(4)
			parts := make([]string, depth)
			for d := range parts {
				parts[d] = labels[rng.Intn(len(labels))]
			}
			names = append(names, strings.Join(parts, ".")+".")
		}

		byComparator := append([]string(nil), names...)
		sort.SliceStable(byComparator, func(i, j int) bool {
			return canonicalOwnerLess(byComparator[i], byComparator[j])
		})

		byKey := append([]string(nil), names...)
		keys := make(map[string][]byte, len(byKey))
		for _, nm := range byKey {
			keys[nm] = canonicalSortKey(nm)
		}
		sort.SliceStable(byKey, func(i, j int) bool {
			return bytes.Compare(keys[byKey[i]], keys[byKey[j]]) < 0
		})

		for i := range byComparator {
			if byComparator[i] != byKey[i] {
				t.Fatalf("round %d: the two sorts disagree at position %d\n"+
					"  comparator: %v\n  key:        %v", round, i, byComparator, byKey)
			}
		}
	}
}

// The apex sorts first, which is the property the NSEC chain is built on and
// the one a lexicographic sort gets wrong.
func TestCanonicalSortKeyPutsTheApexFirst(t *testing.T) {
	names := []string{"ns.clean.example.", "alpha.clean.example.", "clean.example."}
	keys := map[string][]byte{}
	for _, n := range names {
		keys[n] = canonicalSortKey(n)
	}
	sort.Slice(names, func(i, j int) bool {
		return bytes.Compare(keys[names[i]], keys[names[j]]) < 0
	})
	if names[0] != "clean.example." {
		t.Errorf("the apex is not first: %v", names)
	}
}

func BenchmarkCanonicalOwnerLess(b *testing.B) {
	x, y := "alpha.bench.example.", "bravo.bench.example."
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = canonicalOwnerLess(x, y)
	}
}

func BenchmarkCanonicalSortKeyCompare(b *testing.B) {
	kx, ky := canonicalSortKey("alpha.bench.example."), canonicalSortKey("bravo.bench.example.")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = bytes.Compare(kx, ky) < 0
	}
}

// The realistic comparison: sorting a zone's owner names, which is what every
// publish of a signed zone does.
func benchmarkOwnerSort(b *testing.B, n int, useKeys bool) {
	base := make([]string, n)
	for i := range base {
		base[i] = strings.Repeat("x", i%7+1) + string(rune('a'+i%26)) +
			".sub.bench.example."
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		names := append([]string(nil), base...)
		if useKeys {
			keys := make(map[string][]byte, len(names))
			for _, nm := range names {
				keys[nm] = canonicalSortKey(nm)
			}
			sort.Slice(names, func(i, j int) bool {
				return bytes.Compare(keys[names[i]], keys[names[j]]) < 0
			})
		} else {
			sort.Slice(names, func(i, j int) bool {
				return canonicalOwnerLess(names[i], names[j])
			})
		}
	}
}

func BenchmarkOwnerSortComparator10k(b *testing.B) { benchmarkOwnerSort(b, 10000, false) }
func BenchmarkOwnerSortKeys10k(b *testing.B)       { benchmarkOwnerSort(b, 10000, true) }
