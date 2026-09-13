package tdns

import (
	"bytes"
	"math/rand"
	"net"
	"sort"
	"testing"

	"github.com/miekg/dns"
)

// Owner names reach the signer in presentation form, where one octet may be
// spelled as an escape: \255 is the single octet 0xff, \. a dot inside a
// label. RFC 4034 §6.1 orders the OCTETS. Compare the text instead and every
// escape sorts by its backslash (0x5C) -- an NSEC chain in an order validators
// reject, and a ZONEMD digest no other implementation computes.

// RFC 4034 §6.1 gives this list as its example of canonical order. \001 and
// \200 are one octet each; read as text, \001 lands after the asterisk, where
// the RFC has it before.
func TestCanonicalOrderMatchesTheRFC4034Example(t *testing.T) {
	want := []string{
		"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.",
		"zABC.a.EXAMPLE.", "z.example.", `\001.z.example.`, "*.z.example.",
		`\200.z.example.`,
	}
	rng := rand.New(rand.NewSource(4034))
	for round := 0; round < 20; round++ {
		names := append([]string(nil), want...)
		rng.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })

		byKey := append([]string(nil), names...)
		canonicalOwnerOrder(byKey)
		byLess := append([]string(nil), names...)
		sort.SliceStable(byLess, func(i, j int) bool {
			return canonicalOwnerLess(byLess[i], byLess[j])
		})

		for _, sorted := range []struct {
			how   string
			names []string
		}{{"canonicalOwnerOrder", byKey}, {"canonicalOwnerLess", byLess}} {
			for i := range want {
				if sorted.names[i] != want[i] {
					t.Fatalf("round %d, %s: position %d is %q, want %q\n  got:  %q\n  want: %q",
						round, sorted.how, i, sorted.names[i], want[i], sorted.names, want)
				}
			}
		}
	}
}

// In every "before" pair the presentation text sorts the other way round, so a
// comparison of text rather than octets fails each one. The "same" pairs are
// one name spelled two ways, which must share a position.
func TestCanonicalOrderComparesOctetsNotEscapes(t *testing.T) {
	before := []struct{ a, b, why string }{
		{`z.example.`, `\255.example.`, `\255 is the octet 0xff, after 'z'`},
		{`y.example.`, `\090.example.`, `\090 is 'Z', which folds to 'z'`},
		{`\000.example.`, `*.example.`, `\000 is the octet 0x00, before '*'`},
		{`a\.b.example.`, `a0.example.`, `\. is the octet '.', before '0'`},
	}
	for _, tc := range before {
		if !canonicalOwnerLess(tc.a, tc.b) || canonicalOwnerLess(tc.b, tc.a) {
			t.Errorf("canonicalOwnerLess does not put %q before %q (%s)", tc.a, tc.b, tc.why)
		}
		if bytes.Compare(canonicalSortKey(tc.a), canonicalSortKey(tc.b)) >= 0 {
			t.Errorf("canonicalSortKey does not put %q before %q (%s)\n  key(a)=% x\n  key(b)=% x",
				tc.a, tc.b, tc.why, canonicalSortKey(tc.a), canonicalSortKey(tc.b))
		}
	}

	same := []struct{ a, b, why string }{
		{`\065.example.`, `a.example.`, `\065 is 'A', and case folds however it is spelled`},
		{`\a.example.`, `a.example.`, `\a is the octet 'a'`},
		{`\255.example.`, "\xff.example.", "an escape and the raw octet it stands for"},
		{`a\000b.example.`, "a\x00b.example.", "an escaped zero octet and a raw one"},
		{`a\.b.example.`, `a\046b.example.`, "two escapes for one dot"},
	}
	for _, tc := range same {
		if canonicalOwnerLess(tc.a, tc.b) || canonicalOwnerLess(tc.b, tc.a) {
			t.Errorf("canonicalOwnerLess orders %q and %q apart (%s)", tc.a, tc.b, tc.why)
		}
		if !bytes.Equal(canonicalSortKey(tc.a), canonicalSortKey(tc.b)) {
			t.Errorf("canonicalSortKey gives %q and %q different keys (%s)\n  key(a)=% x\n  key(b)=% x",
				tc.a, tc.b, tc.why, canonicalSortKey(tc.a), canonicalSortKey(tc.b))
		}
	}
}

// canonicalSortKey reads presentation text itself, and the octets it has to
// arrive at are the ones miekg/dns puts on the wire. So its order is checked
// here against an order computed from PackDomainName's output, over every
// escape form the packer accepts.
func TestCanonicalSortKeyOrdersByWireOctets(t *testing.T) {
	names := []string{
		".", "example.", "a.example", "A.EXAMPLE.", "z.example.", "*.example.",
		"a.b.example.", "b.a.example.", "_dns.ns.example.", "K.example.",
		"ns\xfe1.example.", "ns\xff1.example.", "a\x00b.example.", "\x00.example.",
		`\255.example.`, `\254.example.`, `\090.example.`, `\065.example.`,
		`\a.example.`, `\A.example.`, `\000.example.`, `\001.example.`,
		`a\000b.example.`, `a\000.example.`, `a\.b.example.`, `a\046b.example.`,
		`a0.example.`, `a-.example.`, `a\\b.example.`, `\\.example.`,
		`a\ b.example.`, `\032.example.`, `\.\..example.`, `x.\255.example.`,
		`\001.z.example.`, `*.z.example.`, `\200.z.example.`, `yljkjljk.a.example.`,
	}

	wire := make(map[string][][]byte, len(names))
	for _, n := range names {
		buf := make([]byte, 256)
		off, err := dns.PackDomainName(dns.Fqdn(n), buf, 0, nil, false)
		if err != nil {
			t.Fatalf("packing %q: %v", n, err)
		}
		var labels [][]byte
		for i := 0; i < off && buf[i] != 0; i += 1 + int(buf[i]) {
			l := buf[i+1 : i+1+int(buf[i])]
			for k, c := range l {
				if c >= 'A' && c <= 'Z' {
					l[k] = c + 'a' - 'A'
				}
			}
			labels = append(labels, l)
		}
		wire[n] = labels
	}
	wireCompare := func(al, bl [][]byte) int {
		for i, j := len(al)-1, len(bl)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
			if c := bytes.Compare(al[i], bl[j]); c != 0 {
				return c
			}
		}
		switch {
		case len(al) < len(bl):
			return -1
		case len(al) > len(bl):
			return 1
		}
		return 0
	}

	for _, a := range names {
		for _, b := range names {
			want := wireCompare(wire[a], wire[b])
			if got := bytes.Compare(canonicalSortKey(a), canonicalSortKey(b)); got != want {
				t.Errorf("%q vs %q: key order %d, wire order %d\n  key(a)=% x\n  key(b)=% x",
					a, b, got, want, canonicalSortKey(a), canonicalSortKey(b))
			}
		}
	}
}

// One name spelled several ways shares one key. Owner keys are canonical and
// never tie, but where spellings of one name do meet, where they sort among
// themselves must not depend on the order they arrived in.
func TestCanonicalOwnerOrderBreaksKeyTiesBySpelling(t *testing.T) {
	want := []string{"A.example.", `\065.example.`, `\a.example.`, "a.example.", "b.example."}
	rng := rand.New(rand.NewSource(65))
	for round := 0; round < 50; round++ {
		names := append([]string(nil), want...)
		rng.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
		canonicalOwnerOrder(names)
		for i := range want {
			if names[i] != want[i] {
				t.Fatalf("round %d: got %q, want %q", round, names, want)
			}
		}
	}
}

// And the digest of a zone that writes one name several ways is one value:
// the file-change detector fires whenever two computations over one zone
// disagree.
func TestZoneDigestIsStableOverOneNameSpelledTwoWays(t *testing.T) {
	mkA := func(owner, addr string) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(addr),
		}
	}
	soa, err := dns.NewRR("example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200")
	if err != nil {
		t.Fatalf("building the SOA: %v", err)
	}
	rrs := []dns.RR{soa,
		mkA(`\065.example.`, "192.0.2.1"), mkA(`\a.example.`, "192.0.2.2"), mkA("a.example.", "192.0.2.3"),
	}

	first, err := ZoneDigest("example.", rrs, 1, 1)
	if err != nil {
		t.Fatalf("ZoneDigest: %v", err)
	}
	for i := 0; i < 50; i++ {
		got, err := ZoneDigest("example.", rrs, 1, 1)
		if err != nil {
			t.Fatalf("ZoneDigest: %v", err)
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("computation %d digests the same zone to a different value", i+2)
		}
	}
}

// RFC 4034 §6.2 lowers an owner's US-ASCII letters before it is hashed, and
// \065 is one of them: a zone that writes its owner \065.example. digests as
// the zone that writes it a.example.
func TestZoneDigestReadsEscapesInOwnerNames(t *testing.T) {
	mkA := func(owner string) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		}
	}
	soa, err := dns.NewRR("example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200")
	if err != nil {
		t.Fatalf("building the SOA: %v", err)
	}

	want, err := ZoneDigest("example.", []dns.RR{soa, mkA("a.example.")}, 1, 1)
	if err != nil {
		t.Fatalf("ZoneDigest: %v", err)
	}
	for _, owner := range []string{`\065.example.`, `\097.example.`, "A.example."} {
		got, err := ZoneDigest("example.", []dns.RR{soa, mkA(owner)}, 1, 1)
		if err != nil {
			t.Fatalf("ZoneDigest with owner %q: %v", owner, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("a zone writing its owner %q digests differently from one writing a.example.", owner)
		}
	}
}
