/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The example zone of RFC 5155 Appendix A: hash SHA-1, salt aabbccdd, 12
// iterations, every NSEC3 with Opt-Out set. Keyed by the first four
// characters of the owner hash. The proofs of Appendix B are made from these.
var rfc5155Chain = map[string]string{
	"0p9m": "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG", // example
	"2t7b": "2t7b4g4vsa5smi47k61mv5bv1a22bojr 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG",                           // ns1.example
	"2vpt": "2vptu5timamqttgl4luu9kg21e0aor3s 35mthgpgcu1qg68fab165klnsnk3dpvl MX RRSIG",                          // x.y.w.example
	"35mt": "35mthgpgcu1qg68fab165klnsnk3dpvl b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG",                       // a.example
	"b4um": "b4um86eghhds6nea196smvmlo4ors995 gjeqe526plbf1g8mklp59enfd789njgi MX RRSIG",                          // x.w.example
	"gjeq": "gjeqe526plbf1g8mklp59enfd789njgi ji6neoaepv8b5o6k4ev33abha8ht9fgc A HINFO AAAA RRSIG",                // ai.example
	"ji6n": "ji6neoaepv8b5o6k4ev33abha8ht9fgc k8udemvp1j2f7eg6jebps17vp3n8i58h",                                   // y.w.example, empty non-terminal
	"k8ud": "k8udemvp1j2f7eg6jebps17vp3n8i58h kohar7mbb8dc2ce8a9qvl8hon4k53uhi",                                   // w.example, empty non-terminal
	"koha": "kohar7mbb8dc2ce8a9qvl8hon4k53uhi q04jkcevqvmu85r014c7dkba38o0ji5r A RRSIG",                           // 2t7b4g4vsa5smi47k61mv5bv1a22bojr.example
	"q04j": "q04jkcevqvmu85r014c7dkba38o0ji5r r53bq7cc2uvmubfu5ocmm6pers9tk9en A RRSIG",                           // ns2.example
	"r53b": "r53bq7cc2uvmubfu5ocmm6pers9tk9en t644ebqk9bibcna874givr6joj62mlhv MX RRSIG",                          // *.w.example
	"t644": "t644ebqk9bibcna874givr6joj62mlhv 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom A HINFO AAAA RRSIG",                // xx.example
}

// rfcNSEC3 is the Appendix A record key, with flags, and with its bitmap
// replaced when types is given.
func rfcNSEC3(t *testing.T, key string, flags uint8, types ...string) *dns.NSEC3 {
	t.Helper()
	f := strings.Fields(rfc5155Chain[key])
	if len(f) < 2 {
		t.Fatalf("no record %q", key)
	}
	bitmap := strings.Join(f[2:], " ")
	if types != nil {
		bitmap = strings.Join(types, " ")
	}
	rr, err := dns.NewRR(f[0] + ".example. 3600 IN NSEC3 1 " + string('0'+rune(flags)) + " 12 aabbccdd " + f[1] + " " + bitmap)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	return rr.(*dns.NSEC3)
}

func rfcRecords(t *testing.T, flags uint8, keys ...string) []*dns.NSEC3 {
	var rrs []*dns.NSEC3
	for _, k := range keys {
		rrs = append(rrs, rfcNSEC3(t, k, flags))
	}
	return rrs
}

// synthNSEC3 is an NSEC3 in zone under the given parameters matching name, or,
// with cover, covering its hash with an interval that holds it and no other.
func synthNSEC3(zone, name string, cover bool, flags uint8, iterations uint16, salt string, types ...uint16) *dns.NSEC3 {
	h := dns.HashName(name, dns.SHA1, iterations, salt)
	owner := h
	if cover {
		owner = hashStep(h, -1)
	}
	return &dns.NSEC3{Hdr: dns.RR_Header{Name: owner + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash: dns.SHA1, Flags: flags, Iterations: iterations, SaltLength: uint8(len(salt) / 2), Salt: salt,
		HashLength: 20, NextDomain: hashStep(h, 1), TypeBitMap: types}
}

// RFC 5155 Appendix A lists the hash of every name in the example zone.
// nsec3Hash must give the same, fold upper case in names, and fold nothing
// else.
func TestNSEC3HashRFC5155AppendixA(t *testing.T) {
	params := nsec3Params{alg: dns.SHA1, iterations: 12, salt: "\xaa\xbb\xcc\xdd"}
	for name, want := range map[string]string{
		"example.":       "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
		"a.example.":     "35mthgpgcu1qg68fab165klnsnk3dpvl",
		"ai.example.":    "gjeqe526plbf1g8mklp59enfd789njgi",
		"ns1.example.":   "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
		"ns2.example.":   "q04jkcevqvmu85r014c7dkba38o0ji5r",
		"w.example.":     "k8udemvp1j2f7eg6jebps17vp3n8i58h",
		"*.w.example.":   "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
		"x.w.example.":   "b4um86eghhds6nea196smvmlo4ors995",
		"y.w.example.":   "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
		"x.y.w.example.": "2vptu5timamqttgl4luu9kg21e0aor3s",
		"xx.example.":    "t644ebqk9bibcna874givr6joj62mlhv",
		"2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.": "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
		// The names Appendix B proves absent.
		"c.x.w.example.": "0va5bpr2ou0vk0lbqeeljri88laipsfh",
		"*.x.w.example.": "92pqneegtaue7pjatc3l3qnk738c6v5m",
		"c.example.":     "4g6p9u5gvfshp30pqecj98b3maqbn1ck",
		"z.w.example.":   "qlu7gtfaeh0ek0c05ksfhdpbcgglbe03",
		// Upper case is folded.
		"X.W.Example.":    "b4um86eghhds6nea196smvmlo4ors995",
		`\088.w.example.`: "b4um86eghhds6nea196smvmlo4ors995", // \088 is "X"
	} {
		wire, ok := canonicalWire(name)
		if !ok {
			t.Fatalf("%s does not pack", name)
		}
		got := strings.ToLower(base32hexNoPad.EncodeToString(nsec3Hash(wire, params)))
		if got != want {
			t.Errorf("H(%s) = %s, want %s", name, got, want)
		}
	}
	// Octets above US-ASCII are not folded: \196 and \228 are different names.
	w1, _ := canonicalWire(`\196.example.`)
	w2, _ := canonicalWire(`\228.example.`)
	if bytes.Equal(nsec3Hash(w1, params), nsec3Hash(w2, params)) {
		t.Error(`\196 and \228 hash alike: an octet above US-ASCII was folded`)
	}
}

// The proofs of RFC 5155 Appendix B, from the records the RFC puts in each
// response, and each with one record taken out, altered or added.
func TestNSEC3ProofsRFC5155AppendixB(t *testing.T) {
	const (
		nameError = iota
		noData
		wildcardAnswer
	)
	cases := []struct {
		name    string
		kind    int
		qname   string
		qtype   uint16
		labels  uint8
		records func(t *testing.T, flags uint8) []*dns.NSEC3
		optOut  nsec3Verdict // with the RFC's Opt-Out flags
		noOpt   nsec3Verdict // with every flag cleared
	}{
		// B.1: a.c.x.w.example does not exist. x.w.example is the closest
		// encloser, c.x.w.example the next closer name, *.x.w.example the
		// wildcard.
		{"B.1 name error", nameError, "a.c.x.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "0p9m", "b4um", "35mt") }, nsec3OptOut, nsec3Proven},
		{"B.1 without the closest encloser", nameError, "a.c.x.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "0p9m", "35mt") }, nsec3Unproven, nsec3Unproven},
		{"B.1 without the next closer cover", nameError, "a.c.x.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "b4um", "35mt") }, nsec3Unproven, nsec3Unproven},
		{"B.1 without the wildcard cover", nameError, "a.c.x.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "0p9m", "b4um") }, nsec3Unproven, nsec3Unproven},
		{"B.1 with a record matching the qname", nameError, "a.c.x.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return append(rfcRecords(t, f, "0p9m", "b4um", "35mt"),
					synthNSEC3("example.", "a.c.x.w.example.", false, f, 12, "aabbccdd", dns.TypeA, dns.TypeRRSIG))
			}, nsec3Unproven, nsec3Unproven},
		{"B.1, closest encloser with DNAME", nameError, "a.c.x.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "0p9m", f), rfcNSEC3(t, "b4um", f, "DNAME", "RRSIG"), rfcNSEC3(t, "35mt", f)}
			}, nsec3Unproven, nsec3Unproven},
		{"B.1, closest encloser an insecure delegation", nameError, "a.c.x.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "0p9m", f), rfcNSEC3(t, "b4um", f, "NS"), rfcNSEC3(t, "35mt", f)}
			}, nsec3InsecureDelegation, nsec3InsecureDelegation},
		{"B.1, closest encloser a secure delegation", nameError, "a.c.x.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "0p9m", f), rfcNSEC3(t, "b4um", f, "NS", "DS", "RRSIG"), rfcNSEC3(t, "35mt", f)}
			}, nsec3Unproven, nsec3Unproven},
		{"B.1, closest encloser the zone apex", nameError, "a.c.x.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				// No record for x.w or w: example is the closest encloser, and
				// w.example the next closer name.
				return []*dns.NSEC3{rfcNSEC3(t, "0p9m", f), synthNSEC3("example.", "w.example.", true, f, 12, "aabbccdd"),
					synthNSEC3("example.", "*.example.", true, f, 12, "aabbccdd")}
			}, nsec3OptOut, nsec3Proven},

		// B.2: ns1.example has no MX.
		{"B.2 no data", noData, "ns1.example.", dns.TypeMX, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "2t7b") }, nsec3Proven, nsec3Proven},
		{"B.2 with MX in the bitmap", noData, "ns1.example.", dns.TypeMX, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "2t7b", f, "A", "MX", "RRSIG")}
			}, nsec3Unproven, nsec3Unproven},
		{"B.2 with CNAME in the bitmap", noData, "ns1.example.", dns.TypeMX, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "2t7b", f, "CNAME", "RRSIG")}
			}, nsec3Unproven, nsec3Unproven},
		{"B.2, the match an insecure delegation", noData, "ns1.example.", dns.TypeMX, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return []*dns.NSEC3{rfcNSEC3(t, "2t7b", f, "NS")} }, nsec3InsecureDelegation, nsec3InsecureDelegation},
		{"B.2, the match a secure delegation", noData, "ns1.example.", dns.TypeMX, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "2t7b", f, "NS", "DS", "RRSIG")}
			}, nsec3Unproven, nsec3Unproven},
		{"B.2, a DS at a delegation", noData, "ns1.example.", dns.TypeDS, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return []*dns.NSEC3{rfcNSEC3(t, "2t7b", f, "NS")} }, nsec3Proven, nsec3Proven},
		{"B.2 without its record", noData, "ns1.example.", dns.TypeMX, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return nil }, nsec3Unproven, nsec3Unproven},

		// B.2.1: y.w.example is an empty non-terminal.
		{"B.2.1 empty non-terminal", noData, "y.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "ji6n") }, nsec3Proven, nsec3Proven},
		{"B.2.1 with the wrong record", noData, "y.w.example.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "35mt") }, nsec3Unproven, nsec3Unproven},

		// c.example is delegated in an Opt-Out span (B.3): its DS is denied by
		// the closest encloser proof, with Opt-Out on the next closer cover.
		{"DS no data through Opt-Out", noData, "c.example.", dns.TypeDS, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "0p9m", "35mt") }, nsec3OptOut, nsec3Unproven},
		{"DS no data below an insecure delegation", noData, "b.a.example.", dns.TypeDS, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "0p9m", f), rfcNSEC3(t, "35mt", f, "NS"),
					synthNSEC3("example.", "b.a.example.", true, f, 12, "aabbccdd")}
			}, nsec3Unproven, nsec3Unproven},

		// B.4: a.z.w.example MX is synthesised from *.w.example (Labels 2);
		// z.w.example must not exist.
		{"B.4 wildcard answer", wildcardAnswer, "a.z.w.example.", dns.TypeMX, 2,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "q04j") }, nsec3OptOut, nsec3Proven},
		{"B.4 without the next closer cover", wildcardAnswer, "a.z.w.example.", dns.TypeMX, 2,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "r53b") }, nsec3Unproven, nsec3Unproven},
		{"B.4 with Labels as long as the qname", wildcardAnswer, "a.z.w.example.", dns.TypeMX, 4,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "q04j") }, nsec3Unproven, nsec3Unproven},
		{"B.4 with Labels above the zone", wildcardAnswer, "a.z.w.example.", dns.TypeMX, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "q04j") }, nsec3Unproven, nsec3Unproven},

		// B.5: a.z.w.example has no AAAA: the wildcard *.w.example matches, and
		// has none.
		{"B.5 wildcard no data", noData, "a.z.w.example.", dns.TypeAAAA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "k8ud", "q04j", "r53b") }, nsec3OptOut, nsec3Proven},
		{"B.5 without the closest encloser", noData, "a.z.w.example.", dns.TypeAAAA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "q04j", "r53b") }, nsec3Unproven, nsec3Unproven},
		{"B.5 without the next closer cover", noData, "a.z.w.example.", dns.TypeAAAA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "k8ud", "r53b") }, nsec3Unproven, nsec3Unproven},
		{"B.5 without the wildcard", noData, "a.z.w.example.", dns.TypeAAAA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "k8ud", "q04j") }, nsec3OptOut, nsec3Unproven},
		{"B.5, the wildcard has AAAA", noData, "a.z.w.example.", dns.TypeAAAA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "k8ud", f), rfcNSEC3(t, "q04j", f), rfcNSEC3(t, "r53b", f, "AAAA", "RRSIG")}
			}, nsec3Unproven, nsec3Unproven},
		{"B.5, the wildcard has CNAME", noData, "a.z.w.example.", dns.TypeAAAA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "k8ud", f), rfcNSEC3(t, "q04j", f), rfcNSEC3(t, "r53b", f, "CNAME", "RRSIG")}
			}, nsec3Unproven, nsec3Unproven},
		{"B.5, the wildcard is a delegation", noData, "a.z.w.example.", dns.TypeAAAA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 {
				return []*dns.NSEC3{rfcNSEC3(t, "k8ud", f), rfcNSEC3(t, "q04j", f), rfcNSEC3(t, "r53b", f, "NS")}
			}, nsec3Unproven, nsec3Unproven},

		// B.6: the DS of example, asked of example itself. RFC 5155 section
		// 8.6 checks the DS and CNAME bits only.
		{"B.6 DS at the apex", noData, "example.", dns.TypeDS, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "0p9m") }, nsec3Proven, nsec3Proven},

		// A qname outside the zone proves nothing.
		{"a qname outside the zone", nameError, "a.example.org.", dns.TypeA, 0,
			func(t *testing.T, f uint8) []*dns.NSEC3 { return rfcRecords(t, f, "0p9m", "b4um", "35mt") }, nsec3Unproven, nsec3Unproven},
	}
	for _, c := range cases {
		for _, flags := range []uint8{1, 0} {
			want := c.optOut
			if flags == 0 {
				want = c.noOpt
			}
			p := newNSEC3Proof("example.", c.records(t, flags), 150)
			var got nsec3Verdict
			switch c.kind {
			case nameError:
				got = p.nameError(c.qname)
			case noData:
				got = p.noData(c.qname, c.qtype)
			case wildcardAnswer:
				got = p.wildcardAnswer(c.qname, c.labels)
			}
			if got != want {
				t.Errorf("%s, flags %d: %s, want %s", c.name, flags, nsec3VerdictToString[got], nsec3VerdictToString[want])
			}
		}
	}
}

// Only records that meet RFC 5155 sections 8.1 and 8.2, owned directly below
// the zone, with hashes that decode, count. Each record here is B.2's with one
// thing wrong, and alone it proves nothing.
func TestNSEC3RecordsThatDoNotCount(t *testing.T) {
	for name, edit := range map[string]func(*dns.NSEC3){
		"hash algorithm 2": func(r *dns.NSEC3) { r.Hash = 2 },
		"flags 2":          func(r *dns.NSEC3) { r.Flags = 2 },
		"hash length 19":   func(r *dns.NSEC3) { r.HashLength = 19 },
		"an owner label that is not base32hex": func(r *dns.NSEC3) {
			r.Hdr.Name = "wt7b4g4vsa5smi47k61mv5bv1a22bojr.example."
		},
		"a next hash that is too short":   func(r *dns.NSEC3) { r.NextDomain = "2vptu5timamqttgl4luu9kg21e0aor3" },
		"owned in another zone":           func(r *dns.NSEC3) { r.Hdr.Name = "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.org." },
		"owned two labels below the zone": func(r *dns.NSEC3) { r.Hdr.Name = "2t7b4g4vsa5smi47k61mv5bv1a22bojr.sub.example." },
	} {
		rr := rfcNSEC3(t, "2t7b", 0)
		edit(rr)
		p := newNSEC3Proof("example.", []*dns.NSEC3{rr}, 150)
		if len(p.records) != 0 {
			t.Errorf("%s: the record counts", name)
		}
		if got := p.noData("ns1.example.", dns.TypeMX); got != nsec3Unproven {
			t.Errorf("%s: %s, want unproven", name, nsec3VerdictToString[got])
		}
	}
	// The same record, unaltered, counts.
	if got := newNSEC3Proof("example.", []*dns.NSEC3{rfcNSEC3(t, "2t7b", 0)}, 150).noData("ns1.example.", dns.TypeMX); got != nsec3Proven {
		t.Errorf("B.2 unaltered: %s, want proven", nsec3VerdictToString[got])
	}
}

// A record covers the hashes strictly between its owner and its next hashed
// owner. The owner exists, so it is never covered; the last record of the
// chain wraps around; a chain of one record covers every hash but its own.
func TestNSEC3Covers(t *testing.T) {
	b := func(v byte) []byte { return append(bytes.Repeat([]byte{0}, nsec3HashLen-1), v) }
	for _, c := range []struct {
		name        string
		owner, next byte
		h           byte
		want        bool
	}{
		{"between", 10, 20, 15, true},
		{"the owner", 10, 20, 10, false},
		{"the next owner", 10, 20, 20, false},
		{"before the owner", 10, 20, 5, false},
		{"after the next owner", 10, 20, 25, false},
		{"last record, after the owner", 20, 10, 25, true},
		{"last record, before the next owner", 20, 10, 5, true},
		{"last record, between next and owner", 20, 10, 15, false},
		{"last record, the owner", 20, 10, 20, false},
		{"one record, another hash", 10, 10, 15, true},
		{"one record, its own hash", 10, 10, 10, false},
	} {
		if got := covers(&nsec3Record{owner: b(c.owner), next: b(c.next)}, b(c.h)); got != c.want {
			t.Errorf("%s: covers %v, want %v", c.name, got, c.want)
		}
	}
}

// Hashes compare as octets: an owner label or next hash in lower, upper or
// mixed case is the same record.
func TestNSEC3HashCaseDoesNotMatter(t *testing.T) {
	for _, fold := range []func(string) string{strings.ToLower, strings.ToUpper,
		func(s string) string { return strings.ToUpper(s[:16]) + strings.ToLower(s[16:]) }} {
		var rrs []*dns.NSEC3
		for _, k := range []string{"0p9m", "b4um", "35mt"} {
			rr := rfcNSEC3(t, k, 0)
			labels := dns.SplitDomainName(rr.Hdr.Name)
			rr.Hdr.Name = fold(labels[0]) + ".example."
			rr.NextDomain = fold(rr.NextDomain)
			rrs = append(rrs, rr)
		}
		if got := newNSEC3Proof("example.", rrs, 150).nameError("a.c.x.w.example."); got != nsec3Proven {
			t.Errorf("owner %s: %s, want proven", rrs[0].Hdr.Name, nsec3VerdictToString[got])
		}
	}
}

// RFC 9276: records over the iteration limit are set aside. A proof the
// others make stands; one they do not make is Insecure (over the limit), not
// Bogus.
func TestNSEC3IterationLimit(t *testing.T) {
	b2 := func() []*dns.NSEC3 { return rfcRecords(t, 0, "2t7b") } // 12 iterations
	for _, c := range []struct {
		name  string
		limit uint16
		rrs   []*dns.NSEC3
		want  nsec3Verdict
	}{
		{"at the limit", 12, b2(), nsec3Proven},
		{"above the limit", 11, b2(), nsec3OverLimit},
		{"a limit of 0", 0, b2(), nsec3OverLimit},
		{"another record above the limit", 12,
			append(b2(), synthNSEC3("example.", "ns1.example.", true, 0, 500, "")), nsec3Proven},
		{"the proof above the limit, a stray record within it", 12,
			[]*dns.NSEC3{synthNSEC3("example.", "ns1.example.", false, 0, 500, "", dns.TypeA), rfcNSEC3(t, "t644", 0)}, nsec3OverLimit},
		{"nothing above the limit, nothing proven", 12, rfcRecords(t, 0, "t644"), nsec3Unproven},
	} {
		if got := newNSEC3Proof("example.", c.rrs, c.limit).noData("ns1.example.", dns.TypeMX); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, nsec3VerdictToString[got], nsec3VerdictToString[c.want])
		}
	}
}

// Each record is hashed with its own parameters, so a proof may be made of
// records from two parameter sets. A name one set matches exists, whatever
// another set covers.
func TestNSEC3ParameterSets(t *testing.T) {
	// B.1 with the wildcard cover from a chain with no salt and 3 iterations.
	rrs := append(rfcRecords(t, 0, "0p9m", "b4um"), synthNSEC3("example.", "*.x.w.example.", true, 0, 3, ""))
	p := newNSEC3Proof("example.", rrs, 150)
	if got := p.nameError("a.c.x.w.example."); got != nsec3Proven {
		t.Errorf("proof from two parameter sets: %s, want proven", nsec3VerdictToString[got])
	}
	// The qname matched in the second set: it exists.
	rrs = append(rfcRecords(t, 0, "0p9m", "b4um", "35mt"), synthNSEC3("example.", "a.c.x.w.example.", false, 0, 3, "", dns.TypeA))
	if got := newNSEC3Proof("example.", rrs, 150).nameError("a.c.x.w.example."); got != nsec3Unproven {
		t.Errorf("qname matched in the other set: %s, want unproven", nsec3VerdictToString[got])
	}
	// The next closer name, c.x.w, covered by a record of each set, and only
	// the second set's has Opt-Out: the proof is made through Opt-Out, whichever
	// record comes first.
	optOutNC := synthNSEC3("example.", "c.x.w.example.", true, 1, 3, "")
	for _, rrs := range [][]*dns.NSEC3{
		append(rfcRecords(t, 0, "0p9m", "b4um", "35mt"), optOutNC),
		append([]*dns.NSEC3{optOutNC}, rfcRecords(t, 0, "0p9m", "b4um", "35mt")...),
	} {
		if got := newNSEC3Proof("example.", rrs, 150).nameError("a.c.x.w.example."); got != nsec3OptOut {
			t.Errorf("NC covered by two sets, one with Opt-Out: %s, want %s",
				nsec3VerdictToString[got], nsec3VerdictToString[nsec3OptOut])
		}
	}
}

// Each name is hashed once per parameter set and proof, and a proof stops at
// nsec3HashBudget hashes: one that needs more is not judged.
func TestNSEC3HashMemoAndBudget(t *testing.T) {
	p := newNSEC3Proof("example.", rfcRecords(t, 0, "0p9m", "b4um", "35mt"), 150)
	if got := p.nameError("a.c.x.w.example."); got != nsec3Proven {
		t.Fatalf("B.1: %s, want proven", nsec3VerdictToString[got])
	}
	// a.c.x.w, c.x.w, x.w and *.x.w: four names, one parameter set, although
	// every record is compared with each and c.x.w is looked up twice.
	if p.hashes != 4 {
		t.Errorf("B.1 hashed %d times, want 4", p.hashes)
	}

	// A qname 120 labels below the apex, whose closest encloser is the apex.
	deep := strings.Repeat("a.", 120) + "example."
	nc := "a.example."
	proof := func(sets int) *nsec3Proof {
		var rrs []*dns.NSEC3
		for i := 0; i < sets; i++ {
			salt := strings.Repeat("0", 2*i)
			rrs = append(rrs,
				synthNSEC3("example.", "example.", false, 0, 0, salt, dns.TypeNS, dns.TypeSOA),
				synthNSEC3("example.", nc, true, 0, 0, salt),
				synthNSEC3("example.", "*.example.", true, 0, 0, salt))
		}
		return newNSEC3Proof("example.", rrs, 150)
	}
	if got := proof(1).nameError(deep); got != nsec3Proven {
		t.Errorf("one parameter set: %s, want proven", nsec3VerdictToString[got])
	}
	if got := proof(3).nameError(deep); got != nsec3OverBudget {
		t.Errorf("three parameter sets: %s, want over the budget", nsec3VerdictToString[got])
	}
	if got := nsec3OverBudget.state(); got != ValidationStateIndeterminate {
		t.Errorf("over the budget is %s, want indeterminate", ValidationStateToString[got])
	}
}

// What each verdict makes of the data it is about.
func TestNSEC3VerdictStates(t *testing.T) {
	for v, want := range map[nsec3Verdict]ValidationState{
		nsec3Proven:             ValidationStateSecure,
		nsec3OptOut:             ValidationStateInsecure,
		nsec3InsecureDelegation: ValidationStateInsecure,
		nsec3OverLimit:          ValidationStateInsecure,
		nsec3OverBudget:         ValidationStateIndeterminate,
		nsec3Unproven:           ValidationStateBogus,
	} {
		if got := v.state(); got != want {
			t.Errorf("%s: %s, want %s", nsec3VerdictToString[v], ValidationStateToString[got], ValidationStateToString[want])
		}
	}
}

// benchNameError proves B.1's shape at iterations: a closest encloser, a next
// closer cover and a wildcard cover, a fresh proof each time.
func benchNameError(b *testing.B, iterations uint16) {
	const qname = "a.c.x.w.example."
	rrs := []*dns.NSEC3{
		synthNSEC3("example.", "x.w.example.", false, 0, iterations, "aabbccdd", dns.TypeMX),
		synthNSEC3("example.", "c.x.w.example.", true, 0, iterations, "aabbccdd"),
		synthNSEC3("example.", "*.x.w.example.", true, 0, iterations, "aabbccdd"),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if v := newNSEC3Proof("example.", rrs, 150).nameError(qname); v != nsec3Proven {
			b.Fatalf("%s", nsec3VerdictToString[v])
		}
	}
}

func BenchmarkNSEC3NameError0(b *testing.B)   { benchNameError(b, 0) }
func BenchmarkNSEC3NameError12(b *testing.B)  { benchNameError(b, 12) }
func BenchmarkNSEC3NameError150(b *testing.B) { benchNameError(b, 150) }
