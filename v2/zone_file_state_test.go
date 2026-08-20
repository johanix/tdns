/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestZoneFileStateRoundTrip: what is recorded comes back.
func TestZoneFileStateRoundTrip(t *testing.T) {
	kdb := newTestKeyDB(t)

	if _, have, err := kdb.GetZoneFileState("example."); err != nil {
		t.Fatalf("GetZoneFileState on an empty table: %v", err)
	} else if have {
		t.Fatal("an empty table reported a recorded identity")
	}

	if err := kdb.SetZoneFileState("example.", 7, "abc123"); err != nil {
		t.Fatalf("SetZoneFileState: %v", err)
	}
	id, have, err := kdb.GetZoneFileState("example.")
	if err != nil || !have {
		t.Fatalf("GetZoneFileState: %v (have=%v)", err, have)
	}
	if id.Serial != 7 || id.Digest != "abc123" {
		t.Fatalf("got serial %d digest %q, want 7/abc123", id.Serial, id.Digest)
	}

	// One row per zone: recording again replaces rather than accumulates.
	if err := kdb.SetZoneFileState("example.", 8, "def456"); err != nil {
		t.Fatalf("second SetZoneFileState: %v", err)
	}
	id, _, err = kdb.GetZoneFileState("example.")
	if err != nil {
		t.Fatalf("GetZoneFileState: %v", err)
	}
	if id.Serial != 8 || id.Digest != "def456" {
		t.Fatalf("upsert did not replace: serial %d digest %q", id.Serial, id.Digest)
	}
}

// TestZoneFileDigestIgnoresFormatting is the entire reason this is a ZONEMD
// digest and not a hash of the file. Reordering records, adding comments,
// changing whitespace and changing case in owner names must all leave the
// verdict at "unchanged" -- none of them change the zone.
func TestZoneFileDigestIgnoresFormatting(t *testing.T) {
	const plain = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
mail.example.	3600	IN	MX	10 mx.example.
`
	// Same zone: records reordered, comments added, whitespace changed, owner
	// names in mixed case, TTLs written differently.
	const reformatted = `; this zone has been through an editor
example.  3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200

MAIL.example.	3600	IN	MX	10 MX.EXAMPLE.

; a comment about the web server
WWW.Example.     3600     IN     A     192.0.2.1
example.	3600	IN	NS	NS.example.
`
	a, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", plain),
		ZonemdSchemeSimple, zoneFileStateAlg)
	if err != nil {
		t.Fatalf("digest of the plain zone: %v", err)
	}
	b, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", reformatted),
		ZonemdSchemeSimple, zoneFileStateAlg)
	if err != nil {
		t.Fatalf("digest of the reformatted zone: %v", err)
	}
	if a != b {
		t.Fatalf("reformatting changed the digest:\n plain: %s\n after: %s", a, b)
	}
}

// TestZoneFileDigestCatchesRealChange: the other half. A digest that ignored
// formatting by ignoring too much would pass the test above and be useless.
func TestZoneFileDigestCatchesRealChange(t *testing.T) {
	const before = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
`
	// Same serial, one address changed. This is the case a serial comparison
	// misses entirely -- a regenerated file that reused its serial.
	const after = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.99
`
	a, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", before),
		ZonemdSchemeSimple, zoneFileStateAlg)
	if err != nil {
		t.Fatalf("digest of the zone before the change: %v", err)
	}
	b, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", after),
		ZonemdSchemeSimple, zoneFileStateAlg)
	if err != nil {
		t.Fatalf("digest of the zone after the change: %v", err)
	}
	if a == b {
		t.Fatal("a changed A record did not change the digest")
	}
}

// TestZoneFileDigestNoticesATTLChange. A TTL is zone content: ZONEMD covers it,
// and an operator who edits one has changed what resolvers cache.
func TestZoneFileDigestNoticesATTLChange(t *testing.T) {
	const before = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
`
	const after = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	60	IN	A	192.0.2.1
`
	a, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", before),
		ZonemdSchemeSimple, zoneFileStateAlg)
	if err != nil {
		t.Fatalf("digest of the zone before the TTL change: %v", err)
	}
	b, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", after),
		ZonemdSchemeSimple, zoneFileStateAlg)
	if err != nil {
		t.Fatalf("digest of the zone after the TTL change: %v", err)
	}
	if a == b {
		t.Fatal("a changed TTL did not change the digest")
	}
}

// TestCompareZoneFileStateVerdicts walks the three outcomes.
func TestCompareZoneFileStateVerdicts(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testZone(t, "example.", deltaZone)
	registerZones(t, zd)
	zd.KeyDB = kdb

	// The parse hook should have fingerprinted the zone.
	zd.mu.Lock()
	digest := zd.fileDigest
	zd.mu.Unlock()
	if digest == "" {
		t.Fatal("parsing a zone recorded no file digest")
	}

	// Nothing recorded yet: unknown, not changed. This is the upgrade case, and
	// calling it "changed" would be a fleet-wide false alarm.
	v, _, err := zd.CompareZoneFileState()
	if err != nil {
		t.Fatalf("CompareZoneFileState: %v", err)
	}
	if v != ZoneFileUnknown {
		t.Fatalf("verdict with no recorded state = %v, want unknown", v)
	}

	if err := zd.RecordZoneFileState(zd.fileSerial, digest); err != nil {
		t.Fatalf("RecordZoneFileState: %v", err)
	}
	if v, _, err = zd.CompareZoneFileState(); err != nil {
		t.Fatalf("CompareZoneFileState: %v", err)
	} else if v != ZoneFileUnchanged {
		t.Fatalf("verdict against its own record = %v, want unchanged", v)
	}

	// Someone replaced the file.
	zd.mu.Lock()
	zd.fileDigest = strings.Repeat("00", 48)
	zd.mu.Unlock()
	if v, _, err = zd.CompareZoneFileState(); err != nil {
		t.Fatalf("CompareZoneFileState: %v", err)
	} else if v != ZoneFileChanged {
		t.Fatalf("verdict after a content change = %v, want changed", v)
	}
}

// TestZoneDigestExcludesOutOfZoneNames guards the bug RFC 8976's A.2 vector
// caught: a zone file can carry an absolute name from another zone, and
// including it would make the digest depend on records the zone does not own.
func TestZoneDigestExcludesOutOfZoneNames(t *testing.T) {
	const clean = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
`
	const withStray = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
foo.elsewhere.	3600	IN	TXT	"not mine"
`
	a, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", clean),
		ZonemdSchemeSimple, zoneFileStateAlg)
	if err != nil {
		t.Fatalf("digest of the clean zone: %v", err)
	}
	b, err := ZoneDigestHex("example.", parseZoneRRs(t, "example.", withStray),
		ZonemdSchemeSimple, zoneFileStateAlg)
	if err != nil {
		t.Fatalf("digest of the zone with a stray record: %v", err)
	}
	if a != b {
		t.Fatal("an out-of-zone record changed the digest; it must be excluded")
	}
}

// TestCanonicalOwnerLess pins the ordering rule a lexicographic sort gets
// wrong. RFC 4034 §6.1 compares labels from the RIGHT.
func TestCanonicalOwnerLess(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		// z.example. before a.b.example.: the rightmost differing label decides,
		// and "z" loses to "b" one level in. A string sort says the opposite.
		{"z.example.", "a.b.example.", false},
		{"a.b.example.", "z.example.", true},
		// A name sorts before its own subdomains.
		{"example.", "a.example.", true},
		// Case is irrelevant.
		{"A.example.", "b.example.", true},
		{"b.example.", "A.example.", false},
	} {
		if got := canonicalOwnerLess(tc.a, tc.b); got != tc.want {
			t.Errorf("canonicalOwnerLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestZoneDigestSurvivesAWriteReadRoundTrip pins the contract that file-change
// detection rests on: what WriteFileWithSerial serialises and what the parser
// digests on the way back in must cover the same records.
//
// If the two ever diverge -- one of them including a record class the other
// skips, say -- then every load after a perfectly ordinary write-out digests
// something different from what was recorded, reports ZoneFileChanged for a file
// nobody touched, and sends the zone through the whole merge path: serial
// lifted, possibly a .rejected artefact, and a ConfigWarning raised. That is an
// expensive way to find out about a traversal change, so it is worth a test.
func TestZoneDigestSurvivesAWriteReadRoundTrip(t *testing.T) {
	const zone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 3 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	192.0.2.53
www.example.	3600	IN	A	192.0.2.1
www.example.	3600	IN	A	192.0.2.2
txt.example.	3600	IN	TXT	"a string with spaces"
mx.example.	3600	IN	MX	10 Mail.Example.
`
	zd := testZone(t, "example.", zone)

	published, err := zd.ZoneDigestOfPublished()
	if err != nil {
		t.Fatalf("digest of the published snapshot: %v", err)
	}

	path := filepath.Join(t.TempDir(), "example.zone")
	if _, _, err := zd.WriteFileWithSerial(path); err != nil {
		t.Fatalf("WriteFileWithSerial: %v", err)
	}

	// A fresh zone, as a restart would build it, reading the file just written.
	reread := &ZoneData{
		ZoneName:  "example.",
		ZoneStore: MapZone,
		Logger:    log.New(os.Stderr, "", 0),
	}
	if _, _, rerr := reread.ReadZoneFile(path, true); rerr != nil {
		t.Fatalf("ReadZoneFile: %v", rerr)
	}
	back, err := reread.zoneDigestOfWorkingData()
	if err != nil {
		t.Fatalf("digest of the re-read file: %v", err)
	}

	if published != back {
		t.Fatalf("a write/read round trip changed the digest:\n  published %s\n  re-read   %s\n"+
			"every load after a write-out would report the file as CHANGED", published, back)
	}
}
