package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// writeZoneToTemp serialises the published zone the way WriteFileWithSerial
// would and returns the file's contents.
func writeZoneToTemp(t *testing.T, zd *ZoneData) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.zone")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	if _, err := zd.WriteZoneToFile(f); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

const propZone = `prop.example.	300	IN	SOA	ns.prop.example. hostmaster.prop.example. 1 1800 900 604800 300
prop.example.	300	IN	NS	ns.prop.example.
ns.prop.example.	300	IN	A	127.0.0.1
alpha.prop.example.	300	IN	A	10.0.0.1
`

// A zone file carrying NSEC records must round-trip: the parser routes them to
// the owner property, and everything downstream reads them from there. A file
// written by another signer is the case that matters -- a secondary loading
// from disk has no key and cannot rebuild what it drops.
func TestParserRoutesNsecToTheProperty(t *testing.T) {
	signed := propZone +
		"prop.example.	300	IN	NSEC	alpha.prop.example. NS SOA RRSIG NSEC\n" +
		"alpha.prop.example.	300	IN	NSEC	ns.prop.example. A RRSIG NSEC\n"

	zd := testZone(t, "prop.example.", signed)

	apex, ok := zd.Data.Get("prop.example.")
	if !ok {
		t.Fatal("no apex after parse")
	}
	if len(apex.NSEC.RRs) != 1 {
		t.Fatalf("apex NSEC did not land in the property: %+v", apex.NSEC)
	}
	if _, isNsec := apex.NSEC.RRs[0].(*dns.NSEC); !isNsec {
		t.Fatalf("apex NSEC property holds a %T", apex.NSEC.RRs[0])
	}
	// ...and NOT in RRtypes, or the ghost and journal problems come straight back.
	if _, present := apex.RRtypes.Get(dns.TypeNSEC); present {
		t.Fatal("NSEC is still an RRtypes entry; the property model is not in effect")
	}

	alpha, _ := zd.Data.Get("alpha.prop.example.")
	if len(alpha.NSEC.RRs) != 1 {
		t.Fatalf("alpha NSEC did not land in the property: %+v", alpha.NSEC)
	}
}

// The RRSIG covering an NSEC follows it into the property rather than into
// RRtypes[NSEC], which no longer exists.
func TestParserRoutesNsecSignatureToTheProperty(t *testing.T) {
	signed := propZone +
		"prop.example.	300	IN	NSEC	alpha.prop.example. NS SOA RRSIG NSEC\n" +
		"prop.example.	300	IN	RRSIG	NSEC 15 2 300 20260901000000 20260801000000 1234 prop.example. abcdefgh\n"

	zd := testZone(t, "prop.example.", signed)
	apex, _ := zd.Data.Get("prop.example.")
	if len(apex.NSEC.RRSIGs) != 1 {
		t.Fatalf("the NSEC's RRSIG did not follow it into the property: %+v", apex.NSEC)
	}
	if _, present := apex.RRtypes.Get(dns.TypeNSEC); present {
		t.Fatal("an RRtypes[NSEC] entry was created for the signature")
	}
}

// The digest must cover the property. If it does not, the digest of a file
// just parsed and the digest of the zone about to be written disagree for
// identical content, and every load reports the file as CHANGED.
func TestDigestCoversTheNsecProperty(t *testing.T) {
	withNsec := propZone +
		"alpha.prop.example.	300	IN	NSEC	ns.prop.example. A RRSIG NSEC\n"

	bare := testZone(t, "prop.example.", propZone)
	signed := testZone(t, "prop.example.", withNsec)

	d1, err := bare.zoneDigestOfWorkingData()
	if err != nil {
		t.Fatalf("digest of the bare zone: %v", err)
	}
	d2, err := signed.zoneDigestOfWorkingData()
	if err != nil {
		t.Fatalf("digest of the zone with an NSEC: %v", err)
	}
	if d1 == d2 {
		t.Fatal("adding an NSEC record did not change the digest;" +
			" the property is invisible to it, so a written file and a parsed file" +
			" will never agree and every load will report the file as CHANGED")
	}
}

// The writer must emit the property, or a secondary loading the file from disk
// gets a signed zone with no chain.
func TestZoneFileWriterEmitsTheNsecProperty(t *testing.T) {
	withNsec := propZone +
		"alpha.prop.example.	300	IN	NSEC	ns.prop.example. A RRSIG NSEC\n"
	zd := testZone(t, "prop.example.", withNsec)
	registerZones(t, zd)
	zd.InstallInitialSnapshot()

	f, err := writeZoneToTemp(t, zd)
	if err != nil {
		t.Fatalf("writing the zone: %v", err)
	}
	if !strings.Contains(f, "NSEC") {
		t.Fatalf("the written zone file carries no NSEC records:\n%s", f)
	}
	if !strings.Contains(f, "alpha.prop.example.") {
		t.Fatalf("the written zone file lost alpha:\n%s", f)
	}
}

// An NSEC at a wildcard owner describes that owner. It must not be expanded to
// a queried name the way an address record is: doing so invents a record
// asserting what exists either side of a name that has no NSEC at all.
func TestNsecIsNotWildcardExpanded(t *testing.T) {
	od := &OwnerData{Name: "*.prop.example.", RRtypes: NewRRTypeStore()}
	rr, err := dns.NewRR("*.prop.example. 300 IN NSEC ns.prop.example. A RRSIG NSEC")
	if err != nil {
		t.Fatal(err)
	}
	od.NSEC = core.RRset{Name: "*.prop.example.", RRtype: dns.TypeNSEC, RRs: []dns.RR{rr}}

	// Queried directly at the wildcard owner: answered.
	if _, ok := ownerRRsetForQuery(od, dns.TypeNSEC, false); !ok {
		t.Error("an NSEC queried at its own (wildcard) owner was not answered")
	}
	// Reached by wildcard expansion for some other name: not answered, so the
	// ordinary wildcard-NODATA path handles it.
	if _, ok := ownerRRsetForQuery(od, dns.TypeNSEC, true); ok {
		t.Error("the wildcard's NSEC was expanded to a queried name")
	}
	// Other types are still expanded as usual.
	arr, err := dns.NewRR("*.prop.example. 300 IN A 10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	od.RRtypes.Set(dns.TypeA, core.RRset{Name: "*.prop.example.", RRtype: dns.TypeA, RRs: []dns.RR{arr}})
	if _, ok := ownerRRsetForQuery(od, dns.TypeA, true); !ok {
		t.Error("a wildcard A record is no longer expanded")
	}
}
