package tdns

import (
	"context"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// T1: the invariant checker. One deliberate violation per invariant, and a
// clean zone that reports nothing.

// stageApexRRset publishes rs at the zone apex, RRSIGs included.
func stageApexRRset(t *testing.T, zd *ZoneData, rrtype uint16, rrs, sigs []dns.RR) {
	t.Helper()
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked(zd.ZoneName, core.RRset{
		Name: zd.ZoneName, RRtype: rrtype, Class: dns.ClassINET, RRs: rrs, RRSIGs: sigs,
	})
	zd.publishLocked(zd.generation.Load())
}

func parseRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return rr
}

func rrsigBy(zone string, covered uint16, keytag uint16) dns.RR {
	return rrsigByAlg(zone, covered, keytag, dns.ED25519)
}

func rrsigByAlg(zone string, covered uint16, keytag uint16, alg uint8) dns.RR {
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: covered, Algorithm: alg, KeyTag: keytag, SignerName: zone,
	}
}

// checkerZone is a loaded zone whose served DNSKEY RRset is exactly the
// keystore's pub=1 rows and whose DNSKEY and SOA RRsets are signed by the
// sign=1 keys: the clean case every violation below is a one-step departure
// from.
type checkerZone struct {
	kdb  *KeyDB
	zd   *ZoneData
	rows map[string]KeyRow // by "state role"
}

func newCheckerZone(t *testing.T) *checkerZone {
	t.Helper()
	const zone = "example."
	kdb := newTestKeyDB(t)
	zd := testZone(t, zone, csyncTestZone)
	zd.KeyDB = kdb
	registerZones(t, zd)
	rng := newTestRand(9)
	c := &checkerZone{kdb: kdb, zd: zd, rows: map[string]KeyRow{}}
	for _, sr := range [][2]string{
		{DnskeyStateActive, "KSK"}, {DnskeyStateActive, "ZSK"},
		{DnskeyStateStandby, "ZSK"}, {DnskeyStateRetired, "ZSK"}, {DnskeyStateCreated, "KSK"},
	} {
		row := testKeyRow(zone, sr[0], sr[1], rng)
		c.insertRow(t, row)
		c.rows[sr[0]+" "+sr[1]] = row
	}
	c.serveFromRows(t)
	return c
}

func (c *checkerZone) row(state, role string) KeyRow { return c.rows[state+" "+role] }

func (c *checkerZone) insertRow(t *testing.T, row KeyRow) {
	t.Helper()
	tx, err := c.kdb.Begin("checker")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := insertKeyRowTx(tx, row); err != nil {
		tx.Rollback()
		t.Fatalf("insert %s %d: %v", row.State, row.Keyid, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// serveFromRows stages the DNSKEY RRset from the pub=1 rows, signed by the
// active KSK, and signs the SOA with the active ZSK.
func (c *checkerZone) serveFromRows(t *testing.T) {
	t.Helper()
	var dnskeys []dns.RR
	for _, state := range []string{DnskeyStateActive, DnskeyStateStandby, DnskeyStateRetired} {
		for _, role := range []string{"KSK", "ZSK"} {
			if r, ok := c.rows[state+" "+role]; ok {
				dnskeys = append(dnskeys, parseRR(t, r.KeyRR))
			}
		}
	}
	ksk, zsk := c.row(DnskeyStateActive, "KSK"), c.row(DnskeyStateActive, "ZSK")
	stageApexRRset(t, c.zd, dns.TypeDNSKEY, dnskeys, []dns.RR{rrsigBy(c.zd.ZoneName, dns.TypeDNSKEY, ksk.Keyid)})
	soa, err := c.zd.RRsetForAnalysis(c.zd.ZoneName, dns.TypeSOA)
	if err != nil || soa == nil {
		t.Fatalf("no SOA: %v", err)
	}
	stageApexRRset(t, c.zd, dns.TypeSOA, soa.RRs, []dns.RR{rrsigBy(c.zd.ZoneName, dns.TypeSOA, zsk.Keyid)})
}

func (c *checkerZone) rawExec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := c.kdb.DB.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func expectOnly(t *testing.T, vs []KeyInvariantViolation, invariant string) {
	t.Helper()
	by := violationsByInvariant(vs)
	if len(by[invariant]) == 0 {
		t.Errorf("%s not reported; got: %s", invariant, violationList(vs))
	}
	for inv := range by {
		if inv != invariant {
			t.Errorf("%s reported beside %s: %s", inv, invariant, violationList(by[inv]))
		}
	}
}

func TestCheckerReportsNothingForACleanZone(t *testing.T) {
	c := newCheckerZone(t)
	if vs := CheckKeyInvariants(c.kdb, c.zd); len(vs) != 0 {
		t.Errorf("clean zone: %s", violationList(vs))
	}
}

func TestCheckerI1SignImpliesPub(t *testing.T) {
	c := newCheckerZone(t)
	r := c.row(DnskeyStateActive, "ZSK")
	c.rawExec(t, `UPDATE DnssecKeyStore SET pub=0 WHERE zonename=? AND keyid=?`, r.Zone, r.Keyid)
	// The served RRset still carries a key the pub=1 rows lack (I5) and the
	// flags no longer match the table (I9); I1 is the one asked for here.
	by := violationsByInvariant(CheckKeyInvariants(c.kdb, c.zd))
	if len(by["I1"]) != 1 || by["I1"][0].KeyID != r.Keyid {
		t.Errorf("I1: %s", violationList(by["I1"]))
	}
}

func TestCheckerI2SignNeedsAPrivateKey(t *testing.T) {
	c := newCheckerZone(t)
	r := c.row(DnskeyStateActive, "ZSK")
	c.rawExec(t, `UPDATE DnssecKeyStore SET privatekey='' WHERE zonename=? AND keyid=?`, r.Zone, r.Keyid)
	expectOnly(t, CheckKeyInvariants(c.kdb, c.zd), "I2")
}

func TestCheckerI3DsOnlyOnSepKeys(t *testing.T) {
	c := newCheckerZone(t)
	r := c.row(DnskeyStateActive, "ZSK")
	c.rawExec(t, `UPDATE DnssecKeyStore SET ds=1 WHERE zonename=? AND keyid=?`, r.Zone, r.Keyid)
	expectOnly(t, CheckKeyInvariants(c.kdb, c.zd), "I3")
}

func TestCheckerI4OneSignerPerRoleAndAlgorithm(t *testing.T) {
	c := newCheckerZone(t)
	// A second active ZSK of the same algorithm, served and signing the SOA
	// beside the first: only I4 is broken by it.
	row := testKeyRow(c.zd.ZoneName, DnskeyStateActive, "ZSK", newTestRand(11))
	c.insertRow(t, row)
	c.rows["active ZSK2"] = row
	dk, _ := c.zd.RRsetForAnalysis(c.zd.ZoneName, dns.TypeDNSKEY)
	rrs := append(append([]dns.RR{}, dk.RRs...), parseRR(t, row.KeyRR))
	stageApexRRset(t, c.zd, dns.TypeDNSKEY, rrs, dk.RRSIGs)
	soa, _ := c.zd.RRsetForAnalysis(c.zd.ZoneName, dns.TypeSOA)
	sigs := append(append([]dns.RR{}, soa.RRSIGs...), rrsigBy(c.zd.ZoneName, dns.TypeSOA, row.Keyid))
	stageApexRRset(t, c.zd, dns.TypeSOA, soa.RRs, sigs)
	expectOnly(t, CheckKeyInvariants(c.kdb, c.zd), "I4")
}

func TestCheckerI4AllowsTwoSepSignersOfDifferentAlgorithms(t *testing.T) {
	c := newCheckerZone(t)
	row := testKeyRow(c.zd.ZoneName, DnskeyStateActive, "KSK", newTestRand(12))
	row.Algorithm = dns.AlgorithmToString[dns.ECDSAP256SHA256]
	rr := parseRR(t, row.KeyRR).(*dns.DNSKEY)
	rr.Algorithm = dns.ECDSAP256SHA256
	row.KeyRR = rr.String()
	row.Keyid = rr.KeyTag()
	c.insertRow(t, row)
	dk, _ := c.zd.RRsetForAnalysis(c.zd.ZoneName, dns.TypeDNSKEY)
	rrs := append(append([]dns.RR{}, dk.RRs...), rr)
	sigs := append(append([]dns.RR{}, dk.RRSIGs...), rrsigByAlg(c.zd.ZoneName, dns.TypeDNSKEY, row.Keyid, dns.ECDSAP256SHA256))
	stageApexRRset(t, c.zd, dns.TypeDNSKEY, rrs, sigs)
	if vs := CheckKeyInvariants(c.kdb, c.zd); len(vs) != 0 {
		t.Errorf("an algorithm rollover's two SEP signers were reported: %s", violationList(vs))
	}
}

func TestCheckerI5ServedDnskeysEqualPubRows(t *testing.T) {
	c := newCheckerZone(t)
	dk, _ := c.zd.RRsetForAnalysis(c.zd.ZoneName, dns.TypeDNSKEY)
	// Serve one DNSKEY fewer than the pub=1 rows.
	stageApexRRset(t, c.zd, dns.TypeDNSKEY, dk.RRs[:len(dk.RRs)-1], dk.RRSIGs)
	expectOnly(t, CheckKeyInvariants(c.kdb, c.zd), "I5")

	// And one more than the rows.
	extra := testDNSKEY(c.zd.ZoneName, "ZSK", newTestRand(13))
	stageApexRRset(t, c.zd, dns.TypeDNSKEY, append(append([]dns.RR{}, dk.RRs...), extra), dk.RRSIGs)
	expectOnly(t, CheckKeyInvariants(c.kdb, c.zd), "I5")
}

func TestCheckerI6SignaturesAreBySignKeys(t *testing.T) {
	c := newCheckerZone(t)
	retired := c.row(DnskeyStateRetired, "ZSK")
	soa, _ := c.zd.RRsetForAnalysis(c.zd.ZoneName, dns.TypeSOA)
	stageApexRRset(t, c.zd, dns.TypeSOA, soa.RRs, []dns.RR{rrsigBy(c.zd.ZoneName, dns.TypeSOA, retired.Keyid)})
	expectOnly(t, CheckKeyInvariants(c.kdb, c.zd), "I6")
}

func TestCheckerI6EverySignKeySignsSomething(t *testing.T) {
	c := newCheckerZone(t)
	// The active ZSK signs nothing: the SOA is signed by the KSK instead.
	ksk := c.row(DnskeyStateActive, "KSK")
	soa, _ := c.zd.RRsetForAnalysis(c.zd.ZoneName, dns.TypeSOA)
	stageApexRRset(t, c.zd, dns.TypeSOA, soa.RRs, []dns.RR{rrsigBy(c.zd.ZoneName, dns.TypeSOA, ksk.Keyid)})
	expectOnly(t, CheckKeyInvariants(c.kdb, c.zd), "I6")
}

func TestCheckerI7ServedCdsFollowsDsRows(t *testing.T) {
	c := newCheckerZone(t)
	// Every SEP row gets its ds set, so I7 applies: the created KSK has ds=0,
	// the active KSK ds=1.
	c.rawExec(t, `UPDATE DnssecKeyStore SET ds = CASE state WHEN 'active' THEN 1 ELSE 0 END WHERE zonename=? AND (flags & 1) = 1`, c.zd.ZoneName)
	if vs := CheckKeyInvariants(c.kdb, c.zd); len(vs) != 0 {
		t.Fatalf("with no CDS served and ds set: %s", violationList(vs))
	}
	created := parseRR(t, c.row(DnskeyStateCreated, "KSK").KeyRR).(*dns.DNSKEY)
	cds := &dns.CDS{DS: *created.ToDS(dns.SHA256)}
	cds.Hdr = dns.RR_Header{Name: c.zd.ZoneName, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 120}
	stageApexRRset(t, c.zd, dns.TypeCDS, []dns.RR{cds}, nil)
	expectOnly(t, CheckKeyInvariants(c.kdb, c.zd), "I7")

	// With one SEP row's ds unset, I7 no longer applies.
	c.rawExec(t, `UPDATE DnssecKeyStore SET ds=NULL WHERE zonename=? AND state='created'`, c.zd.ZoneName)
	if vs := CheckKeyInvariants(c.kdb, c.zd); len(vs) != 0 {
		t.Errorf("I7 applied with a ds unset: %s", violationList(vs))
	}
}

func TestCheckerI8NoRowWithoutFlags(t *testing.T) {
	c := newCheckerZone(t)
	keyid := insertRawTestKeyRow(t, c.kdb, c.zd.ZoneName, DnskeyStateRemoved, "ZSK", newTestRand(14))
	by := violationsByInvariant(CheckKeyInvariants(c.kdb, c.zd))
	if len(by["I8"]) != 1 || by["I8"][0].KeyID != keyid {
		t.Errorf("I8: %s", violationList(by["I8"]))
	}
}

func TestCheckerI9FlagsMatchTheTableForTheState(t *testing.T) {
	c := newCheckerZone(t)
	r := c.row(DnskeyStateStandby, "ZSK")
	c.rawExec(t, `UPDATE DnssecKeyStore SET sign=1 WHERE zonename=? AND keyid=?`, r.Zone, r.Keyid)
	// The standby key now claims to sign: I9 (standby has sign=0), I6 (a
	// sign=1 key that signed nothing) and I4 (two signing ZSKs of one
	// algorithm) all speak. I9 is the one asked for here.
	by := violationsByInvariant(CheckKeyInvariants(c.kdb, c.zd))
	if len(by["I9"]) != 1 || by["I9"][0].KeyID != r.Keyid {
		t.Errorf("I9: %s", violationList(by["I9"]))
	}
}

func TestCheckerRowsOnlyForAZoneThatIsNotLoaded(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "unloaded.example."
	rng := newTestRand(15)
	insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "KSK", rng)
	insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "ZSK", rng)
	if vs := CheckKeyRowInvariants(kdb, zone); len(vs) != 0 {
		t.Errorf("clean rows: %s", violationList(vs))
	}
	keyid := insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "ZSK", rng)
	by := violationsByInvariant(CheckKeyRowInvariants(kdb, zone))
	if len(by["I4"]) == 0 {
		t.Errorf("a second active ZSK (%d) was not reported: %s", keyid, violationList(CheckKeyRowInvariants(kdb, zone)))
	}
}

// The same checks behind the keystore API: "keystore dnssec check".
func TestKeystoreCheckCommandReportsViolations(t *testing.T) {
	c := newCheckerZone(t)
	r := c.row(DnskeyStateActive, "ZSK")
	c.rawExec(t, `UPDATE DnssecKeyStore SET privatekey='' WHERE zonename=? AND keyid=?`, r.Zone, r.Keyid)
	resp, err := c.kdb.DnssecKeyMgmt(context.Background(), nil, KeystorePost{Command: "dnssec-mgmt", SubCommand: "check", Zone: c.zd.ZoneName})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if resp.Error {
		t.Fatalf("check: %s", resp.ErrorMsg)
	}
	expectOnly(t, resp.KeyViolations, "I2")

	// No zone: every zone in the keystore.
	rng := newTestRand(16)
	insertTestKeyRow(t, c.kdb, "other.example.", DnskeyStateActive, "ZSK", rng)
	insertTestKeyRow(t, c.kdb, "other.example.", DnskeyStateActive, "ZSK", rng)
	resp, err = c.kdb.DnssecKeyMgmt(context.Background(), nil, KeystorePost{Command: "dnssec-mgmt", SubCommand: "check"})
	if err != nil {
		t.Fatalf("check all: %v", err)
	}
	by := violationsByInvariant(resp.KeyViolations)
	if len(by["I2"]) != 1 || len(by["I4"]) == 0 {
		t.Errorf("check all: %s", violationList(resp.KeyViolations))
	}
}
