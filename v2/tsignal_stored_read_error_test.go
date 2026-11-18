package tdns

import (
	"slices"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A record of what the pass stored that cannot be read is not "no record"
// (CodeRabbit on #1118). Taken for "no record", it made the pass's own
// signal the operator's after a restart: the pass then forgot the record,
// for good, and later configurations no longer applied to the name. The
// read fails here the way a failed migration makes it fail: the column the
// read selects is missing.

const readErrZoneBody = `	3600	IN	NS	ns1.%[1]s
ns1.%[1]s	3600	IN	A	127.0.0.1
`

// storeThenRestart runs the pass once with signal, as one process, and
// returns a second process's zone loaded with what the first stored, both
// on kdb.
func storeThenRestart(t *testing.T, z string, kdb *KeyDB, signal string) (*ZoneData, *Config) {
	t.Helper()
	body := z + strings.ReplaceAll(readErrZoneBody, "%[1]s", z)
	zd, conf := signalTestZone(t, z, body, "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = signal
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, rr := range svcbRecords(zd, "_dns.ns1."+z) {
		lines = append(lines, rr.String())
	}
	if len(lines) != 1 {
		t.Fatalf("the pass stored %v", lines)
	}
	zd2, conf2 := signalTestZone(t, z, body+strings.Join(lines, "\n")+"\n", "127.0.0.1:53")
	zd2.KeyDB = kdb
	conf2.Service.Identities = []string{"ns1." + z}
	conf2.Service.Transport.Signal = signal
	return zd2, conf2
}

// breakSignalRecordReads makes GetTransportSignalStored fail, and returns
// the function that mends it. Listing the owners and deleting a record
// still work, so a delete that should not happen would show.
func breakSignalRecordReads(t *testing.T, kdb *KeyDB) func() {
	t.Helper()
	if _, err := kdb.DB.Exec(`ALTER TABLE TransportSignalStored RENAME COLUMN earlier TO earlier_gone`); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if _, err := kdb.DB.Exec(`ALTER TABLE TransportSignalStored RENAME COLUMN earlier_gone TO earlier`); err != nil {
			t.Fatal(err)
		}
	}
}

// signalRecordRows counts the records of owner in zone without the read
// that breakSignalRecordReads breaks.
func signalRecordRows(t *testing.T, kdb *KeyDB, z, owner string) int {
	t.Helper()
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM TransportSignalStored WHERE zone=? AND owner=?`, z, owner).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The synthesis pass after a restart: with the record unreadable, the
// pass's own signal is neither taken for the operator's (and its record
// forgotten) nor replaced. Once the record reads again, the pass knows the
// signal for its own and applies the changed configuration.
func TestAnUnreadableRecordDoesNotMakeThePassSignalTheOperators(t *testing.T) {
	const z = "readerr.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	zd, conf := storeThenRestart(t, z, kdb, "dot:50")
	conf.Service.Transport.Signal = "dot:20"

	mend := breakSignalRecordReads(t, kdb)
	logs := captureSignalLog(t)
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "leaving the operator's") {
		t.Fatalf("an unreadable record made the pass's signal the operator's:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "could not read the record of what the pass stored") {
		t.Fatalf("no warning for the unreadable record:\n%s", logs.String())
	}
	if n := signalRecordRows(t, kdb, z, owner); n != 1 {
		t.Fatalf("the record was dropped on a failed read (%d rows)", n)
	}
	if got := svcbRecords(zd, owner); len(got) != 1 || !strings.Contains(got[0].String(), "dot:50") {
		t.Fatalf("the signal at the owner changed while its record could not be read: %v", got)
	}

	mend()
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd, owner); len(got) != 1 || !strings.Contains(got[0].String(), "dot:20") {
		t.Fatalf("once the record read again, the pass did not replace its own signal: %v", got)
	}
}

// The withdrawal after a restart: the name is no longer an identity, and
// the record cannot be read. The signal is not withdrawn and the record is
// not forgotten; once it reads again, the pass withdraws its signal.
func TestAnUnreadableRecordDoesNotWithdrawOrForget(t *testing.T) {
	const z = "readerrw.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	zd, conf := storeThenRestart(t, z, kdb, "dot:50")
	conf.Service.Transport.Type = "none"

	mend := breakSignalRecordReads(t, kdb)
	logs := captureSignalLog(t)
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "could not read the record of what the pass stored") {
		t.Fatalf("no warning for the unreadable record:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "withdrew the signal") {
		t.Fatalf("the pass withdrew a signal it could not tell for its own:\n%s", logs.String())
	}
	if n := signalRecordRows(t, kdb, z, owner); n != 1 {
		t.Fatalf("the record was dropped on a failed read (%d rows)", n)
	}
	if got := svcbRecords(zd, owner); len(got) != 1 {
		t.Fatalf("the signal at the owner changed while its record could not be read: %v", got)
	}

	mend()
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if getOwnerFrom(zd.publishedSnapshot(), owner) != nil {
		t.Fatalf("once the record read again, the pass did not withdraw its signal: %v", svcbRecords(zd, owner))
	}
}

// A refresh while the record cannot be read: the pass's signal, which is in
// no zone file or transfer, is carried over as the pass's own would be, so
// the served zone keeps it. Not carrying it, as for an operator's RRset,
// took it out of the zone for as long as the record stayed unreadable.
func TestARefreshCarriesThePassSignalWhileTheRecordCannotBeRead(t *testing.T) {
	const z = "readerrc.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	zd, conf := storeThenRestart(t, z, kdb, "dot:50")

	breakSignalRecordReads(t, kdb)
	logs := captureSignalLog(t)
	if err := zd.CreateTransportSignalRRs(conf); err != nil { // leaves the owner as it is
		t.Fatal(err)
	}
	carried := false
	for _, rs := range zd.CollectDynamicRRs(conf) {
		if rs.RRtype == dns.TypeSVCB && core.EqualNames(rs.Name, owner) {
			carried = len(rs.RRs) == 1 && strings.Contains(rs.RRs[0].String(), "dot:50")
		}
	}
	if !carried {
		t.Fatalf("the pass's signal is not carried over a refresh while its record cannot be read:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "carried over the refresh") {
		t.Fatalf("no warning for the carry:\n%s", logs.String())
	}
}

// A digest put ahead of the record by a writer that could not read it keeps
// the digests the record holds; the same digest again changes nothing, and
// an owner with no record gets one.
func TestPrependTransportSignalStoredKeepsTheEarlierDigests(t *testing.T) {
	const z = "prepend.sig.example."
	kdb := newTestKeyDB(t)
	read := func(owner string) []string {
		t.Helper()
		d, _, err := kdb.GetTransportSignalStored(z, owner)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if err := kdb.SetTransportSignalStored(z, "_dns.a."+z, []string{"b", "a"}); err != nil {
		t.Fatal(err)
	}
	if err := kdb.PrependTransportSignalStored(z, "_dns.a."+z, "c"); err != nil {
		t.Fatal(err)
	}
	if got := read("_dns.a." + z); !slices.Equal(got, []string{"c", "b", "a"}) {
		t.Errorf("after prepending c to [b a]: %v", got)
	}
	if err := kdb.PrependTransportSignalStored(z, "_dns.a."+z, "c"); err != nil {
		t.Fatal(err)
	}
	if got := read("_dns.a." + z); !slices.Equal(got, []string{"c", "b", "a"}) {
		t.Errorf("after prepending the last digest again: %v", got)
	}
	if err := kdb.PrependTransportSignalStored(z, "_dns.b."+z, "x"); err != nil {
		t.Fatal(err)
	}
	if got := read("_dns.b." + z); !slices.Equal(got, []string{"x"}) {
		t.Errorf("an owner with no record: %v", got)
	}
}

// A record of the pass's signal made while the earlier digests could not be
// read leaves nothing in memory, so the next record reads the KeyDB's and
// keeps its earlier digests. A record in memory holding the new digest alone
// was what the next store read and wrote back whole, dropping them. Here
// the failed read fails the prepend too; what is checked is what the second
// record finds.
func TestASecondRecordAfterAFailedReadKeepsTheEarlierDigests(t *testing.T) {
	const z = "noteagain.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	if err := kdb.SetTransportSignalStored(z, owner, []string{"b", "a"}); err != nil {
		t.Fatal(err)
	}
	zd := &ZoneData{ZoneName: z, KeyDB: kdb}
	rrs := mustRRs(t, owner+` 300 IN SVCB 1 . alpn=dot`)
	digest := signalDigest(rrs)

	mend := breakSignalRecordReads(t, kdb)
	captureSignalLog(t)
	zd.noteSignalStored(owner, rrs)
	mend()
	zd.noteSignalStored(owner, rrs)

	got, _, err := kdb.GetTransportSignalStored(z, owner)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{digest, "b", "a"}; !slices.Equal(got, want) {
		t.Errorf("after a record with the read broken and one after it: %v, want %v", got, want)
	}
}
