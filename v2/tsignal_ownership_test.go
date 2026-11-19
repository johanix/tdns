package tdns

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// Stored-signal ownership and withdrawal (CodeRabbit on #1118, issue
// #1133): the record of what the pass stored must not be lost while the
// pass's signal is still what the zone serves or what a restart loads.

// A release for an owner the KeyDB alone knows (the pass has not touched it
// in this process), while the KeyDB cannot be read: an error, not "nothing to
// release" with the record left in place.
func TestAReleaseWhoseKeyDBCannotBeReadSaysSo(t *testing.T) {
	const z = "relerr.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	zd, _ := storeThenRestart(t, z, kdb, "dot:50")

	if _, err := kdb.DB.Exec(`ALTER TABLE TransportSignalStored RENAME TO TransportSignalStored_gone`); err != nil {
		t.Fatal(err)
	}
	released, err := zd.releaseSignal(owner)
	if err == nil {
		t.Fatalf("a release with the KeyDB unreadable: released=%v and no error, want an error", released)
	}
	if _, err := kdb.DB.Exec(`ALTER TABLE TransportSignalStored_gone RENAME TO TransportSignalStored`); err != nil {
		t.Fatal(err)
	}
	if n := signalRecordRows(t, kdb, z, owner); n != 1 {
		t.Fatalf("the failed release dropped the record (%d rows)", n)
	}

	released, err = zd.releaseSignal(owner)
	if err != nil || !released {
		t.Fatalf("the release run again: released=%v err=%v, want it released", released, err)
	}
	if n := signalRecordRows(t, kdb, z, owner); n != 0 {
		t.Fatalf("after the release the KeyDB still holds the record (%d rows)", n)
	}
}

// holdPublishes makes the publish cadence hold back what is staged from now
// on, with an unrelated change staged so that the working set is not bare.
func holdPublishes(t *testing.T, zd *ZoneData) {
	t.Helper()
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.publishCadence = time.Hour
	zd.lastPublish = time.Now()
	note := "note." + zd.ZoneName
	zd.stageRRsetLocked(note, core.RRset{Name: note, Class: dns.ClassINET, RRtype: dns.TypeTXT,
		RRs: mustRRs(t, note+`	3600	IN	TXT	"an unrelated change"`)})
}

// publishNow publishes what is staged, as the next publish would.
func publishNow(zd *ZoneData) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.publishLocked(zd.generation.Load())
}

// An operator's change at the owner, staged and held back by the publish
// cadence when the pass runs, while the published RRset is still the pass's.
// The pass leaves the owner alone and keeps its record: a stop before the
// change is published loses it, and a restart then loads the pass's signal,
// which must still read as the pass's. Once the change is published, the
// next run forgets the record.
func TestAnUnpublishedOperatorChangeDoesNotForgetThePassSignal(t *testing.T) {
	const z = "unpub.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	zd, conf := storeThenRestart(t, z, kdb, "dot:50")
	stored := svcbRecords(zd, owner)

	holdPublishes(t, zd)
	zd.mu.Lock()
	zd.stageRRsetLocked(owner, core.RRset{Name: owner, Class: dns.ClassINET, RRtype: dns.TypeSVCB,
		RRs: mustRRs(t, owner+`	300	IN	SVCB	1 . oots="doq:30"`)})
	zd.mu.Unlock()

	logs := captureSignalLog(t)
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "leaving the operator's") {
		t.Fatalf("the pass took an unpublished change for the operator's records:\n%s", logs.String())
	}
	if n := signalRecordRows(t, kdb, z, owner); n != 1 {
		t.Fatalf("the pass forgot its record over an unpublished change (%d rows)", n)
	}
	if got := svcbRecords(zd, owner); !sameRecords(got, stored) {
		t.Fatalf("the published signal changed: %v", got)
	}

	// A stop before the publish: the next process loads the pass's signal
	// and knows it for its own, so a changed configuration applies.
	var lines []string
	for _, rr := range stored {
		lines = append(lines, rr.String())
	}
	body := z + strings.ReplaceAll(readErrZoneBody, "%[1]s", z) + strings.Join(lines, "\n") + "\n"
	zd2, conf2 := signalTestZone(t, z, body, "127.0.0.1:53")
	zd2.KeyDB = kdb
	conf2.Service.Identities = []string{"ns1." + z}
	conf2.Service.Transport.Signal = "dot:20"
	if err := zd2.CreateTransportSignalRRs(conf2); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd2, owner); len(got) != 1 || !strings.Contains(got[0].String(), "dot:20") {
		t.Fatalf("after a stop before the publish, the pass's signal is not its own: %v", got)
	}

	// In the first process, the change is published: the RRset is the
	// operator's, and the next run forgets the record.
	Zones.Set(z, zd)
	publishNow(zd)
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "leaving the operator's") {
		t.Fatalf("once the change was published, the pass did not leave the operator's records alone:\n%s", logs.String())
	}
	if n := signalRecordRows(t, kdb, z, owner); n != 0 {
		t.Fatalf("once the change was published, the pass kept its record (%d rows)", n)
	}
}

// A TXT at the owner beside the pass's signal, the name dropped from
// service.identities, and the withdrawal held back: a second run, which
// finds the TXT staged and no SVCB, publishes the withdrawal again and keeps
// the record, rather than forgetting the record while the pass's signal is
// still served.
func TestASecondRunKeepsAnUnpublishedWithdrawalBesideATXT(t *testing.T) {
	const z = "unpubtxt.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	zd, conf := signalTestZone(t, z, z+strings.ReplaceAll(readErrZoneBody, "%[1]s", z), "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:50"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	stored := svcbRecords(zd, owner)
	if len(stored) != 1 {
		t.Fatalf("the pass stored %v", stored)
	}
	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked(owner, core.RRset{Name: owner, Class: dns.ClassINET, RRtype: dns.TypeTXT,
		RRs: mustRRs(t, owner+`	300	IN	TXT	"beside the signal"`)})
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()

	holdPublishes(t, zd)
	conf.Service.Identities = nil
	logs := captureSignalLog(t)
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "withdrew the signal") {
		t.Fatalf("the pass did not withdraw its signal:\n%s", logs.String())
	}
	if got := svcbRecords(zd, owner); !sameRecords(got, stored) {
		t.Fatalf("the withdrawal was published at once, and the test needs it held back: %v", got)
	}

	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if n := signalRecordRows(t, kdb, z, owner); n != 1 {
		t.Fatalf("the second run forgot the record while the pass's signal is still served (%d rows)", n)
	}
	if !strings.Contains(logs.String(), "not published yet; publishing it again") {
		t.Fatalf("the second run did not publish the withdrawal again:\n%s", logs.String())
	}

	publishNow(zd)
	if got := svcbRecords(zd, owner); len(got) != 0 {
		t.Fatalf("the publish did not carry the withdrawal: %v", got)
	}
}

// More stores than the history keeps, one per restart, each with another
// configuration and no zone write in between: every restart loads the
// signal the zone file holds, the first one, and must know it for the
// pass's. The digest a store replaces is never evicted.
func TestTheHistoryKeepsTheSignalARestartLoads(t *testing.T) {
	const z = "history.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	zd, _ := storeThenRestart(t, z, kdb, "dot:50")
	var lines []string
	for _, rr := range svcbRecords(zd, owner) {
		lines = append(lines, rr.String())
	}
	body := z + strings.ReplaceAll(readErrZoneBody, "%[1]s", z) + strings.Join(lines, "\n") + "\n"

	for i := 1; i <= signalStoredKeep+2; i++ {
		zdN, confN := signalTestZone(t, z, body, "127.0.0.1:53")
		zdN.KeyDB = kdb
		confN.Service.Identities = []string{"ns1." + z}
		want := fmt.Sprintf("dot:%d", i)
		confN.Service.Transport.Signal = want
		logs := captureSignalLog(t)
		if err := zdN.CreateTransportSignalRRs(confN); err != nil {
			t.Fatal(err)
		}
		if got := svcbRecords(zdN, owner); len(got) != 1 || !strings.Contains(got[0].String(), `"`+want+`"`) {
			t.Fatalf("restart %d: the pass did not know the signal the zone file holds for its own: %v\n%s", i, got, logs.String())
		}
	}
}

// The pass runs between the refresh's collection of what it carries and the
// replacement: what is carried is what the pass last published. A signal it
// withdrew is not put back, and one it replaced is not replaced by the old
// one.
func TestARefreshCarriesWhatThePassLastPublished(t *testing.T) {
	const owner = "_dns.ns1.example."
	const head = `example.	3600	IN	SOA	ns1.example. hostmaster.example. %d 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
ns1.example.	3600	IN	A	127.0.0.1
`
	zd := reloadZone(t, newTestKeyDB(t), fmt.Sprintf(head, 1))
	zd.Options[OptAddTransportSignal] = true
	prevSVCB, prevListeners := Globals.ServerSVCB, Conf.Listeners.Addresses
	Globals.ServerSVCB = &dns.SVCB{Hdr: dns.RR_Header{Name: "_dns.server.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300}, Priority: 1, Target: "."}
	Conf.Listeners.Addresses = []string{"127.0.0.1:53"}
	t.Cleanup(func() { Globals.ServerSVCB, Conf.Listeners.Addresses = prevSVCB, prevListeners })
	conf := &Config{}
	conf.Service.Transport.Type = "svcb"
	conf.Service.Identities = []string{"ns1.example."}
	conf.Service.Transport.Signal = "dot:50"
	conf.Listeners.Addresses = Conf.Listeners.Addresses
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}

	// Withdrawn in between.
	collected := zd.CollectDynamicRRs(conf)
	conf.Service.Transport.Type = "none"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd, owner); len(got) != 0 {
		t.Fatalf("the pass did not withdraw its signal: %v", got)
	}
	operatorEdit(t, zd, fmt.Sprintf(head, 2))
	if _, err := zd.FetchFromFile(context.Background(), false, false, true, collected); err != nil {
		t.Fatalf("FetchFromFile: %v", err)
	}
	if got := svcbRecords(zd, owner); len(got) != 0 {
		t.Fatalf("the refresh put back the signal the pass withdrew: %v", got)
	}

	// Replaced in between.
	conf.Service.Transport.Type = "svcb"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	collected = zd.CollectDynamicRRs(conf)
	conf.Service.Transport.Signal = "dot:20"
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	operatorEdit(t, zd, fmt.Sprintf(head, 3))
	if _, err := zd.FetchFromFile(context.Background(), false, false, true, collected); err != nil {
		t.Fatalf("FetchFromFile: %v", err)
	}
	if got := svcbRecords(zd, owner); len(got) != 1 || !strings.Contains(got[0].String(), "dot:20") {
		t.Fatalf("the refresh did not carry the signal the pass last published: %v", got)
	}
}

// signalLines is the SVCB RRset zd publishes at owner, as zone file lines.
func signalLines(t *testing.T, zd *ZoneData, owner string) string {
	t.Helper()
	rrs := svcbRecords(zd, owner)
	if len(rrs) == 0 {
		t.Fatalf("no signal published at %s", owner)
	}
	var b strings.Builder
	for _, rr := range rrs {
		b.WriteString(rr.String() + "\n")
	}
	return b.String()
}

// storeSignal runs the pass on zd with signal and checks that it stored it.
func storeSignal(t *testing.T, zd *ZoneData, conf *Config, owner, signal string) {
	t.Helper()
	conf.Service.Transport.Signal = signal
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd, owner); len(got) != 1 || !strings.Contains(got[0].String(), `"`+signal+`"`) {
		t.Fatalf("the pass did not store %s: %v", signal, got)
	}
}

// restartKnowsItsSignal loads body as a restart would, on kdb, and checks
// that the pass takes the signal there for its own: it replaces it with
// signal rather than leaving it as the operator's.
func restartKnowsItsSignal(t *testing.T, z string, kdb *KeyDB, body, signal string) {
	t.Helper()
	zd, conf := signalTestZone(t, z, body, "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	logs := captureSignalLog(t)
	conf.Service.Transport.Signal = signal
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd, "_dns.ns1."+z); len(got) != 1 || !strings.Contains(got[0].String(), `"`+signal+`"`) {
		t.Fatalf("after the restart the pass did not know the signal the zone file holds for its own: %v\n%s", got, logs.String())
	}
}

// Several stores in one process, with no zone write in between, keep the
// signal the zone file holds in the record: it is what a restart loads,
// and it must still be the pass's then. Each store replaces the one before
// it, not the file's (CodeRabbit on #1145).
func TestStoresInOneProcessKeepTheSignalTheZoneFileHolds(t *testing.T) {
	const z = "manystores.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	loaded, _ := storeThenRestart(t, z, kdb, "dot:50")
	body := z + strings.ReplaceAll(readErrZoneBody, "%[1]s", z) + signalLines(t, loaded, owner)

	zd, conf := signalTestZone(t, z, body, "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	for i := 1; i <= signalStoredKeep+1; i++ {
		storeSignal(t, zd, conf, owner, fmt.Sprintf("dot:%d", i))
	}
	restartKnowsItsSignal(t, z, kdb, body, "dot:99")
}

// A zone write changes what the zone file holds: stores after it, with no
// further write, keep the signal written in the record.
func TestStoresAfterAZoneWriteKeepTheSignalWritten(t *testing.T) {
	const z = "written.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	loaded, _ := storeThenRestart(t, z, kdb, "dot:50")
	head := z + strings.ReplaceAll(readErrZoneBody, "%[1]s", z)

	zd, conf := signalTestZone(t, z, head+signalLines(t, loaded, owner), "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	storeSignal(t, zd, conf, owner, "dot:1")
	written := signalLines(t, zd, owner)
	if _, err := zd.WriteDynamicZoneFile(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= signalStoredKeep+2; i++ {
		storeSignal(t, zd, conf, owner, fmt.Sprintf("dot:%d", i))
	}
	restartKnowsItsSignal(t, z, kdb, head+written, "dot:99")
}

// A zone write that finds an operator's SVCB RRset at the owner does not
// keep its digest for the pass's: the record would then take the
// operator's records for the pass's.
func TestAZoneWriteDoesNotKeepTheOperatorsSignal(t *testing.T) {
	const z = "writtenop.sig.example."
	const owner = "_dns.ns1." + z
	zd, conf := signalTestZone(t, z, z+strings.ReplaceAll(readErrZoneBody, "%[1]s", z), "127.0.0.1:53")
	zd.KeyDB = newTestKeyDB(t)
	conf.Service.Identities = []string{"ns1." + z}
	storeSignal(t, zd, conf, owner, "dot:1")
	op := mustRRs(t, owner+` 300 IN SVCB 1 . oots="doq:10"`)
	zd.mu.Lock()
	zd.stageRRsetLocked(owner, core.RRset{Name: owner, RRtype: dns.TypeSVCB, RRs: op})
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
	zd.mu.Unlock()
	if _, err := zd.WriteDynamicZoneFile(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	zd.signalStoredMu.Lock()
	kept := zd.signalOnDisk[owner]
	zd.signalStoredMu.Unlock()
	if kept == signalDigest(op) {
		t.Fatal("the zone write kept the operator's SVCB RRset as the pass's signal on disk")
	}
	if own, err := zd.signalStoredByPass(owner, op); err != nil || own {
		t.Fatalf("the operator's SVCB RRset reads as the pass's (%v, %v)", own, err)
	}
}

// Stores the publish cadence holds back keep the signal the zone serves in
// the record. Each replaces the one staged before it, not the served one,
// which would otherwise drop out of the record at the seventh while the
// zone still serves it; the pass would then take it for the operator's
// (CodeRabbit on #1145).
func TestHeldBackStoresKeepTheSignalServed(t *testing.T) {
	const z = "heldback.sig.example."
	const owner = "_dns.ns1." + z
	zd, conf := signalTestZone(t, z, z+strings.ReplaceAll(readErrZoneBody, "%[1]s", z), "127.0.0.1:53")
	zd.KeyDB = newTestKeyDB(t)
	conf.Service.Identities = []string{"ns1." + z}
	storeSignal(t, zd, conf, owner, "dot:1")
	served := svcbRecords(zd, owner)

	// An unrelated change, held back by the cadence, holds back the stores
	// after it too.
	t.Cleanup(zd.stopPublisher)
	zd.mu.Lock()
	zd.publishCadence = time.Hour
	zd.lastPublish = time.Now()
	zd.stageRRsetLocked("note."+z, core.RRset{Name: "note." + z, Class: dns.ClassINET, RRtype: dns.TypeTXT,
		RRs: mustRRs(t, "note."+z+`	3600	IN	TXT	"an operator's change"`)})
	zd.mu.Unlock()
	for i := 2; i <= signalStoredKeep+2; i++ {
		conf.Service.Transport.Signal = fmt.Sprintf("dot:%d", i)
		if err := zd.CreateTransportSignalRRs(conf); err != nil {
			t.Fatal(err)
		}
	}
	if got := svcbRecords(zd, owner); !sameRecords(got, served) {
		t.Fatalf("a store was published, and the test needs them held back: %v", got)
	}
	if own, err := zd.signalStoredByPass(owner, served); err != nil || !own {
		t.Fatalf("after the held-back stores the signal the zone serves is not the pass's (%v, %v)", own, err)
	}
	if got, ok, err := zd.KeyDB.GetTransportSignalStored(z, owner); err != nil || !ok || !slices.Contains(got, signalDigest(served)) {
		t.Fatalf("the KeyDB's record does not hold the signal the zone serves: %v (present %v, error %v)", got, ok, err)
	}
}

// A reload that adopts a zone file holding a signal of the pass's other
// than the one last written moves what the record keeps for the zone file
// to it: stores after the reload keep it, and a restart from that file
// knows it for the pass's (CodeRabbit on #1145).
func TestStoresAfterAReloadKeepTheSignalTheFileHolds(t *testing.T) {
	const owner = "_dns.ns1.example."
	const head = `example.	3600	IN	SOA	ns1.example. hostmaster.example. %d 7200 1800 604800 7200
`
	const body = `example.	3600	IN	NS	ns1.example.
ns1.example.	3600	IN	A	127.0.0.1
`
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, fmt.Sprintf(head, 1)+body)
	zd.Options[OptAddTransportSignal] = true
	prevSVCB, prevListeners := Globals.ServerSVCB, Conf.Listeners.Addresses
	Globals.ServerSVCB = &dns.SVCB{Hdr: dns.RR_Header{Name: "_dns.server.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300}, Priority: 1, Target: "."}
	Conf.Listeners.Addresses = []string{"127.0.0.1:53"}
	t.Cleanup(func() { Globals.ServerSVCB, Conf.Listeners.Addresses = prevSVCB, prevListeners })
	conf := &Config{}
	conf.Service.Transport.Type = "svcb"
	conf.Service.Identities = []string{"ns1.example."}
	conf.Listeners.Addresses = Conf.Listeners.Addresses

	storeSignal(t, zd, conf, owner, "dot:1")
	if _, err := zd.WriteDynamicZoneFile(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// The zone file the zone loads from comes to hold a later signal of the
	// pass's, as a copy restored from a backup would, and a reload adopts it.
	storeSignal(t, zd, conf, owner, "dot:2")
	adopted := body + signalLines(t, zd, owner)
	operatorEdit(t, zd, fmt.Sprintf(head, 2)+adopted)
	if _, err := zd.FetchFromFile(context.Background(), false, false, true, nil); err != nil {
		t.Fatalf("FetchFromFile: %v", err)
	}
	for i := 3; i <= signalStoredKeep+3; i++ {
		storeSignal(t, zd, conf, owner, fmt.Sprintf("dot:%d", i))
	}
	restartKnowsItsSignal(t, "example.", kdb, adopted, "dot:99")
}

// A zone write whose rename landed has put the signal in the zone file even
// when the directory sync after it fails: what the record keeps for the
// zone file moves to it all the same, and the write still reports the
// failure (CodeRabbit on #1145).
func TestAZoneWriteWhoseDirectorySyncFailsStillMovesTheFilesSignal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a directory it may not read")
	}
	const z = "dirsync.sig.example."
	const owner = "_dns.ns1." + z
	zd, conf := signalTestZone(t, z, z+strings.ReplaceAll(readErrZoneBody, "%[1]s", z), "127.0.0.1:53")
	zd.KeyDB = newTestKeyDB(t)
	conf.Service.Identities = []string{"ns1." + z}
	storeSignal(t, zd, conf, owner, "dot:1")

	// A directory the server may write to but not read: the rename lands,
	// and opening the directory to sync it fails.
	dir := t.TempDir()
	prevDir := viper.GetString("external.filedir")
	viper.Set("external.filedir", dir)
	t.Cleanup(func() { viper.Set("external.filedir", prevDir) })
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if _, _, err := zd.WriteFileWithSerial("dirsync.zone"); err == nil || !strings.Contains(err.Error(), "to sync the rename") {
		t.Fatalf("the write whose directory sync failed returned %v", err)
	}
	zd.signalStoredMu.Lock()
	kept := zd.signalOnDisk[owner]
	zd.signalStoredMu.Unlock()
	if want := signalDigest(svcbRecords(zd, owner)); kept != want {
		t.Fatalf("after the rename the record keeps %q for the zone file, want the signal written (%q)", kept, want)
	}
}

// Stores that run while the zone file is being written, and publish newer
// signals, do not push the signal being written out of the record: once the
// write is in place, what the record keeps for the zone file moves to it,
// stores after it keep it, and a restart from that file knows it for the
// pass's (CodeRabbit on #1145).
func TestStoresDuringAZoneWriteKeepTheSignalItWrites(t *testing.T) {
	const z = "writing.sig.example."
	const owner = "_dns.ns1." + z
	kdb := newTestKeyDB(t)
	loaded, _ := storeThenRestart(t, z, kdb, "dot:50")
	head := z + strings.ReplaceAll(readErrZoneBody, "%[1]s", z)

	zd, conf := signalTestZone(t, z, head+signalLines(t, loaded, owner), "127.0.0.1:53")
	zd.KeyDB = kdb
	conf.Service.Identities = []string{"ns1." + z}
	storeSignal(t, zd, conf, owner, "dot:1")
	written := signalLines(t, zd, owner)
	t.Cleanup(func() { testHookZoneFileWriting = nil })
	testHookZoneFileWriting = func() {
		testHookZoneFileWriting = nil
		for i := 2; i <= signalStoredKeep+2; i++ {
			storeSignal(t, zd, conf, owner, fmt.Sprintf("dot:%d", i))
		}
	}
	if _, err := zd.WriteDynamicZoneFile(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for i := signalStoredKeep + 3; i <= 2*signalStoredKeep+3; i++ {
		storeSignal(t, zd, conf, owner, fmt.Sprintf("dot:%d", i))
	}
	restartKnowsItsSignal(t, z, kdb, head+written, "dot:99")
}

// A refresh that collected an operator's SVCB RRset as the operator's, and
// cannot read the record when it takes the signal again, does not carry
// that RRset: the fresh data, which no longer holds it, stands (CodeRabbit
// on #1145).
func TestARefreshDoesNotCarryTheOperatorsSignalOnAFailedRecheck(t *testing.T) {
	const owner = "_dns.ns1.example."
	const head = `example.	3600	IN	SOA	ns1.example. hostmaster.example. %d 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
ns1.example.	3600	IN	A	127.0.0.1
`
	const operators = `_dns.ns1.example.	3600	IN	SVCB	1 . alpn="dot"
`
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, fmt.Sprintf(head, 1)+operators)
	zd.Options[OptAddTransportSignal] = true
	conf := &Config{}
	conf.Service.Transport.Type = "svcb"
	if got := svcbRecords(zd, owner); len(got) != 1 {
		t.Fatalf("the zone does not serve the operator's SVCB RRset: %v", got)
	}
	collected := zd.CollectDynamicRRs(conf)
	for _, rs := range collected {
		if rs != nil && rs.RRtype == dns.TypeSVCB {
			t.Fatalf("the refresh collected the operator's SVCB RRset: %v", rs.RRs)
		}
	}

	// The operator removes the RRset from the file, and the record cannot be
	// read when the refresh takes the signal again.
	operatorEdit(t, zd, fmt.Sprintf(head, 2))
	if _, err := kdb.DB.Exec(`ALTER TABLE TransportSignalStored RENAME TO TransportSignalStored_gone`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kdb.DB.Exec(`ALTER TABLE TransportSignalStored_gone RENAME TO TransportSignalStored`) })
	if _, err := zd.FetchFromFile(context.Background(), false, false, true, collected); err != nil {
		t.Fatalf("FetchFromFile: %v", err)
	}
	if got := svcbRecords(zd, owner); len(got) != 0 {
		t.Fatalf("the refresh brought back the operator's SVCB RRset the file no longer holds: %v", got)
	}
}
