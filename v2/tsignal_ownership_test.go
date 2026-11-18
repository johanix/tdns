package tdns

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
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
