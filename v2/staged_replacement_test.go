/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// Tests for #748: a replacement (a transfer, or a reload of the zone's file)
// is not a local change and must never reach the journal as one. A
// replacement refused at signing stays staged for a later publish to retry,
// and a zone-updater change arriving meanwhile used to be applied on top of it
// and journalled together with it.

// srSigning makes zd's signing fail or work again, the way
// TestPublishRefusesAReplacementItCannotSign breaks it: a policy algorithm
// its active keys do not have, which strict completeness refuses.
func srSigning(t *testing.T, zd *ZoneData, works bool) {
	t.Helper()
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if works {
		zd.DnssecPolicy.KSKAlgorithm, zd.DnssecPolicy.ZSKAlgorithm = dns.ED25519, dns.ED25519
	} else {
		zd.DnssecPolicy.KSKAlgorithm, zd.DnssecPolicy.ZSKAlgorithm = dns.RSASHA256, dns.RSASHA256
	}
}

const srFresh = "fresh.example.\t3600\tIN\tA\t10.9.9.9"

// srRefusedTransfer runs a full transfer from an upstream serving its own CDS
// and a new A record, with signing broken, and checks that it was refused and
// left staged.
func srRefusedTransfer(t *testing.T, zd *ZoneData) {
	t.Helper()
	withCompleteness(t, CompletenessStrict)
	srSigning(t, zd, false)
	served := ovServedSerial(t, zd)
	ovTransfer(t, zd, ovUpstreamZone(20, ovCDSText(9), srFresh), true)
	zd.mu.Lock()
	staged := zd.workingSet != nil
	zd.mu.Unlock()
	if got := ovServedSerial(t, zd); got != served || !staged {
		t.Fatalf("precondition: the transfer was not refused and staged (serial %d -> %d, staged %v)",
			served, got, staged)
	}
	srSigning(t, zd, true)
}

// An update arriving once signing works again publishes the staged transfer
// first, and journals only its own change. After the journal overlay the
// upstream's CDS, which arrived only through that window, is not kept once
// the upstream withdraws it.
func TestStagedReplacementIsNotJournalledByAnUpdate(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	srRefusedTransfer(t, zd)

	local := mustRR(t, "local.example.\t3600\tIN\tA\t10.0.0.7")
	if err := ovUpdate(t, zd, local); err != nil {
		t.Fatalf("local update: %v", err)
	}
	if !ovHas(ovServed(t, zd, "fresh.example.", dns.TypeA), mustRR(t, srFresh)) {
		t.Error("the staged transfer is not served after the update")
	}
	if !ovHas(ovServed(t, zd, "local.example.", dns.TypeA), local) {
		t.Error("the local change is not served")
	}
	ovRowsAre(t, ovOneDelta(t, zd), ovAdd(local.String()))

	ovTransfer(t, zd, ovUpstreamZone(21), true)
	if ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), ovCDS(t, 9)) {
		t.Error("the upstream's withdrawn CDS is still served")
	}
}

// While the staged transfer still cannot be published, a local change is
// refused rather than applied on top of it. Nothing is journalled, and the
// transfer stays staged for the next publish.
func TestStagedReplacementRefusesAnUpdateWhileItCannotPublish(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	srRefusedTransfer(t, zd)
	srSigning(t, zd, false)

	if err := ovUpdate(t, zd, mustRR(t, "local.example.\t3600\tIN\tA\t10.0.0.7")); err == nil {
		t.Error("a local change was accepted on top of a transfer that cannot be published")
	}
	if deltas := ovJournal(t, zd); len(deltas) != 0 {
		t.Errorf("the journal is not empty:%s", ovJournalString(deltas))
	}
	zd.mu.Lock()
	staged := zd.workingSet != nil
	zd.mu.Unlock()
	if !staged {
		t.Error("the refused update dropped the staged transfer")
	}
}

// A publish with no update in between, as the publisher's retry is, publishes
// the staged transfer and journals nothing.
func TestStagedReplacementRetriedByAPublishJournalsNothing(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	srRefusedTransfer(t, zd)

	zd.mu.Lock()
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()

	if !ovHas(ovServed(t, zd, "fresh.example.", dns.TypeA), mustRR(t, srFresh)) {
		t.Error("the retry did not publish the staged transfer")
	}
	if deltas := ovJournal(t, zd); len(deltas) != 0 {
		t.Errorf("the retry journalled the transfer:%s", ovJournalString(deltas))
	}
}

// The other order: an update refused at signing leaves its journal flag set,
// and a transfer that replaces its staged change must not publish under that
// flag. It would journal the transfer as the update.
func TestReplacementDoesNotInheritARefusedUpdate(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	withCompleteness(t, CompletenessStrict)
	srSigning(t, zd, false)
	// Refused at signing and left staged; the applier reports no error.
	_ = ovUpdate(t, zd, mustRR(t, "local.example.\t3600\tIN\tA\t10.0.0.7"))
	srSigning(t, zd, true)

	ovTransfer(t, zd, ovUpstreamZone(20, ovCDSText(9), srFresh), true)

	if !ovHas(ovServed(t, zd, "fresh.example.", dns.TypeA), mustRR(t, srFresh)) {
		t.Fatal("precondition: the transfer was not published")
	}
	if deltas := ovJournal(t, zd); len(deltas) != 0 {
		t.Errorf("the transfer was journalled as a local change:%s", ovJournalString(deltas))
	}
}

// The same on a primary: a reload of an edited file refused at signing, then
// an update. The journal holds the update alone, not the file's edit, which
// the next load would otherwise replay over the file that already has it.
func TestStagedFileReloadIsNotJournalledByAnUpdate(t *testing.T) {
	zd := reloadZone(t, newTestKeyDB(t), reloadBase)
	makeZoneSigning(t, zd)
	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.wsNeedsFullSign = true
	zd.publishWorkingSetLocked(zd.generation.Load(), true)
	zd.mu.Unlock()

	withCompleteness(t, CompletenessStrict)
	srSigning(t, zd, false)
	operatorEdit(t, zd, `example.	3600	IN	SOA	ns.example. hostmaster.example. 101 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
operator.example.	3600	IN	A	10.9.9.9
`)
	if _, err := zd.Refresh(context.Background(), false, false, false, &Config{}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if hasARRset(t, zd, "operator.example.") {
		t.Fatal("precondition: the reload was published although signing is broken")
	}
	srSigning(t, zd, true)

	if err := apiUpdate(t, zd, zd.KeyDB, "journal.example. 3600 IN A 10.1.1.1"); err != nil {
		t.Fatalf("the API update failed: %v", err)
	}
	if !hasARRset(t, zd, "operator.example.") {
		t.Error("the staged reload is not served after the update")
	}
	deltas := ovJournal(t, zd)
	if len(deltas) != 1 {
		t.Fatalf("the journal holds %d deltas, want one:%s", len(deltas), ovJournalString(deltas))
	}
	ovRowsAre(t, deltas[0].RRs, ovAdd("journal.example.\t3600\tIN\tA\t10.1.1.1"))
}
