/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// An operator's edit of CDS, CDNSKEY or CSYNC is told to the parent (#752;
// design docs/2026-09-24-cds-publication-and-rfc-conformance.md §1.2 (d)).
// Test numbers are the design's §1.3 numbers.

// signalsRig is a zone in child delegation-sync mode that takes updates from
// both of an operator's channels, with a DelegationSyncQ nothing reads.
func signalsRig(t *testing.T) (*ZoneData, *KeyDB) {
	t.Helper()
	prev := Globals.App.Type
	t.Cleanup(func() { Globals.App.Type = prev })
	Globals.App.Type = AppTypeAuth

	kdb := newTestKeyDB(t)
	kdb.UpdateQ = make(chan UpdateRequest, 4)
	zd := testZone(t, "example.", csyncTestZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.ZoneType = Primary
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true, OptAllowApiUpdates: true, OptParentSync: true}
	zd.UpdatePolicy = policyAllowing(dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeCSYNC, dns.TypeTXT)
	zd.DelegationSyncQ = make(chan DelegationSyncRequest, 8)
	return zd, kdb
}

// signalsEdited drains the zone's DelegationSyncQ and returns the types of each
// SIGNALS-EDITED queued.
func signalsEdited(zd *ZoneData) [][]uint16 {
	var out [][]uint16
	for {
		select {
		case req := <-zd.DelegationSyncQ:
			if req.Command == "SIGNALS-EDITED" {
				out = append(out, req.SignalTypes)
			}
		default:
			return out
		}
	}
}

func operatorUpdate(t *testing.T, kdb *KeyDB, zone string, api bool, rrs ...string) {
	t.Helper()
	ur := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zone, PreAuthorized: api}
	for _, s := range rrs {
		ur.Actions = append(ur.Actions, mustRR(t, s))
	}
	if res := runUpdaterForResult(t, kdb, ur); res.Err != nil {
		t.Fatalf("update %v: %v", rrs, res.Err)
	}
}

const (
	editCDS   = "example. 120 IN CDS 12345 13 2 3f8a1f4c7b0d6c9e8a2b5d4f3e1c0b9a8d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f"
	editCSYNC = "example. 3600 IN CSYNC 17 3 A NS AAAA"
)

// Tests 20 and 21. An operator's CDS edit, through the management API or DNS
// UPDATE, queues one SIGNALS-EDITED naming CDS; the same edit again queues
// nothing.
func TestAnOperatorsCdsEditIsPassedOn(t *testing.T) {
	for _, api := range []bool{true, false} {
		name := "DNS UPDATE"
		if api {
			name = "management API"
		}
		t.Run(name, func(t *testing.T) {
			zd, kdb := signalsRig(t)

			operatorUpdate(t, kdb, zd.ZoneName, api, editCDS)
			if got := signalsEdited(zd); !reflect.DeepEqual(got, [][]uint16{{dns.TypeCDS}}) {
				t.Fatalf("SIGNALS-EDITED queued = %v, want one naming CDS", got)
			}

			operatorUpdate(t, kdb, zd.ZoneName, api, editCDS)
			if got := signalsEdited(zd); len(got) != 0 {
				t.Errorf("an identical republish queued %v", got)
			}
		})
	}
}

// Tests 23 and 24 at the updater. A CSYNC edit is passed on; a removal is
// passed on too, as an edit, and the handler decides it sends nothing.
func TestCsyncEditsAndRemovalsAreDetected(t *testing.T) {
	zd, kdb := signalsRig(t)

	operatorUpdate(t, kdb, zd.ZoneName, true, editCSYNC)
	if got := signalsEdited(zd); !reflect.DeepEqual(got, [][]uint16{{dns.TypeCSYNC}}) {
		t.Fatalf("SIGNALS-EDITED queued = %v, want one naming CSYNC", got)
	}

	del := &dns.ANY{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeCSYNC, Class: dns.ClassANY}}
	if res := runUpdaterForResult(t, kdb, UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName,
		PreAuthorized: true, Actions: []dns.RR{del}}); res.Err != nil {
		t.Fatalf("delete the CSYNC: %v", res.Err)
	}
	if got := signalsEdited(zd); !reflect.DeepEqual(got, [][]uint16{{dns.TypeCSYNC}}) {
		t.Errorf("SIGNALS-EDITED queued = %v after the removal, want one naming CSYNC", got)
	}
}

// Test 25. tdns's own writers set InternalUpdate and send their own NOTIFY, so
// their publishes queue no SIGNALS-EDITED.
func TestInternalWritersQueueNoSignalsEdited(t *testing.T) {
	zd, kdb := signalsRig(t)
	ur := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, InternalUpdate: true,
		Actions: []dns.RR{cdsDeleteRR(zd.ZoneName), mustRR(t, editCDS), mustRR(t, editCSYNC)}}
	if res := runUpdaterForResult(t, kdb, ur); res.Err != nil {
		t.Fatalf("internal update: %v", res.Err)
	}
	if got := signalsEdited(zd); len(got) != 0 {
		t.Errorf("an internal update queued %v", got)
	}
}

// Test 26 at the updater. Under a transaction hold the served zone is still
// the old one: the edit is found in what the update staged.
func TestAnEditUnderATransactionHoldIsDetected(t *testing.T) {
	zd, kdb := signalsRig(t)
	id, err := zd.BeginTx(0)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	t.Cleanup(func() { _ = zd.CommitTx(id) })

	operatorUpdate(t, kdb, zd.ZoneName, true, editCDS)

	if servesApexType(zd, dns.TypeCDS) {
		t.Fatal("the held edit is served already; this test needs it staged")
	}
	if got := signalsEdited(zd); !reflect.DeepEqual(got, [][]uint16{{dns.TypeCDS}}) {
		t.Errorf("SIGNALS-EDITED queued = %v, want one naming CDS", got)
	}
}

// Test 26 at the syncher. Nothing goes to the parent while the hold lasts:
// the request comes back once the transaction has committed.
func TestSignalsEditedWaitsOutATransactionHold(t *testing.T) {
	prev := txHoldPollInterval
	txHoldPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { txHoldPollInterval = prev })

	zd, _ := signalsRig(t)
	id, err := zd.BeginTx(0)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := make(chan DelegationSyncRequest, 1)
	done := deferUntilHoldEnds(ctx, q, zd, DelegationSyncRequest{Command: "SIGNALS-EDITED", ZoneName: zd.ZoneName})

	select {
	case got := <-q:
		t.Fatalf("the request came back while the transaction was open: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	select {
	case got := <-q:
		if got.Command != "SIGNALS-EDITED" {
			t.Errorf("re-enqueued %s, want SIGNALS-EDITED", got.Command)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never came back after the commit")
	}
	<-done
}

// Test 27. A zone not in child delegation-sync mode queues nothing: a
// multi-provider zone, and a zone without parentsync.
func TestOnlyChildSyncZonesPassEditsOn(t *testing.T) {
	cases := map[string]func(zd *ZoneData){
		"multi-provider": func(zd *ZoneData) { zd.Options[OptMultiProvider] = true },
		"no parentsync":  func(zd *ZoneData) { zd.Options[OptParentSync] = false },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			zd, kdb := signalsRig(t)
			setup(zd)
			operatorUpdate(t, kdb, zd.ZoneName, true, editCDS)
			if got := signalsEdited(zd); len(got) != 0 {
				t.Errorf("queued %v", got)
			}
		})
	}
}

// fakeSignalsSteps records what the SIGNALS-EDITED handler does.
type fakeSignalsSteps struct {
	managed bool
	served  map[uint16][]dns.RR
	noTgt   bool
	calls   []string
}

func (f *fakeSignalsSteps) steps() signalsEditedSteps {
	return signalsEditedSteps{
		managed:      func() (bool, error) { return f.managed, nil },
		explicitSync: func() { f.calls = append(f.calls, "sync") },
		markKeys:     func() { f.calls = append(f.calls, "mark") },
		served:       func(t uint16) []dns.RR { return f.served[t] },
		target: func(t uint16) (*DsyncTarget, error) {
			if f.noTgt {
				return nil, errors.New("no DSYNC type CDS scheme 1 destination found")
			}
			return testDsyncTarget, nil
		},
		notify: func(t uint16, _ *DsyncTarget) bool {
			f.calls = append(f.calls, "notify "+dns.TypeToString[t])
			return true
		},
	}
}

// Tests 20, 22, 23, 24 and 28 at the handler.
func TestTheSignalsEditedHandler(t *testing.T) {
	cdsRRs := func(t *testing.T) []dns.RR { return []dns.RR{mustRR(t, editCDS)} }
	cases := []struct {
		name    string
		types   []uint16
		managed bool
		served  func(t *testing.T) map[uint16][]dns.RR
		noTgt   bool
		want    []string
	}{
		{"not managed: the operator's CDS is announced", []uint16{dns.TypeCDS}, false,
			func(t *testing.T) map[uint16][]dns.RR { return map[uint16][]dns.RR{dns.TypeCDS: cdsRRs(t)} },
			false, []string{"notify CDS"}},
		{"not managed: a CDNSKEY edit is a NOTIFY(CDS)", []uint16{dns.TypeCDNSKEY}, false,
			func(t *testing.T) map[uint16][]dns.RR {
				return map[uint16][]dns.RR{dns.TypeCDNSKEY: {mustRR(t, "example. 120 IN CDNSKEY 257 3 13 AAAA")}}
			}, false, []string{"notify CDS"}},
		{"not managed: a hand-published delete CDS is announced", []uint16{dns.TypeCDS}, false,
			func(t *testing.T) map[uint16][]dns.RR {
				return map[uint16][]dns.RR{dns.TypeCDS: {mustRR(t, "example. 120 IN CDS 0 0 0 00")}}
			}, false, []string{"notify CDS"}},
		{"managed: sync first, then mark", []uint16{dns.TypeCDS}, true,
			func(t *testing.T) map[uint16][]dns.RR { return map[uint16][]dns.RR{dns.TypeCDS: cdsRRs(t)} },
			false, []string{"sync", "mark"}},
		{"CSYNC", []uint16{dns.TypeCSYNC}, false,
			func(t *testing.T) map[uint16][]dns.RR {
				return map[uint16][]dns.RR{dns.TypeCSYNC: {mustRR(t, editCSYNC)}}
			}, false, []string{"notify CSYNC"}},
		{"removed CDS and CSYNC", []uint16{dns.TypeCDS, dns.TypeCSYNC}, false,
			func(t *testing.T) map[uint16][]dns.RR { return nil }, false, nil},
		{"no NOTIFY target", []uint16{dns.TypeCDS}, false,
			func(t *testing.T) map[uint16][]dns.RR { return map[uint16][]dns.RR{dns.TypeCDS: cdsRRs(t)} },
			true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSignalsSteps{managed: tc.managed, served: tc.served(t), noTgt: tc.noTgt}
			handleSignalsEditedWith(&ZoneData{ZoneName: "example."}, tc.types, f.steps())
			if strings.Join(f.calls, ",") != strings.Join(tc.want, ",") {
				t.Errorf("handler did %v, want %v", f.calls, tc.want)
			}
		})
	}
}

// editedSignalTypes compares records, not TTLs.
func TestEditedSignalTypesIgnoresTTL(t *testing.T) {
	a := map[uint16][]dns.RR{dns.TypeCDS: {mustRR(t, editCDS)}}
	b := map[uint16][]dns.RR{dns.TypeCDS: {mustRR(t, strings.Replace(editCDS, " 120 ", " 3600 ", 1))}}
	if got := editedSignalTypes(a, b); len(got) != 0 {
		t.Errorf("a TTL change counted as an edit of %v", got)
	}
	if got := editedSignalTypes(a, map[uint16][]dns.RR{}); !reflect.DeepEqual(got, []uint16{dns.TypeCDS}) {
		t.Errorf("a removal counted as %v, want CDS", got)
	}
}
