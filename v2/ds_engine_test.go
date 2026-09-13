/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// dsEngineRig is a keystore, a zone, a zone updater that really publishes what it
// is given, a notifier, and a running DS engine.
type dsEngineRig struct {
	kdb     *KeyDB
	zd      *ZoneData
	notifyq chan NotifyRequest
	log     *fakeUpdaterLog
}

// newDSEngineRig builds the rig. applyDelay slows the zone updater, which is what
// makes a caller that does not wait for its update visible. With serveNotify
// false nothing reads notifyq, so a test can count what was sent.
func newDSEngineRig(t *testing.T, applyDelay time.Duration, serveNotify bool) *dsEngineRig {
	t.Helper()
	kdb := newTestKeyDB(t)
	kdb.UpdateQ = make(chan UpdateRequest, 8)
	kdb.DSEngineQ = make(chan DSEngineRequest, 8)
	r := &dsEngineRig{kdb: kdb, notifyq: make(chan NotifyRequest, 8), log: &fakeUpdaterLog{}}

	zd := testZone(t, "example.", csyncTestZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true}
	zd.CurrentSerial = 17
	r.zd = zd

	serveQueue(t, kdb.UpdateQ, func(ctx context.Context, ur UpdateRequest) {
		select {
		case <-time.After(applyDelay):
		case <-ctx.Done():
			return
		}
		applyApexActions(zd, ur.Actions)
		r.log.record("published " + actionTypes(ur.Actions))
		ur.respond(true, nil)
	})
	if serveNotify {
		serveQueue(t, r.notifyq, func(_ context.Context, req NotifyRequest) {
			r.log.record("notified " + dns.TypeToString[req.RRtype])
			if req.Response != nil {
				req.Response <- NotifyResponse{Rcode: dns.RcodeSuccess}
			}
		})
	}
	startDSEngine(t, kdb)
	return r
}

// startDSEngine runs the DS engine until the test ends. Registered after the
// fakes, so it is stopped before them.
func startDSEngine(t *testing.T, kdb *KeyDB) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		_ = kdb.DSEngine(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Error("the DS engine did not exit within 5s of cancellation")
		}
	})
}

// applyApexActions applies a delete-then-add apex update the way the zone
// updater does for these publishers: a class-ANY record removes the RRset, and
// the class-IN records that follow become the new one.
func applyApexActions(zd *ZoneData, actions []dns.RR) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()
	adds := map[uint16][]dns.RR{}
	var order []uint16
	for _, rr := range actions {
		h := rr.Header()
		switch h.Class {
		case dns.ClassANY:
			zd.stageDeleteLocked(zd.ZoneName, h.Rrtype)
		case dns.ClassINET:
			if _, seen := adds[h.Rrtype]; !seen {
				order = append(order, h.Rrtype)
			}
			adds[h.Rrtype] = append(adds[h.Rrtype], rr)
		}
	}
	for _, rrtype := range order {
		zd.stageRRsetLocked(zd.ZoneName, core.RRset{
			Name: zd.ZoneName, RRtype: rrtype, Class: dns.ClassINET, RRs: adds[rrtype],
		})
	}
	zd.publishLocked(zd.generation.Load())
}

// actionTypes names the RR types an update touches, for the event log.
func actionTypes(actions []dns.RR) string {
	seen := map[string]bool{}
	var out []string
	for _, rr := range actions {
		s := dns.TypeToString[rr.Header().Rrtype]
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}

func testKSK(zone, pubkey string) *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: pubkey,
	}
}

// seedKeyWithIndex writes a KSK and the RolloverKeyState row that gives it a
// rollover index, as the multi-DS rollover engine does.
func seedKeyWithIndex(t *testing.T, kdb *KeyDB, zone, state, pubkey string, index int) uint16 {
	t.Helper()
	seedKey(t, kdb, zone, state, 257, pubkey)
	keyid := testKSK(zone, pubkey).KeyTag()
	_, err := kdb.DB.Exec(`INSERT INTO RolloverKeyState (zone, keyid, rollover_index, rollover_method, rollover_state_at)
		VALUES (?, ?, ?, 'multi-ds', ?)`, zone, int(keyid), index, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("seed RolloverKeyState(%s, %d): %v", zone, keyid, err)
	}
	return keyid
}

// cdsFor is the CDS RRset asking for the DS of the KSKs with these public keys.
func cdsFor(zone string, pubkeys ...string) []dns.RR {
	var ds []dns.RR
	for _, pk := range pubkeys {
		ds = append(ds, testKSK(zone, pk).ToDS(dns.SHA256))
	}
	return cdsFromDS(zone, ds)
}

func servedCDS(t *testing.T, zd *ZoneData) map[cdsTuple]struct{} {
	t.Helper()
	got, err := currentCdsTuples(zd)
	if err != nil {
		t.Fatalf("read the served CDS: %v", err)
	}
	return got
}

// stageCDS publishes cds at the apex directly, as a CDS already on the wire.
func stageCDS(t *testing.T, zd *ZoneData, cds []dns.RR) {
	t.Helper()
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked(zd.ZoneName, core.RRset{
		Name: zd.ZoneName, RRtype: dns.TypeCDS, Class: dns.ClassINET, RRs: cds,
	})
	zd.publishLocked(zd.generation.Load())
}

func dsChangeFor(zone, pubkey string) DelegationSyncStatus {
	return DelegationSyncStatus{DSAdds: []dns.RR{testKSK(zone, pubkey).ToDS(dns.SHA256)}}
}

func eventIndex(events []string, want string) int {
	for i, e := range events {
		if e == want {
			return i
		}
	}
	return -1
}

var testDsyncTarget = &DsyncTarget{Name: "parent.", Addresses: []string{"192.0.2.53:53"}}

func TestDSModelForZone(t *testing.T) {
	policy := func(m RolloverMethod) *DnssecPolicy {
		return &DnssecPolicy{Rollover: RolloverPolicy{Method: m}}
	}
	cases := []struct {
		name string
		zd   *ZoneData
		want DSModel
	}{
		{"no policy", &ZoneData{}, DSModelNone},
		{"rollover method none", &ZoneData{DnssecPolicy: policy(RolloverMethodNone)}, DSModelNone},
		{"multi-ds", &ZoneData{DnssecPolicy: policy(RolloverMethodMultiDS)}, DSModelMultiDS},
		{"double-signature", &ZoneData{DnssecPolicy: policy(RolloverMethodDoubleSignature)}, DSModelDoubleSignature},
		{"multi-provider wins over the rollover method", &ZoneData{
			Options:      map[ZoneOption]bool{OptMultiProvider: true},
			DnssecPolicy: policy(RolloverMethodMultiDS),
		}, DSModelMultiProvider},
	}
	for _, tc := range cases {
		if got := dsModelForZone(tc.zd); got != tc.want {
			t.Errorf("%s: model = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestNotifySchemePublishesTheCdsBeforeTheNotify: a NOTIFY(CDS) tells the parent
// to come and read the child's CDS. For a zone the KSK rollover engine does not
// manage nothing published one, so the parent scanned, found nothing, concluded
// there was nothing to do, and both ends reported success while the DS never
// appeared. The updater is slow on purpose: a sender that does not wait for the
// CDS loses the race.
func TestNotifySchemePublishesTheCdsBeforeTheNotify(t *testing.T) {
	r := newDSEngineRig(t, 50*time.Millisecond, true)
	seedKey(t, r.kdb, "example.", DnskeyStateActive, 257, pubA)

	_, rcode, err := r.zd.SyncZoneDelegationViaNotify(context.Background(), r.kdb, r.notifyq,
		dsChangeFor("example.", pubA), testDsyncTarget)
	if err != nil {
		t.Fatalf("SyncZoneDelegationViaNotify: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[int(rcode)])
	}

	waitForEvents(t, r.log, 3)
	events := r.log.snapshot()
	published, notified := eventIndex(events, "published CDS"), eventIndex(events, "notified CDS")
	if published < 0 || notified < 0 || published > notified {
		t.Fatalf("events = %v; the parent must be told to read a CDS only once it is published", events)
	}
	if want := cdsTuplesOf(cdsFor("example.", pubA)); !cdsTupleSetsEqual(servedCDS(t, r.zd), want) {
		t.Errorf("served CDS keyids %v, want %v", tupleKeyids(servedCDS(t, r.zd)), tupleKeyids(want))
	}
}

// TestNotifySchemeSendsNothingItCannotBackWithACds: when the DS engine has no CDS
// to publish, the NOTIFY candidate fails whole -- no NOTIFY(CSYNC) either -- so
// the plan moves on to UPDATE or API instead of stopping at a vacuous success.
func TestNotifySchemeSendsNothingItCannotBackWithACds(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, r *dsEngineRig)
		wantErr string
	}{
		{"keys not managed by tdns and no CDS served", func(t *testing.T, r *dsEngineRig) {},
			"does not manage this zone's keys"},
		{"no key warrants a DS", func(t *testing.T, r *dsEngineRig) {
			seedKey(t, r.kdb, "example.", DnskeyStateRetired, 257, pubA)
		}, "RFC 8078"},
		{"double-signature is not implemented", func(t *testing.T, r *dsEngineRig) {
			seedKey(t, r.kdb, "example.", DnskeyStateActive, 257, pubA)
			r.zd.DnssecPolicy = &DnssecPolicy{Rollover: RolloverPolicy{Method: RolloverMethodDoubleSignature}}
		}, "double-signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newDSEngineRig(t, 0, false)
			tc.setup(t, r)
			syncstate := dsChangeFor("example.", pubA)
			syncstate.NsAdds = []dns.RR{mustRR(t, "example. 3600 IN NS ns2.example.")}

			_, rcode, err := r.zd.SyncZoneDelegationViaNotify(context.Background(), r.kdb, r.notifyq,
				syncstate, testDsyncTarget)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
			}
			if rcode != dns.RcodeServerFailure {
				t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[int(rcode)])
			}
			if n := len(r.notifyq); n != 0 {
				t.Errorf("%d NOTIFY(s) went out from a candidate that could not back its NOTIFY(CDS)", n)
			}
			if got := servedCDS(t, r.zd); len(got) != 0 {
				t.Errorf("a CDS was published (keyids %v)", tupleKeyids(got))
			}
		})
	}
}

// TestNotifySchemeNotifiesForACdsSomeoneElsePublished: a zone whose keys tdns does
// not manage is signed elsewhere, and its signer may well publish a CDS. That CDS
// is not the DS engine's to write, but a NOTIFY(CDS) pointing the parent at it is
// exactly right.
func TestNotifySchemeNotifiesForACdsSomeoneElsePublished(t *testing.T) {
	r := newDSEngineRig(t, 0, false)
	stageCDS(t, r.zd, cdsFor("example.", pubB))

	_, rcode, err := r.zd.SyncZoneDelegationViaNotify(context.Background(), r.kdb, r.notifyq,
		dsChangeFor("example.", pubB), testDsyncTarget)
	if err != nil {
		t.Fatalf("SyncZoneDelegationViaNotify: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[int(rcode)])
	}
	if n := len(r.notifyq); n != 1 {
		t.Fatalf("%d NOTIFY(s) sent, want one NOTIFY(CDS)", n)
	}
	if req := <-r.notifyq; req.RRtype != dns.TypeCDS {
		t.Errorf("sent a NOTIFY(%s), want NOTIFY(CDS)", dns.TypeToString[req.RRtype])
	}
	for _, e := range r.log.snapshot() {
		if strings.Contains(e, "CDS") {
			t.Errorf("the DS engine wrote to a CDS it does not own: %q", e)
		}
	}
	if want := cdsTuplesOf(cdsFor("example.", pubB)); !cdsTupleSetsEqual(servedCDS(t, r.zd), want) {
		t.Errorf("served CDS keyids %v, want the signer's %v", tupleKeyids(servedCDS(t, r.zd)), tupleKeyids(want))
	}
}

// TestNotifySchemeLeavesTheDSToABusyRollover: under multi-DS a rollover phase in
// flight is pushing the DS itself, with its own CDS. Delegation sync must neither
// publish a CDS over it nor notify for it.
func TestNotifySchemeLeavesTheDSToABusyRollover(t *testing.T) {
	r := newDSEngineRig(t, 0, false)
	r.zd.DnssecPolicy = &DnssecPolicy{Rollover: RolloverPolicy{Method: RolloverMethodMultiDS}}
	seedKeyWithIndex(t, r.kdb, "example.", DnskeyStateActive, pubA, 0)
	seedRolloverRowPhase(t, r.kdb, "example.", 0, rolloverPhasePendingParentPush)

	_, rcode, err := r.zd.SyncZoneDelegationViaNotify(context.Background(), r.kdb, r.notifyq,
		dsChangeFor("example.", pubA), testDsyncTarget)
	if err != nil {
		t.Fatalf("SyncZoneDelegationViaNotify: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[int(rcode)])
	}
	if n := len(r.notifyq); n != 0 {
		t.Errorf("%d NOTIFY(s) sent for a DS the rollover engine is pushing", n)
	}
	if got := servedCDS(t, r.zd); len(got) != 0 {
		t.Errorf("published a CDS (keyids %v) while the rollover engine owns the DS", tupleKeyids(got))
	}
}

// TestEnsureCDSUnderMultiDSLeavesTheRolloverAbleToCleanUp: a CDS published for
// delegation sync on a multi-DS zone is the rollover target's, and carries the
// rollover's claim, so the rollover's own cleanup removes it. A target the
// cleanup could never match is refused.
func TestEnsureCDSUnderMultiDSLeavesTheRolloverAbleToCleanUp(t *testing.T) {
	ctx := context.Background()
	multiDS := &DnssecPolicy{Rollover: RolloverPolicy{Method: RolloverMethodMultiDS}}

	t.Run("claimed for the rollover and released by it", func(t *testing.T) {
		r := newDSEngineRig(t, 0, false)
		r.zd.DnssecPolicy = multiDS
		seedKeyWithIndex(t, r.kdb, "example.", DnskeyStateActive, pubA, 3)
		seedKeyWithIndex(t, r.kdb, "example.", DnskeyStateCreated, pubB, 4)

		res := r.kdb.askDSEngine(ctx, DSEngineRequest{cmd: dsCmdEnsureCDS, zd: r.zd})
		if res.err != nil || res.deferred != "" {
			t.Fatalf("ensure: err=%v deferred=%q", res.err, res.deferred)
		}
		// The multi-DS target includes the pre-published created key.
		if want := cdsTuplesOf(cdsFor("example.", pubA, pubB)); !cdsTupleSetsEqual(servedCDS(t, r.zd), want) {
			t.Fatalf("served CDS keyids %v, want %v", tupleKeyids(servedCDS(t, r.zd)), tupleKeyids(want))
		}
		row, err := LoadRolloverZoneRow(r.kdb, "example.")
		if err != nil || row == nil {
			t.Fatalf("LoadRolloverZoneRow: row=%v err=%v", row, err)
		}
		if !row.LastPublishedCdsIndexLow.Valid || row.LastPublishedCdsIndexLow.Int64 != 3 ||
			!row.LastPublishedCdsIndexHigh.Valid || row.LastPublishedCdsIndexHigh.Int64 != 4 {
			t.Fatalf("claim = [%v, %v], want [3, 4]", row.LastPublishedCdsIndexLow, row.LastPublishedCdsIndexHigh)
		}

		cleanupCdsAfterConfirm(ctx, r.zd, r.kdb)
		if got := servedCDS(t, r.zd); len(got) != 0 {
			t.Errorf("the rollover's cleanup left the CDS in place (keyids %v)", tupleKeyids(got))
		}
		row, err = LoadRolloverZoneRow(r.kdb, "example.")
		if err != nil || row == nil {
			t.Fatalf("LoadRolloverZoneRow: row=%v err=%v", row, err)
		}
		if row.LastPublishedCdsIndexLow.Valid || row.LastPublishedCdsIndexHigh.Valid {
			t.Errorf("the claim was not cleared after the CDS was withdrawn")
		}
	})

	t.Run("refused when the rollover could never clean it up", func(t *testing.T) {
		r := newDSEngineRig(t, 0, false)
		r.zd.DnssecPolicy = multiDS
		seedKey(t, r.kdb, "example.", DnskeyStateActive, 257, pubA) // no rollover index

		res := r.kdb.askDSEngine(ctx, DSEngineRequest{cmd: dsCmdEnsureCDS, zd: r.zd})
		if res.err == nil || !strings.Contains(res.err.Error(), "rollover index") {
			t.Fatalf("err = %v, want a refusal naming the missing rollover index", res.err)
		}
		if got := servedCDS(t, r.zd); len(got) != 0 {
			t.Errorf("a CDS nothing could remove was published (keyids %v)", tupleKeyids(got))
		}
	})
}

// TestRolloverNotifyPushWaitsUntilTheCdsIsServed: the rollover's NOTIFY push
// used to queue its CDS and notify at once, racing the parent's fetch against the
// apply. The updater is slow on purpose.
func TestRolloverNotifyPushWaitsUntilTheCdsIsServed(t *testing.T) {
	r := newDSEngineRig(t, 50*time.Millisecond, true)
	keyid := seedKeyWithIndex(t, r.kdb, "example.", DnskeyStateActive, pubA, 0)
	deps := RolloverEngineDeps{
		Zone:            r.zd,
		KDB:             r.kdb,
		NotifyQ:         r.notifyq,
		InternalUpdateQ: r.kdb.UpdateQ,
	}

	res, err := pushDSRRsetViaNotify(context.Background(), deps, testDsyncTarget)
	if err != nil {
		t.Fatalf("pushDSRRsetViaNotify: %v", err)
	}
	if res.Scheme != "NOTIFY" {
		t.Errorf("scheme = %q, want NOTIFY", res.Scheme)
	}

	waitForEvents(t, r.log, 2)
	events := r.log.snapshot()
	published, notified := eventIndex(events, "published CDS"), eventIndex(events, "notified CDS")
	if published < 0 || notified < 0 || published > notified {
		t.Fatalf("events = %v; NOTIFY(CDS) went out before the CDS was served", events)
	}
	if want := cdsTuplesOf(cdsFor("example.", pubA)); !cdsTupleSetsEqual(servedCDS(t, r.zd), want) {
		t.Errorf("served CDS keyids %v, want %v", tupleKeyids(servedCDS(t, r.zd)), tupleKeyids(want))
	}
	row, err := LoadRolloverZoneRow(r.kdb, "example.")
	if err != nil || row == nil {
		t.Fatalf("LoadRolloverZoneRow: row=%v err=%v", row, err)
	}
	if !row.LastPublishedCdsIndexLow.Valid || row.LastPublishedCdsIndexLow.Int64 != 0 {
		t.Errorf("the rollover's claim on its CDS was not recorded: %v", row.LastPublishedCdsIndexLow)
	}
	keyids, _, err := loadCdsPublication(r.kdb, "example.")
	if err != nil || len(keyids) != 1 || keyids[0] != keyid {
		t.Errorf("recorded publication keyids = %v (err %v), want [%d]", keyids, err, keyid)
	}
}

// TestAPublishedCdsFollowsTheKeys: under the none model a CDS stays published
// once delegation sync has asked for it, so it has to follow the keys. A stale one
// would have a parent that polls CDS point the DS at keys the zone no longer uses.
func TestAPublishedCdsFollowsTheKeys(t *testing.T) {
	cases := []struct {
		name   string
		served []string
		setup  func(t *testing.T, r *dsEngineRig)
		want   []string
	}{
		{"a stale CDS is replaced", []string{pubB}, func(t *testing.T, r *dsEngineRig) {
			seedKey(t, r.kdb, "example.", DnskeyStateActive, 257, pubA)
		}, []string{pubA}},
		{"withdrawn when no key warrants a DS", []string{pubA}, func(t *testing.T, r *dsEngineRig) {
			seedKey(t, r.kdb, "example.", DnskeyStateRetired, 257, pubA)
		}, nil},
		{"left alone when tdns does not manage the keys", []string{pubB}, func(t *testing.T, r *dsEngineRig) {},
			[]string{pubB}},
		{"a zone serving no CDS gets none", nil, func(t *testing.T, r *dsEngineRig) {
			seedKey(t, r.kdb, "example.", DnskeyStateActive, 257, pubA)
		}, nil},
		{"a multi-DS zone's CDS is the rollover's", []string{pubB}, func(t *testing.T, r *dsEngineRig) {
			r.zd.DnssecPolicy = &DnssecPolicy{Rollover: RolloverPolicy{Method: RolloverMethodMultiDS}}
			seedKeyWithIndex(t, r.kdb, "example.", DnskeyStateActive, pubA, 0)
		}, []string{pubB}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newDSEngineRig(t, 0, false)
			if len(tc.served) > 0 {
				stageCDS(t, r.zd, cdsFor("example.", tc.served...))
			}
			tc.setup(t, r)

			if res := r.kdb.askDSEngine(context.Background(), DSEngineRequest{cmd: dsCmdKeysChanged, zd: r.zd}); res.err != nil {
				t.Fatalf("keys changed: %v", res.err)
			}
			want := cdsTuplesOf(cdsFor("example.", tc.want...))
			if got := servedCDS(t, r.zd); !cdsTupleSetsEqual(got, want) {
				t.Errorf("served CDS keyids %v, want %v", tupleKeyids(got), tupleKeyids(want))
			}
		})
	}
}

// TestPublishDnskeyRRsTellsTheDSEngineWhenAKskChanges: the DNSKEY RRset is built
// from the keystore in one place, so that is where a KSK change shows. It tells
// the DS engine only when it matters -- a zone serving a CDS whose KSK set
// changed -- and never blocks, since it runs with zd.mu held.
func TestPublishDnskeyRRsTellsTheDSEngineWhenAKskChanges(t *testing.T) {
	newZone := func(t *testing.T, withCDS bool) (*ZoneData, *KeyDB) {
		t.Helper()
		kdb := newTestKeyDB(t)
		kdb.DSEngineQ = make(chan DSEngineRequest, 4)
		zd := testZone(t, "example.", csyncTestZone)
		registerZones(t, zd)
		zd.KeyDB = kdb
		zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
		if withCDS {
			stageCDS(t, zd, cdsFor("example.", pubB))
		}
		return zd, kdb
	}

	t.Run("a KSK change on a zone serving a CDS", func(t *testing.T) {
		zd, kdb := newZone(t, true)
		seedKey(t, kdb, "example.", DnskeyStatePublished, 257, pubA)
		if err := zd.PublishDnskeyRRs(&DnssecKeys{}); err != nil {
			t.Fatalf("PublishDnskeyRRs: %v", err)
		}
		if n := len(kdb.DSEngineQ); n != 1 {
			t.Fatalf("the DS engine was told %d time(s), want once", n)
		}
		if req := <-kdb.DSEngineQ; req.cmd != dsCmdKeysChanged || req.zd != zd {
			t.Errorf("request = {cmd %d, zone %p}, want keys-changed for this zone", req.cmd, req.zd)
		}
		if err := zd.PublishDnskeyRRs(&DnssecKeys{}); err != nil {
			t.Fatalf("PublishDnskeyRRs again: %v", err)
		}
		if n := len(kdb.DSEngineQ); n != 0 {
			t.Errorf("republishing the same KSKs told the DS engine %d time(s)", n)
		}
	})

	t.Run("a zone serving no CDS", func(t *testing.T) {
		zd, kdb := newZone(t, false)
		seedKey(t, kdb, "example.", DnskeyStatePublished, 257, pubA)
		if err := zd.PublishDnskeyRRs(&DnssecKeys{}); err != nil {
			t.Fatalf("PublishDnskeyRRs: %v", err)
		}
		if n := len(kdb.DSEngineQ); n != 0 {
			t.Errorf("told the DS engine %d time(s) about a zone with no CDS to follow", n)
		}
	})

	t.Run("a ZSK change", func(t *testing.T) {
		zd, kdb := newZone(t, true)
		seedKey(t, kdb, "example.", DnskeyStatePublished, 256, pubA)
		if err := zd.PublishDnskeyRRs(&DnssecKeys{}); err != nil {
			t.Fatalf("PublishDnskeyRRs: %v", err)
		}
		if n := len(kdb.DSEngineQ); n != 0 {
			t.Errorf("told the DS engine %d time(s) about a ZSK, which has no DS", n)
		}
	})

	t.Run("a full queue does not block", func(t *testing.T) {
		zd, kdb := newZone(t, true)
		kdb.DSEngineQ = make(chan DSEngineRequest) // nobody reading
		seedKey(t, kdb, "example.", DnskeyStatePublished, 257, pubA)
		done := make(chan error, 1)
		go func() { done <- zd.PublishDnskeyRRs(&DnssecKeys{}) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("PublishDnskeyRRs: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("PublishDnskeyRRs blocked on the DS engine queue with zd.mu held")
		}
	})
}

// TestAskingAnAbsentDSEngineFails: a rollover tick or the delegation syncher that
// asks an engine nobody started must get an error, not wait forever.
func TestAskingAnAbsentDSEngineFails(t *testing.T) {
	req := DSEngineRequest{cmd: dsCmdEnsureCDS, zd: &ZoneData{ZoneName: "example."}}

	t.Run("no queue", func(t *testing.T) {
		res := (&KeyDB{}).askDSEngine(context.Background(), req)
		if !errors.Is(res.err, errDSEngineNotRunning) {
			t.Errorf("err = %v, want errDSEngineNotRunning", res.err)
		}
	})

	t.Run("nobody serving the queue", func(t *testing.T) {
		kdb := &KeyDB{DSEngineQ: make(chan DSEngineRequest)}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		start := time.Now()
		res := kdb.askDSEngine(ctx, req)
		if res.err == nil {
			t.Fatal("no error from a DS engine nobody is running")
		}
		if waited := time.Since(start); waited > 2*time.Second {
			t.Errorf("waited %s for an engine nobody is running", waited)
		}
	})
}
