/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A child's DS delete must remove the DS it names (#843). The zone's copy of a
 * DS that was read from text -- the zone file, a journal replay -- keeps the
 * digest in the case it was written in, and the library writes it upper case.
 * The copy in an UPDATE is unpacked from the wire, and is lower case. The
 * delete compared the two as strings, removed nothing, and was answered,
 * signed, notified and logged as done.
 */
package tdns

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const (
	dsdParent = "parent.example."
	dsdChild  = "child.parent.example."
	// The DS the zone file holds, digest upper case as a zone file written
	// by tdns has it.
	dsdOldDS = "child.parent.example. 3600 IN DS 53763 15 2 6F2095DB0A1B2C3D4E5F60718293A4B5C6D7E8F90112233445566778DFEE1027"
	// The DS a KSK roll adds.
	dsdNewDS = "child.parent.example. 3600 IN DS 24680 15 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
	// A DS the zone has never held.
	dsdStrayDS = "child.parent.example. 3600 IN DS 11111 15 2 FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100"
)

const dsdZone = `parent.example.	3600	IN	SOA	ns.parent.example. hostmaster.parent.example. 1 7200 1800 604800 7200
parent.example.	3600	IN	NS	ns.parent.example.
ns.parent.example.	3600	IN	A	192.0.2.53
child.parent.example.	3600	IN	NS	ns1.child.parent.example.
ns1.child.parent.example.	3600	IN	A	192.0.2.54
` + dsdOldDS + `
nods.parent.example.	3600	IN	NS	ns1.nods.parent.example.
ns1.nods.parent.example.	3600	IN	A	192.0.2.55
`

// dsdParentZone is a signed parent that takes child updates through the direct
// backend: online signing, allow-child-updates, a child policy allowing DS.
func dsdParentZone(t *testing.T) (*ZoneData, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := testZone(t, dsdParent, dsdZone)
	registerZones(t, zd)
	zd.ZoneType = Primary
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true, OptAllowChildUpdates: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity: PolicySigValidity{
			Default: 30 * 86400, DNSKEY: 30 * 86400, DS: 30 * 86400,
		},
	}
	zd.UpdatePolicy.Child = UpdatePolicyDetail{
		Type:    "selfsub",
		RRtypes: map[uint16]bool{dns.TypeNS: true, dns.TypeA: true, dns.TypeAAAA: true, dns.TypeDS: true},
		TTL:     3600,
	}
	zd.DelegationBackend = &DirectDelegationBackend{zd: zd, kdb: kdb}
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("initial SignZone: %v", err)
	}
	return zd, kdb
}

// dsdReceived builds the UPDATE the child's delegation syncher sends
// (CreateChildUpdate: a remove is class NONE, TTL 0) and returns its update
// section as the parent reads it off the wire.
func dsdReceived(t *testing.T, adds, removes []string) []dns.RR {
	t.Helper()
	parse := func(in []string) []dns.RR {
		var out []dns.RR
		for _, s := range in {
			rr, err := dns.NewRR(s)
			if err != nil {
				t.Fatalf("NewRR %q: %v", s, err)
			}
			out = append(out, rr)
		}
		return out
	}
	m, err := CreateChildUpdate(dsdParent, dsdChild, parse(adds), parse(removes))
	if err != nil {
		t.Fatalf("CreateChildUpdate: %v", err)
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("packing the UPDATE: %v", err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(wire); err != nil {
		t.Fatalf("unpacking the UPDATE: %v", err)
	}
	return r.Ns
}

func dsdApply(t *testing.T, zd *ZoneData, kdb *KeyDB, actions []dns.RR) (bool, error) {
	t.Helper()
	return zd.ApplyChildUpdateToZoneData(UpdateRequest{
		Cmd: "CHILD-UPDATE", ZoneName: dsdParent, Actions: actions, Validated: true, Trusted: true,
	}, kdb)
}

// dsdKeyTags returns the key tags of the DS RRset the zone serves for owner.
func dsdKeyTags(t *testing.T, zd *ZoneData, owner string) []uint16 {
	t.Helper()
	od := getOwnerFrom(zd.publishedSnapshot(), owner)
	if od == nil {
		t.Fatalf("%s is not in the published zone", owner)
	}
	var tags []uint16
	for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypeDS).RRs {
		tags = append(tags, rr.(*dns.DS).KeyTag)
	}
	return tags
}

func dsdDeltaCount(t *testing.T, kdb *KeyDB) int {
	t.Helper()
	deltas, err := kdb.LoadZoneDeltas(dsdParent)
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	return len(deltas)
}

func dsdDrain(q chan NotifyRequest) {
	for len(q) > 0 {
		<-q
	}
}

// The case in #843: the zone holds the child's old DS from its zone file, the
// child adds the DS for its new KSK, and then deletes the old one.
func TestChildUpdateDeletesDSReadFromZoneFile(t *testing.T) {
	notifyq := withNotifyQ(t, 8)
	zd, kdb := dsdParentZone(t)
	zd.Notify = []PeerConf{{Addr: aDownstream}}

	if updated, err := dsdApply(t, zd, kdb, dsdReceived(t, []string{dsdNewDS}, nil)); err != nil || !updated {
		t.Fatalf("adding the new DS: updated=%v err=%v", updated, err)
	}
	if got := dsdKeyTags(t, zd, dsdChild); len(got) != 2 {
		t.Fatalf("after the add the zone serves DS %v, want the old and the new", got)
	}
	dsdDrain(notifyq)
	serialBefore := zd.CurrentSerial
	deltasBefore := dsdDeltaCount(t, kdb)

	updated, err := dsdApply(t, zd, kdb, dsdReceived(t, nil, []string{dsdOldDS}))
	if err != nil || !updated {
		t.Fatalf("deleting the old DS: updated=%v err=%v", updated, err)
	}

	if got := dsdKeyTags(t, zd, dsdChild); len(got) != 1 || got[0] != 24680 {
		t.Errorf("after the delete the zone serves DS %v, want [24680]", got)
	}
	if n := sigCount(t, zd, dsdChild, dns.TypeDS); n == 0 {
		t.Error("the DS RRset left after the delete is unsigned")
	}
	if !serialNewer(zd.CurrentSerial, serialBefore) {
		t.Errorf("serial %d did not move past %d", zd.CurrentSerial, serialBefore)
	}
	if got := len(notifyq); got != 1 {
		t.Errorf("%d NOTIFYs for the delete, want 1", got)
	}

	// The journal carries the delete, or a restart brings the DS back.
	deltas, err := kdb.LoadZoneDeltas(dsdParent)
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	if len(deltas) != deltasBefore+1 {
		t.Fatalf("%d journal deltas after the delete, want %d", len(deltas), deltasBefore+1)
	}
	journalled := false
	for _, row := range deltas[len(deltas)-1].RRs {
		rr, err := dns.NewRR(row.RR)
		if err != nil {
			t.Fatalf("journal row %q: %v", row.RR, err)
		}
		if ds, ok := rr.(*dns.DS); ok && row.Action == ZoneDeltaDel && ds.KeyTag == 53763 {
			journalled = true
		}
	}
	if !journalled {
		t.Errorf("the journal has no delete of DS 53763: %+v", deltas[len(deltas)-1].RRs)
	}
}

// The same comparison decides whether an add is a duplicate: the child's add
// of a DS the zone file already holds is not a second copy of it.
func TestChildUpdateReAddOfDSReadFromZoneFileAddsNoDuplicate(t *testing.T) {
	zd, kdb := dsdParentZone(t)
	if _, err := dsdApply(t, zd, kdb, dsdReceived(t, []string{dsdOldDS}, nil)); err != nil {
		t.Fatalf("re-adding the DS: %v", err)
	}
	if got := dsdKeyTags(t, zd, dsdChild); len(got) != 1 || got[0] != 53763 {
		t.Errorf("after the re-add the zone serves DS %v, want [53763]", got)
	}
}

// A delete of a record the zone does not hold changes nothing, and must not
// say that it did: no publish, no journal row, no NOTIFY, and an error rather
// than success, which the child's syncher would take as done.
func TestChildUpdateDeleteOfAbsentRecordIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name          string
		adds, removes []string
	}{
		{"DS not in the RRset", nil, []string{dsdStrayDS}},
		{"no DS RRset at the owner", nil,
			[]string{strings.Replace(dsdStrayDS, dsdChild, "nods.parent.example.", 1)}},
		{"unknown owner", nil,
			[]string{strings.Replace(dsdStrayDS, dsdChild, "gone.parent.example.", 1)}},
		{"with an add in the same update", []string{dsdNewDS}, []string{dsdStrayDS}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			notifyq := withNotifyQ(t, 8)
			zd, kdb := dsdParentZone(t)
			zd.Notify = []PeerConf{{Addr: aDownstream}}
			update := dsdReceived(t, tc.adds, tc.removes)

			serialBefore := zd.CurrentSerial
			deltasBefore := dsdDeltaCount(t, kdb)

			updated, err := dsdApply(t, zd, kdb, update)
			var absent *ChildDeleteNotInZoneError
			if !errors.As(err, &absent) {
				t.Errorf("err = %v, want a ChildDeleteNotInZoneError", err)
			}
			if updated {
				t.Error("updated=true for an update that must change nothing")
			}
			if zd.CurrentSerial != serialBefore {
				t.Errorf("serial moved from %d to %d", serialBefore, zd.CurrentSerial)
			}
			if got := dsdDeltaCount(t, kdb); got != deltasBefore {
				t.Errorf("%d journal deltas, want %d", got, deltasBefore)
			}
			if got := len(notifyq); got != 0 {
				t.Errorf("%d NOTIFYs, want none", got)
			}
			// Nothing in the update is applied, the add included.
			if got := dsdKeyTags(t, zd, dsdChild); len(got) != 1 || got[0] != 53763 {
				t.Errorf("the zone serves DS %v, want [53763] as before", got)
			}
		})
	}
}

// The same refusal as the child sees it: through the ZoneUpdater and the
// RFC 2136 responder, with the log the updater writes.
func TestChildUpdateDeleteOfAbsentRecordAnswersNXRRSET(t *testing.T) {
	notifyq := withNotifyQ(t, 8)
	zd, kdb := dsdParentZone(t)
	zd.Notify = []PeerConf{{Addr: aDownstream}}

	var logbuf bytes.Buffer
	prev := lg
	lg = slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lg = prev })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updateq := make(chan UpdateRequest, 4)
	go func() {
		for {
			select {
			case ur := <-updateq:
				kdb.applyUpdate(ctx, ur)
			case <-ctx.Done():
				return
			}
		}
	}()

	serialBefore := zd.CurrentSerial
	deltasBefore := dsdDeltaCount(t, kdb)

	req := UpdateRequest{
		Cmd: "CHILD-UPDATE", ZoneName: dsdParent, Actions: dsdReceived(t, nil, []string{dsdStrayDS}),
		Validated: true, Trusted: true,
	}
	w := &chanResponseWriter{ch: make(chan *dns.Msg, 1)}
	m := new(dns.Msg)
	m.SetUpdate(dsdParent)
	m.SetEdns0(1232, true)
	if err := answerAfterApply(ctx, w, m, req, updateq, dns.RcodeSuccess); err != nil {
		t.Fatalf("answerAfterApply: %v", err)
	}
	var reply *dns.Msg
	select {
	case reply = <-w.ch:
	case <-time.After(10 * time.Second):
		t.Fatal("no answer")
	}

	if reply.Rcode != dns.RcodeNXRrset {
		t.Errorf("rcode = %s, want NXRRSET", dns.RcodeToString[reply.Rcode])
	}
	found := false
	if opt := reply.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ede, ok := o.(*dns.EDNS0_EDE); ok && ede.InfoCode == edns0.EDEZoneUpdateNotApplied &&
				strings.Contains(ede.ExtraText, "11111") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no EDE naming the record that is not in the zone: %v", reply.IsEdns0())
	}
	if zd.CurrentSerial != serialBefore {
		t.Errorf("serial moved from %d to %d", serialBefore, zd.CurrentSerial)
	}
	if got := dsdDeltaCount(t, kdb); got != deltasBefore {
		t.Errorf("%d journal deltas, want %d", got, deltasBefore)
	}
	if got := len(notifyq); got != 0 {
		t.Errorf("%d NOTIFYs, want none", got)
	}
	if strings.Contains(logbuf.String(), "CHILD-UPDATE DELETED") {
		t.Errorf("the updater logged a delete that did not happen:\n%s", logbuf.String())
	}
}
