/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// #863: a parent that also holds its child's zone as the unsigned source of a
// multi-provider zone answered every question about the child from that copy
// (#846). The providers' signers add the child's DNSKEY and KEY records
// downstream, so the copy has neither: the SIG(0) bootstrap of the child's key
// never verified, and the coherence check refused every DS UPDATE. With the
// zone option modified-downstream the copy is not answered from, and the
// child's questions go where they would go if the server did not hold it: in
// the rig, to the stub for the child, whose server is the published child.

// ownChildCopy is the child as its source holds it: unsigned, no KEY, and an
// address the published child does not have.
const ownChildCopy = `child.parent.example.	3600	IN	SOA	ns.child.parent.example. hostmaster.child.parent.example. 1 7200 1800 604800 300
child.parent.example.	3600	IN	NS	ns.child.parent.example.
ns.child.parent.example.	3600	IN	A	192.0.2.3
www.child.parent.example.	3600	IN	A	192.0.2.99
`

// The option is a zone option like any other: written in the configuration, in
// any case, it is set on the zone, with no error.
func TestParseZoneOptionsAcceptsModifiedDownstream(t *testing.T) {
	if StringToZoneOption["modified-downstream"] != OptModifiedDownstream || ZoneOptionToString[OptModifiedDownstream] != "modified-downstream" {
		t.Fatal("modified-downstream is not in both option name maps")
	}
	zd := &ZoneData{ZoneName: ownChild}
	zconf := &ZoneConf{Name: ownChild, Type: "primary", OptionsStrs: []string{"Modified-Downstream"}}
	if options := parseZoneOptions(nil, ownChild, zconf, zd); !options[OptModifiedDownstream] {
		t.Fatalf("parseZoneOptions did not set OptModifiedDownstream; got %v", options)
	}
	for _, e := range zd.ErrorList() {
		if e.Type == ConfigError {
			t.Fatalf("ConfigError after parsing modified-downstream: %q", e.Msg)
		}
	}
}

// hostChildCopy registers ownChildCopy as a zone this server holds, with the
// option modified-downstream or without it.
func hostChildCopy(t *testing.T, modified bool) *ZoneData {
	t.Helper()
	zd := testSnapshotZone(t, ownChild, ownChildCopy)
	zd.Options = map[ZoneOption]bool{OptModifiedDownstream: modified}
	return zd
}

// With the option, the child's questions -- its keys, its SIG(0) key, its data
// -- are answered by the published child and validated through the parent's
// DS. The DS is still the parent's own data, and the coherence check on a DS
// UPDATE passes.
func TestModifiedDownstreamZoneIsResolved(t *testing.T) {
	rig := newOwnZoneRig(t)
	hostChildCopy(t, true)
	ctx := context.Background()

	for _, q := range []struct {
		qname string
		qtype uint16
	}{
		{ownChild, dns.TypeDNSKEY},
		{ownChild, dns.TypeKEY},
		{"www." + ownChild, dns.TypeA},
	} {
		what := q.qname + " " + dns.TypeToString[q.qtype]
		if zd := rig.imr.ownZoneForQuestion(q.qname, q.qtype); zd != nil {
			t.Errorf("%s: answered from %s, a zone modified downstream", what, zd.ZoneName)
		}
		resp, err := rig.imr.ImrQueryFresh(ctx, q.qname, q.qtype, dns.ClassINET)
		if err != nil || resp.Error || resp.RRset == nil || len(resp.RRset.RRs) == 0 {
			t.Errorf("%s: %+v (err %v), want the published child's answer", what, resp, err)
			continue
		}
		if !resp.Validated {
			t.Errorf("%s: not validated: the parent's DS for the child should make it secure", what)
		}
		if len(rig.childLog.find(q.qname, q.qtype)) == 0 {
			t.Errorf("%s was not asked of the child's server", what)
		}
		if q.qtype == dns.TypeA && rdataOf(resp.RRset.RRs[0]) != "192.0.2.55" {
			t.Errorf("%s: answer %s, want the published 192.0.2.55, not the copy's", what, rdataOf(resp.RRset.RRs[0]))
		}
	}

	if zd := rig.imr.ownZoneForQuestion(ownChild, dns.TypeDS); zd != rig.parent {
		t.Errorf("%s DS: own zone %v, want %s: the DS is the parent's", ownChild, zd, ownParent)
	}

	// The DS UPDATE #863 saw refused as incoherent: the child's keys could not
	// be looked up.
	next := newFwdSecKey(t, ownChild).dnskey.ToDS(dns.SHA256)
	if err := rig.parent.CheckDelegationCoherenceForUpdate([]dns.RR{next}, imrDnskeyFetcher(rig.imr)); err != nil {
		t.Errorf("coherence check on adding a DS for %s: %v", ownChild, err)
	}
	requireUpstreamNotAsked(t, rig.upLog, ownParent)
}

// Without the option the copy is the zone the world sees, and its questions
// are answered from it, as for any zone the server holds (#846).
func TestChildCopyIsAnsweredFromWithoutTheOption(t *testing.T) {
	rig := newOwnZoneRig(t)
	child := hostChildCopy(t, false)

	for _, qtype := range []uint16{dns.TypeDNSKEY, dns.TypeKEY, dns.TypeSOA} {
		if zd := rig.imr.ownZoneForQuestion(ownChild, qtype); zd != child {
			t.Errorf("%s %s: own zone %v, want the copy", ownChild, dns.TypeToString[qtype], zd)
		}
	}
	resp, err := rig.imr.ImrQuery(context.Background(), "www."+ownChild, dns.TypeA, dns.ClassINET, nil)
	if err != nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 || rdataOf(resp.RRset.RRs[0]) != "192.0.2.99" {
		t.Errorf("www.%s A: %+v (err %v), want the copy's 192.0.2.99", ownChild, resp, err)
	}
	if len(rig.childLog.find("www."+ownChild, dns.TypeA)) != 0 {
		t.Errorf("www.%s A was asked of the child's server", ownChild)
	}
}

// Which questions a zone modified downstream leaves to the resolver: all of
// its own, a DS below it included. The DS at its apex is its parent's.
func TestOwnZoneForQuestionModifiedDownstream(t *testing.T) {
	rig := newOwnZoneRig(t)
	hostChildCopy(t, true)
	cases := []struct {
		qname string
		qtype uint16
		own   bool
	}{
		{ownChild, dns.TypeSOA, false},
		{ownChild, dns.TypeNS, false},
		{"ns." + ownChild, dns.TypeA, false},
		{"nosuch." + ownChild, dns.TypeA, false},
		{"grandchild." + ownChild, dns.TypeDS, false},
		{ownChild, dns.TypeDS, true},
		{"www." + ownParent, dns.TypeA, true},
	}
	for _, c := range cases {
		if got := rig.imr.ownZoneForQuestion(c.qname, c.qtype) != nil; got != c.own {
			t.Errorf("ownZoneForQuestion(%s %s) = %v, want %v", c.qname, dns.TypeToString[c.qtype], got, c.own)
		}
	}
}

// The resolver's start skips the trust anchor of a zone it is to answer from
// once the zone loads (ownZonePending). A zone modified downstream is never
// answered from: its anchor is processed at start, whether the zone is
// registered but not yet answering, or only in the configuration.
func TestModifiedDownstreamZoneIsNotPending(t *testing.T) {
	imr := &Imr{}
	const loaded, configured = "loaded.example.", "configured.example."

	zd := testSnapshotZone(t, loaded, `loaded.example.	3600	IN	SOA	ns.loaded.example. hostmaster.loaded.example. 1 7200 1800 604800 300
loaded.example.	3600	IN	NS	ns.loaded.example.
ns.loaded.example.	3600	IN	A	192.0.2.1
`)
	zd.SetError(ConfigError, "test: not answering yet")
	if !imr.ownZonePending(nil, loaded) {
		t.Fatalf("%s: a registered zone that does not answer yet is not pending", loaded)
	}
	zd.Options = map[ZoneOption]bool{OptModifiedDownstream: true}
	if imr.ownZonePending(nil, loaded) {
		t.Errorf("%s: pending, although it is modified downstream", loaded)
	}

	conf := &Config{Zones: []ZoneConf{{Name: configured}}}
	conf.Internal.AllZones = []string{loaded, configured}
	if !imr.ownZonePending(conf, configured) {
		t.Fatalf("%s: a configured zone that has not loaded is not pending", configured)
	}
	conf.Zones[0].OptionsStrs = []string{" Modified-Downstream "}
	if imr.ownZonePending(conf, configured) {
		t.Errorf("%s: pending, although its configuration says modified-downstream", configured)
	}
}
