/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * RFC 2136 §2.3: the zone section of an UPDATE names the zone to be updated.
 * A server that is primary for a parent and for its child must apply the
 * parent's update of the child's delegation to the parent, however many
 * records the update holds.
 */
package tdns

import (
	"context"
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const coHostedChildZone = `child.parent.example.	3600	IN	SOA	ns1.child.parent.example. hostmaster.child.parent.example. 1 7200 1800 604800 7200
child.parent.example.	3600	IN	NS	ns1.child.parent.example.
ns1.child.parent.example.	3600	IN	A	192.0.2.1
`

const otherUpdateZone = `other.example.	3600	IN	SOA	ns.other.example. hostmaster.other.example. 1 7200 1800 604800 7200
other.example.	3600	IN	NS	ns.other.example.
ns.other.example.	3600	IN	A	192.0.2.54
`

// updateNamed runs an update section through UpdateResponder with the given
// zone section. Unsigned, so it stops at validation, after routing and
// classification: see classify.
func updateNamed(t *testing.T, zone string, rrs ...dns.RR) (*DnsUpdateRequest, *dns.Msg) {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(zone)
	m.Ns = append(m.Ns, rrs...)

	cw := &captureWriter{}
	dur := &DnsUpdateRequest{ResponseWriter: cw, Msg: m, Qname: zone, Status: &UpdateStatus{}}
	_ = UpdateResponder(context.Background(), dur, nil)
	if cw.got == nil {
		t.Fatal("responder wrote no response")
	}
	return dur, cw.got
}

// The child zone is served here too, and takes no updates to its own data.
// A DS change routed to it instead of to the parent is refused as a
// ZONE-UPDATE with "zone does not allow DNS UPDATE".
func TestDelegationUpdateGoesToTheZoneInTheZoneSection(t *testing.T) {
	childKeyParent(t)
	child := testSnapshotZone(t, "child.parent.example.", coHostedChildZone)
	child.Options = map[ZoneOption]bool{}

	newDS := mustRR(t, "child.parent.example. 3600 IN DS 2 15 2 0000")
	oldDS := mustRR(t, "child.parent.example. 3600 IN DS 1 15 2 0000")
	oldDS.Header().Class = dns.ClassNONE
	oldDS.Header().Ttl = 0

	for _, tc := range []struct {
		name string
		rrs  []dns.RR
	}{
		// A KSK roll that waits for the parent's DS sends the new DS alone.
		{"one record", []dns.RR{newDS}},
		{"two records", []dns.RR{oldDS, newDS}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dur, resp := updateNamed(t, "parent.example.", tc.rrs...)
			if dur.Status.Type != "CHILD-UPDATE" {
				t.Errorf("classified as %q, want CHILD-UPDATE of parent.example.", dur.Status.Type)
			}
			if found, code, _ := edns0.ExtractEDEFromMsg(resp); found && code == edns0.EDEZoneUpdatesNotAllowed {
				t.Errorf("refused with EDE %d: the update went to the child zone, not the parent", code)
			}
			if resp.Rcode != dns.RcodeFormatError {
				t.Errorf("rcode %s, want FORMERR from validating the unsigned UPDATE in the parent",
					dns.RcodeToString[resp.Rcode])
			}
		})
	}
}

// A zone section that names no zone served here: a one-record update is still
// routed by its owner, as before. The child is not served; its delegation is.
func TestOneRecordUpdateNamingAnUnservedZoneRoutesByOwner(t *testing.T) {
	childKeyParent(t)

	dur, _ := updateNamed(t, "child.parent.example.", mustRR(t, "child.parent.example. 3600 IN DS 2 15 2 0000"))
	if dur.Status.Type != "CHILD-UPDATE" {
		t.Errorf("classified as %q, want CHILD-UPDATE of parent.example.", dur.Status.Type)
	}
}

// RFC 2136 §3.4.1.3: a record outside the named zone is NOTZONE. It is neither
// applied to the named zone nor redirected to the zone its owner is in, even
// when this server serves that zone and it takes updates.
func TestRecordOutsideTheZoneIsNotZone(t *testing.T) {
	childKeyParent(t)
	other := testSnapshotZone(t, "other.example.", otherUpdateZone)
	other.Options = map[ZoneOption]bool{OptAllowUpdates: true}

	outside := mustRR(t, "www.other.example. 3600 IN A 192.0.2.80")
	inside := mustRR(t, "www.parent.example. 3600 IN A 192.0.2.80")

	for _, tc := range []struct {
		name string
		rrs  []dns.RR
	}{
		{"one record", []dns.RR{outside}},
		{"one of two records", []dns.RR{inside, outside}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dur, resp := updateNamed(t, "parent.example.", tc.rrs...)
			if resp.Rcode != dns.RcodeNotZone {
				t.Errorf("rcode %s (type %q), want NOTZONE", dns.RcodeToString[resp.Rcode], dur.Status.Type)
			}
		})
	}
}
