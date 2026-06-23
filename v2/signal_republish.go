/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

// Republish-at-signal-names consumer (RFC 9615 at-NS bootstrap signaling).
//
// When a tdns-auth secondary transfers a customer zone whose apex carries
// HSYNCPARAM with the pubkey and/or pubcds flag, this consumer republishes
// the customer's apex SIG(0) KEY / CDS(+CDNSKEY) under the RFC 9615
// signaling names, owned by each of the customer's nameservers:
//
//	pubcds -> CDS(/CDNSKEY) at _dsboot.<child>._signal.<ns>
//	pubkey -> KEY (SIG0)    at _sig0key.<child>._signal.<ns>
//
// The signal record lives UNDER THE NS'S ZONE, not the customer zone, so a
// parent/validator can find the child's bootstrap data via the child's
// nameservers and DNSSEC-validate it with those nameservers' own keys. The
// existing CONSUMERS of these names already live in tdns
// (queryCDSAtSignalingNames for CDS, LookupChildKeyAtSignal for the KEY);
// this is the missing PRODUCER on a plain secondary.
//
// The publish targets whichever LOCAL PRIMARY zone the signal name falls in
// (found via FindZone). An NS whose zone we do not locally serve as primary
// is a non-starter and is skipped. The consumer is change-gated: it diffs
// the desired content against what is already published at the signal name
// in the target zone, so a re-transfer of unchanged data is a no-op.

package tdns

import (
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var lgSignal = Logger("signal-republish")

// signalSpec describes one HSYNCPARAM flag's republish behaviour: which apex
// RRtypes feed it and which RFC 9615 owner-name prefix the signal record
// uses. The two specs are otherwise identical machinery.
type signalSpec struct {
	flag    string // "pubkey" | "pubcds" (for logging)
	prefix  string // "_sig0key" | "_dsboot"
	rrtypes []uint16
	active  func(*core.HSYNCPARAM) bool
}

var signalSpecs = []signalSpec{
	{
		flag:    "pubkey",
		prefix:  "_sig0key",
		rrtypes: []uint16{dns.TypeKEY},
		active:  (*core.HSYNCPARAM).HasPubkey,
	},
	{
		flag:    "pubcds",
		prefix:  "_dsboot",
		rrtypes: []uint16{dns.TypeCDS, dns.TypeCDNSKEY},
		active:  (*core.HSYNCPARAM).HasPubcds,
	},
}

// RepublishAtSignalNames is the OnZonePostRefresh callback registered on
// every tdns-auth secondary. After a transfer of childZD's customer zone it
// republishes the apex bootstrap RRsets under the RFC 9615 signal names if
// the apex HSYNCPARAM asks for it. It is always-on but acts only when the
// transferred zone actually carries the relevant flag and this server is
// locally primary for a parent of the signal name.
func (childZD *ZoneData) RepublishAtSignalNames() {
	hp := childZD.apexHsyncparam()
	if hp == nil {
		return
	}

	nsNames := childZD.apexNSNames()
	if len(nsNames) == 0 {
		return
	}

	for _, spec := range signalSpecs {
		if !spec.active(hp) {
			continue
		}
		childZD.republishOneFlag(spec, nsNames)
	}
}

// republishOneFlag handles a single active flag: collect the apex source RRs
// and, for each NS, publish them re-owned to the signal name into the local
// primary zone that owns it.
func (childZD *ZoneData) republishOneFlag(spec signalSpec, nsNames []string) {
	srcRRs := childZD.apexRRsFor(spec.rrtypes)
	if len(srcRRs) == 0 {
		lgSignal.Warn("HSYNCPARAM flag set but apex source RRset is empty",
			"zone", childZD.ZoneName, "flag", spec.flag)
		return
	}

	for _, ns := range nsNames {
		owner := fmt.Sprintf("%s.%s_signal.%s", spec.prefix, childZD.ZoneName, ns)

		target, _ := FindZone(owner)
		if target == nil || target.ZoneType != Primary {
			lgSignal.Debug("skipping NS: not locally primary for signal name",
				"zone", childZD.ZoneName, "flag", spec.flag, "ns", ns, "signal", owner)
			continue
		}

		desired := reownRRs(srcRRs, owner)
		if signalRRsEqual(target, owner, spec.rrtypes, desired) {
			continue // already published, change-gated no-op
		}

		if err := target.publishSignalRRs(owner, spec.rrtypes, desired); err != nil {
			lgSignal.Error("failed to publish signal RRset",
				"zone", childZD.ZoneName, "flag", spec.flag, "ns", ns,
				"signal", owner, "target", target.ZoneName, "err", err)
			continue
		}
		lgSignal.Info("republished apex RRset at signal name",
			"zone", childZD.ZoneName, "flag", spec.flag, "ns", ns,
			"signal", owner, "target", target.ZoneName, "rrs", len(desired))
	}
}

// publishSignalRRs replaces the signal-name RRsets in the (primary) target
// zone with the desired RRs. It enqueues a delete-RRset (ClassANY) per
// rrtype followed by the adds (ClassINET) so the result is exactly the
// desired set, re-signed by the normal ZONE-UPDATE path if the target is
// signed.
func (target *ZoneData) publishSignalRRs(owner string, rrtypes []uint16, desired []dns.RR) error {
	if target.KeyDB == nil || target.KeyDB.UpdateQ == nil {
		return fmt.Errorf("target zone %q has no KeyDB.UpdateQ", target.ZoneName)
	}

	var actions []dns.RR
	for _, rrtype := range rrtypes {
		del := new(dns.ANY)
		del.Hdr = dns.RR_Header{Name: owner, Rrtype: rrtype, Class: dns.ClassANY, Ttl: 0}
		actions = append(actions, del)
	}
	actions = append(actions, desired...)

	target.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       target.ZoneName,
		Actions:        actions,
		InternalUpdate: true,
	}
	return nil
}

// apexRRs returns the apex RRs of the given type, or nil. It reads the apex
// owner directly (not via GetRRset, which panics on a missing apex owner) so
// it is safe on a not-yet-fully-loaded or malformed zone.
func (zd *ZoneData) apexRRs(rrtype uint16) []dns.RR {
	owner, err := zd.GetOwner(zd.ZoneName)
	if err != nil || owner == nil || owner.RRtypes == nil {
		return nil
	}
	rrset, ok := owner.RRtypes.Get(rrtype)
	if !ok {
		return nil
	}
	return rrset.RRs
}

// apexHsyncparam returns the typed apex HSYNCPARAM record, or nil if absent.
func (zd *ZoneData) apexHsyncparam() *core.HSYNCPARAM {
	rrs := zd.apexRRs(core.TypeHSYNCPARAM)
	if len(rrs) == 0 {
		return nil
	}
	prr, ok := rrs[0].(*dns.PrivateRR)
	if !ok {
		return nil
	}
	hp, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return nil
	}
	return hp
}

// apexNSNames returns the (fqdn) nameserver hostnames from the apex NS RRset.
func (zd *ZoneData) apexNSNames() []string {
	var names []string
	for _, rr := range zd.apexRRs(dns.TypeNS) {
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, ns.Ns)
		}
	}
	return names
}

// apexRRsFor collects the apex RRs of the given types (in order), skipping
// types that are absent. Used to gather KEY for pubkey, CDS+CDNSKEY for
// pubcds.
func (zd *ZoneData) apexRRsFor(rrtypes []uint16) []dns.RR {
	var out []dns.RR
	for _, rrtype := range rrtypes {
		out = append(out, zd.apexRRs(rrtype)...)
	}
	return out
}

// reownRRs returns copies of src re-owned to the signal name. The TTL is left
// as-is; the ZONE-UPDATE path clamps it to the target zone's policy TTL.
func reownRRs(src []dns.RR, owner string) []dns.RR {
	out := make([]dns.RR, 0, len(src))
	for _, rr := range src {
		c := dns.Copy(rr)
		c.Header().Name = owner
		out = append(out, c)
	}
	return out
}

// signalRRsEqual reports whether the signal-name RRsets already published in
// the target zone match desired (same set, ignoring TTL). This is the
// change gate: equal -> skip the republish.
func signalRRsEqual(target *ZoneData, owner string, rrtypes []uint16, desired []dns.RR) bool {
	var current []dns.RR
	for _, rrtype := range rrtypes {
		rrset, err := target.GetRRset(owner, rrtype)
		if err != nil || rrset == nil {
			continue
		}
		current = append(current, rrset.RRs...)
	}
	return rrsetContentEqual(current, desired)
}

// rrsetContentEqual compares two RR slices for equal content, order- and
// TTL-insensitive, using dns.IsDuplicate (which ignores TTL).
func rrsetContentEqual(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	matched := make([]bool, len(b))
	for _, ra := range a {
		found := false
		for i, rb := range b {
			if matched[i] {
				continue
			}
			if dns.IsDuplicate(ra, rb) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
