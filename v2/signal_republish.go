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
//
// The transfer-driven republish is OPT-IN, per zone, via the secondary-only
// use-hsyncparam option: it writes records into a zone this server is
// authoritative for on the strength of a THIRD PARTY's signaling, so the
// operator of that zone has to say yes. The child-side publishes in this file
// (publishSig0KeyAtSignalNames, refreshSig0KeyAtSignalNames) and the
// satisfiability probe canPublishSig0KeyAtSignal are NOT gated -- there the
// zone being published for is our own and selecting at-ns is the intent.

package tdns

import (
	"context"
	"fmt"
	"time"

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
		prefix:  signalPrefixSig0Key,
		rrtypes: []uint16{dns.TypeKEY},
		active:  (*core.HSYNCPARAM).HasPubkey,
	},
	{
		flag:    "pubcds",
		prefix:  signalPrefixDsboot,
		rrtypes: []uint16{dns.TypeCDS, dns.TypeCDNSKEY},
		active:  (*core.HSYNCPARAM).HasPubcds,
	},
}

// RepublishAtSignalNames is the OnZonePostRefresh callback registered on
// every secondary. After a transfer of childZD's customer zone it republishes
// the apex bootstrap RRsets under the RFC 9615 signal names if the zone is
// configured to act on HSYNCPARAM and the apex HSYNCPARAM asks for it.
//
// The use-hsyncparam check is here rather than at registration time on
// purpose: the hook is registered once, on first load (registering per reload
// would accumulate duplicate callbacks), while zd.Options is replaced
// wholesale on every config reload. Reading the option when the hook RUNS is
// what makes it take effect on `config reload` instead of only on restart.
func (childZD *ZoneData) RepublishAtSignalNames() {
	if !childZD.Options[OptUseHsyncparam] {
		return
	}

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
	// Fire-and-forget (nil ctx): this runs inside a post-refresh hook, which
	// must not block on the zone updater.
	childZD.publishAtSignalNames(nil, spec.flag, spec.prefix, spec.rrtypes, srcRRs, nsNames, false)
}

// The signal-name prefixes this file produces and the parent side consumes
// (LookupChildKeyAtSignal, queryCDSAtSignalingNames).
const (
	signalPrefixSig0Key = "_sig0key"
	signalPrefixDsboot  = "_dsboot"
)

// signalOwnerName is the one spelling of an RFC 9615 signal name:
// <prefix>.<child>._signal.<ns>. Producer and consumers share it so they
// cannot drift.
func signalOwnerName(prefix, child, ns string) string {
	return prefix + "." + dns.Fqdn(child) + "_signal." + dns.Fqdn(ns)
}

// signalPublishTarget is one NS of the child whose signal name this server
// can publish at: the name falls in a zone served here as primary.
type signalPublishTarget struct {
	NS    string
	Owner string
	Zone  *ZoneData
}

// signalPublishTargets lists, for the child's apex NS set, the signal names
// this server is locally primary for. An NS whose signal name is not in a
// local primary zone is a non-starter and is skipped; the draft has the
// nameserver's operator publish it, and that is someone else.
//
// This is also the child-side test of whether the at-ns SIG(0) bootstrap
// method is satisfiable at all (zoneChildBootstrapMethods): a child cannot
// offer at-ns to a parent unless it can put its KEY somewhere the parent's
// LookupChildKeyAtSignal will look.
func (childZD *ZoneData) signalPublishTargets(prefix string, nsNames []string) []signalPublishTarget {
	var out []signalPublishTarget
	for _, ns := range nsNames {
		owner := signalOwnerName(prefix, childZD.ZoneName, ns)
		target := FindZone(owner)
		if target == nil || target.ZoneType != Primary {
			lgSignal.Debug("skipping NS: not locally primary for signal name",
				"zone", childZD.ZoneName, "prefix", prefix, "ns", ns, "signal", owner)
			continue
		}
		out = append(out, signalPublishTarget{NS: ns, Owner: owner, Zone: target})
	}
	return out
}

// publishAtSignalNames publishes srcRRs, re-owned to <prefix>.<child>._signal.<ns>,
// into the local primary zone owning each of those names, for every NS in
// nsNames this server can publish for. Change-gated per target: a signal
// RRset that already matches is left alone. With onlyExisting, targets that
// hold no RRset of these types yet are skipped -- that is the SIG(0) rollover
// refresh, which must update the signal names a bootstrap once populated
// without starting to populate ones it never did.
//
// With a non-nil ctx the publication is CONFIRMED: each update is waited on
// until the zone updater reports it applied (or refused, or the wait ran out),
// and only an applied update counts. The bootstrap path needs that -- the
// parent will look for the KEY the moment the ceremony arrives, and an
// enqueued update is not a published record. With a nil ctx the update is
// only enqueued, for callers that must not block (the post-refresh hook).
//
// Returns the number of targets whose signal RRset is now (or already was)
// the desired content. Zero means the child could not be published at any
// signal name; when there were targets to publish at, that is logged.
func (childZD *ZoneData) publishAtSignalNames(ctx context.Context, what, prefix string, rrtypes []uint16, srcRRs []dns.RR, nsNames []string, onlyExisting bool) int {
	satisfied, attempted := 0, 0
	for _, tgt := range childZD.signalPublishTargets(prefix, nsNames) {
		if onlyExisting && !signalRRsPresent(tgt.Zone, tgt.Owner, rrtypes) {
			continue
		}
		attempted++
		desired := reownRRs(srcRRs, tgt.Owner)
		if signalRRsEqual(tgt.Zone, tgt.Owner, rrtypes, desired) {
			satisfied++
			continue // already published, change-gated no-op
		}
		if err := tgt.Zone.publishSignalRRs(ctx, tgt.Owner, rrtypes, desired); err != nil {
			lgSignal.Error("failed to publish signal RRset",
				"zone", childZD.ZoneName, "what", what, "ns", tgt.NS,
				"signal", tgt.Owner, "target", tgt.Zone.ZoneName, "err", err)
			continue
		}
		satisfied++
		lgSignal.Info("published RRset at signal name",
			"zone", childZD.ZoneName, "what", what, "ns", tgt.NS,
			"signal", tgt.Owner, "target", tgt.Zone.ZoneName, "rrs", len(desired), "confirmed", ctx != nil)
	}
	if attempted > 0 && satisfied == 0 {
		lgSignal.Warn("no signal name could be published for the zone; a parent verifying via at-ns will not find the KEY there",
			"zone", childZD.ZoneName, "what", what, "prefix", prefix, "targets", attempted)
	}
	return satisfied
}

// canPublishSig0KeyAtSignal reports whether at least one of the child's
// nameservers has its _sig0key signal name in a zone this server is primary
// for -- the precondition for offering the at-ns bootstrap method.
func (childZD *ZoneData) canPublishSig0KeyAtSignal() bool {
	return len(childZD.signalPublishTargets(signalPrefixSig0Key, childZD.apexNSNames())) > 0
}

// publishSig0KeyAtSignalNames is the at-ns half of the child's SIG(0)
// bootstrap (draft-ietf-dnsop-delegation-mgmt-via-ddns-02 §"When Child
// Nameserver Is In A DNSSEC-signed Zone"): put the KEY the child is about to
// bootstrap at _sig0key.<child>._signal.<ns> for every NS this server can
// publish for, before the self-signed UPDATE goes to the parent, so the
// parent's at-ns verification finds it. The source is the keystore KEY, not
// the apex RRset: the apex publication is itself an asynchronous zone update
// and may not have landed yet. Returns the number of signal names satisfied.
func (childZD *ZoneData) publishSig0KeyAtSignalNames(ctx context.Context, keys []dns.RR) int {
	if ctx == nil {
		ctx = context.Background()
	}
	return childZD.publishAtSignalNames(ctx, "at-ns bootstrap", signalPrefixSig0Key, []uint16{dns.TypeKEY}, keys, childZD.apexNSNames(), false)
}

// refreshSig0KeyAtSignalNames re-publishes keys at every _sig0key signal name
// a previous bootstrap populated, after a SIG(0) key rollover, so a parent
// re-verifying via at-ns does not find the retired key. Signal names never
// populated are left alone.
func (childZD *ZoneData) refreshSig0KeyAtSignalNames(ctx context.Context, keys []dns.RR) int {
	if ctx == nil {
		ctx = context.Background()
	}
	return childZD.publishAtSignalNames(ctx, "SIG(0) rollover", signalPrefixSig0Key, []uint16{dns.TypeKEY}, keys, childZD.apexNSNames(), true)
}

// signalRRsPresent reports whether the target zone holds any RRset of the
// given types at owner.
func signalRRsPresent(target *ZoneData, owner string, rrtypes []uint16) bool {
	for _, rrtype := range rrtypes {
		if rrset, err := target.GetRRset(owner, rrtype); err == nil && rrset != nil && len(rrset.RRs) > 0 {
			return true
		}
	}
	return false
}

// signalPublishApplyTimeout bounds the confirmed publish's wait for the zone
// updater. A variable so tests can shorten it.
var signalPublishApplyTimeout = UpdateApplyTimeout

// publishSignalRRs replaces the signal-name RRsets in the (primary) target
// zone with the desired RRs. It enqueues a delete-RRset (ClassANY) per
// rrtype followed by the adds (ClassINET) so the result is exactly the
// desired set, re-signed by the normal ZONE-UPDATE path if the target is
// signed.
//
// With a non-nil ctx it waits for the updater's verdict (UpdateRequest.Resp),
// the same promise the DSYNC API handler makes its clients: a nil return then
// means applied and being served, not merely queued. A refused apply, a
// cancelled ctx, or the apply timeout is an error. With a nil ctx it only
// enqueues.
func (target *ZoneData) publishSignalRRs(ctx context.Context, owner string, rrtypes []uint16, desired []dns.RR) error {
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

	ur := UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       target.ZoneName,
		Actions:        actions,
		InternalUpdate: true,
	}
	if ctx == nil {
		target.KeyDB.UpdateQ <- ur
		return nil
	}

	respch := make(chan ZoneUpdateResult, 1)
	ur.Resp = respch
	select {
	case target.KeyDB.UpdateQ <- ur:
	case <-ctx.Done():
		return fmt.Errorf("cancelled while queueing the signal update for %s: %w", owner, ctx.Err())
	}
	select {
	case res := <-respch:
		if res.Err != nil {
			return fmt.Errorf("signal update for %s was not applied: %w", owner, res.Err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("cancelled while the signal update for %s was being applied: %w", owner, ctx.Err())
	case <-time.After(signalPublishApplyTimeout):
		return fmt.Errorf("timed out after %s waiting for the signal update for %s to be applied", signalPublishApplyTimeout, owner)
	}
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
