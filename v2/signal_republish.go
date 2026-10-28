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
// (queryCDSAtSignalingNames for CDS, atNsFindings for the KEY);
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
//
// With parentsync on, the zone's _sig0key names belong to that bootstrap, and
// use-hsyncparam publishes only pubcds for it (signalSpec.leftToTheBootstrap).
//
// Every publication is recorded in the SignalPublication ledger
// (db_signal_publication.go), and WITHDRAWAL reads that ledger and nothing
// else. The target is an ordinary primary zone of this server's and an
// operator may have published a signal name there by hand, so "we no longer
// want this record" is not by itself authority to delete it -- "we put it
// there" is. ReconcileSignalPublications settles both directions after every
// refresh; see docs/2026-09-03-signal-name-withdrawal.md.

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

// leftToTheBootstrap reports whether use-hsyncparam leaves this spec's signal
// names to the zone's own at-ns SIG(0) bootstrap. With parentsync on, the
// bootstrap publishes its keystore KEY at the _sig0key names
// (publishSig0KeyAtSignalNames). use-hsyncparam would write the apex KEY, which
// need not be that key, into the same RRset under the same ledger row. The
// parent verifies the bootstrap's self-signed UPDATE with the bootstrap's key,
// so the bootstrap keeps those names (#968). It never writes the _dsboot names, and pubcds
// still publishes there.
func (spec signalSpec) leftToTheBootstrap(delSyncChild bool) bool {
	return delSyncChild && spec.prefix == signalPrefixSig0Key
}

// registerSignalReconcileHook appends ReconcileSignalPublications to zdp's
// post-refresh callbacks. Named for what it registers: the callback both
// publishes (RepublishAtSignalNames) and withdraws (signal_withdraw.go).
//
// Not called directly: registerStandardRefreshHooks (v2/zone_hooks.go) is the
// single entry point, and every path that CONSTRUCTS a live ZoneData calls it
// before publishing the zone. See that function for the ordering contract and
// why registration is unconditional and once-per-ZoneData.
//
// Registered for EVERY zone regardless of type, and here that is not merely
// harmless. The publish half self-gates on Options[OptUseHsyncparam], which
// only a secondary can hold (parseZoneOptions drops it on a primary) -- but the
// WITHDRAWAL half also acts on parentsync (OptParentSync), for a zone whose
// own at-ns bootstrap published a _sig0key, and that zone is one this server is
// PRIMARY for. A primary registers this hook to do work, not to no-op.
func (zdp *ZoneData) registerSignalReconcileHook() {
	zdp.OnZonePostRefresh = append(zdp.OnZonePostRefresh, func(zd *ZoneData) {
		zd.ReconcileSignalPublications()
	})
}

// RepublishAtSignalNames is the publish half of the reconciler
// (ReconcileSignalPublications, the registered callback). After a transfer of
// childZD's customer zone it republishes the apex bootstrap RRsets under the
// RFC 9615 signal names if the zone is configured to act on HSYNCPARAM and the
// apex HSYNCPARAM asks for it.
//
// The use-hsyncparam check is here rather than at registration time on purpose:
// the hook is registered once, when the ZoneData is CONSTRUCTED (see
// registerStandardRefreshHooks), while zd.Options is replaced wholesale on
// every config reload. Reading the option when the hook RUNS is what makes both
// enabling and disabling it take effect on `config reload` instead of only on
// restart -- and it is what lets the withdrawal half treat an option removed
// while the daemon was stopped exactly like one removed while it was running.
func (childZD *ZoneData) RepublishAtSignalNames() {
	// signalOptions reads both options under zd.mu; see there for why the read
	// is locked.
	useHsyncparam, delSyncChild := childZD.signalOptions()
	if !useHsyncparam {
		return
	}
	if childZD.leavesSignalsToItsAgents() {
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
		if !spec.active(hp) || spec.leftToTheBootstrap(delSyncChild) {
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
	childZD.publishAtSignalNames(nil, spec.flag, signalSourceHsyncparam, spec.prefix, spec.rrtypes, srcRRs, nsNames, nil)
}

// The signal-name prefixes this file produces and the parent side consumes
// (atNsFindings, queryCDSAtSignalingNames).
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
// atNsFindings will look.
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
// nsNames this server can publish for. A fire-and-forget publication is
// change-gated per target: a signal RRset that already matches is left alone.
// A confirmed one is not (see the loop). With a non-nil only, targets whose
// signal name is not in it are skipped -- that is the SIG(0) rollover refresh,
// which must update the signal names a bootstrap recorded without starting to
// populate ones it never did.
//
// With a non-nil ctx the publication is CONFIRMED: each update is waited on
// until the zone updater reports it applied (or refused, or the wait ran out),
// and only an applied update counts. The bootstrap path needs that -- the
// parent will look for the KEY the moment the ceremony arrives, and an
// enqueued update is not a published record. With a nil ctx the update is
// only enqueued, for callers that must not block (the post-refresh hook).
//
// source is what goes in the SignalPublication ledger: signalSourceHsyncparam
// or signalSourceAtNs. A ledger row is written for every target that ends up
// holding the desired content, INCLUDING one the change gate found already
// correct -- otherwise a restart against a zone that is already published
// would leave the publication unrecorded and therefore unwithdrawable.
//
// Returns the number of targets whose signal RRset is now (or already was)
// the desired content. Zero means the child could not be published at any
// signal name; when there were targets to publish at, that is logged.
func (childZD *ZoneData) publishAtSignalNames(ctx context.Context, what, source, prefix string, rrtypes []uint16, srcRRs []dns.RR, nsNames []string, only map[string]bool) int {
	satisfied, attempted := 0, 0
	for _, tgt := range childZD.signalPublishTargets(prefix, nsNames) {
		if only != nil && !only[tgt.Owner] {
			continue
		}
		attempted++
		desired := reownRRs(srcRRs, tgt.Owner)
		// The change gate reads the published snapshot, which an update still
		// in the queue may be about to change. A fire-and-forget publication
		// can live with that: it runs again after the zone's next refresh. A
		// confirmed one cannot. Its caller acts on the result at once (the
		// parent looks for the KEY), and a withdrawal's delete still queued
		// would remove a record the gate took for published, under a ledger
		// row that says it is there. So a confirmed publication always goes
		// through the updater, which applies the queue in order: its add lands
		// after any delete queued before it. The cost is one serial bump when
		// the record was already served.
		if ctx == nil && signalRRsEqual(tgt.Zone, tgt.Owner, rrtypes, desired) {
			satisfied++
			childZD.recordSignalPublication(tgt, source, prefix)
			continue // already published, change-gated no-op
		}
		if err := tgt.Zone.publishSignalRRs(ctx, tgt.Owner, rrtypes, desired); err != nil {
			lgSignal.Error("failed to publish signal RRset",
				"zone", childZD.ZoneName, "what", what, "ns", tgt.NS,
				"signal", tgt.Owner, "target", tgt.Zone.ZoneName, "err", err)
			continue
		}
		satisfied++
		childZD.recordSignalPublication(tgt, source, prefix)
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
	return childZD.publishAtSignalNames(ctx, "at-ns bootstrap", signalSourceAtNs, signalPrefixSig0Key, []uint16{dns.TypeKEY}, keys, childZD.apexNSNames(), nil)
}

// refreshSig0KeyAtSignalNames re-publishes keys at every _sig0key signal name
// a previous bootstrap recorded in the ledger, after a SIG(0) key rollover, so
// a parent re-verifying via at-ns does not find the retired key. The ledger,
// not the zone, says which names those are: one whose KEY has gone since is
// published again, and a KEY that another publisher put at a name is left
// alone (#968). Signal names never recorded are left alone.
//
// A ledger that cannot be read is an error for the caller: the rollover would
// otherwise report success while every recorded name still holds the retired
// key.
func (childZD *ZoneData) refreshSig0KeyAtSignalNames(ctx context.Context, keys []dns.RR) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	owners, err := childZD.bootstrapSig0KeyOwners()
	if err != nil {
		return 0, err
	}
	return childZD.publishAtSignalNames(ctx, "SIG(0) rollover", signalSourceAtNs, signalPrefixSig0Key, []uint16{dns.TypeKEY}, keys, childZD.apexNSNames(), owners), nil
}

// bootstrapSig0KeyOwners returns the _sig0key signal names the ledger records
// for this zone's own at-ns bootstrap. With no ledger at all, nothing was ever
// recorded, and the answer is no names. A ledger that is there and cannot be
// read is an error, not an empty answer.
func (childZD *ZoneData) bootstrapSig0KeyOwners() (map[string]bool, error) {
	owners := map[string]bool{}
	if !SignalLedgerReadable(childZD.KeyDB) {
		return owners, nil
	}
	rows, err := childZD.KeyDB.SignalPublicationsForZone(childZD.ZoneName)
	if err != nil {
		return nil, fmt.Errorf("reading the signal publication ledger: %w", err)
	}
	for _, p := range rows {
		if p.Source == signalSourceAtNs && p.Prefix == signalPrefixSig0Key {
			owners[p.Owner] = true
		}
	}
	return owners, nil
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
	bound := max(signalPublishApplyTimeout, twiceCadence(target.ZoneName))
	select {
	case res := <-respch:
		if res.Err != nil {
			return fmt.Errorf("signal update for %s was not applied: %w", owner, res.Err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("cancelled while the signal update for %s was being applied: %w", owner, ctx.Err())
	case <-time.After(bound):
		return fmt.Errorf("timed out after %s waiting for the signal update for %s to be applied",
			bound, owner)
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

// multiProviderCopy reports whether the zone's copy carries HSYNC3 records: it
// is a multi-provider zone. Its providers' agents publish its KEY and its CDS
// and CDNSKEY at the _signal names, through their combiners, by the steps of
// the owner's instructions and not by what one copy of the zone says. The
// use-hsyncparam reconciler therefore publishes nothing for it, and what it
// published before is no longer warranted (warrantedSignalOwners). A stale CDS
// left at a _dsboot name would give a parent a DS for a key the zone may since
// have rolled.
func (zd *ZoneData) multiProviderCopy() bool {
	return len(zd.apexRRs(core.TypeHSYNC3)) > 0
}

// leavesSignalsToItsAgents is multiProviderCopy for the publish half, which
// logs the skip once and not at every refresh (signalSkipLogged). A zone whose
// copy loses HSYNC3 says it again if its copy carries HSYNC3 once more.
func (zd *ZoneData) leavesSignalsToItsAgents() bool {
	if !zd.multiProviderCopy() {
		zd.signalSkipLogged.Store(false)
		return false
	}
	if zd.signalSkipLogged.CompareAndSwap(false, true) {
		lgSignal.Info("a multi-provider zone: its agents publish at the _signal names, so use-hsyncparam publishes nothing for it",
			"zone", zd.ZoneName)
	}
	return true
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
