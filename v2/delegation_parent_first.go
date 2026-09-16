/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Removing a nameserver: the parent first, then the zone (#665).
//
// Adding and removing delegation data go in opposite orders. A nameserver is
// added to the zone first and published at the parent after, so a resolver the
// parent sends to it finds it serving. A nameserver is withdrawn at the parent
// first and dropped from the zone after, so the parent never refers resolvers
// to a nameserver the child has already stopped listing.
//
// tdns-auth used to do everything zone-first, and then build the parent's
// transaction from the zone as it had become. For a removal that is the wrong
// order however the transaction is built. A zone that syncs its own delegation
// now works out the parent's transaction from the update BEFORE applying it,
// and applies an update that removes a nameserver only once the parent has
// confirmed it:
//
//  1. Here, first: what the update adds to the delegation, and glue changes for
//     nameservers that stay. Those are child-first changes, and the parent
//     checks that the child serves them.
//  2. The parent: the delegation as it will be after the update, over a scheme
//     whose answer is the parent's verdict (UPDATE or API; a NOTIFY is acted on
//     later, by reading what the child serves, so it cannot confirm anything).
//  3. Here: the update itself, as sent.
//
// If the parent does not confirm, step 1 is undone and nothing else is applied
// -- unless the operator forced it, in which case the update is applied anyway
// and the ordinary zone-first sync follows it.
//
// Updates that remove no nameserver are not handled here at all.

const (
	// parentFirstTimeout bounds step 2. Someone is waiting on the answer: an
	// operator at the CLI, or a DNS UPDATE client.
	parentFirstTimeout = 60 * time.Second

	// Two attempts, not the background sync's backoff: enough for one BADKEY
	// re-bootstrap, and a REFUSED is the parent's answer rather than a
	// condition to wait out while the operator does.
	parentFirstUpdateAttempts = 2
	parentFirstUpdateDelay    = time.Second
)

// ParentNotConfirmedError reports that the parent did not confirm a delegation
// change sent to it before applying it. Nothing was applied to the zone.
type ParentNotConfirmedError struct {
	Parent string
	Err    error
}

func (e *ParentNotConfirmedError) Error() string {
	return fmt.Sprintf("parent %s did not confirm the delegation change: %v", e.Parent, e.Err)
}

func (e *ParentNotConfirmedError) Unwrap() error { return e.Err }

// delegationChange is what one update does to the zone's delegation, worked out
// before it is applied.
type delegationChange struct {
	// status is the parent's transaction: the delegation after the update, and
	// the edits that take the current one there.
	status DelegationSyncStatus
	// removesNS is true when the update takes a nameserver out of the apex NS
	// RRset -- the case that goes to the parent first.
	removesNS bool
	// early is step 1: additions to the delegation, and glue changes for the
	// nameservers that stay. undo reverts exactly early.
	early []dns.RR
	undo  []dns.RR
}

// planDelegationChange works out what actions would do to the delegation,
// from the zone as it stands and the same RFC 2136 semantics the parent's own
// coherence check applies (rrsetAfterActions).
func (zd *ZoneData) planDelegationChange(actions []dns.RR) (delegationChange, error) {
	zone := dns.Fqdn(zd.ZoneName)
	apex, err := zd.GetOwner(zone)
	if err != nil {
		return delegationChange{}, err
	}
	if apex == nil {
		return delegationChange{}, fmt.Errorf("zone %s has no apex", zone)
	}
	currentNS := apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs
	newNS, touched := rrsetAfterActions(zone, dns.TypeNS, currentNS, actions)
	if !touched || len(newNS) == 0 {
		// An update that would empty the NS RRset is not a withdrawal: the
		// applier refuses it, and the parent would refuse it too.
		newNS = currentNS
	}

	var ch delegationChange
	st := &ch.status
	st.ZoneName = zone
	st.Parent = zd.GetParent()
	st.Time = time.Now()

	for _, rr := range newNS {
		st.NewNS = append(st.NewNS, inClassIN(rr))
		if !recordIn(currentNS, rr) {
			st.NsAdds = append(st.NsAdds, inClassIN(rr))
			ch.early = append(ch.early, inClassIN(rr))
			ch.undo = append(ch.undo, removalOf(rr))
		}
	}
	for _, rr := range currentNS {
		if !recordIn(newNS, rr) {
			st.NsRemoves = append(st.NsRemoves, removalOf(rr))
		}
	}
	ch.removesNS = len(st.NsRemoves) > 0

	// Glue for the nameservers of the RESULTING set. A withdrawn nameserver's
	// glue is not listed: the parent-side builders delete it by name
	// (withdrawnGlueOwners), and what the zone does with that name's addresses
	// is the update's own business, applied in step 3.
	oldNames, _ := BailiwickNS(zone, currentNS)
	wasGlue := map[string]bool{}
	for _, name := range oldNames {
		wasGlue[core.CanonicalizeName(dns.Fqdn(name))] = true
	}
	newNames, _ := BailiwickNS(zone, newNS)
	seen := map[string]bool{}
	for _, name := range newNames {
		key := core.CanonicalizeName(dns.Fqdn(name))
		if seen[key] {
			continue
		}
		seen[key] = true

		owner, err := zd.GetOwner(dns.Fqdn(name))
		if err != nil {
			return delegationChange{}, fmt.Errorf("reading the glue of %s: %w", name, err)
		}
		for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			var cur []dns.RR
			if owner != nil {
				cur = owner.RRtypes.GetOnlyRRSet(rrtype).RRs
			}
			after, _ := rrsetAfterActions(dns.Fqdn(name), rrtype, cur, actions)

			newGlue, adds, removes := &st.NewA, &st.AAdds, &st.ARemoves
			if rrtype == dns.TypeAAAA {
				newGlue, adds, removes = &st.NewAAAA, &st.AAAAAdds, &st.AAAARemoves
			}
			for _, rr := range after {
				*newGlue = append(*newGlue, inClassIN(rr))
				if !recordIn(cur, rr) {
					ch.early = append(ch.early, inClassIN(rr))
					ch.undo = append(ch.undo, removalOf(rr))
				}
				// A name that only now becomes a nameserver has no glue at the
				// parent yet, so all of its addresses are additions there.
				if !wasGlue[key] || !recordIn(cur, rr) {
					*adds = append(*adds, inClassIN(rr))
				}
			}
			for _, rr := range cur {
				if recordIn(after, rr) {
					continue
				}
				ch.early = append(ch.early, removalOf(rr))
				ch.undo = append(ch.undo, inClassIN(rr))
				if wasGlue[key] {
					*removes = append(*removes, removalOf(rr))
				}
			}
		}
	}

	st.InSync = len(st.NsAdds)+len(st.NsRemoves)+len(st.AAdds)+len(st.ARemoves)+
		len(st.AAAAAdds)+len(st.AAAARemoves) == 0
	return ch, nil
}

func inClassIN(rr dns.RR) dns.RR {
	c := dns.Copy(rr)
	c.Header().Class = dns.ClassINET
	return c
}

func recordIn(list []dns.RR, rr dns.RR) bool {
	for _, have := range list {
		if sameRecord(have, rr) {
			return true
		}
	}
	return false
}

// lockDelegationChanges takes the zone's delegation lock if the zone syncs its
// own delegation, and returns what releases it (a no-op for any other zone).
//
// Every update to such a zone is applied holding it, not only the removals
// that go to the parent first. A removal's transaction is computed from the
// zone as it stands and may wait up to parentFirstTimeout for the parent; an
// addition applied during that wait changes the delegation underneath it, and
// its own sync to the parent races the removal's.
func (zd *ZoneData) lockDelegationChanges() (unlock func()) {
	if !zd.syncsOwnDelegation() {
		return func() {}
	}
	zd.parentFirstMu.Lock()
	return zd.parentFirstMu.Unlock
}

// syncsOwnDelegation reports whether this server sends the zone's delegation
// to its parent as the zone's own primary. A proxy forwards a change it has
// already seen published, and cannot go first.
func (zd *ZoneData) syncsOwnDelegation() bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.Options[OptParentSync] && !zd.Options[OptParentSyncProxy]
}

// zoneUpdateSubmitter applies one update through the ZoneUpdater and waits for
// the outcome. The channels an update arrives on each have their own.
type zoneUpdateSubmitter func(ctx context.Context, ur UpdateRequest) (ZoneUpdateResult, error)

// parentConfirmer sends the parent a delegation transaction and returns nil
// only when the parent has confirmed it.
type parentConfirmer func(ctx context.Context, status DelegationSyncStatus) (string, error)

// parentConfirmerFor is how a zone asks its parent. A variable so that a test
// can stand in for the parent.
var parentConfirmerFor = func(zd *ZoneData) parentConfirmer {
	return func(ctx context.Context, status DelegationSyncStatus) (string, error) {
		return zd.confirmWithParent(ctx, zd.KeyDB, Globals.ImrEngine, status)
	}
}

// applyParentFirst applies ur the parent-first way when it removes a
// nameserver from a zone that syncs its own delegation. handled is false for
// every other update, which the caller applies as before.
//
// force applies the update even when the parent does not confirm it.
//
// The caller holds the zone's delegation lock (lockDelegationChanges), and holds
// it through applying the update itself when this returns handled == false.
func (zd *ZoneData) applyParentFirst(ctx context.Context, ur UpdateRequest, force bool,
	submit zoneUpdateSubmitter, confirm parentConfirmer) (handled bool, msg string, err error) {

	if !zd.syncsOwnDelegation() {
		return false, "", nil
	}

	change, perr := zd.planDelegationChange(ur.Actions)
	if perr != nil {
		// Not knowing whether the update removes a nameserver is not the same
		// as knowing it does not.
		return true, "", fmt.Errorf("zone %s: cannot work out what the update does to the delegation: %w",
			zd.ZoneName, perr)
	}
	if !change.removesNS {
		return false, "", nil
	}

	// Once started, the three steps finish. A client that hangs up after step
	// 1 must not leave the zone half-changed with nobody to undo it.
	ctx = context.WithoutCancel(ctx)
	parent := zd.GetParent()

	lgDns.Info("delegation change removes a nameserver; asking the parent before applying it",
		"zone", zd.ZoneName, "parent", parent, "update", ur.Description,
		"ns_removes", len(change.status.NsRemoves), "applied_first", len(change.early))

	step := func(actions []dns.RR, note string, parentSyncDone bool) error {
		derived := ur
		derived.Resp = nil
		derived.Actions = actions
		derived.ParentSyncDone = parentSyncDone
		if note != "" {
			derived.Description = ur.Description + " (" + note + ")"
		}
		res, err := submit(ctx, derived)
		if err != nil {
			return err
		}
		return res.Err
	}

	// 1.
	if len(change.early) > 0 {
		if err := step(change.early, "additions, before asking the parent", true); err != nil {
			return true, "", fmt.Errorf("zone %s: applying the additions before asking the parent failed;"+
				" nothing was sent to the parent and nothing else was applied: %w", zd.ZoneName, err)
		}
	}

	// 2.
	cctx, cancel := context.WithTimeout(ctx, parentFirstTimeout)
	cmsg, cerr := confirm(cctx, change.status)
	cancel()

	if cerr == nil {
		// 3.
		if err := step(ur.Actions, "", true); err != nil {
			lgDns.Error("the parent confirmed the delegation change but applying it here failed;"+
				" the parent is ahead of the zone", "zone", zd.ZoneName, "parent", parent, "err", err)
			return true, "", fmt.Errorf("zone %s: parent %s confirmed the change (%s), but applying it here failed: %w",
				zd.ZoneName, parent, cmsg, err)
		}
		lgDns.Info("delegation change applied after the parent confirmed it",
			"zone", zd.ZoneName, "parent", parent, "parent_says", cmsg)
		return true, fmt.Sprintf("Zone %s: applied after parent %s confirmed the delegation change (%s)",
			zd.ZoneName, parent, cmsg), nil
	}

	notConfirmed := &ParentNotConfirmedError{Parent: parent, Err: cerr}

	if force {
		lgDns.Warn("the parent did not confirm the delegation change; applying it anyway, as forced",
			"zone", zd.ZoneName, "parent", parent, "err", cerr)
		// Not ParentSyncDone: the parent does not have this, so the ordinary
		// zone-first sync that follows any delegation change still runs.
		if err := step(ur.Actions, "forced without the parent's confirmation", false); err != nil {
			return true, "", fmt.Errorf("zone %s: %v; applying it anyway failed as well: %w",
				zd.ZoneName, notConfirmed, err)
		}
		return true, fmt.Sprintf("Zone %s: applied WITHOUT the parent's confirmation (forced): %v;"+
			" the change is sent to the parent again now that the zone has it", zd.ZoneName, notConfirmed), nil
	}

	if len(change.undo) > 0 {
		if err := step(change.undo, "undoing the additions: the parent did not confirm", true); err != nil {
			lgDns.Error("the parent did not confirm the delegation change, and undoing the additions failed",
				"zone", zd.ZoneName, "parent", parent, "parent_err", cerr, "err", err)
			return true, "", fmt.Errorf("zone %s: %w; the additions applied before asking could NOT be undone: %v",
				zd.ZoneName, notConfirmed, err)
		}
	}
	lgDns.Warn("the parent did not confirm the delegation change; not applied",
		"zone", zd.ZoneName, "parent", parent, "err", cerr)
	return true, "", notConfirmed
}

// confirmWithParent sends the parent a delegation transaction over a scheme
// whose answer is the parent's verdict, and returns nil only once the parent
// has accepted it.
func (zd *ZoneData) confirmWithParent(ctx context.Context, kdb *KeyDB, imr *Imr,
	status DelegationSyncStatus) (string, error) {

	if kdb == nil {
		return "", fmt.Errorf("zone %s has no keystore", zd.ZoneName)
	}
	if _, err := zd.ResolveParentVia(imr); err != nil {
		return "", err
	}
	plan, err := zd.BuildParentSyncPlan(ctx, kdb, imr, SyncRoleChild)
	if err != nil {
		return "", err
	}
	confirming := confirmingPlan(plan)
	if !confirming.Usable() {
		return "", fmt.Errorf("parent %s offers no scheme that can confirm a change [%s]",
			plan.Parent, confirming.Summary())
	}
	return zd.walkSyncPlan(ctx, confirming, func(cand SyncCandidate) (string, error) {
		switch cand.Scheme {
		case "UPDATE":
			m, _, _, err := zd.sendDelegationUpdate(ctx, kdb, status, cand.Target, childUpdateMode(kdb),
				parentFirstUpdateAttempts, parentFirstUpdateDelay)
			return m, err
		case "API":
			m, _, err := zd.SyncZoneDelegationViaApi(ctx, imr, status, cand.Target)
			return m, err
		}
		return "", fmt.Errorf("scheme %s cannot confirm a change", cand.Scheme)
	})
}

// confirmingPlan keeps the schemes whose answer is the parent's verdict on the
// change: UPDATE (the rcode) and API (the HTTP status and the read-back). A
// NOTIFY only asks the parent to look, later, at what the child serves -- which
// for a withdrawal sent first is exactly what has not changed yet.
func confirmingPlan(plan *ParentSyncPlan) *ParentSyncPlan {
	out := &ParentSyncPlan{Parent: plan.Parent, Validated: plan.Validated}
	out.Skipped = append(out.Skipped, plan.Skipped...)
	for _, c := range plan.Candidates {
		switch c.Scheme {
		case "UPDATE", "API":
			out.Candidates = append(out.Candidates, c)
		default:
			out.Skipped = append(out.Skipped, SkippedScheme{c.Scheme,
				"cannot confirm a change: the parent acts on it later, from what the child serves"})
		}
	}
	return out
}
