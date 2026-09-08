/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// The childsync-proxy's advertisement reconciler: the parent-side analogue
// of the child-side proxy's ProxyUpdatePreconditionCheck. It compares what
// this agent needs advertised in the parent zone -- the DSYNC RRset, the API
// service description, the target addresses, the bootstrap SVCB and the
// UPDATE receiver's SIG(0) KEY -- against what the served (transferred) copy
// carries, and hands the difference to the push engine. It never publishes
// into the agent's own copy of the zone, and it never touches the network
// itself (design §5.3, amendment A-2).
//
// The loop it closes: the agent asks for records, the primary publishes
// them, the next transfer brings them back, the diff goes empty, the warning
// clears. NotifyResponder's advertisesDsyncNotify gate reads the same
// transferred _dsync RRset, so the NOTIFY receiver comes up exactly when the
// advertisement has landed.

// ChildSyncProxyState is what stands between this agent and being a working
// DSYNC receiver for its parent zone.
type ChildSyncProxyState string

const (
	// The served parent zone carries every record the advertisement needs and
	// the agent holds the private half of the published receiver KEY.
	ChildSyncProxyReady ChildSyncProxyState = "ready"
	// A delta exists between what this agent wants advertised and what the
	// parent zone serves, and it has been handed to the push engine.
	ChildSyncProxyPublishing ChildSyncProxyState = "publishing"
	// A delta exists and nothing delivers it automatically: the operator
	// must publish the block at the primary.
	ChildSyncProxyWaiting ChildSyncProxyState = "waiting-for-publication"
	// A KEY is published at the UPDATE target and the agent does not hold
	// its private half. Do not mint a competing key.
	ChildSyncProxyForeignKey ChildSyncProxyState = "foreign-key"
	// The parent zone has not been transferred yet; nothing can be decided.
	ChildSyncProxyNoZone ChildSyncProxyState = "no-zone-data"
)

// ChildSyncProxyStatus is the operator's view of the advertisement.
type ChildSyncProxyStatus struct {
	State ChildSyncProxyState `json:"state"`
	// Delta counts the records the served zone still lacks at the last
	// reconcile. Zero in the ready state.
	Delta int `json:"delta"`
	// Instruction is the nsupdate(1) block that publishes the delta, when
	// nothing automatic delivers it.
	Instruction   string    `json:"instruction,omitempty"`
	LastReconcile time.Time `json:"last_reconcile,omitempty"`
	Error         string    `json:"error,omitempty"`
}

func (zd *ZoneData) setChildSyncProxyStatus(st ChildSyncProxyStatus) {
	zd.mu.Lock()
	zd.childSyncProxy = &st
	zd.mu.Unlock()
}

// ChildSyncProxyStatus reports the last reconcile's outcome.
func (zd *ZoneData) ChildSyncProxyStatus() ChildSyncProxyStatus {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.childSyncProxy == nil {
		return ChildSyncProxyStatus{State: ChildSyncProxyNoZone}
	}
	return *zd.childSyncProxy
}

const childSyncProxyWarningPrefix = "childsync-proxy advertisement: "

// receiverKeyState is what the reconciler found at the UPDATE target.
type receiverKeyState int

const (
	receiverKeyNotWanted receiverKeyState = iota // the UPDATE scheme is not offered, or has no target
	receiverKeyPublished                         // present, and ours
	receiverKeyMissing                           // absent: ours is in the delta
	receiverKeyForeign                           // present, and not ours
)

// advertisementDelta computes everything the served parent zone still lacks
// for this agent's DSYNC service: the DSYNC publication as
// BuildDsyncPublication builds it, plus the UPDATE receiver's SIG(0) KEY at
// the UPDATE target. It publishes nothing.
func (zd *ZoneData) advertisementDelta() ([]dns.RR, receiverKeyState, error) {
	pub, err := zd.BuildDsyncPublication()
	if err != nil {
		return nil, receiverKeyNotWanted, err
	}
	actions := pub.Actions()
	keyState, keyRR, err := zd.receiverKeyDelta()
	if err != nil {
		return nil, keyState, err
	}
	if keyRR != nil {
		actions = append(actions, keyRR)
	}
	return actions, keyState, nil
}

// receiverKeyDelta is §5.3 step 3, the KEY at the UPDATE target: present and
// ours is fine; present and not ours is a foreign key, and no competing key
// is minted; absent means ours goes into the delta -- generated in the
// keystore if there is none, and never published locally, the same split
// proxyEnsureSig0Key makes on the child side, for the same reason.
func (zd *ZoneData) receiverKeyDelta() (receiverKeyState, dns.RR, error) {
	dsc := ChildSyncConfig()
	if !dsyncSchemeConfigured(dsc.Schemes, "update") {
		return receiverKeyNotWanted, nil, nil
	}
	target := DsyncUpdateTargetName(zd.ZoneName)
	if target == "" || dsyncUpdateTargetIsZoneApex(zd.ZoneName, target) {
		return receiverKeyNotWanted, nil, nil
	}
	if zd.KeyDB == nil {
		return receiverKeyNotWanted, nil, fmt.Errorf("no keystore to hold the receiver key for %s", target)
	}

	var published []dns.RR
	if owner, err := zd.GetOwner(target); err == nil && owner != nil {
		if rrset, ok := owner.RRtypes.Get(dns.TypeKEY); ok {
			published = rrset.RRs
		}
	}
	sak, err := zd.KeyDB.GetSig0Keys(target, Sig0StateActive)
	if err != nil {
		return receiverKeyNotWanted, nil, fmt.Errorf("reading the keystore for %s: %w", target, err)
	}
	if len(published) > 0 {
		if sak != nil {
			for _, rr := range published {
				pub, ok := rr.(*dns.KEY)
				if !ok {
					continue
				}
				for _, held := range sak.Keys {
					if keyRRSameKey(&held.KeyRR, pub) {
						return receiverKeyPublished, nil, nil
					}
				}
			}
		}
		return receiverKeyForeign, nil, nil
	}

	if sak == nil || len(sak.Keys) == 0 {
		alg, aerr := parseKeygenAlgorithm(childSyncKeygenAlgorithm(), dns.ED25519)
		if aerr != nil {
			return receiverKeyMissing, nil, aerr
		}
		kp := KeystorePost{
			Command:    "sig0-mgmt",
			SubCommand: "generate",
			Zone:       zd.ZoneName,
			Keyname:    target,
			Algorithm:  alg,
			State:      Sig0StateActive,
			Creator:    "childsync-proxy",
		}
		if _, gerr := zd.KeyDB.Sig0KeyMgmt(nil, kp); gerr != nil {
			return receiverKeyMissing, nil, fmt.Errorf("generating the receiver SIG(0) key for %s: %w", target, gerr)
		}
		sak, err = zd.KeyDB.GetSig0Keys(target, Sig0StateActive)
		if err != nil || sak == nil || len(sak.Keys) == 0 {
			return receiverKeyMissing, nil, fmt.Errorf("no active SIG(0) key for %s after generating one", target)
		}
		lg.Info("childsync-proxy: generated the UPDATE receiver's SIG(0) key; it stays in the keystore and is published at the parent primary",
			"zone", zd.ZoneName, "name", target)
	}
	keyRR := sak.Keys[0].KeyRR
	keyRR.Hdr.Name = target
	keyRR.Hdr.Class = dns.ClassINET
	keyRR.Hdr.Ttl = 7200
	return receiverKeyMissing, &keyRR, nil
}

// keyRRSameKey compares two KEY records on RDATA -- flags, protocol,
// algorithm, public key -- ignoring owner and TTL, which are not the key's
// identity: one side is read from the served zone, the other from the
// keystore.
func keyRRSameKey(a, b *dns.KEY) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Flags == b.Flags && a.Protocol == b.Protocol && a.Algorithm == b.Algorithm && a.PublicKey == b.PublicKey
}

// childSyncKeygenAlgorithm is the algorithm for a generated receiver key:
// the childsync block's keygen setting, else the parentsync block's (which
// is what ParentSig0KeyPrep reads on tdns-auth), else ED25519.
func childSyncKeygenAlgorithm() string {
	if a := ChildSyncConfig().Update.Keygen.Algorithm; a != "" {
		return a
	}
	return ParentSyncConfig().Update.Keygen.Algorithm
}

// ReconcileChildSyncAdvertisement compares the advertisement this agent needs
// against what the served zone carries and acts on the difference: an enqueue
// to the push engine when the zone's writer delivers to the network, an
// instruction block and a warning otherwise. Idempotent, in-memory, and cheap
// enough to run on every refresh.
func (zd *ZoneData) ReconcileChildSyncAdvertisement() ChildSyncProxyState {
	now := time.Now()
	if !zd.HasPublishedData() {
		zd.setChildSyncProxyStatus(ChildSyncProxyStatus{State: ChildSyncProxyNoZone, LastReconcile: now})
		return ChildSyncProxyNoZone
	}

	actions, keyState, err := zd.advertisementDelta()
	if err != nil {
		lg.Error("childsync-proxy: could not compute the advertisement", "zone", zd.ZoneName, "err", err)
		zd.setChildSyncProxyStatus(ChildSyncProxyStatus{State: ChildSyncProxyWaiting, Error: err.Error(), LastReconcile: now})
		zd.SetError(DelegationSyncWarning, "%scould not be computed: %v", childSyncProxyWarningPrefix, err)
		return ChildSyncProxyWaiting
	}

	_, _, async := zd.asyncParentWriter()
	st := ChildSyncProxyStatus{Delta: len(actions), LastReconcile: now}
	switch {
	case keyState == receiverKeyForeign:
		st.State = ChildSyncProxyForeignKey
	case len(actions) == 0:
		st.State = ChildSyncProxyReady
	case !async:
		st.State = ChildSyncProxyWaiting
	default:
		st.State = ChildSyncProxyPublishing
	}
	if len(actions) > 0 {
		if async {
			enqueueParentPush(ParentPushRequest{Kind: ParentPushAdvertisement, ZoneData: zd, Reason: "advertisement reconcile"})
		} else {
			st.Instruction = RenderNsupdateBlock(zd.ZoneName, zd.upstreamAddrs(), "", actions)
		}
	}
	zd.setChildSyncProxyStatus(st)

	switch st.State {
	case ChildSyncProxyReady, ChildSyncProxyPublishing:
		zd.clearPrefixedWarning(childSyncProxyWarningPrefix)
	case ChildSyncProxyWaiting:
		zd.SetError(DelegationSyncWarning, "%swaiting for publication at the parent primary, %d record(s) missing;"+
			" `zone childsync proxy-status` prints the nsupdate block", childSyncProxyWarningPrefix, len(actions))
	case ChildSyncProxyForeignKey:
		zd.SetError(DelegationSyncWarning, "%sa KEY this agent does not hold is published at %s; no competing key is minted,"+
			" and the UPDATE scheme and KeyState answers cannot be signed until it is removed",
			childSyncProxyWarningPrefix, DsyncUpdateTargetName(zd.ZoneName))
	}
	lg.Info("childsync-proxy: advertisement reconciled", "zone", zd.ZoneName, "state", st.State, "delta", st.Delta)
	return st.State
}

// ChildSyncProxyPostRefresh is the refresh hook's body and SetupZoneSync's
// proxy path: reconcile the advertisement, then ask the push engine to
// reconcile every child the store knows (§6.4). In-memory work and
// non-blocking enqueues only; the hook runs on the refresh engine's own
// goroutine on first load and on a pool worker after that, and neither may
// wait on a primary (A-2).
func (zd *ZoneData) ChildSyncProxyPostRefresh() {
	zd.ReconcileChildSyncAdvertisement()
	if _, _, async := zd.asyncParentWriter(); async {
		enqueueParentPush(ParentPushRequest{Kind: ParentPushReconcile, ZoneData: zd, Reason: "refresh reconcile"})
	}
}

// registerChildSyncProxyHook attaches the PostRefresh hook. Called from
// registerStandardRefreshHooks for every zone, once, at construction; the
// closure self-gates on the option so enabling it on reload takes effect.
func (zdp *ZoneData) registerChildSyncProxyHook() {
	zdp.OnZonePostRefresh = append(zdp.OnZonePostRefresh, func(zd *ZoneData) {
		if !zd.childSyncProxyEnabled() {
			return
		}
		zd.ChildSyncProxyPostRefresh()
	})
}

func (zd *ZoneData) childSyncProxyEnabled() bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.Options[OptChildSyncProxy]
}
