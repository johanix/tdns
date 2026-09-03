package tdns

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

// SendDelegationUpdate is the single child-side UPDATE sender. Both the
// tdns-auth child path and the tdns-agent proxy produce a DelegationSyncStatus
// and call this; the role only supplies the mode default (child: delta, proxy:
// replace). The §10.8 UPDATE gate stays in updateGateBlocked, not here.
func (zd *ZoneData) SendDelegationUpdate(ctx context.Context, kdb *KeyDB,
	syncstate DelegationSyncStatus, target *DsyncTarget, mode string) (string, uint8, UpdateResult, error) {

	if target == nil || len(target.Addresses) == 0 {
		return "", 0, UpdateResult{}, fmt.Errorf("SendDelegationUpdate: no usable UPDATE target for %s", zd.ZoneName)
	}
	if err := zd.resolveParentZone(); err != nil {
		return "", 0, UpdateResult{}, fmt.Errorf("SendDelegationUpdate: %w", err)
	}

	parent := zd.GetParent()
	m, err := buildDelegationUpdate(parent, zd.ZoneName, syncstate, mode)
	if err != nil {
		return "", 0, UpdateResult{}, err
	}

	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil {
		return "", 0, UpdateResult{}, fmt.Errorf("keystore lookup for %s: %w", zd.ZoneName, err)
	}
	if sak == nil || len(sak.Keys) == 0 {
		return "", 0, UpdateResult{}, fmt.Errorf("no active SIG(0) key for %s", zd.ZoneName)
	}
	smsg, err := SignMsg(*m, zd.ZoneName, sak)
	if err != nil {
		return "", 0, UpdateResult{}, err
	}
	if smsg == nil {
		return "", 0, UpdateResult{}, fmt.Errorf("signing UPDATE for %s produced no message and no error", zd.ZoneName)
	}

	lgDns.Info("SendDelegationUpdate: sending the signed update",
		"zone", zd.ZoneName, "target", target.Name, "addresses", target.Addresses, "port", target.Port)

	rcode, ur, err := zd.SendUpdateWithRetry(ctx, smsg, parent, target.Addresses)
	if err != nil {
		return "", 0, ur, err
	}
	msg := fmt.Sprintf("SendUpdate(%s) returned rcode %s", parent, dns.RcodeToString[rcode])
	lgDns.Info("SendDelegationUpdate: update sent",
		"zone", zd.ZoneName, "parent", parent, "mode", mode, "rcode", dns.RcodeToString[rcode])
	return msg, uint8(rcode), ur, nil
}

func buildDelegationUpdate(parent, child string, syncstate DelegationSyncStatus, mode string) (*dns.Msg, error) {
	if mode == UpdateModeReplace {
		lgDns.Info("SendDelegationUpdate: using replace mode", "zone", child)
		return CreateChildReplaceUpdateWithDS(parent, child,
			syncstate.NewNS, syncstate.NewA, syncstate.NewAAAA,
			syncstate.NewDS, syncstate.NewDSKnown)
	}
	lgDns.Info("SendDelegationUpdate: using delta mode", "zone", child)
	adds := append([]dns.RR{}, syncstate.NsAdds...)
	adds = append(adds, syncstate.AAdds...)
	adds = append(adds, syncstate.AAAAAdds...)
	adds = append(adds, syncstate.DSAdds...)
	removes := append([]dns.RR{}, syncstate.NsRemoves...)
	removes = append(removes, syncstate.ARemoves...)
	removes = append(removes, syncstate.AAAARemoves...)
	removes = append(removes, syncstate.DSRemoves...)
	return CreateChildUpdate(parent, child, adds, removes)
}

// apexKEYEnsurer is the one role-dependent step of SIG(0) bootstrap: the KEY
// RR must be at the child apex before the ceremony is sent. tdns-auth
// publishes it; the proxy waits for the operator (the §10.8 WAITING state)
// and is a no-op once READY.
type apexKEYEnsurer interface {
	EnsureApexKEY() error
}

type authApexKEY struct {
	zd  *ZoneData
	kdb *KeyDB
	alg uint8
}

func (a authApexKEY) EnsureApexKEY() error {
	return a.zd.Sig0KeyPreparation(a.zd.ZoneName, a.alg, a.kdb)
}

type proxyApexKEY struct{}

func (proxyApexKEY) EnsureApexKEY() error { return nil }

func (zd *ZoneData) bootstrapSig0Key(ctx context.Context, alg uint8, apex apexKEYEnsurer) (string, UpdateResult, error) {
	if err := apex.EnsureApexKEY(); err != nil {
		return "", UpdateResult{}, err
	}
	return zd.bootstrapSig0KeyWithParent(ctx, alg, zd.zoneChildBootstrapMethods())
}

// resolveParentZone fills the zone's parent when unset or still the old "."
// sentinel. Error-only wrapper for callers that read the field afterwards.
func (zd *ZoneData) resolveParentZone() error {
	_, err := zd.ResolveParent()
	return err
}

// --- zd.parent: one owner, one lazy resolve -------------------------------
//
// parentMu, not zd.mu. zd.mu guards zone content, is held across long
// operations, and is not reentrant -- the whole setErrorLocked/errorListLocked
// family exists because of that. Folding a lazily-initialised string into it
// would put every parent read at risk of deadlocking against a path that
// already holds it. A dedicated mutex for one field is provably free of that,
// and nothing ever takes zd.mu while holding parentMu.

// GetParent returns the cached parent name, or "" when it has not been
// resolved yet. Use ResolveParent when a value is required.
func (zd *ZoneData) GetParent() string {
	zd.parentMu.Lock()
	defer zd.parentMu.Unlock()
	return zd.parent
}

// SetParent caches a parent name obtained by other means.
func (zd *ZoneData) SetParent(p string) {
	zd.parentMu.Lock()
	defer zd.parentMu.Unlock()
	zd.parent = p
}

// ResolveParent returns the zone's parent, resolving and caching it on first
// use. "." is treated as unset: it is the old sentinel for "not looked up".
//
// The IMR lookup runs OUTSIDE parentMu -- it is a network call, and holding a
// lock across it would serialise every zone behind the slowest parent
// resolution -- so two callers can race to resolve. That is harmless: they
// compute the same answer, and the re-check under the lock means the first one
// to arrive wins and the other adopts it, so all callers observe one value.
func (zd *ZoneData) ResolveParent() (string, error) {
	return zd.ResolveParentVia(Globals.ImrEngine)
}

// ResolveParentVia is ResolveParent against a specific resolver, for the paths
// that already hold one rather than reaching for Globals.ImrEngine.
func (zd *ZoneData) ResolveParentVia(imr *Imr) (string, error) {
	if p := zd.GetParent(); p != "" && p != "." {
		return p, nil
	}
	if imr == nil {
		return "", fmt.Errorf("parent zone for %s is unknown: no IMR engine to resolve it", zd.ZoneName)
	}
	p, err := imr.ParentZone(zd.ZoneName)
	if err != nil {
		return "", fmt.Errorf("ParentZone(%s): %w", zd.ZoneName, err)
	}
	if p == "" {
		return "", fmt.Errorf("parent zone for %s is unknown", zd.ZoneName)
	}
	zd.parentMu.Lock()
	defer zd.parentMu.Unlock()
	if zd.parent == "" || zd.parent == "." {
		zd.parent = p
	}
	return zd.parent, nil
}
