/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// parentSyncAfterKeyPublication is called asynchronously after onLeaderElected
// publishes the SIG(0) KEY to the combiner. It queries the parent via KeyState
// EDNS(0) to determine if bootstrap is needed, and if so, sends the bootstrap
// UPDATE.
//
// Flow:
//  1. Check HSYNCPARAM parentsync=agent (caller already verified OptDelSyncChild)
//  2. Query parent via KeyState EDNS(0) inquiry
//  3. KeyStateTrusted → done
//  4. KeyStateUnknown → bootstrap
//  5. KeyStateBootstrapAutoOngoing → poll
//  6. Query failure → retry with backoff
func (conf *Config) parentSyncAfterKeyPublication(zone ZoneName, keyName string, keyid uint16, algorithm uint8) {
	kdb := conf.Internal.KeyDB
	lem := conf.Internal.LeaderElectionManager

	// Wait for IMR to become available (it starts asynchronously).
	var imr *Imr
	for i := 0; i < 10; i++ {
		imr = conf.Internal.ImrEngine
		if imr != nil {
			break
		}
		lgElect.Info("parentSyncAfterKeyPublication: waiting for IMR engine", "zone", zone, "attempt", i+1)
		time.Sleep(2 * time.Second)
	}
	if imr == nil {
		lgElect.Error("parentSyncAfterKeyPublication: IMR engine not available after waiting", "zone", zone)
		return
	}

	// Only the leader should bootstrap.
	if lem != nil && !lem.IsLeader(zone) {
		lgElect.Info("parentSyncAfterKeyPublication: not the leader, skipping", "zone", zone)
		return
	}

	// Check HSYNCPARAM parentsync=agent.
	if !zoneHasParentSyncAgent(zone) {
		lgElect.Info("parentSyncAfterKeyPublication: parentsync is not 'agent', skipping", "zone", zone)
		return
	}

	// Retry KeyState inquiry with backoff: 5s, 10s, 20s, 40s, then give up.
	maxRetries := 5
	delay := 5 * time.Second
	bootstrapped := false

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Re-check leadership before each attempt.
		if lem != nil && !lem.IsLeader(zone) {
			lgElect.Info("parentSyncAfterKeyPublication: lost leadership, aborting", "zone", zone)
			return
		}

		keyState, err := queryParentKeyState(kdb, imr, keyName, keyid)
		if err != nil {
			lgElect.Warn("parentSyncAfterKeyPublication: KeyState inquiry failed",
				"zone", zone, "attempt", attempt, "err", err)
			time.Sleep(delay)
			delay *= 2
			continue
		}

		switch keyState {
		case edns0.KeyStateTrusted:
			lgElect.Info("parentSyncAfterKeyPublication: parent trusts our key",
				"zone", zone, "keyid", keyid)
			updateParentState(kdb, keyName, keyid, keyState)
			return

		case edns0.KeyStateUnknown:
			if bootstrapped {
				// Already sent bootstrap, parent hasn't processed it yet — keep polling
				lgElect.Info("parentSyncAfterKeyPublication: parent still unknown after bootstrap, polling",
					"zone", zone, "keyid", keyid, "attempt", attempt)
				time.Sleep(delay)
				delay *= 2
				continue
			}
			lgElect.Info("parentSyncAfterKeyPublication: parent does not know our key, bootstrapping",
				"zone", zone, "keyid", keyid)
			updateParentState(kdb, keyName, keyid, keyState)
			err := bootstrapWithParent(zone, keyName, algorithm)
			if err != nil {
				lgElect.Error("parentSyncAfterKeyPublication: bootstrap failed",
					"zone", zone, "err", err)
				return
			}
			lgElect.Info("parentSyncAfterKeyPublication: bootstrap UPDATE sent to parent, will poll for trust",
				"zone", zone, "keyid", keyid)
			bootstrapped = true
			time.Sleep(delay)
			delay *= 2
			continue

		case edns0.KeyStateBootstrapAutoOngoing:
			lgElect.Info("parentSyncAfterKeyPublication: parent is verifying key, will poll",
				"zone", zone, "keyid", keyid, "attempt", attempt)
			updateParentState(kdb, keyName, keyid, keyState)
			time.Sleep(delay)
			delay *= 2
			continue

		default:
			lgElect.Info("parentSyncAfterKeyPublication: parent returned unexpected state",
				"zone", zone, "keyid", keyid, "state", keyState)
			updateParentState(kdb, keyName, keyid, keyState)
			return
		}
	}

	lgElect.Warn("parentSyncAfterKeyPublication: exhausted retries",
		"zone", zone, "keyid", keyid)
}

// queryParentKeyState sends a KeyState EDNS(0) inquiry to the parent and
// returns the parent's reported state for the key.
func queryParentKeyState(kdb *KeyDB, imr *Imr, keyName string, keyid uint16) (uint8, error) {
	ctx := context.Background()

	dsyncTarget, err := imr.LookupDSYNCTarget(ctx, keyName, dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		return 0, fmt.Errorf("DSYNC lookup failed: %v", err)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(keyName), dns.TypeANY)

	edns0.AttachKeyStateToResponse(m, &edns0.KeyStateOption{
		KeyID:    keyid,
		KeyState: edns0.KeyStateInquiryKey,
	})

	sak, err := kdb.GetSig0Keys(keyName, Sig0StateActive)
	if err != nil || len(sak.Keys) == 0 {
		return 0, fmt.Errorf("no active SIG(0) key for %s", keyName)
	}

	signedMsg, err := SignMsg(*m, keyName, sak)
	if err != nil {
		return 0, fmt.Errorf("failed to sign KeyState inquiry: %v", err)
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	if len(dsyncTarget.Addresses) == 0 {
		return 0, fmt.Errorf("DSYNC target has no addresses for %s", keyName)
	}

	r, _, err := c.Exchange(signedMsg, dsyncTarget.Addresses[0])
	if err != nil {
		return 0, fmt.Errorf("DNS exchange failed: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return 0, fmt.Errorf("DNS request failed with rcode %s", dns.RcodeToString[r.Rcode])
	}

	opt := r.IsEdns0()
	if opt == nil {
		return 0, fmt.Errorf("no EDNS(0) OPT RR in response")
	}

	keystate, found := edns0.ExtractKeyStateOption(opt)
	if !found {
		return 0, fmt.Errorf("KeyState option missing in response")
	}

	return keystate.KeyState, nil
}

// queryParentKeyStateDetailed is like queryParentKeyState but also returns the
// ExtraText from the KeyState response, for display purposes.
func queryParentKeyStateDetailed(kdb *KeyDB, imr *Imr, keyName string, keyid uint16) (uint8, string, error) {
	ctx := context.Background()

	dsyncTarget, err := imr.LookupDSYNCTarget(ctx, keyName, dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		return 0, "", fmt.Errorf("DSYNC lookup failed: %v", err)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(keyName), dns.TypeANY)

	edns0.AttachKeyStateToResponse(m, &edns0.KeyStateOption{
		KeyID:    keyid,
		KeyState: edns0.KeyStateInquiryKey,
	})

	sak, err := kdb.GetSig0Keys(keyName, Sig0StateActive)
	if err != nil || len(sak.Keys) == 0 {
		return 0, "", fmt.Errorf("no active SIG(0) key for %s", keyName)
	}

	signedMsg, err := SignMsg(*m, keyName, sak)
	if err != nil {
		return 0, "", fmt.Errorf("failed to sign KeyState inquiry: %v", err)
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	if len(dsyncTarget.Addresses) == 0 {
		return 0, "", fmt.Errorf("DSYNC target has no addresses for %s", keyName)
	}

	r, _, err := c.Exchange(signedMsg, dsyncTarget.Addresses[0])
	if err != nil {
		return 0, "", fmt.Errorf("DNS exchange failed: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return 0, "", fmt.Errorf("DNS request failed with rcode %s", dns.RcodeToString[r.Rcode])
	}

	opt := r.IsEdns0()
	if opt == nil {
		return 0, "", fmt.Errorf("no EDNS(0) OPT RR in response")
	}

	keystate, found := edns0.ExtractKeyStateOption(opt)
	if !found {
		return 0, "", fmt.Errorf("KeyState option missing in response")
	}

	return keystate.KeyState, keystate.ExtraText, nil
}

// updateParentState persists the parent's KeyState response in the local keystore.
func updateParentState(kdb *KeyDB, keyName string, keyid uint16, parentState uint8) {
	tx, err := kdb.Begin("updateParentState")
	if err != nil {
		lgElect.Error("updateParentState: failed to begin transaction", "err", err)
		return
	}

	kp := KeystorePost{
		Command:     "sig0-mgmt",
		SubCommand:  "setparentstate",
		Keyname:     keyName,
		Keyid:       keyid,
		ParentState: parentState,
	}

	_, err = kdb.Sig0KeyMgmt(tx, kp)
	if err != nil {
		lgElect.Error("updateParentState: failed to update parent state", "err", err)
		tx.Rollback()
		return
	}

	if err := tx.Commit(); err != nil {
		lgElect.Error("updateParentState: failed to commit", "err", err)
	}
}

// bootstrapWithParent sends a self-signed UPDATE to the parent to bootstrap
// trust for the child's SIG(0) key.
func bootstrapWithParent(zone ZoneName, keyName string, algorithm uint8) error {
	lgElect.Info("bootstrapWithParent: starting", "zone", zone, "keyName", keyName, "algorithm", algorithm)

	// Try Zones map first, then FindZone (label-walking).
	zd, ok := Zones.Get(keyName)
	if !ok || zd == nil {
		lgElect.Debug("bootstrapWithParent: zone not in Zones map, trying FindZone", "keyName", keyName)
		zd, _ = FindZone(keyName)
	}
	if zd == nil {
		return fmt.Errorf("zone %s not found (available zones: %v)", keyName, Zones.Keys())
	}

	ctx := context.Background()
	msg, ur, err := zd.BootstrapSig0KeyWithParent(ctx, algorithm)
	if err != nil {
		return fmt.Errorf("BootstrapSig0KeyWithParent: %s: %v", msg, err)
	}

	lgElect.Info("bootstrapWithParent: success", "zone", zone, "result", msg, "updateResult", ur)
	return nil
}

// zoneHasParentSyncAgent checks whether the zone's HSYNCPARAM record has
// parentsync=agent. Returns false if HSYNCPARAM is absent or parentsync=owner.
func zoneHasParentSyncAgent(zone ZoneName) bool {
	zd, ok := Zones.Get(string(zone))
	if !ok || zd == nil {
		return false
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return false
	}

	hsyncparamRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !exists || len(hsyncparamRRset.RRs) == 0 {
		return false
	}

	prr, ok := hsyncparamRRset.RRs[0].(*dns.PrivateRR)
	if !ok {
		return false
	}

	hsyncparam, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return false
	}

	return hsyncparam.GetParentSync() == core.HsyncParentSyncAgent
}
