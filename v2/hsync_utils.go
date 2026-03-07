/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"errors"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func (zd *ZoneData) HsyncChanged(newzd *ZoneData) (bool, *HsyncStatus, error) {
	var hss = HsyncStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
		Msg:      "No change",
		Error:    false,
		ErrorMsg: "",
		Status:   true,
	}
	var differ bool

	zd.Logger.Printf("*** HsyncChanged: enter (zone %q)", zd.ZoneName)

	oldapex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		if !errors.Is(err, ErrZoneNotReady) {
			return false, nil, fmt.Errorf("error from zd.GetOwner(%s): %v", zd.ZoneName, err)
		}
		// Fall through with oldapex == nil (initial load)
	}

	newhsync, err := newzd.GetRRset(zd.ZoneName, core.TypeHSYNC)
	if err != nil {
		return false, nil, err
	}

	if oldapex == nil {
		lgAgent.Info("initial zone load, old apex was nil", "zone", zd.ZoneName)
		if newhsync == nil {
			lgAgent.Debug("new apex has no HSYNC RRset, no action", "zone", zd.ZoneName)
			return false, &hss, nil
		}
		hss.HsyncAdds = newhsync.RRs
		return true, &hss, nil
	}

	var oldhsync *core.RRset

	if rrset, exists := oldapex.RRtypes.Get(core.TypeHSYNC); exists {
		oldhsync = &rrset
	} else {
		oldhsync = nil
	}

	var newRRs, oldRRs []dns.RR
	if newhsync != nil {
		newRRs = newhsync.RRs
	}
	if oldhsync != nil {
		oldRRs = oldhsync.RRs
	}

	differ, hss.HsyncAdds, hss.HsyncRemoves = core.RRsetDiffer(zd.ZoneName, newRRs, oldRRs, core.TypeHSYNC, zd.Logger, Globals.Verbose, Globals.Debug)
	zd.Logger.Printf("*** HsyncChanged: exit (zone %q, differ: %v)", zd.ZoneName, differ)
	return differ, &hss, nil
}

// DnskeyStatus holds the result of DNSKEY change detection (local keys only).
type DnskeyStatus struct {
	Time             time.Time
	ZoneName         string
	LocalAdds        []dns.RR // Local DNSKEYs added since last check
	LocalRemoves     []dns.RR // Local DNSKEYs removed since last check
	CurrentLocalKeys []dns.RR // Complete current set of local DNSKEYs (for replace operations)
}

// LocalDnskeysChanged compares old and new DNSKEY RRsets, filtering out
// known remote DNSKEYs, and returns whether local DNSKEYs changed.
// Modeled on HsyncChanged() but operates on dns.TypeDNSKEY.
//
// "Remote" keys are those whose key tag matches zd.RemoteDNSKEYs.
// Everything else in the DNSKEY RRset is "local" (from our signer).
func (zd *ZoneData) LocalDnskeysChanged(newzd *ZoneData) (bool, *DnskeyStatus, error) {
	ds := &DnskeyStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
	}

	zd.Logger.Printf("LocalDnskeysChanged: enter (zone %q)", zd.ZoneName)

	// Build set of remote key tags for filtering
	remoteKeyTags := make(map[uint16]bool)
	for _, rr := range zd.GetRemoteDNSKEYs() {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			remoteKeyTags[dnskey.KeyTag()] = true
		}
	}

	// Get old DNSKEY RRset (from current zone data).
	// On initial load, zd may not be ready yet, so GetRRset returns ErrZoneNotReady.
	// Treat this as oldkeys == nil (no old data) — the existing nil handling below
	// will correctly classify all new keys as adds.
	oldkeys, err := zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		if errors.Is(err, ErrZoneNotReady) {
			zd.Logger.Printf("LocalDnskeysChanged: old zone not ready (initial load), treating as no old keys")
			oldkeys = nil
		} else {
			return false, nil, fmt.Errorf("LocalDnskeysChanged: old GetRRset: %v", err)
		}
	}

	// Get new DNSKEY RRset (from incoming zone data)
	newkeys, err := newzd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, nil, fmt.Errorf("LocalDnskeysChanged: new GetRRset: %v", err)
	}

	// Filter: keep only local DNSKEYs (not in remote set)
	oldLocal := filterLocalDNSKEYs(oldkeys, remoteKeyTags)
	newLocal := filterLocalDNSKEYs(newkeys, remoteKeyTags)

	// Handle initial load (no old data)
	if oldkeys == nil && newkeys == nil {
		return false, ds, nil
	}
	if oldkeys == nil {
		// First load — all new local keys are "adds"
		ds.LocalAdds = newLocal
		if len(ds.LocalAdds) > 0 {
			zd.Logger.Printf("LocalDnskeysChanged: zone %s: initial load, %d local DNSKEYs",
				zd.ZoneName, len(ds.LocalAdds))
			return true, ds, nil
		}
		return false, ds, nil
	}

	differ, adds, removes := core.RRsetDiffer(zd.ZoneName, newLocal, oldLocal,
		dns.TypeDNSKEY, zd.Logger, Globals.Verbose, Globals.Debug)

	ds.LocalAdds = adds
	ds.LocalRemoves = removes

	zd.Logger.Printf("LocalDnskeysChanged: exit (zone %q, differ: %v, adds: %d, removes: %d)",
		zd.ZoneName, differ, len(adds), len(removes))
	return differ, ds, nil
}

// LocalDnskeysFromKeystate derives local DNSKEY adds/removes from the KEYSTATE
// inventory rather than from the zone transfer's DNSKEY RRset. The KEYSTATE
// inventory (from the signer) is the authoritative source for which keys are
// local vs foreign. Each inventory entry's KeyRR field contains the full DNSKEY
// RR string, so we can build dns.RR objects directly.
//
// Returns (changed, status, error). If KEYSTATE is unavailable (LastKeyInventory == nil),
// returns (false, nil, nil) — caller should suppress SYNC-DNSKEY-RRSET.
func (zd *ZoneData) LocalDnskeysFromKeystate() (bool, *DnskeyStatus, error) {
	inv := zd.GetLastKeyInventory()
	if inv == nil {
		zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: no KEYSTATE inventory available", zd.ZoneName)
		return false, nil, nil
	}

	if time.Since(inv.Received) > 1*time.Hour {
		lgEngine.Warn("using stale KEYSTATE inventory", "zone", zd.ZoneName, "age", time.Since(inv.Received))
	}

	ds := &DnskeyStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
	}

	// Extract local keys from the KEYSTATE inventory.
	// Skip states that should NOT be in the DNSKEY RRset:
	// - foreign: belongs to another signer
	// - created: not yet staged for distribution
	// - mpremove: being removed, awaiting agent confirmation
	// - removed: already removed
	var newLocalKeys []dns.RR
	for _, entry := range inv.Inventory {
		switch entry.State {
		case DnskeyStateForeign, DnskeyStateCreated, DnskeyStateMpremove, DnskeyStateRemoved:
			continue
		}
		if entry.KeyRR == "" {
			zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: skipping key %d with empty KeyRR",
				zd.ZoneName, entry.KeyTag)
			continue
		}
		rr, err := dns.NewRR(entry.KeyRR)
		if err != nil {
			zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: failed to parse KeyRR for key %d: %v",
				zd.ZoneName, entry.KeyTag, err)
			continue
		}
		newLocalKeys = append(newLocalKeys, rr)
	}

	oldLocalKeys := zd.LocalDNSKEYs

	// Handle initial case (no previous local keys)
	if len(oldLocalKeys) == 0 && len(newLocalKeys) == 0 {
		return false, ds, nil
	}
	if len(oldLocalKeys) == 0 {
		// First KEYSTATE — all local keys are adds
		ds.LocalAdds = newLocalKeys
		ds.CurrentLocalKeys = newLocalKeys
		zd.LocalDNSKEYs = newLocalKeys
		if len(ds.LocalAdds) > 0 {
			zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: initial KEYSTATE, %d local DNSKEYs",
				zd.ZoneName, len(ds.LocalAdds))
			return true, ds, nil
		}
		return false, ds, nil
	}

	differ, adds, removes := core.RRsetDiffer(zd.ZoneName, newLocalKeys, oldLocalKeys,
		dns.TypeDNSKEY, zd.Logger, Globals.Verbose, Globals.Debug)

	ds.LocalAdds = adds
	ds.LocalRemoves = removes
	ds.CurrentLocalKeys = newLocalKeys
	zd.LocalDNSKEYs = newLocalKeys

	zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: differ=%v, adds=%d, removes=%d",
		zd.ZoneName, differ, len(adds), len(removes))
	return differ, ds, nil
}

// filterLocalDNSKEYs returns only the DNSKEY RRs whose key tag is NOT in remoteKeyTags.
func filterLocalDNSKEYs(rrset *core.RRset, remoteKeyTags map[uint16]bool) []dns.RR {
	if rrset == nil || len(rrset.RRs) == 0 {
		return nil
	}
	var local []dns.RR
	for _, rr := range rrset.RRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if !remoteKeyTags[dnskey.KeyTag()] {
				local = append(local, rr)
			}
		}
	}
	return local
}

// RequestAndWaitForKeyInventory sends an RFI KEYSTATE to the signer and waits
// for the inventory response. Uses the inventory to populate zd.RemoteDNSKEYs
// by matching foreign key tags against the actual DNSKEY RRset in the zone.
//
// Sets zd.KeystateOK/KeystateError/KeystateTime to reflect success or failure.
// KEYSTATE failure is an error condition — the agent depends on KEYSTATE for
// DNSKEY classification and must not guess when it's unavailable.
func (zd *ZoneData) RequestAndWaitForKeyInventory() {
	zd.SetKeystateTime(time.Now())

	tm := Conf.Internal.TransportManager
	if tm == nil {
		zd.SetKeystateOK(false)
		zd.SetKeystateError("no TransportManager available")
		zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", zd.ZoneName, zd.GetKeystateError())
		zd.SetRemoteDNSKEYs(nil)
		return
	}

	// Use a dedicated channel for this solicited RFI response so the
	// HsyncEngine's proactive-inventory consumer doesn't steal it.
	rfiChan := make(chan *KeystateInventoryMsg, 1)
	tm.keystateRfiChan.Store(&rfiChan)
	defer tm.keystateRfiChan.Store(nil)

	// Send RFI KEYSTATE to signer
	if err := tm.sendRfiToSigner(zd.ZoneName, "KEYSTATE"); err != nil {
		zd.SetKeystateOK(false)
		zd.SetKeystateError(fmt.Sprintf("RFI KEYSTATE send failed: %v", err))
		zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", zd.ZoneName, zd.GetKeystateError())
		zd.SetRemoteDNSKEYs(nil)
		return
	}

	// Wait for the inventory response (signer sends it as a separate KEYSTATE "inventory" message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case inv := <-rfiChan:
		if inv == nil || inv.Zone != zd.ZoneName {
			zd.SetKeystateOK(false)
			zd.SetKeystateError("received nil or mismatched inventory from signer")
			zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", zd.ZoneName, zd.GetKeystateError())
			zd.SetRemoteDNSKEYs(nil)
			return
		}

		// Store the inventory snapshot for diagnostics
		zd.SetLastKeyInventory(&KeyInventorySnapshot{
			SenderID:  inv.SenderID,
			Zone:      inv.Zone,
			Inventory: inv.Inventory,
			Received:  time.Now(),
		})

		// Build set of foreign key tags from the inventory
		foreignKeyTags := make(map[uint16]bool)
		for _, entry := range inv.Inventory {
			if entry.State == DnskeyStateForeign {
				foreignKeyTags[entry.KeyTag] = true
			}
		}

		// Match foreign key tags against actual DNSKEYs in the zone
		remoteDNSKEYs := zd.buildRemoteDNSKEYsFromTags(foreignKeyTags)
		zd.SetRemoteDNSKEYs(remoteDNSKEYs)

		zd.SetKeystateOK(true)
		zd.SetKeystateError("")
		zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: received %d-key inventory from signer, %d foreign → %d RemoteDNSKEYs",
			zd.ZoneName, len(inv.Inventory), len(foreignKeyTags), len(remoteDNSKEYs))

	case <-timeout.C:
		zd.SetKeystateOK(false)
		zd.SetKeystateError("timeout waiting for signer response (15s)")
		zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", zd.ZoneName, zd.GetKeystateError())
		zd.SetRemoteDNSKEYs(nil)
	}
}

// RequestAndWaitForEdits sends an RFI EDITS to the combiner and waits for the
// contributions response. Applies the received records to the SynchedDataEngine
// as confirmed data (the combiner already has them).
//
// Modeled on RequestAndWaitForKeyInventory.
func (zd *ZoneData) RequestAndWaitForEdits() {
	tm := Conf.Internal.TransportManager
	if tm == nil {
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: no TransportManager available", zd.ZoneName)
		return
	}

	msgQs := Conf.Internal.MsgQs
	if msgQs == nil || msgQs.EditsResponse == nil {
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: no EditsResponse channel available", zd.ZoneName)
		return
	}

	// Send RFI EDITS to combiner
	if err := tm.sendRfiToCombiner(zd.ZoneName, "EDITS"); err != nil {
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: RFI EDITS send failed: %v", zd.ZoneName, err)
		return
	}

	// Wait for the contributions response (combiner sends it as a separate EDITS message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case resp := <-msgQs.EditsResponse:
		if resp == nil || resp.Zone != zd.ZoneName {
			zd.Logger.Printf("RequestAndWaitForEdits: zone %s: received nil or mismatched edits from combiner", zd.ZoneName)
			return
		}

		// Count total records for logging
		totalRRs := 0
		for _, rrs := range resp.Records {
			totalRRs += len(rrs)
		}

		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: received edits from combiner (%d owners, %d RRs)",
			zd.ZoneName, len(resp.Records), totalRRs)

		// Apply to SDE — this is Step 7 (see plan)
		zd.applyEditsToSDE(resp.Records)

	case <-timeout.C:
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: timeout waiting for combiner EDITS response (15s)", zd.ZoneName)
	}
}

// applyEditsToSDE imports the combiner's contributions response into the SynchedDataEngine.
// Records are the agent's own contributions as tracked by the combiner — they should be
// added as confirmed data (not queued for sending to the combiner again).
func (zd *ZoneData) applyEditsToSDE(records map[string][]string) {
	if len(records) == 0 {
		zd.Logger.Printf("applyEditsToSDE: zone %s: no records to apply", zd.ZoneName)
		return
	}

	zdr := Conf.Internal.ZoneDataRepo
	if zdr == nil {
		zd.Logger.Printf("applyEditsToSDE: zone %s: no ZoneDataRepo available", zd.ZoneName)
		return
	}

	localAgentID := AgentId(Conf.Agent.Identity)
	if localAgentID == "" {
		zd.Logger.Printf("applyEditsToSDE: zone %s: no local agent identity configured", zd.ZoneName)
		return
	}

	// Parse the RR strings and add them to the SDE repo as confirmed data.
	// The records are owner → []RR strings. We need to add each RR to the
	// agent's repo entry in the SDE, marked as accepted (combiner has them).
	added := 0
	for _, rrStrings := range records {
		for _, rrStr := range rrStrings {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				zd.Logger.Printf("applyEditsToSDE: zone %s: failed to parse RR %q: %v", zd.ZoneName, rrStr, err)
				continue
			}
			zdr.AddConfirmedRR(ZoneName(zd.ZoneName), localAgentID, rr)
			added++
		}
	}

	zd.Logger.Printf("applyEditsToSDE: zone %s: applied %d confirmed RRs from combiner edits", zd.ZoneName, added)
}

// buildRemoteDNSKEYsFromTags returns DNSKEY RRs from the zone that match the given key tags.
func (zd *ZoneData) buildRemoteDNSKEYsFromTags(foreignKeyTags map[uint16]bool) []dns.RR {
	if len(foreignKeyTags) == 0 {
		return nil
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		zd.Logger.Printf("buildRemoteDNSKEYsFromTags: zone %s: cannot get apex: %v", zd.ZoneName, err)
		return nil
	}

	dnskeyRRset, exists := apex.RRtypes.Get(dns.TypeDNSKEY)
	if !exists || len(dnskeyRRset.RRs) == 0 {
		return nil
	}

	var remote []dns.RR
	for _, rr := range dnskeyRRset.RRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if foreignKeyTags[dnskey.KeyTag()] {
				remote = append(remote, dns.Copy(rr))
			}
		}
	}
	return remote
}

// bool=true if the HSYNC RRset exists and is valid, false otherwise
// error is non-nil for errors other than the HSYNC RRset not existing
func (zd *ZoneData) ValidateHsyncRRset() (bool, error) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, fmt.Errorf("error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	hsyncrrset, exists := apex.RRtypes.Get(core.TypeHSYNC)
	if !exists || len(hsyncrrset.RRs) == 0 {
		return false, nil
	}

	// Requirements:
	// 1. nsmgmt must be consistent across the HSYNC RRs.
	// 2. ...

	if len(hsyncrrset.RRs) == 1 {
		return true, nil
	}

	hsync := hsyncrrset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNC)
	nsmgmt := hsync.NSmgmt

	for _, rr := range hsyncrrset.RRs[1:] {
		hsync := rr.(*dns.PrivateRR).Data.(*core.HSYNC)
		if hsync.NSmgmt != nsmgmt {
			return false, fmt.Errorf("nsmgmt is not consistent across the HSYNC RRs")
		}
	}

	return true, nil
}

// weAreASigner checks the HSYNC RRset for a record matching our identity
// and returns whether its Sign field says SIGN.
// On agents: uses Globals.AgentId.
// On the signer (AppTypeAuth): uses multi-provider.hsync-identity (or
// multi-provider.agent.identity as fallback, since the HSYNC lists agents).
// analyzeHsyncSigners walks the HSYNC/HSYNC2 RRset once and returns:
//   - weShouldSign: whether our identity has SIGN=YES
//   - otherSigners: count of other identities with SIGN=YES
//
// Defaults: sign=true if no matching record found, otherSigners=0 if no records.
func (zd *ZoneData) analyzeHsyncSigners() (weShouldSign bool, otherSigners int, err error) {
	ourIdentity := string(Globals.AgentId)

	// On the signer, our HSYNC identity is the agent we represent, not the signer itself.
	if Globals.App.Type == AppTypeAuth && Conf.MultiProvider != nil {
		if Conf.MultiProvider.HsyncIdentity != "" {
			ourIdentity = dns.Fqdn(Conf.MultiProvider.HsyncIdentity)
		} else if len(Conf.MultiProvider.Agents) > 0 && Conf.MultiProvider.Agents[0].Identity != "" {
			ourIdentity = dns.Fqdn(Conf.MultiProvider.Agents[0].Identity)
		}
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return true, 0, fmt.Errorf("analyzeHsyncSigners: cannot get apex for zone %s: %v", zd.ZoneName, err)
	}

	foundOurRecord := false

	// Try HSYNC first, then HSYNC2
	hsyncRRset, exists := apex.RRtypes.Get(core.TypeHSYNC)
	if exists && len(hsyncRRset.RRs) > 0 {
		for _, rr := range hsyncRRset.RRs {
			hsync := rr.(*dns.PrivateRR).Data.(*core.HSYNC)
			if hsync.Identity == ourIdentity {
				foundOurRecord = true
				weShouldSign = hsync.Sign == core.HsyncSignYES
			} else if hsync.Sign == core.HsyncSignYES {
				otherSigners++
			}
		}
		if !foundOurRecord {
			zd.Logger.Printf("analyzeHsyncSigners: zone %s: no HSYNC record matches our identity %q", zd.ZoneName, ourIdentity)
			weShouldSign = true // default: sign if no matching record
		}
		return weShouldSign, otherSigners, nil
	}

	hsync2RRset, exists := apex.RRtypes.Get(core.TypeHSYNC2)
	if exists && len(hsync2RRset.RRs) > 0 {
		for _, rr := range hsync2RRset.RRs {
			hsync2 := rr.(*dns.PrivateRR).Data.(*core.HSYNC2)
			if hsync2.Identity == ourIdentity {
				foundOurRecord = true
				weShouldSign = hsync2.DoSign()
			} else if hsync2.DoSign() {
				otherSigners++
			}
		}
		if !foundOurRecord {
			zd.Logger.Printf("analyzeHsyncSigners: zone %s: no HSYNC2 record matches our identity %q", zd.ZoneName, ourIdentity)
			weShouldSign = true
		}
		return weShouldSign, otherSigners, nil
	}

	// No HSYNC/HSYNC2 records at all — sign by default, no other signers
	return true, 0, nil
}

// weAreASigner is a convenience wrapper around analyzeHsyncSigners.
func (zd *ZoneData) weAreASigner() (bool, error) {
	shouldSign, _, err := zd.analyzeHsyncSigners()
	return shouldSign, err
}

func (zd *ZoneData) PrintOwnerNames() error {
	switch zd.ZoneStore {
	case SliceZone:
		for _, owner := range zd.Owners {
			fmt.Printf("Owner: %s\n", owner.Name)
		}
	case MapZone:
		for _, owner := range zd.Data.Keys() {
			fmt.Printf("Owner: %s\n", owner)
		}
	}
	return nil
}

func (zd *ZoneData) PrintApexRRs() error {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return fmt.Errorf("error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	for _, rrtype := range apex.RRtypes.Keys() {
		for _, rr := range apex.RRtypes.GetOnlyRRSet(rrtype).RRs {
			fmt.Printf("%s: %s\n", dns.TypeToString[rrtype], rr.String())
		}
	}
	return nil
}
