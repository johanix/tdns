/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"errors"
	"fmt"
	"strings"
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

	newhsync, err := newzd.GetRRset(zd.ZoneName, core.TypeHSYNC3)
	if err != nil {
		return false, nil, err
	}

	if oldapex == nil {
		if newhsync == nil {
			lgAgent.Debug("initial zone load, no HSYNC3 RRs in new zone", "zone", zd.ZoneName)
			return false, &hss, nil
		}
		lgAgent.Info("initial zone load, found HSYNC3 RRs", "zone", zd.ZoneName, "count", len(newhsync.RRs))
		hss.HsyncAdds = newhsync.RRs
		return true, &hss, nil
	}

	var oldhsync *core.RRset

	if rrset, exists := oldapex.RRtypes.Get(core.TypeHSYNC3); exists {
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

	differ, hss.HsyncAdds, hss.HsyncRemoves = core.RRsetDiffer(zd.ZoneName, newRRs, oldRRs, core.TypeHSYNC3, zd.Logger, Globals.Verbose, Globals.Debug)
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
	// Don't process DNSKEYs for unsigned zones, but clean up any
	// previously published keys on transition to unsigned.
	if zd.MPdata != nil && !zd.MPdata.ZoneSigned {
		if len(zd.LocalDNSKEYs) > 0 {
			ds := &DnskeyStatus{
				Time:         time.Now(),
				ZoneName:     zd.ZoneName,
				LocalRemoves: zd.LocalDNSKEYs,
			}
			zd.LocalDNSKEYs = nil
			return true, ds, nil
		}
		return false, nil, nil
	}

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
	// Include: published, standby, active, retired, mpdist
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
	// Include the zone name so routeKeystateMessage only routes
	// matching responses here (prevents cross-zone interference).
	rfiChan := make(chan *KeystateInventoryMsg, 1)
	tm.setKeystateRfi(zd.ZoneName, rfiChan)
	defer tm.deleteKeystateRfi(zd.ZoneName)

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
		totalAgents := len(resp.AgentRecords)
		totalRRs := 0
		for _, ownerMap := range resp.AgentRecords {
			for _, rrs := range ownerMap {
				totalRRs += len(rrs)
			}
		}

		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: received edits from combiner (%d agents, %d RRs)",
			zd.ZoneName, totalAgents, totalRRs)

		// Apply to SDE with per-agent attribution
		zd.applyEditsToSDE(resp.AgentRecords)

	case <-timeout.C:
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: timeout waiting for combiner EDITS response (15s)", zd.ZoneName)
	}
}

// RequestAndWaitForConfig sends an RFI CONFIG to a peer agent and waits for the config
// response on MsgQs.ConfigResponse. Returns the config data or nil on timeout/error.
func RequestAndWaitForConfig(ar *AgentRegistry, agent *Agent, zone string, subtype string) *ConfigResponseMsg {
	msgQs := Conf.Internal.MsgQs
	if msgQs == nil || msgQs.ConfigResponse == nil {
		lgEngine.Warn("RequestAndWaitForConfig: no ConfigResponse channel available")
		return nil
	}

	// Send RFI CONFIG to the peer agent
	_, err := ar.sendRfiToAgent(agent, &AgentMsgPost{
		MessageType:  AgentMsgRfi,
		OriginatorID: AgentId(ar.LocalAgent.Identity),
		YourIdentity: agent.Identity,
		Zone:         ZoneName(zone),
		RfiType:      "CONFIG",
		RfiSubtype:   subtype,
	})
	if err != nil {
		lgEngine.Warn("RequestAndWaitForConfig: RFI CONFIG send failed", "agent", agent.Identity, "zone", zone, "subtype", subtype, "err", err)
		return nil
	}

	// Wait for the config response (peer sends it as a separate CONFIG message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case resp := <-msgQs.ConfigResponse:
		if resp == nil {
			lgEngine.Warn("RequestAndWaitForConfig: received nil config response", "zone", zone, "subtype", subtype)
			return nil
		}
		lgEngine.Info("RequestAndWaitForConfig: received config response", "sender", resp.SenderID, "zone", resp.Zone, "subtype", resp.Subtype)
		return resp

	case <-timeout.C:
		lgEngine.Warn("RequestAndWaitForConfig: timeout waiting for config response (15s)", "zone", zone, "subtype", subtype)
		return nil
	}
}

// RequestAndWaitForAudit sends an RFI AUDIT to a peer agent and waits for the audit
// response on MsgQs.AuditResponse. Returns the audit data or nil on timeout/error.
func RequestAndWaitForAudit(ar *AgentRegistry, agent *Agent, zone string) *AuditResponseMsg {
	msgQs := Conf.Internal.MsgQs
	if msgQs == nil || msgQs.AuditResponse == nil {
		lgEngine.Warn("RequestAndWaitForAudit: no AuditResponse channel available")
		return nil
	}

	// Send RFI AUDIT to the peer agent
	_, err := ar.sendRfiToAgent(agent, &AgentMsgPost{
		MessageType:  AgentMsgRfi,
		OriginatorID: AgentId(ar.LocalAgent.Identity),
		YourIdentity: agent.Identity,
		Zone:         ZoneName(zone),
		RfiType:      "AUDIT",
	})
	if err != nil {
		lgEngine.Warn("RequestAndWaitForAudit: RFI AUDIT send failed", "agent", agent.Identity, "zone", zone, "err", err)
		return nil
	}

	// Wait for the audit response (peer sends it as a separate AUDIT message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case resp := <-msgQs.AuditResponse:
		if resp == nil {
			lgEngine.Warn("RequestAndWaitForAudit: received nil audit response", "zone", zone)
			return nil
		}
		lgEngine.Info("RequestAndWaitForAudit: received audit response", "sender", resp.SenderID, "zone", resp.Zone)
		return resp

	case <-timeout.C:
		lgEngine.Warn("RequestAndWaitForAudit: timeout waiting for audit response (15s)", "zone", zone)
		return nil
	}
}

// applyEditsToSDE imports the combiner's contributions response into the SynchedDataEngine.
// AgentRecords is agentID → owner → []RR strings. Each agent's records are added with
// proper attribution so the SDE knows which agent contributed what.
func (zd *ZoneData) applyEditsToSDE(agentRecords map[string]map[string][]string) {
	if len(agentRecords) == 0 {
		zd.Logger.Printf("applyEditsToSDE: zone %s: no records to apply", zd.ZoneName)
		return
	}

	zdr := Conf.Internal.ZoneDataRepo
	if zdr == nil {
		zd.Logger.Printf("applyEditsToSDE: zone %s: no ZoneDataRepo available", zd.ZoneName)
		return
	}

	added := 0
	for agentID, ownerMap := range agentRecords {
		for _, rrStrings := range ownerMap {
			for _, rrStr := range rrStrings {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					zd.Logger.Printf("applyEditsToSDE: zone %s: failed to parse RR %q: %v", zd.ZoneName, rrStr, err)
					continue
				}
				zdr.AddConfirmedRR(ZoneName(zd.ZoneName), AgentId(agentID), rr)
				added++
			}
		}
	}

	zd.Logger.Printf("applyEditsToSDE: zone %s: applied %d confirmed RRs from %d agents", zd.ZoneName, added, len(agentRecords))
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

// ValidateHsyncRRset checks that HSYNC3 and HSYNCPARAM records exist at the
// zone apex and that the HSYNCPARAM has valid keys. With HSYNCPARAM, NSmgmt
// is in a single record so per-RR consistency checks are unnecessary.
// Returns true if both record types exist and are valid, false otherwise.
// error is non-nil for errors other than the records not existing.
func (zd *ZoneData) ValidateHsyncRRset() (bool, error) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, fmt.Errorf("error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	// Check that HSYNC3 exists
	hsync3rrset, hsync3exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !hsync3exists || len(hsync3rrset.RRs) == 0 {
		return false, nil
	}

	// Check that HSYNCPARAM exists
	hsyncparamrrset, paramexists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !paramexists || len(hsyncparamrrset.RRs) == 0 {
		return false, nil
	}

	// HSYNCPARAM exists — NSmgmt is a single value in the param record,
	// no cross-RR consistency check needed.
	return true, nil
}

// ourHsyncIdentities returns the set of FQDN identities we should match against
// HSYNC3 records. On agents this is the single Globals.AgentId; on signers/combiners
// it is all configured agent identities from Conf.MultiProvider.Agents.
func ourHsyncIdentities() []string {
	var ids []string
	if Conf.MultiProvider != nil {
		if Conf.MultiProvider.Role == "agent" {
			// Agent: our own identity
			if Conf.MultiProvider.Identity != "" {
				ids = append(ids, dns.Fqdn(Conf.MultiProvider.Identity))
			}
		} else {
			// Signer/Combiner: configured agent identities
			for _, agent := range Conf.MultiProvider.Agents {
				if agent != nil && agent.Identity != "" {
					ids = append(ids, dns.Fqdn(agent.Identity))
				}
			}
		}
	}
	return ids
}

// matchHsyncProvider checks whether any of our identities appear in the zone's
// HSYNC3 RRset. This determines whether the zone owner considers us a provider
// for this zone — independent of signing.
//
// Returns:
//   - matched: true if at least one of our identities matches an HSYNC3 Identity
//   - label: the HSYNC3 Label of the matching record (e.g. "netnod")
//   - err: non-nil on lookup errors
func (zd *ZoneData) matchHsyncProvider(ourIdentities []string) (matched bool, label string, err error) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, "", fmt.Errorf("matchHsyncProvider: cannot get apex for zone %s: %v", zd.ZoneName, err)
	}

	hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !exists || len(hsync3RRset.RRs) == 0 {
		return false, "", nil
	}

	for _, rr := range hsync3RRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok {
			continue
		}
		for _, id := range ourIdentities {
			if h3.Identity == id {
				return true, strings.TrimSuffix(h3.Label, "."), nil
			}
		}
	}

	// Also try legacy HSYNC/HSYNC2 — these have Identity but no Label,
	// so we use the first matching identity (stripped of trailing dot) as label.
	hsyncRRset, exists := apex.RRtypes.Get(core.TypeHSYNC)
	if exists {
		for _, rr := range hsyncRRset.RRs {
			hsync := rr.(*dns.PrivateRR).Data.(*core.HSYNC)
			for _, id := range ourIdentities {
				if hsync.Identity == id {
					return true, strings.TrimSuffix(id, "."), nil
				}
			}
		}
	}

	hsync2RRset, exists := apex.RRtypes.Get(core.TypeHSYNC2)
	if exists {
		for _, rr := range hsync2RRset.RRs {
			hsync2 := rr.(*dns.PrivateRR).Data.(*core.HSYNC2)
			for _, id := range ourIdentities {
				if hsync2.Identity == id {
					return true, strings.TrimSuffix(id, "."), nil
				}
			}
		}
	}

	return false, "", nil
}

// analyzeHsyncSigners determines whether we should sign the zone and how many
// other signers exist, by examining HSYNC3+HSYNCPARAM (preferred), then falling
// back to HSYNC or HSYNC2 for backward compatibility with old zones.
//
// Requires that matchHsyncProvider() has already confirmed we are a provider.
// The ourLabel parameter is the label returned by matchHsyncProvider().
//
// Returns:
//   - weShouldSign: whether our label is listed as a signer
//   - otherSigners: count of other signers
//   - zoneSigned: whether the zone has any signers listed (HSYNCPARAM signers= non-empty)
func (zd *ZoneData) analyzeHsyncSigners(ourIdentities []string, ourLabel string) (weShouldSign bool, otherSigners int, zoneSigned bool, err error) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, 0, false, fmt.Errorf("analyzeHsyncSigners: cannot get apex for zone %s: %v", zd.ZoneName, err)
	}

	// Try HSYNC3+HSYNCPARAM first (preferred)
	hsyncparamRRset, paramExists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if paramExists && len(hsyncparamRRset.RRs) > 0 {
		hsyncparam := hsyncparamRRset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
		signers := hsyncparam.GetSigners()
		if len(signers) == 0 {
			// No signers specified — zone owner has not authorized signing
			return false, 0, false, nil
		}
		zoneSigned = true
		zd.Logger.Printf("analyzeHsyncSigners: zone %s: ourLabel=%q signers=%v", zd.ZoneName, ourLabel, signers)
		for _, s := range signers {
			if strings.TrimSuffix(s, ".") == strings.TrimSuffix(ourLabel, ".") {
				weShouldSign = true
			} else {
				otherSigners++
			}
		}
		return weShouldSign, otherSigners, zoneSigned, nil
	}

	// Fallback: try HSYNC, then HSYNC2 (for backward compat with old zones)
	isOurIdentity := func(id string) bool {
		for _, ours := range ourIdentities {
			if id == ours {
				return true
			}
		}
		return false
	}
	foundOurRecord := false

	hsyncRRset, exists := apex.RRtypes.Get(core.TypeHSYNC)
	if exists && len(hsyncRRset.RRs) > 0 {
		for _, rr := range hsyncRRset.RRs {
			hsync := rr.(*dns.PrivateRR).Data.(*core.HSYNC)
			if isOurIdentity(hsync.Identity) {
				foundOurRecord = true
				weShouldSign = hsync.Sign == core.HsyncSignYES
			} else if hsync.Sign == core.HsyncSignYES {
				otherSigners++
			}
		}
		if !foundOurRecord {
			zd.Logger.Printf("analyzeHsyncSigners: zone %s: no HSYNC record matches our identities %v", zd.ZoneName, ourIdentities)
			weShouldSign = true
		}
		// Legacy HSYNC implies zone is signed if any signer exists
		zoneSigned = weShouldSign || otherSigners > 0
		return weShouldSign, otherSigners, zoneSigned, nil
	}

	hsync2RRset, exists := apex.RRtypes.Get(core.TypeHSYNC2)
	if exists && len(hsync2RRset.RRs) > 0 {
		for _, rr := range hsync2RRset.RRs {
			hsync2 := rr.(*dns.PrivateRR).Data.(*core.HSYNC2)
			if isOurIdentity(hsync2.Identity) {
				foundOurRecord = true
				weShouldSign = hsync2.DoSign()
			} else if hsync2.DoSign() {
				otherSigners++
			}
		}
		if !foundOurRecord {
			zd.Logger.Printf("analyzeHsyncSigners: zone %s: no HSYNC2 record matches our identities %v", zd.ZoneName, ourIdentities)
			weShouldSign = true
		}
		zoneSigned = weShouldSign || otherSigners > 0
		return weShouldSign, otherSigners, zoneSigned, nil
	}

	// No HSYNC3+HSYNCPARAM/HSYNC/HSYNC2 records at all — no authorization to sign
	return false, 0, false, nil
}

// populateMPdata evaluates the four multi-provider guards for a zone and
// populates zd.MPdata accordingly. Called after every zone refresh/transfer.
//
// Guard 1: OptMultiProvider must be set in the zone config.
// Guard 2: The zone owner must declare the zone as MP (HSYNC3+HSYNCPARAM present).
// Guard 3: We must be a listed provider (our identity matches an HSYNC3 record).
// Guard 4: If the zone is signed (HSYNCPARAM signers= non-empty), we must be a signer.
//
// If any guard fails, zd.MPdata is set to nil. The caller can check zd.MPdata to
// determine whether this zone should be treated as multi-provider.
func (zd *ZoneData) populateMPdata() {
	// Guard 1: static config must declare this as an MP zone
	if !zd.Options[OptMultiProvider] {
		zd.MPdata = nil
		return
	}

	// Guard 2: zone owner must have HSYNC3+HSYNCPARAM (or legacy HSYNC/HSYNC2)
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		zd.Logger.Printf("populateMPdata: zone %s: cannot get apex: %v", zd.ZoneName, err)
		zd.MPdata = nil
		return
	}

	_, h3exists := apex.RRtypes.Get(core.TypeHSYNC3)
	_, hpExists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	_, h1exists := apex.RRtypes.Get(core.TypeHSYNC)
	_, h2exists := apex.RRtypes.Get(core.TypeHSYNC2)

	hasHsyncRecords := (h3exists && hpExists) || h1exists || h2exists
	if !hasHsyncRecords {
		zd.Logger.Printf("populateMPdata: zone %s: OptMultiProvider is set but zone owner has no HSYNC3+HSYNCPARAM (or legacy HSYNC/HSYNC2) records — zone is not multi-provider", zd.ZoneName)
		zd.MPdata = nil
		return
	}

	// Guard 3: we must be a listed provider
	ourIdentities := ourHsyncIdentities()
	matched, ourLabel, err := zd.matchHsyncProvider(ourIdentities)
	if err != nil {
		zd.Logger.Printf("populateMPdata: zone %s: error matching provider identity: %v", zd.ZoneName, err)
		zd.MPdata = nil
		return
	}
	if !matched {
		zd.Logger.Printf("populateMPdata: zone %s: none of our identities %v match any HSYNC3 provider in the zone -- we are not a provider for this zone", zd.ZoneName, ourIdentities)
		zd.Options[OptMPNotListedErr] = true
		zd.MPdata = nil
		return
	}
	// Clear warning if we were previously not listed but now are
	zd.Options[OptMPNotListedErr] = false

	// Guard 4: if zone is signed, we must be a signer
	weShouldSign, otherSigners, zoneSigned, err := zd.analyzeHsyncSigners(ourIdentities, ourLabel)
	if err != nil {
		zd.Logger.Printf("populateMPdata: zone %s: error analyzing signers: %v", zd.ZoneName, err)
		zd.MPdata = nil
		return
	}
	if zoneSigned && !weShouldSign {
		zd.Logger.Printf("populateMPdata: zone %s: we are provider %q but not listed as a signer -- zone is signed and we must not modify it", zd.ZoneName, ourLabel)
		zd.Options[OptMPDisallowEdits] = true
		zd.Options[OptAllowEdits] = false
		zd.MPdata = nil
		return
	}
	// Clear disallow-edits and restore allow-edits if we are (or became) a signer
	zd.Options[OptMPDisallowEdits] = false
	zd.Options[OptAllowEdits] = true

	// Preserve any existing MPdata.Options (set at parse time),
	// create the map if needed.
	var mpOpts map[ZoneOption]bool
	if zd.MPdata != nil && zd.MPdata.Options != nil {
		mpOpts = zd.MPdata.Options
	} else {
		mpOpts = make(map[ZoneOption]bool)
	}
	mpOpts[OptMultiProvider] = true
	mpOpts[OptMPDisallowEdits] = zoneSigned && !weShouldSign
	mpOpts[OptMultiSigner] = weShouldSign && otherSigners > 0

	zd.MPdata = &MPdata{
		WeAreProvider: true,
		OurLabel:      ourLabel,
		WeAreSigner:   weShouldSign,
		OtherSigners:  otherSigners,
		ZoneSigned:    zoneSigned,
		Options:       mpOpts,
	}
	zd.Logger.Printf("populateMPdata: zone %s: provider=%q signer=%v otherSigners=%d zoneSigned=%v",
		zd.ZoneName, ourLabel, weShouldSign, otherSigners, zoneSigned)
}

// weAreASigner is a convenience wrapper that checks provider membership first,
// then signer status.
func (zd *ZoneData) weAreASigner() (bool, error) {
	ids := ourHsyncIdentities()
	matched, label, err := zd.matchHsyncProvider(ids)
	if err != nil {
		return false, err
	}
	if !matched {
		return false, nil
	}
	shouldSign, _, _, err := zd.analyzeHsyncSigners(ids, label)
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
