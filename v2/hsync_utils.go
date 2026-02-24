/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"errors"
	"fmt"
	"log"
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
		log.Printf("HsyncChanged: Zone %s old apexdata was nil. This is the initial zone load.", zd.ZoneName)
		if newhsync == nil {
			log.Printf("HsyncChanged: Zone %s new apex has no HSYNC RRset. No action.", zd.ZoneName)
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
	Time         time.Time
	ZoneName     string
	LocalAdds    []dns.RR // Local DNSKEYs added since last check
	LocalRemoves []dns.RR // Local DNSKEYs removed since last check
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
	for _, rr := range zd.RemoteDNSKEYs {
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
// Returns (true, nil) if we should sign, (false, nil) if we should not,
// or (true, nil) as a safe default if no identity is configured or no
// matching HSYNC record is found.
// Handles both HSYNC and HSYNC2 record types.
func (zd *ZoneData) weAreASigner() (bool, error) {
	ourIdentity := string(Globals.AgentId)

	// On the signer, our HSYNC identity is the agent we represent, not the signer itself.
	if Globals.App.Type == AppTypeAuth && Conf.MultiProvider != nil {
		if Conf.MultiProvider.HsyncIdentity != "" {
			ourIdentity = dns.Fqdn(Conf.MultiProvider.HsyncIdentity)
		} else if Conf.MultiProvider.Agent != nil && Conf.MultiProvider.Agent.Identity != "" {
			ourIdentity = dns.Fqdn(Conf.MultiProvider.Agent.Identity)
		}
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return true, fmt.Errorf("weAreASigner: cannot get apex for zone %s: %v", zd.ZoneName, err)
	}

	// Try HSYNC first, then HSYNC2
	hsyncRRset, exists := apex.RRtypes.Get(core.TypeHSYNC)
	if exists && len(hsyncRRset.RRs) > 0 {
		for _, rr := range hsyncRRset.RRs {
			hsync := rr.(*dns.PrivateRR).Data.(*core.HSYNC)
			if hsync.Identity == ourIdentity {
				return hsync.Sign == core.HsyncSignYES, nil
			}
		}
		// No matching HSYNC record for our identity
		zd.Logger.Printf("weAreASigner: zone %s: no HSYNC record matches our identity %q", zd.ZoneName, ourIdentity)
		return true, nil
	}

	hsync2RRset, exists := apex.RRtypes.Get(core.TypeHSYNC2)
	if exists && len(hsync2RRset.RRs) > 0 {
		for _, rr := range hsync2RRset.RRs {
			hsync2 := rr.(*dns.PrivateRR).Data.(*core.HSYNC2)
			if hsync2.Identity == ourIdentity {
				return hsync2.DoSign(), nil
			}
		}
		// No matching HSYNC2 record for our identity
		zd.Logger.Printf("weAreASigner: zone %s: no HSYNC2 record matches our identity %q", zd.ZoneName, ourIdentity)
		return true, nil
	}

	// No HSYNC/HSYNC2 records at all — sign by default
	return true, nil
}

// isMultiSigner checks the HSYNC RRset and returns true if more than one
// agent has Sign=SIGN (or DoSign() for HSYNC2). This distinguishes
// multi-signer mode (mode 4) from single-signer multi-provider (mode 2).
// Returns (false, nil) if 0 or 1 signers, (true, nil) if 2+.
func (zd *ZoneData) isMultiSigner() (bool, error) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, fmt.Errorf("isMultiSigner: cannot get apex for zone %s: %v", zd.ZoneName, err)
	}

	signerCount := 0

	// Try HSYNC first
	hsyncRRset, exists := apex.RRtypes.Get(core.TypeHSYNC)
	if exists && len(hsyncRRset.RRs) > 0 {
		for _, rr := range hsyncRRset.RRs {
			hsync := rr.(*dns.PrivateRR).Data.(*core.HSYNC)
			if hsync.Sign == core.HsyncSignYES {
				signerCount++
			}
		}
		return signerCount > 1, nil
	}

	// Try HSYNC2
	hsync2RRset, exists := apex.RRtypes.Get(core.TypeHSYNC2)
	if exists && len(hsync2RRset.RRs) > 0 {
		for _, rr := range hsync2RRset.RRs {
			hsync2 := rr.(*dns.PrivateRR).Data.(*core.HSYNC2)
			if hsync2.DoSign() {
				signerCount++
			}
		}
		return signerCount > 1, nil
	}

	// No HSYNC/HSYNC2 records — not multi-signer
	return false, nil
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
