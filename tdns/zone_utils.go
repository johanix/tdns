/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (zd *ZoneData) Refresh(verbose, debug, force bool) (bool, error) {
	var updated bool

	// zd.Logger.Printf("zd.Refresh(): refreshing zone %s (%s) force=%v.", zd.ZoneName,
	// 	ZoneTypeToString[zd.ZoneType], force)

	// if zd.FoldCase {
	if zd.Options[OptFoldCase] {
		zd.Logger.Printf("zd.Refresh(): folding case for zone %s", zd.ZoneName)
		zd.ZoneName = strings.ToLower(zd.ZoneName)
	}

	switch zd.ZoneType {
	case Primary:
		// zd.Logger.Printf("zd.Refresh(): Should reload zone %s from file %s", zd.ZoneName, zd.ZoneFile)

		updated, err := zd.FetchFromFile(verbose, debug, force)
		if err != nil {
			return false, err
		}
		return updated, err

	case Secondary:
		do_transfer, upstream_serial, err := zd.DoTransfer()
		if err != nil {
			return false, err
		}

		if do_transfer || force {
			if do_transfer {
				zd.Logger.Printf("Refresher: %s: upstream serial has increased: %d-->%d",
					zd.ZoneName, zd.IncomingSerial, upstream_serial)
			} else if force {
				zd.Logger.Printf("Refresher: %s: forced retransfer regardless of whether SOA serial has increased", zd.ZoneName)
			}
			updated, err = zd.FetchFromUpstream(verbose, debug)
			if err != nil {
				log.Printf("Error from FetchZone(%s, %s): %v", zd.ZoneName, zd.Upstream, err)
				return false, err
			}
			return updated, nil // zone updated, no error
		}

		zd.Logger.Printf("Refresher: %s: upstream serial is unchanged: %d", zd.ZoneName, zd.IncomingSerial)

	default:
		return false, fmt.Errorf("Error: cannot refresh zone %s of unknown type %d", zd.ZoneName, zd.ZoneType)
	}

	return false, nil
}

// Return shouldTransfer, new upstream serial, error
func (zd *ZoneData) DoTransfer() (bool, uint32, error) {
	var upstream_serial uint32

	if zd == nil {
		panic("DoTransfer: zd == nil")
	}

	// log.Printf("%s: known zone, current incoming serial %d", zd.ZoneName, zd.IncomingSerial)
	m := new(dns.Msg)
	m.SetQuestion(zd.ZoneName, dns.TypeSOA)

	upstream := zd.Upstream
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		// If error, assume no port was specified
		upstream = net.JoinHostPort(upstream, "53")
		if Globals.Verbose {
			zd.Logger.Printf("DoTransfer: zone %q: no port specified for upstream %q, using default port 53", zd.ZoneName, zd.Upstream)
		}
	}
	r, err := dns.Exchange(m, upstream)
	if err != nil {
		log.Printf("Error from dns.Exchange(%s, SOA): %v", zd.ZoneName, err)
		return false, 0, err
	}

	rcode := r.MsgHdr.Rcode
	switch rcode {
	case dns.RcodeRefused, dns.RcodeServerFailure, dns.RcodeNameError:
		return false, 0, nil // never mind
	case dns.RcodeSuccess:
		if soa, ok := r.Answer[0].(*dns.SOA); ok {
			// log.Printf("UpstreamSOA: %v", soa.String())
			if soa.Serial <= zd.IncomingSerial {
				// log.Printf("New upstream serial for %s (%d) is <= old incoming serial (%d)",
				// 	zd.ZoneName, soa.Serial, zd.IncomingSerial)
				return false, soa.Serial, nil
			}
			// log.Printf("New upstream serial for %s (%d) is > current serial (%d)",
			// 	zd.ZoneName, soa.Serial, zd.IncomingSerial)
			return true, soa.Serial, nil
		}
	default:
	}

	return false, upstream_serial, nil
}

// Return updated, error
func (zd *ZoneData) FetchFromFile(verbose, debug, force bool) (bool, error) {

	// log.Printf("Reading zone %s from file %s\n", zd.ZoneName, zd.Upstream)

	new_zd := ZoneData{
		ZoneName:       zd.ZoneName,
		ZoneStore:      zd.ZoneStore,
		ZoneType:       zd.ZoneType,
		XfrType:        zd.XfrType,
		IncomingSerial: zd.IncomingSerial,
		CurrentSerial:  zd.CurrentSerial,
		Logger:         zd.Logger,
		Verbose:        zd.Verbose,
		Debug:          zd.Debug,
		Options:        zd.Options,
		// FoldCase:       zd.FoldCase, // Must be here, as this is an instruction to the zone reader
	}

	updated, _, err := new_zd.ReadZoneFile(zd.Zonefile, force)
	if err != nil {
		log.Printf("Error from ReadZoneFile(%s): %v", zd.ZoneName, err)
		return false, err
	}

	// zd.Logger.Printf("FetchFromFile: Zone %s: zone file read, updated=%v delegation sync=%v", zd.ZoneName, updated, zd.Optoins["delegationsync"])

	if !updated {
		return false, nil // new zone not loaded, but not returning any error
	}

	zd.mu.Lock()
	zd.Ready = true // this is a lie
	zd.mu.Unlock()
	new_zd.Ready = true

	// Detect whether the delegation data has changed.
	// zd.Logger.Printf("FetchFromFile: Zone %s: delegation sync is enabled", zd.ZoneName)
	var delchanged bool
	var dss DelegationSyncStatus
	if zd.Options[OptDelSyncChild] {
		delchanged, dss, err = zd.DelegationDataChangedNG(&new_zd)
		if err != nil {
			zd.Logger.Printf("Error from DelegationDataChanged(%s): %v", zd.ZoneName, err)
			return false, err
		}
	}

	var hsyncchanged, keyschanged bool
	var hss *HsyncStatus
	switch Globals.App.Type {
	case AppTypeAgent, AppTypeCombiner:
		hsyncchanged, hss, err = zd.HsyncChanged(&new_zd)
		if err != nil {
			zd.Logger.Printf("Error from HsyncChanged(%s): %v", zd.ZoneName, err)
			// return false, err
		}
		keyschanged, err = zd.DnskeysChangedNG(&new_zd)
		if err != nil {
			zd.Logger.Printf("Error from DnskeysChanged(%s): %v", zd.ZoneName, err)
			// return false, err
		}
	}

	zd.mu.Lock()
	zd.Owners = new_zd.Owners
	zd.OwnerIndex = new_zd.OwnerIndex
	zd.IncomingSerial = new_zd.IncomingSerial
	zd.CurrentSerial = new_zd.CurrentSerial
	zd.ApexLen = new_zd.ApexLen
	zd.XfrType = new_zd.XfrType
	zd.ZoneStore = new_zd.ZoneStore
	zd.ZoneType = new_zd.ZoneType
	zd.Data = new_zd.Data
	zd.Ready = true
	zd.mu.Unlock()

	// If the delegation has changed, send an update to the DelegationSyncEngine
	if zd.Options[OptDelSyncChild] && delchanged {
		zd.Logger.Printf("FetchFromFile: Zone %s: delegation data has changed. Sending update to DelegationSyncEngine", zd.ZoneName)
		zd.DelegationSyncQ <- DelegationSyncRequest{
			Command:    "SYNC-DELEGATION",
			ZoneName:   zd.ZoneName,
			ZoneData:   zd,
			SyncStatus: dss,
		}
	}

	// If this is a multi-signer zone, check for changes to the HSYNC and DNSKEY RRsets; notify MultiSignerSyncEngine if needed
	if zd.Options[OptMultiSigner] {
		if keyschanged {
			zd.Logger.Printf("FetchFromFile: Zone %s: DNSKEY RRset has changed. Sending update to MultiSignerSyncEngine", zd.ZoneName)
			oldkeys, err := zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
			if err != nil {
				zd.Logger.Printf("Error from GetRRset(%s, %d): %v", zd.ZoneName, dns.TypeDNSKEY, err)
				// return false, err
			}
			newkeys, err := new_zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
			if err != nil {
				zd.Logger.Printf("Error from GetRRset(%s, %d): %v", zd.ZoneName, dns.TypeDNSKEY, err)
				// return false, err
			}
			zd.SyncQ <- SyncRequest{
				Command:    "SYNC-DNSKEY-RRSET",
				ZoneName:   ZoneName(zd.ZoneName),
				ZoneData:   zd,
				OldDnskeys: oldkeys,
				NewDnskeys: newkeys,
				SyncStatus: nil,
			}
		}

		if hsyncchanged {
			zd.Logger.Printf("FetchFromFile: Zone %s: HSYNC RRset has changed. Sending update to HsyncEngine", zd.ZoneName)

			zd.SyncQ <- SyncRequest{
				Command:    "HSYNC-UPDATE",
				ZoneName:   ZoneName(zd.ZoneName),
				ZoneData:   zd,
				SyncStatus: hss,
			}
		}
	}

	if viper.GetBool("service.debug") {
		fname, err := zd.ZoneFileName()
		if err != nil {
			zd.Logger.Printf("Error from ZoneFileName(%s): %v", zd.ZoneName, err)
		} else {
			_, err := new_zd.WriteFile(fname)
			if err != nil {
				zd.Logger.Printf("Error from WriteFile(%s): %v", zd.ZoneName, err)
			} else {
				// zd.Logger.Printf("FetchFromFile: Zone %s: zone file written to %s", zd.ZoneName, f)
			}
		}
	}

	return true, nil
}

// Return updated, err
func (zd *ZoneData) FetchFromUpstream(verbose, debug bool) (bool, error) {

	log.Printf("Transferring zone %s via AXFR from %s\n", zd.ZoneName, zd.Upstream)

	new_zd := ZoneData{
		ZoneName:       zd.ZoneName,
		ZoneType:       zd.ZoneType,
		ZoneStore:      zd.ZoneStore,
		XfrType:        zd.XfrType,
		IncomingSerial: zd.IncomingSerial,
		CurrentSerial:  zd.CurrentSerial,
		Logger:         zd.Logger,
		Verbose:        zd.Verbose,
		Debug:          zd.Debug,
		Options:        zd.Options,
		Ready:          true, // this is only used by the checks for changes to DNSKEYs, HSYNC, etc.
		// FoldCase:       zd.FoldCase, // Must be here, as this is an instruction to the zone reader
	}

	_, err := new_zd.ZoneTransferIn(zd.Upstream, zd.IncomingSerial, "axfr")
	if err != nil {
		zd.Logger.Printf("Error from ZoneTransfer(%s): %v", zd.ZoneName, err)
		return false, err
	}

	if new_zd.CurrentSerial == zd.CurrentSerial {
		zd.Logger.Printf("FetchFromUpstream: zone %s: SOA serial is unchanged (%d)",
			zd.ZoneName, zd.CurrentSerial)
		return false, nil
	}

	new_zd.Ready = true

	// Detect whether the delegation data has changed.
	// zd.Logger.Printf("FetchFromUpstream: Zone %s: delegation sync is enabled", zd.ZoneName)
	var delchanged bool
	var dss DelegationSyncStatus
	if zd.Options[OptDelSyncChild] {
		delchanged, dss, err = zd.DelegationDataChangedNG(&new_zd)
		if err != nil {
			zd.Logger.Printf("Error from DelegationDataChanged(%s): %v", zd.ZoneName, err)
			// return false, err
		}
	}

	var hsyncchanged, dnskeyschanged bool
	var hss *HsyncStatus
	switch Globals.App.Type {
	case AppTypeAgent, AppTypeCombiner:
		hsyncchanged, hss, err = zd.HsyncChanged(&new_zd)
		if err != nil {
			zd.Logger.Printf("Error from HsyncChanged(%s): %v", zd.ZoneName, err)
			// return false, err
		}
		dnskeyschanged, err = zd.DnskeysChangedNG(&new_zd)
		if err != nil {
			zd.Logger.Printf("Error from DnskeysChangedNG(%s): %v", zd.ZoneName, err)
			// return false, err
		}
	default:
		// Do nothing
	}

	zd.mu.Lock()
	zd.Owners = new_zd.Owners
	zd.OwnerIndex = new_zd.OwnerIndex
	zd.IncomingSerial = new_zd.IncomingSerial
	zd.CurrentSerial = new_zd.CurrentSerial
	zd.ApexLen = new_zd.ApexLen
	zd.XfrType = new_zd.XfrType
	zd.ZoneStore = new_zd.ZoneStore
	zd.ZoneType = new_zd.ZoneType
	zd.Data = new_zd.Data
	zd.Ready = true
	zd.mu.Unlock()

	// Can only test for differences between old and new zone data if the zone data is ready.
	if delchanged && zd.Options[OptDelSyncChild] {
		zd.Logger.Printf("FetchFromUpstream: Zone %s: delegation data has changed. Sending update to DelegationSyncEngine", zd.ZoneName)
		zd.DelegationSyncQ <- DelegationSyncRequest{
			Command:    "SYNC-DELEGATION",
			ZoneName:   zd.ZoneName,
			ZoneData:   zd,
			SyncStatus: dss,
		}
	}

	if dnskeyschanged {
		switch Globals.App.Type {
		case AppTypeAgent:
			zd.Logger.Printf("FetchFromUpstream: Zone %s: DNSSEC keys have changed. Sending update to DelegationSyncEngine", zd.ZoneName)
			oldkeys, err := zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
			if err != nil {
				zd.Logger.Printf("Error from GetRRset(%s, %d): %v", zd.ZoneName, dns.TypeDNSKEY, err)
				// return false, err
			}
			newkeys, err := new_zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
			if err != nil {
				zd.Logger.Printf("Error from GetRRset(%s, %d): %v", zd.ZoneName, dns.TypeDNSKEY, err)
				// return false, err
			}
			zd.MusicSyncQ <- MusicSyncRequest{
				Command:    "SYNC-DNSKEY-RRSET",
				ZoneName:   zd.ZoneName,
				ZoneData:   zd,
				OldDnskeys: oldkeys,
				NewDnskeys: newkeys,
			}
		case AppTypeCombiner:
			// A combiner doesn't need to act on DNSKEY changes. But for now we log it to verify the code path.
			zd.Logger.Printf("FetchFromUpstream: Zone %s: Incoming DNSKEYs have changed. No action needed.", zd.ZoneName)
		}
	}

	if hsyncchanged {
		switch Globals.App.Type {
		case AppTypeAgent:
			zd.Logger.Printf("FetchFromUpstream: Zone %s: HSYNC RRset has changed. Sending update to HsyncEngine", zd.ZoneName)
			zd.SyncQ <- SyncRequest{
				Command:    "HSYNC-UPDATE",
				ZoneName:   ZoneName(zd.ZoneName),
				ZoneData:   zd,
				SyncStatus: hss,
			}
		case AppTypeCombiner:
			// A combiner needs to act on HSYNC changes, but only to verify whether itself is in the HSYNC RRset
			zd.Logger.Printf("FetchFromUpstream: Zone %s: HSYNC RRset has changed. Verifying whether we are in the HSYNC RRset", zd.ZoneName)
			// XXX: Kludge just for testing. Should be replaced by HSYNC RRset parsing
			zd.Options[OptAllowCombine] = true
			// TODO: Implement this
		}
	}

	zd.Logger.Printf("FetchFromUpstream: Zone %q: Globals.App.Type: %q allow-combine: %v",
		zd.ZoneName, AppTypeToString[Globals.App.Type], zd.Options[OptAllowCombine])
	// XXX: Current thinking: the OptCombiner option is dynamically set for a zone given the combination of
	//      (a) it contains a HSYNC RRset and (b) appname is "combiner".
	if Globals.App.Type == AppTypeCombiner && zd.Options[OptAllowCombine] {
		// XXX: We are a combiner and this zone has a HSYNC RRset. Therefore we need to check whether there are
		// any local changes to the zone that needs to be applied before we can send the zone to the downstreams.
		// XXX: This MUST not be a request through a channel, but rather a direct call to something that does this.
		zd.Logger.Printf("FetchFromUpstream: Zone %q: Combining with local changes", zd.ZoneName)
		success, err := zd.CombineWithLocalChanges()
		if err != nil {
			zd.Logger.Printf("Error from CombineWithLocalChanges(%q): %v", zd.ZoneName, err)
			return false, err
		}
		if success {
			zd.Logger.Printf("FetchFromUpstream: Zone %q: Local changes to the zone have been applied. Sending to downstreams.", zd.ZoneName)
		} else {
			zd.Logger.Printf("FetchFromUpstream: Zone %q: Local changes to the zone have not been applied. Not sending to downstreams.", zd.ZoneName)
		}
	}

	if viper.GetBool("service.debug") {
		fname, err := zd.ZoneFileName()
		if err != nil {
			zd.Logger.Printf("Error from ZoneFileName(%s): %v", zd.ZoneName, err)
		} else {
			_, err := new_zd.WriteFile(fname)
			if err != nil {
				zd.Logger.Printf("Error from WriteFile(%s): %v", zd.ZoneName, err)
			} else {
				// zd.Logger.Printf("FetchFromUpstream: Zone %s: zone file written to %s", zd.ZoneName, f)
			}
		}
	}

	return true, nil
}

func (zd *ZoneData) ZoneFileName() (string, error) {
	filedir := viper.GetString("dnsengine.zones.filedir")
	if filedir == "" {
		return "", fmt.Errorf("ZoneFileName: dnsengine.zones.filedir is not set")
	}
	filetmpl := viper.GetString("dnsengine.zones.filetmpl")
	if filetmpl == "" {
		return "", fmt.Errorf("ZoneFileName: dnsengine.zones.filetmpl is not set")
	}
	fname := fmt.Sprintf("/tmp"+filetmpl, filedir, zd.ZoneName) // Must ensure that we don't allow writing everywhere
	fname = path.Clean(fname)
	dirname := path.Dir(fname)
	if _, err := os.Stat(dirname); os.IsNotExist(err) {
		if err := os.MkdirAll(dirname, 0755); err != nil {
			return "", fmt.Errorf("ZoneFileName: failed to create missing directory %s: %v", dirname, err)
		}
	}
	return fname, nil
}

func (zd *ZoneData) WriteZone(tosource bool, force bool) (string, error) {
	var fname string
	var err error
	if tosource {
		fname = zd.Zonefile
	} else {
		fname, err = zd.ZoneFileName()
		if err != nil {
			return err.Error(), err
		}
	}
	if !zd.Options[OptDirty] && !force {
		return fmt.Sprintf("Zone %s not modified, writing to disk not needed", zd.ZoneName), nil
	}
	_, err = zd.WriteFile(fname)
	if err == nil {
		zd.mu.Lock()
		zd.Options[OptDirty] = false
		zd.mu.Unlock()
	}
	return fmt.Sprintf("Zone %s written to %s", zd.ZoneName, fname), err
}

func (zd *ZoneData) SetOption(option ZoneOption, value bool) {
	zd.mu.Lock()
	zd.Options[option] = value
	zd.mu.Unlock()
}

func (zd *ZoneData) NameExists(qname string) bool {
	var ok bool
	switch zd.ZoneStore {
	case SliceZone:
		_, ok = zd.OwnerIndex.Get(qname)

	case MapZone:
		_, ok = zd.Data.Get(qname)

	default:
		zd.Logger.Printf("NameExists: should not get here for zonestorage: %s",
			ZoneStoreToString[zd.ZoneStore])
		return false
	}

	if zd.Debug {
		zd.Logger.Printf("NameExists: returning %v for qname %s", ok, qname)
	}
	return ok
}

// XXX: FIXME: SliceZones do not yet have support for adding new owner names.

func (zd *ZoneData) GetOwner(qname string) (*OwnerData, error) {
	if !zd.Ready {
		return nil, fmt.Errorf("GetOwner: Zone %s: zone data is not yet ready", zd.ZoneName)
	}
	var owner OwnerData
	var ok bool
	switch zd.ZoneStore {
	case SliceZone:
		if len(zd.Owners) == 0 {
			return nil, nil
		}
		idx, _ := zd.OwnerIndex.Get(qname)
		owner = zd.Owners[idx]

	case MapZone:
		if zd.Data.IsEmpty() {
			return nil, nil
		}
		if owner, ok = zd.Data.Get(qname); !ok {
			owner = OwnerData{
				Name:    qname,
				RRtypes: NewRRTypeStore(),
			}
			// XXX: Hmm. This seems wrong. We create an ownername where there wasn't one
			//      based on a request for it?
			// zd.Data.Set(qname, owner)
			return nil, nil // Seems better
		}
		return &owner, nil

	default:
		zd.Logger.Printf("GetOwner: zone storage not supported: %v", zd.ZoneStore)
		return &owner, fmt.Errorf("GetOwner: only supported for SliceZone and MapZone, not %s",
			ZoneStoreToString[zd.ZoneStore])
	}
	// dump.P(owner)
	return &owner, nil
}

// XXX: This MUST ONLY be called from the ZoneUpdater, due to locking issues
func (zd *ZoneData) AddOwner(owner *OwnerData) {
	//	zd.mu.Lock()
	switch zd.ZoneStore {
	case SliceZone:
		zd.Owners = append(zd.Owners, *owner)
		zd.OwnerIndex.Set(owner.Name, len(zd.Owners)-1)

	case MapZone:
		zd.Data.Set(owner.Name, *owner)
	}
	// zd.mu.Unlock()
}

func (zd *ZoneData) GetRRset(qname string, rrtype uint16) (*RRset, error) {
	if zd == nil {
		return nil, fmt.Errorf("GetRRset: zone data is nil. This should not happen")
	}
	owner, err := zd.GetOwner(qname)
	if err != nil {
		return nil, err
	}
	if owner == nil && zd.ZoneName != qname {
		return nil, nil // this can happen if qname does not exist in the zone
	}
	if owner == nil {
		// XXX: This can not happen, as there should always be data at the zone apez
		panic(fmt.Sprintf("GetRRset: owner data is nil for zone apex %s. This should not happen", zd.ZoneName))
	}
	// dump.P(owner)
	if rrset, exists := owner.RRtypes.Get(rrtype); exists {
		return &rrset, nil
	} else {
		return nil, nil
	}
}

func (zd *ZoneData) GetOwnerNames() ([]string, error) {
	var names []string
	switch zd.ZoneStore {
	case SliceZone:
		if len(zd.Owners) == 0 {
			return names, nil
		}
		names = zd.OwnerIndex.Keys()

	case MapZone:
		if zd.Data.IsEmpty() {
			return names, nil
		}
		names = zd.Data.Keys()

	default:
		zd.Logger.Printf("GetOwnerNames: zone storage not supported: %v", zd.ZoneStore)
		return names, fmt.Errorf("GetOwnerNames: only supported for SliceZone and MapZone, not %s",
			ZoneStoreToString[zd.ZoneStore])
	}
	return names, nil
}

// XXX: Is qname the name of a zone cut for a child zone?
func (zd *ZoneData) IsChildDelegation(qname string) bool {
	zd.Logger.Printf("IsChildDelegation: checking delegation of %q from %q",
		qname, zd.ZoneName)
	owner, err := zd.GetOwner(qname)
	if err != nil || owner == nil || qname == zd.ZoneName {
		return false
	}
	if _, exists := owner.RRtypes.Get(dns.TypeNS); !exists {
		return false
	}
	if len(owner.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs) == 0 {
		return false
	}
	// zd.Logger.Printf("IsChildDelegation: %s is an existing child of %s",
	// 	qname, zd.ZoneName)
	return true
}

func (zd *ZoneData) GetSOA() (*dns.SOA, error) {
	owner, err := zd.GetOwner(zd.ZoneName)
	if err != nil || owner == nil {
		return nil, err
	}
	soa := owner.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs[0]
	return soa.(*dns.SOA), nil
}

func (zd *ZoneData) PrintOwners() {
	switch zd.ZoneStore {
	case SliceZone:
		fmt.Printf("owner name\tindex\n")
		for i, v := range zd.Owners {
			rrtypes := []string{}
			for _, t := range v.RRtypes.Keys() {
				rrtypes = append(rrtypes, dns.TypeToString[t])
			}
			fmt.Printf("%d\t%s\t%s\n", i, v.Name, strings.Join(rrtypes, ", "))
		}
		for _, k := range zd.OwnerIndex.Keys() {
			v, _ := zd.OwnerIndex.Get(k)
			fmt.Printf("%s\t%d\n", k, v)
		}
	case MapZone:
		for _, key := range zd.Data.Keys() {
			fmt.Printf("%s\n", key)
		}
	default:
		zd.Logger.Printf("Sorry, only zone storage Map and Slice for now")
	}
}

func (zd *ZoneData) NotifyDownstreams() error {
	// zd.Logger.Printf("NotifyDownstreams: Zone %s has downstreams: %v", zd.ZoneName, zd.Downstreams)
	if zd == nil {
		zd.Logger.Printf("Error: zonedata is nil")
		return fmt.Errorf("zonedata is nil")
	}
	for _, d := range zd.Downstreams {

		// log.Printf("%s: Notifying downstream server %s about new SOA serial", zd.ZoneName, d)

		m := new(dns.Msg)
		m.SetNotify(zd.ZoneName)
		r, err := dns.Exchange(m, d)
		if err != nil {
			// well, we tried
			log.Printf("Error from downstream %s on Notify(%s): %v", d, zd.ZoneName, err)
			continue
		}
		if r.Opcode != dns.OpcodeNotify {
			// well, we tried
			log.Printf("Error: not a NOTIFY QR from downstream %s on Notify(%s): %s",
				d, zd.ZoneName, dns.OpcodeToString[r.Opcode])
		}
	}
	return nil
}

func WildcardReplace(rrs []dns.RR, qname, origqname string) []dns.RR {
	res := []dns.RR{}
	for _, rr := range rrs {
		newrr := dns.Copy(rr)
		newrr.Header().Name = origqname
		res = append(res, newrr)
	}
	return res
}

func IsIxfr(rrs []dns.RR) bool {
	first_soa := false

	if len(rrs) < 3 {
		return false
	}

	if _, ok := rrs[0].(*dns.SOA); ok {
		first_soa = true
	}

	if _, ok := rrs[1].(*dns.SOA); ok {
		if first_soa {
			return true
		}
	}
	return false
}

// Find the closest enclosing auth zone that has qname below it (qname is either auth data
// in the zone or located further down in a child zone that we are not auth for).
// Return zone, case fold used to match
func FindZone(qname string) (*ZoneData, bool) {
	var tzone string
	labels := strings.Split(qname, ".")
	for i := 0; i < len(labels)-1; i++ {
		tzone = strings.Join(labels[i:], ".")
		if zd, ok := Zones.Get(tzone); ok {
			return zd, false
		}
	}

	// if no match for exact qname, let's try with a case folded version
	qname = strings.ToLower(qname)
	labels = strings.Split(qname, ".")

	for i := 0; i < len(labels)-1; i++ {
		tzone = strings.Join(labels[i:], ".")
		if zd, ok := Zones.Get(tzone); ok {
			return zd, true
		}
	}
	log.Printf("FindZone: no zone for qname=%q found", qname)
	return nil, false
}

func FindZoneNG(qname string) *ZoneData {
	i := strings.Index(qname, ".")
	for {
		if i == -1 {
			break // done
		}
		if zd, ok := Zones.Get(qname[i:]); ok {
			return zd
		}
		i = strings.Index(qname[i:], ".")
	}
	return nil
}

func (zd *ZoneData) BumpSerial() (BumperResponse, error) {
	resp := BumperResponse{
		Zone: zd.ZoneName,
	}

	log.Printf("BumpSerial: bumping SOA serial for zone '%s'", zd.ZoneName)
	zd.mu.Lock()

	defer func() {
		zd.mu.Unlock()
	}()

	resp.OldSerial = zd.CurrentSerial
	zd.CurrentSerial++
	resp.NewSerial = zd.CurrentSerial
	if zd.Options[OptOnlineSigning] {
		//		dak, err := zd.KeyDB.GetDnssecActiveKeys(zd.ZoneName)
		//		if err != nil {
		//			log.Printf("SignZone: failed to get dnssec active keys for zone %s", zd.ZoneName)
		//			zd.mu.Unlock()
		//			return resp, err
		//		}
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil {
			zd.Logger.Printf("Error from GetOwner(%s): %v", zd.ZoneName, err)
			return resp, err
		}
		soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
		apex.RRtypes.Set(dns.TypeSOA, soaRRset)

		rrset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		_, err = zd.SignRRset(&rrset, zd.ZoneName, nil, true) // true = force signing, as we know the SOA has changed
		if err != nil {
			log.Printf("BumpSerial: failed to sign SOA RRset for zone %s", zd.ZoneName)
			return resp, err
		}
	}
	//	zd.mu.Unlock()

	zd.NotifyDownstreams()

	return resp, nil
}

func (zd *ZoneData) FetchChildDelegationData(childname string) (*ChildDelegationData, error) {
	zd.Logger.Printf("FetchChildDelegationData: fetching delegation data for %s", childname)
	if !zd.IsChildDelegation(childname) {
		return nil, fmt.Errorf("FetchChildDelegationData: %s is not a child of %s", childname, zd.ZoneName)
	}
	//	if zd.Children[childname] != nil {
	//		if zd.Children[childname].ParentSerial == zd.CurrentSerial || time.Since(zd.Children[childname].Timestamp) < 24*time.Hour {
	//			return nil
	//		}
	//	}
	cdd := ChildDelegationData{
		ChildName:    childname,
		ParentSerial: zd.CurrentSerial,
		Timestamp:    time.Now(),
		RRsets:       make(map[string]map[uint16]RRset),
		NS_rrs:       []dns.RR{},
		A_glue:       []dns.RR{},
		AAAA_glue:    []dns.RR{},
	}

	owner, err := zd.GetOwner(childname)
	if err != nil {
		return nil, fmt.Errorf("FetchChildDelegationData: error getting owner for %s: %v", childname, err)
	}

	cdd.RRsets[childname] = map[uint16]RRset{
		dns.TypeNS: owner.RRtypes.GetOnlyRRSet(dns.TypeNS),
		dns.TypeDS: owner.RRtypes.GetOnlyRRSet(dns.TypeDS),
	}

	cdd.NS_rrs = owner.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs

	bns, err := BailiwickNS(childname, owner.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs)
	if err != nil {
		return nil, fmt.Errorf("FetchChildDelegationData: error getting in bailiwick NS for %s: %v", childname, err)
	}

	for _, ns := range bns {
		nsowner, err := zd.GetOwner(ns)
		if err != nil {
			return nil, fmt.Errorf("FetchChildDelegationData: error getting owner for %s: %v", ns, err)
		}
		cdd.RRsets[ns] = map[uint16]RRset{
			dns.TypeA:    nsowner.RRtypes.GetOnlyRRSet(dns.TypeA),
			dns.TypeAAAA: nsowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA),
		}
		cdd.A_glue = append(cdd.A_glue, nsowner.RRtypes.GetOnlyRRSet(dns.TypeA).RRs...)
		cdd.AAAA_glue = append(cdd.AAAA_glue, nsowner.RRtypes.GetOnlyRRSet(dns.TypeAAAA).RRs...)
	}

	zd.Children[childname] = &cdd
	return &cdd, nil
}

func (zd *ZoneData) SetupZoneSync(delsyncq chan<- DelegationSyncRequest) error {
	wantsSync := zd.Options[OptDelSyncParent] || zd.Options[OptDelSyncChild]
	if !wantsSync {
		zd.Logger.Printf("SetupZoneSync: Zone %s does not require delegation sync", zd.ZoneName)
		return nil
	}
	zd.Logger.Printf("SetupZoneSync: Zone %s requests delegation sync", zd.ZoneName)

	// Is this a parent zone and should we then publish a DSYNC RRset?
	if zd.Options[OptDelSyncParent] {
		// For the moment we receive both updates and notifies on the same address as the rest of
		// the DNS service. Doesn't have to be that way, but for now it is.

		owner, _ := zd.GetOwner("_dsync." + zd.ZoneName)
		dsync_rrset, exist := owner.RRtypes.Get(TypeDSYNC)
		if exist && len(dsync_rrset.RRs) > 0 {
			// If there is a DSYNC RRset, we assume that it is correct and will not modify
			zd.Logger.Printf("SetupZoneSync(%s, parent-side): DSYNC RRset exists. Will not modify.", zd.ZoneName)
		} else {
			zd.Logger.Printf("SetupZoneSync: Zone %s: No DSYNC RRset in zone. Will add.", zd.ZoneName)
			//			ur := UpdateRequest{
			//				Cmd:          "DEFERRED-UPDATE",
			//				ZoneName:     zd.ZoneName,
			//				Description:  fmt.Sprintf("Publish DSYNC RRs for zone %s", zd.ZoneName),
			//				PreCondition: ZoneIsReady(zd.ZoneName),
			//				Action:       zd.PublishDsyncRRs,
			//			}
			//			zd.KeyDB.UpdateQ <- ur
			err := zd.PublishDsyncRRs()
			if err != nil {
				zd.Logger.Printf("Error from PublishDsyncRRs(%s): %v", zd.ZoneName, err)
				return err
			}
		}

		// Figure out if there is a DSYNC RR with scheme UPDATE; if so, we need to ensure that
		// we generate a SIG(0) key pair for the target and publish the public key in the zone.
		updateTarget := dns.Fqdn(strings.Replace(viper.GetString("delegationsync.parent.update.target"), "{ZONENAME}", zd.ZoneName, 1))
		if _, ok := dns.IsDomainName(updateTarget); !ok {
			zd.Logger.Printf("SetupZoneSync(%s, parent-side): Invalid DSYNC update target: %s", zd.ZoneName, updateTarget)
		} else {
			zd.Logger.Printf("SetupZoneSync(%s, parent-side): DSYNC update target: %s", zd.ZoneName, updateTarget)
			err := zd.ParentSig0KeyPrep(updateTarget, zd.KeyDB)
			if err != nil {
				zd.Logger.Printf("Error from ParentSig0KeyPrep(%s): %v", updateTarget, err)
				return err
			}
		}
	}

	// If this is a child zone and we have the delegation-sync-child option set, we need to
	// ensure that there is a SIG(0) keypair and that the public key is published in the zone.
	// XXX: There is an option for dont-publish-key, but at present we do not support that.
	if zd.Options[OptDelSyncChild] {
		for _, scheme := range viper.GetStringSlice("delegationsync.child.schemes") {
			switch scheme {
			case "update":
				delsyncq <- DelegationSyncRequest{
					Command:  "DELEGATION-SYNC-SETUP",
					ZoneName: zd.ZoneName,
					ZoneData: zd,
					// Response:   make(chan DelegationSyncStatus),
				}

			case "notify":
				// Nothing to do here as CSYNC and CDS will only be published when
				// the zone is modified, not proactively.
			default:
			}
		}
	}

	return nil
}

func (zd *ZoneData) SetupZoneSigning(resignq chan<- *ZoneData) error {
	if !zd.Options[OptOnlineSigning] {
		return nil // this zone should not be signed (at least not by us)
	}

	if !zd.Options[OptAllowUpdates] {
		return nil // this zone does not allow any modifications
	}

	if Globals.App.Type == AppTypeAgent {
		return nil // this zone does not allow any modifications
	}

	if zd.ZoneType != Primary {
		return nil // this zone is not a primary zone, it cannot be signed
	}

	kdb := zd.KeyDB
	newrrsigs, err := zd.SignZone(kdb, false)
	if err != nil {
		zd.Logger.Printf("Error from SignZone(%s): %v", zd.ZoneName, err)
		return err
	}

	log.Printf("SetupZoneSigning: zone %s signed. %d new RRSIGs", zd.ZoneName, newrrsigs)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	select {
	case resignq <- zd:
	case <-ctx.Done():
		log.Printf("SetupZoneSigning: timeout while sending zone %s to resign queue", zd.ZoneName)
	}

	return nil
}

func (zd *ZoneData) ReloadZone(refreshCh chan<- ZoneRefresher, force bool) (string, error) {
	if zd.Options[OptDirty] {
		return "", fmt.Errorf("zone %s: zone has been modified, reload not possible", zd.ZoneName)
	}

	var respch = make(chan RefresherResponse, 1)
	refreshCh <- ZoneRefresher{
		Name:     zd.ZoneName,
		Response: respch,
		Force:    force,
	}

	var resp RefresherResponse

	select {
	case resp = <-respch:
	case <-time.After(2 * time.Second):
		return fmt.Sprintf("Zone %s: timeout waiting for response from RefreshEngine", zd.ZoneName), fmt.Errorf("zone %s: timeout waiting for response from RefreshEngine", zd.ZoneName)
	}

	if resp.Error {
		log.Printf("ReloadZone: Error from RefreshEngine: %s", resp.ErrorMsg)
		return fmt.Sprintf("zone %s: Error reloading: %s", zd.ZoneName, resp.ErrorMsg),
			fmt.Errorf("zone %s: Error reloading: %v", zd.ZoneName, resp.ErrorMsg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: reloaded", zd.ZoneName)
	}
	return resp.Msg, nil
}

type DelegationData struct {
	CurrentNS *RRset
	AddedNS   *RRset
	RemovedNS *RRset

	BailiwickNS []string
	A_glue      map[string]*RRset // map[nsname]
	AAAA_glue   map[string]*RRset // map[nsname]
	Actions     []dns.RR          // actions are DNS UPDATE actions that modify delegation data
	Time        time.Time
}

func (zd *ZoneData) DelegationData() (*DelegationData, error) {
	dd := DelegationData{
		Time:      time.Now(),
		AddedNS:   &RRset{},
		RemovedNS: &RRset{},
		A_glue:    map[string]*RRset{},
		AAAA_glue: map[string]*RRset{},
	}

	rrset, err := zd.GetRRset(zd.ZoneName, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if len(rrset.RRs) == 0 {
		return nil, err
	}

	dd.CurrentNS = rrset

	// Get the in-bailiwick nameserver names
	dd.BailiwickNS, err = BailiwickNS(zd.ZoneName, dd.CurrentNS.RRs)
	if err != nil {
		return nil, err
	}

	for _, nsname := range dd.BailiwickNS {
		owner, err := zd.GetOwner(nsname)
		if err != nil {
			return nil, err
		}
		// XXX: Note that it *is* possible to have an nsname that isn't present in the zone.
		//      I.e. a broken config with an in-bailiwick NS w/o any address.
		if owner == nil {
			zd.Logger.Printf("Error: Zone %s has an in-bailiwick NS \"%s\" without any address RRs.", zd.ZoneName, nsname)
			continue
		}

		if rrset, exist := owner.RRtypes.Get(dns.TypeA); exist {
			if len(rrset.RRs) > 0 {
				dd.A_glue[nsname] = &rrset
			}
		}
		if rrset, exist := owner.RRtypes.Get(dns.TypeAAAA); exist {
			if len(rrset.RRs) > 0 {
				dd.AAAA_glue[nsname] = &rrset
			}
		}
	}
	return &dd, nil
}

func isValidIP(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil
}

func (kdb *KeyDB) CreateAutoZone(zonename string, addrs []string) (*ZoneData, error) {
	if zonename == "" {
		return nil, fmt.Errorf("zonename cannot be empty")
	}
	if !dns.IsFqdn(zonename) {
		return nil, fmt.Errorf("zonename must be fully qualified (end with dot)")
	}

	log.Printf("CreateAutoZone: Zone %s enter", zonename)

	// Create a fake zone for the sidecar identity just to be able to
	// to use to generate the TLSA.
	tmpl := `
$ORIGIN {ZONENAME}
$TTL 86400
{ZONENAME}    IN SOA ns1.{ZONENAME} hostmaster.{ZONENAME} (
          {SERIAL}   ; serial
          3600       ; refresh (1 hour)
          1800       ; retry (30 minutes)
          1209600    ; expire (2 weeks)
          86400      ; minimum (1 day)
          )
{ZONENAME}     IN NS  ns.{ZONENAME}
`
	currentTime := fmt.Sprintf("%d", time.Now().Unix())
	zonedatastr := strings.ReplaceAll(tmpl, "{ZONENAME}", zonename)
	zonedatastr = strings.ReplaceAll(zonedatastr, "{SERIAL}", currentTime)

	if len(addrs) == 0 {
		addrs = []string{"192.0.2.1"} // fake it till you make it
	}

	log.Printf("CreateAutoZone: adding NS RRs for addresses: %v", addrs)
	for _, addr := range addrs {
		if !isValidIP(addr) {
			log.Printf("CreateAutoZone: invalid IP address: %s", addr)
			return nil, fmt.Errorf("invalid IP address: %s", addr)
		}
		if strings.Contains(addr, ":") {
			// IPv6 address
			zonedatastr += fmt.Sprintf("ns.%s IN AAAA %s\n", zonename, addr)
		} else {
			// IPv4 address
			zonedatastr += fmt.Sprintf("ns.%s IN A %s\n", zonename, addr)
		}
	}

	log.Printf("CreateAutoZone: template zone data:\n%s\n", zonedatastr)

	zd := &ZoneData{
		ZoneName:  zonename,
		ZoneStore: MapZone,
		Logger:    log.Default(),
		ZoneType:  Primary,
		Options:   map[ZoneOption]bool{OptAutomaticZone: true},
		KeyDB:     kdb,
	}

	log.Printf("CreateAutoZone: reading zone data for zone '%s'", zonename)
	_, _, err := zd.ReadZoneData(zonedatastr, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read zone data: %v", err)
	}

	zd.Ready = true
	Zones.Set(zonename, zd)

	return zd, nil
}

// Extract the addresses we listen on from the dnsengine configuration. Exclude localhost and non-standard ports.
func (conf *Config) FindDnsEngineAddrs() ([]string, error) {
	addrs := []string{}
	if Globals.Debug {
		log.Printf("FindDnsEngineAddrs: dnsengine addresses: %v", conf.DnsEngine.Addresses)
		// dump.P(tconf.DnsEngine)
	}
	for _, ns := range conf.DnsEngine.Addresses {
		addr, port, err := net.SplitHostPort(ns)
		if err != nil {
			// return nil, fmt.Errorf("FindDnsEngineAddrs: failed to split host and port from address '%s': %v", ns, err)
			// Assume error was missing port, so add it
			addr, port = ns, "53"
		}
		if port != "53" {
			continue
		}
		// if addr == "127.0.0.1" || addr == "::1" {
		// 	continue
		// }
		if addr == "" {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

type HsyncStatus struct {
	Time         time.Time
	ZoneName     string
	Command      string
	Status       bool
	Error        bool
	ErrorMsg     string
	Msg          string
	HsyncAdds    []dns.RR // Changed from Adds
	HsyncRemoves []dns.RR // Changed from Removes
}
