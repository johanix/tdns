/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (zd *ZoneData) Refresh(force bool) (bool, error) {
	verbose := true
	var updated bool

	// zd.Logger.Printf("zd.Refresh(): refreshing zone %s (%s) force=%v.", zd.ZoneName,
	// 	ZoneTypeToString[zd.ZoneType], force)

	// if zd.FoldCase {
	if zd.Options["foldcase"] {
		zd.Logger.Printf("zd.Refresh(): folding case for zone %s", zd.ZoneName)
		zd.ZoneName = strings.ToLower(zd.ZoneName)
	}

	switch zd.ZoneType {
	case Primary:
		// zd.Logger.Printf("zd.Refresh(): Should reload zone %s from file %s", zd.ZoneName, zd.ZoneFile)

		updated, err := zd.FetchFromFile(verbose, force)
		if err != nil {
			return false, err
		}
		return updated, err

	case Secondary:
		do_transfer, upstream_serial, err := zd.DoTransfer()
		if err != nil {
			zd.Logger.Printf("Error from DoZoneTransfer(%s): %v", zd.ZoneName, err)
			return false, err
		}

		if do_transfer || force {
			if do_transfer {
				zd.Logger.Printf("Refresher: %s: upstream serial has increased: %d-->%d",
					zd.ZoneName, zd.IncomingSerial, upstream_serial)
			} else if force {
				zd.Logger.Printf("Refresher: %s: forced retransfer regardless of whether SOA serial has increased", zd.ZoneName)
			}
			updated, err = zd.FetchFromUpstream(verbose)
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

	r, err := dns.Exchange(m, zd.Upstream)
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
func (zd *ZoneData) FetchFromFile(verbose, force bool) (bool, error) {

	// log.Printf("Reading zone %s from file %s\n", zd.ZoneName, zd.Upstream)

	zonedata := ZoneData{
		ZoneName:       zd.ZoneName,
		ZoneStore:      zd.ZoneStore,
		ZoneType:       zd.ZoneType,
		XfrType:        zd.XfrType,
		IncomingSerial: zd.IncomingSerial,
		CurrentSerial:  zd.CurrentSerial,
		Logger:         zd.Logger,
		Verbose:        zd.Verbose,
		Options:        zd.Options,
		// FoldCase:       zd.FoldCase, // Must be here, as this is an instruction to the zone reader
	}

	updated, _, err := zonedata.ReadZoneFile(zd.Zonefile, force)
	if err != nil {
		log.Printf("Error from ReadZoneFile(%s): %v", zd.ZoneName, err)
		return false, err
	}

	// zd.Logger.Printf("FetchFromFile: Zone %s: zone file read, updated=%v delegation sync=%v", zd.ZoneName, updated, zd.Optoins["delegationsync"])

	if !updated {
		return false, nil // new zone not loaded, but not returning any error
	}

	// if zd.DelegationSync {
	if zd.Options["delegationsync"] {
		// Detect whether the delegation data has changed.
		// zd.Logger.Printf("FetchFromFile: Zone %s: delegation sync is enabled", zd.ZoneName)
		delchanged, adds, removes, delsyncstatus, err := zd.DelegationDataChanged(&zonedata)
		if err != nil {
			zd.Logger.Printf("Error from DelegationDataChanged(%s): %v", zd.ZoneName, err)
			return false, err
		}
		if delchanged {
			zd.Logger.Printf("FetchFromFile: Zone %s: delegation data has changed. Sending update to DelegationSyncEngine", zd.ZoneName)
			zd.DelegationSyncCh <- DelegationSyncRequest{
				Command:    "SYNC-DELEGATION",
				ZoneName:   zd.ZoneName,
				ZoneData:   zd,
				Adds:       adds,
				Removes:    removes,
				SyncStatus: delsyncstatus,
			}
		} else {
			// zd.Logger.Printf("FetchFromFile: Zone %s: delegation data has NOT changed:", zd.ZoneName)
		}
	}

	if viper.GetBool("service.debug") {
		fname, err := zd.ZoneFileName()
		if err != nil {
			zd.Logger.Printf("Error from ZoneFileName(%s): %v", zd.ZoneName, err)
		} else {
			_, err := zonedata.WriteFile(fname)
			if err != nil {
				zd.Logger.Printf("Error from WriteFile(%s): %v", zd.ZoneName, err)
			} else {
				// zd.Logger.Printf("FetchFromFile: Zone %s: zone file written to %s", zd.ZoneName, f)
			}
		}
	}

	zd.mu.Lock()
	zd.Owners = zonedata.Owners
	zd.OwnerIndex = zonedata.OwnerIndex
	zd.IncomingSerial = zonedata.IncomingSerial
	zd.CurrentSerial = zonedata.CurrentSerial
	zd.ApexLen = zonedata.ApexLen
	zd.XfrType = zonedata.XfrType
	zd.ZoneStore = zonedata.ZoneStore
	zd.ZoneType = zonedata.ZoneType
	zd.Data = zonedata.Data
	zd.mu.Unlock()

	return true, nil
}

// Return updated, err
func (zd *ZoneData) FetchFromUpstream(verbose bool) (bool, error) {

	log.Printf("Transferring zone %s via AXFR from %s\n", zd.ZoneName, zd.Upstream)

	zonedata := ZoneData{
		ZoneName:       zd.ZoneName,
		ZoneType:       zd.ZoneType,
		ZoneStore:      zd.ZoneStore,
		XfrType:        zd.XfrType,
		IncomingSerial: zd.IncomingSerial,
		CurrentSerial:  zd.CurrentSerial,
		Logger:         zd.Logger,
		Verbose:        zd.Verbose,
		Options:        zd.Options,
		// FoldCase:       zd.FoldCase, // Must be here, as this is an instruction to the zone reader
	}

	_, err := zonedata.ZoneTransferIn(zd.Upstream, zd.IncomingSerial, "axfr")
	if err != nil {
		zd.Logger.Printf("Error from ZoneTransfer(%s): %v", zd.ZoneName, err)
		return false, err
	}

	if zonedata.CurrentSerial == zd.CurrentSerial {
		zd.Logger.Printf("FetchFromUpstream: zone %s: SOA serial is unchanged (%d)",
			zd.ZoneName, zd.CurrentSerial)
		return false, nil
	}

	// if zd.DelegationSync {
	if zd.Options["delegationsync"] {
		// Detect whether the delegation data has changed.
		//zd.Logger.Printf("FetchFromUpstream: Zone %s: delegation sync is enabled", zd.ZoneName)
		delchanged, adds, removes, delsyncstatus, err := zd.DelegationDataChanged(&zonedata)
		if err != nil {
			zd.Logger.Printf("Error from DelegationDataChanged(%s): %v", zd.ZoneName, err)
			return false, err
		}
		if delchanged {
			zd.Logger.Printf("FetchFromUpstream: Zone %s: delegation data has changed. Sending update to DelegationSyncEngine", zd.ZoneName)
			zd.DelegationSyncCh <- DelegationSyncRequest{
				Command:    "SYNC-DELEGATION",
				ZoneName:   zd.ZoneName,
				ZoneData:   zd,
				SyncStatus: delsyncstatus,
				Adds:       adds,
				Removes:    removes,
			}
		} else {
			// zd.Logger.Printf("FetchFromUpstream: Zone %s: delegation data has NOT changed:", zd.ZoneName)
		}
	}

	if viper.GetBool("service.debug") {
		fname, err := zd.ZoneFileName()
		if err != nil {
			zd.Logger.Printf("Error from ZoneFileName(%s): %v", zd.ZoneName, err)
		} else {
			_, err := zonedata.WriteFile(fname)
			if err != nil {
				zd.Logger.Printf("Error from WriteFile(%s): %v", zd.ZoneName, err)
			} else {
				// zd.Logger.Printf("FetchFromUpstream: Zone %s: zone file written to %s", zd.ZoneName, f)
			}
		}
	}

	zd.mu.Lock()
	//	zd.RRs = zonedata.RRs
	zd.Owners = zonedata.Owners
	zd.OwnerIndex = zonedata.OwnerIndex
	zd.IncomingSerial = zonedata.IncomingSerial
	zd.CurrentSerial = zonedata.CurrentSerial
	zd.ApexLen = zonedata.ApexLen
	zd.XfrType = zonedata.XfrType
	zd.ZoneStore = zonedata.ZoneStore
	zd.ZoneType = zonedata.ZoneType
	zd.Data = zonedata.Data
	zd.mu.Unlock()

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
	zd.Logger.Printf("NameExists: returning %v for qname %s", ok, qname)
	return ok
}

// XXX: FIXME: SliceZones do not yet have support for adding new owner names.
func (zd *ZoneData) GetOwner(qname string) (*OwnerData, error) {
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
				RRtypes: make(map[uint16]RRset),
			}
			zd.Data.Set(qname, owner)
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

func (zd *ZoneData) IsChildDelegation(qname string) bool {
	zd.Logger.Printf("IsChildDelegation: checking delegation of %s from %s",
		qname, zd.ZoneName)
	owner, err := zd.GetOwner(qname)
	if err != nil || owner == nil || qname == zd.ZoneName {
		return false
	}
	if _, exists := owner.RRtypes[dns.TypeNS]; !exists {
		return false
	}
	if len(owner.RRtypes[dns.TypeNS].RRs) == 0 {
		return false
	}
	zd.Logger.Printf("IsChildDelegation: %s is an existing child of %s",
		qname, zd.ZoneName)
	return true
}

func (zd *ZoneData) GetSOA() (*dns.SOA, error) {
	owner, err := zd.GetOwner(zd.ZoneName)
	if err != nil || owner == nil {
		return nil, err
	}
	soa := owner.RRtypes[dns.TypeSOA].RRs[0]
	return soa.(*dns.SOA), nil
}

func (zd *ZoneData) PrintOwners() {
	switch zd.ZoneStore {
	case SliceZone:
		fmt.Printf("owner name\tindex\n")
		for i, v := range zd.Owners {
			rrtypes := []string{}
			for t, _ := range v.RRtypes {
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
	log.Printf("FindZone: no zone for qname=%s found", qname)
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
	resp.OldSerial = zd.CurrentSerial
	zd.CurrentSerial++
	resp.NewSerial = zd.CurrentSerial
	zd.mu.Unlock()

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
		dns.TypeNS: owner.RRtypes[dns.TypeNS],
		dns.TypeDS: owner.RRtypes[dns.TypeDS],
	}

	cdd.NS_rrs = owner.RRtypes[dns.TypeNS].RRs

	bns, err := BailiwickNS(childname, owner.RRtypes[dns.TypeNS].RRs)
	if err != nil {
		return nil, fmt.Errorf("FetchChildDelegationData: error getting in bailiwick NS for %s: %v", childname, err)
	}

	for _, ns := range bns {
		nsowner, err := zd.GetOwner(ns)
		if err != nil {
			return nil, fmt.Errorf("FetchChildDelegationData: error getting owner for %s: %v", ns, err)
		}
		cdd.RRsets[ns] = map[uint16]RRset{
			dns.TypeA:    nsowner.RRtypes[dns.TypeA],
			dns.TypeAAAA: nsowner.RRtypes[dns.TypeAAAA],
		}
		cdd.A_glue = append(cdd.A_glue, nsowner.RRtypes[dns.TypeA].RRs...)
		cdd.AAAA_glue = append(cdd.AAAA_glue, nsowner.RRtypes[dns.TypeAAAA].RRs...)
	}

	zd.Children[childname] = &cdd
	return &cdd, nil
}
