/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

var lg = Logger("zones")

// ErrZoneNotReady is returned by GetOwner/GetRRset when the zone data
// has not been loaded yet (zd.Ready == false). Callers that need to
// handle initial-load gracefully can check with errors.Is.
var ErrZoneNotReady = errors.New("zone data is not yet ready")

func (zd *ZoneData) Refresh(verbose, debug, force bool, conf *Config) (bool, error) {
	var updated bool

	// Collect dynamic RRs before refresh (they will be lost during refresh)
	dynamicRRs := zd.CollectDynamicRRs(conf)

	// zd.Logger.Printf("zd.Refresh(): refreshing zone %s (%s) force=%v.", zd.ZoneName,
	// 	ZoneTypeToString[zd.ZoneType], force)

	// if zd.FoldCase {
	if zd.Options[OptFoldCase] {
		lg.Debug("folding case for zone", "zone", zd.ZoneName)
		zd.ZoneName = strings.ToLower(zd.ZoneName)
	}

	switch zd.ZoneType {
	case Primary:
		// zd.Logger.Printf("zd.Refresh(): Should reload zone %s from file %s", zd.ZoneName, zd.ZoneFile)

		updated, err := zd.FetchFromFile(verbose, debug, force, dynamicRRs)
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
				lg.Info("upstream serial has increased", "zone", zd.ZoneName, "old", zd.IncomingSerial, "new", upstream_serial)
			} else if force {
				lg.Debug("forced retransfer regardless of SOA serial", "zone", zd.ZoneName)
			}
			updated, err = zd.FetchFromUpstream(verbose, debug, dynamicRRs)
			if err != nil {
				lg.Error("FetchZone failed", "zone", zd.ZoneName, "upstream", zd.Upstream, "err", err)
				return false, err
			}
			return updated, nil // zone updated, no error
		}

		lg.Debug("upstream serial is unchanged", "zone", zd.ZoneName, "serial", zd.IncomingSerial)

	default:
		return false, fmt.Errorf("error: cannot refresh zone %s of unknown type %d", zd.ZoneName, zd.ZoneType)
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
		lg.Debug("DoTransfer: no port specified for upstream, using default port 53", "zone", zd.ZoneName, "upstream", zd.Upstream)
	}
	r, err := dns.Exchange(m, upstream)
	if err != nil {
		lg.Error("dns.Exchange failed", "zone", zd.ZoneName, "qtype", "SOA", "err", err)
		return false, 0, err
	}

	rcode := r.MsgHdr.Rcode
	switch rcode {
	case dns.RcodeRefused, dns.RcodeServerFailure, dns.RcodeNameError:
		return false, 0, nil // never mind
	case dns.RcodeSuccess:
		if len(r.Answer) == 0 {
			lg.Debug("DoTransfer: NOERROR but empty answer section", "zone", zd.ZoneName, "upstream", upstream)
			return false, 0, nil
		}
		if soa, ok := r.Answer[0].(*dns.SOA); ok {
			lg.Info("DoTransfer: serial check", "zone", zd.ZoneName, "notify_serial", soa.Serial, "incoming_serial", zd.IncomingSerial, "current_serial", zd.CurrentSerial)
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
func (zd *ZoneData) FetchFromFile(verbose, debug, force bool, dynamicRRs []*core.RRset) (bool, error) {

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
		lg.Error("ReadZoneFile failed", "zone", zd.ZoneName, "err", err)
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

	// Pre-refresh callbacks: analysis of old vs new zone data + modification of new_zd.
	// MP roles (agent, combiner, signer) register callbacks to detect HSYNC/DNSKEY/delegation
	// changes, add combiner contributions, populate MP data, etc. — all before the hard flip.
	for _, cb := range zd.OnZonePreRefresh {
		cb(zd, &new_zd)
	}

	// Hard flip: update served zone data atomically.
	zd.mu.Lock()
	zd.Owners = new_zd.Owners
	zd.OwnerIndex = new_zd.OwnerIndex
	zd.IncomingSerial = new_zd.IncomingSerial
	if zd.FirstZoneLoad {
		zd.CurrentSerial = new_zd.CurrentSerial
		zd.FirstZoneLoad = false
	} else {
		zd.CurrentSerial++
		if zd.KeyDB != nil && zd.KeyDB.Options[AuthOptPersistOutboundSerial] != "" {
			if err := zd.KeyDB.SaveOutgoingSerial(zd.ZoneName, zd.CurrentSerial); err != nil {
				lg.Error("failed to persist outgoing serial", "zone", zd.ZoneName, "err", err)
			}
		}
	}
	zd.ApexLen = new_zd.ApexLen
	zd.XfrType = new_zd.XfrType
	zd.ZoneStore = new_zd.ZoneStore
	zd.ZoneType = new_zd.ZoneType
	zd.Data = new_zd.Data
	zd.Ready = true
	zd.mu.Unlock()

	// Repopulate all dynamically generated RRs after zone refresh
	// (they may have been lost if not present in the zone file)
	zd.RepopulateDynamicRRs(dynamicRRs)

	// Post-refresh callbacks: queue sends and notifications that need the live zone pointer.
	for _, cb := range zd.OnZonePostRefresh {
		cb(zd)
	}

	return true, nil
}

// Return updated, err
func (zd *ZoneData) FetchFromUpstream(verbose, debug bool, dynamicRRs []*core.RRset) (bool, error) {

	lg.Info("transferring zone via AXFR", "zone", zd.ZoneName, "upstream", zd.Upstream)

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
		lg.Error("ZoneTransfer failed", "zone", zd.ZoneName, "err", err)
		return false, err
	}

	if new_zd.IncomingSerial == zd.IncomingSerial {
		lg.Debug("FetchFromUpstream: upstream serial is unchanged", "zone", zd.ZoneName, "serial", zd.IncomingSerial)
		return false, nil
	}

	new_zd.Ready = true

	// Pre-refresh callbacks: analysis of old vs new zone data + modification of new_zd.
	for _, cb := range zd.OnZonePreRefresh {
		cb(zd, &new_zd)
	}

	// Hard flip: update served zone data atomically.
	zd.mu.Lock()
	zd.Owners = new_zd.Owners
	zd.OwnerIndex = new_zd.OwnerIndex
	zd.IncomingSerial = new_zd.IncomingSerial
	if zd.FirstZoneLoad {
		zd.CurrentSerial = new_zd.CurrentSerial
		zd.FirstZoneLoad = false
	} else {
		zd.CurrentSerial++
		if zd.KeyDB != nil && zd.KeyDB.Options[AuthOptPersistOutboundSerial] != "" {
			if err := zd.KeyDB.SaveOutgoingSerial(zd.ZoneName, zd.CurrentSerial); err != nil {
				lg.Error("failed to persist outgoing serial", "zone", zd.ZoneName, "err", err)
			}
		}
	}
	zd.ApexLen = new_zd.ApexLen
	zd.XfrType = new_zd.XfrType
	zd.ZoneStore = new_zd.ZoneStore
	zd.ZoneType = new_zd.ZoneType
	zd.Data = new_zd.Data
	zd.Ready = true
	zd.mu.Unlock()

	// Repopulate all dynamically generated RRs after zone refresh
	// (they may have been lost if not present in the transferred zone)
	zd.RepopulateDynamicRRs(dynamicRRs)

	// Post-refresh callbacks: queue sends and notifications that need the live zone pointer.
	for _, cb := range zd.OnZonePostRefresh {
		cb(zd)
	}

	if viper.GetBool("service.debug") {
		fname, err := zd.ZoneFileName()
		if err != nil {
			lg.Error("ZoneFileName failed", "zone", zd.ZoneName, "err", err)
		} else {
			_, err := new_zd.WriteFile(fname)
			if err != nil {
				lg.Error("WriteFile failed", "zone", zd.ZoneName, "err", err)
			} else {
				// zd.Logger.Printf("FetchFromUpstream: Zone %s: zone file written to %s", zd.ZoneName, f)
			}
		}
	}

	return true, nil
}

// ZoneFileName returns the path to use for this zone's file. Only zones with zonefile: set
// (in config) are written to disk; autozones and secondaries without zonefile are not persisted.
func (zd *ZoneData) ZoneFileName() (string, error) {
	if zd.Zonefile == "" {
		return "", fmt.Errorf("zone has no zonefile (autozone or secondary not persisted); not written to disk")
	}
	fname := path.Clean(zd.Zonefile)
	dirname := path.Dir(fname)
	if _, err := os.Stat(dirname); os.IsNotExist(err) {
		if err := os.MkdirAll(dirname, 0755); err != nil {
			return "", fmt.Errorf("zoneFileName: failed to create missing directory %s: %v", dirname, err)
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
		lg.Error("NameExists: unexpected zone storage type", "zoneStore", ZoneStoreToString[zd.ZoneStore])
		return false
	}

	lg.Debug("NameExists result", "qname", qname, "exists", ok)
	return ok
}

// XXX: FIXME: SliceZones do not yet have support for adding new owner names.

func (zd *ZoneData) GetOwner(qname string) (*OwnerData, error) {
	if !zd.Ready {
		return nil, fmt.Errorf("getOwner: zone %s: %w", zd.ZoneName, ErrZoneNotReady)
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
		lg.Error("GetOwner: zone storage not supported", "zoneStore", zd.ZoneStore)
		return &owner, fmt.Errorf("getOwner: only supported for SliceZone and MapZone, not %s",
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

func (zd *ZoneData) GetRRset(qname string, rrtype uint16) (*core.RRset, error) {
	if zd == nil {
		return nil, fmt.Errorf("getRRset: zone data is nil, this should not happen")
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
		lg.Error("GetOwnerNames: zone storage not supported", "zoneStore", zd.ZoneStore)
		return names, fmt.Errorf("getOwnerNames: only supported for SliceZone and MapZone, not %s",
			ZoneStoreToString[zd.ZoneStore])
	}
	return names, nil
}

// XXX: Is qname the name of a zone cut for a child zone?
func (zd *ZoneData) IsChildDelegation(qname string) bool {
	lg.Debug("IsChildDelegation: checking delegation", "qname", qname, "zone", zd.ZoneName)
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
	// For new secondary zones that haven't been transferred yet, return synthetic SOA
	// This allows the refresh engine to proceed with the first transfer without error.
	// Primary zones must load from disk and should not use synthetic SOA.
	if !zd.Ready && zd.ZoneType == Secondary && zd.IncomingSerial == 0 {
		// Return synthetic SOA with serial 0 and default refresh interval
		// Serial 0 ensures the first transfer will always proceed (any real serial > 0)
		lg.Debug("GetSOA: new secondary zone not yet transferred, returning synthetic SOA with serial 0", "zone", zd.ZoneName)
		return &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   zd.ZoneName,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    86400,
			},
			Ns:      "invalid.",
			Mbox:    "hostmaster." + zd.ZoneName,
			Serial:  0,
			Refresh: 300,     // 5 minutes default
			Retry:   1800,    // 30 minutes
			Expire:  1209600, // 2 weeks
			Minttl:  86400,   // 1 day
		}, nil
	}

	// For all other cases (primary zones, ready zones, catalog zones), require real data
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
		lg.Debug("PrintOwners: unsupported zone storage type", "zoneStore", ZoneStoreToString[zd.ZoneStore])
	}
}

func (zd *ZoneData) NotifyDownstreams() error {
	// zd.Logger.Printf("NotifyDownstreams: Zone %s has downstreams: %v", zd.ZoneName, zd.Downstreams)
	if zd == nil {
		lg.Error("NotifyDownstreams: zonedata is nil")
		return fmt.Errorf("zonedata is nil")
	}
	for _, d := range zd.Downstreams {

		// log.Printf("%s: Notifying downstream server %s about new SOA serial", zd.ZoneName, d)

		m := new(dns.Msg)
		m.SetNotify(zd.ZoneName)
		r, err := dns.Exchange(m, d)
		if err != nil {
			// well, we tried
			lg.Error("downstream NOTIFY failed", "downstream", d, "zone", zd.ZoneName, "err", err)
			continue
		}
		if r.Opcode != dns.OpcodeNotify {
			// well, we tried
			lg.Error("unexpected opcode from downstream on NOTIFY", "downstream", d, "zone", zd.ZoneName, "opcode", dns.OpcodeToString[r.Opcode])
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
	lg.Debug("FindZone: no zone found", "qname", qname)
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

// BumpSerialOnly increments the SOA serial and updates the SOA RR,
// but does not notify downstreams. Use when the caller will handle
// notification separately or when notification is not appropriate
// (e.g. inside a NOTIFY handler where triggering downstream NOTIFYs
// could cause side effects).
func (zd *ZoneData) BumpSerialOnly() (BumperResponse, error) {
	resp := BumperResponse{
		Zone: zd.ZoneName,
	}

	lg.Debug("BumpSerialOnly: bumping SOA serial", "zone", zd.ZoneName)
	zd.mu.Lock()
	defer zd.mu.Unlock()

	resp.OldSerial = zd.CurrentSerial
	zd.CurrentSerial++
	resp.NewSerial = zd.CurrentSerial
	if zd.KeyDB != nil && zd.KeyDB.Options[AuthOptPersistOutboundSerial] != "" {
		if err := zd.KeyDB.SaveOutgoingSerial(zd.ZoneName, zd.CurrentSerial); err != nil {
			lg.Error("failed to persist outgoing serial", "zone", zd.ZoneName, "err", err)
		}
	}
	if zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] {
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil {
			lg.Error("GetOwner failed", "zone", zd.ZoneName, "err", err)
			return resp, err
		}
		soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
		apex.RRtypes.Set(dns.TypeSOA, soaRRset)

		rrset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		_, err = zd.SignRRset(&rrset, zd.ZoneName, nil, true) // true = force signing, as we know the SOA has changed
		if err != nil {
			lg.Error("BumpSerialOnly: failed to sign SOA RRset", "zone", zd.ZoneName, "err", err)
			return resp, err
		}
		apex.RRtypes.Set(dns.TypeSOA, rrset)
	}

	return resp, nil
}

func (zd *ZoneData) BumpSerial() (BumperResponse, error) {
	resp, err := zd.BumpSerialOnly()
	if err != nil {
		return resp, err
	}
	zd.NotifyDownstreams()
	return resp, nil
}

func (zd *ZoneData) FetchChildDelegationData(childname string) (*ChildDelegationData, error) {
	lg.Debug("FetchChildDelegationData: fetching delegation data", "child", childname)
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
		RRsets:       make(map[string]map[uint16]core.RRset),
		NS_rrs:       []dns.RR{},
		A_glue:       []dns.RR{},
		AAAA_glue:    []dns.RR{},
	}

	owner, err := zd.GetOwner(childname)
	if err != nil {
		return nil, fmt.Errorf("fetchChildDelegationData: error getting owner for %s: %v", childname, err)
	}

	cdd.RRsets[childname] = map[uint16]core.RRset{
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
			return nil, fmt.Errorf("fetchChildDelegationData: error getting owner for %s: %v", ns, err)
		}
		cdd.RRsets[ns] = map[uint16]core.RRset{
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

	// Check HSYNCPARAM for parentsync=agent, which means the providers
	// coordinate parent sync via leader election.
	// Only if our identity is listed in the zone's HSYNC3 records.
	if !zd.Options[OptDelSyncChild] && Globals.App.Type == AppTypeAgent {
		matched, _, _ := zd.matchHsyncProvider(ourHsyncIdentities())
		if matched {
			apex, err := zd.GetOwner(zd.ZoneName)
			if err == nil && apex != nil {
				hsyncparamRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
				if exists && len(hsyncparamRRset.RRs) > 0 {
					if prr, ok := hsyncparamRRset.RRs[0].(*dns.PrivateRR); ok {
						if hsyncparam, ok := prr.Data.(*core.HSYNCPARAM); ok {
							if hsyncparam.GetParentSync() == core.HsyncParentSyncAgent {
								lg.Info("SetupZoneSync: HSYNCPARAM parentsync=agent, enabling delegation sync",
									"zone", zd.ZoneName)
								zd.Options[OptDelSyncChild] = true
								wantsSync = true
							}
						}
					}
				}
			}
		}
	}

	if !wantsSync {
		lg.Debug("SetupZoneSync: zone does not require delegation sync", "zone", zd.ZoneName)
		return nil
	}
	lg.Debug("SetupZoneSync: zone requests delegation sync", "zone", zd.ZoneName)

	// Is this a parent zone and should we then publish a DSYNC RRset?
	if zd.Options[OptDelSyncParent] {
		// For the moment we receive both updates and notifies on the same address as the rest of
		// the DNS service. Doesn't have to be that way, but for now it is.

		owner, err := zd.GetOwner("_dsync." + zd.ZoneName)
		if err != nil {
			lg.Error("SetupZoneSync: error getting _dsync owner", "zone", zd.ZoneName, "err", err)
			return err
		}

		var dsync_rrset core.RRset
		var exist bool
		if owner != nil {
			dsync_rrset, exist = owner.RRtypes.Get(core.TypeDSYNC)
		}

		if exist && len(dsync_rrset.RRs) > 0 {
			// If there is a DSYNC RRset, we assume that it is correct and will not modify
			lg.Debug("SetupZoneSync: DSYNC RRset exists, will not modify", "zone", zd.ZoneName)
		} else {
			lg.Debug("SetupZoneSync: no DSYNC RRset in zone, will add", "zone", zd.ZoneName)
			err := zd.PublishDsyncRRs()
			if err != nil {
				lg.Error("PublishDsyncRRs failed", "zone", zd.ZoneName, "err", err)
				return err
			}
		}

		// Figure out if there is a DSYNC RR with scheme UPDATE; if so, we need to ensure that
		// we generate a SIG(0) key pair for the target and publish the public key in the zone.
		updateTarget := dns.Fqdn(strings.Replace(viper.GetString("delegationsync.parent.update.target"), "{ZONENAME}", zd.ZoneName, 1))
		if _, ok := dns.IsDomainName(updateTarget); !ok {
			lg.Error("SetupZoneSync: invalid DSYNC update target", "zone", zd.ZoneName, "target", updateTarget)
		} else {
			lg.Debug("SetupZoneSync: DSYNC update target", "zone", zd.ZoneName, "target", updateTarget)
			err := zd.ParentSig0KeyPrep(updateTarget, zd.KeyDB)
			if err != nil {
				lg.Error("ParentSig0KeyPrep failed", "target", updateTarget, "err", err)
				return err
			}
		}
	}

	// If this is a child zone and we have the delegation-sync-child option set, we need to
	// ensure that there is a SIG(0) keypair and that the public key is published in the zone.
	// delegation-sync-child is valid for auth (standalone) or agent+multi-provider zones.
	// Combiner and signer roles don't do child delegation sync.
	if zd.Options[OptDelSyncChild] &&
		((Globals.App.Type == AppTypeAuth && !zd.Options[OptMultiProvider]) ||
			(Globals.App.Type == AppTypeAgent && zd.Options[OptMultiProvider])) {
		schemes := viper.GetStringSlice("delegationsync.child.schemes")
		if len(schemes) == 0 {
			lg.Error("SetupZoneSync: zone has delegation-sync-child enabled but delegationsync.child.schemes is not configured — delegation sync will not work", "zone", zd.ZoneName)
			zd.SetError(ConfigError, "delegation-sync-child enabled but delegationsync.child.schemes is not configured")
			return fmt.Errorf("delegation-sync-child enabled but delegationsync.child.schemes is not configured for zone %s", zd.ZoneName)
		}
		for _, scheme := range schemes {
			switch scheme {
			case "update":
				delsyncq <- DelegationSyncRequest{
					Command:  "DELEGATION-SYNC-SETUP",
					ZoneName: zd.ZoneName,
					ZoneData: zd,
					// Response:   make(chan DelegationSyncStatus),
				}

			case "notify":
				// CSYNC and CDS are published proactively when the zone is modified
				// (via zone_updater.go and delegation_sync.go).
			default:
			}
		}
	}

	return nil
}

// CollectDynamicRRs collects all dynamically generated RRsets for a zone that need to be
// repopulated after refresh. These RRs are stored outside ZoneData (in database or generated
// from config) and will be lost when the zone is reloaded.
//
// Returns a slice of RRsets that should be repopulated into the zone after refresh:
// - DNSKEY records (from DnssecKeyStore database, if online-signing enabled)
// - SIG(0) KEY records (from Sig0KeyStore database, if needed)
// - Transport signals (SVCB/TSYNC) - if Config provided and add-transport-signal enabled
func (zd *ZoneData) CollectDynamicRRs(conf *Config) []*core.RRset {
	var dynamicRRs []*core.RRset

	if (!zd.Options[OptAllowUpdates] && !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning]) || zd.KeyDB == nil {
		return dynamicRRs
	}

	// 1. Collect DNSKEY records (if signing enabled)
	if zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] {
		dak, err := zd.KeyDB.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			lg.Error("CollectDynamicRRs: failed to get DNSSEC keys", "zone", zd.ZoneName, "err", err)
		} else if dak != nil {
			var publishkeys []dns.RR
			for _, ksk := range dak.KSKs {
				publishkeys = append(publishkeys, dns.RR(&ksk.DnskeyRR))
			}
			for _, zsk := range dak.ZSKs {
				// If a ZSK has flags = 257 then it is a clone of a KSK and should not be included twice
				if zsk.DnskeyRR.Flags == 257 {
					continue
				}
				publishkeys = append(publishkeys, dns.RR(&zsk.DnskeyRR))
			}

			// Also include published/retired/foreign keys from database
			const fetchZoneDnskeysSql = `
SELECT keyid, flags, algorithm, keyrr FROM DnssecKeyStore WHERE zonename=? AND (state='published' OR state='retired' OR state='foreign')`
			rows, err := zd.KeyDB.Query(fetchZoneDnskeysSql, zd.ZoneName)
			if err != nil {
				lg.Error("CollectDynamicRRs: failed to query DNSKEYs", "zone", zd.ZoneName, "err", err)
			} else {
				defer rows.Close()
				for rows.Next() {
					var keyid, flags, algorithm string
					var keyrr string
					if err := rows.Scan(&keyid, &flags, &algorithm, &keyrr); err != nil {
						lg.Error("CollectDynamicRRs: failed to scan DNSKEY row", "zone", zd.ZoneName, "err", err)
						continue
					}
					if rr, err := dns.NewRR(keyrr); err == nil {
						publishkeys = append(publishkeys, rr)
					} else {
						lg.Error("CollectDynamicRRs: failed to parse DNSKEY RR", "keyrr", keyrr, "zone", zd.ZoneName, "err", err)
					}
				}
			}

			if len(publishkeys) > 0 {
				dynamicRRs = append(dynamicRRs, &core.RRset{
					Name:   zd.ZoneName,
					Class:  dns.ClassINET,
					RRtype: dns.TypeDNSKEY,
					RRs:    publishkeys,
				})
			}
		}
	}

	// 2. Collect SIG(0) KEY records (if they should be published)
	if !zd.Options[OptDontPublishKey] {
		sak, err := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
		if err != nil {
			// Not an error if no SIG(0) keys exist
			lg.Debug("CollectDynamicRRs: no active SIG(0) keys for zone (or error)", "zone", zd.ZoneName, "err", err)
		} else if sak != nil && len(sak.Keys) > 0 {
			var keyRRs []dns.RR
			for _, pkc := range sak.Keys {
				if strings.HasSuffix(pkc.KeyRR.Header().Name, zd.ZoneName) {
					keyRRs = append(keyRRs, &pkc.KeyRR)
				}
			}
			if len(keyRRs) > 0 {
				dynamicRRs = append(dynamicRRs, &core.RRset{
					Name:   zd.ZoneName,
					Class:  dns.ClassINET,
					RRtype: dns.TypeKEY,
					RRs:    keyRRs,
				})
			}
		}
	}

	// 3. Collect transport signals (if add-transport-signal enabled)
	// Collect from zd.TransportSignal if it exists, and also from zone data at _dns.* owners
	if zd.Options[OptAddTransportSignal] {
		// Collect from zd.TransportSignal field
		if zd.TransportSignal != nil && len(zd.TransportSignal.RRs) > 0 {
			// Clone the transport signal RRset
			tsClone := &core.RRset{
				Name:   zd.TransportSignal.Name,
				Class:  dns.ClassINET,
				RRtype: zd.TransportSignal.RRtype,
				RRs:    make([]dns.RR, len(zd.TransportSignal.RRs)),
				RRSIGs: make([]dns.RR, len(zd.TransportSignal.RRSIGs)),
			}
			for i, rr := range zd.TransportSignal.RRs {
				tsClone.RRs[i] = dns.Copy(rr)
			}
			for i, rr := range zd.TransportSignal.RRSIGs {
				tsClone.RRSIGs[i] = dns.Copy(rr)
			}
			dynamicRRs = append(dynamicRRs, tsClone)
		}

		// Also collect transport signals from zone data at _dns.* owners
		// (they may exist in zone data even if TransportSignal field is not set)
		for item := range zd.Data.IterBuffered() {
			owner := item.Key
			if strings.HasPrefix(owner, "_dns.") {
				od := item.Val
				// Check for SVCB
				if svcbRRset, exists := od.RRtypes.Get(dns.TypeSVCB); exists && len(svcbRRset.RRs) > 0 {
					svcbClone := &core.RRset{
						Name:   owner,
						Class:  dns.ClassINET,
						RRtype: dns.TypeSVCB,
						RRs:    make([]dns.RR, len(svcbRRset.RRs)),
						RRSIGs: make([]dns.RR, len(svcbRRset.RRSIGs)),
					}
					for i, rr := range svcbRRset.RRs {
						svcbClone.RRs[i] = dns.Copy(rr)
					}
					for i, rr := range svcbRRset.RRSIGs {
						svcbClone.RRSIGs[i] = dns.Copy(rr)
					}
					dynamicRRs = append(dynamicRRs, svcbClone)
				}
				// Check for TSYNC
				if tsyncRRset, exists := od.RRtypes.Get(core.TypeTSYNC); exists && len(tsyncRRset.RRs) > 0 {
					tsyncClone := &core.RRset{
						Name:   owner,
						Class:  dns.ClassINET,
						RRtype: core.TypeTSYNC,
						RRs:    make([]dns.RR, len(tsyncRRset.RRs)),
						RRSIGs: make([]dns.RR, len(tsyncRRset.RRSIGs)),
					}
					for i, rr := range tsyncRRset.RRs {
						tsyncClone.RRs[i] = dns.Copy(rr)
					}
					for i, rr := range tsyncRRset.RRSIGs {
						tsyncClone.RRSIGs[i] = dns.Copy(rr)
					}
					dynamicRRs = append(dynamicRRs, tsyncClone)
				}
			}
		}
	}

	return dynamicRRs
}

// RepopulateDynamicRRs repopulates dynamically generated RRsets into the zone data after refresh.
// The RRsets are passed in from RefreshEngine which collected them before the refresh.
func (zd *ZoneData) RepopulateDynamicRRs(dynamicRRs []*core.RRset) {
	if len(dynamicRRs) == 0 {
		return
	}

	for _, rrset := range dynamicRRs {
		if rrset == nil || len(rrset.RRs) == 0 {
			continue
		}

		owner, err := zd.GetOwner(rrset.Name)
		if err != nil || owner == nil {
			// Owner doesn't exist, create it
			if zd.ZoneStore == MapZone {
				owner = &OwnerData{
					Name:    rrset.Name,
					RRtypes: NewRRTypeStore(),
				}
				zd.Data.Set(rrset.Name, *owner)
			} else {
				lg.Error("RepopulateDynamicRRs: failed to get/create owner", "owner", rrset.Name, "zone", zd.ZoneName, "err", err)
				continue
			}
		}

		// Get existing RRset if any, or create new one
		existing, exists := owner.RRtypes.Get(rrset.RRtype)
		if exists {
			// Merge: add any RRs that don't already exist
			for _, newRR := range rrset.RRs {
				present := false
				for _, oldRR := range existing.RRs {
					if dns.IsDuplicate(newRR, oldRR) {
						present = true
						break
					}
				}
				if !present {
					existing.RRs = append(existing.RRs, newRR)
				}
			}
			// Merge RRSIGs (replace if new ones exist)
			if len(rrset.RRSIGs) > 0 {
				existing.RRSIGs = rrset.RRSIGs
			}
			owner.RRtypes.Set(rrset.RRtype, existing)
		} else {
			// Set new RRset
			owner.RRtypes.Set(rrset.RRtype, *rrset)
		}

		// Update owner in zone data (in case we created it or modified it)
		if zd.ZoneStore == MapZone {
			zd.Data.Set(rrset.Name, *owner)
		}

		// Special handling for transport signals: also set zd.TransportSignal
		// Use the first transport signal RRset found as the primary one
		if (rrset.RRtype == dns.TypeSVCB || rrset.RRtype == core.TypeTSYNC) && zd.TransportSignal == nil {
			zd.TransportSignal = rrset
			zd.AddTransportSignal = true
		}
	}

	lg.Info("RepopulateDynamicRRs: repopulated dynamic RRsets", "count", len(dynamicRRs), "zone", zd.ZoneName)
}

func (zd *ZoneData) SetupZoneSigning(resignq chan<- *ZoneData) error {
	if Globals.App.Type == AppTypeAgent {
		return nil // agents never sign
	}

	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return nil // this zone should not be signed (at least not by us)
	}

	if zd.ZoneType != Primary && !zd.Options[OptInlineSigning] {
		return nil // non-primary zones require inline-signing to be signed
	}

	kdb := zd.KeyDB
	newrrsigs, err := zd.SignZone(kdb, false)
	if err != nil {
		lg.Error("SignZone failed", "zone", zd.ZoneName, "err", err)
		return err
	}

	lg.Info("SetupZoneSigning: zone signed", "zone", zd.ZoneName, "newRRSIGs", newrrsigs)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	select {
	case resignq <- zd:
	case <-ctx.Done():
		lg.Error("SetupZoneSigning: timeout sending zone to resign queue", "zone", zd.ZoneName)
	}

	return nil
}

func (zd *ZoneData) ReloadZone(refreshCh chan<- ZoneRefresher, force bool, wait bool, timeoutStr string) (string, error) {
	if zd.Options[OptDirty] {
		return "", fmt.Errorf("zone %s: zone has been modified, reload not possible", zd.ZoneName)
	}

	var respch = make(chan RefresherResponse, 1)
	refreshCh <- ZoneRefresher{
		Name:     zd.ZoneName,
		Response: respch,
		Force:    force,
		Wait:     wait,
	}

	var resp RefresherResponse

	timeout := 2 * time.Second
	if wait {
		timeout = 10 * time.Second // default for --error mode
		if timeoutStr != "" {
			if d, err := time.ParseDuration(timeoutStr); err == nil {
				timeout = d
			}
		}
	}

	select {
	case resp = <-respch:
	case <-time.After(timeout):
		return fmt.Sprintf("Zone %s: timeout waiting for response from RefreshEngine", zd.ZoneName), fmt.Errorf("zone %s: timeout waiting for response from RefreshEngine", zd.ZoneName)
	}

	if resp.Error {
		lg.Error("ReloadZone: error from RefreshEngine", "err", resp.ErrorMsg)
		return "", fmt.Errorf("%s", resp.ErrorMsg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: reloaded", zd.ZoneName)
	}
	return resp.Msg, nil
}

type DelegationData struct {
	CurrentNS *core.RRset
	AddedNS   *core.RRset
	RemovedNS *core.RRset

	BailiwickNS []string
	A_glue      map[string]*core.RRset // map[nsname]
	AAAA_glue   map[string]*core.RRset // map[nsname]
	Actions     []dns.RR               // actions are DNS UPDATE actions that modify delegation data
	Time        time.Time
}

func (zd *ZoneData) DelegationData() (*DelegationData, error) {
	dd := DelegationData{
		Time:      time.Now(),
		AddedNS:   &core.RRset{},
		RemovedNS: &core.RRset{Name: zd.ZoneName},
		A_glue:    map[string]*core.RRset{},
		AAAA_glue: map[string]*core.RRset{},
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
			lg.Error("in-bailiwick NS without any address RRs", "zone", zd.ZoneName, "ns", nsname)
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

func (kdb *KeyDB) CreateAutoZone(zonename string, addrs []string, nsNames []string) (*ZoneData, error) {
	if zonename == "" {
		return nil, fmt.Errorf("zonename cannot be empty")
	}
	if !dns.IsFqdn(zonename) {
		return nil, fmt.Errorf("zonename must be fully qualified (end with dot)")
	}

	lg.Info("CreateAutoZone", "zone", zonename)

	// Create a fake zone for the sidecar identity just to be able to
	// to use to generate the TLSA.
	// Use "invalid." as the NS record for all autozones (RFC 9432 recommendation)
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
{ZONENAME}     IN NS  invalid.
`
	currentTime := fmt.Sprintf("%d", time.Now().Unix())
	zonedatastr := strings.ReplaceAll(tmpl, "{ZONENAME}", zonename)
	zonedatastr = strings.ReplaceAll(zonedatastr, "{SERIAL}", currentTime)

	// Explicit nameserver hostnames (no glue): use for NS RRset only
	if len(nsNames) > 0 {
		lg.Debug("CreateAutoZone: using configured nameservers (no glue)", "nameservers", nsNames)
		nsLines := ""
		for _, n := range nsNames {
			nsLines += fmt.Sprintf("%s     IN NS  %s\n", zonename, dns.Fqdn(n))
		}
		zonedatastr = strings.ReplaceAll(zonedatastr, zonename+"     IN NS  invalid.\n", nsLines)
	} else if len(addrs) > 0 {
		// Add address records if addresses are provided (NS ns.{zone} + glue)
		lg.Debug("CreateAutoZone: adding address records", "addrs", addrs)

		// Update NS record to point to ns.{zonename} instead of invalid. when addresses are provided
		// This ensures the NS and glue records use the same owner name (no orphaned records)
		nsTarget := fmt.Sprintf("ns.%s", zonename)
		zonedatastr = strings.ReplaceAll(zonedatastr, "invalid.", nsTarget)

		for _, addr := range addrs {
			if !isValidIP(addr) {
				lg.Error("CreateAutoZone: invalid IP address", "addr", addr)
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
	}

	lg.Debug("CreateAutoZone: template zone data", "data", zonedatastr)

	zd := &ZoneData{
		ZoneName:  zonename,
		ZoneStore: MapZone,
		Logger:    log.Default(),
		ZoneType:  Primary,
		Options:   map[ZoneOption]bool{OptAutomaticZone: true},
		KeyDB:     kdb,
	}

	lg.Debug("CreateAutoZone: reading zone data", "zone", zonename)
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
	lg.Debug("FindDnsEngineAddrs: dnsengine addresses", "addresses", conf.DnsEngine.Addresses)
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
