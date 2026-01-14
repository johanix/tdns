/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"fmt"
	"log"
	"time"

	core "github.com/johanix/tdns/v0.x/core"
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

	var oldapex *OwnerData
	// ------------------------------------------------------------
	// Inline version of zd.GetOwner() to get around the "ready" test:
	var owner OwnerData
	var ok bool
	switch zd.ZoneStore {
	case SliceZone:
		if len(zd.Owners) == 0 {
			oldapex = nil
		}
		idx, _ := zd.OwnerIndex.Get(zd.ZoneName)
		oldapex = &zd.Owners[idx]

	case MapZone:
		if zd.Data.IsEmpty() {
			oldapex = nil
		}
		if owner, ok = zd.Data.Get(zd.ZoneName); ok {
			oldapex = &owner
		} else {
			oldapex = nil
		}

	default:
		zd.Logger.Printf("HsyncChanged: zone storage not supported: %q", ZoneStoreToString[zd.ZoneStore])
	}
	// ------

	// log.Printf("*** newzd.PrintOwnerNames()")
	// newzd.PrintOwnerNames()
	// log.Printf("*** newzd.PrintApexRRs()")
	// newzd.PrintApexRRs()

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
