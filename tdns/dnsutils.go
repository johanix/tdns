/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/spf13/viper"
	"github.com/twotwotwo/sorts"
	// "github.com/gookit/goutil/dump"
)

const (
	year68     = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits
	timelayout = "2006-01-02 15:04:05"
)

// TODO: Add support for TSIG zone transfers.

func (zd *ZoneData) ZoneTransferIn(upstream string, serial uint32, ttype string) (uint32, error) {

	if upstream == "" {
		log.Fatalf("ZoneTransfer: upstream not set")
	}

	msg := new(dns.Msg)
	if ttype == "ixfr" {
		// msg.SetIxfr(zone, serial, soa.Ns, soa.Mbox)
		msg.SetIxfr(zd.ZoneName, serial, "", "")
	} else {
		msg.SetAxfr(zd.ZoneName)
	}

	if zd.ZoneStore == MapZone || zd.ZoneStore == SliceZone {
		// zd.Data = make(map[string]OwnerData, 30)
		zd.Data = cmap.New[OwnerData]()
	}
	log.Printf("ZoneTransferIn: Zone %s ZoneStore: %s", zd.ZoneName, ZoneStoreToString[zd.ZoneStore])

	transfer := new(dns.Transfer)
	answerChan, err := transfer.In(msg, upstream)
	if err != nil {
		zd.Logger.Printf("Error from transfer.In: %v\n", err)
		return 0, err
	}

	count := 0
	firstSoaSeen := false
	for envelope := range answerChan {
		if envelope.Error != nil {
			zd.Logger.Printf("ZoneTransfer: zone %s error: %v", zd.ZoneName, envelope.Error)
			return 0, envelope.Error
		}

		for _, rr := range envelope.RR {
			count++
			firstSoaSeen = zd.SortFunc(rr, firstSoaSeen)
		}
	}

	// apex, _ := zd.Data[zd.ZoneName]
	apex, _ := zd.Data.Get(zd.ZoneName)
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs[0].(*dns.SOA)
	zd.CurrentSerial = soa.Serial
	zd.IncomingSerial = soa.Serial

	zd.Logger.Printf("*** Zone %s transferred from upstream %s. No errors.", zd.ZoneName, upstream)
	if zd.Data.IsEmpty() {
		return 0, nil
	}

	zd.ComputeIndices() // if zd.ZoneStore == SliceZone, otherwise no-op

	return soa.Serial, nil
}

func (zd *ZoneData) ZoneTransferOut(w dns.ResponseWriter, r *dns.Msg) (int, error) {
	zone := dns.Fqdn(zd.ZoneName)

	if zd.Verbose {
		zd.Logger.Printf("ZoneTransferOut: Will try to serve zone %s", zone)
	}

	outbound_xfr := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		err := tr.Out(w, r, outbound_xfr)
		if err != nil {
			zd.Logger.Printf("Error from transfer.Out(): %v", err)
		}
		wg.Done()
	}()

	apex, _ := zd.GetOwner(zd.ZoneName)
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs[0].(*dns.SOA)
	soa.Serial = zd.CurrentSerial

	total_sent := 0
	count := 0
	// env := dns.Envelope{}
	rrs := []dns.RR{soa}

	// SOA
	// env.RR = append(env.RR, soa)
	// XXX: If we change the SOA serial we must also recompute the RRSIG.
	// env.RR = append(env.RR, apex.RRtypes[dns.TypeSOA].RRSIGs...)
	rrs = append(rrs, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs...)
	if Globals.Debug {
		// zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, soa.String())
	}

	// Rest of apex
	for _, rrt := range apex.RRtypes.Keys() {
		if rrt != dns.TypeSOA {
			// env.RR = append(env.RR, apex.RRtypes[rrt].RRs...)
			rrs = append(rrs, apex.RRtypes.GetOnlyRRSet(rrt).RRs...)
			if Globals.Debug {
				// zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, apex.RRtypes.GetOnlyRRSet(rrt).RRs)
			}
			// env.RR = append(env.RR, apex.RRtypes[rrt].RRSIGs...)
			rrs = append(rrs, apex.RRtypes.GetOnlyRRSet(rrt).RRSIGs...)
		}
	}
	count = len(rrs)

	switch zd.ZoneStore {
	case SliceZone:
		// Rest of zone
		for _, owner := range zd.Owners {
			if owner.Name == zd.ZoneName {
				continue
			}
			for _, rrt := range owner.RRtypes.Keys() {
				rrl := owner.RRtypes.GetOnlyRRSet(rrt)
				rrs = append(rrs, rrl.RRs...)
				if Globals.Debug {
					// zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, rrl.RRs)
				}
				count += len(rrl.RRs)
				rrs = append(rrs, rrl.RRSIGs...)
				count += len(rrl.RRSIGs)

				if count >= 400 {
					total_sent += count
					outbound_xfr <- &dns.Envelope{RR: rrs}
					rrs = []dns.RR{}
					count = 0
				}
			}
		}

	case MapZone:
		// Rest of zone
		for _, owner := range zd.Data.Keys() {
			omap, _ := zd.Data.Get(owner)
			if owner == zd.ZoneName {
				continue
			}
			for _, rrt := range omap.RRtypes.Keys() {
				rrl := omap.RRtypes.GetOnlyRRSet(uint16(rrt))
				rrs = append(rrs, rrl.RRs...)
				if Globals.Debug {
					// zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, rrl.RRs)
				}
				count += len(rrl.RRs)
				rrs = append(rrs, rrl.RRSIGs...)
				count += len(rrl.RRSIGs)

				if count >= 400 {
					total_sent += count
					outbound_xfr <- &dns.Envelope{RR: rrs}
					rrs = []dns.RR{}
					count = 0
				}
			}
		}

	default:
		zd.Logger.Printf("Zone %s: zone store %d: outbound zone transfer not supported. Sorry.",
			zd.ZoneName, zd.ZoneStore)
	}

	// env.RR = append(env.RR, soa) // trailing SOA
	rrs = append(rrs, soa)
	if Globals.Debug {
		// zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, soa)
	}

	total_sent += len(rrs)
	zd.Logger.Printf("XfrOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)\n",
		zd.ZoneName, len(rrs), total_sent)
	outbound_xfr <- &dns.Envelope{RR: rrs}

	close(outbound_xfr)
	wg.Wait() // wait until everything is written out
	w.Close() // close connection

	zd.Logger.Printf("ZoneTransferOut: %s: Sent %d RRs.", zone, total_sent)

	return total_sent, nil
}

func (zd *ZoneData) ReadZoneFile(filename string, force bool) (bool, uint32, error) {
	zd.Logger.Printf("ReadZoneData: zone: %s", zd.ZoneName)

	f, err := os.Open(filename)
	if err != nil {
		return false, 0, fmt.Errorf("ReadZoneFile: Error: failed to read %s: %v", filename, err)
	}
	return zd.ParseZoneFromReader(bufio.NewReader(f), force)
}

func (zd *ZoneData) ReadZoneData(zoneData string, force bool) (bool, uint32, error) {
	zd.Logger.Printf("ReadZoneData: zone: %s", zd.ZoneName)
	return zd.ParseZoneFromReader(strings.NewReader(zoneData), force)
}

func (zd *ZoneData) ParseZoneFromReader(r io.Reader, force bool) (bool, uint32, error) {
	zd.Logger.Printf("ParseZoneFromReader: zone: %s", zd.ZoneName)

	switch zd.ZoneStore {
	case MapZone, SliceZone:
		zd.Data = cmap.New[OwnerData]()
	default:
		return false, 0, fmt.Errorf("ParseZoneFromReader: zone store %d not supported", zd.ZoneStore)
	}

	zp := dns.NewZoneParser(r, "", "")
	zp.SetIncludeAllowed(true)

	firstSoaSeen := false
	checkedForUnchanged := false

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if Globals.Debug {
			//  zd.Logger.Printf("ReadZoneData: parsed RR: %s", rr.String())
		}
		firstSoaSeen = zd.SortFunc(rr, firstSoaSeen)

		if firstSoaSeen && !checkedForUnchanged {
			checkedForUnchanged = true
			apex, _ := zd.Data.Get(zd.ZoneName)
			//dump.P(apex)
			soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs[0].(*dns.SOA)
			zd.Logger.Printf("ParseZoneFromReader: %s: old incoming serial: %d new SOA serial: %d",
				zd.ZoneName, zd.IncomingSerial, soa.Serial)
			if soa.Serial == zd.IncomingSerial {
				if !force {
					zd.Logger.Printf("ParseZoneFromReader: %s: new SOA serial is the same as current. Reload not needed.", zd.ZoneName)
					return false, soa.Serial, nil
				}
				zd.Logger.Printf("ParseZoneFromReader: %s: new SOA serial is the same as current but still forced to reload.", zd.ZoneName)
			}
		}
	}

	var err error

	if err = zp.Err(); err != nil {
		zd.Logger.Printf("ParseZoneFromReader: Zone %s: Error from ZoneParser: %v", zd.ZoneName, err)
		return false, 0, err
	}

	apex, _ := zd.Data.Get(zd.ZoneName)
	if err != nil {
		return false, 0, fmt.Errorf("ParseZoneFromReader: Zone %s: Error: failed to get zone apex %v", zd.ZoneName, err)
	}

	soa_rrset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	var soa *dns.SOA
	if len(soa_rrset.RRs) > 0 {
		soa = soa_rrset.RRs[0].(*dns.SOA)
	} else {
		log.Printf("ParseZoneFromReader: Zone %s: Error: SOA: %v", zd.ZoneName, soa_rrset)
		return false, 0, fmt.Errorf("ParseZoneFromReader: Zone %s: Error: SOA: %v", zd.ZoneName, soa_rrset)
	}

	zd.CurrentSerial = soa.Serial
	zd.IncomingSerial = soa.Serial

	zd.ComputeIndices()
	zd.XfrType = "axfr"
	return true, soa.Serial, nil
}

func (zd *ZoneData) SortFunc(rr dns.RR, firstSoaSeen bool) bool {
	owner := rr.Header().Name
	// if zd.FoldCase {
	if zd.Options[OptFoldCase] {
		owner = strings.ToLower(owner)
	}
	rrtype := rr.Header().Rrtype

	//	zd.Logger.Printf("SortFunc: owner=%s rrtype=%s (%d)", owner, dns.TypeToString[rrtype], rrtype)

	var ztype ZoneStore
	var omap OwnerData
	var ok bool

	switch zd.ZoneStore {
	case XfrZone:
		ztype = XfrZone
	case SliceZone:
		fallthrough // store slicezones as mapzones during inbound transfer, sort afterwards into slice
	case MapZone:
		// omap = zd.Data[owner]
		if omap, ok = zd.Data.Get(owner); !ok {

			// if omap.RRtypes == nil {
			omap.Name = owner
			omap.RRtypes = NewRRTypeStore()
		}
		ztype = MapZone
	}

	var tmp RRset

	switch v := rr.(type) {
	case *dns.SOA:
		if !firstSoaSeen {
			// zd.Logger.Printf("SortFunc: zone %s firstSoaSeen is nil. Setting to true", zd.ZoneName)
			firstSoaSeen = true
			zd.ApexLen++
			if ztype == MapZone {
				tmp = omap.RRtypes.GetOnlyRRSet(rrtype)
				tmp.RRs = append(tmp.RRs, rr)
				omap.RRtypes.Set(rrtype, tmp)
			}
		}

	case *dns.RRSIG:
		rrt := v.TypeCovered
		switch ztype {
		case MapZone:
			tmp = omap.RRtypes.GetOnlyRRSet(rrt)
			tmp.RRSIGs = append(tmp.RRSIGs, rr)
			omap.RRtypes.Set(rrt, tmp)
		}

	default:
		switch ztype {
		case MapZone:
			tmp = omap.RRtypes.GetOnlyRRSet(rrtype)
			tmp.RRs = append(tmp.RRs, rr)
			omap.RRtypes.Set(rrtype, tmp)
		}
	}
	if ztype == MapZone {
		zd.Data.Set(owner, omap)
	}
	return firstSoaSeen
}

func (zd *ZoneData) WriteTmpFile(lg *log.Logger) (string, error) {
	f, err := os.CreateTemp(viper.GetString("external.tmpdir"), fmt.Sprintf("%s*.zone", zd.ZoneName))
	if err != nil {
		return f.Name(), err
	}

	err = zd.WriteZoneToFile(f)
	if err != nil {
		return f.Name(), err
	}
	return f.Name(), nil
}

func (zd *ZoneData) WriteFile(filename string) (string, error) {
	fname := fmt.Sprintf("%s/%s", viper.GetString("external.filedir"), filename)
	f, err := os.Create(fname)
	if err != nil {
		return fname, err
	}

	err = zd.WriteZoneToFile(f)
	if err != nil {
		return f.Name(), err
	}
	return f.Name(), nil
}

func (zd *ZoneData) WriteZoneToFile(f *os.File) error {
	var err error
	var bytes, totalbytes int
	zonedata := ""

	writer := bufio.NewWriter(f)

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		log.Printf("WriteZoneToFile: Error: failed to get zone apex %s: %v", zd.ZoneName, err)
		return err
	}
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	soa.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial

	//	zonedata += soa.String() + "\n"
	count := 0
	//	var total_sent int

	switch zd.ZoneStore {
	case SliceZone:
		// SOA
		soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		zonedata += RRsetToString(&soa)
		count += len(soa.RRs) + len(soa.RRSIGs)

		// Rest of apex
		for _, rrt := range apex.RRtypes.Keys() {
			if rrt != dns.TypeSOA {
				rrset := apex.RRtypes.GetOnlyRRSet(rrt)
				zonedata += RRsetToString(&rrset)
				count += len(rrset.RRs) + len(rrset.RRSIGs)
			}
		}

		// Rest of zone
		for _, owner := range zd.Owners {
			if owner.Name == zd.ZoneName {
				continue
			}
			for _, rrt := range owner.RRtypes.Keys() {
				rrl := owner.RRtypes.GetOnlyRRSet(rrt)
				zonedata += RRsetToString(&rrl)
				count += len(rrl.RRs) + len(rrl.RRSIGs)

				if count >= 1000 {
					//				   	total_sent += count
					bytes, err = writer.WriteString(zonedata)
					if err != nil {
						return err
					}
					totalbytes += bytes
					bytes = 0
					count = 0
				}
			}
		}

	case MapZone:
		// SOA
		soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		zonedata += RRsetToString(&soa)
		count += len(soa.RRs) + len(soa.RRSIGs)

		// Rest of apex
		for _, rrt := range apex.RRtypes.Keys() {
			if rrt != dns.TypeSOA {
				rrset := apex.RRtypes.GetOnlyRRSet(rrt)
				zonedata += RRsetToString(&rrset)
				count += len(rrset.RRs) + len(rrset.RRSIGs)
			}
		}

		// Rest of zone
		for _, owner := range zd.Data.Keys() {
			omap, _ := zd.Data.Get(owner)
			if owner == zd.ZoneName {
				continue
			}
			for _, rrt := range omap.RRtypes.Keys() {
				rrl := omap.RRtypes.GetOnlyRRSet(rrt)
				zonedata += RRsetToString(&rrl)
				count += len(rrl.RRs) + len(rrl.RRSIGs)

				if count >= 1000 {
					//					total_sent += count
					bytes, err = writer.WriteString(zonedata)
					if err != nil {
						return err
					}
					totalbytes += bytes
					bytes = 0
					count = 0
				}
			}
		}

	default:
		zd.Logger.Printf("Zone %s: zone store %d: no outbound zone transfer. Sorry.",
			zd.ZoneName, zd.ZoneStore)
	}

	// 	for _, rr := range zd.RRs {
	// 		zonedata += rr.String() + "\n"
	// 		rrcount++
	// 		if rrcount%1000 == 0 {
	// 			bytes, err = writer.WriteString(zonedata)
	// 			if err != nil {
	// 				return err
	// 			}
	// 			totalbytes += bytes
	// 			bytes = 0
	// 			zonedata = ""
	// 		}
	// 	}
	bytes, err = writer.WriteString(zonedata)
	if err != nil {
		return err
	}
	totalbytes += bytes
	writer.Flush()
	return err
}

func RRsetToString(rrset *RRset) string {
	var tmp string
	for _, rr := range rrset.RRs {
		tmp += rr.String() + "\n"
	}
	for _, rr := range rrset.RRSIGs {
		tmp += rr.String() + "\n"
	}
	return tmp
}

func InBailiwick(zone string, ns *dns.NS) bool {
	return strings.HasSuffix(ns.Ns, zone)
}

func (zd *ZoneData) ComputeIndices() {
	if zd.ZoneStore == SliceZone {
		// for _, v := range zd.Data {
		for _, key := range zd.Data.Keys() {
			v, _ := zd.Data.Get(key)
			zd.Owners = append(zd.Owners, v)
		}
		quickSort(zd.Owners)
		// zd.Data = nil
		zd.Data.Clear()
		// zd.OwnerIndex = map[string]int{}
		zd.OwnerIndex = cmap.New[int]()
		for i, od := range zd.Owners {
			// zd.OwnerIndex[od.Name] = i
			zd.OwnerIndex.Set(od.Name, i)
		}
		idx, _ := zd.OwnerIndex.Get(zd.ZoneName)
		soas := zd.Owners[idx].RRtypes.GetOnlyRRSet(dns.TypeSOA)
		soas.RRs = soas.RRs[:1]
		zd.Owners[idx].RRtypes.Set(dns.TypeSOA, soas)
	}
	if zd.Verbose {
		zd.PrintOwners()
	}
}

func (owners Owners) Len() int {
	return len(owners)
}

func (owners Owners) Swap(i, j int) {
	owners[i], owners[j] = owners[j], owners[i]
}

func (owners Owners) Less(i, j int) bool {
	return owners[i].Name < owners[j].Name
}

func quickSort(sortable sort.Interface) {
	sorts.Quicksort(sortable)
}

func SetupIMR() {
	if Globals.IMR == "" {
		Globals.IMR = viper.GetString("resolver.address")
	}

	if Globals.Verbose {
		log.Printf("Using resolver \"%s\"\n", Globals.IMR)
	}
}
