/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"github.com/twotwotwo/sorts"
	"github.com/orcaman/concurrent-map/v2"
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
	soa := apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA)
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
		tr.Out(w, r, outbound_xfr)
		wg.Done()
	}()

	apex, _ := zd.GetOwner(zd.ZoneName)
	soa := apex.RRtypes[dns.TypeSOA].RRs[0]
	soa.(*dns.SOA).Serial = zd.CurrentSerial

	total_sent := 0
	count := 0
	env := dns.Envelope{}

	env.RR = append(env.RR, soa)

	switch zd.ZoneStore {
	case SliceZone:
		// SOA
		env.RR = append(env.RR, apex.RRtypes[dns.TypeSOA].RRSIGs...)

		// Rest of apex
		for rrt, _ := range apex.RRtypes {
			if rrt != dns.TypeSOA {
				env.RR = append(env.RR, apex.RRtypes[rrt].RRs...)
				env.RR = append(env.RR, apex.RRtypes[rrt].RRSIGs...)
			}
		}
		count = len(env.RR)

		// Rest of zone
		for _, owner := range zd.Owners {
			if owner.Name == zd.ZoneName {
				continue
			}
			for _, rrl := range owner.RRtypes {
				env.RR = append(env.RR, rrl.RRs...)
				count += len(rrl.RRs)
				env.RR = append(env.RR, rrl.RRSIGs...)
				count += len(rrl.RRSIGs)

				if count >= 500 {
					total_sent += count
					outbound_xfr <- &env
					env = dns.Envelope{}
					count = 0
				}
			}
		}

	case MapZone:
		// SOA
		env.RR = append(env.RR, apex.RRtypes[dns.TypeSOA].RRSIGs...)

		// Rest of apex
		for rrt, _ := range apex.RRtypes {
			if rrt != dns.TypeSOA {
				env.RR = append(env.RR, apex.RRtypes[rrt].RRs...)
				env.RR = append(env.RR, apex.RRtypes[rrt].RRSIGs...)
			}
		}
		count = len(env.RR)

		// Rest of zone
		for _, owner := range zd.Data.Keys() {
		        omap, _ := zd.Data.Get(owner)
			if owner == zd.ZoneName {
				continue
			}
			for _, rrl := range omap.RRtypes {
				env.RR = append(env.RR, rrl.RRs...)
				count += len(rrl.RRs)
				env.RR = append(env.RR, rrl.RRSIGs...)
				count += len(rrl.RRSIGs)

				if count >= 500 {
					total_sent += count
					outbound_xfr <- &env
					env = dns.Envelope{}
					count = 0
				}
			}
		}

	default:
		zd.Logger.Printf("Zone %s: zone store %d: no outbound zone transfer. Sorry.",
				       zd.ZoneName, zd.ZoneStore)
	}

	env.RR = append(env.RR, soa) // trailing SOA

	total_sent += len(env.RR)
	zd.Logger.Printf("ZoneTransferOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)\n",
		zd.ZoneName, len(env.RR), total_sent)
	outbound_xfr <- &env

	close(outbound_xfr)
	wg.Wait() // wait until everything is written out
	w.Close() // close connection

	zd.Logger.Printf("ZoneTransferOut: %s: Sent %d RRs.", zone, total_sent)

	return total_sent, nil
}

func ZoneTransferPrint(zname, upstream string, serial uint32, ttype uint16) error {
	msg := new(dns.Msg)
	if ttype == dns.TypeIXFR {
		// msg.SetIxfr(zname, serial, soa.Ns, soa.Mbox)
		msg.SetIxfr(zname, serial, "", "")
	} else {
		msg.SetAxfr(zname)
	}

	transfer := new(dns.Transfer)
	answerChan, err := transfer.In(msg, upstream)
	if err != nil {
		fmt.Printf("Error from transfer.In: %v\n", err)
		return err
	}

	for envelope := range answerChan {
		if envelope.Error != nil {
			errstr := envelope.Error.Error()
			if strings.Contains(errstr, "bad xfr rcode: 9") {
			   fmt.Printf("Error: %s: Not authoritative for zone %s\n",
			   		      upstream, zname)
			} else {
			   fmt.Printf("Error: zone %s error: %v", zname, errstr)
			}
			break
		}

		for _, rr := range envelope.RR {
			fmt.Printf("%s\n", rr.String())
		}
	}
	return nil
}

// If the zone is completely loaded, return true otherwise false
func (zd *ZoneData) ReadZoneFile(filename string, force bool) (bool, uint32, error) {
	zd.Logger.Printf("ReadZoneFile: zone: %s filename: %s", zd.ZoneName, filename)

	f, err := os.Open(filename)
	if err != nil {
		return false, 0, fmt.Errorf("ReadZoneFile: Error: failed to read %s: %v", filename, err)
	}
	if zd.ZoneStore == MapZone || zd.ZoneStore == SliceZone {
		// zd.Data = make(map[string]OwnerData, 30)
		zd.Data = cmap.New[OwnerData]()
	}

	zp := dns.NewZoneParser(bufio.NewReader(f), "", "")
	zp.SetIncludeAllowed(true)

	firstSoaSeen := false
	checkedForUnchanged := false

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		firstSoaSeen = zd.SortFunc(rr, firstSoaSeen)
		if firstSoaSeen && !checkedForUnchanged {
		   checkedForUnchanged = true
		   apex, _ := zd.Data.Get(zd.ZoneName)
		   soa := apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA)
		   zd.Logger.Printf("ReadZoneFile: %s: old incoming serial: %d new SOA serial: %d",
		   				       zd.ZoneName, zd.IncomingSerial, soa.Serial)
		   if soa.Serial == zd.IncomingSerial {
		      if !force {
		      	 zd.Logger.Printf("ReadZoneFile: %s: new SOA serial is the same as current. Reload not needed.",
		      				      zd.ZoneName)
		      	 return false, soa.Serial, nil
		      }
		      zd.Logger.Printf("ReadZoneFile: %s: new SOA serial is the same as current but still forced to reload.",
		      				      zd.ZoneName)
		   }
		}
	}

	apex, _ := zd.GetOwner(zd.ZoneName)
	soa := apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA)

	zd.CurrentSerial = soa.Serial
	zd.IncomingSerial = soa.Serial

	if err := zp.Err(); err != nil {
		zd.Logger.Printf("ReadZoneFile: Error from ZoneParser(%s): %v",
						zd.ZoneName, err)
		return false, soa.Serial, fmt.Errorf("Error from ZoneParser: %v", err)
	}
	zd.Logger.Printf("*** Zone %s read from file. No errors.", zd.ZoneName)
	zd.ComputeIndices() // for zonestore SliceZone, otherwise no-op
	zd.XfrType = "axfr" // XXX: technically not true
	return true, soa.Serial, nil
}

func (zd *ZoneData) SortFunc(rr dns.RR, firstSoaSeen bool) bool {
	owner := rr.Header().Name
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
			omap.RRtypes = map[uint16]RRset{}
		}
		ztype = MapZone
	}

	var tmp RRset

	switch v := rr.(type) {
	case *dns.SOA:
		if !firstSoaSeen {
			zd.Logger.Printf("SortFunc: zone %s firstSoaSeen is nil. Setting to true", zd.ZoneName)
			firstSoaSeen = true
			zd.ApexLen++
			if ztype == MapZone {
				tmp = omap.RRtypes[rrtype]
				tmp.RRs = append(tmp.RRs, rr)
				omap.RRtypes[rrtype] = tmp
			}
		}

	case *dns.RRSIG:
		rrt := v.TypeCovered

		if owner == zd.ZoneName {
			switch ztype {
//			case XfrZone:
//				zd.RRs = append(zd.RRs, rr)
			case MapZone:
				tmp = omap.RRtypes[rrt]
				tmp.RRSIGs = append(tmp.RRSIGs, rr)
				omap.RRtypes[rrt] = tmp
			}
		}

		switch ztype {
//		case XfrZone:
//			zd.RRs = append(zd.RRs, rr)
		case MapZone:
			tmp = omap.RRtypes[rrt]
			tmp.RRSIGs = append(tmp.RRSIGs, rr)
			omap.RRtypes[rrt] = tmp
		}

	default:
		switch ztype {
//		case XfrZone:
//			zd.RRs = append(zd.RRs, rr)
		case MapZone:
			tmp = omap.RRtypes[rrtype]
			tmp.RRs = append(tmp.RRs, rr)
			omap.RRtypes[rrtype] = tmp
		}
	}
	if ztype == MapZone {
		// zd.Data[owner] = omap
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

	apex, _ := zd.GetOwner(zd.ZoneName)
	soa := apex.RRtypes[dns.TypeSOA].RRs[0]
	soa.(*dns.SOA).Serial = zd.CurrentSerial

	zonedata += soa.String() + "\n"
	count := 1
//	var total_sent int

	switch zd.ZoneStore {
	case SliceZone:
		// SOA
		zonedata += RRsetToString(apex.RRtypes[dns.TypeSOA].RRSIGs)
		count += len(apex.RRtypes[dns.TypeSOA].RRSIGs)

		// Rest of apex
		for rrt, _ := range apex.RRtypes {
			if rrt != dns.TypeSOA {
				zonedata += RRsetToString(apex.RRtypes[rrt].RRs)
				count += len(apex.RRtypes[rrt].RRs)
				zonedata += RRsetToString(apex.RRtypes[rrt].RRSIGs)
				count += len(apex.RRtypes[rrt].RRSIGs)
			}
		}

		// Rest of zone
		for _, owner := range zd.Owners {
			if owner.Name == zd.ZoneName {
				continue
			}
			for _, rrl := range owner.RRtypes {
				zonedata += RRsetToString(rrl.RRs)
				count += len(rrl.RRs)
				zonedata += RRsetToString(rrl.RRSIGs)
				count += len(rrl.RRSIGs)

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
		zonedata += RRsetToString(apex.RRtypes[dns.TypeSOA].RRSIGs)
		count += len(apex.RRtypes[dns.TypeSOA].RRSIGs)

		// Rest of apex
		for rrt, _ := range apex.RRtypes {
			if rrt != dns.TypeSOA {
				zonedata += RRsetToString(apex.RRtypes[rrt].RRs)
				count += len(apex.RRtypes[rrt].RRs)
				zonedata += RRsetToString(apex.RRtypes[rrt].RRSIGs)
				count += len(apex.RRtypes[rrt].RRSIGs)
			}
		}

		// Rest of zone
		for _, owner := range zd.Data.Keys() {
		        omap, _ := zd.Data.Get(owner)
			if owner == zd.ZoneName {
				continue
			}
			for _, rrl := range omap.RRtypes {
				zonedata += RRsetToString(rrl.RRs)
				count += len(rrl.RRs)
				zonedata += RRsetToString(rrl.RRSIGs)
				count += len(rrl.RRSIGs)

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

func RRsetToString(rrs []dns.RR) string {
     var tmp string
     for _, rr := range rrs {
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
		soas := zd.Owners[idx].RRtypes[dns.TypeSOA]
		soas.RRs = soas.RRs[:1]
		zd.Owners[idx].RRtypes[dns.TypeSOA] = soas
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
