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
	"strconv"
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
		err := tr.Out(w, r, outbound_xfr)
		if err != nil {
			zd.Logger.Printf("Error from transfer.Out(): %v", err)
		}
		wg.Done()
	}()

	apex, _ := zd.GetOwner(zd.ZoneName)
	soa := apex.RRtypes[dns.TypeSOA].RRs[0]
	soa.(*dns.SOA).Serial = zd.CurrentSerial

	total_sent := 0
	count := 0
	// env := dns.Envelope{}
	rrs := []dns.RR{soa}

	// SOA
	// env.RR = append(env.RR, soa)
	// XXX: If we change the SOA serial we must also recompute the RRSIG.
	// env.RR = append(env.RR, apex.RRtypes[dns.TypeSOA].RRSIGs...)
	rrs = append(rrs, apex.RRtypes[dns.TypeSOA].RRSIGs...)
	if Globals.Debug {
		zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, soa.String())
	}

	// Rest of apex
	for rrt, _ := range apex.RRtypes {
		if rrt != dns.TypeSOA {
			// env.RR = append(env.RR, apex.RRtypes[rrt].RRs...)
			rrs = append(rrs, apex.RRtypes[rrt].RRs...)
			if Globals.Debug {
				zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, apex.RRtypes[rrt].RRs)
			}
			// env.RR = append(env.RR, apex.RRtypes[rrt].RRSIGs...)
			rrs = append(rrs, apex.RRtypes[rrt].RRSIGs...)
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
			for _, rrl := range owner.RRtypes {
				rrs = append(rrs, rrl.RRs...)
				if Globals.Debug {
					zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, rrl.RRs)
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
			for _, rrl := range omap.RRtypes {
				rrs = append(rrs, rrl.RRs...)
				if Globals.Debug {
					zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, rrl.RRs)
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
		zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, soa)
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

func ZoneTransferPrint(zname, upstream string, serial uint32, ttype uint16, options map[string]string) error {
	msg := new(dns.Msg)
	if ttype == dns.TypeIXFR {
		// msg.SetIxfr(zname, serial, soa.Ns, soa.Mbox)
		msg.SetIxfr(zname, serial, "", "")
	} else {
		msg.SetAxfr(zname)
	}

	maxlen := 35
	rightmargin := 72

	printKeyRR := func(rr dns.RR, rrtype, ktype string, keyid uint16, maxlen int) {
		p := strings.Fields(rr.String())
		// rhp := strings.Fields(parts[1])
		namepad := strings.Repeat(" ", maxlen-len(p[0])-len(p[1]))
		if len(namepad) < 1 {
			namepad = " "
		}
		fmt.Printf("%s%s%s %s %s %s %s %s (\n", p[0], namepad, p[1], p[2], p[3], p[4], p[5], p[6])
		spaces := strings.Repeat(" ", maxlen)
		var keyparts []string
		keystr := p[7]
		for len(keystr) > 72-len(spaces) {
			keyparts = append(keyparts, keystr[:rightmargin-len(spaces)])
			keystr = keystr[72-len(spaces):]
		}
		keyparts = append(keyparts, keystr)
		for idx, part := range keyparts {
			if idx == len(keyparts)-1 {
				fmt.Printf("%s %s )\n", spaces, part)
			} else {
				fmt.Printf("%s %s\n", spaces, part)
			}
		}
		alg, _ := strconv.Atoi(p[6])
		algstr := dns.AlgorithmToString[uint8(alg)]
		fmt.Printf("%s ; %s alg = %s ; key id = %d\n", spaces, ktype, algstr, keyid)
	}

	transfer := new(dns.Transfer)
	answerChan, err := transfer.In(msg, upstream)
	if err != nil {
		fmt.Printf("Error from transfer.In: %v\n", err)
		return err
	}

	for envelope := range answerChan {
		if envelope.Error != nil {
			fmt.Printf("Oops. Zone transfer envelope signals an error:\n")
			errstr := envelope.Error.Error()
			if strings.Contains(errstr, "bad xfr rcode: 9") {
				fmt.Printf("Error: %s: Not authoritative for zone %s\n",
					upstream, zname)
			} else {
				fmt.Printf("Error: zone %s error: %v\n", zname, errstr)
			}
			if !Globals.Debug {
				fmt.Printf("Xfr error: breaking off\n")
				break
			} else {
				fmt.Printf("DEBUG: envelope: %v\n", envelope)
			}
		}

		if Globals.Debug {
			fmt.Printf("Printing %d RRs in envelope\n", len(envelope.RR))
		}

		for _, rr := range envelope.RR {
			if options["multi"] == "true" {
				switch rr.(type) {
				case *dns.KEY:
					keyid := rr.(*dns.KEY).KeyTag()
					t := ""
					printKeyRR(rr, "KEY", t, keyid, maxlen)
				case *dns.DNSKEY:
					keyid := rr.(*dns.DNSKEY).KeyTag()
					t := " ZSK ;"
					if rr.(*dns.DNSKEY).Flags == 257 {
						t = " KSK ;"
					}
					printKeyRR(rr, "DNSKEY", t, keyid, maxlen)

				case *dns.RRSIG:
					p := strings.Fields(rr.String())
					// rhp := strings.Fields(p[1])
					namepad := strings.Repeat(" ", maxlen-len(p[0])-len(p[1]))
					if len(namepad) < 1 {
						namepad = " "
					}
					fmt.Printf("%s%s%s %s (\n", p[0], namepad, p[1], strings.Join(p[2:8], " "))
					// spaces := strings.Repeat(" ", len(parts[0])+1)
					spaces := strings.Repeat(" ", maxlen)
					fmt.Printf("%s %s %s %s %s\n", spaces, p[8], p[9], p[10], p[11])
					var rrsigparts []string
					part := p[12]
					for len(part) > rightmargin-len(spaces) {
						rrsigparts = append(rrsigparts, part[:rightmargin-len(spaces)])
						part = part[rightmargin-len(spaces):]
					}
					rrsigparts = append(rrsigparts, part)
					for idx, part := range rrsigparts {
						if idx == len(rrsigparts)-1 {
							fmt.Printf("%s %s )\n", spaces, part)
						} else {
							fmt.Printf("%s %s\n", spaces, part)
						}
					}

				case *dns.SVCB:
					p := strings.Fields(rr.String())
					namepad := strings.Repeat(" ", maxlen-len(p[0])-len(p[1]))
					if len(namepad) < 1 {
						namepad = " "
					}
					spaces := strings.Repeat(" ", maxlen)
					fmt.Printf("%s%s%s %s", p[0], namepad, p[1], strings.Join(p[2:6], " "))
					if len(p) > 6 {
						fmt.Printf(" (\n")
						fmt.Printf("%s %s )\n", spaces, strings.Join(p[6:], " "))
					} else {
						fmt.Printf("\n")
					}

				case *dns.SOA:
					p := strings.Fields(rr.String())
					// rhp := strings.Fields(p[1])
					namepad := strings.Repeat(" ", maxlen-len(p[0])-len(p[1]))
					if len(namepad) < 1 {
						namepad = " "
					}
					fmt.Printf("%s%s%s %s (\n", p[0], namepad, p[1], strings.Join(p[2:6], " "))
					spaces := strings.Repeat(" ", maxlen)
					fmt.Printf("%s %s%s ; SOA serial\n", spaces, p[6], strings.Repeat(" ", 10-len(p[6])))
					fmt.Printf("%s %s%s ; Refresh\n", spaces, p[7], strings.Repeat(" ", 10-len(p[7])))
					fmt.Printf("%s %s%s ; Retry\n", spaces, p[8], strings.Repeat(" ", 10-len(p[8])))
					fmt.Printf("%s %s%s ; Expire\n", spaces, p[9], strings.Repeat(" ", 10-len(p[9])))
					fmt.Printf("%s %s )%s ; Ncache TTL\n", spaces, p[10], strings.Repeat(" ", 10-len(p[10])-2))

				default:
					p := strings.Fields(rr.String())
					namepad := strings.Repeat(" ", maxlen-len(p[0])-len(p[1]))
					// fmt.Printf("len(qname)=%d, len(ttl)=%d, namepad=%d\n", len(p[0]), len(p[1]), len(namepad))
					fmt.Printf("%s%s%s\n", p[0], namepad, strings.Join(p[1:], " "))
				}
			} else {
				fmt.Printf("%s\n", rr.String())
			}
		}
		if Globals.Debug {
			fmt.Printf("Done printing %d RRs in envelope\n", len(envelope.RR))
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
		// log.Printf("ReadZoneFile: RR: %s", rr.String())
		firstSoaSeen = zd.SortFunc(rr, firstSoaSeen)
		if firstSoaSeen && !checkedForUnchanged {
			checkedForUnchanged = true
			apex, _ := zd.Data.Get(zd.ZoneName)
			soa := apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA)
			zd.Logger.Printf("ReadZoneFile: %s: old incoming serial: %d new SOA serial: %d",
				zd.ZoneName, zd.IncomingSerial, soa.Serial)
			if soa.Serial == zd.IncomingSerial {
				if !force {
					zd.Logger.Printf("ReadZoneFile: %s: new SOA serial is the same as current. Reload not needed.", zd.ZoneName)
					return false, soa.Serial, nil
				}
				zd.Logger.Printf("ReadZoneFile: %s: new SOA serial is the same as current but still forced to reload.", zd.ZoneName)
			}
		}
	}

	if err := zp.Err(); err != nil {
		log.Printf("Error from ZoneParser: %v", err)
		return false, 0, err
	}

	apex, _ := zd.GetOwner(zd.ZoneName)
	//	dump.P(apex)
	soa_rrset := apex.RRtypes[dns.TypeSOA]
	var soa *dns.SOA
	if len(soa_rrset.RRs) > 0 {
		soa = soa_rrset.RRs[0].(*dns.SOA)
	} else {
		log.Printf("ReadZoneFile: Error: SOA: %v", soa_rrset)
		return false, 0, fmt.Errorf("Error loading zone %s from file %s", zd.ZoneName, f.Name())
	}

	zd.CurrentSerial = soa.Serial
	zd.IncomingSerial = soa.Serial

	if err := zp.Err(); err != nil {
		zd.Logger.Printf("ReadZoneFile: Error from ZoneParser(%s): %v",
			zd.ZoneName, err)
		return false, soa.Serial, fmt.Errorf("Error from ZoneParser: %v", err)
	}
	// zd.Logger.Printf("*** Zone %s read from file. No errors.", zd.ZoneName)
	zd.ComputeIndices() // for zonestore SliceZone, otherwise no-op
	zd.XfrType = "axfr" // XXX: technically not true
	return true, soa.Serial, nil
}

func (zd *ZoneData) SortFunc(rr dns.RR, firstSoaSeen bool) bool {
	owner := rr.Header().Name
	// if zd.FoldCase {
	if zd.Options["fold-case"] {
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
			omap.RRtypes = map[uint16]RRset{}
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
				tmp = omap.RRtypes[rrtype]
				tmp.RRs = append(tmp.RRs, rr)
				omap.RRtypes[rrtype] = tmp
			}
		}

	case *dns.RRSIG:
		rrt := v.TypeCovered
		switch ztype {
		case MapZone:
			tmp = omap.RRtypes[rrt]
			tmp.RRSIGs = append(tmp.RRSIGs, rr)
			omap.RRtypes[rrt] = tmp
		}

	default:
		switch ztype {
		case MapZone:
			tmp = omap.RRtypes[rrtype]
			tmp.RRs = append(tmp.RRs, rr)
			omap.RRtypes[rrtype] = tmp
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

	apex, _ := zd.GetOwner(zd.ZoneName)
	soa := apex.RRtypes[dns.TypeSOA].RRs[0]
	soa.(*dns.SOA).Serial = zd.CurrentSerial

	//	zonedata += soa.String() + "\n"
	count := 0
	//	var total_sent int

	switch zd.ZoneStore {
	case SliceZone:
		// SOA
		soa := apex.RRtypes[dns.TypeSOA]
		zonedata += RRsetToString(&soa)
		count += len(soa.RRs) + len(soa.RRSIGs)

		// Rest of apex
		for rrt, rrset := range apex.RRtypes {
			if rrt != dns.TypeSOA {
				zonedata += RRsetToString(&rrset)
				count += len(rrset.RRs) + len(rrset.RRSIGs)
			}
		}

		// Rest of zone
		for _, owner := range zd.Owners {
			if owner.Name == zd.ZoneName {
				continue
			}
			for _, rrl := range owner.RRtypes {
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
		soa := apex.RRtypes[dns.TypeSOA]
		zonedata += RRsetToString(&soa)
		count += len(soa.RRs) + len(soa.RRSIGs)

		// Rest of apex
		for rrt, rrset := range apex.RRtypes {
			if rrt != dns.TypeSOA {
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
			for _, rrl := range omap.RRtypes {
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

func xxxRRsetToStringOG(rrs []dns.RR) string {
	var tmp string
	for _, rr := range rrs {
		tmp += rr.String() + "\n"
	}
	return tmp
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

func SetupIMR() {
	if Globals.IMR == "" {
		Globals.IMR = viper.GetString("resolver.address")
	}

	if Globals.Verbose {
		log.Printf("Using resolver \"%s\"\n", Globals.IMR)
	}
}
