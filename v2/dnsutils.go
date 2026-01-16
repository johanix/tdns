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
	core "github.com/johanix/tdns/v2/core"
)

const (
	year68     = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits
	TimeLayout = "2006-01-02 15:04:05"
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

// batchState holds the state for zone transfer batching
type batchState struct {
	rrs           *[]dns.RR
	count         *int
	estimatedSize *int
	batchNum      *int
	totalSent     *int
	outbound      chan<- *dns.Envelope
	zd            *ZoneData
}

// maybeFlushBatch checks if the current batch should be sent based on size estimates.
// It handles both pre-add checks (when newRRSize > 0) and periodic checks (when newRRSize == 0).
// Returns true if a batch was sent, false otherwise.
func maybeFlushBatch(bs *batchState, newRRSize int, isPeriodicCheck bool) bool {
	const maxMessageSize = 60000
	const safeMessageSize = 59000
	const theoreticalMaxSize = 65536
	const checkSizeInterval = 50
	const accurateCheckThreshold = 55000

	// Pre-add check: if adding newRRSize would exceed limit, do accurate check
	if newRRSize > 0 {
		if *bs.estimatedSize+newRRSize >= safeMessageSize ||
			(*bs.estimatedSize >= accurateCheckThreshold && len(*bs.rrs)%checkSizeInterval == 0) {
			actualSize := estimateEnvelopeSize(*bs.rrs)
			if actualSize >= safeMessageSize {
				// Send current batch before adding more
				*bs.totalSent += *bs.count
				if bs.zd.Verbose || Globals.Debug {
					efficiency := float64(actualSize) / float64(safeMessageSize) * 100.0
					maxEfficiency := float64(actualSize) / float64(maxMessageSize) * 100.0
					theoreticalEfficiency := float64(actualSize) / float64(theoreticalMaxSize) * 100.0
					bs.zd.Logger.Printf("XfrOut: Zone %s: Sending batch #%d: %d RRs, %d bytes (estimated: %d, efficiency: %.1f%% of %d safe / %.1f%% of %d target / %.1f%% of %d theoretical max)",
						bs.zd.ZoneName, *bs.batchNum, *bs.count, actualSize, *bs.estimatedSize, efficiency, safeMessageSize, maxEfficiency, maxMessageSize, theoreticalEfficiency, theoreticalMaxSize)
				}
				bs.outbound <- &dns.Envelope{RR: *bs.rrs}
				*bs.rrs = []dns.RR{}
				*bs.count = 0
				*bs.estimatedSize = 0
				(*bs.batchNum)++
				return true
			} else {
				// Update estimate with accurate measurement
				*bs.estimatedSize = actualSize
			}
		}
	}

	// Periodic accurate check to verify estimate accuracy
	if isPeriodicCheck && len(*bs.rrs)%checkSizeInterval == 0 && *bs.estimatedSize >= accurateCheckThreshold {
		actualSize := estimateEnvelopeSize(*bs.rrs)
		if actualSize >= safeMessageSize {
			*bs.totalSent += *bs.count
			if bs.zd.Verbose || Globals.Debug {
				efficiency := float64(actualSize) / float64(safeMessageSize) * 100.0
				maxEfficiency := float64(actualSize) / float64(maxMessageSize) * 100.0
				theoreticalEfficiency := float64(actualSize) / float64(theoreticalMaxSize) * 100.0
				bs.zd.Logger.Printf("XfrOut: Zone %s: Sending batch #%d: %d RRs, %d bytes (estimated: %d, efficiency: %.1f%% of %d safe / %.1f%% of %d target / %.1f%% of %d theoretical max)",
					bs.zd.ZoneName, *bs.batchNum, *bs.count, actualSize, *bs.estimatedSize, efficiency, safeMessageSize, maxEfficiency, maxMessageSize, theoreticalEfficiency, theoreticalMaxSize)
			}
			bs.outbound <- &dns.Envelope{RR: *bs.rrs}
			*bs.rrs = []dns.RR{}
			*bs.count = 0
			*bs.estimatedSize = 0
			(*bs.batchNum)++
			return true
		} else {
			// Adjust estimate based on actual measurement
			*bs.estimatedSize = actualSize
		}
	}

	return false
}

// estimateRRSize estimates the size of a single RR by packing it individually
// This gives us an approximate size without packing the entire message
func estimateRRSize(rr dns.RR) int {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{rr}
	packed, err := msg.Pack()
	if err != nil {
		// Conservative fallback estimate
		return 200 // Overestimate to be safe
	}
	// Subtract DNS message header size (~12 bytes) to get just the RR size
	// This is approximate but good enough for our purposes
	if len(packed) > 12 {
		return len(packed) - 12
	}
	return len(packed)
}

// estimateEnvelopeSize estimates the size of a DNS envelope by serializing it
// This is used for accurate checks when we're close to the limit
func estimateEnvelopeSize(rrs []dns.RR) int {
	if len(rrs) == 0 {
		return 0
	}
	// Build a test message with the RRs to estimate size
	msg := new(dns.Msg)
	msg.Answer = rrs
	packed, err := msg.Pack()
	if err != nil {
		// If packing fails, return a conservative estimate
		return len(rrs) * 100 // Rough estimate: ~100 bytes per RR
	}
	return len(packed)
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
	batchNum := 1 // Track batch number for debug output
	estimatedSize := 0 // Running estimate of message size
	const maxMessageSize = 60000 // Practical limit we target (theoretical DNS max is 65536 bytes / 64K)
	// We may overshoot maxMessageSize by up to ~1000 bytes in practice, but that's still safely below 65536
	const safeMessageSize = 59000 // Conservative threshold to avoid "message too large" errors (leaves headroom for DNS header/overhead and compression variations)
	const theoreticalMaxSize = 65536 // True theoretical maximum DNS message size (64K)
	const checkSizeInterval = 50  // Check actual size every N RRs to verify estimate accuracy
	const accurateCheckThreshold = 55000 // When estimated size exceeds this, do accurate checks more frequently
	// env := dns.Envelope{}
	rrs := []dns.RR{soa}
	// Estimate size of initial SOA
	estimatedSize += estimateRRSize(soa)

	// SOA
	// env.RR = append(env.RR, soa)
	// XXX: If we change the SOA serial we must also recompute the RRSIG.
	// env.RR = append(env.RR, apex.RRtypes[dns.TypeSOA].RRSIGs...)
	soaRRSIGs := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs
	rrs = append(rrs, soaRRSIGs...)
	for _, sig := range soaRRSIGs {
		estimatedSize += estimateRRSize(sig)
	}
	if Globals.Debug {
		// zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, soa.String())
	}

	// Rest of apex
	for _, rrt := range apex.RRtypes.Keys() {
		if rrt != dns.TypeSOA {
			// env.RR = append(env.RR, apex.RRtypes[rrt].RRs...)
			rrset := apex.RRtypes.GetOnlyRRSet(rrt)
			rrs = append(rrs, rrset.RRs...)
			for _, rr := range rrset.RRs {
				estimatedSize += estimateRRSize(rr)
			}
			if Globals.Debug {
				// zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, apex.RRtypes.GetOnlyRRSet(rrt).RRs)
			}
			// env.RR = append(env.RR, apex.RRtypes[rrt].RRSIGs...)
			rrs = append(rrs, rrset.RRSIGs...)
			for _, sig := range rrset.RRSIGs {
				estimatedSize += estimateRRSize(sig)
			}
		}
	}
	count = len(rrs)

	// Initialize batch state for helper function
	bs := &batchState{
		rrs:           &rrs,
		count:         &count,
		estimatedSize: &estimatedSize,
		batchNum:      &batchNum,
		totalSent:     &total_sent,
		outbound:      outbound_xfr,
		zd:            zd,
	}

	switch zd.ZoneStore {
	case SliceZone:
		// Rest of zone
		for _, owner := range zd.Owners {
			if owner.Name == zd.ZoneName {
				continue
			}
			for _, rrt := range owner.RRtypes.Keys() {
				rrl := owner.RRtypes.GetOnlyRRSet(rrt)
				
				// Estimate size of new RRs before adding
				newRRSize := 0
				for _, rr := range rrl.RRs {
					newRRSize += estimateRRSize(rr)
				}
				for _, sig := range rrl.RRSIGs {
					newRRSize += estimateRRSize(sig)
				}
				
				// Check if batch should be flushed before adding new RRs
				maybeFlushBatch(bs, newRRSize, false)
				
				// Now add the RRset
				rrs = append(rrs, rrl.RRs...)
				if Globals.Debug {
					// zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, rrl.RRs)
				}
				count += len(rrl.RRs)
				rrs = append(rrs, rrl.RRSIGs...)
				count += len(rrl.RRSIGs)
				estimatedSize += newRRSize
				
				// Periodic accurate check to verify estimate accuracy
				maybeFlushBatch(bs, 0, true)
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
				
				// Estimate size of new RRs before adding
				newRRSize := 0
				for _, rr := range rrl.RRs {
					newRRSize += estimateRRSize(rr)
				}
				for _, sig := range rrl.RRSIGs {
					newRRSize += estimateRRSize(sig)
				}
				
				// Check if batch should be flushed before adding new RRs
				maybeFlushBatch(bs, newRRSize, false)
				
				// Now add the RRset
				rrs = append(rrs, rrl.RRs...)
				if Globals.Debug {
					// zd.Logger.Printf("XfrOut[%s]: %v\n", zd.ZoneName, rrl.RRs)
				}
				count += len(rrl.RRs)
				rrs = append(rrs, rrl.RRSIGs...)
				count += len(rrl.RRSIGs)
				estimatedSize += newRRSize
				
				// Periodic accurate check to verify estimate accuracy
				maybeFlushBatch(bs, 0, true)
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
	// Get actual size of final message
	finalSize := estimateEnvelopeSize(rrs)
	if zd.Verbose || Globals.Debug {
		efficiency := float64(finalSize) / float64(safeMessageSize) * 100.0
		maxEfficiency := float64(finalSize) / float64(maxMessageSize) * 100.0
		theoreticalEfficiency := float64(finalSize) / float64(theoreticalMaxSize) * 100.0
		zd.Logger.Printf("XfrOut: Zone %s: Sending final batch #%d: %d RRs, %d bytes (efficiency: %.1f%% of %d safe / %.1f%% of %d target / %.1f%% of %d theoretical max, total sent: %d RRs)\n",
			zd.ZoneName, batchNum, len(rrs), finalSize, efficiency, safeMessageSize, maxEfficiency, maxMessageSize, theoreticalEfficiency, theoreticalMaxSize, total_sent)
	} else {
		zd.Logger.Printf("XfrOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)\n",
			zd.ZoneName, len(rrs), total_sent)
	}
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

	var tmp core.RRset

	if !strings.HasSuffix(rr.Header().Name, zd.ZoneName) {
		zd.Logger.Printf("*** SortFunc: zone %s: RR %s is not in zone. Ignored.", zd.ZoneName, rr.String())
		return firstSoaSeen
	}

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

func RRsetToString(rrset *core.RRset) string {
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
