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
	"strconv"
	"strings"
	"sync"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	// "github.com/gookit/goutil/dump"
)

const (
	year68            = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits
	TimeLayout        = "2006-01-02 15:04:05"
	safeMessageSize   = 64000 // ~1.5 KB headroom for per-envelope question + TSIG
	dnsMaxMessageSize = 65535
)

// clarifyXfrError turns the opaque miekg/dns "bad xfr rcode: N" transfer
// error into a human-readable failure that names the rcode, e.g.
// "inbound zone transfer of dingo.dnago.dungo. from <upstream> failed: REFUSED"
// instead of "dns: bad xfr rcode: 5". Non-transfer errors pass through
// unchanged. Applied at the source so every ZoneTransferIn caller (refresh
// engine, etc.) reports the clear message.
func clarifyXfrError(zone, upstream string, err error) error {
	if err == nil {
		return nil
	}
	const marker = "bad xfr rcode: "
	if i := strings.Index(err.Error(), marker); i >= 0 {
		if code, perr := strconv.Atoi(strings.TrimSpace(err.Error()[i+len(marker):])); perr == nil {
			name := dns.RcodeToString[code]
			if name == "" {
				name = fmt.Sprintf("rcode %d", code)
			}
			return fmt.Errorf("inbound zone transfer of %s from %s failed: %s", zone, upstream, name)
		}
	}
	return err
}

func (zd *ZoneData) ZoneTransferIn(upstream string, serial uint32, ttype, keyName string, conf *Config) (uint32, error) {

	if upstream == "" {
		Fatal("ZoneTransfer: upstream not set")
	}

	msg := new(dns.Msg)
	if ttype == "ixfr" {
		// msg.SetIxfr(zone, serial, soa.Ns, soa.Mbox)
		msg.SetIxfr(zd.ZoneName, serial, "", "")
	} else {
		msg.SetAxfr(zd.ZoneName)
	}

	if zd.ZoneStore == MapZone {
		zd.Data = core.NewCmap[OwnerData]()
	}
	lgDns.Info("ZoneTransferIn", "zone", zd.ZoneName, "store", ZoneStoreToString[zd.ZoneStore])

	transfer := new(dns.Transfer)
	// Sign the AXFR/IXFR request under this upstream's key (NOKEY => unsigned).
	// The provider also verifies the TSIG on the inbound envelopes.
	provider, serr := SignForPeer(msg, keyName, conf)
	if serr != nil {
		return 0, fmt.Errorf("ZoneTransferIn %s: TSIG sign setup: %w", zd.ZoneName, serr)
	}
	transfer.TsigProvider = provider
	answerChan, err := transfer.In(msg, upstream)
	if err != nil {
		zd.Logger.Printf("Error from transfer.In: %v\n", err)
		return 0, clarifyXfrError(zd.ZoneName, upstream, err)
	}

	count := 0
	firstSoaSeen := false
	for envelope := range answerChan {
		if envelope.Error != nil {
			zd.Logger.Printf("ZoneTransfer: zone %s error: %v", zd.ZoneName, envelope.Error)
			return 0, clarifyXfrError(zd.ZoneName, upstream, envelope.Error)
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
	done          <-chan struct{}
	zd            *ZoneData
}

func (bs *batchState) sendEnvelope(rrs []dns.RR) bool {
	select {
	case bs.outbound <- &dns.Envelope{RR: rrs}:
		return true
	case <-bs.done:
		return false
	}
}

func (bs *batchState) flushBatch() bool {
	if len(*bs.rrs) == 0 {
		return true
	}
	actualSize := estimateEnvelopeSize(*bs.rrs)
	*bs.totalSent += *bs.count
	if bs.zd.Verbose || Globals.Debug {
		bs.zd.Logger.Printf("XfrOut: Zone %s: Sending batch #%d: %d RRs, %d bytes (estimated: %d)",
			bs.zd.ZoneName, *bs.batchNum, *bs.count, actualSize, *bs.estimatedSize)
	}
	if !bs.sendEnvelope(*bs.rrs) {
		return false
	}
	*bs.rrs = []dns.RR{}
	*bs.count = 0
	*bs.estimatedSize = 0
	(*bs.batchNum)++
	return true
}

// maybeFlushBatch flushes the current batch when adding newRRSize would exceed
// safeMessageSize, or on periodic accurate checks near the limit.
func maybeFlushBatch(bs *batchState, newRRSize int, isPeriodicCheck bool) bool {
	if len(*bs.rrs) == 0 {
		return true
	}
	currentSize := estimateEnvelopeSize(*bs.rrs)
	if newRRSize > 0 && currentSize+newRRSize >= safeMessageSize {
		return bs.flushBatch()
	}
	if isPeriodicCheck && currentSize >= safeMessageSize {
		return bs.flushBatch()
	}
	if isPeriodicCheck && currentSize > 0 {
		*bs.estimatedSize = currentSize
	}
	return true
}

func appendRRset(bs *batchState, rrset core.RRset) bool {
	newRRSize := 0
	for _, rr := range rrset.RRs {
		newRRSize += estimateRRSize(rr)
	}
	for _, sig := range rrset.RRSIGs {
		newRRSize += estimateRRSize(sig)
	}
	if newRRSize >= safeMessageSize {
		owner, rrtype := oversizeRRsetOwner(append([]dns.RR(nil), rrset.RRs...))
		if owner == "" && len(rrset.RRs) > 0 {
			owner = rrset.RRs[0].Header().Name
			rrtype = dns.TypeToString[rrset.RRs[0].Header().Rrtype]
		}
		bs.zd.Logger.Printf("ZoneTransferOut: %s: aborting transfer, oversize RRset owner=%s type=%s size~=%d",
			bs.zd.ZoneName, owner, rrtype, newRRSize)
		return false
	}
	if !maybeFlushBatch(bs, newRRSize, false) {
		return false
	}
	*bs.rrs = append(*bs.rrs, rrset.RRs...)
	*bs.rrs = append(*bs.rrs, rrset.RRSIGs...)
	*bs.count += len(rrset.RRs) + len(rrset.RRSIGs)
	*bs.estimatedSize += newRRSize
	return maybeFlushBatch(bs, 0, len(*bs.rrs)%50 == 0 && *bs.estimatedSize >= 55000)
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

	if src, ok := peerIP(w.RemoteAddr().String()); !ok {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, unparseable source %q", zone, w.RemoteAddr())
		return zd.refuseTransfer(w, r)
	} else if allowed, approvedKeys := zd.downstreamsDecision(src); !allowed {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer to %s (not permitted by downstreams ACL)", zone, src)
		return zd.refuseTransfer(w, r)
	} else if err := checkInboundTSIG(w, r, approvedKeys); err != nil {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer to %s: %v", zone, src, err)
		return zd.refuseTransfer(w, r)
	}

	if zd.GetStatus() != ZoneStatusReady {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, zone status %s", zone, ZoneStatusToString[zd.GetStatus()])
		return zd.refuseTransfer(w, r)
	}

	if zd.ZoneStore != MapZone {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, zone store %s not supported",
			zone, ZoneStoreToString[zd.ZoneStore])
		return zd.refuseTransfer(w, r)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, apex lookup failed: %v", zone, err)
		return zd.refuseTransfer(w, r)
	}
	if apex == nil {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, missing apex", zone)
		return zd.refuseTransfer(w, r)
	}
	soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soaRRset.RRs) == 0 {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, empty SOA RRset", zone)
		return zd.refuseTransfer(w, r)
	}
	soaOrig, ok := soaRRset.RRs[0].(*dns.SOA)
	if !ok {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, invalid SOA RR", zone)
		return zd.refuseTransfer(w, r)
	}

	soaCopy := dns.Copy(soaOrig).(*dns.SOA)
	soaCopy.Serial = zd.CurrentSerial
	transferSOA := core.RRset{
		Name:   zd.ZoneName,
		Class:  dns.ClassINET,
		RRtype: dns.TypeSOA,
		RRs:    []dns.RR{soaCopy},
		RRSIGs: soaRRset.RRSIGs,
	}

	if zd.Verbose {
		zd.Logger.Printf("ZoneTransferOut: Will try to serve zone %s", zone)
	}

	outbound_xfr := make(chan *dns.Envelope)
	done := make(chan struct{})
	var closeOnce sync.Once
	closeOutbound := func() { closeOnce.Do(func() { close(outbound_xfr) }) }

	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := tr.Out(w, r, outbound_xfr); err != nil {
			zd.Logger.Printf("Error from transfer.Out(): %v", err)
			close(done)
		}
	}()

	defer func() {
		closeOutbound()
		wg.Wait()
		w.Close()
	}()

	totalSent := 0
	count := 0
	batchNum := 1
	estimatedSize := 0
	rrs := []dns.RR{}

	bs := &batchState{
		rrs:           &rrs,
		count:         &count,
		estimatedSize: &estimatedSize,
		batchNum:      &batchNum,
		totalSent:     &totalSent,
		outbound:      outbound_xfr,
		done:          done,
		zd:            zd,
	}

	if !appendRRset(bs, transferSOA) {
		return 0, nil
	}
	for _, rrt := range apex.RRtypes.Keys() {
		if rrt == dns.TypeSOA {
			continue
		}
		if !appendRRset(bs, apex.RRtypes.GetOnlyRRSet(rrt)) {
			return 0, nil
		}
	}

	for _, owner := range zd.Data.Keys() {
		if owner == zd.ZoneName {
			continue
		}
		omap, _ := zd.Data.Get(owner)
		for _, rrt := range omap.RRtypes.Keys() {
			rrset := omap.RRtypes.GetOnlyRRSet(uint16(rrt))
			if !appendRRset(bs, rrset) {
				return 0, nil
			}
		}
	}

	trailingSOA := dns.Copy(soaCopy).(*dns.SOA)
	trailingSize := estimateRRSize(trailingSOA)
	if !maybeFlushBatch(bs, trailingSize, false) {
		return 0, nil
	}
	*bs.rrs = append(*bs.rrs, trailingSOA)
	*bs.count++
	*bs.estimatedSize += trailingSize

	finalSize := estimateEnvelopeSize(*bs.rrs)
	if finalSize >= safeMessageSize {
		if len(*bs.rrs) > 1 {
			withoutTrailing := (*bs.rrs)[:len(*bs.rrs)-1]
			savedCount := *bs.count - 1
			*bs.rrs = withoutTrailing
			*bs.count = savedCount
			if !bs.flushBatch() {
				return 0, nil
			}
			*bs.rrs = []dns.RR{trailingSOA}
			*bs.count = 1
			*bs.estimatedSize = trailingSize
			finalSize = estimateEnvelopeSize(*bs.rrs)
		}
	}
	if finalSize >= safeMessageSize {
		owner, rrtype := oversizeRRsetOwner(*bs.rrs)
		zd.Logger.Printf("ZoneTransferOut: %s: aborting transfer, oversize RRset owner=%s type=%s size=%d",
			zone, owner, rrtype, finalSize)
		return 0, fmt.Errorf("ZoneTransferOut: %s: oversize transfer envelope (%d bytes)", zone, finalSize)
	}

	totalSent += *bs.count
	if zd.Verbose || Globals.Debug {
		zd.Logger.Printf("XfrOut: Zone %s: Sending final batch #%d: %d RRs, %d bytes (total sent: %d RRs)",
			zd.ZoneName, batchNum, len(*bs.rrs), finalSize, totalSent)
	} else {
		zd.Logger.Printf("XfrOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)",
			zd.ZoneName, len(*bs.rrs), totalSent)
	}
	if !bs.sendEnvelope(*bs.rrs) {
		return 0, nil
	}

	zd.Logger.Printf("ZoneTransferOut: %s: Sent %d RRs.", zone, totalSent)
	return totalSent, nil
}

func oversizeRRsetOwner(rrs []dns.RR) (owner, rrtype string) {
	if len(rrs) == 0 {
		return "", ""
	}
	rr := rrs[0]
	return rr.Header().Name, dns.TypeToString[rr.Header().Rrtype]
}

// refuseTransfer writes a REFUSED reply to an AXFR/IXFR request (signed when the
// request itself carried a verified TSIG, per RFC 8945) and reports zero RRs sent.
func (zd *ZoneData) refuseTransfer(w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	signResponseLikeRequest(w, r, m)
	if err := w.WriteMsg(m); err != nil {
		zd.Logger.Printf("ZoneTransferOut: %s: WriteMsg on REFUSED failed: %v", dns.Fqdn(zd.ZoneName), err)
	}
	return 0, nil
}

func (zd *ZoneData) ReadZoneFile(filename string, force bool) (bool, uint32, error) {
	zd.Logger.Printf("ReadZoneData: zone: %s", zd.ZoneName)

	f, err := os.Open(filename)
	if err != nil {
		return false, 0, fmt.Errorf("ReadZoneFile: Error: failed to read %s: %v", filename, err)
	}
	return zd.ParseZoneFromReader(bufio.NewReader(f), force, filename)
}

func (zd *ZoneData) ReadZoneData(zoneData string, force bool) (bool, uint32, error) {
	zd.Logger.Printf("ReadZoneData: zone: %s", zd.ZoneName)
	return zd.ParseZoneFromReader(strings.NewReader(zoneData), force, "")
}

func (zd *ZoneData) ParseZoneFromReader(r io.Reader, force bool, filename string) (bool, uint32, error) {
	zd.Logger.Printf("ParseZoneFromReader: zone: %s", zd.ZoneName)

	switch zd.ZoneStore {
	case MapZone:
		zd.Data = core.NewCmap[OwnerData]()
	default:
		return false, 0, fmt.Errorf("ParseZoneFromReader: zone store %d not supported", zd.ZoneStore)
	}

	zp := dns.NewZoneParser(r, "", filename)
	zp.SetIncludeAllowed(true)

	firstSoaSeen := false
	checkedForUnchanged := false
	serialChanged := false // Track whether serial actually changed

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if Globals.Debug {
			//  zd.Logger.Printf("ReadZoneData: parsed RR: %s", rr.String())
		}
		firstSoaSeen = zd.SortFunc(rr, firstSoaSeen)

		if firstSoaSeen && !checkedForUnchanged {
			checkedForUnchanged = true
			apex, ok := zd.Data.Get(zd.ZoneName)
			if !ok || apex.RRtypes == nil {
				return false, 0, fmt.Errorf("zone %s: zonefile contains no records for the configured apex; parsed apexes: [%s] (likely wrong zonefile path or stale file content)", zd.ZoneName, strings.Join(zd.Data.Keys(), ", "))
			}
			soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs[0].(*dns.SOA)
			zd.Logger.Printf("ParseZoneFromReader: %s: old incoming serial: %d new SOA serial: %d",
				zd.ZoneName, zd.IncomingSerial, soa.Serial)
			if soa.Serial == zd.IncomingSerial {
				if !force {
					zd.Logger.Printf("ParseZoneFromReader: %s: new SOA serial is the same as current. Reload not needed.", zd.ZoneName)
					return false, soa.Serial, nil
				}
				// force=true: continue parsing to validate zone file, but serial didn't change
				zd.Logger.Printf("ParseZoneFromReader: %s: new SOA serial is the same as current but still forced to reload (validating zone file).", zd.ZoneName)
				serialChanged = false
			} else {
				// Serial changed - this indicates an actual update
				serialChanged = true
			}
		}
	}

	var err error

	if err = zp.Err(); err != nil {
		zd.Logger.Printf("ParseZoneFromReader: Zone %s: Error from ZoneParser: %v", zd.ZoneName, err)
		if filename != "" {
			return false, 0, formatZoneParseError(err, filename)
		}
		return false, 0, err
	}

	apex, ok := zd.Data.Get(zd.ZoneName)
	if !ok || apex.RRtypes == nil {
		return false, 0, fmt.Errorf("zone %s: zonefile contains no records for the configured apex; parsed apexes: [%s] (likely wrong zonefile path or stale file content)", zd.ZoneName, strings.Join(zd.Data.Keys(), ", "))
	}

	soa_rrset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	var soa *dns.SOA
	if len(soa_rrset.RRs) > 0 {
		soa = soa_rrset.RRs[0].(*dns.SOA)
	} else {
		lgDns.Error("ParseZoneFromReader: SOA error", "zone", zd.ZoneName, "soa_rrset", soa_rrset)
		return false, 0, fmt.Errorf("ParseZoneFromReader: Zone %s: Error: SOA: %v", zd.ZoneName, soa_rrset)
	}

	zd.CurrentSerial = soa.Serial
	zd.IncomingSerial = soa.Serial

	zd.XfrType = "axfr"
	// Return true only if serial changed (indicates actual update)
	// If force=true but serial unchanged, return false (validated but no update)
	// This prevents unnecessary zone file writes on config reload when zone hasn't changed
	return serialChanged, soa.Serial, nil
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
	case MapZone:
		if omap, ok = zd.Data.Get(owner); !ok {
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
		lgDns.Error("WriteZoneToFile: failed to get zone apex", "zone", zd.ZoneName, "err", err)
		return err
	}
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	soa.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial

	//	zonedata += soa.String() + "\n"
	count := 0
	//	var total_sent int

	// SOA
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

// formatZoneParseError extracts the line number from the parse error string
// and appends the offending line from the zone file for context.
func formatZoneParseError(err error, filename string) error {
	errStr := err.Error()
	lineNum := 0
	if idx := strings.Index(errStr, "at line: "); idx != -1 {
		numStr := errStr[idx+len("at line: "):]
		parts := strings.SplitN(numStr, ":", 2)
		if n, e := strconv.Atoi(parts[0]); e == nil {
			lineNum = n
		}
	}
	if lineNum > 0 {
		if line, e := readLineFromFile(filename, lineNum); e == nil {
			return fmt.Errorf("%w\n  line %d: %s", err, lineNum, line)
		}
	}
	return err
}

func readLineFromFile(filename string, lineNum int) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for i := 1; scanner.Scan(); i++ {
		if i == lineNum {
			return scanner.Text(), nil
		}
	}
	return "", fmt.Errorf("line %d not found", lineNum)
}
