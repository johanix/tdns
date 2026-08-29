/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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

// drainTransferEnvelopes consumes the AXFR/IXFR envelope stream, feeding each
// RR to the zone's sort function, and stops early if ctx is cancelled.
//
// Extracted from ZoneTransferIn so the cancellation behaviour is reachable from
// a test: driving it through ZoneTransferIn means dialling a real upstream, and
// a test that cannot reach the loop cannot prove anything about it.
//
// On cancellation it does NOT simply walk away. abort() closes the transfer
// connection, then the remaining envelopes are drained until the library's
// reader closes the channel. That sequence is required, not tidiness:
// dns.Transfer.inAxfr sends on an UNBUFFERED channel, so a receiver that stops
// receiving parks it forever on its next send, its deferred t.Close()/close(c)
// never run, and the goroutine AND socket are retained for the life of the
// process. Closing the connection makes the reader's next ReadMsg fail, which
// puts it one send away from returning.
//
// (dns.Transfer.In has no context-aware variant and adding one to the
// johanix/dns fork was rejected -- every fork line is re-applied on every
// upstream sync -- which is why cancellation is handled here rather than in the
// library.)
func (zd *ZoneData) drainTransferEnvelopes(ctx context.Context, answerChan <-chan *dns.Envelope,
	upstream string, firstSoaSeen bool, abort func()) (int, error) {

	count := 0
	for {
		select {
		case <-ctx.Done():
			// Abandoning the stream here is NOT enough, and getting this wrong
			// is worse than not cancelling at all. dns.Transfer's reader
			// goroutine sends on an UNBUFFERED channel (xfr.go inAxfr:
			// `c <- &Envelope{...}`), so if we simply stop receiving it parks
			// forever on its next send. Its deferred t.Close()/close(c) never
			// run, and the goroutine AND its socket leak for the life of the
			// process -- once per cancelled transfer.
			//
			// So: close the connection first, which makes the reader's next
			// ReadMsg fail immediately, then keep receiving until it has sent
			// that final error envelope and closed the channel. Bounded, because
			// after the close the reader is at most one send from returning.
			if abort != nil {
				abort()
			}
			drained := drainRemainder(answerChan, transferDrainGrace)
			if !drained {
				// Should not happen: the reader is one send from exiting once
				// the connection is closed. Say so rather than leak silently.
				lg.Warn("ZoneTransferIn: transfer reader did not exit after cancellation; goroutine may be retained",
					"zone", zd.ZoneName, "upstream", upstream, "grace", transferDrainGrace)
			}
			return count, fmt.Errorf("ZoneTransferIn %s from %s: %w", zd.ZoneName, upstream, ctx.Err())

		case envelope, ok := <-answerChan:
			if !ok {
				return count, nil // channel closed: the transfer finished normally
			}
			if envelope.Error != nil {
				zd.Logger.Printf("ZoneTransfer: zone %s error: %v", zd.ZoneName, envelope.Error)
				return count, clarifyXfrError(zd.ZoneName, upstream, envelope.Error)
			}
			for _, rr := range envelope.RR {
				count++
				firstSoaSeen = zd.SortFunc(rr, firstSoaSeen)
			}
		}
	}
}

// transferDrainGrace bounds how long a cancelled transfer waits for the
// library's reader goroutine to notice the closed connection and exit. It is
// short on purpose: the reader is at most one channel send away from returning
// once the socket is closed, so anything longer would be waiting on a bug.
const transferDrainGrace = 5 * time.Second

// drainRemainder consumes and discards whatever the reader still sends, until
// it closes the channel or the grace period expires. Reports whether the
// channel actually closed (i.e. the reader goroutine finished).
func drainRemainder(ch <-chan *dns.Envelope, grace time.Duration) bool {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return true
			}
			// discard; we are on the way out
		case <-timer.C:
			return false
		}
	}
}

// ZoneTransferIn pulls the zone from the upstream primary described by up:
// AXFR/IXFR over Do53, or over TLS (XoT, RFC 9103) when up.Transport is dot.
// TSIG (up.Key) and TLS are independent layers and may be combined.
//
// ctx bounds the transfer. An AXFR of a large zone is the longest-running
// network operation in the daemon, so a shutdown landing mid-stream should stop
// it rather than let it run to completion against an engine that is going away.
// openTransferStream performs the setup every inbound transfer needs -- XoT TLS
// config, TSIG signing, the bound source address -- and starts the stream.
//
// Extracted so the AXFR and IXFR paths cannot drift apart on any of it. All
// three are invisible from the outside until something refuses us, and then the
// only evidence is in the far end's log.
func (zd *ZoneData) openTransferStream(ctx context.Context, up PeerConf, msg *dns.Msg, conf *Config) (<-chan *dns.Envelope, *dns.Transfer, error) {
	upstream := up.Addr
	transfer := new(dns.Transfer)
	// XoT: a DoT peer gets a verifying TLS config (pin/dane/pkix) and the
	// fork's Transfer.In dials tcp-tls with it. nil => plain TCP (Do53).
	tlsCfg, terr := conf.ClientTLSConfigForPeer(up)
	if terr != nil {
		return nil, nil, fmt.Errorf("ZoneTransferIn %s: TLS setup for %s: %w", zd.ZoneName, upstream, terr)
	}
	transfer.TLS = tlsCfg
	// Sign the AXFR/IXFR request under this upstream's key (NOKEY => unsigned).
	// The provider also verifies the TSIG on the inbound envelopes.
	provider, serr := SignForPeer(msg, up.Key, conf)
	if serr != nil {
		return nil, nil, fmt.Errorf("ZoneTransferIn %s: TSIG sign setup: %w", zd.ZoneName, serr)
	}
	transfer.TsigProvider = provider

	// Bind the local (source) address when the zone or the server names one.
	// This is what the upstream's allow-transfer/provide-xfr ACL sees; without
	// it the kernel picks a source from the outgoing interface, which on a
	// multi-homed server is generally not the address we advertise as our
	// identity -- so an ACL naming that address refuses us.
	//
	// dns.Transfer.In only dials when Conn is nil, and the library documents
	// pre-dialling for exactly this purpose, so no fork change is needed.
	//
	// Logged either way. Whether a source was bound is invisible from the
	// outside until an upstream ACL refuses the transfer, and then the only
	// evidence is in the far end's log -- which is where an afternoon goes.
	src, tier := zd.EffectiveTransferSrcWithSource()
	if len(src) > 0 {
		conn, derr := dialTransferConn(ctx, upstream, tlsCfg, src, transfer.DialTimeout)
		if derr != nil {
			return nil, nil, fmt.Errorf("ZoneTransferIn %s: dial %s: %w", zd.ZoneName, upstream, derr)
		}
		// nil means no configured source matched this upstream's family; leave
		// Conn unset so In() dials normally rather than relying on a typed-nil
		// pointer comparing equal to nil.
		if conn != nil {
			transfer.Conn = conn
			lgDns.Info("ZoneTransferIn: bound source address", "zone", zd.ZoneName,
				"upstream", upstream, "src", conn.LocalAddr().String(), "from", tier)
		} else {
			lgDns.Warn("ZoneTransferIn: no configured transfer-src matches this upstream's family; dialling unbound",
				"zone", zd.ZoneName, "upstream", upstream, "configured", src, "from", tier)
		}
	} else {
		lgDns.Debug("ZoneTransferIn: no transfer-src configured; dialling unbound",
			"zone", zd.ZoneName, "upstream", upstream)
	}

	answerChan, err := transfer.In(msg, upstream)
	if err != nil {
		zd.Logger.Printf("Error from transfer.In: %v\n", err)
		return nil, nil, clarifyXfrError(zd.ZoneName, upstream, err)
	}
	return answerChan, transfer, nil
}

func (zd *ZoneData) ZoneTransferIn(ctx context.Context, up PeerConf, serial uint32, ttype string, conf *Config) (uint32, error) {
	upstream := up.Addr
	if upstream == "" {
		Fatal("ZoneTransfer: upstream not set")
	}

	msg := new(dns.Msg)
	if ttype == "ixfr" {
		// NB: SetIxfr("", "") packs ZERO bytes for the empty MNAME/RNAME
		// (malformed SOA rdata → the primary FORMERRs the request). Root
		// names pack correctly; the primary only reads the serial anyway.
		msg.SetIxfr(zd.ZoneName, serial, ".", ".")
	} else {
		msg.SetAxfr(zd.ZoneName)
	}

	if zd.ZoneStore == MapZone {
		zd.Data = core.NewNameMap[OwnerData]()
	}
	lgDns.Info("ZoneTransferIn", "zone", zd.ZoneName, "store", ZoneStoreToString[zd.ZoneStore], "transport", transportLabel(up))

	answerChan, transfer, err := zd.openTransferStream(ctx, up, msg, conf)
	if err != nil {
		return 0, err
	}

	// count was previously computed and discarded; log it rather than drop it.
	count, err := zd.drainTransferEnvelopes(ctx, answerChan, upstream, false, func() { _ = transfer.Close() })
	if err != nil {
		return 0, err
	}
	lg.Debug("ZoneTransferIn: stream drained", "zone", zd.ZoneName, "upstream", upstream, "rrs", count)

	// A completed transfer always carries the apex SOA -- for AXFR the closing
	// SOA is what ends the stream, and dns.Transfer.In reports a stream that
	// ends without it as an error, handled above. So reaching this point
	// without one means the peer sent something that is not this zone.
	//
	// This used to take the lookup result unchecked and index the SOA RRset
	// directly. Both steps panic on the way through: a miss leaves RRtypes nil,
	// and an apex without an SOA leaves the RRset empty. That is a panic on the
	// success path of every zone transfer, reachable only through a peer that
	// is already misbehaving -- which is precisely when a nameserver must stay
	// up. An error discards the data, which is what a transfer that did not
	// deliver a zone deserves.
	soa, serr := zd.transferredApexSOA(upstream)
	if serr != nil {
		return 0, serr
	}

	zd.CurrentSerial = soa.Serial
	zd.IncomingSerial = soa.Serial
	// The journal anchors to the FILE, not to whatever the serial becomes
	// after load-time signing and republication. See ZoneData.fileSerial.
	zd.fileSerial = soa.Serial

	zd.Logger.Printf("*** Zone %s transferred from upstream %s. No errors.", zd.ZoneName, upstream)

	return soa.Serial, nil
}

// transferredApexSOA returns the apex SOA of a just-received zone, or an error
// if the peer did not deliver one.
func (zd *ZoneData) transferredApexSOA(upstream string) (*dns.SOA, error) {
	apex, ok := zd.Data.Get(zd.ZoneName)
	if !ok {
		return nil, fmt.Errorf("ZoneTransferIn %s: transfer from %s delivered no apex",
			zd.ZoneName, upstream)
	}
	if apex.RRtypes == nil {
		return nil, fmt.Errorf("ZoneTransferIn %s: apex from %s carries no RRsets",
			zd.ZoneName, upstream)
	}
	soaRRs := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs
	if len(soaRRs) == 0 {
		return nil, fmt.Errorf("ZoneTransferIn %s: transfer from %s delivered an apex with no SOA",
			zd.ZoneName, upstream)
	}
	soa, ok := soaRRs[0].(*dns.SOA)
	if !ok {
		return nil, fmt.Errorf("ZoneTransferIn %s: apex SOA RRset from %s holds a %T",
			zd.ZoneName, upstream, soaRRs[0])
	}
	return soa, nil
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

// ZoneTransferOut streams the zone to an authorized downstream. imr is only
// consulted by the downstream-auth tls-dane mechanism and may be nil (the
// mechanism then fails closed).
func (zd *ZoneData) ZoneTransferOut(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, imr *Imr) (int, error) {
	zone := dns.Fqdn(zd.ZoneName)

	// The complete authorization gate: downstreams ACL (address + TSIG,
	// unchanged semantics) plus the per-zone downstream-auth mechanism
	// ladder (peers tls-identity checks against the connection's client
	// certificate). See v2/downstream_auth.go.
	if err := zd.authorizeTransfer(ctx, w, r, imr); err != nil {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer to %s: %v", zone, w.RemoteAddr(), err)
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

	// Pin ONE snapshot for the whole transfer so every owner comes from the
	// same serial — no torn AXFR (M1).
	snap := zd.publishedSnapshot()
	if snap == nil {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, no published snapshot", zone)
		return zd.refuseTransfer(w, r)
	}
	apex := getOwnerFrom(snap, zd.ZoneName)
	if apex == nil {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, missing apex", zone)
		return zd.refuseTransfer(w, r)
	}
	soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soaRRset.RRs) == 0 {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, empty SOA RRset", zone)
		return zd.refuseTransfer(w, r)
	}
	// Fail-closed: a zone configured to be signed must never be transferred
	// unsigned. The SOA is an apex RRset and is always signed in a healthy
	// signed zone, so an SOA with no RRSIG means the pinned snapshot is not
	// (yet / any longer) signed — refuse rather than hand a secondary a zone it
	// would serve BOGUS. Catches both a persistent sign failure and the reload
	// re-sign window. (Surfacing WHY is deferred to the DnssecError redesign.)
	if (zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]) && len(soaRRset.RRSIGs) == 0 {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, zone is configured to be signed but the SOA has no RRSIG (unsigned/broken)", zone)
		return zd.refuseTransfer(w, r)
	}
	soaOrig, ok := soaRRset.RRs[0].(*dns.SOA)
	if !ok {
		zd.Logger.Printf("ZoneTransferOut: %s: refusing transfer, invalid SOA RR", zone)
		return zd.refuseTransfer(w, r)
	}

	soaCopy := dns.Copy(soaOrig).(*dns.SOA)
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

	// Outbound IXFR (RFC 1995, Project C). Decided before the envelope stream
	// is set up: single-SOA answers short-circuit entirely; a provable delta
	// (contiguous chain from the client's serial to the pinned snapshot's
	// serial) is streamed below; anything else falls through to the full
	// transfer, which IS the RFC 1995 §4 fallback shape. All decisions key on
	// the pinned snapshot only.
	var ixfrSteps []Ixfr
	if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeIXFR && snap.SOA != nil {
		clientSOA := ixfrQuerySOA(r)
		switch {
		case clientSOA == nil:
			zd.Logger.Printf("ZoneTransferOut: %s: IXFR query from %s carries no SOA in the authority section; serving full zone",
				zone, w.RemoteAddr())
		case !serialNewer(snap.Serial, clientSOA.Serial):
			// Client is same-or-newer than us: single SOA (RFC 1995 §2).
			return zd.ixfrSingleSOAReply(w, r, dns.Copy(snap.SOA).(*dns.SOA))
		case isUDPTransport(w):
			// v1 never streams deltas over UDP: a single SOA at the current
			// serial tells the client to retry over TCP (RFC 1995 §4).
			return zd.ixfrSingleSOAReply(w, r, dns.Copy(snap.SOA).(*dns.SOA))
		default:
			if steps, ok := ixfrDeltaSteps(snap, clientSOA.Serial); ok {
				ixfrSteps = steps
			} else {
				zd.Logger.Printf("ZoneTransferOut: %s: no contiguous IXFR history from serial %d to %d; falling back to full transfer",
					zone, clientSOA.Serial, snap.Serial)
			}
		}
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

	if ixfrSteps != nil {
		return zd.emitIxfrDelta(bs, dns.Copy(snap.SOA).(*dns.SOA), ixfrSteps)
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
	// The NSEC property travels in the transfer like any other record. The
	// receiving secondary has no private key and cannot synthesise denial, so
	// the chain it gets here is the only one it will ever have.
	if len(apex.NSEC.RRs) > 0 && !appendRRset(bs, apex.NSEC) {
		return 0, nil
	}

	names := make([]string, 0, len(snap.Data))
	for name := range snap.Data {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, owner := range names {
		if owner == zd.ZoneName {
			continue
		}
		omap := getOwnerFrom(snap, owner)
		if omap == nil {
			continue
		}
		for _, rrt := range omap.RRtypes.Keys() {
			rrset := omap.RRtypes.GetOnlyRRSet(uint16(rrt))
			if !appendRRset(bs, rrset) {
				return 0, nil
			}
		}
		if len(omap.NSEC.RRs) > 0 && !appendRRset(bs, omap.NSEC) {
			return 0, nil
		}
	}

	return zd.finishTransferWithTrailingSOA(bs, dns.Copy(soaCopy).(*dns.SOA))
}

// finishTransferWithTrailingSOA appends the trailing SOA (flushing first when
// it would not fit), runs the final oversize check, and sends the last
// envelope. Shared by the AXFR and IXFR emission paths.
func (zd *ZoneData) finishTransferWithTrailingSOA(bs *batchState, trailingSOA *dns.SOA) (int, error) {
	zone := dns.Fqdn(zd.ZoneName)
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

	*bs.totalSent += *bs.count
	if zd.Verbose || Globals.Debug {
		zd.Logger.Printf("XfrOut: Zone %s: Sending final batch #%d: %d RRs, %d bytes (total sent: %d RRs)",
			zd.ZoneName, *bs.batchNum, len(*bs.rrs), finalSize, *bs.totalSent)
	} else {
		zd.Logger.Printf("XfrOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)",
			zd.ZoneName, len(*bs.rrs), *bs.totalSent)
	}
	if !bs.sendEnvelope(*bs.rrs) {
		return 0, nil
	}

	zd.Logger.Printf("ZoneTransferOut: %s: Sent %d RRs.", zone, *bs.totalSent)
	return *bs.totalSent, nil
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
		return 0, err
	}
	return 0, nil
}

func (zd *ZoneData) ReadZoneFile(ctx context.Context, filename string, force bool) (bool, uint32, error) {
	zd.Logger.Printf("ReadZoneFile: zone: %s", zd.ZoneName)

	f, err := os.Open(filename)
	if err != nil {
		return false, 0, fmt.Errorf("ReadZoneFile: Error: failed to read %s: %v", filename, err)
	}
	// The handle was never closed, on any path. It leaked on success too --
	// every zone load, for as long as it took the finalizer to notice -- so a
	// server reloading zones often could accumulate descriptors it was not
	// using. Cancellation makes the same leak easier to reach, since a parse
	// now returns before EOF, but it did not introduce it.
	//
	// Safe as a defer: ParseZoneFromReader consumes the reader within the call
	// and does not retain it past return.
	defer f.Close()

	return zd.ParseZoneFromReader(ctx, bufio.NewReader(f), force, filename)
}

// ReadZoneData parses a zone from a string already in memory.
//
// Deliberately not context-aware, and deliberately not a TODO. The cancellation
// check inside ParseZoneFromReader exists for the file path, where parsing is
// the long uninterruptible stretch of a refresh that a shutdown may need to
// abandon. Here the caller already holds the entire zone: there is no I/O to
// abort, and threading a context to reach this call would mean adding one to
// CreateAutoZone and to a dozen test helpers for no cancellation anyone can
// observe. If a caller ever parses a string large enough for that to be wrong,
// give this function a ctx then.
func (zd *ZoneData) ReadZoneData(zoneData string, force bool) (bool, uint32, error) {
	zd.Logger.Printf("ReadZoneData: zone: %s", zd.ZoneName)
	return zd.ParseZoneFromReader(context.Background(), strings.NewReader(zoneData), force, "")
}

// The receiver must be a ZoneData the caller owns exclusively. This writes the
// file identity fields (fileSerial, fileDigest) directly and without taking
// zd.mu, so parsing into a zone other goroutines can already observe is a data
// race against every reader of that state.
//
// The lock is deliberately NOT taken here: several callers construct a zone and
// parse into it before anyone else can see it, and one of them would have to
// hold zd.mu across the parse to be correct -- which would deadlock. The
// invariant belongs to the caller instead. FetchFromFile shows the pattern for
// a registered zone: parse into a scratch new_zd, then copy the fields across
// under the lock.
func (zd *ZoneData) ParseZoneFromReader(ctx context.Context, r io.Reader, force bool, filename string) (bool, uint32, error) {
	// Safe here for the reason the comment above gives: the caller owns this
	// ZoneData exclusively. Every path that builds a ZoneData already folds the
	// name, but this is the one gate a zone must pass to acquire any data at
	// all, and the owner map it is about to fill is keyed canonically -- a zone
	// arriving with an unfolded name would not find its own apex.
	zd.normalizeZoneName()
	zd.Logger.Printf("ParseZoneFromReader: zone: %s", zd.ZoneName)

	switch zd.ZoneStore {
	case MapZone:
		zd.Data = core.NewNameMap[OwnerData]()
	default:
		return false, 0, fmt.Errorf("ParseZoneFromReader: zone store %d not supported", zd.ZoneStore)
	}

	zp := dns.NewZoneParser(r, "", filename)
	zp.SetIncludeAllowed(true)

	firstSoaSeen := false
	checkedForUnchanged := false
	serialChanged := false // Track whether serial actually changed

	// Parsing a large zone file is the longest uninterruptible stretch on the
	// load path, so it is where a cancelled refresh would otherwise sit until
	// the file ran out. Checked every parseCancelCheckInterval records rather
	// than every record: ctx.Err() is cheap but not free, and a zone big enough
	// for the wait to matter is big enough that a few thousand records of
	// latency is not what anyone is waiting on.
	const parseCancelCheckInterval = 2048
	parsed := 0

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		parsed++
		if parsed%parseCancelCheckInterval == 0 {
			if cerr := ctx.Err(); cerr != nil {
				return false, 0, fmt.Errorf("zone %s: parsing %s abandoned after %d records: %w",
					zd.ZoneName, filename, parsed, cerr)
			}
		}
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
				// force=true: parse the whole file anyway. For the zone-file
				// refresh path that is not "the operator forced it" but the
				// normal case -- whether the file changed is decided on its
				// content digest, which cannot be computed without parsing it.
				zd.Logger.Printf("ParseZoneFromReader: %s: new SOA serial is the same as the one last read; parsing the whole file anyway.", zd.ZoneName)
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
	// The journal anchors to the FILE, not to whatever the serial becomes
	// after load-time signing and republication. See ZoneData.fileSerial.
	zd.fileSerial = soa.Serial

	// And its ZONEMD digest, taken HERE for the same reason: this is the last
	// moment at which the in-memory zone is what the file says and nothing
	// else. Anything computed after load-time signing includes RRSIGs the file
	// never had, and would never match the file it is meant to identify.
	//
	// A failure is not fatal to the load. The digest is a detector; without it
	// the zone falls back to comparing serials, which is what it did before
	// this existed. Refusing to serve a zone because we could not fingerprint
	// it would be a poor trade.
	if digest, derr := zd.zoneDigestOfWorkingData(); derr != nil {
		lgDns.Warn("could not compute the zone file digest; file-change detection"+
			" falls back to the SOA serial for this load",
			"zone", zd.ZoneName, "error", derr)
	} else {
		zd.fileDigest = digest
	}

	zd.XfrType = "axfr"
	// Return true only if serial changed (indicates actual update)
	// If force=true but serial unchanged, return false (validated but no update)
	// This prevents unnecessary zone file writes on config reload when zone hasn't changed
	return serialChanged, soa.Serial, nil
}

func (zd *ZoneData) SortFunc(rr dns.RR, firstSoaSeen bool) bool {
	// The owner keeps the spelling it arrived with. zd.Data folds the key, so
	// the name is found however it is later asked for, while OwnerData.Name and
	// the RR headers still carry what the zone file actually said -- which is
	// what an outgoing AXFR and a written zone file reproduce.
	owner := rr.Header().Name
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

	// In-bailiwick test, not a string suffix test. strings.HasSuffix compares
	// bytes, so an owner spelling the zone-name part in another case --
	// www.EXAMPLE.com. in example.com., which is what $ORIGIN EXAMPLE.com. with
	// relative names produces -- failed this check and was silently discarded,
	// unreachable afterwards by any spelling. dns.IsSubDomain folds case as DNS
	// requires and is true for the apex itself.
	if !dns.IsSubDomain(zd.ZoneName, rr.Header().Name) {
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

	case *dns.NSEC:
		// NSEC is a property of the owner, not an RRset of its own: see
		// OwnerData.NSEC. Parsed here so a zone file written by this server --
		// or by anything else -- round-trips, and so a secondary loading a
		// signed zone from disk keeps the chain it was given.
		switch ztype {
		case MapZone:
			omap.NSEC.Name, omap.NSEC.RRtype, omap.NSEC.Class = owner, dns.TypeNSEC, dns.ClassINET
			omap.NSEC.RRs = append(omap.NSEC.RRs, rr)
		}

	case *dns.RRSIG:
		rrt := v.TypeCovered
		switch ztype {
		case MapZone:
			if rrt == dns.TypeNSEC {
				// Follows its NSEC into the property rather than into
				// RRtypes[NSEC], which no longer exists.
				omap.NSEC.Name, omap.NSEC.RRtype, omap.NSEC.Class = owner, dns.TypeNSEC, dns.ClassINET
				omap.NSEC.RRSIGs = append(omap.NSEC.RRSIGs, rr)
				break
			}
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

	_, err = zd.WriteZoneToFile(f)
	if err != nil {
		return f.Name(), err
	}
	return f.Name(), nil
}

// WriteFile writes the zone and returns the filename. Callers that need the
// serial written -- WriteZone, to bound its delta drop -- use
// WriteFileWithSerial.
func (zd *ZoneData) WriteFile(filename string) (string, error) {
	fname, _, err := zd.WriteFileWithSerial(filename)
	return fname, err
}

// WriteFileWithSerial writes the zone out and reports the SOA serial it wrote.
//
// The write is staged in a temporary file in the same directory and renamed
// into place, and every step -- flush, sync, close, rename -- is checked. Both
// properties are load-bearing for Phase 2, not general tidiness.
//
// WriteZone treats a successful return here as "the file now contains
// everything the zone has" and DELETES the journal deltas up to that serial.
// The journal is the only replayable copy of those changes. So a write that
// half-succeeded and reported success would take the file AND the journal in
// one move: os.Create truncates first, and the buffered tail can fail to flush
// on a full or failing disk long after the early records landed. Returning the
// error keeps the journal, which is what makes the failure survivable.
//
// Staging and renaming closes the other half: a reader -- the next startup,
// most of all -- never sees a partially written zone file, because the name
// only ever points at a complete one. The directory fsync is what makes that
// rename outlive a power cut rather than merely a process crash.
func (zd *ZoneData) WriteFileWithSerial(filename string) (string, uint32, error) {
	fname := fmt.Sprintf("%s/%s", viper.GetString("external.filedir"), filename)

	dir := filepath.Dir(fname)
	tmp, err := os.CreateTemp(dir, filepath.Base(fname)+".tmp")
	if err != nil {
		return fname, 0, fmt.Errorf("creating a temporary file beside %s: %v", fname, err)
	}
	tmpname := tmp.Name()

	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpname)
		}
	}()

	wrote, err := zd.WriteZoneToFile(tmp)
	if err != nil {
		return fname, 0, err
	}
	if err := tmp.Sync(); err != nil {
		return fname, 0, fmt.Errorf("syncing %s: %v", tmpname, err)
	}
	if err := tmp.Close(); err != nil {
		return fname, 0, fmt.Errorf("closing %s: %v", tmpname, err)
	}

	// os.CreateTemp makes the file 0600. Carry over the mode of the file being
	// replaced, so a zone file readable by a non-root process stays readable.
	mode := os.FileMode(0644)
	if fi, serr := os.Stat(fname); serr == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.Chmod(tmpname, mode); err != nil {
		return fname, 0, fmt.Errorf("setting mode on %s: %v", tmpname, err)
	}

	if err := os.Rename(tmpname, fname); err != nil {
		return fname, 0, fmt.Errorf("renaming %s to %s: %v", tmpname, fname, err)
	}
	committed = true

	// Persist the rename itself, and FAIL if that cannot be done.
	//
	// Logging and returning success was the wrong call: WriteZone reads a
	// successful return as licence to delete the journal deltas, so a directory
	// entry that never reached disk leaves a power failure with the OLD zone
	// file and no journal -- the precise loss the staging and syncing above
	// exist to prevent, reached one step later. Reporting the write as
	// incomplete keeps the journal, which is what makes it survivable.
	d, derr := os.Open(dir)
	if derr != nil {
		return fname, 0, fmt.Errorf("opening %s to sync the rename: %v", dir, derr)
	}
	if serr := d.Sync(); serr != nil {
		d.Close()
		return fname, 0, fmt.Errorf("syncing %s after renaming %s into place: %v", dir, fname, serr)
	}
	if cerr := d.Close(); cerr != nil {
		return fname, 0, fmt.Errorf("closing %s after syncing: %v", dir, cerr)
	}

	return fname, wrote, nil
}

// WriteZoneToFile serialises the PUBLISHED snapshot and reports the SOA serial
// it wrote. That serial is what makes the delta drop in WriteZone exact: any
// journalled change whose ToSerial is not newer than it is, by definition,
// already in this file.
func (zd *ZoneData) WriteZoneToFile(f *os.File) (uint32, error) {
	var err error
	var bytes, totalbytes int
	zonedata := ""

	writer := bufio.NewWriter(f)

	snap := zd.publishedSnapshot()
	apex := getOwnerFrom(snap, zd.ZoneName)
	if apex == nil {
		lgDns.Error("WriteZoneToFile: failed to get zone apex", "zone", zd.ZoneName)
		return 0, fmt.Errorf("WriteZoneToFile: %s: no apex in published snapshot", zd.ZoneName)
	}
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)

	// The serial actually written. Reported to the caller so the delta drop in
	// WriteZone can be bound to this file's CONTENT rather than to a time
	// window. Reading a journal ceiling before the write leaves a gap in which
	// a publish lands in the file while its delta row survives the drop, and
	// that retained row then fails the chain check on the next load -- the same
	// false "the file has been edited or replaced" accusation, reached from the
	// other side.
	var wroteSerial uint32
	if len(soa.RRs) > 0 {
		if s, ok := soa.RRs[0].(*dns.SOA); ok {
			wroteSerial = s.Serial
		}
	}

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
	// The NSEC property is written like any other record. A secondary that
	// loads this file in the absence of its primary has no private key and
	// answers denial from the chain in the file, so leaving it out would hand
	// that secondary a signed zone it cannot prove anything with.
	zonedata += RRsetToString(&apex.NSEC)
	count += len(apex.NSEC.RRs) + len(apex.NSEC.RRSIGs)

	// Rest of zone
	names := make([]string, 0, len(snap.Data))
	for name := range snap.Data {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, owner := range names {
		if owner == zd.ZoneName {
			continue
		}
		omap := getOwnerFrom(snap, owner)
		if omap == nil {
			continue
		}
		zonedata += RRsetToString(&omap.NSEC)
		count += len(omap.NSEC.RRs) + len(omap.NSEC.RRSIGs)
		for _, rrt := range omap.RRtypes.Keys() {
			rrl := omap.RRtypes.GetOnlyRRSet(rrt)
			zonedata += RRsetToString(&rrl)
			count += len(rrl.RRs) + len(rrl.RRSIGs)

			if count >= 1000 {
				bytes, err = writer.WriteString(zonedata)
				if err != nil {
					return 0, err
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
	// 				return 0, err
	// 			}
	// 			totalbytes += bytes
	// 			bytes = 0
	// 			zonedata = ""
	// 		}
	// 	}
	bytes, err = writer.WriteString(zonedata)
	if err != nil {
		return 0, err
	}
	totalbytes += bytes
	// Flush's error is the one that matters most and used to be discarded. Every
	// WriteString above only fills a buffer; the actual disk write happens here,
	// so a full or failing disk shows up at THIS call and nowhere earlier. The
	// old `return wroteSerial, err` returned the (nil) error from the last
	// WriteString instead, reporting a complete file to a caller that then
	// deleted the journal.
	if err := writer.Flush(); err != nil {
		return 0, fmt.Errorf("writing zone %s: %v", zd.ZoneName, err)
	}
	return wroteSerial, nil
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

// InBailiwick reports whether a nameserver name lies inside zone.
//
// dns.IsSubDomain, not strings.HasSuffix: the latter compares bytes, so it is
// both case-sensitive and blind to label boundaries -- it calls
// ns.evilexample. in-bailiwick for example.
//
// NOTE: this has no callers. NSInBailiwick in scanner_csync.go is the live
// twin, fixed the same way in the delegation stage of this series, and
// BailiwickNS is a third spelling of the same predicate. The three should be
// one function.
func InBailiwick(zone string, ns *dns.NS) bool {
	return dns.IsSubDomain(zone, ns.Ns)
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

// pickTransferSrc picks the source address to bind for an upstream, and the
// network ("tcp4"/"tcp6") to dial so the destination cannot end up in the other
// family. A family with no configured source returns nil, meaning "dial
// unbound" -- deliberately forgiving, because an operator who names only a v4
// source should not thereby break every v6 upstream.
//
// The upstream may be a LITERAL or a HOSTNAME. For a literal the family is read
// off the address. For a hostname it has to be resolved: the first version of
// this bound whichever family net.ParseIP happened to report for a name it
// could not parse -- always "not v4" -- so a hostname upstream that resolves to
// IPv4 got an IPv6 source bound and the dial failed. Resolution failure falls
// back to unbound rather than to a guess.
//
// When a hostname resolves to both families, the configured sources decide:
// whichever family we have a source for wins, in configured order. That keeps
// the ACL-visible address predictable, which is the entire point of the option.
// lookup is injected so the hostname path is testable without depending on what
// the test host's resolver happens to return -- a dual-stack "localhost" would
// make the v4-only case untestable, which is precisely the case that was broken.
// nil means the system resolver.
func pickTransferSrc(ctx context.Context, lookup func(context.Context, string) ([]net.IPAddr, error), upstream string, srcs []string) (net.IP, string) {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		host = upstream
	}

	// Parsed sources, in configured order. Unparseable entries cannot reach
	// here -- ValidateTransferSrc rejects them at config load -- but skip them
	// rather than binding something meaningless if one ever does.
	var parsed []net.IP
	for _, s := range srcs {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			parsed = append(parsed, ip)
		}
	}
	if len(parsed) == 0 {
		return nil, ""
	}

	// Which families can the upstream actually be reached over?
	var have4, have6 bool
	if ip := net.ParseIP(host); ip != nil {
		have4, have6 = ip.To4() != nil, ip.To4() == nil
	} else {
		if lookup == nil {
			lookup = net.DefaultResolver.LookupIPAddr
		}
		addrs, rerr := lookup(ctx, host)
		if rerr != nil {
			// Cannot tell the family; binding a guess risks failing a transfer
			// that would otherwise work.
			return nil, ""
		}
		for _, a := range addrs {
			if a.IP.To4() != nil {
				have4 = true
			} else {
				have6 = true
			}
		}
	}

	for _, ip := range parsed {
		if ip.To4() != nil && have4 {
			return ip, "tcp4"
		}
		if ip.To4() == nil && have6 {
			return ip, "tcp6"
		}
	}
	return nil, ""
}

// bindClientSrc configures c to send from one of srcs when a source of the
// upstream's family is configured, and reports the address it bound (nil for
// "left alone"). It is the SOA probe's counterpart to dialTransferConn.
//
// WHY THE PROBE NEEDS THIS AT ALL. transfer-src exists so that the address the
// primary's ACL sees is the one the operator published. Binding it on the AXFR
// and not on the probe that precedes every AXFR gets that half right: against a
// primary that only permits the published address, the transfer would work and
// the probe does not, so the zone never transfers -- and the error names a
// source the operator never configured and cannot find in any config file.
//
// TWO THINGS DIFFER FROM THE TRANSFER PATH, and both are easy to get wrong.
//
// The probe defaults to UDP, so LocalAddr must be a *net.UDPAddr. A *net.TCPAddr
// there -- the type dialTransferConn correctly uses -- fails the dial with a
// mismatched address type, which reads as an unreachable primary.
//
// The family has to be pinned in c.Net for the same reason dialTransferConn
// pins the network: binding a v4 source and letting a dual-stack hostname
// upstream resolve to v6 cannot work. The pinned spelling has to match the
// transport already selected, hence the switch rather than a bare "udp4".
//
// A family with no configured source leaves c untouched and returns nil, so the
// probe dials unbound -- the same forgiving default pickTransferSrc applies, for
// the same reason: naming only a v4 source must not break every v6 upstream.
func bindClientSrc(ctx context.Context, c *dns.Client, upstream string, srcs []string) net.IP {
	if c == nil || len(srcs) == 0 {
		return nil
	}
	src, _ := pickTransferSrc(ctx, nil, upstream, srcs)
	if src == nil {
		return nil
	}

	fam := "6"
	if src.To4() != nil {
		fam = "4"
	}

	// Preserve the dial timeout the client would otherwise have got from
	// miekg's own default; setting Dialer replaces that machinery wholesale.
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}

	switch transport := c.Net; {
	case strings.HasSuffix(transport, "-tls"):
		c.Net = strings.TrimSuffix(transport, "-tls") + fam + "-tls"
		d.LocalAddr = &net.TCPAddr{IP: src}
	case strings.HasPrefix(transport, "tcp"):
		c.Net = "tcp" + fam
		d.LocalAddr = &net.TCPAddr{IP: src}
	default: // "" and "udp" both mean UDP to miekg
		c.Net = "udp" + fam
		d.LocalAddr = &net.UDPAddr{IP: src}
	}
	c.Dialer = d
	return src
}

// dialTransferConn dials upstream with the source address bound, returning a
// *dns.Conn ready to hand to dns.Transfer. tlsCfg non-nil selects XoT.
//
// The network is pinned to the source's family. Dialling "tcp" with a v4
// LocalAddr and letting the resolver hand back a v6 destination (or the
// reverse) is a guaranteed failure, and for a dual-stack hostname upstream that
// is not a hypothetical. The hostname is still what gets dialled, so SNI and
// certificate verification on the XoT path are unchanged.
func dialTransferConn(parent context.Context, upstream string, tlsCfg *tls.Config, srcs []string, timeout time.Duration) (*dns.Conn, error) {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	if parent == nil {
		parent = context.Background()
	}
	// Derive from the caller's context, so a shutdown landing in a bound-source
	// dial returns immediately instead of waiting out the full dial timeout.
	//
	// The ctx has to reach the CONNECT, not just the lookup: for an IP-literal
	// upstream -- the common case -- pickTransferSrc does no resolution at all,
	// so passing ctx only there would leave the 2s dial uncancellable while the
	// comment claimed otherwise. Hence DialContext, and tls.Dialer rather than
	// tls.DialWithDialer so the handshake runs under the same ctx too.
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	src, network := pickTransferSrc(ctx, nil, upstream, srcs)
	if src == nil {
		return nil, nil // no matching family; caller leaves Conn nil and In() dials
	}
	d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: src}}

	if tlsCfg != nil {
		td := &tls.Dialer{NetDialer: d, Config: tlsCfg}
		c, err := td.DialContext(ctx, network, upstream)
		if err != nil {
			return nil, err
		}
		return &dns.Conn{Conn: c}, nil
	}
	c, err := d.DialContext(ctx, network, upstream)
	if err != nil {
		return nil, err
	}
	return &dns.Conn{Conn: c}, nil
}
