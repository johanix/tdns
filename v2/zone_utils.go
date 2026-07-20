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
	"sort"
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
		// D1: re-resolve hostname primaries each refresh, so a transient
		// resolution failure self-heals and a changed primary address is
		// followed. Literal-IP primaries pass through unchanged (no lookup). If
		// nothing resolves this cycle (IMR not up yet at startup, or the name is
		// temporarily unreachable), keep the previous upstreams; DoTransfer then
		// surfaces a refresh error and we retry next cycle — never a permanent
		// quarantine.
		if len(zd.PrimariesConf) > 0 {
			if res := resolvePrimaries(context.Background(), conf.Internal.ImrEngine, zd.PrimariesConf); len(res.Resolved) > 0 {
				zd.Upstreams = res.Resolved
			} else {
				lg.Warn("zone refresh: no primary resolved this cycle, will retry next refresh", "zone", zd.ZoneName, "unresolved", res.Unresolved)
			}
		}
		do_transfer, upstream_serial, err := zd.DoTransfer(conf)
		if err != nil {
			return false, err
		}

		if do_transfer || force {
			if do_transfer {
				lg.Info("upstream serial has increased", "zone", zd.ZoneName, "old", zd.IncomingSerial, "new", upstream_serial)
			} else if force {
				lg.Debug("forced retransfer regardless of SOA serial", "zone", zd.ZoneName)
			}
			updated, err = zd.FetchFromUpstream(verbose, debug, dynamicRRs, conf)
			if err != nil {
				lg.Error("FetchZone failed", "zone", zd.ZoneName, "upstream", firstUpstreamAddr(zd.Upstreams), "err", err)
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

// firstUpstreamAddr returns the first transfer target, or "" if none configured.
func firstUpstreamAddr(upstreams []PeerConf) string {
	if len(upstreams) == 0 {
		return ""
	}
	return upstreams[0].Addr
}

// Return shouldTransfer, new upstream serial, error
//
// The SOA probe iterates zd.Upstreams, advancing to the next address whenever
// the current one does not yield a usable SOA — a transport error OR a
// non-usable rcode (REFUSED/SERVFAIL/NXDOMAIN/empty). Different primaries are
// independent servers that may answer differently (e.g. per-primary ACLs), so
// one primary refusing does not mean the zone is unavailable from a sibling.
// A usable NOERROR+SOA from any primary is honoured (transfer decided on
// serial). If every primary answered but none gave a usable SOA, we back off
// quietly (no transfer, no error); only all-unreachable is a hard error.
func (zd *ZoneData) DoTransfer(conf *Config) (bool, uint32, error) {
	if zd == nil {
		panic("DoTransfer: zd == nil")
	}

	if len(zd.Upstreams) == 0 {
		return false, 0, fmt.Errorf("DoTransfer: zone %s has no upstreams configured", zd.ZoneName)
	}

	sawResponse := false
	var lastErr error
	for _, up := range zd.Upstreams {
		upstream := up.Addr
		if _, _, err := net.SplitHostPort(upstream); err != nil {
			// If error, assume no port was specified
			upstream = net.JoinHostPort(upstream, defaultPortForPeer(up))
			lg.Debug("DoTransfer: no port specified for upstream, using transport default", "zone", zd.ZoneName, "upstream", upstream)
		}
		// Fresh message per attempt: TSIG signing adds an RR with a per-attempt
		// timestamp and this upstream's key.
		m := new(dns.Msg)
		m.SetQuestion(zd.ZoneName, dns.TypeSOA)
		c := new(dns.Client)
		// XoT peer: probe the SOA over the same verified-TLS channel the
		// transfer itself will use (same pin/dane/pkix gate).
		if tlsCfg, terr := conf.ClientTLSConfigForPeer(up); terr != nil {
			lg.Error("DoTransfer: TLS setup failed, trying next upstream", "zone", zd.ZoneName, "upstream", upstream, "err", terr)
			lastErr = terr
			continue
		} else if tlsCfg != nil {
			c.Net = "tcp-tls"
			c.TLSConfig = tlsCfg
		}
		provider, serr := SignForPeer(m, up.Key, conf)
		if serr != nil {
			lg.Error("DoTransfer: TSIG sign setup failed, trying next upstream", "zone", zd.ZoneName, "upstream", upstream, "key", up.Key, "err", serr)
			lastErr = serr
			continue
		}
		c.TsigProvider = provider // nil for NOKEY => plain exchange (no MAC)
		r, _, err := c.Exchange(m, upstream)
		if err != nil {
			// Transport failure (or a TSIG response-verify failure) — try the next sibling.
			lg.Warn("DoTransfer: SOA probe failed, trying next upstream", "zone", zd.ZoneName, "upstream", upstream, "err", err)
			lastErr = err
			continue
		}
		sawResponse = true
		switch r.MsgHdr.Rcode {
		case dns.RcodeSuccess:
			if len(r.Answer) == 0 {
				lg.Debug("DoTransfer: NOERROR but empty answer section, trying next upstream", "zone", zd.ZoneName, "upstream", upstream)
				continue
			}
			if soa, ok := r.Answer[0].(*dns.SOA); ok {
				lg.Info("DoTransfer: serial check", "zone", zd.ZoneName, "upstream", upstream, "notify_serial", soa.Serial, "incoming_serial", zd.IncomingSerial, "current_serial", zd.CurrentSerial)
				if soa.Serial <= zd.IncomingSerial {
					return false, soa.Serial, nil
				}
				return true, soa.Serial, nil
			}
			// NOERROR but the first answer is not a SOA — try the next sibling.
			continue
		default:
			// REFUSED / SERVFAIL / NXDOMAIN / etc. This primary will not give a
			// usable SOA, but a sibling may (e.g. differing per-primary ACLs).
			lg.Debug("DoTransfer: non-usable SOA rcode, trying next upstream", "zone", zd.ZoneName, "upstream", upstream, "rcode", dns.RcodeToString[r.MsgHdr.Rcode])
			continue
		}
	}

	if sawResponse {
		// At least one primary answered, but none gave a usable SOA (e.g. all
		// REFUSED). Back off quietly — no transfer this cycle, not an error.
		return false, 0, nil
	}
	// No primary was even reachable.
	lg.Error("DoTransfer: SOA probe failed on all upstreams (unreachable)", "zone", zd.ZoneName, "count", len(zd.Upstreams), "err", lastErr)
	return false, 0, fmt.Errorf("SOA probe of %s failed: all %d upstream(s) unreachable: %w", zd.ZoneName, len(zd.Upstreams), lastErr)
}

// Return updated, error
func (zd *ZoneData) FetchFromFile(verbose, debug, force bool, dynamicRRs []*core.RRset) (bool, error) {

	// log.Printf("Reading zone %s from file %s\n", zd.ZoneName, zd.Zonefile)
	// Capture prior status so an error or no-op (unchanged) file read of an
	// already-ready zone is restored to it, not left stuck in `loading`.
	prevStatus := zd.GetStatus()
	zd.SetStatus(ZoneStatusLoading)

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
		zd.SetStatus(prevStatus)
		return false, err
	}

	// zd.Logger.Printf("FetchFromFile: Zone %s: zone file read, updated=%v delegation sync=%v", zd.ZoneName, updated, zd.Optoins["delegationsync"])

	if !updated {
		zd.SetStatus(prevStatus)
		return false, nil // new zone not loaded, but not returning any error
	}

	new_zd.Ready = true

	// Pre-refresh callbacks: analysis of old vs new zone data + modification of new_zd.
	// MP roles (agent, combiner, signer) register callbacks to detect HSYNC/DNSKEY/delegation
	// changes, add combiner contributions, populate MP data, etc. — all before the hard flip.
	for _, cb := range zd.OnZonePreRefresh {
		cb(zd, &new_zd)
	}

	// Publish replacement: working set from refreshed data + dynamic RRs.
	zd.mu.Lock()
	firstLoad := zd.FirstZoneLoad
	if err := zd.applyRefreshReplacementLocked(&new_zd, dynamicRRs, firstLoad); err != nil {
		zd.mu.Unlock()
		lg.Error("failed to persist outgoing serial", "zone", zd.ZoneName, "err", err)
		return false, err
	}
	zd.mu.Unlock()

	// Post-refresh callbacks: queue sends and notifications that need the live zone pointer.
	for _, cb := range zd.OnZonePostRefresh {
		cb(zd)
	}

	return true, nil
}

// Return updated, err
func (zd *ZoneData) FetchFromUpstream(verbose, debug bool, dynamicRRs []*core.RRset, conf *Config) (bool, error) {

	if len(zd.Upstreams) == 0 {
		return false, fmt.Errorf("FetchFromUpstream: zone %s has no upstreams configured", zd.ZoneName)
	}
	// Capture the prior status so a no-op (serial unchanged) or all-failed
	// refresh of an already-ready zone is restored to it, not left stuck in
	// `loading` until some later successful transfer flips it back.
	prevStatus := zd.GetStatus()
	zd.SetStatus(ZoneStatusLoading)

	// Iterate the resolved upstreams, advancing to the next on ANY failure —
	// a transport error, a REFUSED/NOTAUTH/SERVFAIL xfr rcode, or bad zone data.
	// allow-transfer ACLs commonly differ per primary, so one primary refusing
	// us says nothing about a sibling. A fresh new_zd per attempt keeps a failed
	// transfer from polluting the next try; the live zd.IncomingSerial is only
	// touched in the hard flip below, after a success.
	var new_zd ZoneData
	transferred := false
	var lastErr error
	for _, up := range zd.Upstreams {
		upstream := up.Addr
		lg.Info("transferring zone via AXFR", "zone", zd.ZoneName, "upstream", upstream)
		new_zd = ZoneData{
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
		if _, err := new_zd.ZoneTransferIn(up, zd.IncomingSerial, "axfr", conf); err != nil {
			lg.Warn("FetchFromUpstream: AXFR from upstream failed, trying next", "zone", zd.ZoneName, "upstream", upstream, "err", err)
			lastErr = err
			continue
		}
		transferred = true
		break
	}
	if !transferred {
		lg.Error("FetchFromUpstream: AXFR failed on all upstreams", "zone", zd.ZoneName, "count", len(zd.Upstreams), "err", lastErr)
		zd.SetStatus(prevStatus) // still serving prior data; failure surfaces as RefreshError
		return false, fmt.Errorf("AXFR of %s failed: tried all %d upstream(s): %w", zd.ZoneName, len(zd.Upstreams), lastErr)
	}

	if new_zd.IncomingSerial == zd.IncomingSerial {
		lg.Debug("FetchFromUpstream: upstream serial is unchanged", "zone", zd.ZoneName, "serial", zd.IncomingSerial)
		zd.SetStatus(prevStatus) // no-op refresh — nothing changed, restore prior status
		return false, nil
	}

	new_zd.Ready = true

	// Pre-refresh callbacks: analysis of old vs new zone data + modification of new_zd.
	for _, cb := range zd.OnZonePreRefresh {
		cb(zd, &new_zd)
	}

	// Publish replacement: working set from transferred data + dynamic RRs.
	zd.mu.Lock()
	firstLoad := zd.FirstZoneLoad
	if err := zd.applyRefreshReplacementLocked(&new_zd, dynamicRRs, firstLoad); err != nil {
		zd.mu.Unlock()
		lg.Error("failed to persist outgoing serial", "zone", zd.ZoneName, "err", err)
		return false, err
	}
	zd.mu.Unlock()

	// Post-refresh callbacks: queue sends and notifications that need the live zone pointer.
	for _, cb := range zd.OnZonePostRefresh {
		cb(zd)
	}

	if ConfLive().ServiceDebug {
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

// getOwnerFrom reads an owner from an ALREADY-PINNED snapshot. Response paths
// (QueryResponder, ZoneTransferOut) pin one snapshot at the top and read
// everything through the *From helpers, so every read in one response comes from
// the same serial — no intra-response tearing. snap==nil yields nil (the caller
// SERVFAILs / refuses).
func getOwnerFrom(snap *zoneSnapshot, qname string) *OwnerData {
	if snap == nil {
		return nil
	}
	return snap.Data[qname]
}

// getRRsetFrom reads one RRset from a pinned snapshot.
func getRRsetFrom(snap *zoneSnapshot, qname string, rrtype uint16) *core.RRset {
	owner := getOwnerFrom(snap, qname)
	if owner == nil {
		return nil
	}
	if rrset, ok := owner.RRtypes.Get(rrtype); ok {
		return &rrset
	}
	return nil
}

// nameExistsFrom reports whether qname exists in a pinned snapshot.
func nameExistsFrom(snap *zoneSnapshot, qname string) bool {
	if snap == nil {
		return false
	}
	_, ok := snap.Data[qname]
	return ok
}

func (zd *ZoneData) NameExists(qname string) bool {
	if zd.ZoneStore != MapZone {
		return false
	}
	return nameExistsFrom(zd.publishedSnapshot(), qname)
}

func (zd *ZoneData) GetOwner(qname string) (*OwnerData, error) {
	if !zd.Ready {
		return nil, fmt.Errorf("getOwner: zone %s: %w", zd.ZoneName, ErrZoneNotReady)
	}
	if zd.ZoneStore != MapZone {
		return nil, fmt.Errorf("getOwner: only supported for MapZone, not %s",
			ZoneStoreToString[zd.ZoneStore])
	}
	return getOwnerFrom(zd.publishedSnapshot(), qname), nil
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
	if zd.ZoneStore != MapZone {
		return nil, fmt.Errorf("getOwnerNames: only supported for MapZone, not %s",
			ZoneStoreToString[zd.ZoneStore])
	}
	snap := zd.publishedSnapshot()
	if snap == nil || len(snap.Data) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(snap.Data))
	for name := range snap.Data {
		names = append(names, name)
	}
	sort.Strings(names)
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

	// For all other cases (primary zones, ready zones, catalog zones), require real data.
	// GetSOA must never return (nil, nil): a nil SOA with no error is a landmine for
	// callers that read soa.* only in the err==nil branch (e.g. RefreshEngine). During a
	// concurrent reload the apex owner can be transiently absent — surface that as an
	// error, not a nil SOA.
	if snap := zd.publishedSnapshot(); snap != nil && snap.SOA != nil {
		return snap.SOA, nil
	}
	owner, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return nil, err
	}
	if owner == nil {
		return nil, fmt.Errorf("GetSOA: zone %s: apex owner not found", zd.ZoneName)
	}
	soaSet := owner.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soaSet.RRs) == 0 {
		return nil, fmt.Errorf("GetSOA: zone %s: no SOA record at apex", zd.ZoneName)
	}
	soa, ok := soaSet.RRs[0].(*dns.SOA)
	if !ok {
		return nil, fmt.Errorf("GetSOA: zone %s: apex SOA record is not a *dns.SOA (got %T)", zd.ZoneName, soaSet.RRs[0])
	}
	return soa, nil
}

func (zd *ZoneData) PrintOwners() {
	names, err := zd.GetOwnerNames()
	if err != nil {
		return
	}
	for _, key := range names {
		fmt.Printf("%s\n", key)
	}
}

func (zd *ZoneData) NotifyDownstreams() error {
	// zd.Logger.Printf("NotifyDownstreams: Zone %s has downstreams: %v", zd.ZoneName, zd.Downstreams)
	if zd == nil {
		lg.Error("NotifyDownstreams: zonedata is nil")
		return fmt.Errorf("zonedata is nil")
	}
	for _, d := range zd.Notify {

		// log.Printf("%s: Notifying downstream server %s about new SOA serial", zd.ZoneName, d.Addr)

		m := new(dns.Msg)
		m.SetNotify(zd.ZoneName)
		r, err := dns.Exchange(m, d.Addr)
		if err != nil {
			// well, we tried
			lg.Error("downstream NOTIFY failed", "downstream", d.Addr, "zone", zd.ZoneName, "err", err)
			continue
		}
		if r.Opcode != dns.OpcodeNotify {
			// well, we tried
			lg.Error("unexpected opcode from downstream on NOTIFY", "downstream", d.Addr, "zone", zd.ZoneName, "opcode", dns.OpcodeToString[r.Opcode])
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

// nextOutboundSerial returns the next SOA serial that should be advertised
// to downstreams given zd.CurrentSerial and the configured outbound_soa_serial
// mode:
//   - "" / "keep" / "persist": prev + 1 (legacy behaviour; "persist" only
//     differs in that the resulting serial is also written to OutgoingSerials)
//   - "unixtime": time.Now().Unix(), unless that would not advance the serial
//     (e.g. multiple bumps within the same wallclock second), in which case
//     fall back to prev + 1 to preserve monotonicity.
func nextOutboundSerial(zd *ZoneData) uint32 {
	mode := ""
	if zd.KeyDB != nil {
		mode = zd.KeyDB.OutboundSoaSerial
	}
	if mode == OutboundSoaSerialUnixtime {
		s := uint32(time.Now().Unix())
		if s > zd.CurrentSerial {
			return s
		}
	}
	return zd.CurrentSerial + 1
}

// BumpSerialOnly advances the SOA serial per the configured
// outbound_soa_serial mode and rewrites the apex SOA RR (and its
// RRSIG, when the zone is signed). Does not notify downstreams.
// Use when the caller will handle notification separately or when
// notification is not appropriate (e.g. inside a NOTIFY handler
// where triggering downstream NOTIFYs could cause side effects).
func (zd *ZoneData) BumpSerialOnly() (BumperResponse, error) {
	lg.Debug("BumpSerialOnly: bumping SOA serial", "zone", zd.ZoneName)
	return zd.publishSync()
}

func (zd *ZoneData) BumpSerial() (BumperResponse, error) {
	return zd.BumpSerialOnly()
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
	wantsSync := zd.Options[OptDelSyncParent] || zd.Options[OptDelSyncChild] || zd.Options[OptDelSyncProxy]

	// Dynamic parentsync=agent detection removed — handled by tdns-mp
	// MPPostRefresh (hsync_utils.go) and OnFirstLoad (start_agent.go).

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

	// delegation-sync-proxy: a tdns-agent acting as a SECONDARY for a zone
	// whose primary is DSYNC-unaware (BIND/Knot). The agent inspects incoming
	// transfers for CDS/CSYNC (and NS/glue/DNSKEY) changes and forwards
	// NOTIFY(CDS/CSYNC) — and, when the parent advertises UPDATE and the agent's
	// KEY is published at the apex, DNS UPDATEs — to the parent on the primary's
	// behalf. Valid only for agent + secondary zones; reject other combinations
	// so a misconfiguration is loud rather than silently inert.
	if zd.Options[OptDelSyncProxy] {
		if Globals.App.Type != AppTypeAgent || zd.ZoneType != Secondary {
			lg.Error("SetupZoneSync: delegation-sync-proxy is only valid for a tdns-agent secondary zone",
				"zone", zd.ZoneName, "app", Globals.App.Type, "zonetype", zd.ZoneType)
			zd.SetError(ConfigError, "delegation-sync-proxy is only valid for an agent secondary zone")
			return fmt.Errorf("delegation-sync-proxy on zone %s requires a tdns-agent secondary zone", zd.ZoneName)
		}
		lg.Info("SetupZoneSync: delegation-sync-proxy enabled (agent secondary)", "zone", zd.ZoneName)
		// Run the UPDATE-proxy precondition check (§10.8) off the refresh path,
		// via the DelegationSyncher: it does DSYNC discovery (network) and may
		// generate a SIG(0) key, so it must not run inline here. The check is a
		// no-op for the NOTIFY proxy, which needs no key.
		if delsyncq != nil {
			delsyncq <- DelegationSyncRequest{
				Command:  "PROXY-UPDATE-SETUP",
				ZoneName: zd.ZoneName,
				ZoneData: zd,
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

			// Use the shared FetchZoneDnskeysSql (ops_dnskey.go) so
			// the snapshot here exactly matches PublishDnskeyRRs's
			// served RRset. Centralizing the predicate prevents the
			// two from drifting apart again.
			rows, err := zd.KeyDB.Query(FetchZoneDnskeysSql, zd.ZoneName)
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
				if err := rows.Err(); err != nil {
					lg.Error("CollectDynamicRRs: DNSKEY row iteration failed", "zone", zd.ZoneName, "err", err)
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

	// 3. Preserve stored transport-signal owner RRsets across a refresh replace.
	// A refresh rebuilds the working set from the freshly transferred zone data,
	// which does not include server-synthesized _dns.<ns> signals; carry them
	// over so they survive until the transport postpass regenerates them. (The
	// synthesized-fallback map is carried separately in applyRefreshReplacementLocked.)
	if zd.Options[OptAddTransportSignal] {
		snap := zd.publishedSnapshot()
		if snap == nil {
			return dynamicRRs
		}
		for owner, od := range snap.Data {
			if od == nil || !strings.HasPrefix(owner, "_dns.") {
				continue
			}
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

	return dynamicRRs
}

// repopulateWorkingSetLocked merges dynamic RRsets into the working set.
// Caller must hold zd.mu and have initialized zd.workingSet.
func (zd *ZoneData) repopulateWorkingSetLocked(dynamicRRs []*core.RRset) {
	if len(dynamicRRs) == 0 {
		return
	}

	for _, rrset := range dynamicRRs {
		if rrset == nil || len(rrset.RRs) == 0 {
			continue
		}

		owner := zd.stagedOwner(rrset.Name)
		if owner == nil {
			if zd.ZoneStore != MapZone {
				lg.Error("RepopulateDynamicRRs: failed to get/create owner", "owner", rrset.Name, "zone", zd.ZoneName)
				continue
			}
			owner = zd.getOrCreateWorkingOwner(rrset.Name)
		}

		existing, exists := owner.RRtypes.Get(rrset.RRtype)
		if exists {
			// Get returns an RRset whose RRs slice shares the published
			// snapshot's backing array; copy it before appending so a
			// spare-capacity append cannot mutate the live snapshot.
			merged := append([]dns.RR(nil), existing.RRs...)
			for _, newRR := range rrset.RRs {
				present := false
				for _, oldRR := range merged {
					if dns.IsDuplicate(newRR, oldRR) {
						present = true
						break
					}
				}
				if !present {
					merged = append(merged, newRR)
				}
			}
			existing.RRs = merged
			if len(rrset.RRSIGs) > 0 {
				existing.RRSIGs = rrset.RRSIGs
			}
			zd.stageRRsetLocked(rrset.Name, existing)
		} else {
			zd.stageRRsetLocked(rrset.Name, cloneRRset(*rrset))
		}
	}

	lg.Info("RepopulateDynamicRRs: repopulated dynamic RRsets", "count", len(dynamicRRs), "zone", zd.ZoneName)

	apexCdsRRs := 0
	if owner := zd.stagedOwner(zd.ZoneName); owner != nil {
		if rs, ok := owner.RRtypes.Get(dns.TypeCDS); ok {
			apexCdsRRs = len(rs.RRs)
		}
	}
	lgRollover.Debug("post-refresh apex CDS observation",
		"zone", zd.ZoneName, "apex_cds_rrs", apexCdsRRs)
}

// RepopulateDynamicRRs repopulates dynamically generated RRsets and publishes.
func (zd *ZoneData) RepopulateDynamicRRs(dynamicRRs []*core.RRset) {
	if len(dynamicRRs) == 0 {
		return
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()
	zd.repopulateWorkingSetLocked(dynamicRRs)
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
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

	// Re-read and re-parse the dnssec: block from the config file so this zone
	// is re-applied against the CURRENT policy definitions — an edited policy is
	// picked up without a separate `config reload`. Cheap; a parse error keeps
	// the previous policies. Updates the server-wide policy structs, but only
	// this zone is re-applied here — other zones converge when reloaded.
	confMu.Lock()
	if err := Conf.reloadDnssecFromFile(); err != nil {
		lg.Error("ReloadZone: failed to re-parse dnssec config, keeping previous policies", "zone", zd.ZoneName, "err", err)
	} else {
		// Publish only on success — on a parse error the old policies are kept,
		// so a republish would just re-snapshot the same state (matches
		// ReloadConfig).
		Conf.publishRuntimeConfig()
	}
	confMu.Unlock()

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

	zd.InstallInitialSnapshot()
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
