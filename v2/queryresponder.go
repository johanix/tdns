/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

// QueryHandler consumes DnsQueryRequest messages from the DnsQueryQ channel
// and calls the provided handler function. This allows custom query handlers
// (like KDC for KMREQ queries) to process queries via channels.
// handlerFunc: Function that processes a DnsQueryRequest
func QueryHandler(ctx context.Context, conf *Config, handlerFunc func(context.Context, *DnsQueryRequest) error) error {
	dnsqueryq := conf.Internal.DnsQueryQ

	lgHandler.Info("DnsQueryHandler starting")
	lgHandler.Debug("DnsQueryHandler channel info", "capacity", cap(dnsqueryq))

	for {
		select {
		case <-ctx.Done():
			lgHandler.Info("DnsQueryHandler: context cancelled")
			return nil
		case dqr, ok := <-dnsqueryq:
			if !ok {
				lgHandler.Info("DnsQueryHandler: dnsqueryq closed")
				return nil
			}
			lgHandler.Debug("received query from channel", "qname", dqr.Qname, "qtype", dns.TypeToString[dqr.Qtype], "from", dqr.ResponseWriter.RemoteAddr())
			if err := handlerFunc(ctx, &dqr); err != nil {
				lgHandler.Error("error in query handler", "err", err)
			} else {
				lgHandler.Debug("query handler completed successfully")
			}
		}
	}
}

// Define sets of known types
var tdnsSpecialTypes = map[uint16]bool{
	core.TypeDSYNC:      true,
	core.TypeNOTIFY:     true,
	core.TypeMSIGNER:    true,
	core.TypeDELEG:      true,
	core.TypeHSYNC:      true,
	core.TypeHSYNC2:     true,
	core.TypeHSYNC3:     true,
	core.TypeHSYNCPARAM: true,
	core.TypeTSYNC:      true,
}

var standardDNSTypes = map[uint16]bool{
	dns.TypeSOA:        true,
	dns.TypeMX:         true,
	dns.TypeTLSA:       true,
	dns.TypeSRV:        true,
	dns.TypeA:          true,
	dns.TypeAAAA:       true,
	dns.TypeNS:         true,
	dns.TypeTXT:        true,
	dns.TypeZONEMD:     true,
	dns.TypeKEY:        true,
	dns.TypeURI:        true,
	dns.TypeSVCB:       true,
	dns.TypeNSEC:       true,
	dns.TypeNSEC3:      true,
	dns.TypeNSEC3PARAM: true,
	dns.TypeRRSIG:      true,
	dns.TypeDNSKEY:     true,
	dns.TypeCSYNC:      true,
	dns.TypeCDS:        true,
	dns.TypeCDNSKEY:    true,
}

// 0. Check for *any* existence of qname
// 1. [OK] For a qname below zone, first check if there is a delegation. If so--> send referral
// 2. If no delegation, check for exact match
// 3. [OK] If no exact match, check for CNAME match
// 4. If no CNAME match, check for wild card match
// 5. Give up.

// signedApexRRsets returns signed SOA/NS RRsets for the response path without mutating zone data.
func (zd *ZoneData) signedApexRRsets(apex *OwnerData, msgoptions *edns0.MsgOptions, kdb *KeyDB, dak *DnssecKeys) (soa, ns core.RRset, err error) {
	soa = apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	ns = apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
	if !msgoptions.DO {
		return soa, ns, nil
	}
	signFunc := func(rrset core.RRset, qname string) (core.RRset, error) {
		return zd.signRRsetForZone(rrset, qname, msgoptions, kdb, dak)
	}

	var errs []error
	signedSOA, err := signFunc(soa, zd.ZoneName)
	if err != nil {
		lgHandler.Error("failed to sign SOA RRset", "zone", zd.ZoneName, "err", err)
		errs = append(errs, err)
	} else {
		soa = signedSOA
	}
	signedNS, err := signFunc(ns, zd.ZoneName)
	if err != nil {
		lgHandler.Error("failed to sign NS RRset", "zone", zd.ZoneName, "err", err)
		errs = append(errs, err)
	} else {
		ns = signedNS
	}
	if len(errs) > 0 {
		return soa, ns, fmt.Errorf("failed to sign apex RRsets for zone %s: %v", zd.ZoneName, errs)
	}
	return soa, ns, nil
}

// ErrZoneUnsigned marks a must-be-signed zone (online- or inline-signing) whose
// published snapshot carries NO RRSIGs for a served, stored RRset — i.e. the
// zone is broken (e.g. SignZone failed / an unsigned zone was AXFR'd in). The
// query path turns this into SERVFAIL. Both alternatives are wrong: ephemeral-
// signing the answer at query time MASKS the failure (the zone looks healthy to
// DO queries while its stored/transferred zone is unsigned), and serving it
// unsigned is a silent downgrade. A broken zone must look broken. See
// docs/2026-07-14-snapshot-branch-signing-findings.md Finding 1 / Decision 1.
var ErrZoneUnsigned = fmt.Errorf("zone must be signed but has no stored signatures for the RRset")

// isSynthesizedDenial reports whether rrset is a query-time-synthesized denial-
// of-existence record — an NSEC built by addCDEResponse / addReferralNSEC. These
// are the ONLY RRsets legitimately signed ephemerally on the query path: they
// are constructed fresh per response and never stored, so they can't carry
// pre-computed RRSIGs. Every other RRset served through signRRsetForZone is
// stored zone data that must already carry its RRSIGs (a signed zone signs its
// data at SignZone time), so a missing RRSIG there means the zone is broken.
func isSynthesizedDenial(rrset core.RRset) bool {
	for _, rr := range rrset.RRs {
		if rr.Header().Rrtype == dns.TypeNSEC {
			return true
		}
	}
	return false
}

// signRRsetForZone returns the RRset ready for a DO response.
// It checks DNSSEC options and, for a must-be-signed zone, guarantees the served
// RRset is signed — or reports the zone broken.
// Parameters:
//   - rrset: The RRset to sign
//   - name: The owner name of the RRset
//   - msgoptions: EDNS0 message options (checked for DO bit)
//   - kdb: Key database for fetching DNSSEC keys
//   - dak: Optional pre-fetched active DNSSEC keys (if nil, will be fetched from kdb)
//
// Behaviour for a must-be-signed zone whose RRset has no stored RRSIGs: a
// synthesized denial NSEC is signed ephemerally (its only legitimate case);
// any other (stored) RRset yields ErrZoneUnsigned so the responder SERVFAILs.
//
// Returns the signed RRset and any error encountered.
func (zd *ZoneData) signRRsetForZone(rrset core.RRset, name string, msgoptions *edns0.MsgOptions, kdb *KeyDB, dak *DnssecKeys) (core.RRset, error) {
	if !msgoptions.DO {
		lgHandler.Debug("DNSSEC not requested, skipping signing", "name", name, "rrtype", dns.TypeToString[rrset.RRtype])
		return rrset, nil
	}
	// If the RRset is already signed (inline-signing, or online-signing RRSIGs
	// already stored in the snapshot at SignZone time), serve as-is.
	if len(rrset.RRSIGs) > 0 {
		return rrset, nil
	}
	if kdb == nil {
		lgHandler.Warn("no KeyDB available, cannot sign", "zone", zd.ZoneName, "name", name, "rrtype", dns.TypeToString[rrset.RRtype])
		return rrset, fmt.Errorf("no KeyDB available for zone %s", zd.ZoneName)
	}
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		// Zone is legitimately unsigned — serve unsigned.
		return rrset, nil
	}

	// The zone MUST be signed but this RRset has no stored RRSIGs. Only a
	// query-time-synthesized denial NSEC may be signed ephemerally here; any
	// stored RRset with no signatures means the zone is broken → SERVFAIL,
	// rather than ephemeral-signing (which masks the failure) or serving
	// unsigned (a silent downgrade).
	if !isSynthesizedDenial(rrset) {
		lgHandler.Error("must-be-signed zone has no stored signatures for RRset; serving SERVFAIL",
			"zone", zd.ZoneName, "name", name, "rrtype", dns.TypeToString[rrset.RRtype])
		return rrset, ErrZoneUnsigned
	}

	// Get active DNSSEC keys, using provided dak or fetching from kdb
	zoneDak := dak
	var err error
	if zoneDak == nil {
		zoneDak, err = kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			lgHandler.Error("failed to get DNSSEC keys", "zone", zd.ZoneName, "err", err)
			return rrset, err
		}
	}

	if zoneDak == nil || len(zoneDak.ZSKs) == 0 {
		// No active keys found - try to ensure they exist (promote published or generate new)
		lgHandler.Warn("no active ZSKs, attempting to ensure keys exist", "zone", zd.ZoneName)
		zoneDak, err = zd.EnsureActiveDnssecKeys(kdb, false)
		if err != nil {
			lgHandler.Error("failed to ensure active DNSSEC keys", "zone", zd.ZoneName, "err", err)
			return rrset, err
		}
		if zoneDak == nil || len(zoneDak.ZSKs) == 0 {
			lgHandler.Error("still no ZSKs available after EnsureActiveDnssecKeys", "zone", zd.ZoneName)
			return rrset, fmt.Errorf("no ZSKs available for zone %s", zd.ZoneName)
		}
	}
	lgHandler.Debug("signing RRset", "name", name, "rrtype", dns.TypeToString[rrset.RRtype], "zone", zd.ZoneName, "zskCount", len(zoneDak.ZSKs))
	_, err = zd.SignRRset(&rrset, name, zoneDak, false, nil)
	if err != nil {
		lgHandler.Error("error signing RRset", "name", name, "err", err)
		return rrset, err
	}
	lgHandler.Debug("successfully signed RRset", "name", name, "rrtype", dns.TypeToString[rrset.RRtype], "rrsigCount", len(rrset.RRSIGs))
	return rrset, nil
}

// handleDSQuery handles DS queries.
//
// Two cases need to be distinguished by the relationship between qname and
// the zone we matched on:
//
//  1. qname is a strict child of zd.ZoneName (e.g. zd is "dnslab.", qname is
//     "bravo.dnslab."). We ARE the parent. Serve the DS RRset directly from
//     our own zone tree at qname.
//
//  2. qname == zd.ZoneName (DS-at-our-apex query). We are the child. Walk
//     up via imr.ParentZone() to find a parent zone we host, and serve DS
//     from there. If we don't host the parent, return a SOA-only response
//     authoritative for our own zone with EDE/CDE for guidance.
//
// Pre-fix behavior was always case (2), which broke DS queries against the
// parent zone for any child name — the responder walked one zone too far up
// and failed to find DS data that was correctly present in the parent zone.
func (zd *ZoneData) handleDSQuery(m *dns.Msg, w dns.ResponseWriter, qname string, apex *OwnerData, snap *zoneSnapshot,
	msgoptions *edns0.MsgOptions, kdb *KeyDB, dak *DnssecKeys, imr *Imr,
	signFunc func(core.RRset, string) (core.RRset, error)) error {

	// Case 1: qname is a strict child of zd.ZoneName — we are the parent.
	if qname != zd.ZoneName && dns.IsSubDomain(zd.ZoneName, qname) {
		lgHandler.Debug("QueryResponder: DS query, serving from parent zone (this zone)",
			"qname", qname, "zone", zd.ZoneName)
		// Make sure apex RRsets are signed (SOA in authority for negative
		// answers; DNSKEY/etc as needed by signApexRRsets).
		soaRRset, _, err := zd.signedApexRRsets(apex, msgoptions, kdb, nil)
		if err != nil {
			lgHandler.Error("failed to sign parent apex RRsets for DS query", "err", err)
			if msgoptions.DO {
				m.MsgHdr.Rcode = dns.RcodeServerFailure
				w.WriteMsg(m)
				return fmt.Errorf("failed to sign parent apex RRsets for DS query: %v", err)
			}
		}
		m.MsgHdr.Rcode = dns.RcodeSuccess
		dsRRset := getRRsetFrom(snap, qname, dns.TypeDS)
		if dsRRset != nil && len(dsRRset.RRs) > 0 {
			signed, err := signFunc(*dsRRset, qname)
			if err != nil {
				lgHandler.Error("failed to sign DS RRset", "qname", qname, "err", err)
				if msgoptions.DO {
					m.MsgHdr.Rcode = dns.RcodeServerFailure
					w.WriteMsg(m)
					return fmt.Errorf("failed to sign DS RRset for %s: %v", qname, err)
				}
			} else {
				dsRRset = &signed
			}
			m.Answer = append(m.Answer, dsRRset.RRs...)
			if msgoptions.DO {
				m.Answer = append(m.Answer, dsRRset.RRSIGs...)
			}
		}
		m.Ns = append(m.Ns, soaRRset.RRs...)
		w.WriteMsg(m)
		return nil
	}

	// Case 2: qname == zd.ZoneName — DS-at-apex query. Walk up to find a
	// parent zone we host.
	lgHandler.Debug("QueryResponder: DS-at-apex query, looking up parent zone",
		"qname", qname, "zone", zd.ZoneName)
	parent, err := imr.ParentZone(zd.ZoneName)
	if err != nil {
		lgHandler.Error("failed to find parent zone for DS query", "qname", qname)
		m.MsgHdr.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return nil
	}
	pzd, ok := FindZone(parent)
	if !ok {
		// we don't have the parent zone
		m.MsgHdr.Rcode = dns.RcodeSuccess
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
		if msgoptions.DO {
			zd.addCDEResponse(m, qname, apex, nil, msgoptions, signFunc)
		}
		w.WriteMsg(m)
		return nil
	}
	// We have the parent zone; pin ITS snapshot and read the DS from that.
	zd = pzd
	snap = zd.publishedSnapshot()
	apex = getOwnerFrom(snap, zd.ZoneName)
	if apex == nil {
		lgHandler.Error("failed to get apex data for parent zone", "zone", zd.ZoneName)
		m.MsgHdr.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return nil
	}
	// Use parent zone's own keys; let signRRsetForZone fetch them via kdb.
	soaRRset, _, err := zd.signedApexRRsets(apex, msgoptions, kdb, nil)
	if err != nil {
		lgHandler.Error("failed to sign parent apex RRsets for DS query", "err", err)
		if msgoptions.DO {
			m.MsgHdr.Rcode = dns.RcodeServerFailure
			w.WriteMsg(m)
			return fmt.Errorf("failed to sign parent apex RRsets for DS query: %v", err)
		}
	}
	m.MsgHdr.Rcode = dns.RcodeSuccess
	dsRRset := getRRsetFrom(snap, qname, dns.TypeDS)
	if dsRRset != nil && len(dsRRset.RRs) > 0 {
		// Use parent zone's signing context (signFunc closes over the
		// original zd; route through signRRsetForZone on the parent we
		// just switched to).
		signed, err := zd.signRRsetForZone(*dsRRset, qname, msgoptions, kdb, nil)
		if err != nil {
			lgHandler.Error("failed to sign DS RRset", "qname", qname, "err", err)
			if msgoptions.DO {
				m.MsgHdr.Rcode = dns.RcodeServerFailure
				w.WriteMsg(m)
				return fmt.Errorf("failed to sign DS RRset for %s: %v", qname, err)
			}
		} else {
			dsRRset = &signed
		}
		m.Answer = append(m.Answer, dsRRset.RRs...)
		if msgoptions.DO {
			m.Answer = append(m.Answer, dsRRset.RRSIGs...)
		}
	}
	m.Ns = append(m.Ns, soaRRset.RRs...)
	w.WriteMsg(m)
	return nil
}

// sendReferral sends a referral response for a child delegation.
func (zd *ZoneData) sendReferral(m *dns.Msg, w dns.ResponseWriter, cdd *ChildDelegationData, apex *OwnerData,
	msgoptions *edns0.MsgOptions,
	signFunc func(core.RRset, string) (core.RRset, error)) {
	lgHandler.Debug("sending referral", "child", cdd.ChildName)
	m.MsgHdr.Authoritative = false
	m.Ns = append(m.Ns, cdd.NS_rrset.RRs...)
	m.Extra = append(m.Extra, cdd.A_glue...)
	m.Extra = append(m.Extra, cdd.AAAA_glue...)

	// RFC 9824, Section 3.4: Add NSEC for unsigned referrals
	if msgoptions.DO {
		addReferralNSEC(m, cdd, apex, zd.ZoneName, signFunc)
	}

	w.WriteMsg(m)
}

// sendNXDOMAIN sends an NXDOMAIN response with proper DNSSEC negative response if requested.
func (zd *ZoneData) sendNXDOMAIN(m *dns.Msg, w dns.ResponseWriter, qname string, apex *OwnerData, snap *zoneSnapshot,
	msgoptions *edns0.MsgOptions, signFunc func(core.RRset, string) (core.RRset, error)) {
	m.MsgHdr.Rcode = dns.RcodeNameError
	soaRRset := zd.soaForResponseFrom(snap, apex)
	m.Ns = append(m.Ns, soaRRset.RRs...)
	if msgoptions.DO {
		// RFC 9824: Compact denial if CO bit is set, otherwise traditional DNSSEC negative response
		zd.addCDEResponse(m, qname, apex, nil, msgoptions, signFunc)
	}
	w.WriteMsg(m)
}

// addNSAndGlue adds NS records and glue records (A/AAAA) to the message, along with DNSSEC signatures if requested.
// When minimalResponses is true, BIND-style minimal-responses semantics apply: the authority NS RRset and
// its associated additional-section glue (and their RRSIGs) are omitted from positive answers.
func (zd *ZoneData) addNSAndGlue(m *dns.Msg, apex *OwnerData, snap *zoneSnapshot, msgoptions *edns0.MsgOptions, minimalResponses bool) {
	if minimalResponses {
		return
	}
	m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
	v4glue, v6glue := zd.findGlueFrom(snap, apex.RRtypes.GetOnlyRRSet(dns.TypeNS), msgoptions.DO)
	m.Extra = append(m.Extra, v4glue.RRs...)
	m.Extra = append(m.Extra, v6glue.RRs...)
	if msgoptions.DO {
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
		m.Extra = append(m.Extra, v4glue.RRSIGs...)
		m.Extra = append(m.Extra, v6glue.RRSIGs...)
	}
}

// addTransportSignal opportunistically adds transport-signal RRs to the Extra
// section, skipping any (name,type) already present in the Answer (e.g. when the
// query was a direct lookup for the signal itself). RRSIGs of each injected
// RRset are added when DO is set. Returns true if anything was added.
func (zd *ZoneData) addTransportSignal(m *dns.Msg, sigs []core.RRset, msgoptions *edns0.MsgOptions) bool {
	if msgoptions.OtsOptOut || len(sigs) == 0 {
		return false
	}
	present := map[string]bool{}
	for _, arr := range m.Answer {
		h := arr.Header()
		present[h.Name+"|"+dns.TypeToString[h.Rrtype]] = true
	}
	addedAny := false
	for _, ts := range sigs {
		rrsAdded := false
		for _, trr := range ts.RRs {
			h := trr.Header()
			key := h.Name + "|" + dns.TypeToString[h.Rrtype]
			if present[key] {
				continue
			}
			present[key] = true // guard against duplicates across signal RRsets
			m.Extra = append(m.Extra, trr)
			rrsAdded = true
			addedAny = true
		}
		if rrsAdded && msgoptions.DO && len(ts.RRSIGs) > 0 {
			m.Extra = append(m.Extra, ts.RRSIGs...)
		}
	}
	return addedAny
}

// collectSignalRRsets resolves the transport-signal RRsets to advertise for this
// zone, at query time, from the pinned snapshot. It derives the signal owners
// from the apex NS RRset (the authoritative "which nameservers" source) and, for
// each, reads the stored, resigner-maintained SVCB/TSYNC RRset from its
// authoritative home — this zone's pinned snapshot when in-bailiwick, another
// co-hosted zone's snapshot via FindZone otherwise, or the synthesized fallback
// (Case A). AliasMode targets are chased the same way. A signal whose target
// cannot be resolved is still returned (the alias is authoritative and the
// resolver can chase it / may already hold the target); SVCB fails safe.
func (zd *ZoneData) collectSignalRRsets(snap *zoneSnapshot) []core.RRset {
	if snap == nil || snap.Apex == nil || !zd.Options[OptAddTransportSignal] {
		return nil
	}
	nsRRset := snap.Apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
	if len(nsRRset.RRs) == 0 {
		return nil
	}
	var out []core.RRset
	seen := map[string]bool{}
	var add func(name string, depth int)
	add = func(name string, depth int) {
		if depth > 3 {
			return
		}
		for _, rs := range zd.lookupSignalRRsets(snap, name) {
			if len(rs.RRs) == 0 {
				continue
			}
			key := fmt.Sprintf("%s|%d", name, rs.RRtype)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, rs)
			for _, tgt := range signalChaseTargets(rs) {
				add("_dns."+tgt, depth+1)
			}
		}
	}
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			add("_dns."+ns.Ns, 0)
		}
	}
	return out
}

// lookupSignalRRsets returns the SVCB/TSYNC RRsets stored at a transport-signal
// owner name, read from its authoritative home. In-bailiwick names read from the
// pinned snapshot (no intra-response tearing); out-of-bailiwick names read from
// another co-hosted zone's current snapshot; failing both, the per-snapshot
// synthesized fallback (Case A) is used.
func (zd *ZoneData) lookupSignalRRsets(snap *zoneSnapshot, name string) []core.RRset {
	if dns.IsSubDomain(zd.ZoneName, name) {
		return signalRRsetsFromOwner(getOwnerFrom(snap, name))
	}
	if tz, _ := FindZone(name); tz != nil {
		if tz == zd {
			return signalRRsetsFromOwner(getOwnerFrom(snap, name))
		}
		if rrs := signalRRsetsFromOwner(getOwnerFrom(tz.publishedSnapshot(), name)); len(rrs) > 0 {
			return rrs
		}
	}
	if rs, ok := snap.signalSynth[name]; ok && rs != nil {
		return []core.RRset{*rs}
	}
	return nil
}

// signalRRsetsFromOwner extracts the SVCB and TSYNC RRsets from an owner (if any).
func signalRRsetsFromOwner(od *OwnerData) []core.RRset {
	if od == nil {
		return nil
	}
	var out []core.RRset
	if rs, ok := od.RRtypes.Get(dns.TypeSVCB); ok && len(rs.RRs) > 0 {
		out = append(out, rs)
	}
	if rs, ok := od.RRtypes.Get(core.TypeTSYNC); ok && len(rs.RRs) > 0 {
		out = append(out, rs)
	}
	return out
}

// signalChaseTargets returns the alias/target hostnames referenced by a signal
// RRset (SVCB AliasMode Target, TSYNC Alias), for injection-time chasing.
func signalChaseTargets(rs core.RRset) []string {
	var out []string
	for _, rr := range rs.RRs {
		switch r := rr.(type) {
		case *dns.SVCB:
			if r.Target != "." && r.Target != "" {
				out = append(out, r.Target)
			}
		case *dns.PrivateRR:
			if ts, ok := r.Data.(*core.TSYNC); ok && ts != nil && ts.Alias != "" && ts.Alias != "." {
				out = append(out, ts.Alias)
			}
		}
	}
	return out
}

// handleSOAQuery handles SOA queries for the zone apex.
func (zd *ZoneData) handleSOAQuery(m *dns.Msg, w dns.ResponseWriter, apex *OwnerData, snap *zoneSnapshot, sigs []core.RRset,
	msgoptions *edns0.MsgOptions, minimalResponses bool) {
	soaRRset := zd.soaForResponseFrom(snap, apex)
	lgHandler.Debug("SOA RRset details", "zone", zd.ZoneName, "count", len(soaRRset.RRs), "rrset", soaRRset)

	m.Answer = append(m.Answer, soaRRset.RRs[0])
	if msgoptions.DO {
		lgHandler.Debug("DNSSEC requested, adding RRSIGs to SOA response")
		m.Answer = append(m.Answer, soaRRset.RRSIGs...)
		// Note: NS and glue RRSIGs are already added by addNSAndGlue
	}
	zd.addNSAndGlue(m, apex, snap, msgoptions, minimalResponses)
	zd.addTransportSignal(m, sigs, msgoptions)
}

// handleCNAMEChain handles CNAME responses, including following CNAME chains across zones.
// Returns true if a CNAME response was handled and the message should be sent, false otherwise.
func (zd *ZoneData) handleCNAMEChain(m *dns.Msg, w dns.ResponseWriter, qname string, qtype uint16, owner *OwnerData, snap *zoneSnapshot,
	msgoptions *edns0.MsgOptions, kdb *KeyDB, apex *OwnerData, minimalResponses bool) (bool, error) {

	if owner.RRtypes.Count() != 1 {
		return false, nil // Not a CNAME-only owner
	}

	v, ok := owner.RRtypes.Get(dns.TypeCNAME)
	if !ok {
		return false, nil // No CNAME found
	}

	if len(v.RRs) > 1 {
		// XXX: NSD will not even load a zone with multiple CNAMEs. Better to check during load...
		lgHandler.Warn("illegal content: multiple CNAME RRs", "zone", zd.ZoneName, "rrset", v)
	}

	// Add the first CNAME to the answer
	// Sign it first if DNSSEC is enabled
	if msgoptions.DO {
		rrset, err := zd.signRRsetForZone(v, qname, msgoptions, kdb, nil)
		if err != nil {
			lgHandler.Error("failed to sign initial CNAME RRset", "qname", qname, "err", err)
			// Still add the CNAME even if signing failed
			// m.Answer = append(m.Answer, v.RRs...)
			// DNSSEC requested but failed to sign, return NXDOMAIN
			m.MsgHdr.Rcode = dns.RcodeServerFailure
			w.WriteMsg(m)
			return false, fmt.Errorf("failed to sign initial CNAME RRset for qname %s: %v", qname, err)
		} else {
			m.Answer = append(m.Answer, rrset.RRs...)
			m.Answer = append(m.Answer, rrset.RRSIGs...)
		}
	} else {
		m.Answer = append(m.Answer, v.RRs...)
	}

	// Follow CNAME chain with max depth to prevent infinite loops
	currentName := qname
	currentOwner := owner
	maxDepth := 10
	depth := 0

	visited := make(map[string]bool)
	visited[qname] = true

	for depth < maxDepth {
		// Get the current CNAME target
		if currentOwner.RRtypes.Count() != 1 {
			break // Not a CNAME-only owner anymore
		}
		currentCNAME, ok := currentOwner.RRtypes.Get(dns.TypeCNAME)
		if !ok {
			break // No CNAME found
		}
		if len(currentCNAME.RRs) == 0 {
			break
		}
		tgt := currentCNAME.RRs[0].(*dns.CNAME).Target
		lgHandler.Debug("following CNAME chain", "depth", depth+1, "from", currentName, "to", tgt)

		if visited[tgt] {
			lgHandler.Warn("CNAME chain loop detected", "from", currentName, "to", tgt)
			break
		}
		visited[tgt] = true

		// Find which zone the target belongs to
		tgtZone, _ := FindZone(tgt)
		if tgtZone == nil {
			// Target is outside our authority - return CNAME only
			lgHandler.Debug("CNAME target outside our authority", "target", tgt)
			break
		}

		// Get owner data from the target zone (pin ITS snapshot).
		tgtOwner := getOwnerFrom(tgtZone.publishedSnapshot(), tgt)
		if tgtOwner == nil {
			lgHandler.Error("failed to get owner for CNAME target", "target", tgt, "zone", tgtZone.ZoneName)
			break
		}

		// Check if target has the requested qtype
		if tgtrrset, ok := tgtOwner.RRtypes.Get(qtype); ok {
			// Found final answer - add it to answer
			m.Answer = append(m.Answer, tgtrrset.RRs...)
			if msgoptions.DO {
				tgtRRset, err := tgtZone.signRRsetForZone(tgtrrset, tgt, msgoptions, kdb, nil)
				if err != nil {
					lgHandler.Error("failed to sign final answer RRset for CNAME target", "target", tgt, "err", err)
					m.MsgHdr.Rcode = dns.RcodeServerFailure
					w.WriteMsg(m)
					return false, fmt.Errorf("failed to sign final answer RRset for CNAME target %s: %v", tgt, err)
				} else {
					m.Answer = append(m.Answer, tgtRRset.RRSIGs...)
				}
			}
			break // Found final answer, stop following chain
		}

		// Check if target is another CNAME (continue chain)
		if tgtOwner.RRtypes.Count() == 1 {
			if nextCNAME, ok := tgtOwner.RRtypes.Get(dns.TypeCNAME); ok {
				// Add this CNAME to the answer and continue
				m.Answer = append(m.Answer, nextCNAME.RRs...)
				if msgoptions.DO {
					rrset, err := tgtZone.signRRsetForZone(nextCNAME, tgt, msgoptions, kdb, nil)
					if err != nil {
						lgHandler.Error("failed to sign intermediate CNAME RRset", "target", tgt, "err", err)
						m.MsgHdr.Rcode = dns.RcodeServerFailure
						w.WriteMsg(m)
						return false, fmt.Errorf("failed to sign intermediate CNAME RRset for %s: %v", tgt, err)
					} else {
						m.Answer = append(m.Answer, rrset.RRSIGs...)
					}
				}
				// Continue following the chain
				currentName = tgt
				currentOwner = tgtOwner
				depth++
				continue
			}
		}

		// Target exists but doesn't have qtype and isn't a CNAME - stop here
		break
	}

	if depth >= maxDepth {
		lgHandler.Warn("CNAME chain exceeded max depth", "maxDepth", maxDepth, "qname", qname)
	}

	// Add NS and glue records from the zone where we found the final answer (or last CNAME)
	// Use the original zone's apex for NS records
	zd.addNSAndGlue(m, apex, snap, msgoptions, minimalResponses)

	// Opportunistically attach transport signals, deduped against the Answer
	// section (addTransportSignal handles their RRSIGs when DO is set).
	zd.addTransportSignal(m, zd.collectSignalRRsets(snap), msgoptions)

	return true, nil
}

func (zd *ZoneData) QueryResponder(ctx context.Context, w dns.ResponseWriter, r *dns.Msg,
	qname string, qtype uint16, msgoptions *edns0.MsgOptions, kdb *KeyDB, imr *Imr) error {

	select {
	case <-ctx.Done():
		lgHandler.Info("QueryResponder: context cancelled")
		m := new(dns.Msg)
		m.SetReply(r)
		edns0.EnsureResponseOPT(m, r, dns.DefaultMsgSize)
		m.MsgHdr.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return ctx.Err()
	default:
	}
	// minimal-responses: BIND-style suppression of authority NS RRset and
	// apex glue on positive answers. Referrals and NXDOMAIN/NODATA paths are
	// unaffected (their authority/additional sections are still required).
	minimalResponses := false
	if kdb != nil {
		if v, ok := kdb.AuthOption(AuthOptMinimalResponses); ok && v == "true" {
			minimalResponses = true
		}
	}

	// Get DNSSEC keys if KeyDB is available and zone has DNSSEC enabled
	var dak *DnssecKeys
	var err error
	if kdb != nil {
		dak, err = kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			lgHandler.Error("failed to get DNSSEC key", "zone", zd.ZoneName, "err", err)
		}
	} else {
		// No KeyDB available (e.g., KDC catalog zone) - DNSSEC not supported
		if msgoptions.DO {
			lgHandler.Debug("DNSSEC requested but no KeyDB available, responding without DNSSEC", "zone", zd.ZoneName)
		}
	}

	// Wrapper function for addCDEResponse that uses the consolidated signRRsetForZone function
	MaybeSignRRset := func(rrset core.RRset, qname string) (core.RRset, error) {
		return zd.signRRsetForZone(rrset, qname, msgoptions, kdb, dak)
	}

	// log.Printf("QueryResponder: qname: %s qtype: %s", qname, dns.TypeToString[qtype])
	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true
	// RFC 6891 §6.1.1: an EDNS query MUST get an OPT in the response. Attach it
	// once here, up front, so every exit path below (positive answers,
	// referrals, NXDOMAIN/NODATA, DS, CNAME, SOA, REFUSED — all of which reuse
	// this m) carries it. No-op for non-EDNS queries. Later EDE/CDE error paths
	// find and reuse this OPT rather than adding a second one. Downstream UDP
	// truncation preserves the OPT and re-appends it after trimming.
	edns0.EnsureResponseOPT(m, r, dns.DefaultMsgSize)

	// Pin ONE snapshot for the whole response so the answer, authority SOA, NS,
	// and glue all come from the same serial — no intra-response tearing (C1).
	snap := zd.publishedSnapshot()
	if snap == nil {
		lgHandler.Error("no published snapshot; serving SERVFAIL", "zone", zd.ZoneName)
		m.MsgHdr.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return nil
	}
	apex := getOwnerFrom(snap, zd.ZoneName)
	if apex == nil {
		lgHandler.Error("missing apex in snapshot; serving SERVFAIL", "zone", zd.ZoneName)
		m.MsgHdr.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return nil
	}
	// Transport signals to advertise, resolved once from the pinned snapshot
	// (in-bailiwick + co-hosted + synthesized fallback, with alias chasing).
	sigs := zd.collectSignalRRsets(snap)

	// Inline-signed apex RRsets are served from the published zone; online/compact
	// signatures are added ephemerally on each response path below.

	// Reject explicit queries for NXNAME type (RFC 9824)
	// NXNAME is only used in NSEC type bitmaps, not as a query type
	if qtype == dns.TypeNXNAME {
		m.MsgHdr.Rcode = dns.RcodeFormatError
		edns0.AttachEDEToResponse(m, dns.ExtendedErrorCodeInvalidQueryType) // EDE code 30: "Invalid Query Type"
		w.WriteMsg(m)
		return nil
	}

	var wildqname string
	origqname := qname

	// 0. Is this a DS query? If so, trap it ASAP and try to find the parent zone
	if qtype == dns.TypeDS {
		return zd.handleDSQuery(m, w, qname, apex, snap, msgoptions, kdb, dak, imr, MaybeSignRRset)
	}

	// log.Printf("---> Checking for existence of qname %s", qname)
	if !nameExistsFrom(snap, qname) {
		lgHandler.Debug("no exact match for qname", "qname", qname, "zone", zd.ZoneName)

		// 1. Check for child delegation
		lgHandler.Debug("checking for child delegation", "qname", qname)
		cdd := zd.findDelegationFrom(snap, qname, msgoptions.DO)

		// If there is delegation data and an NS RRset is present, return a referral
		if cdd != nil && cdd.NS_rrset != nil && qtype != dns.TypeDS && qtype != core.TypeDELEG {
			zd.sendReferral(m, w, cdd, apex, msgoptions, MaybeSignRRset)
			return nil
		}

		wildqname = "*." + strings.Join(strings.Split(qname, ".")[1:], ".")
		// log.Printf("---> Checking for existence of wildcard %s", wildqname)

		if !nameExistsFrom(snap, wildqname) {
			// return NXDOMAIN
			zd.sendNXDOMAIN(m, w, qname, apex, snap, msgoptions, MaybeSignRRset)
			return nil
		}
		lgHandler.Debug("wildcard match", "qname", qname, "wildcard", wildqname, "zone", zd.ZoneName)
		origqname = qname
		qname = wildqname
	}

	owner := getOwnerFrom(snap, qname)
	if owner == nil {
		// NameExists (against this same snapshot) passed, so this shouldn't
		// happen; guard rather than panic on owner.RRtypes below.
		m.MsgHdr.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return nil
	}

	// 0. Check for *any* existence of qname in zone
	// log.Printf("---> Checking for any existence of qname %s", qname)
	if owner.RRtypes.Count() == 0 {
		soaRRset, err := MaybeSignRRset(zd.soaForResponseFrom(snap, apex), zd.ZoneName)
		if err != nil {
			lgHandler.Error("failed to sign SOA RRset", "zone", zd.ZoneName, "err", err)
			if msgoptions.DO {
				m.MsgHdr.Rcode = dns.RcodeServerFailure
				w.WriteMsg(m)
				return fmt.Errorf("failed to sign SOA RRset before NXDOMAIN: %v", err)
			}
		}
		m.Ns = append(m.Ns, soaRRset.RRs...)
		if msgoptions.DO {
			zd.addCDEResponse(m, origqname, apex, nil, msgoptions, MaybeSignRRset)
		}
		m.MsgHdr.Rcode = dns.RcodeNameError
		w.WriteMsg(m)
		return nil
	}

	if len(qname) > len(zd.ZoneName) {
		// 2. Check for qname + CNAME (only if CNAME is the only RR type)
		lgHandler.Debug("checking for CNAME", "qname", qname, "zone", zd.ZoneName)
		handled, err := zd.handleCNAMEChain(m, w, qname, qtype, owner, snap, msgoptions, kdb, apex, minimalResponses)
		if err != nil {
			lgHandler.Error("error handling CNAME chain", "err", err)
			// Error response already sent by handleCNAMEChain
			return nil
		}
		if handled {
			w.WriteMsg(m)
			return nil
		}

		// 1. If qname is below the zone apex, check for child delegation
		// log.Printf("---> Checking for child delegation for %s", qname)
		cdd := zd.findDelegationFrom(snap, qname, msgoptions.DO)

		// If there is delegation data and an NS RRset is present, return a referral
		if cdd != nil && cdd.NS_rrset != nil && qtype != dns.TypeDS && qtype != core.TypeDELEG {
			zd.sendReferral(m, w, cdd, apex, msgoptions, MaybeSignRRset)
			return nil
		}
	}

	// 2. Check for exact match qname+qtype
	lgHandler.Debug("checking for exact match", "qname", qname, "qtype", dns.TypeToString[qtype], "zone", zd.ZoneName)

	if tdnsSpecialTypes[qtype] || standardDNSTypes[qtype] {
		if rrset, ok := owner.RRtypes.Get(qtype); ok && len(rrset.RRs) > 0 {
			if qtype == dns.TypeSOA {
				rrset = zd.soaForResponseFrom(snap, apex)
			}
			if qname == origqname {
				// zd.Logger.Printf("Exact match qname %s %s", qname, dns.TypeToString[qtype])
				m.Answer = append(m.Answer, rrset.RRs...)
			} else {
				// zd.Logger.Printf("Wildcard match qname %s %s", qname, origqname)
				tmp := WildcardReplace(rrset.RRs, qname, origqname)
				m.Answer = append(m.Answer, tmp...)
			}
			zd.addNSAndGlue(m, apex, snap, msgoptions, minimalResponses)
			// Add transport signal RRs that aren't already present in the Answer section
			zd.addTransportSignal(m, sigs, msgoptions)
			if msgoptions.DO {
				lgHandler.Debug("considering signing", "qname", qname, "qtype", dns.TypeToString[qtype], "origqname", origqname)
				// Fail-closed for BOTH the exact-match answer and the wildcard-
				// synthesized answer: a must-be-signed zone whose stored answer
				// RRset carries no RRSIGs is broken → SERVFAIL. This check runs on
				// the stored RRset (owner = qname, which is the *.parent wildcard
				// name on the wildcard arm) before WildcardReplace. Previously only
				// the exact-match arm ran it; the wildcard arm (qname != origqname)
				// served the WildcardReplace'd answer straight from stored RRSIGs and
				// so emitted an UNSIGNED wildcard answer for a broken zone (there
				// were no RRSIGs to replace) — a silent downgrade. A genuinely signed
				// wildcard still carries stored RRSIGs and answers; an unsigned-by-
				// design zone serves unsigned as before. Ephemeral-signing the answer
				// is not an option: it would mask the broken zone. See Finding 1 /
				// Decision 1.
				signed, err := MaybeSignRRset(rrset, qname)
				if err != nil {
					lgHandler.Error("failed to sign answer RRset; serving SERVFAIL", "qname", qname, "qtype", dns.TypeToString[qtype], "origqname", origqname, "zone", zd.ZoneName, "err", err)
					servfail := new(dns.Msg)
					servfail.SetReply(r)
					servfail.MsgHdr.Authoritative = true
					edns0.EnsureResponseOPT(servfail, r, dns.DefaultMsgSize)
					servfail.MsgHdr.Rcode = dns.RcodeServerFailure
					w.WriteMsg(servfail)
					return nil
				}
				rrset = signed

				if qname == origqname {
					m.Answer = append(m.Answer, rrset.RRSIGs...)
				} else {
					tmp := WildcardReplace(rrset.RRSIGs, qname, origqname)
					m.Answer = append(m.Answer, tmp...)
				}
				// Note: NS and glue RRSIGs are already added by addNSAndGlue
			}
		} else {
			lgHandler.Debug("no exact match for qname+qtype", "qname", qname, "qtype", dns.TypeToString[qtype], "zone", zd.ZoneName)
			soaRRset := zd.soaForResponseFrom(snap, apex)
			m.Ns = append(m.Ns, soaRRset.RRs...)
			if msgoptions.DO {
				// RFC 9824: Compact denial if CO bit is set, otherwise traditional DNSSEC negative response
				rrtypeList := []uint16{}
				rrtypeList = append(rrtypeList, owner.RRtypes.Keys()...)
				zd.addCDEResponse(m, origqname, apex, rrtypeList, msgoptions, MaybeSignRRset)
			}
		}
		w.WriteMsg(m)
		return nil
	}

	lgHandler.Debug("checking for SOA query", "zone", zd.ZoneName)
	if qtype == dns.TypeSOA && qname == zd.ZoneName {
		zd.handleSOAQuery(m, w, apex, snap, sigs, msgoptions, minimalResponses)
		w.WriteMsg(m)
		return nil
	}

	// AXFR and IXFR are handled by the zone transfer code
	if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
		if qname == zd.ZoneName {
			lgHandler.Debug("serving zone transfer", "store", ZoneStoreToString[zd.ZoneStore], "qname", qname)
			zd.ZoneTransferOut(w, r)
			return nil
		} else {
			m.MsgHdr.Rcode = dns.RcodeNotAuth
			w.WriteMsg(m)
			return nil
		}
	}

	// Final catch everything we don't want to deal with.
	// minimal-responses is defined to affect positive answers only, so on
	// the REFUSED catch-all we keep the pre-existing behavior (always
	// include authority NS + glue) regardless of the option.
	m.MsgHdr.Rcode = dns.RcodeRefused
	zd.addNSAndGlue(m, apex, snap, msgoptions, false)
	w.WriteMsg(m)

	_ = origqname

	return nil
}

// addReferralNSEC adds an NSEC record to a referral response per RFC 9824, Section 3.4
// This NSEC covers the delegation point (zone cut) and indicates that qname doesn't exist in the current zone
func addReferralNSEC(m *dns.Msg, cdd *ChildDelegationData, apex *OwnerData, zoneName string, signFunc func(core.RRset, string) (core.RRset, error)) {
	var soaMinTTL uint32 = 3600
	if soaRR, ok := apex.RRtypes.Get(dns.TypeSOA); ok && len(soaRR.RRs) > 0 {
		if soa, ok := soaRR.RRs[0].(*dns.SOA); ok {
			soaMinTTL = soa.Minttl
		}
	}

	// Compute NextDomain: extract leftmost label, add "\000", then append rest
	// e.g., if ChildName is "child.parent.com.", NextDomain should be "child\000.parent.com."
	var nextDomain string
	if firstDot := strings.Index(cdd.ChildName, "."); firstDot > 0 {
		leftmostLabel := cdd.ChildName[:firstDot]
		rest := cdd.ChildName[firstDot:]
		nextDomain = leftmostLabel + "\000" + rest
	} else {
		// Fallback if no dot found (shouldn't happen for valid domain names)
		nextDomain = cdd.ChildName + "\000."
	}

	// Create NSEC record covering the delegation point (zone cut)
	// The NSEC indicates that the delegation point exists but has no DS records (unsigned referral)
	nsecRR := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   cdd.ChildName,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    soaMinTTL,
		},
		NextDomain: nextDomain,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG},
	}

	// Sign the NSEC record
	nsecRRset, err := signFunc(core.RRset{RRs: []dns.RR{nsecRR}}, zoneName)
	if err != nil {
		lgHandler.Error("failed to sign NSEC RRset for referral at zone cut", "child", cdd.ChildName, "err", err)
	} else {
		m.Ns = append(m.Ns, nsecRR)
		m.Ns = append(m.Ns, nsecRRset.RRSIGs...)
	}
}

// addCDEResponse adds a DNSSEC negative response to the message
// If CO bit is set, uses compact denial format (RFC 9824)
// Otherwise, uses traditional DNSSEC negative response format
// rrtypeList == nil means NXDOMAIN (name doesn't exist)
// rrtypeList != nil means NODATA (name exists but qtype doesn't)
func (zd *ZoneData) addCDEResponse(m *dns.Msg, qname string, apex *OwnerData, rrtypeList []uint16, msgoptions *edns0.MsgOptions, signFunc func(core.RRset, string) (core.RRset, error)) {
	var soaMinTTL uint32 = 3600

	if soaRR, ok := apex.RRtypes.Get(dns.TypeSOA); ok && len(soaRR.RRs) > 0 {
		if soa, ok := soaRR.RRs[0].(*dns.SOA); ok {
			soaMinTTL = soa.Minttl
			lgHandler.Debug("negative TTL from SOA", "zone", zd.ZoneName, "minTTL", soaMinTTL)
		}
	}

	// Handle Rcode based on CO bit and response type
	if msgoptions.CO {
		// Compact denial (RFC 9824): Rcode depends on response type
		// For NXDOMAIN: Rcode = NXDOMAIN (already set by caller)
		// For NODATA: Rcode = NOERROR
		if rrtypeList != nil {
			m.MsgHdr.Rcode = dns.RcodeSuccess
		}
		// For NXDOMAIN, Rcode is already RcodeNameError from caller
	} else {
		// Traditional DNSSEC: For synthetic NSEC (owner=qname), Rcode must be NOERROR
		// because the NSEC makes it appear the name exists
		// TODO: Implement proper traditional NSEC generation (covering qname and wildcard for NXDOMAIN)
		m.MsgHdr.Rcode = dns.RcodeSuccess
	}

	// Create NSEC record (common to both CO=1 and CO=0)
	nsecRR := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    soaMinTTL,
		},
		NextDomain: "\000." + qname,
		TypeBitMap: func() []uint16 {
			baseBitMap := []uint16{dns.TypeNSEC, dns.TypeRRSIG}
			if rrtypeList == nil {
				// NXDOMAIN: bitmap contains exactly RRSIG, NSEC, NXNAME
				return append(baseBitMap, dns.TypeNXNAME)
			}
			// NODATA: bitmap contains RRSIG, NSEC, and existing types (not qtype)
			allTypes := append(baseBitMap, rrtypeList...)
			sort.Slice(allTypes, func(i, j int) bool {
				return allTypes[i] < allTypes[j]
			})
			return allTypes
		}(),
	}
	m.Ns = append(m.Ns, nsecRR)
	m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs...)

	nsecRRset, err := signFunc(core.RRset{RRs: []dns.RR{nsecRR}}, zd.ZoneName)
	if err != nil {
		lgHandler.Error("failed to sign NSEC RRset for CDE response", "zone", zd.ZoneName, "err", err)
	}
	m.Ns = append(m.Ns, nsecRRset.RRSIGs...)
}
