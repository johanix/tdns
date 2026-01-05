/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v1.0/tdns/core"
	edns0 "github.com/johanix/tdns/v1.0/tdns/edns0"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

// Define sets of known types
var tdnsSpecialTypes = map[uint16]bool{
	core.TypeDSYNC:   true,
	core.TypeNOTIFY:  true,
	core.TypeMSIGNER: true,
	core.TypeDELEG:   true,
	core.TypeHSYNC:   true,
	core.TypeHSYNC2:  true,
	core.TypeTSYNC:   true,
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

// signApexRRsets signs the SOA and NS RRsets at the zone apex if DNSSEC is requested.
func (zd *ZoneData) signApexRRsets(apex *OwnerData, msgoptions *edns0.MsgOptions, kdb *KeyDB, dak *DnssecKeys) error {
	if !msgoptions.DO {
		return nil
	}
	signFunc := func(rrset core.RRset, qname string) (core.RRset, error) {
		return zd.signRRsetForZone(rrset, qname, msgoptions, kdb, dak)
	}

	var errs []error

	soaRRset, err := signFunc(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA), zd.ZoneName)
	if err != nil {
		log.Printf("QueryResponder: failed to sign SOA RRset for zone %s: %v", zd.ZoneName, err)
		errs = append(errs, err)
	} else {
		apex.RRtypes.Set(dns.TypeSOA, soaRRset)
	}
	nsRRset, err := signFunc(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), zd.ZoneName)
	if err != nil {
		log.Printf("QueryResponder: failed to sign NS RRset for zone %s: %v", zd.ZoneName, err)
		errs = append(errs, err)
	} else {
		apex.RRtypes.Set(dns.TypeNS, nsRRset)
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to sign apex RRsets for zone %s: %v", zd.ZoneName, errs)
	}
	return nil
}

// signRRsetForZone signs an RRset using a zone's DNSSEC keys.
// It checks DNSSEC options, fetches keys if needed, ensures keys exist, and signs the RRset.
// Parameters:
//   - rrset: The RRset to sign
//   - name: The owner name of the RRset
//   - zone: The zone data containing the zone configuration
//   - msgoptions: EDNS0 message options (checked for DO bit)
//   - kdb: Key database for fetching DNSSEC keys
//   - dak: Optional pre-fetched active DNSSEC keys (if nil, will be fetched from kdb)
//
// Returns the signed RRset and any error encountered.
func (zd *ZoneData) signRRsetForZone(rrset core.RRset, name string, msgoptions *edns0.MsgOptions, kdb *KeyDB, dak *DnssecKeys) (core.RRset, error) {
	if !msgoptions.DO {
		log.Printf("QueryResponder: DNSSEC not requested (DO=0), skipping signing for %s %s", name, dns.TypeToString[rrset.RRtype])
		return rrset, nil
	}
	if !zd.Options[OptOnlineSigning] {
		log.Printf("QueryResponder: online signing not enabled for zone %s, skipping signing for %s %s", zd.ZoneName, name, dns.TypeToString[rrset.RRtype])
		return rrset, fmt.Errorf("online signing not enabled for zone %s", zd.ZoneName)
	}
	if len(rrset.RRSIGs) > 0 {
		log.Printf("QueryResponder: RRset %s %s already has %d RRSIGs, skipping signing", name, dns.TypeToString[rrset.RRtype], len(rrset.RRSIGs))
		return rrset, nil
	}

	// Get active DNSSEC keys, using provided dak or fetching from kdb
	zoneDak := dak
	var err error
	if zoneDak == nil {
		zoneDak, err = kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			log.Printf("QueryResponder: failed to get dnssec keys for zone %s: %v", zd.ZoneName, err)
			return rrset, err
		}
	}

	if zoneDak == nil || len(zoneDak.ZSKs) == 0 {
		// No active keys found - try to ensure they exist (promote published or generate new)
		log.Printf("QueryResponder: no active ZSKs for zone %s, attempting to ensure keys exist", zd.ZoneName)
		zoneDak, err = zd.ensureActiveDnssecKeys(kdb)
		if err != nil {
			log.Printf("QueryResponder: failed to ensure active DNSSEC keys for zone %s: %v", zd.ZoneName, err)
			return rrset, err
		}
		if zoneDak == nil || len(zoneDak.ZSKs) == 0 {
			log.Printf("QueryResponder: still no ZSKs available for zone %s after ensureActiveDnssecKeys", zd.ZoneName)
			return rrset, fmt.Errorf("no ZSKs available for zone %s", zd.ZoneName)
		}
	}
	log.Printf("QueryResponder: signing %s %s using zone %s ZSKs (have %d ZSKs)", name, dns.TypeToString[rrset.RRtype], zd.ZoneName, len(zoneDak.ZSKs))
	_, err = zd.SignRRset(&rrset, name, zoneDak, false)
	if err != nil {
		log.Printf("QueryResponder: error signing %s: %v", name, err)
		return rrset, err
	}
	log.Printf("QueryResponder: successfully signed %s %s, now has %d RRSIGs", name, dns.TypeToString[rrset.RRtype], len(rrset.RRSIGs))
	return rrset, nil
}

// handleDSQuery handles DS queries by finding the parent zone and returning DS records.
func (zd *ZoneData) handleDSQuery(m *dns.Msg, w dns.ResponseWriter, qname string, apex *OwnerData,
	msgoptions *edns0.MsgOptions, kdb *KeyDB, dak *DnssecKeys, imr *Imr,
	signFunc func(core.RRset, string) (core.RRset, error)) error {
	zd.Logger.Printf("QueryResponder: DS query for %s. Trying to find parent zone.", qname)
	parent, err := imr.ParentZone(zd.ZoneName)
	if err != nil {
		log.Printf("QueryResponder: failed to find parent zone for %s to handle DS query", qname)
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
	// We have the parent zone, so let's try to find the DS record
	zd = pzd
	apex, err = zd.GetOwner(zd.ZoneName)
	if err != nil {
		log.Printf("QueryResponder: failed to get apex data for parent zone %s", zd.ZoneName)
	}
	// Use parent zone's own keys; let signRRsetForZone fetch them via kdb.
	if err := zd.signApexRRsets(apex, msgoptions, kdb, nil); err != nil { // force fetch parent zone's DNSSEC keys
		log.Printf("QueryResponder: failed to sign parent apex RRsets for DS query: %v", err)
		if msgoptions.DO {
			m.MsgHdr.Rcode = dns.RcodeServerFailure
			w.WriteMsg(m)
			return fmt.Errorf("failed to sign parent apex RRsets for DS query: %v", err)
		}
	}
	m.MsgHdr.Rcode = dns.RcodeSuccess
	dsRRset, err := zd.GetRRset(qname, dns.TypeDS)
	if err != nil {
		log.Printf("QueryResponder: failed to get DS record for %s", qname)
	}
	m.Answer = append(m.Answer, dsRRset.RRs...)
	if msgoptions.DO {
		m.Answer = append(m.Answer, dsRRset.RRSIGs...)
	}
	m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
	w.WriteMsg(m)
	return nil
}

// sendReferral sends a referral response for a child delegation.
func (zd *ZoneData) sendReferral(m *dns.Msg, w dns.ResponseWriter, cdd *ChildDelegationData, apex *OwnerData,
	msgoptions *edns0.MsgOptions,
	signFunc func(core.RRset, string) (core.RRset, error)) {
	log.Printf("---> Sending referral for %s", cdd.ChildName)
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
func (zd *ZoneData) sendNXDOMAIN(m *dns.Msg, w dns.ResponseWriter, qname string, apex *OwnerData,
	msgoptions *edns0.MsgOptions, signFunc func(core.RRset, string) (core.RRset, error)) {
	m.MsgHdr.Rcode = dns.RcodeNameError
	// ensure correct serial
	soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
	apex.RRtypes.Set(dns.TypeSOA, soaRRset)

	m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
	if msgoptions.DO {
		// RFC 9824: Compact denial if CO bit is set, otherwise traditional DNSSEC negative response
		zd.addCDEResponse(m, qname, apex, nil, msgoptions, signFunc)
	}
	w.WriteMsg(m)
}

// addNSAndGlue adds NS records and glue records (A/AAAA) to the message, along with DNSSEC signatures if requested.
func (zd *ZoneData) addNSAndGlue(m *dns.Msg, apex *OwnerData, msgoptions *edns0.MsgOptions) {
	m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
	v4glue, v6glue := zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), msgoptions.DO)
	m.Extra = append(m.Extra, v4glue.RRs...)
	m.Extra = append(m.Extra, v6glue.RRs...)
	if msgoptions.DO {
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
		m.Extra = append(m.Extra, v4glue.RRSIGs...)
		m.Extra = append(m.Extra, v6glue.RRSIGs...)
	}
}

// addTransportSignal adds transport signal RRs to the Extra section if not already present in Answer.
// Returns true if any transport signal was added.
func (zd *ZoneData) addTransportSignal(m *dns.Msg, msgoptions *edns0.MsgOptions, transportSignalInAnswer bool) bool {
	if !zd.AddTransportSignal || msgoptions.OtsOptOut || zd.TransportSignal == nil || len(zd.TransportSignal.RRs) == 0 {
		return false
	}
	if transportSignalInAnswer {
		return false
	}
	// Build a set of (name, type) present in Answer to avoid duplicates
	present := map[string]bool{}
	for _, arr := range m.Answer {
		h := arr.Header()
		present[h.Name+"|"+dns.TypeToString[h.Rrtype]] = true
	}
	addedAny := false
	for _, trr := range zd.TransportSignal.RRs {
		h := trr.Header()
		key := h.Name + "|" + dns.TypeToString[h.Rrtype]
		if !present[key] {
			m.Extra = append(m.Extra, trr)
			addedAny = true
		}
	}
	// If we added any TSYNC/SVCB above, consider adding their signatures too
	if addedAny && msgoptions.DO && len(zd.TransportSignal.RRSIGs) > 0 {
		m.Extra = append(m.Extra, zd.TransportSignal.RRSIGs...)
	}
	return addedAny
}

// handleSOAQuery handles SOA queries for the zone apex.
func (zd *ZoneData) handleSOAQuery(m *dns.Msg, w dns.ResponseWriter, apex *OwnerData,
	msgoptions *edns0.MsgOptions, transportSignalInAnswer *bool) {
	soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
	zd.Logger.Printf("There are %d SOA RRs in %s RRset: %v", len(soaRRset.RRs), zd.ZoneName, soaRRset)
	apex.RRtypes.Set(dns.TypeSOA, soaRRset)

	m.Answer = append(m.Answer, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs[0])
	if msgoptions.DO {
		log.Printf("ApexResponder: dnssec_ok is true, adding RRSIGs")
		m.Answer = append(m.Answer, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs...)
		// Note: NS and glue RRSIGs are already added by addNSAndGlue
	}
	zd.addNSAndGlue(m, apex, msgoptions)
	zd.addTransportSignal(m, msgoptions, *transportSignalInAnswer)
}

// handleCNAMEChain handles CNAME responses, including following CNAME chains across zones.
// Returns true if a CNAME response was handled and the message should be sent, false otherwise.
func (zd *ZoneData) handleCNAMEChain(m *dns.Msg, w dns.ResponseWriter, qname string, qtype uint16, owner *OwnerData,
	msgoptions *edns0.MsgOptions, kdb *KeyDB, apex *OwnerData, transportSignalInAnswer *bool) (bool, error) {

	if owner.RRtypes.Count() != 1 {
		return false, nil // Not a CNAME-only owner
	}

	v, ok := owner.RRtypes.Get(dns.TypeCNAME)
	if !ok {
		return false, nil // No CNAME found
	}

	if len(v.RRs) > 1 {
		// XXX: NSD will not even load a zone with multiple CNAMEs. Better to check during load...
		log.Printf("QueryResponder: Zone %s: Illegal content: multiple CNAME RRs: %v", zd.ZoneName, v)
	}

	// Add the first CNAME to the answer
	// Sign it first if DNSSEC is enabled
	if msgoptions.DO {
		rrset, err := zd.signRRsetForZone(v, qname, msgoptions, kdb, nil)
		if err != nil {
			log.Printf("QueryResponder: failed to sign initial CNAME RRset for qname %s: %v", qname, err)
			// Still add the CNAME even if signing failed
			// m.Answer = append(m.Answer, v.RRs...)
			// DNSSEC requested but failed to sign, return NXDOMAIN
			m.MsgHdr.Rcode = dns.RcodeServerFailure
			w.WriteMsg(m)
			return false, fmt.Errorf("failed to sign initial CNAME RRset for qname %s: %v", qname, err)
		} else {
			owner.RRtypes.Set(dns.TypeCNAME, rrset)
			m.Answer = append(m.Answer, v.RRs...)
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
		log.Printf("QueryResponder: CNAME chain depth %d: %s -> %s", depth+1, currentName, tgt)

		if visited[tgt] {
			log.Printf("QueryResponder: CNAME chain loop detected: %s -> %s", currentName, tgt)
			break
		}
		visited[tgt] = true

		// Find which zone the target belongs to
		tgtZone, _ := FindZone(tgt)
		if tgtZone == nil {
			// Target is outside our authority - return CNAME only
			log.Printf("QueryResponder: CNAME target %s is outside our authority", tgt)
			break
		}

		// Get owner data from the target zone
		tgtOwner, err := tgtZone.GetOwner(tgt)
		if err != nil || tgtOwner == nil {
			log.Printf("QueryResponder: failed to get owner for CNAME target %s in zone %s", tgt, tgtZone.ZoneName)
			break
		}

		// Check if target has the requested qtype
		if tgtrrset, ok := tgtOwner.RRtypes.Get(qtype); ok {
			// Found final answer - add it to answer
			m.Answer = append(m.Answer, tgtrrset.RRs...)
			if msgoptions.DO {
				tgtRRset, err := tgtZone.signRRsetForZone(tgtrrset, tgt, msgoptions, kdb, nil)
				if err != nil {
					log.Printf("QueryResponder: failed to sign final answer RRset for CNAME target %s: %v", tgt, err)
					m.MsgHdr.Rcode = dns.RcodeServerFailure
					w.WriteMsg(m)
					return false, fmt.Errorf("failed to sign final answer RRset for CNAME target %s: %v", tgt, err)
				} else {
					tgtOwner.RRtypes.Set(qtype, tgtRRset)
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
						log.Printf("QueryResponder: failed to sign intermediate CNAME RRset for %s: %v", tgt, err)
						m.MsgHdr.Rcode = dns.RcodeServerFailure
						w.WriteMsg(m)
						return false, fmt.Errorf("failed to sign intermediate CNAME RRset for %s: %v", tgt, err)
					} else {
						tgtOwner.RRtypes.Set(dns.TypeCNAME, rrset)
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
		log.Printf("QueryResponder: CNAME chain exceeded max depth (%d) for %s", maxDepth, qname)
	}

	// Add NS and glue records from the zone where we found the final answer (or last CNAME)
	// Use the original zone's apex for NS records
	zd.addNSAndGlue(m, apex, msgoptions)

	// Check for transport signal
	if zd.AddTransportSignal && zd.TransportSignal != nil {
		for _, arr := range m.Answer {
			if rrMatchesTransportSignal(arr, zd.TransportSignal) {
				*transportSignalInAnswer = true
				break
			}
		}
	}
	zd.addTransportSignal(m, msgoptions, *transportSignalInAnswer)
	if msgoptions.DO && zd.AddTransportSignal && !msgoptions.OtsOptOut && zd.TransportSignal != nil {
		if !*transportSignalInAnswer && len(zd.TransportSignal.RRSIGs) > 0 {
			m.Extra = append(m.Extra, zd.TransportSignal.RRSIGs...)
		}
	}

	return true, nil
}

func (zd *ZoneData) QueryResponder(ctx context.Context, w dns.ResponseWriter, r *dns.Msg,
	qname string, qtype uint16, msgoptions *edns0.MsgOptions, kdb *KeyDB, imr *Imr) error {

	select {
	case <-ctx.Done():
		log.Printf("QueryResponder: context cancelled")
		m := new(dns.Msg)
		m.SetReply(r)
		m.MsgHdr.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return ctx.Err()
	default:
	}
	// Track if the configured transport signal is already present in the Answer section
	transportSignalInAnswer := false

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		log.Printf("QueryResponder: failed to get dnssec key for zone %s", zd.ZoneName)
	}

	// Wrapper function for addCDEResponse that uses the consolidated signRRsetForZone function
	MaybeSignRRset := func(rrset core.RRset, qname string) (core.RRset, error) {
		return zd.signRRsetForZone(rrset, qname, msgoptions, kdb, dak)
	}

	// log.Printf("QueryResponder: qname: %s qtype: %s", qname, dns.TypeToString[qtype])
	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		log.Printf("QueryResponder: failed to get apex data for zone %s: %v", zd.ZoneName, err)
		m.MsgHdr.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return fmt.Errorf("failed to get apex data for zone %s: %v", zd.ZoneName, err)
	}

	if err := zd.signApexRRsets(apex, msgoptions, kdb, dak); err != nil {
		log.Printf("QueryResponder: failed to sign apex RRsets for zone %s: %v", zd.ZoneName, err)
		if msgoptions.DO {
			m.MsgHdr.Rcode = dns.RcodeServerFailure
			w.WriteMsg(m)
			return fmt.Errorf("failed to sign apex RRsets for zone %s: %v", zd.ZoneName, err)
		}
	}

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
		return zd.handleDSQuery(m, w, qname, apex, msgoptions, kdb, dak, imr, MaybeSignRRset)
	}

	// log.Printf("---> Checking for existence of qname %s", qname)
	if !zd.NameExists(qname) {
		log.Printf("---> No exact match for %s in zone %s", qname, zd.ZoneName)

		// 1. Check for child delegation
		log.Printf("---> Checking for child delegation for %s", qname)
		cdd := zd.FindDelegation(qname, msgoptions.DO)

		// If there is delegation data and an NS RRset is present, return a referral
		if cdd != nil && cdd.NS_rrset != nil && qtype != dns.TypeDS && qtype != core.TypeDELEG {
			zd.sendReferral(m, w, cdd, apex, msgoptions, MaybeSignRRset)
			return nil
		}

		wildqname = "*." + strings.Join(strings.Split(qname, ".")[1:], ".")
		// log.Printf("---> Checking for existence of wildcard %s", wildqname)

		if !zd.NameExists(wildqname) {
			// return NXDOMAIN
			zd.sendNXDOMAIN(m, w, qname, apex, msgoptions, MaybeSignRRset)
			return nil
		}
		log.Printf("---> Wildcard match for %s (matches %s) in zone %s", qname, wildqname, zd.ZoneName)
		origqname = qname
		qname = wildqname
	}

	owner, err := zd.GetOwner(qname)
	if err != nil {
		log.Printf("QueryResponder: failed to get owner for qname %s", qname)
	}

	// 0. Check for *any* existence of qname in zone
	// log.Printf("---> Checking for any existence of qname %s", qname)
	if owner.RRtypes.Count() == 0 {
		soaRRset, err := MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA), zd.ZoneName)
		if err != nil {
			log.Printf("QueryResponder: failed to sign SOA RRset for zone %s: %v", zd.ZoneName, err)
			if msgoptions.DO {
				m.MsgHdr.Rcode = dns.RcodeServerFailure
				w.WriteMsg(m)
				return fmt.Errorf("failed to sign SOA RRset before NXDOMAIN: %v", err)
			}
		} else {
			apex.RRtypes.Set(dns.TypeSOA, soaRRset)
		}
		zd.sendNXDOMAIN(m, w, origqname, apex, msgoptions, MaybeSignRRset)
		return nil
	}

	if len(qname) > len(zd.ZoneName) {
		// 2. Check for qname + CNAME (only if CNAME is the only RR type)
		log.Printf("---> Checking for qname + CNAME %s in zone %s", qname, zd.ZoneName)
		handled, err := zd.handleCNAMEChain(m, w, qname, qtype, owner, msgoptions, kdb, apex, &transportSignalInAnswer)
		if err != nil {
			log.Printf("QueryResponder: error handling CNAME chain: %v", err)
			// Error response already sent by handleCNAMEChain
			return nil
		}
		if handled {
			w.WriteMsg(m)
			return nil
		}

		// 1. If qname is below the zone apex, check for child delegation
		// log.Printf("---> Checking for child delegation for %s", qname)
		cdd := zd.FindDelegation(qname, msgoptions.DO)

		// If there is delegation data and an NS RRset is present, return a referral
		if cdd != nil && cdd.NS_rrset != nil && qtype != dns.TypeDS && qtype != core.TypeDELEG {
			zd.sendReferral(m, w, cdd, apex, msgoptions, MaybeSignRRset)
			return nil
		}
	}

	// 2. Check for exact match qname+qtype
	log.Printf("---> Checking for exact match qname+qtype %s %s in zone %s", qname, dns.TypeToString[qtype], zd.ZoneName)

	if tdnsSpecialTypes[qtype] || standardDNSTypes[qtype] {
		if rrset, ok := owner.RRtypes.Get(qtype); ok && len(rrset.RRs) > 0 {
			if qtype == dns.TypeSOA {
				soaRR := rrset.RRs[0].(*dns.SOA)
				soaRR.Serial = zd.CurrentSerial
				owner.RRtypes.Set(qtype, core.RRset{RRs: []dns.RR{soaRR}})
				rrset.RRs[0] = soaRR
			}
			if qname == origqname {
				// zd.Logger.Printf("Exact match qname %s %s", qname, dns.TypeToString[qtype])
				m.Answer = append(m.Answer, rrset.RRs...)
				if zd.AddTransportSignal && zd.TransportSignal != nil && qtype == zd.TransportSignal.RRtype && (qname == zd.TransportSignal.Name || origqname == zd.TransportSignal.Name) {
					transportSignalInAnswer = true
				}
			} else {
				// zd.Logger.Printf("Wildcard match qname %s %s", qname, origqname)
				tmp := WildcardReplace(rrset.RRs, qname, origqname)
				m.Answer = append(m.Answer, tmp...)
				if zd.AddTransportSignal && zd.TransportSignal != nil && qtype == zd.TransportSignal.RRtype && (qname == zd.TransportSignal.Name || origqname == zd.TransportSignal.Name) {
					transportSignalInAnswer = true
				}
			}
			zd.addNSAndGlue(m, apex, msgoptions)
			// Add transport signal RRs that aren't already present in the Answer section
			zd.addTransportSignal(m, msgoptions, transportSignalInAnswer)
			if msgoptions.DO {
				log.Printf("Should we sign qname %s %s (origqname: %s)?", qname, dns.TypeToString[qtype], origqname)
				if qname == origqname {
					signed, err := MaybeSignRRset(rrset, qname)
					if err != nil {
						log.Printf("QueryResponder: failed to sign RRset for qname %s: %v", qname, err)
					}
					owner.RRtypes.Set(qtype, signed)
					rrset = signed
				}

				if qname == origqname {
					m.Answer = append(m.Answer, rrset.RRSIGs...)
				} else {
					tmp := WildcardReplace(rrset.RRSIGs, qname, origqname)
					m.Answer = append(m.Answer, tmp...)
				}
				// Note: NS and glue RRSIGs are already added by addNSAndGlue
			}
		} else {
			log.Printf("---> No exact match qname+qtype %s %s in zone %s", qname, dns.TypeToString[qtype], zd.ZoneName)
			// ensure correct serial
			soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
			soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
			apex.RRtypes.Set(dns.TypeSOA, soaRRset)
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
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

	log.Printf("---> Checking for SOA query for zone %s", zd.ZoneName)
	if qtype == dns.TypeSOA && qname == zd.ZoneName {
		zd.handleSOAQuery(m, w, apex, msgoptions, &transportSignalInAnswer)
		w.WriteMsg(m)
		return nil
	}

	// AXFR and IXFR are handled by the zone transfer code
	if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
		if qname == zd.ZoneName {
			log.Printf("We have the %s %s, so let's try to serve it", ZoneStoreToString[zd.ZoneStore], qname)
			zd.ZoneTransferOut(w, r)
			return nil
		} else {
			m.MsgHdr.Rcode = dns.RcodeNotAuth
			w.WriteMsg(m)
			return nil
		}
	}

	// Final catch everything we don't want to deal with
	m.MsgHdr.Rcode = dns.RcodeRefused
	zd.addNSAndGlue(m, apex, msgoptions)
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
	nextDomain := cdd.ChildName
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
		log.Printf("addReferralNSEC: failed to sign NSEC RRset for referral at zone cut %s: %v", cdd.ChildName, err)
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
			log.Printf("Negative TTL for zone %s: %d", zd.ZoneName, soaMinTTL)
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
		log.Printf("addCDEResponse: failed to sign NSEC RRset for zone %s: %v", zd.ZoneName, err)
	}
	m.Ns = append(m.Ns, nsecRRset.RRSIGs...)
}

// rrMatchesTransportSignal checks whether a given RR matches the configured transport signal RRset
func rrMatchesTransportSignal(rr dns.RR, ts *core.RRset) bool {
	if ts == nil || rr == nil {
		return false
	}
	h := rr.Header()
	return h.Rrtype == ts.RRtype && h.Name == ts.Name
}

// findServerTSYNCRRset returns a TSYNC RRset from any owner under this zone that starts with _dns.
func (zd *ZoneData) XXfindServerTSYNCRRset() *core.RRset {
	// Look for any TSYNC RRset at owners beginning with _dns.
	for item := range zd.Data.IterBuffered() {
		owner := item.Key
		od := item.Val
		if strings.HasPrefix(owner, "_dns.") {
			rrset := od.RRtypes.GetOnlyRRSet(core.TypeTSYNC)
			if len(rrset.RRs) > 0 {
				return &rrset
			}
		}
	}
	return nil
}
