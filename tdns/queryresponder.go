/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"log"
	"sort"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

// Define sets of known types
var tdnsSpecialTypes = map[uint16]bool{
	TypeDSYNC:   true,
	TypeNOTIFY:  true,
	TypeMSIGNER: true,
	TypeDELEG:   true,
	TypeHSYNC:   true,
	TypeHSYNC2:  true,
	TypeTSYNC:   true,
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

func (zd *ZoneData) QueryResponder(w dns.ResponseWriter, r *dns.Msg,
	qname string, qtype uint16, msgoptions MsgOptions, kdb *KeyDB) error {

	// Track if the configured transport signal is already present in the Answer section
	transportSignalInAnswer := false

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		log.Printf("QueryResponder: failed to get dnssec key for zone %s", zd.ZoneName)
	}

	MaybeSignRRset := func(rrset RRset, qname string) RRset {
		if dak == nil {
			log.Printf("QueryResponder: MaybeSignRRset: Warning: dak is nil")
			return rrset
		}
		if zd.Options[OptOnlineSigning] && len(dak.ZSKs) > 0 && len(rrset.RRSIGs) == 0 {
			log.Printf("QueryResponder: MaybeSignRRset: have ZSKs, no prior RRSIGs. Signing %s %s", qname, dns.TypeToString[rrset.RRtype])
			_, err := zd.SignRRset(&rrset, qname, dak, false)
			if err != nil {
				log.Printf("Error signing %s: %v", qname, err)
			} else {
				log.Printf("Signed %s: %v", qname, err)
			}
		}
		return rrset
	}

	// AddCDEResponse adds a compact-denial-of-existence response to the message
	AddCDEResponse := func(m *dns.Msg, qname string, apex *OwnerData, rrtypeList []uint16) {
		m.MsgHdr.Rcode = dns.RcodeSuccess

		var soaMinTTL uint32 = 3600

		if soaRR, ok := apex.RRtypes.Get(dns.TypeSOA); ok && len(soaRR.RRs) > 0 {
			if soa, ok := soaRR.RRs[0].(*dns.SOA); ok {
				soaMinTTL = soa.Minttl
				log.Printf("Negative TTL for zone %s: %d", zd.ZoneName, soaMinTTL)
			}
		}

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
					return append(baseBitMap, dns.TypeNXNAME)
				}
				allTypes := append(baseBitMap, rrtypeList...)
				sort.Slice(allTypes, func(i, j int) bool {
					return allTypes[i] < allTypes[j]
				})
				return allTypes
			}(),
		}
		m.Ns = append(m.Ns, nsecRR)
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs...)

		nsecRRset := MaybeSignRRset(RRset{RRs: []dns.RR{nsecRR}}, zd.ZoneName)
		m.Ns = append(m.Ns, nsecRRset.RRSIGs...)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		log.Fatalf("QueryResponder: failed to get apex data for zone %s", zd.ZoneName)
	}

	if msgoptions.DnssecOK {
		apex.RRtypes.Set(dns.TypeSOA, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA), zd.ZoneName))
		apex.RRtypes.Set(dns.TypeNS, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), zd.ZoneName))
	}

	// log.Printf("QueryResponder: qname: %s qtype: %s", qname, dns.TypeToString[qtype])
	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	var v4glue, v6glue *RRset
	var wildqname string
	origqname := qname

	// 0. Is this a DS query? If so, trap it ASAP and try to find the parent zone
	if qtype == dns.TypeDS {
		zd.Logger.Printf("QueryResponder: DS query for %s. Trying to find parent zone.", qname)
		SetupIMR()
		m := new(dns.Msg)
		m.SetReply(r)
		parent, err := ParentZone(zd.ZoneName, Globals.IMR)
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
			w.WriteMsg(m)
			return nil
		}
		// We have the parent zone, so let's try to find the DS record
		zd = pzd
		apex, err = zd.GetOwner(zd.ZoneName)
		if err != nil {
			log.Printf("QueryResponder: failed to get apex data for parent zone %s", zd.ZoneName)
		}
		if msgoptions.DnssecOK {
			apex.RRtypes.Set(dns.TypeSOA, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA), zd.ZoneName))
			apex.RRtypes.Set(dns.TypeNS, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), zd.ZoneName))
		}
		m.MsgHdr.Rcode = dns.RcodeSuccess
		dsRRset, err := zd.GetRRset(qname, dns.TypeDS)
		if err != nil {
			log.Printf("QueryResponder: failed to get DS record for %s", qname)
		}
		m.Answer = append(m.Answer, dsRRset.RRs...)
		if msgoptions.DnssecOK {
			m.Answer = append(m.Answer, dsRRset.RRSIGs...)
		}
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
		w.WriteMsg(m)
		return nil
	}

	// log.Printf("---> Checking for existence of qname %s", qname)
	if !zd.NameExists(qname) {
		log.Printf("---> No exact match for %s in zone %s", qname, zd.ZoneName)

		// 1. Check for child delegation
		log.Printf("---> Checking for child delegation for %s", qname)
		cdd := zd.FindDelegation(qname, msgoptions.DnssecOK)

		// If there is delegation data and an NS RRset is present, return a referral
		if cdd != nil && cdd.NS_rrset != nil && qtype != dns.TypeDS && qtype != TypeDELEG {
			log.Printf("---> Sending referral for %s", qname)
			m.MsgHdr.Authoritative = false
			m.Ns = append(m.Ns, cdd.NS_rrset.RRs...)
			m.Extra = append(m.Extra, cdd.A_glue...)
			m.Extra = append(m.Extra, cdd.AAAA_glue...)
			w.WriteMsg(m)
			return nil
		}

		wildqname = "*." + strings.Join(strings.Split(qname, ".")[1:], ".")
		// log.Printf("---> Checking for existence of wildcard %s", wildqname)

		if !zd.NameExists(wildqname) {
			// return NXDOMAIN
			m.MsgHdr.Rcode = dns.RcodeNameError
			// ensure correct serial
			soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
			soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
			apex.RRtypes.Set(dns.TypeSOA, soaRRset)

			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
			if msgoptions.DnssecOK {
				AddCDEResponse(m, qname, apex, nil)
			}
			// log.Printf("QR: qname %s does not exist in zone %s. Returning NXDOMAIN", qname, zd.ZoneName)
			w.WriteMsg(m)
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
		m.MsgHdr.Rcode = dns.RcodeNameError
		// ensure correct serial
		apex.RRtypes.Set(dns.TypeSOA, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA), zd.ZoneName))
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
		if msgoptions.DnssecOK {
			AddCDEResponse(m, origqname, apex, nil)
		}
		w.WriteMsg(m)
		return nil
	}

	if len(qname) > len(zd.ZoneName) {
		// 2. Check for qname + CNAME
		log.Printf("---> Checking for qname + CNAME %s in zone %s", qname, zd.ZoneName)
		if owner.RRtypes.Count() == 1 {
			for _, k := range owner.RRtypes.Keys() {
				v := owner.RRtypes.GetOnlyRRSet(k)
				if k == dns.TypeCNAME {
					if len(v.RRs) > 1 {
						// XXX: NSD will not even load a zone with multiple CNAMEs. Better to check during load...
						log.Printf("QueryResponder: Zone %s: Illegal content: multiple CNAME RRs: %v", zd.ZoneName, v)
					}
					m.Answer = append(m.Answer, v.RRs...)
					if msgoptions.DnssecOK {
						owner.RRtypes.Set(k, MaybeSignRRset(v, qname))
						m.Answer = append(m.Answer, v.RRSIGs...)
					}
					tgt := v.RRs[0].(*dns.CNAME).Target
					if strings.HasSuffix(tgt, zd.ZoneName) {
						tgtowner, _ := zd.GetOwner(tgt)
						if tgtrrset, ok := tgtowner.RRtypes.Get(qtype); ok {
							m.Answer = append(m.Answer, tgtrrset.RRs...)
							// XXX: This is not correct. We need to check if the CNAME target is a transport signal RR.
							// if zd.AddTransportSignal && zd.TransportSignal != nil && rrMatchesTransportSignal(v.RRs[0], zd.TransportSignal) {
							//	transportSignalInAnswer = true
							//}
							if zd.AddTransportSignal && zd.TransportSignal != nil {
							   for _, arr := range m.Answer {
							       if rrMatchesTransportSignal(arr, zd.TransportSignal) {
							           transportSignalInAnswer = true
							           break
							       }
							   }
							}
							m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
							v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), msgoptions.DnssecOK)
							m.Extra = append(m.Extra, v4glue.RRs...)
							m.Extra = append(m.Extra, v6glue.RRs...)
							if !msgoptions.OtsOptOut && zd.TransportSignal != nil && len(zd.TransportSignal.RRs) > 0 {
								if !transportSignalInAnswer {
									m.Extra = append(m.Extra, zd.TransportSignal.RRs...)
								}
							}
							
							if msgoptions.DnssecOK {
								tgtowner.RRtypes.Set(qtype, MaybeSignRRset(tgtowner.RRtypes.GetOnlyRRSet(qtype), qname))
								m.Answer = append(m.Answer, tgtowner.RRtypes.GetOnlyRRSet(qtype).RRSIGs...)

								m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)

								m.Extra = append(m.Extra, v4glue.RRSIGs...)
								m.Extra = append(m.Extra, v6glue.RRSIGs...)
								if !msgoptions.OtsOptOut && zd.TransportSignal != nil && len(zd.TransportSignal.RRSIGs) > 0 {
									if !transportSignalInAnswer {
										m.Extra = append(m.Extra, zd.TransportSignal.RRSIGs...)
									}
								}
							}
						}
						w.WriteMsg(m)
						return nil
					}
				}
			}
		}

		// 1. If qname is below the zone apex, check for child delegation
		// log.Printf("---> Checking for child delegation for %s", qname)
		cdd := zd.FindDelegation(qname, msgoptions.DnssecOK)

		// If there is delegation data and an NS RRset is present, return a referral
		if cdd != nil && cdd.NS_rrset != nil && qtype != dns.TypeDS && qtype != TypeDELEG {
			log.Printf("---> Sending referral for %s", qname)
			m.MsgHdr.Authoritative = false
			m.Ns = append(m.Ns, cdd.NS_rrset.RRs...)
			m.Extra = append(m.Extra, cdd.A_glue...)
			m.Extra = append(m.Extra, cdd.AAAA_glue...)
			w.WriteMsg(m)
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
				owner.RRtypes.Set(qtype, RRset{RRs: []dns.RR{soaRR}})
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
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
			v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), msgoptions.DnssecOK)
			m.Extra = append(m.Extra, v4glue.RRs...)
			m.Extra = append(m.Extra, v6glue.RRs...)
			// Add transport signal RRs that aren't already present in the Answer section
			if zd.AddTransportSignal && !msgoptions.OtsOptOut && zd.TransportSignal != nil && len(zd.TransportSignal.RRs) > 0 {
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
				if addedAny && msgoptions.DnssecOK && len(zd.TransportSignal.RRSIGs) > 0 {
					m.Extra = append(m.Extra, zd.TransportSignal.RRSIGs...)
				}
			}
			if msgoptions.DnssecOK {
				log.Printf("Should we sign qname %s %s (origqname: %s)?", qname, dns.TypeToString[qtype], origqname)
				// if zd.Options[OptOnlineSigning] && dak != nil && len(dak.ZSKs) > 0 {
					if qname == origqname {
						owner.RRtypes.Set(qtype, MaybeSignRRset(rrset, qname))
					}
				// }

				if qname == origqname {
					m.Answer = append(m.Answer, rrset.RRSIGs...)
				} else {
					tmp := WildcardReplace(rrset.RRSIGs, qname, origqname)
					m.Answer = append(m.Answer, tmp...)
				}
				m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
				m.Extra = append(m.Extra, v4glue.RRSIGs...)
				m.Extra = append(m.Extra, v6glue.RRSIGs...)
				if zd.AddTransportSignal && !msgoptions.OtsOptOut && zd.TransportSignal != nil {
					// RRSIGs for any transport signal RRs we appended above are already covered
					// by the DNSSEC block above. Nothing more to do here.
				}
				// TSYNC has no signatures to add
			}
		} else {
			log.Printf("---> No exact match qname+qtype %s %s in zone %s", qname, dns.TypeToString[qtype], zd.ZoneName)
			// ensure correct serial
			soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
			soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
			apex.RRtypes.Set(dns.TypeSOA, soaRRset)
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
			if msgoptions.DnssecOK {
				rrtypeList := []uint16{}
				rrtypeList = append(rrtypeList, owner.RRtypes.Keys()...)

				AddCDEResponse(m, origqname, apex, rrtypeList)
			}
		}
		w.WriteMsg(m)
		return nil
	}

	log.Printf("---> Checking for SOA query for zone %s", zd.ZoneName)
	if qtype == dns.TypeSOA && qname == zd.ZoneName {
		soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
		zd.Logger.Printf("There are %d SOA RRs in %s RRset: %v", len(soaRRset.RRs),
			zd.ZoneName, soaRRset)
		apex.RRtypes.Set(dns.TypeSOA, soaRRset)

		m.Answer = append(m.Answer, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs[0])
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
		v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), msgoptions.DnssecOK)
		m.Extra = append(m.Extra, v4glue.RRs...)
		m.Extra = append(m.Extra, v6glue.RRs...)
		if zd.AddTransportSignal && !msgoptions.OtsOptOut && zd.TransportSignal != nil && len(zd.TransportSignal.RRs) > 0 {
			if !transportSignalInAnswer {
				m.Extra = append(m.Extra, zd.TransportSignal.RRs...)
			}
		}
		if msgoptions.DnssecOK {
			log.Printf("ApexResponder: dnssec_ok is true, adding RRSIGs")
			m.Answer = append(m.Answer, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs...)
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
			m.Extra = append(m.Extra, v4glue.RRSIGs...)
			m.Extra = append(m.Extra, v6glue.RRSIGs...)
			if zd.AddTransportSignal && !msgoptions.OtsOptOut && zd.TransportSignal != nil {
				if !transportSignalInAnswer {
					m.Extra = append(m.Extra, zd.TransportSignal.RRSIGs...)
				}
			}
			// TSYNC has no signatures to add
		}
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
	m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
	v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), msgoptions.DnssecOK)
	m.Extra = append(m.Extra, v4glue.RRs...)
	m.Extra = append(m.Extra, v6glue.RRs...)
	if msgoptions.DnssecOK {
		m.Extra = append(m.Extra, v4glue.RRSIGs...)
		m.Extra = append(m.Extra, v6glue.RRSIGs...)
	}
	w.WriteMsg(m)

	_ = origqname

	return nil
}


// rrMatchesTransportSignal checks whether a given RR matches the configured transport signal RRset
func rrMatchesTransportSignal(rr dns.RR, ts *RRset) bool {
	if ts == nil || rr == nil {
		return false
	}
	h := rr.Header()
	return h.Rrtype == ts.RRtype && h.Name == ts.Name
}

// findServerTSYNCRRset returns a TSYNC RRset from any owner under this zone that starts with _dns.
func (zd *ZoneData) XXfindServerTSYNCRRset() *RRset {
	// Look for any TSYNC RRset at owners beginning with _dns.
	for item := range zd.Data.IterBuffered() {
		owner := item.Key
		od := item.Val
		if strings.HasPrefix(owner, "_dns.") {
			rrset := od.RRtypes.GetOnlyRRSet(TypeTSYNC)
			if len(rrset.RRs) > 0 {
				return &rrset
			}
		}
	}
	return nil
}
