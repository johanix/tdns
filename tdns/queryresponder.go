/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"net"
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

func (zd *ZoneData) xxxApexResponder(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, dnssec_ok bool, kdb *KeyDB) error {
	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		log.Printf("ApexResponder: failed to get dnssec key for zone %s", zd.ZoneName)
	}

	MaybeSignRRset := func(rrset RRset, qname string) RRset {
		if dak == nil {
			log.Printf("ApexResponder: MaybeSignRRset: Warning: dak is nil")
			return rrset
		}
		if zd.Options[OptOnlineSigning] && dak != nil && len(dak.ZSKs) > 0 && len(rrset.RRSIGs) == 0 {
			_, err := zd.SignRRset(&rrset, qname, dak, false)
			if err != nil {
				log.Printf("Error signing %s: %v", qname, err)
			} else {
				log.Printf("Signed %s: %v", qname, err)
			}
		}
		return rrset
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		if err != nil {
			log.Printf("ApexResponder: failed to get apex data for zone %s: %v", zd.ZoneName, err)
			return err
		} else {
			log.Printf("ApexResponder: failed to get apex data for zone %s", zd.ZoneName)
		}
	}

	if dnssec_ok {
		apex.RRtypes.Set(dns.TypeSOA, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA), zd.ZoneName))
		apex.RRtypes.Set(dns.TypeNS, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), zd.ZoneName))
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	var v4glue, v6glue *RRset

	switch qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		log.Printf("We are AUTH for %s %s, so let's try to serve it", ZoneStoreToString[zd.ZoneStore], qname)
		zd.ZoneTransferOut(w, r)
		return nil

	case dns.TypeSOA:
		zd.Logger.Printf("There are %d SOA RRs in %s. rrset: %v", len(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs),
			zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA))

		soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
		apex.RRtypes.Set(dns.TypeSOA, soaRRset)

		m.Answer = append(m.Answer, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs[0])
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
		v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), dnssec_ok)
		m.Extra = append(m.Extra, v4glue.RRs...)
		m.Extra = append(m.Extra, v6glue.RRs...)
		if dnssec_ok {
			log.Printf("ApexResponder: dnssec_ok is true, adding RRSIGs")
			m.Answer = append(m.Answer, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs...)
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
			m.Extra = append(m.Extra, v4glue.RRSIGs...)
			m.Extra = append(m.Extra, v6glue.RRSIGs...)
		}

	default:
		// Check if qtype is in our known types
		if tdnsSpecialTypes[qtype] || standardDNSTypes[qtype] {
			if rrset, ok := apex.RRtypes.Get(qtype); ok {
				if len(rrset.RRs) > 0 {
					m.Answer = append(m.Answer, rrset.RRs...)
					m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
					v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), dnssec_ok)
					m.Extra = append(m.Extra, v4glue.RRs...)
					m.Extra = append(m.Extra, v6glue.RRs...)
					if dnssec_ok {
						apex.RRtypes.Set(qtype, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(qtype), zd.ZoneName))
						apex.RRtypes.Set(dns.TypeNS, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), zd.ZoneName))

						m.Answer = append(m.Answer, apex.RRtypes.GetOnlyRRSet(qtype).RRSIGs...)
						m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
						m.Extra = append(m.Extra, v4glue.RRSIGs...)
						m.Extra = append(m.Extra, v6glue.RRSIGs...)
					}
				} else {
					m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
					if dnssec_ok {
						apex.RRtypes.Set(dns.TypeSOA, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA), zd.ZoneName))
						m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs...)
					}
				}
			} else {
				m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
				if dnssec_ok {
					apex.RRtypes.Set(dns.TypeSOA, MaybeSignRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA), zd.ZoneName))
					m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs...)
				}
			}

			// Special handling for certain types
			if qtype == dns.TypeNS {
				m.Ns = []dns.RR{} // authority not needed when querying for zone NS
			}
		} else {
			// every apex query we don't want to deal with
			m.MsgHdr.Rcode = dns.RcodeRefused
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
		}
	}
	w.WriteMsg(m)
	return nil
}

// 0. Check for *any* existence of qname
// 1. [OK] For a qname below zone, first check if there is a delegation. If so--> send referral
// 2. If no delegation, check for exact match
// 3. [OK] If no exact match, check for CNAME match
// 4. If no CNAME match, check for wild card match
// 5. Give up.

func (zd *ZoneData) QueryResponder(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, dnssec_ok bool, kdb *KeyDB) error {

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		log.Printf("QueryResponder: failed to get dnssec key for zone %s", zd.ZoneName)
	}

	MaybeSignRRset := func(rrset RRset, qname string) RRset {
		if dak == nil {
			log.Printf("QueryResponder: MaybeSignRRset: Warning: dak is nil")
			return rrset
		}
		if zd.Options[OptOnlineSigning] && dak != nil && len(dak.ZSKs) > 0 && len(rrset.RRSIGs) == 0 {
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

	if dnssec_ok {
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

	// log.Printf("---> Checking for existence of qname %s", qname)
	if !zd.NameExists(qname) {
		log.Printf("---> No exact match for %s in zone %s", qname, zd.ZoneName)

		// 1. Check for child delegation
		log.Printf("---> Checking for child delegation for %s", qname)
		cdd := zd.FindDelegation(qname, dnssec_ok)

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
			if dnssec_ok {
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
		if dnssec_ok {
			AddCDEResponse(m, origqname, apex, nil)
		}
		w.WriteMsg(m)
		return nil
	}

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
				if dnssec_ok {
					owner.RRtypes.Set(k, MaybeSignRRset(v, qname))
					m.Answer = append(m.Answer, v.RRSIGs...)
				}
				tgt := v.RRs[0].(*dns.CNAME).Target
				if strings.HasSuffix(tgt, zd.ZoneName) {
					tgtowner, _ := zd.GetOwner(tgt)
					if tgtrrset, ok := tgtowner.RRtypes.Get(qtype); ok {
						m.Answer = append(m.Answer, tgtrrset.RRs...)
						m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
						v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), dnssec_ok)
						m.Extra = append(m.Extra, v4glue.RRs...)
						m.Extra = append(m.Extra, v6glue.RRs...)
						if zd.ServerSVCB != nil {
							m.Extra = append(m.Extra, zd.ServerSVCB.RRs...)
						}
						if dnssec_ok {
							tgtowner.RRtypes.Set(qtype, MaybeSignRRset(tgtowner.RRtypes.GetOnlyRRSet(qtype), qname))
							m.Answer = append(m.Answer, tgtowner.RRtypes.GetOnlyRRSet(qtype).RRSIGs...)

							m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)

							m.Extra = append(m.Extra, v4glue.RRSIGs...)
							m.Extra = append(m.Extra, v6glue.RRSIGs...)
							if zd.ServerSVCB != nil {
								m.Extra = append(m.Extra, zd.ServerSVCB.RRSIGs...)
							}
						}
					}
					w.WriteMsg(m)
					return nil
				}
			}
		}
	}

	// 1. Check for child delegation
	// log.Printf("---> Checking for child delegation for %s", qname)
	cdd := zd.FindDelegation(qname, dnssec_ok)

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
			} else {
				// zd.Logger.Printf("Wildcard match qname %s %s", qname, origqname)
				tmp := WildcardReplace(rrset.RRs, qname, origqname)
				m.Answer = append(m.Answer, tmp...)
			}
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
			v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), dnssec_ok)
			m.Extra = append(m.Extra, v4glue.RRs...)
			m.Extra = append(m.Extra, v6glue.RRs...)
			if zd.ServerSVCB != nil {
				log.Printf("Adding SVCB: %s", zd.ServerSVCB.RRs[0].String())
				m.Extra = append(m.Extra, zd.ServerSVCB.RRs...)
			}
			if dnssec_ok {
				log.Printf("Should we sign qname %s %s (origqname: %s)?", qname, dns.TypeToString[qtype], origqname)
				if zd.Options[OptOnlineSigning] && dak != nil && len(dak.ZSKs) > 0 {
					if qname == origqname {
						owner.RRtypes.Set(qtype, MaybeSignRRset(rrset, qname))
					}
				}

				if qname == origqname {
					m.Answer = append(m.Answer, rrset.RRSIGs...)
				} else {
					tmp := WildcardReplace(rrset.RRSIGs, qname, origqname)
					m.Answer = append(m.Answer, tmp...)
				}
				m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
				m.Extra = append(m.Extra, v4glue.RRSIGs...)
				m.Extra = append(m.Extra, v6glue.RRSIGs...)
				if zd.ServerSVCB != nil {
					m.Extra = append(m.Extra, zd.ServerSVCB.RRSIGs...)
				}
			}
		} else {
			log.Printf("---> No exact match qname+qtype %s %s in zone %s", qname, dns.TypeToString[qtype], zd.ZoneName)
			// ensure correct serial
			soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
			soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
			apex.RRtypes.Set(dns.TypeSOA, soaRRset)
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
			if dnssec_ok {
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
		v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), dnssec_ok)
		m.Extra = append(m.Extra, v4glue.RRs...)
		m.Extra = append(m.Extra, v6glue.RRs...)
		if zd.ServerSVCB != nil && len(zd.ServerSVCB.RRs) > 0 {
			m.Extra = append(m.Extra, zd.ServerSVCB.RRs...)
		}
		if dnssec_ok {
			log.Printf("ApexResponder: dnssec_ok is true, adding RRSIGs")
			m.Answer = append(m.Answer, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs...)
			m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
			m.Extra = append(m.Extra, v4glue.RRSIGs...)
			m.Extra = append(m.Extra, v6glue.RRSIGs...)
			if zd.ServerSVCB != nil {
				m.Extra = append(m.Extra, zd.ServerSVCB.RRSIGs...)
			}
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
	v4glue, v6glue = zd.FindGlue(apex.RRtypes.GetOnlyRRSet(dns.TypeNS), dnssec_ok)
	m.Extra = append(m.Extra, v4glue.RRs...)
	m.Extra = append(m.Extra, v6glue.RRs...)
	if dnssec_ok {
		m.Extra = append(m.Extra, v4glue.RRSIGs...)
		m.Extra = append(m.Extra, v6glue.RRSIGs...)
	}
	w.WriteMsg(m)

	_ = origqname

	return nil
}

func (zd *ZoneData) CreateServerSvcbRRs(conf *Config) error {
	// Get the NS RRset for the zone apex
	apex, exists := zd.Data.Get(zd.ZoneName)
	if !exists {
		return fmt.Errorf("zone apex not found")
	}

	nsRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
	if len(nsRRset.RRs) == 0 {
		return fmt.Errorf("no NS records found at zone apex")
	}

	// First check if any NS names match service identities
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			nsName := ns.Ns

			// Check if this NS name is in service.identities
			if CaseFoldContains(conf.Service.Identities, nsName) {
				if strings.HasSuffix(nsName, zd.ZoneName) {
					continue // we'll deal with this below
				}
				log.Printf("CreateServerSvcbRRs: Zone %s: Found identity NS %s", zd.ZoneName, nsName)
				// Create SVCB record for this NS name
				tmp := &dns.SVCB{
					Hdr:      dns.RR_Header{Name: nsName, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 10800},
					Priority: 1,
					Target:   ".",
					Value:    Globals.ServerSVCB.Value,
				}
				zd.ServerSVCB = &RRset{Name: nsName, RRtype: dns.TypeSVCB, RRs: []dns.RR{tmp}}

				// To be able to sign this SVCB we need to know that we are authoritative for the zone that the
				// NS name is in and that we have the DNSSEC keys for that zone. As we get here during the initial
				// zone load we don't necessarily know that yet, so this would turn into a deferred operation.
				// Skipping this for now.

				log.Printf("CreateServerSvcbRRs: Adding server SVCB to zone %s using identity NS %s", zd.ZoneName, nsName)
				log.Printf("CreateServerSvcbRRs: SVCB: %s", tmp.String())
				return nil
			}
		}
	}

	// var svcbRRsets = map[string]*RRset{} // map[nsname]*RRset

	// Next look for in-bailiwick NS records and their addresses
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			nsName := ns.Ns
			if dns.IsSubDomain(zd.ZoneName, nsName) {
				// var svcbRRset = RRset{}
				// This is an in-bailiwick NS
				if nsData, exists := zd.Data.Get(nsName); exists {
					// Check A/AAAA records
					aRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeA)
					aaaaRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeAAAA)

					// Convert A/AAAA records to string slices
					var ipv4s []net.IP
					var ipv6s []net.IP

					if aRRset.RRs != nil {
						for _, rr := range aRRset.RRs {
							if a, ok := rr.(*dns.A); ok {
								ipv4s = append(ipv4s, a.A)
							}
						}
						log.Printf("CreateServerSvcbRRs: Zone %s: Found %d A records for in-bailiwick NS %s: %v", zd.ZoneName, len(ipv4s), nsName, ipv4s)
					}

					if aaaaRRset.RRs != nil {
						for _, rr := range aaaaRRset.RRs {
							if aaaa, ok := rr.(*dns.AAAA); ok {
								ipv6s = append(ipv6s, aaaa.AAAA)
							}
						}
						log.Printf("CreateServerSvcbRRs: Zone %s: Found %d AAAA records for in-bailiwick NS %s: %v", zd.ZoneName, len(ipv6s), nsName, ipv6s)
					}

					// Convert to SVCBKeyValue if we have any addresses
					// if len(ipv4s) > 0 {
					//	svcbRRset.RRs = append(svcbRRset.RRs, &dns.SVCBIPv4Hint{Hint: ipv4s})
					// }
					// if len(ipv6s) > 0 {
					//	svcbRRset.RRs = append(svcbRRset.RRs, &dns.SVCBIPv6Hint{Hint: ipv6s})
					// }

					// Helper to check if address matches any configured addresses
					checkAddrs := func(addrs []string, rrset *RRset) bool {
						if rrset == nil {
							return false
						}
						for _, rr := range rrset.RRs {
							var ip string
							switch r := rr.(type) {
							case *dns.A:
								ip = r.A.String()
							case *dns.AAAA:
								ip = r.AAAA.String()
							}
							for _, addr := range addrs {
								if strings.HasPrefix(addr, ip) {
									values := Globals.ServerSVCB.Value
									if len(ipv4s) > 0 {
										values = append(values, &dns.SVCBIPv4Hint{Hint: ipv4s})
									}
									if len(ipv6s) > 0 {
										values = append(values, &dns.SVCBIPv6Hint{Hint: ipv6s})
									}
									tmp := &dns.SVCB{
										Hdr:      dns.RR_Header{Name: nsName, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 10800},
										Priority: 1,
										Target:   ".",
										Value:    values,
									}
									zd.ServerSVCB = &RRset{Name: nsName, RRtype: dns.TypeSVCB, RRs: []dns.RR{tmp}}
									log.Printf("CreateServerSvcbRRs: Adding server SVCB to zone %s using in-bailiwick NS %s", zd.ZoneName, nsName)
									log.Printf("CreateServerSvcbRRs: SVCB: %s", tmp.String())

									_, err := zd.SignRRset(zd.ServerSVCB, "", nil, false)
									if err != nil {
										log.Printf("Error signing %s: %v", nsName, err)
									} else {
										log.Printf("Signed %s: %v", nsName, err)
									}
									// check whether we have any SVCB records for this NS name and if not add this to the zone
									serversvcbs := nsData.RRtypes.GetOnlyRRSet(dns.TypeSVCB)
									if len(serversvcbs.RRs) == 0 {
										nsData.RRtypes.Set(dns.TypeSVCB, RRset{RRs: []dns.RR{tmp}})
									} else {
										nsData.RRtypes.Set(dns.TypeSVCB, RRset{RRs: append(serversvcbs.RRs, tmp)})
										log.Printf("CreateServerSvcbRRs: Added server SVCB to existing SVCB RRset for zone %s using in-bailiwick NS %s", zd.ZoneName, nsName)
									}

									// return true
								}
							}
						}
						return false
					}

					if checkAddrs(conf.DnsEngine.Addresses, &aRRset) || checkAddrs(conf.DnsEngine.Addresses, &aaaaRRset) {
						return nil
					}
				}
			}
		}
	}

	return nil
}
