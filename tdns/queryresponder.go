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

func (zd *ZoneData) ApexResponder(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, dnssec_ok bool, kdb *KeyDB) error {
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
		log.Fatalf("ApexResponder: failed to get apex data for zone %s", zd.ZoneName)
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
		log.Printf("We have the %s %s, so let's try to serve it", ZoneStoreToString[zd.ZoneStore], qname)
		zd.ZoneTransferOut(w, r)
		return nil

	case dns.TypeSOA:
		// zd.Logger.Printf("apex: %v", apex)
		zd.Logger.Printf("There are %d SOA RRs in %s. rrset: %v", len(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs),
			zd.ZoneName, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA))

		soaRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
		soaRRset.RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
		apex.RRtypes.Set(dns.TypeSOA, soaRRset)

		//apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA).Serial = zd.CurrentSerial

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

	case TypeDSYNC, TypeNOTIFY, TypeMSIGNER, dns.TypeMX, dns.TypeTLSA, dns.TypeSRV,
		dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeTXT, dns.TypeZONEMD, dns.TypeKEY,
		dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeRRSIG,
		dns.TypeDNSKEY, dns.TypeCSYNC, dns.TypeCDS, dns.TypeCDNSKEY:
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
		// Anything special?
		switch qtype {
		case dns.TypeNS:
			m.Ns = []dns.RR{} // authority not needed when querying for zone NS
		}

	default:
		// every apex query we don't want to deal with
		m.MsgHdr.Rcode = dns.RcodeRefused
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs...)
		m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)
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
					return append(baseBitMap, uint16(128))
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
						if dnssec_ok {
							tgtowner.RRtypes.Set(qtype, MaybeSignRRset(tgtowner.RRtypes.GetOnlyRRSet(qtype), qname))
							m.Answer = append(m.Answer, tgtowner.RRtypes.GetOnlyRRSet(qtype).RRSIGs...)

							m.Ns = append(m.Ns, apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRSIGs...)

							m.Extra = append(m.Extra, v4glue.RRSIGs...)
							m.Extra = append(m.Extra, v6glue.RRSIGs...)
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

	// dump.P(cdd)

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
	switch qtype {
	case dns.TypeTXT, dns.TypeMX, dns.TypeA, dns.TypeAAAA, dns.TypeSRV, TypeNOTIFY, TypeDSYNC,
		TypeDELEG, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG:
		if rrset, ok := owner.RRtypes.Get(qtype); ok && len(owner.RRtypes.GetOnlyRRSet(qtype).RRs) > 0 {
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
			if dnssec_ok {

				log.Printf("Should we sign qname %s %s (origqname: %s)?", qname, dns.TypeToString[qtype], origqname)
				// if zd.OnlineSigning && cs != nil {
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
				for _, rrtype := range owner.RRtypes.Keys() {
					rrtypeList = append(rrtypeList, rrtype)
				}

				AddCDEResponse(m, origqname, apex, rrtypeList)
			}
		}
		w.WriteMsg(m)
		return nil
	}

	// Final catcheverything we don't want to deal with
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
