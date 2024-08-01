/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func sigLifetime(t time.Time, lifetime uint32) (uint32, uint32) {
	sigJitter := time.Duration(60 * time.Second)
	sigValidity := time.Duration(lifetime) * time.Second
	if lifetime == 0 {
		sigValidity = time.Duration(5 * time.Minute)
	}
	incep := uint32(t.Add(-sigJitter).Unix())
	expir := uint32(t.Add(sigValidity).Add(sigJitter).Unix())
	return incep, expir
}

func SignMsg(m dns.Msg, signer string, sak *Sig0ActiveKeys) (*dns.Msg, error) {

	if sak == nil || len(sak.Keys) == 0 {
		return nil, fmt.Errorf("SignMsg: no active SIG(0) keys available")
	}

	for _, key := range sak.Keys {
		sigrr := new(dns.SIG)
		sigrr.Hdr = dns.RR_Header{
			Name:   key.KeyRR.Header().Name,
			Rrtype: dns.TypeSIG,
			Class:  dns.ClassINET,
			Ttl:    300,
		}
		sigrr.RRSIG.KeyTag = key.KeyRR.DNSKEY.KeyTag()
		sigrr.RRSIG.Algorithm = key.KeyRR.DNSKEY.Algorithm
		sigrr.RRSIG.Inception, sigrr.RRSIG.Expiration = sigLifetime(time.Now().UTC(), 60*5) // 5 minutes
		sigrr.RRSIG.SignerName = signer

		_, err := sigrr.Sign(key.CS, &m)
		if err != nil {
			log.Printf("Error from sig.Sign(%s): %v", signer, err)
			return nil, err
		}
		m.Extra = append(m.Extra, sigrr)
	}
	log.Printf("Signed msg: %s\n", m.String())

	return &m, nil
}

func SignRRset(rrset *RRset, name string, dak *DnssecActiveKeys, force bool) error {

	if dak == nil || len(dak.KSKs) == 0 || len(dak.ZSKs) == 0 {
		return fmt.Errorf("SignRRset: no active DNSSEC keys available")
	}

	if len(rrset.RRs) == 0 {
		return fmt.Errorf("SignRRsetNG: rrset has no RRs")
	}

	var signingkeys []*PrivateKeyCache

	if rrset.RRs[0].Header().Rrtype == dns.TypeDNSKEY {
		signingkeys = dak.KSKs
	} else {
		signingkeys = dak.ZSKs
	}

	for _, key := range signingkeys {
		shouldSign := true
		for idx, oldsig := range rrset.RRSIGs {
			if oldsig.(*dns.RRSIG).KeyTag == key.DnskeyRR.KeyTag() {
				// Check if the existing RRSIG by the same key is older than one hour
				inceptionTime := time.Unix(int64(oldsig.(*dns.RRSIG).Inception), 0)
				if (time.Since(inceptionTime) < time.Hour) && !force {
					log.Printf("SignRRset: keeping existing RRSIG( %s %s ) by the same DNSKEY (less than one hour old)", oldsig.Header().Name, dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)])
					shouldSign = false
				} else {
					log.Printf("SignRRset: removing older RRSIG( %s %s ) by the same DNSKEY", oldsig.Header().Name, dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)])
					rrset.RRSIGs = append(rrset.RRSIGs[:idx], rrset.RRSIGs[idx+1:]...)
				}
			}
		}

		if shouldSign {
			rrsig := new(dns.RRSIG)
			rrsig.Hdr = dns.RR_Header{
				Name:   key.DnskeyRR.Header().Name,
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    604800, // one week in seconds
			}
			rrsig.KeyTag = key.DnskeyRR.KeyTag()
			rrsig.Algorithm = key.DnskeyRR.Algorithm
			rrsig.Inception, rrsig.Expiration = sigLifetime(time.Now().UTC(), 3600*24*30) // 30 days
			rrsig.SignerName = name

			err := rrsig.Sign(key.CS, rrset.RRs)
			if err != nil {
				log.Printf("Error from rrsig.Sign(%s): %v", name, err)
				return err
			}

			rrset.RRSIGs = append(rrset.RRSIGs, rrsig)
		}
	}

	return nil
}

func (zd *ZoneData) SignZone(kdb *KeyDB, force bool) error {
	if !zd.Options["sign-zone"] || !zd.Options["online-signing"] {
		return fmt.Errorf("Zone %s should not be signed (option sign-zone=false)", zd.ZoneName)
	}

	if !zd.Options["allow-updates"] {
		return fmt.Errorf("SignZone: zone %s is not allowed to be updated", zd.ZoneName)
	}

	dak, err := kdb.GetDnssecActiveKeys(zd.ZoneName)
	if err != nil {
		log.Printf("SignZone: failed to get dnssec active keys for zone %s", zd.ZoneName)
		return err
	}

	// It's either black lies or we need a traditional NSEC chain
	if !zd.Options["black-lies"] {
		err = zd.GenerateNsecChain(kdb)
		if err != nil {
			return err
		}
	}

	MaybeSignRRset := func(rrset RRset, zone string) RRset {
		err := SignRRset(&rrset, zone, dak, force)
		if err != nil {
			log.Printf("SignZone: failed to sign %s %s RRset for zone %s", rrset.RRs[0].Header().Name, dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)], zd.ZoneName)
		}
		return rrset
	}

	names, err := zd.GetOwnerNames()
	if err != nil {
		return err
	}
	sort.Strings(names)

	err = zd.PublishDnskeyRRs(dak)
	if err != nil {
		return err
	}

	// apex, err := zd.GetOwner(zd.ZoneName)
	// if err != nil {
	// 	return err
	// }

	var delegations []string
	for _, name := range names {
		if name == zd.ZoneName {
			continue
		}
		owner, err := zd.GetOwner(name)
		if err != nil {
			return err
		}
		if _, exist := owner.RRtypes[dns.TypeNS]; exist {
			delegations = append(delegations, name)
		}
	}

	log.Printf("SignZone: Zone %s has the delegations: %v", zd.ZoneName, delegations)

	for _, name := range names {
		owner, err := zd.GetOwner(name)
		if err != nil {
			return err
		}

		for rrt, rrset := range owner.RRtypes {
			if rrt == dns.TypeRRSIG {
				continue // should not happen
			}
			if rrt == dns.TypeNS && name != zd.ZoneName {
				continue // dont' sign delegations
			}
			// XXX: What is the best way to identify that an RR is a glue record?
			var wasglue bool
			if rrt == dns.TypeA || rrt == dns.TypeAAAA {
				log.Printf("SignZone: checking whether %s %s is a glue record for a delegation", name, dns.TypeToString[uint16(rrt)])
				for _, del := range delegations {
					if strings.HasSuffix(name, del) {
						log.Printf("SignZone: not signing glue record %s %s for delegation %s", name, dns.TypeToString[uint16(rrt)], del)
						wasglue = true
						continue
					}
				}
			}
			if wasglue {
				continue
			}
			owner.RRtypes[rrt] = MaybeSignRRset(rrset, zd.ZoneName)
		}
	}

	return nil
}

func (zd *ZoneData) GenerateNsecChain(kdb *KeyDB) error {
	if !zd.Options["allow-updates"] {
		return fmt.Errorf("GenerateNsecChain: zone %s is not allowed to be updated", zd.ZoneName)
	}
	dak, err := kdb.GetDnssecActiveKeys(zd.ZoneName)
	if err != nil {
		log.Printf("GenerateNsecChain: failed to get dnssec active keys for zone %s", zd.ZoneName)
		return err
	}

	//	MaybeSignRRset := func(rrset RRset, zone string, kdb *KeyDB) RRset {
	//		if zd.Options["online-signing"] && len(dak.ZSKs) > 0 {
	//			err := SignRRset(&rrset, zone, dak)
	//			if err != nil {
	//				log.Printf("GenerateNsecChain: failed to sign %s NSEC RRset for zone %s", rrset.RRs[0].Header().Name, zd.ZoneName)
	//			} else {
	//				log.Printf("GenerateNsecChain: signed %s NSEC RRset for zone %s", rrset.RRs[0].Header().Name, zd.ZoneName)
	//			}
	//		}
	//		return rrset
	//	}

	names, err := zd.GetOwnerNames()
	if err != nil {
		return err
	}
	sort.Strings(names)

	var nextidx int
	var nextname string

	var hasRRSIG bool

	for idx, name := range names {
		owner, err := zd.GetOwner(name)
		if err != nil {
			return err
		}

		nextidx = idx + 1
		if nextidx == len(names) {
			nextidx = 0
		}
		nextname = names[nextidx]
		var tmap = []int{int(dns.TypeNSEC)}
		for rrt := range owner.RRtypes {
			if rrt == dns.TypeRRSIG {
				hasRRSIG = true
				continue
			}
			if rrt != dns.TypeNSEC {
				if rrt == 0 {
					log.Printf("GenerateNsecChain: name: %s rrt: %v (not good)", name, rrt)
				}
				tmap = append(tmap, int(rrt))
			}
		}
		if hasRRSIG || (zd.Options["online-signing"] && len(dak.KSKs) > 0) {
			tmap = append(tmap, int(dns.TypeRRSIG))
		}

		log.Printf("GenerateNsecChain: name: %s tmap: %v", name, tmap)

		sort.Ints(tmap) // unfortunately the NSEC TypeBitMap must be in order...
		var rrts = make([]string, len(tmap))
		for idx, t := range tmap {
			rrts[idx] = dns.TypeToString[uint16(t)]
		}

		log.Printf("GenerateNsecChain: creating NSEC RR for name %s: %v %v", name, tmap, rrts)

		items := []string{name, "NSEC", nextname}
		items = append(items, rrts...)
		nsecrr, err := dns.NewRR(strings.Join(items, " "))
		if err != nil {
			return err
		}
		tmp := owner.RRtypes[dns.TypeNSEC]
		tmp.RRs = []dns.RR{nsecrr}
		//		owner.RRtypes[dns.TypeNSEC] = MaybeSignRRset(tmp, zd.ZoneName, kdb)

	}

	return nil
}
