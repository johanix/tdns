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
	"github.com/spf13/viper"
	"golang.org/x/exp/rand"
)

func sigLifetime(t time.Time, lifetime uint32) (uint32, uint32) {
	sigJitter := time.Duration(time.Duration(rand.Intn(61)) * time.Second)
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

func SignRRset(rrset *RRset, name string, dak *DnssecActiveKeys, force bool) (bool, error) {

	if dak == nil || len(dak.KSKs) == 0 || len(dak.ZSKs) == 0 {
		return false, fmt.Errorf("SignRRset: no active DNSSEC keys available")
	}

	if len(rrset.RRs) == 0 {
		return false, fmt.Errorf("SignRRsetNG: rrset has no RRs")
	}

	var signingkeys []*PrivateKeyCache

	if rrset.RRs[0].Header().Rrtype == dns.TypeDNSKEY {
		signingkeys = dak.KSKs
	} else {
		signingkeys = dak.ZSKs
	}

	resigned := false

	for _, key := range signingkeys {
		shouldSign := true
		for idx, oldsig := range rrset.RRSIGs {
			if oldsig.(*dns.RRSIG).KeyTag == key.DnskeyRR.KeyTag() {
				// Check if the existing RRSIG by the same key is older than one hour
				//				inceptionTime := time.Unix(int64(oldsig.(*dns.RRSIG).Inception), 0)
				//				if (time.Since(inceptionTime) < time.Hour) && !force {
				//					log.Printf("SignRRset: keeping existing RRSIG( %s %s ) by the same DNSKEY (less than one hour old)", oldsig.Header().Name, dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)])
				//					shouldSign = false
				//				} else {
				//					log.Printf("SignRRset: removing older RRSIG( %s %s ) by the same DNSKEY", oldsig.Header().Name, dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)])
				//
				//				}
				shouldSign = NeedsResigning(oldsig.(*dns.RRSIG)) || force
				if shouldSign {
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
				return false, err
			}

			rrset.RRSIGs = append(rrset.RRSIGs, rrsig)
			resigned = true
		}
	}

	return resigned, nil
}

// XXX: NeedsResigning should check if the RRSIG exists at all, and
// if so whether it is close to expiration.
// XXX: Perhaps a working algorithm woul be to test for the remaining signature lifetime to be something like
//
//	less than 3 x resigning interval?
func (rrset *RRset) NeedsResigning(force bool) bool {
	if len(rrset.RRSIGs) == 0 {
		return true
	}
	// here we should check is enough lifetime is left for the RRSIG
	// to be valid.

	for _, oldsig := range rrset.RRSIGs {
		inceptionTime := time.Unix(int64(oldsig.(*dns.RRSIG).Inception), 0)
		expirationTime := time.Unix(int64(oldsig.(*dns.RRSIG).Expiration), 0)

		if time.Until(expirationTime) < 3*time.Duration(viper.GetInt("resignerengine.interval")) {
			return true
		}
		if (time.Since(inceptionTime) < time.Hour) && !force {
			return false
		}
	}
	return true
}

func NeedsResigning(rrsig *dns.RRSIG) bool {
	// here we should check is enough lifetime is left for the RRSIG
	// to be valid.

	// inceptionTime := time.Unix(int64(rrsig.Inception), 0)
	expirationTime := time.Unix(int64(rrsig.Expiration), 0)

	if time.Until(expirationTime) < 3*time.Duration(viper.GetInt("resignerengine.interval")) {
		log.Printf("NeedsResigning: RRSIG for %s %s has less than 3 resigning intervals left; resigning now", rrsig.Header().Name, dns.TypeToString[uint16(rrsig.Header().Rrtype)])
		return true
	}
	return false
}

// XXX: MaybesignRRset should report on whether it actually signed anything
// At the end, is anything hass been signed, then we must end by bumping the
// SOA Serial and resigning the SOA.
func (zd *ZoneData) SignZone(kdb *KeyDB, force bool) (int, error) {
	if !zd.Options["sign-zone"] || !zd.Options["online-signing"] {
		return 0, fmt.Errorf("Zone %s should not be signed (option sign-zone=false)", zd.ZoneName)
	}

	if !zd.Options["allow-updates"] {
		return 0, fmt.Errorf("SignZone: zone %s is not allowed to be updated", zd.ZoneName)
	}

	dak, err := kdb.GetDnssecActiveKeys(zd.ZoneName)
	if err != nil {
		log.Printf("SignZone: failed to get DNSSEC active keys for zone %s", zd.ZoneName)
		return 0, err
	}
	if len(dak.KSKs) == 0 && len(dak.ZSKs) == 0 {
		log.Printf("SignZone: no active DNSSEC keys available for zone %s. Will generate new keys", zd.ZoneName)

		// generate ZSK:
		_, msg, err := kdb.GenerateKeypair(zd.ZoneName, "signzone", "active", dns.TypeDNSKEY, zd.DnssecPolicy.Algorithm, "ZSK", nil) // nil = no tx
		if err != nil {
			return 0, err
		}
		log.Printf("SignZone: %s", msg)
		// generate KSK:
		_, msg, err = kdb.GenerateKeypair(zd.ZoneName, "signzone", "active", dns.TypeDNSKEY, zd.DnssecPolicy.Algorithm, "KSK", nil) // nil = no tx
		if err != nil {
			return 0, err
		}
		log.Printf("SignZone: %s", msg)

		log.Printf("SignZone: New DNSSEC keys generated for zone %s", zd.ZoneName)
		// Now try to get the DNSSEC active keys again:
		dak, err = kdb.GetDnssecActiveKeys(zd.ZoneName)
		if err != nil {
			log.Printf("SignZone: failed to get DNSSEC active keys for zone %s", zd.ZoneName)
			return 0, err
		}
		if len(dak.KSKs) == 0 {
			// Give up
			return 0, fmt.Errorf("SignZone: failed to generate active keys for zone %s", zd.ZoneName)
		}
	}

	newrrsigs := 0

	// It's either black lies or we need a traditional NSEC chain
	if !zd.Options["black-lies"] {
		err = zd.GenerateNsecChain(kdb)
		if err != nil {
			return 0, err
		}
	}

	MaybeSignRRset := func(rrset RRset, zone string) (RRset, bool) {
		// SignRRset *will* sign, so we must first check whether it is time
		// to sign.
		// if rrset.NeedsResigning(force) {
		resigned, err := SignRRset(&rrset, zone, dak, force)
		if err != nil {
			log.Printf("SignZone: failed to sign %s %s RRset for zone %s", rrset.RRs[0].Header().Name, dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)], zd.ZoneName)
		}
		if resigned {
			newrrsigs++
		}
		return rrset, resigned
		//}
		// return rrset, false
	}

	names, err := zd.GetOwnerNames()
	if err != nil {
		return 0, err
	}
	sort.Strings(names)

	err = zd.PublishDnskeyRRs(dak)
	if err != nil {
		return 0, err
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
			return 0, err
		}
		if _, exist := owner.RRtypes[dns.TypeNS]; exist {
			delegations = append(delegations, name)
		}
	}

	log.Printf("SignZone: Zone %s has the delegations: %v", zd.ZoneName, delegations)

	var signed, zoneResigned bool
	for _, name := range names {
		// log.Printf("SignZone: signing RRsets under name %s", name)
		owner, err := zd.GetOwner(name)
		if err != nil {
			return 0, err
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
				// log.Printf("SignZone: checking whether %s %s is a glue record for a delegation", name, dns.TypeToString[uint16(rrt)])
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
			owner.RRtypes[rrt], signed = MaybeSignRRset(rrset, zd.ZoneName)
			if signed {
				zoneResigned = true
			}
		}
	}

	if zoneResigned {
		//		zd.CurrentSerial++
		//		apex, _ := zd.GetOwner(zd.ZoneName)
		//		apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
		_, err := zd.BumpSerial()
		if err != nil {
			log.Printf("SignZone: failed to bump SOA serial for zone %s", zd.ZoneName)
			return 0, err
		}
	}

	return newrrsigs, nil
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

		// log.Printf("GenerateNsecChain: name: %s tmap: %v", name, tmap)

		sort.Ints(tmap) // unfortunately the NSEC TypeBitMap must be in order...
		var rrts = make([]string, len(tmap))
		for idx, t := range tmap {
			rrts[idx] = dns.TypeToString[uint16(t)]
		}

		// log.Printf("GenerateNsecChain: creating NSEC RR for name %s: %v %v", name, tmap, rrts)

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

func (zd *ZoneData) ShowNsecChain() ([]string, error) {
	var nsecrrs []string
	names, err := zd.GetOwnerNames()
	if err != nil {
		return nsecrrs, err
	}
	sort.Strings(names)

	for _, name := range names {
		owner, err := zd.GetOwner(name)
		if err != nil {
			return nsecrrs, err
		}
		if name != zd.ZoneName {
			rrs := owner.RRtypes[dns.TypeNSEC].RRs
			if len(rrs) == 1 {
				nsecrrs = append(nsecrrs, rrs[0].String())
			}
		}
	}

	return nsecrrs, nil
}
