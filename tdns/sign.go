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
	incep := uint32(t.Add(-sigJitter).Add(-60 * time.Second).Unix()) // inception == now -60s -jitter to allow for 60s clock skew
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

func (zd *ZoneData) SignRRset(rrset *RRset, name string, dak *DnssecKeys, force bool) (bool, error) {

	if !zd.Options[OptOnlineSigning] {
		return false, fmt.Errorf("SignRRset: zone %s does not allow online signing", zd.ZoneName)
	}

	var err error

	if dak == nil {
		dak, err = zd.KeyDB.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			log.Printf("SignRRset: failed to get DNSSEC active keys for zone %s", zd.ZoneName)
			return false, err
		}
	}

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
				Ttl:    rrset.RRs[0].Header().Ttl,
			}
			rrsig.KeyTag = key.DnskeyRR.KeyTag()
			rrsig.Algorithm = key.DnskeyRR.Algorithm
			rrsig.Inception, rrsig.Expiration = sigLifetime(time.Now().UTC(), 3600*24*30) // 30 days
			rrsig.SignerName = zd.ZoneName                                                // name

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

// XXX: Perhaps a working algorithm woul be to test for the remaining signature lifetime to be something like
//
//	less than 3 x resigning interval?
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
	if !zd.Options[OptOnlineSigning] {
		return 0, fmt.Errorf("SignZone: zone %s should not be signed here (option online-signing=false)", zd.ZoneName)
	}

	if !zd.Options[OptAllowUpdates] {
		return 0, fmt.Errorf("SignZone: zone %s is not allowed to be updated", zd.ZoneName)
	}

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		log.Printf("SignZone: failed to get DNSSEC active keys for zone %s", zd.ZoneName)
		return 0, err
	}
	if len(dak.KSKs) == 0 && len(dak.ZSKs) == 0 {
		log.Printf("SignZone: no active DNSSEC keys available for zone %s. Will generate new keys", zd.ZoneName)

		// XXX: Ok, so there are no active keys for this zone. What to do?
		// 1. Try to promote published keys to active keys. If ok, then generate new keys from scratch and promote to published.
		// 2. Generate new active keys from scratch and immediately promote them to active

		dpk, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStatePublished)
		if err != nil {
			log.Printf("SignZone: failed to get DNSSEC published keys for zone %s", zd.ZoneName)
			return 0, err
		}
		if len(dpk.KSKs) > 0 || len(dpk.ZSKs) > 0 {
			log.Printf("SignZone: Zone %s has published DNSSEC keys that could be promoted to active", zd.ZoneName)

			var promotedKskKeyId uint16

			// Promote the first KSK from published to active
			if len(dpk.KSKs) > 0 {
				promotedKskKeyId = dpk.KSKs[0].KeyId
				err = kdb.PromoteDnssecKey(zd.ZoneName, promotedKskKeyId, DnskeyStatePublished, DnskeyStateActive)
				if err != nil {
					log.Printf("SignZone: failed to promote published KSK to active for zone %s", zd.ZoneName)
					return 0, err
				}
				log.Printf("SignZone: Zone %s: promoted published KSK with keyid %d from published to active", zd.ZoneName, promotedKskKeyId)
			}

			// Promote the first ZSK from published to active unless it has the same keyid as the promoted KSK
			if len(dpk.ZSKs) > 0 && (len(dpk.KSKs) == 0 || dpk.ZSKs[0].KeyId != promotedKskKeyId) {
				err = kdb.PromoteDnssecKey(zd.ZoneName, dpk.ZSKs[0].KeyId, DnskeyStatePublished, DnskeyStateActive)
				if err != nil {
					log.Printf("SignZone: failed to promote published ZSK to active for zone %s", zd.ZoneName)
					return 0, err
				}
				log.Printf("SignZone: Zone %s: promoted published ZSK with keyid %d from published to active", zd.ZoneName, dpk.ZSKs[0].KeyId)
			}
		}

		// Now try to get the DNSSEC active keys again:
		dak, err = kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			log.Printf("SignZone: failed to get DNSSEC active keys for zone %s", zd.ZoneName)
			return 0, err
		}

		// Bummer, promoting didn't work, let's generate KSK:
		if len(dak.KSKs) == 0 {
			// dump.P(zd.DnssecPolicy)
			_, msg, err := kdb.GenerateKeypair(zd.ZoneName, "signzone", DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.Algorithm, "KSK", nil) // nil = no tx
			if err != nil {
				return 0, err
			}
			log.Printf("SignZone: %s", msg)
		}
		// generate ZSK:
		if len(dak.ZSKs) == 0 {
			_, msg, err := kdb.GenerateKeypair(zd.ZoneName, "signzone", DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.Algorithm, "ZSK", nil) // nil = no tx
			if err != nil {
				return 0, err
			}
			log.Printf("SignZone: %s", msg)
		}

		log.Printf("SignZone: New DNSSEC keys generated for zone %s", zd.ZoneName)

		// Now try to get the DNSSEC active keys again:
		dak, err = kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
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
	if !zd.Options[OptBlackLies] {
		err = zd.GenerateNsecChain(kdb)
		if err != nil {
			return 0, err
		}
	}

	MaybeSignRRset := func(rrset RRset, zone string) (RRset, bool) {
		resigned, err := zd.SignRRset(&rrset, zone, dak, force)
		if err != nil {
			log.Printf("SignZone: failed to sign %s %s RRset for zone %s", rrset.RRs[0].Header().Name, dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)], zd.ZoneName)
		}
		if resigned {
			newrrsigs++
		}
		return rrset, resigned
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
		if _, exist := owner.RRtypes.Get(dns.TypeNS); exist {
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

		for _, rrt := range owner.RRtypes.Keys() {
			rrset := owner.RRtypes.GetOnlyRRSet(rrt)
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
						log.Printf("SignZone: Zone %s: not signing glue record %s %s for delegation %s", zd.ZoneName, name, dns.TypeToString[uint16(rrt)], del)
						wasglue = true
						continue
					}
				}
			}
			if wasglue {
				continue
			}
			rrset, signed = MaybeSignRRset(rrset, zd.ZoneName)
			owner.RRtypes.Set(rrt, rrset)

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
	if !zd.Options[OptAllowUpdates] {
		return fmt.Errorf("GenerateNsecChain: zone %s is not allowed to be updated", zd.ZoneName)
	}
	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
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
		for _, rrt := range owner.RRtypes.Keys() {
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
		if hasRRSIG || (zd.Options[OptOnlineSigning] && len(dak.KSKs) > 0) {
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
		tmp := owner.RRtypes.GetOnlyRRSet(dns.TypeNSEC)
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
			rrs := owner.RRtypes.GetOnlyRRSet(dns.TypeNSEC).RRs
			if len(rrs) == 1 {
				nsecrrs = append(nsecrrs, rrs[0].String())
			}
		}
	}

	return nsecrrs, nil
}
