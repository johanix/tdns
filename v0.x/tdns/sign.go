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

	core "github.com/johanix/tdns/v0.x/tdns/core"
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

func (zd *ZoneData) SignRRset(rrset *core.RRset, name string, dak *DnssecKeys, force bool) (bool, error) {

	if !zd.Options[OptOnlineSigning] {
		return false, fmt.Errorf("SignRRset: zone %s does not allow online signing", zd.ZoneName)
	}

	var err error

	if dak == nil {
		// Ensure active keys exist (will generate if needed)
		dak, err = zd.ensureActiveDnssecKeys(zd.KeyDB)
		if err != nil {
			log.Printf("SignRRset: failed to ensure active DNSSEC keys for zone %s: %v", zd.ZoneName, err)
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
				Name:   rrset.RRs[0].Header().Name, // key.DnskeyRR.Header().Name,
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

// refreshActiveDnssecKeys invalidates the cache and re-fetches active DNSSEC keys.
// context is used in error messages to indicate when/why the refresh occurred.
func (zd *ZoneData) refreshActiveDnssecKeys(kdb *KeyDB, context string) (*DnssecKeys, error) {
	delete(kdb.KeystoreDnskeyCache, zd.ZoneName+"+"+DnskeyStateActive)
	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		log.Printf("ensureActiveDnssecKeys: failed to get DNSSEC active keys for zone %s %s: %v", zd.ZoneName, context, err)
		return nil, err
	}
	return dak, nil
}

// ensureActiveDnssecKeys ensures that a zone has active DNSSEC keys.
// If no active keys exist, it will:
// 1. Try to promote published keys to active (if available)
// 2. Generate new KSK and ZSK keys if needed
// Returns the active DNSSEC keys or an error if key generation fails.
func (zd *ZoneData) ensureActiveDnssecKeys(kdb *KeyDB) (*DnssecKeys, error) {
	if !zd.Options[OptOnlineSigning] {
		return nil, fmt.Errorf("ensureActiveDnssecKeys: zone %s does not allow online signing", zd.ZoneName)
	}

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		log.Printf("ensureActiveDnssecKeys: failed to get DNSSEC active keys for zone %s", zd.ZoneName)
		return nil, err
	}

	// If we already have active keys (including a real ZSK, not just KSK reused as CSK), return them
	if len(dak.KSKs) > 0 && len(dak.ZSKs) > 0 {
		// Check if we have a real ZSK (flags=256) or just KSK reused as CSK (flags=257)
		hasRealZSK := false
		for _, zsk := range dak.ZSKs {
			if zsk.DnskeyRR.Flags == 256 {
				hasRealZSK = true
				break
			}
		}
		if hasRealZSK {
			return dak, nil
		}
		// If we only have KSK reused as CSK, we'll generate a real ZSK below
	}

	log.Printf("ensureActiveDnssecKeys: no active DNSSEC keys available for zone %s. Will generate new keys", zd.ZoneName)

	// Try to promote published keys to active first
	dpk, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStatePublished)
	if err != nil {
		log.Printf("ensureActiveDnssecKeys: failed to get DNSSEC published keys for zone %s", zd.ZoneName)
		return nil, err
	}

	if len(dpk.KSKs) > 0 || len(dpk.ZSKs) > 0 {
		log.Printf("ensureActiveDnssecKeys: Zone %s has published DNSSEC keys that could be promoted to active", zd.ZoneName)

		var promotedKskKeyId uint16

		// Promote the first KSK from published to active
		if len(dpk.KSKs) > 0 {
			promotedKskKeyId = dpk.KSKs[0].KeyId
			err = kdb.PromoteDnssecKey(zd.ZoneName, promotedKskKeyId, DnskeyStatePublished, DnskeyStateActive)
			if err != nil {
				log.Printf("ensureActiveDnssecKeys: failed to promote published KSK to active for zone %s", zd.ZoneName)
				return nil, err
			}
			log.Printf("ensureActiveDnssecKeys: Zone %s: promoted published KSK with keyid %d from published to active", zd.ZoneName, promotedKskKeyId)
		}

		// Promote the first ZSK from published to active unless it has the same keyid as the promoted KSK
		if len(dpk.ZSKs) > 0 && (len(dpk.KSKs) == 0 || dpk.ZSKs[0].KeyId != promotedKskKeyId) {
			err = kdb.PromoteDnssecKey(zd.ZoneName, dpk.ZSKs[0].KeyId, DnskeyStatePublished, DnskeyStateActive)
			if err != nil {
				log.Printf("ensureActiveDnssecKeys: failed to promote published ZSK to active for zone %s", zd.ZoneName)
				return nil, err
			}
			log.Printf("ensureActiveDnssecKeys: Zone %s: promoted published ZSK with keyid %d from published to active", zd.ZoneName, dpk.ZSKs[0].KeyId)
		}

		// Re-fetch active keys after promotion
		dak, err = kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			log.Printf("ensureActiveDnssecKeys: failed to get DNSSEC active keys for zone %s after promotion", zd.ZoneName)
			return nil, err
		}
	}

	// Generate KSK if still missing
	if len(dak.KSKs) == 0 {
		// Invalidate cache before generating to ensure fresh data
		delete(kdb.KeystoreDnskeyCache, zd.ZoneName+"+"+DnskeyStateActive)
		_, msg, err := kdb.GenerateKeypair(zd.ZoneName, "ensure-active-keys", DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.Algorithm, "KSK", nil)
		if err != nil {
			return nil, fmt.Errorf("ensureActiveDnssecKeys: failed to generate KSK for zone %s: %v", zd.ZoneName, err)
		}
		log.Printf("ensureActiveDnssecKeys: %s", msg)
		// Invalidate cache and re-fetch active keys after KSK generation
		dak, err = zd.refreshActiveDnssecKeys(kdb, "after KSK generation")
		if err != nil {
			return nil, err
		}
	}

	// Count real ZSKs (flags=256), not KSKs reused as CSK (flags=257)
	realZSKCount := 0
	for _, zsk := range dak.ZSKs {
		if zsk.DnskeyRR.Flags == 256 {
			realZSKCount++
		}
	}

	// Generate ZSK only if we have zero real ZSKs
	if realZSKCount == 0 {
		// Invalidate cache before generating to ensure fresh data
		delete(kdb.KeystoreDnskeyCache, zd.ZoneName+"+"+DnskeyStateActive)
		_, msg, err := kdb.GenerateKeypair(zd.ZoneName, "ensure-active-keys", DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.Algorithm, "ZSK", nil)
		if err != nil {
			return nil, fmt.Errorf("ensureActiveDnssecKeys: failed to generate ZSK for zone %s: %v", zd.ZoneName, err)
		}
		log.Printf("ensureActiveDnssecKeys: %s", msg)
		// Invalidate cache and re-fetch active keys after ZSK generation
		dak, err = zd.refreshActiveDnssecKeys(kdb, "after ZSK generation")
		if err != nil {
			return nil, err
		}
	}

	if len(dak.KSKs) == 0 {
		return nil, fmt.Errorf("ensureActiveDnssecKeys: failed to generate active KSK for zone %s", zd.ZoneName)
	}

	// Ensure we have fresh data before publishing (invalidate cache and re-fetch)
	dak, err = zd.refreshActiveDnssecKeys(kdb, "before publishing")
	if err != nil {
		return nil, err
	}

	// Publish DNSKEYs to the zone so they're available in queries and AXFR
	err = zd.PublishDnskeyRRs(dak)
	if err != nil {
		log.Printf("ensureActiveDnssecKeys: failed to publish DNSKEY RRs for zone %s: %v", zd.ZoneName, err)
		// Don't fail if publishing fails, keys are still usable for signing
	} else {
		// Sign apex RRsets immediately after publishing DNSKEYs
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil {
			log.Printf("ensureActiveDnssecKeys: failed to get apex for zone %s to sign RRsets: %v", zd.ZoneName, err)
		} else {
			// Sign DNSKEY RRset
			if dnskeys, exist := apex.RRtypes.Get(dns.TypeDNSKEY); exist {
				_, err = zd.SignRRset(&dnskeys, zd.ZoneName, dak, true) // true = force signing
				if err != nil {
					log.Printf("ensureActiveDnssecKeys: failed to sign DNSKEY RRset for zone %s: %v", zd.ZoneName, err)
				} else {
					apex.RRtypes.Set(dns.TypeDNSKEY, dnskeys)
					log.Printf("ensureActiveDnssecKeys: signed DNSKEY RRset for zone %s", zd.ZoneName)
				}
			}

			// Sign SOA RRset
			if soa, exist := apex.RRtypes.Get(dns.TypeSOA); exist {
				_, err = zd.SignRRset(&soa, zd.ZoneName, dak, true) // true = force signing
				if err != nil {
					log.Printf("ensureActiveDnssecKeys: failed to sign SOA RRset for zone %s: %v", zd.ZoneName, err)
				} else {
					apex.RRtypes.Set(dns.TypeSOA, soa)
					log.Printf("ensureActiveDnssecKeys: signed SOA RRset for zone %s", zd.ZoneName)
				}
			}

			// Sign NS RRset at apex
			if ns, exist := apex.RRtypes.Get(dns.TypeNS); exist {
				_, err = zd.SignRRset(&ns, zd.ZoneName, dak, true) // true = force signing
				if err != nil {
					log.Printf("ensureActiveDnssecKeys: failed to sign NS RRset for zone %s: %v", zd.ZoneName, err)
				} else {
					apex.RRtypes.Set(dns.TypeNS, ns)
					log.Printf("ensureActiveDnssecKeys: signed NS RRset for zone %s", zd.ZoneName)
				}
			}

			// Sign A/AAAA records at apex (for NS names)
			for _, rrt := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if addr, exist := apex.RRtypes.Get(rrt); exist {
					_, err = zd.SignRRset(&addr, zd.ZoneName, dak, true) // true = force signing
					if err != nil {
						log.Printf("ensureActiveDnssecKeys: failed to sign %s RRset for zone %s: %v", dns.TypeToString[rrt], zd.ZoneName, err)
					} else {
						apex.RRtypes.Set(rrt, addr)
						log.Printf("ensureActiveDnssecKeys: signed %s RRset for zone %s", dns.TypeToString[rrt], zd.ZoneName)
					}
				}
			}
		}
	}

	return dak, nil
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

	// Ensure active DNSSEC keys exist (will generate if needed)
	dak, err := zd.ensureActiveDnssecKeys(kdb)
	if err != nil {
		log.Printf("SignZone: failed to ensure active DNSSEC keys for zone %s: %v", zd.ZoneName, err)
		return 0, err
	}

	newrrsigs := 0

	// It's either black lies or we need a traditional NSEC chain
	if !zd.Options[OptBlackLies] {
		err = zd.GenerateNsecChain(kdb)
		if err != nil {
			return 0, err
		}
	}

	MaybeSignRRset := func(rrset core.RRset, zone string) (core.RRset, bool) {
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
