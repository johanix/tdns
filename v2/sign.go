/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"sort"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
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
			lgSigner.Error("sig.Sign failed", "signer", signer, "err", err)
			return nil, err
		}
		m.Extra = append(m.Extra, sigrr)
	}
	lgSigner.Debug("signed message", "msg", m.String())

	return &m, nil
}

func (zd *ZoneData) SignRRset(rrset *core.RRset, name string, dak *DnssecKeys, force bool) (bool, error) {

	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return false, fmt.Errorf("SignRRset: zone %s does not allow signing (neither online-signing nor inline-signing)", zd.ZoneName)
	}

	var err error

	if dak == nil {
		// Ensure active keys exist (will generate if needed)
		dak, err = zd.ensureActiveDnssecKeys(zd.KeyDB)
		if err != nil {
			lgSigner.Error("failed to ensure active DNSSEC keys", "zone", zd.ZoneName, "err", err)
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
					lgSigner.Debug("removing older RRSIG by same DNSKEY", "name", oldsig.Header().Name, "rrtype", dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)])
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
				lgSigner.Error("rrsig.Sign failed", "name", name, "err", err)
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
		lgSigner.Info("RRSIG needs resigning, less than 3 intervals left", "name", rrsig.Header().Name, "rrtype", dns.TypeToString[uint16(rrsig.Header().Rrtype)])
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
		lgSigner.Error("failed to get DNSSEC active keys", "zone", zd.ZoneName, "context", context, "err", err)
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
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return nil, fmt.Errorf("ensureActiveDnssecKeys: zone %s does not allow signing (neither online-signing nor inline-signing)", zd.ZoneName)
	}

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		lgSigner.Error("failed to get DNSSEC active keys", "zone", zd.ZoneName, "err", err)
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

	lgSigner.Info("no active DNSSEC keys available, will generate new keys", "zone", zd.ZoneName)

	// Try to promote published keys to active first
	dpk, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStatePublished)
	if err != nil {
		lgSigner.Error("failed to get DNSSEC published keys", "zone", zd.ZoneName, "err", err)
		return nil, err
	}

	if len(dpk.KSKs) > 0 || len(dpk.ZSKs) > 0 {
		lgSigner.Info("published DNSSEC keys available for promotion", "zone", zd.ZoneName)

		var promotedKskKeyId uint16

		// For multi-provider zones, published→active requires dual-condition gating:
		// 1. propagation_confirmed (all remote providers confirmed the key)
		// 2. DNSKEY TTL expired since confirmation (caches worldwide have expired)
		multiProviderGating := zd.Options[OptMultiProvider]

		// Promote the first KSK from published to active
		if len(dpk.KSKs) > 0 {
			promotedKskKeyId = dpk.KSKs[0].KeyId
			if multiProviderGating {
				if !kdb.canPromoteMultiProvider(zd.ZoneName, promotedKskKeyId) {
					lgSigner.Info("KSK not yet eligible for promotion (multi-provider gating)", "zone", zd.ZoneName, "keyid", promotedKskKeyId)
					promotedKskKeyId = 0 // Don't mark as promoted
					goto skipKskPromotion
				}
			}
			err = kdb.PromoteDnssecKey(zd.ZoneName, promotedKskKeyId, DnskeyStatePublished, DnskeyStateActive)
			if err != nil {
				lgSigner.Error("failed to promote published KSK to active", "zone", zd.ZoneName, "err", err)
				return nil, err
			}
			lgSigner.Info("promoted published KSK to active", "zone", zd.ZoneName, "keyid", promotedKskKeyId)
		}
	skipKskPromotion:

		// Promote the first ZSK from published to active unless it has the same keyid as the promoted KSK
		if len(dpk.ZSKs) > 0 && (len(dpk.KSKs) == 0 || dpk.ZSKs[0].KeyId != promotedKskKeyId) {
			zskKeyId := dpk.ZSKs[0].KeyId
			if multiProviderGating {
				if !kdb.canPromoteMultiProvider(zd.ZoneName, zskKeyId) {
					lgSigner.Info("ZSK not yet eligible for promotion (multi-provider gating)", "zone", zd.ZoneName, "keyid", zskKeyId)
					goto skipZskPromotion
				}
			}
			err = kdb.PromoteDnssecKey(zd.ZoneName, zskKeyId, DnskeyStatePublished, DnskeyStateActive)
			if err != nil {
				lgSigner.Error("failed to promote published ZSK to active", "zone", zd.ZoneName, "err", err)
				return nil, err
			}
			lgSigner.Info("promoted published ZSK to active", "zone", zd.ZoneName, "keyid", zskKeyId)
		}
	skipZskPromotion:

		// Re-fetch active keys after promotion
		dak, err = kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			lgSigner.Error("failed to get DNSSEC active keys after promotion", "zone", zd.ZoneName, "err", err)
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
		lgSigner.Info("generated KSK", "msg", msg)
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
		lgSigner.Info("generated ZSK", "msg", msg)
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
		lgSigner.Warn("failed to publish DNSKEY RRs", "zone", zd.ZoneName, "err", err)
		// Don't fail if publishing fails, keys are still usable for signing
	}

	return dak, nil
}

// XXX: MaybesignRRset should report on whether it actually signed anything
// At the end, is anything hass been signed, then we must end by bumping the
// SOA Serial and resigning the SOA.
func (zd *ZoneData) SignZone(kdb *KeyDB, force bool) (int, error) {
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return 0, fmt.Errorf("SignZone: zone %s should not be signed here (neither online-signing nor inline-signing)", zd.ZoneName)
	}

	// Four-mode DNSKEY handling for multi-provider zones:
	//   Mode 1: Normal (no multi-provider) — strip incoming DNSKEYs, replace with local
	//   Mode 2: Multi-provider, single-signer, we ARE the signer — strip and replace
	//   Mode 3: Multi-provider, we are NOT a signer — pure pass-through, no signing
	//   Mode 4: Multi-provider, multi-signer — merge remote DNSKEYs with local
	if zd.Options[OptMultiProvider] {
		shouldSign, err := zd.weAreASigner()
		if err != nil {
			lgSigner.Warn("error checking HSYNC Sign field, proceeding with signing", "zone", zd.ZoneName, "err", err)
		} else if !shouldSign {
			// Mode 3: pass-through
			lgSigner.Info("HSYNC Sign=NOSIGN, skipping signing (mode 3: pass-through)", "zone", zd.ZoneName)
			return 0, nil
		}

		// Check if multi-signer (mode 4) or single-signer (mode 2).
		// OptMultiSigner was set during zone refresh by analyzeHsyncSigners().
		if zd.Options[OptMultiSigner] {
			// Mode 4: extract remote DNSKEYs from the current zone data before
			// PublishDnskeyRRs overwrites the DNSKEY RRset with local keys only.
			if err := zd.extractRemoteDNSKEYs(kdb); err != nil {
				lgSigner.Warn("error extracting remote DNSKEYs, proceeding without", "zone", zd.ZoneName, "err", err)
			}
			lgSigner.Info("multi-signer mode (mode 4)", "zone", zd.ZoneName, "remote_dnskeys", len(zd.RemoteDNSKEYs))
		} else {
			// Mode 2: single-signer, we sign — strip and replace (same as mode 1)
			zd.RemoteDNSKEYs = nil
			lgSigner.Info("single-signer multi-provider mode (mode 2), strip and replace", "zone", zd.ZoneName)
		}
	} else {
		// Mode 1: normal signing — no remote DNSKEYs
		zd.RemoteDNSKEYs = nil
	}

	// Ensure active DNSSEC keys exist (will generate if needed)
	dak, err := zd.ensureActiveDnssecKeys(kdb)
	if err != nil {
		lgSigner.Error("failed to ensure active DNSSEC keys", "zone", zd.ZoneName, "err", err)
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
			lgSigner.Error("failed to sign RRset", "name", rrset.RRs[0].Header().Name, "rrtype", dns.TypeToString[uint16(rrset.RRs[0].Header().Rrtype)], "zone", zd.ZoneName)
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

	lgSigner.Debug("zone delegations", "zone", zd.ZoneName, "delegations", delegations)

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
						lgSigner.Debug("not signing glue record", "zone", zd.ZoneName, "name", name, "rrtype", dns.TypeToString[uint16(rrt)], "delegation", del)
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
			lgSigner.Error("failed to bump SOA serial", "zone", zd.ZoneName, "err", err)
			return 0, err
		}
	}

	return newrrsigs, nil
}

func (zd *ZoneData) GenerateNsecChain(kdb *KeyDB) error {
	if !zd.Options[OptAllowUpdates] && !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return fmt.Errorf("GenerateNsecChain: zone %s is not allowed to be updated or signed", zd.ZoneName)
	}
	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		lgSigner.Error("failed to get DNSSEC active keys for NSEC chain", "zone", zd.ZoneName, "err", err)
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
					lgSigner.Warn("NSEC chain: unexpected zero rrtype", "name", name, "rrtype", rrt)
				}
				tmap = append(tmap, int(rrt))
			}
		}
		if hasRRSIG || ((zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]) && len(dak.KSKs) > 0) {
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
		owner.RRtypes.Set(dns.TypeNSEC, tmp)

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

// extractRemoteDNSKEYs examines the current zone's DNSKEY RRset and identifies
// keys that are NOT in our local keystore (i.e. remote signers' keys).
// These are stored in zd.RemoteDNSKEYs for later merging in PublishDnskeyRRs()
// and persisted to the DnssecKeyStore with state='foreign' so that
// GetKeyInventory() can report them in KEYSTATE inventory responses.
// Only called in mode 4 (multi-provider, multi-signer).
func (zd *ZoneData) extractRemoteDNSKEYs(kdb *KeyDB) error {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return fmt.Errorf("extractRemoteDNSKEYs: zone %s: cannot get apex: %v", zd.ZoneName, err)
	}

	dnskeyRRset, exists := apex.RRtypes.Get(dns.TypeDNSKEY)
	if !exists || len(dnskeyRRset.RRs) == 0 {
		lgSigner.Debug("no DNSKEY RRset in zone (normal for fresh zones)", "zone", zd.ZoneName)
		zd.RemoteDNSKEYs = nil
		return nil
	}

	// Get all local keys to identify what's ours (all non-foreign states)
	localKeyTags := make(map[uint16]bool)
	for _, state := range []string{DnskeyStateCreated, DnskeyStateMpdist, DnskeyStateMpremove, DnskeyStatePublished, DnskeyStateStandby, DnskeyStateActive, DnskeyStateRetired, DnskeyStateRemoved} {
		dak, err := kdb.GetDnssecKeys(zd.ZoneName, state)
		if err != nil {
			continue
		}
		for _, k := range dak.KSKs {
			localKeyTags[k.DnskeyRR.KeyTag()] = true
		}
		for _, k := range dak.ZSKs {
			localKeyTags[k.DnskeyRR.KeyTag()] = true
		}
	}

	// Get existing foreign keys from the DB (to detect removals)
	const fetchForeignSql = `SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND state='foreign'`
	rows, err := kdb.Query(fetchForeignSql, zd.ZoneName)
	if err != nil {
		return fmt.Errorf("extractRemoteDNSKEYs: zone %s: error querying foreign keys: %v", zd.ZoneName, err)
	}
	defer rows.Close()
	existingForeign := make(map[uint16]bool)
	for rows.Next() {
		var keyid int
		if err := rows.Scan(&keyid); err != nil {
			return fmt.Errorf("extractRemoteDNSKEYs: zone %s: error scanning foreign key row: %v", zd.ZoneName, err)
		}
		existingForeign[uint16(keyid)] = true
	}

	// Identify foreign keys: any DNSKEY in the zone that is not a local key
	var remote []dns.RR
	currentForeign := make(map[uint16]*dns.DNSKEY)
	for _, rr := range dnskeyRRset.RRs {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		kt := dnskey.KeyTag()
		if !localKeyTags[kt] {
			remote = append(remote, dns.Copy(rr))
			currentForeign[kt] = dnskey
		}
	}

	// Persist new foreign keys to KeyDB (INSERT OR IGNORE to never overwrite existing keys)
	const insertForeignSql = `INSERT OR IGNORE INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	for kt, dnskey := range currentForeign {
		res, err := kdb.Exec(insertForeignSql, zd.ZoneName, DnskeyStateForeign, kt, dnskey.Flags,
			dns.AlgorithmToString[dnskey.Algorithm], "foreign", "", dnskey.String())
		if err != nil {
			lgSigner.Error("failed to persist foreign DNSKEY", "zone", zd.ZoneName, "keytag", kt, "err", err)
		} else if n, _ := res.RowsAffected(); n > 0 {
			lgSigner.Info("persisted new foreign DNSKEY", "zone", zd.ZoneName, "keytag", kt, "flags", dnskey.Flags, "algorithm", dns.AlgorithmToString[dnskey.Algorithm])
		}
	}

	// Remove foreign keys from DB that are no longer in the zone
	const deleteForeignSql = `DELETE FROM DnssecKeyStore WHERE zonename=? AND keyid=? AND state='foreign'`
	for kt := range existingForeign {
		if _, stillPresent := currentForeign[kt]; !stillPresent {
			lgSigner.Info("removing stale foreign DNSKEY from KeyDB", "zone", zd.ZoneName, "keytag", kt)
			_, err := kdb.Exec(deleteForeignSql, zd.ZoneName, kt)
			if err != nil {
				lgSigner.Error("failed to delete stale foreign DNSKEY", "zone", zd.ZoneName, "keytag", kt, "err", err)
			}
		}
	}

	if len(remote) > 0 || len(existingForeign) > 0 {
		lgSigner.Info("foreign DNSKEY summary", "zone", zd.ZoneName, "in_zone", len(currentForeign), "in_db", len(existingForeign), "persisted", len(currentForeign))
	}

	zd.RemoteDNSKEYs = remote
	return nil
}
