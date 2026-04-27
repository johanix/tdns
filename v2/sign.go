/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// sig0TTL is the TTL used for SIG(0) records in signed messages.
const sig0TTL uint32 = 300

// signerStaleRRSIGsDropped counts how many RRSIGs SignRRset has dropped
// because their signing key was no longer in the active key set. The
// counter is intended to surface key-state-related events: outside of
// rollovers it should stay flat; a non-zero rate means SOMETHING changed
// the active set and the stale-RRSIG cleanup is doing its job. Read via
// SignerStaleRRSIGsDropped().
var signerStaleRRSIGsDropped uint64

// SignerStaleRRSIGsDropped returns a snapshot of the stale-RRSIG-drop
// counter. Used by tests and a future observability surface; per-zone
// breakdown can be added later if needed.
func SignerStaleRRSIGsDropped() uint64 {
	return atomic.LoadUint64(&signerStaleRRSIGsDropped)
}

// cryptoRandIntn returns a random int in [0, n) using crypto/rand.
func cryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(int64(n))
	val, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0 // fallback to 0 on error
	}
	return int(val.Int64())
}

func sigLifetime(t time.Time, lifetime uint32) (uint32, uint32) {
	sigJitter := time.Duration(time.Duration(cryptoRandIntn(61)) * time.Second)
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

	lgSigner.Debug("SignMsg: message details before signing", "compress", m.Compress, "extra_count", len(m.Extra), "ns_count", len(m.Ns), "question_count", len(m.Question), "answer_count", len(m.Answer), "id", m.Id)
	preBuf, preErr := m.Pack()
	if preErr == nil {
		lgSigner.Debug("SignMsg: packed message before signing", "buflen", len(preBuf), "first32", fmt.Sprintf("%x", preBuf[:min(32, len(preBuf))]))
	}

	for _, key := range sak.Keys {
		sigrr := new(dns.SIG)
		sigrr.Hdr = dns.RR_Header{
			Name:   key.KeyRR.Header().Name,
			Rrtype: dns.TypeSIG,
			Class:  dns.ClassINET,
			Ttl:    sig0TTL,
		}
		sigrr.RRSIG.KeyTag = key.KeyRR.DNSKEY.KeyTag()
		sigrr.RRSIG.Algorithm = key.KeyRR.DNSKEY.Algorithm
		sigrr.RRSIG.Inception, sigrr.RRSIG.Expiration = sigLifetime(time.Now().UTC(), 60*5) // 5 minutes
		sigrr.RRSIG.SignerName = signer

		signedBuf, err := sigrr.Sign(key.CS, &m)
		if err != nil {
			lgSigner.Error("sig.Sign failed", "signer", signer, "err", err)
			return nil, err
		}
		lgSigner.Debug("SignMsg: sig.Sign returned", "signed_buflen", len(signedBuf), "keyid", sigrr.RRSIG.KeyTag, "first32", fmt.Sprintf("%x", signedBuf[:min(32, len(signedBuf))]))
		m.Extra = append(m.Extra, sigrr)
	}
	lgSigner.Debug("SignMsg: message details after signing", "extra_count", len(m.Extra))
	postBuf, postErr := m.Pack()
	if postErr == nil {
		lgSigner.Debug("SignMsg: packed message after signing (what will be sent)", "buflen", len(postBuf), "first32", fmt.Sprintf("%x", postBuf[:min(32, len(postBuf))]))
	} else {
		lgSigner.Error("SignMsg: failed to pack message after signing", "err", postErr)
	}
	lgSigner.Debug("signed message", "msg", m.String())

	return &m, nil
}

// SignRRset signs an RRset with the zone's active KSK or ZSK keys, regenerating
// any RRSIGs that NeedsResigning indicates are stale. When clamp != nil
// (zone has clamping.enabled and a rollover is scheduled), the RR header
// TTLs are first clamped to min(rrset.UnclampedTTL, K * margin) and then
// signed — so the resulting RRSIG.OrigTtl matches the served TTL. See §5.2
// of the automated KSK rollover design.
//
// clamp == nil disables clamping entirely (no behavior change from the
// pre-4D signature). Most callers pass nil; SignZone builds a *ClampParams
// once per pass for clamping zones and threads it down.
func (zd *ZoneData) SignRRset(rrset *core.RRset, name string, dak *DnssecKeys, force bool, clamp *ClampParams) (bool, error) {

	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return false, fmt.Errorf("SignRRset: zone %s does not allow signing (neither online-signing nor inline-signing)", zd.ZoneName)
	}

	var err error

	if dak == nil {
		// Ensure active keys exist (will generate if needed)
		dak, err = zd.EnsureActiveDnssecKeys(zd.KeyDB)
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

	// 4D K-step clamp: rewrite RR header TTLs in place before signing so
	// the RRSIG covers the clamped TTL. Captures rrset.UnclampedTTL on
	// first encounter; no-op when clamp == nil.
	applyClampToRRset(rrset, clamp)

	var signingkeys []*PrivateKeyCache

	if rrset.RRs[0].Header().Rrtype == dns.TypeDNSKEY {
		signingkeys = dak.KSKs
	} else {
		signingkeys = dak.ZSKs
	}

	resigned := false
	now := time.Now().UTC()

	// Drop any RRSIG whose signing key is no longer in our active key set.
	// This happens after a KSK rollover: the previously-active key is now
	// retired (or removed) and we no longer want its RRSIG covering the
	// DNSKEY RRset (or any other RRset signed by KSKs/ZSKs). Without this,
	// stale RRSIGs by retired keys hang around until their validity
	// expires — long after the keys themselves leave the zone.
	//
	// Logged at INFO level (not Debug) and metered so operators can see
	// in production logs when this fires. Outside of rollover events the
	// counter should stay flat; a non-zero rate would indicate an
	// unexpected key-state change worth investigating.
	activeKeyTags := make(map[uint16]bool, len(signingkeys))
	for _, key := range signingkeys {
		activeKeyTags[key.DnskeyRR.KeyTag()] = true
	}
	filtered := rrset.RRSIGs[:0]
	for _, sig := range rrset.RRSIGs {
		s, ok := sig.(*dns.RRSIG)
		if !ok || activeKeyTags[s.KeyTag] {
			filtered = append(filtered, sig)
			continue
		}
		atomic.AddUint64(&signerStaleRRSIGsDropped, 1)
		lgSigner.Info("dropping RRSIG by non-active key",
			"zone", zd.ZoneName,
			"name", s.Header().Name,
			"rrtype", dns.TypeToString[s.TypeCovered],
			"keytag", s.KeyTag,
			"reason", "key no longer in active set (post-rollover or manual state change)")
		resigned = true // we changed the rrset.RRSIGs; flag as updated
	}
	rrset.RRSIGs = filtered

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
			rrsig.Inception, rrsig.Expiration = sigLifetime(now, 3600*24*30) // 30 days
			rrsig.SignerName = zd.ZoneName                                   // name

			err := rrsig.Sign(key.CS, rrset.RRs)
			if err != nil {
				lgSigner.Error("rrsig.Sign failed", "name", name, "err", err)
				return false, err
			}

			// 4D clamp invariant: warn if validity would expire before the
			// retired-key hold window completes. Doesn't refuse to sign.
			checkValidityInvariant(zd.ZoneName, rrsig, clamp, now)

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

// EnsureActiveDnssecKeys ensures that a zone has active DNSSEC keys.
// If no active keys exist, it will:
// 1. Try to promote published keys to active (if available)
// 2. Generate new KSK and ZSK keys if needed
// Returns the active DNSSEC keys or an error if key generation fails.
func (zd *ZoneData) EnsureActiveDnssecKeys(kdb *KeyDB) (*DnssecKeys, error) {
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return nil, fmt.Errorf("EnsureActiveDnssecKeys: zone %s does not allow signing (neither online-signing nor inline-signing)", zd.ZoneName)
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

		// Promote the first KSK from published to active
		if len(dpk.KSKs) > 0 {
			promotedKskKeyId = dpk.KSKs[0].KeyId
			err = kdb.PromoteDnssecKey(zd.ZoneName, promotedKskKeyId, DnskeyStatePublished, DnskeyStateActive)
			if err != nil {
				lgSigner.Error("failed to promote published KSK to active", "zone", zd.ZoneName, "err", err)
				return nil, err
			}
			lgSigner.Info("promoted published KSK to active", "zone", zd.ZoneName, "keyid", promotedKskKeyId)
		}

		// Promote the first ZSK from published to active unless it has the same keyid as the promoted KSK
		if len(dpk.ZSKs) > 0 && (len(dpk.KSKs) == 0 || dpk.ZSKs[0].KeyId != promotedKskKeyId) {
			zskKeyId := dpk.ZSKs[0].KeyId
			err = kdb.PromoteDnssecKey(zd.ZoneName, zskKeyId, DnskeyStatePublished, DnskeyStateActive)
			if err != nil {
				lgSigner.Error("failed to promote published ZSK to active", "zone", zd.ZoneName, "err", err)
				return nil, err
			}
			lgSigner.Info("promoted published ZSK to active", "zone", zd.ZoneName, "keyid", zskKeyId)
		}

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
		pkc, msg, err := kdb.GenerateKeypair(zd.ZoneName, "ensure-active-keys", DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.Algorithm, "KSK", nil)
		if err != nil {
			return nil, fmt.Errorf("EnsureActiveDnssecKeys: failed to generate KSK for zone %s: %v", zd.ZoneName, err)
		}
		lgSigner.Info("generated KSK", "msg", msg)
		// Bootstrap KSK landed straight in active. Register in
		// RolloverKeyState so rolloverDue and the K-step clamp scheduler
		// can find an active_at timestamp. No-op for non-rollover zones.
		if err := RegisterBootstrapActiveKSK(kdb, zd.ZoneName, pkc.KeyId, zd.DnssecPolicy.Rollover.Method, zd.DnssecPolicy.Algorithm); err != nil {
			lgSigner.Warn("rollover: register bootstrap KSK failed", "zone", zd.ZoneName, "keyid", pkc.KeyId, "err", err)
		}
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
			return nil, fmt.Errorf("EnsureActiveDnssecKeys: failed to generate ZSK for zone %s: %v", zd.ZoneName, err)
		}
		lgSigner.Info("generated ZSK", "msg", msg)
		// Invalidate cache and re-fetch active keys after ZSK generation
		dak, err = zd.refreshActiveDnssecKeys(kdb, "after ZSK generation")
		if err != nil {
			return nil, err
		}
	}

	if len(dak.KSKs) == 0 {
		return nil, fmt.Errorf("EnsureActiveDnssecKeys: failed to generate active KSK for zone %s", zd.ZoneName)
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

	// Single-signer signing (mode 1). Multi-provider signing
	// (modes 2-4) is handled by mpzd.SignZone() in tdns-mp.

	// Ensure active DNSSEC keys exist (will generate if needed)
	dak, err := zd.EnsureActiveDnssecKeys(kdb)
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

	// 4D K-step TTL clamp: build ClampParams once per pass so every RRset
	// signed in this pass observes the same K. nil for non-clamping zones
	// (or zones with no scheduled rollover, mid-rollover, etc.).
	var clamp *ClampParams
	if zd.DnssecPolicy != nil {
		clamp, err = ClampParamsForZone(kdb, zd.ZoneName, zd.DnssecPolicy, time.Now())
		if err != nil {
			lgSigner.Warn("SignZone: ClampParamsForZone failed; signing without clamp", "zone", zd.ZoneName, "err", err)
			clamp = nil
		}
	}

	MaybeSignRRset := func(rrset core.RRset, zone string) (core.RRset, bool) {
		resigned, err := zd.SignRRset(&rrset, zone, dak, force, clamp)
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
		if owner == nil {
			continue
		}
		if _, exist := owner.RRtypes.Get(dns.TypeNS); exist {
			delegations = append(delegations, name)
		}
	}

	lgSigner.Debug("zone delegations", "zone", zd.ZoneName, "delegations", delegations)

	var signed, zoneResigned bool
	var maxObservedTTL uint32
	for _, name := range names {
		// log.Printf("SignZone: signing RRsets under name %s", name)
		owner, err := zd.GetOwner(name)
		if err != nil {
			return 0, err
		}
		if owner == nil {
			continue
		}

		for _, rrt := range owner.RRtypes.Keys() {
			rrset := owner.RRtypes.GetOnlyRRSet(rrt)
			if rrt == dns.TypeRRSIG {
				continue // should not happen
			}
			if rrt == dns.TypeNS && name != zd.ZoneName {
				continue // dont' sign delegations
			}
			if len(rrset.RRs) > 0 {
				if t := rrset.RRs[0].Header().Ttl; t > maxObservedTTL {
					maxObservedTTL = t
				}
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

	// Persist the highest RRset TTL seen this pass. Used by the rollover
	// worker's pending-child-withdraw phase to compute effective_margin.
	// Reset per pass: a TTL reduction takes effect after one full cycle.
	if err := UpsertZoneSigningMaxTTL(kdb, zd.ZoneName, maxObservedTTL); err != nil {
		lgSigner.Warn("SignZone: persist max_observed_ttl", "zone", zd.ZoneName, "err", err)
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
	return zd.GenerateNsecChainWithDak(dak)
}

// GenerateNsecChainWithDak builds or refreshes the NSEC chain using the given active DNSSEC keys.
func (zd *ZoneData) GenerateNsecChainWithDak(dak *DnssecKeys) error {
	if !zd.Options[OptAllowUpdates] && !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return fmt.Errorf("GenerateNsecChainWithDak: zone %s is not allowed to be updated or signed", zd.ZoneName)
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
		if owner == nil {
			continue
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
		if owner == nil {
			continue
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
