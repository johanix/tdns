/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	core "github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
)

// dnskeyFlagSEP is the "Secure Entry Point" (KSK) flag bit for DNSKEY RRs.
// miekg/dns does not currently export a symbolic constant for this, so we
// define it locally for clarity.
const dnskeyFlagSEP = 1 << 8

// RRsetFetcher is a function type for fetching RRsets by querying authoritative servers.
// It takes a context, query name, query type, and a map of authoritative servers,
// and returns the fetched RRset or an error.
type RRsetFetcher func(ctx context.Context, qname string, qtype uint16, servers map[string]*AuthServer) (*core.RRset, error)

// ValidateRRset attempts to validate the provided RRset using DNSKEYs present in the DnskeyCache.
// If a required signer key is missing, it will query for the signer's DNSKEY via the recursive
// engine and retry using keys from the cache. Only keys marked as Trusted are accepted for
// successful validation. Returns true if at least one signature validates and is time-valid.
func (rrcache *RRsetCacheT) ValidateRRset(ctx context.Context, rrset *core.RRset, fetcher RRsetFetcher, verbose bool) (ValidationState, error) {
	if rrset == nil {
		log.Printf("ValidateRRset: rrset is nil; nothing to validate")
		return ValidationStateNone, fmt.Errorf("rrset is nil; nothing to validate")
	}

	dkc := rrcache.DnskeyCache

	if rrcache.Debug {
		log.Printf("ValidateRRset: start: owner=%q type=%s sigs=%d rrs=%d",
			rrset.Name, dns.TypeToString[rrset.RRtype], len(rrset.RRSIGs), len(rrset.RRs))
	}
	// Special-case DNSKEY RRset validation: must anchor via DS and the specific KSK
	if rrset.RRtype == dns.TypeDNSKEY {
		if rrcache.Debug {
			log.Printf("ValidateRRset: validating %s DNSKEY RRset; handing over to ValidateDNSKEYs", rrset.Name)
		}
		// ValidateDNSKEYs will add keys to DnskeyCache upon successful validation
		return rrcache.ValidateDNSKEYs(ctx, rrset, fetcher, verbose)
	}
	if len(rrset.RRSIGs) == 0 {
		if rrcache.Debug {
			log.Printf("ValidateRRset: no RRSIGs present for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
		}
		return ValidationStateInsecure, nil // XXX: THis is wrong, we must know if the zone is insecure or not
		// XXX: The code returns ValidationStateInsecure when RRSIGs are absent (lines 55, 222) but cannot distinguish whether
		// the zone is legitimately unsigned or whether signatures are absent due to incomplete response data. This
		// limitation is systemic—XXX comments at lines 503, 508, 511, 518, and 602 document similar gaps in negative
		// response validation and NSEC proof logic. Properly determining zone security requires querying DS records at 
		// the parent zone, which would require significant architectural changes to the validation engine. This is a
		// known design limitation acknowledged throughout the file and should be tracked as a future enhancement.
	}

	for _, rr := range rrset.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			if rrcache.Debug {
				log.Printf("ValidateRRset: skipping non-RRSIG in RRSIGs slice: %T", rr)
			}
			continue
		}
		signer := dns.Fqdn(sig.SignerName)
		keyid := sig.KeyTag
		if rrcache.Debug {
			log.Printf("ValidateRRset: evaluating signature: signer=%q keyid=%d covered=%s inception=%d expiration=%d",
				signer, keyid, dns.TypeToString[sig.TypeCovered], sig.Inception, sig.Expiration)
		}
		dkrr := dkc.Get(signer, keyid)
		if rrcache.Debug {
			log.Printf("ValidateRRset: TA %q::%d in cache: %+v", signer, keyid, dkrr)
		}
		if dkrr == nil && rrcache != nil && ctx != nil {
			if rrcache.Verbose {
				log.Printf("ValidateRRset: TA %q::%d not in cache; attempting to obtain keys", signer, keyid)
			}
			// Attempt to fetch the signer's DNSKEY to populate cache (chain trust evaluated by caller)
			_, servers, err := rrcache.FindClosestKnownZone(signer)
			if err != nil {
				log.Printf("ValidateRRset: FindClosestKnownZone(%q) failed: %v", signer, err)
				continue
			}
			if rrcache.Debug {
				log.Printf("ValidateRRset: FindClosestKnownZone(%q) returned %d servers", signer, len(servers))
			}
			if len(servers) == 0 {
				if sm, ok := rrcache.ServerMap.Get("."); ok {
					servers = sm
				}
			}
			if len(servers) > 0 && fetcher != nil {
				if dkeys, err := fetcher(ctx, signer, dns.TypeDNSKEY, servers); err == nil && dkeys != nil && len(dkeys.RRs) > 0 {
					if rrcache.Debug {
						log.Printf("ValidateRRset: fetched %d DNSKEY RRs for %q", len(dkeys.RRs), signer)
					}
					// Add fetched keys to cache only after DS-based validation has been performed. 
					// Compute min TTL for expiration.
					minTTL := dkeys.RRs[0].Header().Ttl
					for _, krr := range dkeys.RRs[1:] {
						if krr.Header().Ttl < minTTL {
							minTTL = krr.Header().Ttl
						}
					}
					exp := time.Now().Add(time.Duration(minTTL) * time.Second)
					// Attempt to validate the fetched DNSKEY RRset using DS before adding to DnskeyCache
					// Only add validated/secure DNSKEYs to DnskeyCache, as it's used for validation of other data
					vstate, err := rrcache.ValidateDNSKEYs(ctx, dkeys, fetcher, verbose)
					if err != nil {
						log.Printf("ValidateRRset: failed validating DNSKEYs for %q: %v", signer, err)
						return vstate, err
					}
					if vstate == ValidationStateSecure {
						if verbose {
							log.Printf("ValidateRRset: signer DNSKEY RRset for %q validated; adding keys to DnskeyCache", signer)
						}
						for _, krr := range dkeys.RRs {
							if dk, ok := krr.(*dns.DNSKEY); ok {
								dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
									Name:       dns.Fqdn(dk.Hdr.Name),
									Keyid:      dk.KeyTag(),
									State:      vstate,
									Trusted:    true,
									Dnskey:     *dk,
									Expiration: exp,
								})
							}
						}
					} else {
						if verbose {
							log.Printf("ValidateRRset: signer DNSKEY RRset for %q did not validate (vstate: %s); not adding to DnskeyCache", signer, ValidationStateToString[vstate])
						}
					}
				} else if err != nil && verbose {
					log.Printf("ValidateRRset: failed fetching DNSKEY for %q: %v", signer, err)
				}
			}
			dkrr = dkc.Get(signer, keyid)
		}
		// Require a trusted key for a positive validation result
		if dkrr == nil || !dkrr.Trusted {
			if rrcache.Debug {
				if dkrr == nil {
					log.Printf("ValidateRRset: no TA in cache for %q::%d", signer, keyid)
				} else {
					log.Printf("ValidateRRset: TA present but not trusted for %q::%d", signer, keyid)
				}
			}
			continue
		}
		if err := sig.Verify(&dkrr.Dnskey, rrset.RRs); err != nil {
			if verbose {
				log.Printf("ValidateRRset: signature verify FAILED for %s %s using %s::%d: %v",
					rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid, err)
			}
			continue
		}
		// Time validity
		if WithinValidityPeriod(sig.Inception, sig.Expiration, time.Now().UTC()) {
			if rrcache.Debug {
				log.Printf("ValidateRRset: signature verify OK and within validity window for %s %s using %s::%d",
					rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid)
			}
			if rrcache.Debug {
				log.Printf("ValidateRRset: SUCCESS")
			}
			// If this is a DS RRset we now know that the zone is a secure zone.
			if rrset.RRtype == dns.TypeDS {
				zone, ok := rrcache.ZoneMap.Get(rrset.Name)
				if !ok {
					zone = &Zone{
						ZoneName: rrset.Name,
					}
				}
				zone.SecureDelegation = true
				rrcache.ZoneMap.Set(rrset.Name, zone)
			}
			// cap ttl to the signature expiration
			expirationTime := time.Unix(int64(sig.Expiration), 0)
			remaining := time.Until(expirationTime)
			ttl := time.Duration(remaining.Seconds()) * time.Second
			if ttl < time.Duration(GetMinTTL(rrset.RRs))*time.Second {
				if len(rrset.RRs) > 0 {
					rrset.RRs[0].Header().Ttl = uint32(ttl.Seconds())
				} 
			}
			return ValidationStateSecure, nil
		}
		if rrcache.Verbose {
			log.Printf("ValidateRRset: signature time INVALID for %s %s using %s::%d (inc=%d exp=%d now=%d)",
				rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid, sig.Inception, sig.Expiration, time.Now().UTC().Unix())
		}
	}
	if rrcache.Verbose {
		log.Printf("ValidateRRset: no acceptable signature validated for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
	}
	return ValidationStateInsecure, nil
}

// ValidateDNSKEYs validates a DNSKEY RRset using DS from the parent and the specific KSK named in the RRSIG.
// Steps:
// 1) Identify signer (apex) and key tag from an RRSIG covering DNSKEY.
// 2) Find the matching DNSKEY in the RRset (should be KSK).
// 3) Ensure a validated DS RRset for this apex exists in the cache.
// 4) Match the DNSKEY against any DS digest present.
// 5) Verify the DNSKEY RRset RRSIG with the matched DNSKEY and time window.
func (rrcache *RRsetCacheT) ValidateDNSKEYs(ctx context.Context, rrset *core.RRset, fetcher RRsetFetcher, verbose bool) (ValidationState, error) {
	if rrset == nil {
		log.Printf("ValidateDNSKEYs: rrset is nil; nothing to validate")
		return ValidationStateNone, fmt.Errorf("rrset is nil; nothing to validate")
	}

	if rrcache.Debug && rrset.RRtype == dns.TypeNS {
		fmt.Printf("ValidateDNSKEYs: rrset:\n%s", rrset.String(rrcache.LineWidth))
	}
	if len(rrset.RRSIGs) == 0 {
		if verbose {
			log.Printf("ValidateDNSKEYs: no signatures for %s", rrset.Name)
		}
		return ValidationStateInsecure, nil // XXX: THis is wrong, we must know if the zone is insecure or not
	}

	dkc := rrcache.DnskeyCache
	name := dns.Fqdn(rrset.Name)
	if verbose {
		log.Printf("ValidateDNSKEYs: start: owner=%q rrs=%d sigs=%d", name, len(rrset.RRs), len(rrset.RRSIGs))
	}

	// Special-case the root: there is no DS for ".", validate using a configured
	// trust anchor DNSKEY directly. Here we can pick any RRSIG(DNSKEY) and
	// require that its keytag matches a trusted anchor.
	if name == "." {
		var rootSig *dns.RRSIG
		for _, rr := range rrset.RRSIGs {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDNSKEY {
				rootSig = sig
				break
			}
		}
		if rootSig == nil {
			if verbose {
				log.Printf("ValidateDNSKEYs: no RRSIG(DNSKEY) present for root")
			}
			return ValidationStateBogus, nil
		}
		keyid := rootSig.KeyTag
		ta := dkc.Get(name, keyid)
		if ta == nil || !ta.Trusted {
			if verbose {
				if ta == nil {
					log.Printf("ValidateDNSKEYs: no TA for root keyid=%d", keyid)
				} else {
					log.Printf("ValidateDNSKEYs: root TA present but not trusted for keyid=%d", keyid)
				}
			}
			return ValidationStateIndeterminate, nil // XXX: No trust anchor for root
		}
		if err := rootSig.Verify(&ta.Dnskey, rrset.RRs); err != nil {
			if verbose {
				log.Printf("ValidateDNSKEYs: root signature verify FAILED: %v", err)
			}
			return ValidationStateBogus, nil // XXX: No trust anchor for root
		}
		if !WithinValidityPeriod(rootSig.Inception, rootSig.Expiration, time.Now().UTC()) {
			if verbose {
				log.Printf("ValidateDNSKEYs: root signature time INVALID (inc=%d exp=%d now=%d)",
					rootSig.Inception, rootSig.Expiration, time.Now().UTC().Unix())
			}
			return ValidationStateBogus, nil // XXX: No trust anchor for root
		}
		if verbose {
			log.Printf("ValidateDNSKEYs: SUCCESS for root with keytag=%d", keyid)
		}
		// Cap TTL to signature expiration
		expirationTime := time.Unix(int64(rootSig.Expiration), 0)
		remaining := time.Until(expirationTime)
		ttl := time.Duration(remaining.Seconds()) * time.Second
		if ttl < time.Duration(GetMinTTL(rrset.RRs))*time.Second {
			if len(rrset.RRs) > 0 {
				ttlSeconds := uint32(ttl.Seconds())
				for _, krr := range rrset.RRs {
					krr.Header().Ttl = ttlSeconds
				}
			}
		}
		// Add all DNSKEYs from the validated root RRset to DnskeyCache
		//		minTTL := uint32(0)
		//		for _, krr := range rrset.RRs {
		//			if _, ok := krr.(*dns.DNSKEY); ok {
		//				if minTTL == 0 || krr.Header().Ttl < minTTL {
		//					minTTL = krr.Header().Ttl
		//				}
		//			}
		//		}
		//		if minTTL == 0 {
		//			minTTL = 3600 // fallback
		//		}

		minTTL := GetMinTTL(rrset.RRs)

		exp := time.Now().Add(time.Duration(minTTL) * time.Second)
		for _, krr := range rrset.RRs {
			if dk, ok := krr.(*dns.DNSKEY); ok {
				dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
					Name:       dns.Fqdn(dk.Hdr.Name),
					Keyid:      dk.KeyTag(),
					State:      ValidationStateSecure,
					Trusted:    true,
					Dnskey:     *dk,
					Expiration: exp,
				})
			}
		}
		if verbose {
			log.Printf("ValidateDNSKEYs: added %d DNSKEYs to DnskeyCache for root", len(rrset.RRs))
		}
		return ValidationStateSecure, nil
	}

	// Non-root: use DS-driven validation.
	// 1) Retrieve DS RRset for this apex from cache and require it to be validated.
	var dsRRs *CachedRRset
	if rrcache != nil {
		dsRRs = rrcache.Get(name, dns.TypeDS)
	}
	if dsRRs == nil || dsRRs.RRset == nil || len(dsRRs.RRset.RRs) == 0 {
		if verbose {
			log.Printf("ValidateDNSKEYs: validated DS RRset for %s not present in cache", name)
		}
		return ValidationStateIndeterminate, nil // XXX: No validated DS RRset for this apex
	}

	if dsRRs.State != ValidationStateSecure {
		if verbose {
			log.Printf("ValidateDNSKEYs: validated DS RRset for %s is not secure", name)
		}
		return ValidationStateBogus, nil // XXX: If there is a DS RRset, it must be secure
	}

	// 2) For each DS: look for a matching DNSKEY (typically KSK with SEP bit),
	// verify that the digest matches, and then look for an RRSIG(DNSKEY) made
	// by this key. If any such combination validates, we trust the DNSKEY RRset.
	for _, rr := range dsRRs.RRset.RRs {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		keyid := ds.KeyTag

		var candidateKey *dns.DNSKEY
		for _, krr := range rrset.RRs {
			dk, ok := krr.(*dns.DNSKEY)
			if !ok {
				continue
			}
			if dk.KeyTag() != keyid {
				continue
			}
			// Require SEP (KSK) bit set for DS-backed keys
			if dk.Flags&dnskeyFlagSEP == 0 {
				continue
			}
			// Check that DS digest matches this DNSKEY
			comp := dk.ToDS(ds.DigestType)
			if comp == nil || !strings.EqualFold(comp.Digest, ds.Digest) {
				continue
			}
			candidateKey = dk
			break
		}
		if candidateKey == nil {
			if verbose {
				log.Printf("ValidateDNSKEYs: no DNSKEY with keytag=%d and matching DS digest at %s", keyid, name)
			}
			continue
		}

		// Find an RRSIG(DNSKEY) created by this key.
		var sigForKey *dns.RRSIG
		for _, srr := range rrset.RRSIGs {
			sig, ok := srr.(*dns.RRSIG)
			if !ok || sig.TypeCovered != dns.TypeDNSKEY {
				continue
			}
			if sig.KeyTag == keyid && dns.Fqdn(sig.SignerName) == name {
				sigForKey = sig
				break
			}
		}
		if sigForKey == nil {
			if verbose {
				log.Printf("ValidateDNSKEYs: no RRSIG(DNSKEY) found for DS-backed keytag=%d at %s", keyid, name)
			}
			continue
		}

		// Verify the DNSKEY RRset signature with candidateKey and time window.
		if err := sigForKey.Verify(candidateKey, rrset.RRs); err != nil {
			if verbose {
				log.Printf("ValidateDNSKEYs: signature verify FAILED for %s with keytag=%d: %v", name, keyid, err)
			}
			continue
		}
		if !WithinValidityPeriod(sigForKey.Inception, sigForKey.Expiration, time.Now().UTC()) {
			if verbose {
				log.Printf("ValidateDNSKEYs: signature time INVALID for %s with keytag=%d (inc=%d exp=%d now=%d)",
					name, keyid, sigForKey.Inception, sigForKey.Expiration, time.Now().UTC().Unix())
			}
			continue
		}

		if verbose {
			log.Printf("ValidateDNSKEYs: SUCCESS for %s with DS-backed keytag=%d", name, keyid)
		}
		// Cap TTL to signature expiration
		expirationTime := time.Unix(int64(sigForKey.Expiration), 0)
		remaining := time.Until(expirationTime)
		ttl := time.Duration(remaining.Seconds()) * time.Second
		if ttl < time.Duration(GetMinTTL(rrset.RRs))*time.Second {
			if len(rrset.RRs) > 0 {
				ttlSeconds := uint32(ttl.Seconds())
				for _, krr := range rrset.RRs {
					krr.Header().Ttl = ttlSeconds
				}
			}
		}
		// Add all DNSKEYs from the validated RRset to DnskeyCache so they're available
		// for validating other RRsets (e.g., A records signed by ZSKs).
		// This is a validation-time concern: the validator needs keys available immediately.
		minTTL := GetMinTTL(rrset.RRs)

		exp := time.Now().Add(time.Duration(minTTL) * time.Second)
		for _, krr := range rrset.RRs {
			if dk, ok := krr.(*dns.DNSKEY); ok {
				dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
					Name:       dns.Fqdn(dk.Hdr.Name),
					Keyid:      dk.KeyTag(),
					State:      ValidationStateSecure,
					Trusted:    true,
					Dnskey:     *dk,
					Expiration: exp,
				})
			}
		}
		if verbose {
			log.Printf("ValidateDNSKEYs: added %d DNSKEYs to DnskeyCache for %q", len(rrset.RRs), name)
		}
		return ValidationStateSecure, nil
	}

	if verbose {
		log.Printf("ValidateDNSKEYs: no DS-backed DNSKEY/RRSIG combination validated for %s", name)
	}
	return ValidationStateBogus, nil
}

func (rrcache *RRsetCacheT) ValidateNegativeResponse(ctx context.Context, qname string, qtype uint16, rcode uint8,
	negAuthority []*core.RRset, fetcher RRsetFetcher) (ValidationState, uint8, error) {
	if len(negAuthority) == 0 {
		return ValidationStateNone, rcode, fmt.Errorf("no negative authority RRsets to validate")
	}

	if qtype == dns.TypeDNSKEY {
		// Cannot validate negative DNSKEY responses without the zone's DNSKEYs; treat as bogus
		if rrcache.Debug {
			log.Printf("ValidateNegativeResponse: skipping validation for DNSKEY negative response at %q", qname)
		}
		return ValidationStateBogus, rcode, nil // XXX: Cannot validate negative DNSKEY responses without the zone's DNSKEYs
	}
	if ctx == nil {
		ctx = context.Background()
	}
	qnameCanon := dns.CanonicalName(qname)
	var (
		soarrset      *core.RRset
		hasSignatures bool
		nsecs         []*dns.NSEC
		nsec3Present  bool
	)
	for _, set := range negAuthority {
		if set == nil {
			continue
		}
		if set.RRtype == dns.TypeSOA && soarrset == nil {
			soarrset = set
		}
		if len(set.RRSIGs) > 0 {
			hasSignatures = true
		}
		switch set.RRtype {
		case dns.TypeNSEC:
			for _, rr := range set.RRs {
				if nsec, ok := rr.(*dns.NSEC); ok {
					nsecs = append(nsecs, nsec)
				}
			}
		case dns.TypeNSEC3:
			nsec3Present = true
		}
	}
	if soarrset == nil || len(soarrset.RRs) == 0 { // XXX: Here we need to know if the zone is insecure or not
		return ValidationStateIndeterminate, rcode, fmt.Errorf("no SOA found in negative authority for %s", qname)
	}
	zoneName := dns.CanonicalName(soarrset.Name)
	if !strings.HasSuffix(qnameCanon, zoneName) {
		return ValidationStateBogus, rcode, nil // XXX: The zone name does not match the qname
	}
	if !hasSignatures {
		return ValidationStateInsecure, rcode, nil // XXX: Need to know if zone is secure, but for now: No signatures, so we are insecure
	}
	for _, set := range negAuthority {
		if set == nil {
			continue
		}
		if len(set.RRSIGs) == 0 {
			continue // XXX: Here we need to know if the zone is insecure or not, for now: no signatures, so we are insecure
		}
		vstate, err := rrcache.ValidateRRset(ctx, set, fetcher, rrcache.Debug)
		if err != nil {
			return vstate, rcode, err
		}
		// The Auth section has a set of RRsets that prove non-existence. Each RRset must validate for the proof to be valid
		if vstate == ValidationStateBogus || vstate == ValidationStateIndeterminate {
			return vstate, rcode, fmt.Errorf("negative authority RRset for %s is bogus or indeterminate", qname)
		}
	}

	// NSEC case: Check for traditional denial (NXDOMAIN) or compact denial (RFC 9824)
	if len(nsecs) > 0 {
		// First, check for compact denial of existence (RFC 9824)
		for _, nsec := range nsecs {
			nsecOwner := dns.CanonicalName(nsec.Hdr.Name)
			// Check if this is a compact denial NSEC: owner == qname
			if nsecOwner == qnameCanon {
				// Compact denial has two cases:
				// 1. NXDOMAIN: bitmap contains exactly RRSIG, NSEC, and NXNAME
				//    This proves the name does not exist
				// 2. NODATA: bitmap doesn't include qtype (but may include other types)
				//    This proves the name exists but has no data for the queried type

				// Check for compact denial NXDOMAIN: bitmap contains exactly RRSIG, NSEC, and NXNAME
				if isCompactDenialNXDOMAIN(nsec.TypeBitMap) {
					if rrcache.Debug {
						log.Printf("ValidateNegativeResponse: compact denial NXDOMAIN (RFC 9824) validated for %s: name does not exist", qname)
					}
					// Note: The Rcode should be NXDOMAIN, but this function only validates
					// the negative authority section. The caller should set Rcode appropriately.
					return ValidationStateSecure, dns.RcodeNameError, nil
				}

				// Check for compact denial NODATA: qtype is NOT in the type bitmap
				if !typeInBitmap(qtype, nsec.TypeBitMap) {
					if rrcache.Debug {
						log.Printf("ValidateNegativeResponse: compact denial NODATA (RFC 9824) validated for %s %s: name exists but no data for type", qname, dns.TypeToString[qtype])
					}
					return ValidationStateSecure, rcode, nil
				}

				// If owner == qname but qtype IS in bitmap, this is not a negative response
				// (should not happen in negative authority section, but handle gracefully)
				if rrcache.Debug {
					log.Printf("ValidateNegativeResponse: NSEC owner matches qname but qtype %s is in bitmap - not a compact denial", dns.TypeToString[qtype])
				}
			}
		}

		// Traditional denial (NXDOMAIN): NSECs must cover both qname and wildcard
		baseZone := strings.TrimSuffix(zoneName, ".")
		wildcard := dns.CanonicalName("*." + baseZone)
		coveredQname := false
		coveredWildcard := false
		for _, nsec := range nsecs {
			if nsecCoversName(qnameCanon, nsec) {
				coveredQname = true
			}
			if nsecCoversName(wildcard, nsec) {
				coveredWildcard = true
			}
			if coveredQname && coveredWildcard {
				break
			}
		}
		if !coveredQname || !coveredWildcard {
			return ValidationStateBogus, rcode, nil // The NSECs do not cover the qname and the wildcard
		}
		return ValidationStateSecure, rcode, nil // NSECs present, we do not yet verify them, but we assume they are secure so we are secure
	}

	// NSEC3 case: Check for traditional denial (NXDOMAIN) or compact denial (RFC 9824 NODATA)
	if nsec3Present {
		// TODO: Implement NSEC3 compact denial validation (RFC 9824)
		// For NSEC3 compact denial:
		// - NSEC3 owner (hashed) matches hashed qname
		// - Type bitmap does NOT include qtype
		// For now, we accept NSEC3 presence as secure (traditional denial)
		return ValidationStateSecure, rcode, nil // NSEC3 present, we do not yet verify them, but we assume they are secure
	}

	// No NSEC, no NSEC3, must know if zone is secure or insecure
	return ValidationStateInsecure, rcode, fmt.Errorf("no NSECs or NSEC3, so we are insecure") // XXX: Need to know if zone is secure, but for now: No NSECs or NSEC3, so we are insecure
}

// From Mieks DNS lib:
// const year68 = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits.

// ValidityPeriod uses RFC1982 serial arithmetic to calculate
// if a signature period is valid. If t is the zero time, the
// current time is taken other t is. Returns true if the signature
// is valid at the given time, otherwise returns false.

const year68 = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits

func WithinValidityPeriod(inc, exp uint32, t time.Time) bool {
	var utc int64
	if t.IsZero() {
		utc = time.Now().UTC().Unix()
	} else {
		utc = t.UTC().Unix()
	}
	modi := (int64(inc) - utc) / year68
	mode := (int64(exp) - utc) / year68
	ti := int64(inc) + modi*year68
	te := int64(exp) + mode*year68
	return ti <= utc && utc <= te
}

func nsecCoversName(name string, nsec *dns.NSEC) bool {
	if nsec == nil {
		return false
	}
	owner := dns.CanonicalName(nsec.Hdr.Name)
	next := dns.CanonicalName(nsec.NextDomain)
	target := dns.CanonicalName(name)
	if owner == next {
		return true
	}
	if strings.Compare(owner, next) < 0 {
		return strings.Compare(target, owner) >= 0 && strings.Compare(target, next) < 0
	}
	return strings.Compare(target, owner) >= 0 || strings.Compare(target, next) < 0
}

// typeInBitmap checks if a given record type is present in an NSEC type bitmap.
// The type bitmap is a sorted slice of uint16 values representing record types.
func typeInBitmap(qtype uint16, bitmap []uint16) bool {
	for _, t := range bitmap {
		if t == qtype {
			return true
		}
		// Bitmap is sorted, so if we've passed qtype, it's not present
		if t > qtype {
			return false
		}
	}
	return false
}

// isCompactDenialNXDOMAIN checks if the type bitmap indicates compact denial NXDOMAIN.
// According to RFC 9824, compact denial NXDOMAIN is indicated when the bitmap contains
// exactly RRSIG, NSEC, and NXNAME (and no other types).
func isCompactDenialNXDOMAIN(bitmap []uint16) bool {
	// Must have exactly 3 types: RRSIG, NSEC, and NXNAME
	if len(bitmap) != 3 {
		return false
	}

	// Check that all three required types are present
	hasRRSIG := false
	hasNSEC := false
	hasNXNAME := false

	for _, t := range bitmap {
		switch t {
		case dns.TypeRRSIG:
			hasRRSIG = true
		case dns.TypeNSEC:
			hasNSEC = true
		case dns.TypeNXNAME:
			hasNXNAME = true
		default:
			// Any other type means this is not compact denial NXDOMAIN
			return false
		}
	}

	return hasRRSIG && hasNSEC && hasNXNAME
}
