/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
 package tdns

 import (
	 "context"
	 "log"
	 "strings"
	 "time"
 
	 "github.com/miekg/dns"
	 core "github.com/johanix/tdns/tdns/core"
 )

// ValidateRRset attempts to validate the provided RRset using DNSKEYs present in the DnskeyCache.
// If a required signer key is missing, it will query for the signer's DNSKEY via the recursive
// engine and retry using keys from the cache. Only keys marked as Trusted are accepted for
// successful validation. Returns true if at least one signature validates and is time-valid.
func (rrcache *RRsetCacheT) ValidateRRset(ctx context.Context, dkc *DnskeyCacheT, rrset *core.RRset, verbose bool) (bool, error) {
	if Globals.Debug {
		log.Printf("ValidateRRset: start: owner=%q type=%s sigs=%d rrs=%d",
			rrset.Name, dns.TypeToString[rrset.RRtype], len(rrset.RRSIGs), len(rrset.RRs))
	}
	// Special-case DNSKEY RRset validation: must anchor via DS and the specific KSK
	if rrset != nil && rrset.RRtype == dns.TypeDNSKEY {
		return rrcache.ValidateDNSKEYs(ctx, dkc, rrset, verbose)
	}
	if rrset == nil || len(rrset.RRSIGs) == 0 {
		if Globals.Debug {
			log.Printf("ValidateRRset: no RRSIGs present for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
		}
		return false, nil
	}
	if Globals.Debug {
		log.Printf("ValidateRRset: start: owner=%q type=%s sigs=%d rrs=%d",
			rrset.Name, dns.TypeToString[rrset.RRtype], len(rrset.RRSIGs), len(rrset.RRs))
	}
	for _, rr := range rrset.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			if Globals.Debug {
				log.Printf("ValidateRRset: skipping non-RRSIG in RRSIGs slice: %T", rr)
			}
			continue
		}
		signer := dns.Fqdn(sig.SignerName)
		keyid := sig.KeyTag
		if Globals.Debug {
			log.Printf("ValidateRRset: evaluating signature: signer=%q keyid=%d covered=%s inception=%d expiration=%d",
				signer, keyid, dns.TypeToString[sig.TypeCovered], sig.Inception, sig.Expiration)
		}
		ta := dkc.Get(signer, keyid)
		if Globals.Debug {
			log.Printf("ValidateRRset: TA %q::%d in cache: %+v", signer, keyid, ta)
		}
		if ta == nil && rrcache != nil && ctx != nil {
			if verbose {
				log.Printf("ValidateRRset: TA %q::%d not in cache; attempting to obtain keys", signer, keyid)
			}
			// If validating a DNSKEY RRset, avoid refetching signer DNSKEY:
			// use the provided RRset to populate cache (untrusted) and continue.
			if rrset.RRtype == dns.TypeDNSKEY && (rrset.Name == "" || dns.Fqdn(rrset.Name) == signer) {
				if verbose {
					log.Printf("ValidateRRset: using provided DNSKEY RRset to populate cache for %q", signer)
				}
				// Populate cache entries for the keys in this RRset (untrusted)
				var minTTL uint32
				if len(rrset.RRs) > 0 {
					minTTL = rrset.RRs[0].Header().Ttl
					for _, krr := range rrset.RRs[1:] {
						if krr.Header().Ttl < minTTL {
							minTTL = krr.Header().Ttl
						}
					}
				}
				exp := time.Now().Add(time.Duration(minTTL) * time.Second)
				for _, krr := range rrset.RRs {
					if dk, ok := krr.(*dns.DNSKEY); ok {
						dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
							Name:       dns.Fqdn(dk.Hdr.Name),
							Keyid:      dk.KeyTag(),
							Validated:  false,
							Trusted:    false,
							Dnskey:     *dk,
							Expiration: exp,
						})
						if verbose {
							log.Printf("ValidateRRset: cached DNSKEY (untrusted) %q::%d exp=%v", dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), exp)
						}
					}
				}
			} else {
			// Attempt to fetch the signer's DNSKEY to populate cache (chain trust evaluated by caller)
			_, servers, _ := rrcache.FindClosestKnownZone(signer)
				if Globals.Debug {
				log.Printf("ValidateRRset: FindClosestKnownZone(%q) returned %d servers", signer, len(servers))
			}
			if len(servers) == 0 {
				if sm, ok := rrcache.ServerMap.Get("."); ok {
					servers = sm
				}
			}
			if len(servers) > 0 {
				if dkeys, _, _, err := rrcache.IterativeDNSQuery(ctx, signer, dns.TypeDNSKEY, servers, false); err == nil && dkeys != nil && len(dkeys.RRs) > 0 {
						if Globals.Debug {
						log.Printf("ValidateRRset: fetched %d DNSKEY RRs for %q", len(dkeys.RRs), signer)
					}
					// Add fetched keys to cache (not trusted by default). Trust must be established elsewhere.
					// Compute min TTL for expiration.
					minTTL := dkeys.RRs[0].Header().Ttl
					for _, krr := range dkeys.RRs[1:] {
						if krr.Header().Ttl < minTTL {
							minTTL = krr.Header().Ttl
						}
					}
					exp := time.Now().Add(time.Duration(minTTL) * time.Second)
					for _, krr := range dkeys.RRs {
						if dk, ok := krr.(*dns.DNSKEY); ok {
							dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
								Name:       dns.Fqdn(dk.Hdr.Name),
								Keyid:      dk.KeyTag(),
								Validated:  false,
								Trusted:    false,
								Dnskey:     *dk,
								Expiration: exp,
							})
							if verbose {
								log.Printf("ValidateRRset: cached fetched DNSKEY (untrusted) %q::%d exp=%v", dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), exp)
							}
						}
					}
					// Attempt to validate the fetched DNSKEY RRset using DS and promote keys to trusted if successful
					if ok, _ := rrcache.ValidateDNSKEYs(ctx, dkc, dkeys, verbose); ok {
						if verbose {
							log.Printf("ValidateRRset: signer DNSKEY RRset for %q validated; promoting keys to trusted", signer)
						}
						for _, krr := range dkeys.RRs {
							if dk, ok := krr.(*dns.DNSKEY); ok {
								dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
									Name:       dns.Fqdn(dk.Hdr.Name),
									Keyid:      dk.KeyTag(),
									Validated:  true,
									Trusted:    true,
									Dnskey:     *dk,
									Expiration: exp,
								})
							}
						}
					}
				} else if err != nil && verbose {
					log.Printf("ValidateRRset: failed fetching DNSKEY for %q: %v", signer, err)
				}
			}
			}
			ta = dkc.Get(signer, keyid)
		}
		// Require a trusted key for a positive validation result
		if ta == nil || !ta.Trusted {
			if Globals.Debug {
				if ta == nil {
					log.Printf("ValidateRRset: no TA in cache for %q::%d", signer, keyid)
				} else {
					log.Printf("ValidateRRset: TA present but not trusted for %q::%d", signer, keyid)
				}
			}
			continue
		}
		if err := sig.Verify(&ta.Dnskey, rrset.RRs); err != nil {
			if verbose {
				log.Printf("ValidateRRset: signature verify FAILED for %s %s using %s::%d: %v",
					rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid, err)
			}
			continue
		}
		// Time validity
		if WithinValidityPeriod(sig.Inception, sig.Expiration, time.Now().UTC()) {
			if Globals.Debug {
				log.Printf("ValidateRRset: signature verify OK and within validity window for %s %s using %s::%d",
					rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid)
			}
			if Globals.Debug {
				log.Printf("ValidateRRset: SUCCESS")
			}
			return true, nil
		}
		if Globals.Verbose {
			log.Printf("ValidateRRset: signature time INVALID for %s %s using %s::%d (inc=%d exp=%d now=%d)",
				rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid, sig.Inception, sig.Expiration, time.Now().UTC().Unix())
		}
	}
	if Globals.Verbose {
		log.Printf("ValidateRRset: no acceptable signature validated for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
	}
	return false, nil
}

// ValidateDNSKEYs validates a DNSKEY RRset using DS from the parent and the specific KSK named in the RRSIG.
// Steps:
// 1) Identify signer (apex) and key tag from an RRSIG covering DNSKEY.
// 2) Find the matching DNSKEY in the RRset (should be KSK).
// 3) Ensure a validated DS RRset for this apex exists in the cache.
// 4) Match the DNSKEY against any DS digest present.
// 5) Verify the DNSKEY RRset RRSIG with the matched DNSKEY and time window.
func (rrcache *RRsetCacheT) ValidateDNSKEYs(ctx context.Context, dkc *DnskeyCacheT, rrset *core.RRset, verbose bool) (bool, error) {
	if rrset == nil {
		return false, nil
	}
	if len(rrset.RRSIGs) == 0 {
		if verbose {
			log.Printf("ValidateDNSKEYs: no signatures for %s", rrset.Name)
		}
		return false, nil
	}
	name := dns.Fqdn(rrset.Name)
	if verbose {
		log.Printf("ValidateDNSKEYs: start: owner=%q rrs=%d sigs=%d", name, len(rrset.RRs), len(rrset.RRSIGs))
	}
	// 1) Find an RRSIG that covers DNSKEY; grab signer and key tag
	var chosenSig *dns.RRSIG
	for _, rr := range rrset.RRSIGs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDNSKEY {
			chosenSig = sig
			break
		}
	}
	if chosenSig == nil {
		if verbose {
			log.Printf("ValidateDNSKEYs: no RRSIG(DNSKEY) present for %s", name)
		}
		return false, nil
	}
	signer := dns.Fqdn(chosenSig.SignerName)
	keyid := chosenSig.KeyTag
	if signer != name && verbose {
		log.Printf("ValidateDNSKEYs: warning: signer %q != owner %q (continuing)", signer, name)
	}
	if verbose {
		log.Printf("ValidateDNSKEYs: signer=%q keyid=%d", signer, keyid)
	}
	// 2) Locate the matching DNSKEY in the RRset
	var signerKey *dns.DNSKEY
	for _, rr := range rrset.RRs {
		if dk, ok := rr.(*dns.DNSKEY); ok && dk.KeyTag() == keyid {
			signerKey = dk
			break
		}
	}
	if signerKey == nil {
		if verbose {
			log.Printf("ValidateDNSKEYs: DNSKEY with keytag %d not found in RRset %s", keyid, name)
		}
		return false, nil
	}
	if verbose {
		log.Printf("ValidateDNSKEYs: candidate DNSKEY flags=%d alg=%d", signerKey.Flags, signerKey.Algorithm)
	}
	// Special-case the root: there is no DS for ".", validate using configured trust anchor DNSKEY directly
	if name == "." {
		ta := dkc.Get(name, keyid)
		if ta == nil || !ta.Trusted {
			if verbose {
				if ta == nil {
					log.Printf("ValidateDNSKEYs: no TA for root keyid=%d", keyid)
				} else {
					log.Printf("ValidateDNSKEYs: root TA present but not trusted for keyid=%d", keyid)
				}
			}
			return false, nil
		}
		if err := chosenSig.Verify(&ta.Dnskey, rrset.RRs); err != nil {
			if verbose {
				log.Printf("ValidateDNSKEYs: root signature verify FAILED: %v", err)
			}
			return false, nil
		}
		if !WithinValidityPeriod(chosenSig.Inception, chosenSig.Expiration, time.Now().UTC()) {
			if verbose {
				log.Printf("ValidateDNSKEYs: root signature time INVALID (inc=%d exp=%d now=%d)",
					chosenSig.Inception, chosenSig.Expiration, time.Now().UTC().Unix())
			}
			return false, nil
		}
		if verbose {
			log.Printf("ValidateDNSKEYs: SUCCESS for root with keytag=%d", keyid)
		}
		return true, nil
	}
	// 3) Retrieve DS RRset for this apex from cache and require it to be validated
	var dsRRs *CachedRRset
	if rrcache != nil {
		dsRRs = rrcache.Get(name, dns.TypeDS)
	}
	if dsRRs == nil || dsRRs.RRset == nil || !dsRRs.Validated || len(dsRRs.RRset.RRs) == 0 {
		if verbose {
			log.Printf("ValidateDNSKEYs: validated DS RRset for %s not present in cache", name)
		}
		return false, nil
	}
	// 4) Match signerKey to any DS in DS RRset
	var dsMatch bool
	for _, rr := range dsRRs.RRset.RRs {
		if ds, ok := rr.(*dns.DS); ok {
			if ds.KeyTag != keyid {
				continue
			}
			comp := signerKey.ToDS(ds.DigestType)
			if comp != nil && strings.EqualFold(comp.Digest, ds.Digest) {
				dsMatch = true
				break
			}
		}
	}
	if !dsMatch {
		if verbose {
			log.Printf("ValidateDNSKEYs: no DS matched DNSKEY %d at %s", keyid, name)
		}
		return false, nil
	}
	// 5) Verify the DNSKEY RRset signature with signerKey and time window
	if err := chosenSig.Verify(signerKey, rrset.RRs); err != nil {
		if verbose {
			log.Printf("ValidateDNSKEYs: signature verify FAILED for %s: %v", name, err)
		}
		return false, nil
	}
	if !WithinValidityPeriod(chosenSig.Inception, chosenSig.Expiration, time.Now().UTC()) {
		if verbose {
			log.Printf("ValidateDNSKEYs: signature time INVALID for %s (inc=%d exp=%d now=%d)",
				name, chosenSig.Inception, chosenSig.Expiration, time.Now().UTC().Unix())
		}
		return false, nil
	}
	if verbose {
		log.Printf("ValidateDNSKEYs: SUCCESS for %s with keytag=%d", name, keyid)
	}
	return true, nil
}

 func (rrcache *RRsetCacheT) ValidateNegativeResponse(ctx context.Context, qname string, qtype uint16, negAuthority []*core.RRset) bool {
	if len(negAuthority) == 0 {
		return false
	}
	if qtype == dns.TypeDNSKEY {
		// Cannot validate negative DNSKEY responses without the zone's DNSKEYs; treat as insecure/bogus
		if Globals.Debug {
			log.Printf("ValidateNegativeResponse: skipping validation for DNSKEY negative response at %q", qname)
		}
		return false
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
	if soarrset == nil || len(soarrset.RRs) == 0 {
		return false
	}
	zoneName := dns.CanonicalName(soarrset.Name)
	if !strings.HasSuffix(qnameCanon, zoneName) {
		return false
	}
	if !hasSignatures {
		return true
	}
	for _, set := range negAuthority {
		if set == nil || len(set.RRSIGs) == 0 {
			continue
		}
		if ok, _ := rrcache.ValidateRRset(ctx, DnskeyCache, set, rrcache.Debug); !ok {
			return false
		}
	}
	if len(nsecs) > 0 {
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
		return coveredQname && coveredWildcard
	}
	if nsec3Present {
		return true
	}
	return false
}
