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

	core "github.com/johanix/tdns/v0.x/tdns/core"
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

// ParentZoneFinder finds the authoritative zone for a given domain name.
// It should check the cache first and only query if necessary.
// Returns the zone name and an error if not found.
type ParentZoneFinder func(name string) (string, error)

// validateRRsetWithRRSIG validates a single RRSIG against an RRset.
// Returns:
//   - valid: true if the signature is valid and time-valid
//   - shouldReturnEarly: true if we should return early (signer zone indeterminate or DNSKEY validation indeterminate)
//   - returnState: the state to return if shouldReturnEarly is true
//   - err: error if something went wrong
func (rrcache *RRsetCacheT) validateRRsetWithRRSIG(ctx context.Context, rrset *core.RRset, sig *dns.RRSIG, dkc *DnskeyCacheT, fetcher RRsetFetcher) (valid bool, shouldReturnEarly bool, returnState ValidationState, err error) {
	signer := dns.Fqdn(sig.SignerName)
	keyid := sig.KeyTag
	if rrcache.Debug {
		log.Printf("ValidateRRset: evaluating signature: signer=%q keyid=%d covered=%s inception=%d expiration=%d",
			signer, keyid, dns.TypeToString[sig.TypeCovered], sig.Inception, sig.Expiration)
	}
	// Check the signer zone's state in ZoneMap. If indeterminate or insecure, we cannot validate.
	if zone, ok := rrcache.ZoneMap.Get(signer); ok {
		switch zone.GetState() {
		case ValidationStateIndeterminate:
			if rrcache.Debug {
				log.Printf("ValidateRRset: signer zone %q is indeterminate; returning indeterminate state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
			}
			return false, true, ValidationStateIndeterminate, nil
		case ValidationStateInsecure:
			// Unsigned zone - signed RRsets cannot be validated (no chain of trust)
			if rrcache.Verbose {
				log.Printf("ValidateRRset: signer zone %q is insecure (unsigned); cannot validate signed RRset %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
			}
			return false, true, ValidationStateInsecure, nil
		}
	}

	dkrr := dkc.Get(signer, keyid)
	if rrcache.Debug {
		log.Printf("ValidateRRset: TA %q::%d in cache: %+v", signer, keyid, dkrr)
	}
	if dkrr == nil && ctx != nil {
		// Before attempting to fetch, check again if signer zone is indeterminate or insecure
		// (it might have been added to ZoneMap since the initial check)
		if zone, ok := rrcache.ZoneMap.Get(signer); ok {
			switch zone.GetState() {
			case ValidationStateIndeterminate:
				if rrcache.Verbose {
					log.Printf("ValidateRRset: signer zone %q is indeterminate; skipping DNSKEY fetch and returning indeterminate state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
				}
				return false, true, ValidationStateIndeterminate, nil
			case ValidationStateInsecure:
				// Unsigned zone - cannot fetch DNSKEYs for validation
				if rrcache.Verbose {
					log.Printf("ValidateRRset: signer zone %q is insecure (unsigned); skipping DNSKEY fetch and returning bogus state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
				}
				return false, true, ValidationStateInsecure, nil
			}
		}
		if rrcache.Verbose {
			log.Printf("ValidateRRset: signer DNSKEY %q::%d not in cache; attempting to obtain keys", signer, keyid)
		}
		// Attempt to fetch the signer's DNSKEY to populate cache (chain trust evaluated by caller)
		_, servers, err := rrcache.FindClosestKnownZone(signer)
		if err != nil {
			log.Printf("ValidateRRset: FindClosestKnownZone(%q) failed: %v", signer, err)
			// Check zone state again - might have been marked indeterminate
			if zone, ok := rrcache.ZoneMap.Get(signer); ok && zone.GetState() == ValidationStateIndeterminate {
				return false, true, ValidationStateIndeterminate, nil
			}
			return false, false, ValidationStateNone, nil
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
			// Final check before issuing query: if signer zone is indeterminate or insecure, don't query
			if zone, ok := rrcache.ZoneMap.Get(signer); ok {
				switch zone.GetState() {
				case ValidationStateIndeterminate:
					if rrcache.Verbose {
						log.Printf("ValidateRRset: signer zone %q is indeterminate; skipping DNSKEY query and returning indeterminate state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
					}
					return false, true, ValidationStateIndeterminate, nil
				case ValidationStateInsecure:
					// Unsigned zone - cannot query DNSKEYs
					if rrcache.Verbose {
						log.Printf("ValidateRRset: signer zone %q is insecure (unsigned); skipping DNSKEY query and returning bogus state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
					}
					return false, true, ValidationStateInsecure, nil
				}
			}
			log.Printf("ValidateRRset: issuing a DNS query for DNSKEY RRset from the signer zone %q", signer)
			// Fetch DNSKEYs from the signer zone
			if dkeys, err := fetcher(ctx, signer, dns.TypeDNSKEY, servers); err == nil && dkeys != nil && len(dkeys.RRs) > 0 {
				if rrcache.Debug {
					log.Printf("ValidateRRset: fetched %d DNSKEY RRs for %q", len(dkeys.RRs), signer)
				}
				// Add fetched keys to cache only after DS-based validation has been performed.
				// Compute min TTL for expiration.
				exp := time.Now().Add(GetMinTTL(dkeys.RRs))

				// Attempt to validate the fetched DNSKEY RRset using DS before adding to DnskeyCache
				// Only add validated/secure DNSKEYs to DnskeyCache, as it's used for validation of other data
				vstate, err := rrcache.ValidateDNSKEYs(ctx, dkeys, fetcher)
				if err != nil {
					log.Printf("ValidateRRset: failed validating DNSKEYs for %q: %v", signer, err)
					return false, true, vstate, err
				}
				if vstate == ValidationStateSecure {
					if rrcache.Verbose {
						log.Printf("ValidateRRset: signer DNSKEY RRset for %q validated; adding keys to DnskeyCache", signer)
					}
					for _, krr := range dkeys.RRs {
						if dk, ok := krr.(*dns.DNSKEY); ok {
							dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
								Name:  dns.Fqdn(dk.Hdr.Name),
								Keyid: dk.KeyTag(),
								State: vstate,
								//Trusted:    true,
								Dnskey:     *dk,
								Expiration: exp,
							})
						}
					}
				} else if vstate == ValidationStateIndeterminate {
					// If signer DNSKEYs are indeterminate, we cannot validate this RRset
					// Update ZoneMap to mark the zone as indeterminate so we don't query again
					zone, ok := rrcache.ZoneMap.Get(signer)
					if !ok {
						zone = &Zone{
							ZoneName: signer,
							State:    ValidationStateIndeterminate,
						}
					}
					if ok {
						zone.SetState(ValidationStateIndeterminate)
					}
					rrcache.ZoneMap.Set(signer, zone)
					if rrcache.Verbose {
						log.Printf("ValidateRRset: signer zone %q DNSKEYs are indeterminate; marking zone as indeterminate and returning indeterminate state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
					}
					return false, true, ValidationStateIndeterminate, nil
				} else {
					if rrcache.Verbose {
						log.Printf("ValidateRRset: signer DNSKEY RRset for %q did not validate (vstate: %s); not adding to DnskeyCache", signer, ValidationStateToString[vstate])
					}
				}
			} else if err != nil && rrcache.Verbose {
				log.Printf("ValidateRRset: failed fetching DNSKEY for %q: %v", signer, err)
			}
		}
		// After attempting to fetch, check again if signer zone became indeterminate or insecure
		// (might have been marked during DNSKEY validation)
		if zone, ok := rrcache.ZoneMap.Get(signer); ok {
			switch zone.GetState() {
			case ValidationStateIndeterminate:
				if rrcache.Verbose {
					log.Printf("ValidateRRset: signer zone %q is indeterminate (after DNSKEY fetch attempt); returning indeterminate state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
				}
				return false, true, ValidationStateIndeterminate, nil
			case ValidationStateInsecure:
				// Unsigned zone detected after fetch attempt
				if rrcache.Verbose {
					log.Printf("ValidateRRset: signer zone %q is insecure/unsigned (after DNSKEY fetch attempt); returning insecure state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
				}
				return false, true, ValidationStateInsecure, nil
			}
		}
		dkrr = dkc.Get(signer, keyid)
	}
	// Require a trusted key for a positive validation result
	if dkrr == nil || dkrr.State != ValidationStateSecure {
		if rrcache.Debug {
			if dkrr == nil {
				log.Printf("ValidateRRset: no DNSKEY in cache for %q::%d", signer, keyid)
			} else {
				log.Printf("ValidateRRset: DNSKEY present but not secure for %q::%d", signer, keyid)
			}
		}
		// Before continuing, check if signer zone is indeterminate or insecure (might have been added to ZoneMap during DNSKEY fetch)
		if zone, ok := rrcache.ZoneMap.Get(signer); ok {
			switch zone.GetState() {
			case ValidationStateIndeterminate:
				if rrcache.Verbose {
					log.Printf("ValidateRRset: signer zone %q is indeterminate; returning indeterminate state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
				}
				return false, true, ValidationStateIndeterminate, nil
			case ValidationStateInsecure:
				// Unsigned zone - cannot validate signed RRsets
				if rrcache.Verbose {
					log.Printf("ValidateRRset: signer zone %q is insecure/unsigned; returning insecure state for %s %s", signer, rrset.Name, dns.TypeToString[rrset.RRtype])
				}
				return false, true, ValidationStateInsecure, nil
			}
		}

		return false, false, ValidationStateNone, nil
	}
	if err := sig.Verify(&dkrr.Dnskey, rrset.RRs); err != nil {
		if rrcache.Verbose {
			log.Printf("ValidateRRset: signature verify FAILED for %s %s using %s::%d: %v",
				rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid, err)
		}
		return false, false, ValidationStateNone, nil
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
					State:    ValidationStateIndeterminate,
				}
			}
			zone.SetState(ValidationStateSecure)
			rrcache.ZoneMap.Set(rrset.Name, zone)
		}
		// cap ttl to the signature expiration
		expirationTime := time.Unix(int64(sig.Expiration), 0)
		remaining := time.Until(expirationTime)
		ttl := time.Duration(remaining.Seconds()) * time.Second
		if ttl < GetMinTTL(rrset.RRs) {
			for _, rr := range rrset.RRs {
				rr.Header().Ttl = uint32(ttl.Seconds())
			}
		}
		return true, false, ValidationStateNone, nil
	}
	if rrcache.Verbose {
		log.Printf("ValidateRRset: signature time INVALID for %s %s using %s::%d (inc=%d exp=%d now=%d)",
			rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid, sig.Inception, sig.Expiration, time.Now().UTC().Unix())
	}
	return false, false, ValidationStateNone, nil
}

// ValidateRRset attempts to validate the provided RRset using DNSKEYs present in the DnskeyCache.
// If a required signer key is missing, it will query for the signer's DNSKEY via the recursive
// engine and retry using keys from the cache. Only keys marked as ValidateionStateSecure are accepted for
// successful validation. Returns ValidationStateSecure if at least one signature validates and is time-valid.
func (rrcache *RRsetCacheT) ValidateRRset(ctx context.Context, rrset *core.RRset, fetcher RRsetFetcher) (ValidationState, error) {
	return rrcache.ValidateRRsetWithParentZone(ctx, rrset, fetcher, nil)
}

// ValidateRRsetWithParentZone validates an RRset, optionally using a ParentZoneFinder to find the authoritative zone.
// If parentZoneFinder is nil, it falls back to checking ZoneMap by walking up the domain name.
// If the RRset is already cached with a validation state, that state is returned without re-validating.
func (rrcache *RRsetCacheT) ValidateRRsetWithParentZone(ctx context.Context, rrset *core.RRset, fetcher RRsetFetcher, parentZoneFinder ParentZoneFinder) (ValidationState, error) {
	if rrcache == nil {
		log.Printf("ValidateRRset: rrcache is nil; nothing to validate")
		return ValidationStateNone, fmt.Errorf("rrcache is nil; nothing to validate")
	}
	if rrset == nil {
		log.Printf("ValidateRRset: rrset is nil; nothing to validate")
		return ValidationStateNone, fmt.Errorf("rrset is nil; nothing to validate")
	}

	// Check cache first - if we already have this RRset validated and it hasn't changed or expired, reuse the validation state
	cached := rrcache.Get(rrset.Name, rrset.RRtype)
	if cached != nil && cached.State != ValidationStateNone {
		// Get() already checks expiration and returns nil if expired, so if cached is not nil, it's not expired
		// But we double-check expiration to be explicit about the semantics
		if cached.Expiration.Before(time.Now()) {
			if rrcache.Verbose {
				log.Printf("ValidateRRset: cached RRset for %s %s has expired, re-validating", rrset.Name, dns.TypeToString[rrset.RRtype])
			}
			// Fall through to re-validate
		} else if cached.RRset != nil {
			// Check if the RRset content has changed by comparing RRs and RRSIGs
			// Use RRsetDiffer for RRs (it skips RRSIGs, which is what we want for data comparison)
			// Then separately compare RRSIGs
			rrsetDiffer, _, _ := cached.RRset.RRsetDiffer(rrset, log.Default(), false, false)
			// XXX: Should we really care about comparing RRSIGs? Or perhaps only compare inception?
			rrsigDiffer := cached.RRset.RRSIGsDiffer(rrset)

			if !rrsetDiffer && !rrsigDiffer {
				// RRset hasn't changed and hasn't expired - reuse cached validation state
				if rrcache.Debug {
					log.Printf("ValidateRRset: using cached validation state %s for %s %s (RRset unchanged, not expired)", ValidationStateToString[cached.State], rrset.Name, dns.TypeToString[rrset.RRtype])
				}
				return cached.State, nil
			} else {
				if rrcache.Debug {
					log.Printf("ValidateRRset: cached RRset for %s %s has changed (RRs differ: %v, RRSIGs differ: %v), re-validating", rrset.Name, dns.TypeToString[rrset.RRtype], rrsetDiffer, rrsigDiffer)
				}
				// Fall through to re-validate
			}
		} else {
			// Cached RRset is nil - fall through to validate
			if rrcache.Debug {
				log.Printf("ValidateRRset: cached entry for %s %s has no RRset, re-validating", rrset.Name, dns.TypeToString[rrset.RRtype])
			}
		}
	}

	dkc := rrcache.DnskeyCache

	if rrcache.Debug {
		rrsetStr := rrset.String(rrcache.LineWidth)
		log.Printf("ValidateRRset: start: rrset:")
		log.Printf("%s", rrsetStr)
	}

	log.Printf("ValidateRRset: start: owner=%q type=%s sigs=%d rrs=%d",
		rrset.Name, dns.TypeToString[rrset.RRtype], len(rrset.RRSIGs), len(rrset.RRs))

	// Early check: if the zone containing this RRset is insecure (unsigned),
	// return insecure state (regardless of whether RRset has RRSIGs or not)
	zoneName := dns.Fqdn(rrset.Name)
	if zone, ok := rrcache.ZoneMap.Get(zoneName); ok && zone.GetState() == ValidationStateInsecure {
		if rrcache.Verbose {
			log.Printf("ValidateRRset: zone %q is insecure (unsigned); returning insecure state for %s %s", zoneName, rrset.Name, dns.TypeToString[rrset.RRtype])
		}
		return ValidationStateInsecure, nil
	}

	// Special-case DNSKEY RRset validation: must anchor via DS and the specific KSK
	if rrset.RRtype == dns.TypeDNSKEY {
		if rrcache.Debug {
			log.Printf("ValidateRRset: validating %s DNSKEY RRset; handing over to ValidateDNSKEYs", rrset.Name)
		}
		// ValidateDNSKEYs will add keys to DnskeyCache upon successful validation
		return rrcache.ValidateDNSKEYs(ctx, rrset, fetcher)
	}
	if len(rrset.RRSIGs) == 0 {
		if rrcache.Debug {
			log.Printf("ValidateRRset: no RRSIGs present for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
		}
		// Check zone state to determine appropriate return value
		// Find the authoritative zone for this RRset (rrset.Name might be a nameserver name for glue records, not the zone name)
		name := dns.Fqdn(rrset.Name)
		var foundZone *Zone
		var foundZoneName string

		if parentZoneFinder != nil {
			// Use ParentZoneFinder to find the authoritative zone (checks cache first, queries if needed)
			zoneName, err := parentZoneFinder(name)
			if err == nil && zoneName != "" {
				if zone, ok := rrcache.ZoneMap.Get(zoneName); ok {
					foundZone = zone
					foundZoneName = zoneName
				}
			}
		}

		// Fallback: walk up the domain name and check ZoneMap
		if foundZone == nil {
			labels := strings.Split(name, ".")
			for i := 0; i < len(labels)-1; i++ {
				zoneName := strings.Join(labels[i:], ".")
				if zone, ok := rrcache.ZoneMap.Get(zoneName); ok {
					foundZone = zone
					foundZoneName = zoneName
					break
				}
			}
		}

		if foundZone != nil {
			if rrcache.Debug {
				log.Printf("ValidateRRset: found zone %q for %s %s (state=%s)", foundZoneName, rrset.Name, dns.TypeToString[rrset.RRtype], ValidationStateToString[foundZone.GetState()])
			}
			switch foundZone.GetState() {
			case ValidationStateIndeterminate, ValidationStateInsecure:
				return foundZone.GetState(), nil
			default:
				return ValidationStateInsecure, nil
			}
		}
		// No zone found - return indeterminate without flagging an error
		// This can happen during priming before zone state is established
		if rrcache.Verbose {
			log.Printf("ValidateRRset: no zone found for %s %s; returning indeterminate", rrset.Name, dns.TypeToString[rrset.RRtype])
		}
		return ValidationStateIndeterminate, nil
	}

	for _, rr := range rrset.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			if rrcache.Debug {
				log.Printf("ValidateRRset: skipping non-RRSIG in RRSIGs slice: %T", rr)
			}
			continue
		}
		valid, shouldReturnEarly, returnState, err := rrcache.validateRRsetWithRRSIG(ctx, rrset, sig, dkc, fetcher)
		if err != nil {
			return returnState, err
		}
		if shouldReturnEarly {
			return returnState, nil
		}
		if valid {
			return ValidationStateSecure, nil
		}
		// Continue to next signature
	}
	if rrcache.Verbose {
		log.Printf("ValidateRRset: no acceptable signature validated for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
	}
	// All signatures failed validation - return bogus
	// Note: We don't need to check for indeterminate zones here because the helper function
	// already checks for indeterminate zones and returns early, so we would have returned
	// earlier if any signer zone was indeterminate.
	return ValidationStateBogus, nil
}

// ValidateDNSKEYRRsetUsingDS validates a DNSKEY RRset using a DS record.
// It finds the DNSKEY in the RRset that matches the DS (by keytag, SEP bit, and digest),
// then validates the RRset signature using that DNSKEY.
// Returns true if validation succeeds, false otherwise. Also returns the candidate DNSKEY if found.
// The function may modify the TTLs of RRs in rrset (capping them to signature expiration) but does not modify any caches.
func ValidateDNSKEYRRsetUsingDS(rrset *core.RRset, ds *dns.DS, signerName string, verbose bool) (bool, *dns.DNSKEY) {
	if rrset == nil || ds == nil {
		return false, nil
	}
	name := dns.Fqdn(signerName)
	keyid := ds.KeyTag

	// Find the DNSKEY that matches this DS record
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
			log.Printf("validateDNSKEYRRsetUsingDS: no DNSKEY with keytag=%d and matching DS digest at %s", keyid, name)
		}
		return false, nil
	}

	// Validate DNSKEY RRset signature using candidateKey
	valid, _ := ValidateDNSKEYRRsetSignature(rrset, keyid, name, candidateKey, verbose)
	if !valid {
		return false, candidateKey
	}

	return true, candidateKey
}

// ValidateDNSKEYRRsetSignature validates a DNSKEY RRset signature using a provided DNSKEY.
// It finds the RRSIG(DNSKEY) signed by the specified key, verifies the signature, checks time validity,
// and caps TTLs to signature expiration if necessary.
// Returns true if validation succeeds, false otherwise. Also returns the RRSIG if found.
// signature's expiration; it does not modify any caches.
func ValidateDNSKEYRRsetSignature(rrset *core.RRset, keyid uint16, signerName string, dnskey *dns.DNSKEY, verbose bool) (bool, *dns.RRSIG) {
	if rrset == nil || dnskey == nil {
		return false, nil
	}
	name := dns.Fqdn(signerName)

	// Find an RRSIG(DNSKEY) created by this key
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
			log.Printf("validateDNSKEYRRsetSignature: no RRSIG(DNSKEY) found for keytag=%d at %s", keyid, name)
		}
		return false, nil
	}

	// Verify the DNSKEY RRset signature
	if err := sigForKey.Verify(dnskey, rrset.RRs); err != nil {
		if verbose {
			log.Printf("validateDNSKEYRRsetSignature: signature verify FAILED for %s with keytag=%d: %v", name, keyid, err)
		}
		return false, sigForKey
	}

	// Check time validity
	if !WithinValidityPeriod(sigForKey.Inception, sigForKey.Expiration, time.Now().UTC()) {
		if verbose {
			log.Printf("validateDNSKEYRRsetSignature: signature time INVALID for %s with keytag=%d (inc=%d exp=%d now=%d)",
				name, keyid, sigForKey.Inception, sigForKey.Expiration, time.Now().UTC().Unix())
		}
		return false, sigForKey
	}

	// Cap TTL to signature expiration
	minTTL := GetMinTTL(rrset.RRs)
	expirationTime := time.Unix(int64(sigForKey.Expiration), 0)
	remaining := time.Until(expirationTime)
	expttl := time.Duration(remaining.Seconds()) * time.Second
	if expttl < minTTL {
		if len(rrset.RRs) > 0 {
			expttlSeconds := uint32(expttl.Seconds())
			for _, krr := range rrset.RRs {
				krr.Header().Ttl = expttlSeconds
			}
		}
	}

	if verbose {
		log.Printf("validateDNSKEYRRsetSignature: SUCCESS for %s with keytag=%d", name, keyid)
	}
	return true, sigForKey
}

// ValidateDNSKEYs validates a DNSKEY RRset using DS from the parent and the specific KSK named in the RRSIG.
// Steps:
// 1) Identify signer (apex) and key tag from an RRSIG covering DNSKEY.
// 2) Find the matching DNSKEY in the RRset (should be KSK).
// 3) Ensure a validated DS RRset for this apex exists in the cache.
// 4) Match the DNSKEY against any DS digest present.
// 5) Verify the DNSKEY RRset RRSIG with the matched DNSKEY and time window.
func (rrcache *RRsetCacheT) ValidateDNSKEYs(ctx context.Context, rrset *core.RRset, fetcher RRsetFetcher) (ValidationState, error) {
	if rrcache == nil {
		return ValidationStateNone, fmt.Errorf("rrcache is nil")
	}

	if rrset == nil {
		log.Printf("ValidateDNSKEYs: rrset is nil; nothing to validate")
		return ValidationStateNone, fmt.Errorf("rrset is nil; nothing to validate")
	}

	if rrcache.Debug {
		rrsetStr := rrset.String(rrcache.LineWidth)
		log.Printf("ValidateDNSKEYs: start: rrset:")
		log.Printf("%s", rrsetStr)
	}

	dkc := rrcache.DnskeyCache
	name := dns.Fqdn(rrset.Name)
	if rrcache.Verbose {
		log.Printf("ValidateDNSKEYs: start: owner=%q rrs=%d sigs=%d", name, len(rrset.RRs), len(rrset.RRSIGs))
	}

	var zstate ValidationState

	// Check if zone is in ZoneMap and return early for cases not requiring further validation
	if zone, ok := rrcache.ZoneMap.Get(name); ok {
		zstate = zone.GetState()
		switch zstate {
		case ValidationStateIndeterminate, ValidationStateInsecure:
			if rrcache.Verbose {
				log.Printf("ValidateDNSKEYs: zone %q is %s; returning %s state", name, ValidationStateToString[zstate], ValidationStateToString[zstate])
			}
			return zstate, nil
		}
	} else {
		// Zone not in ZoneMap yet - check if we have a DS in cache
		// If DS is not secure, we cannot validate DNSKEYs, so return the DS state
		if name != "." {
			dsRRs := rrcache.Get(name, dns.TypeDS)
			if dsRRs != nil && dsRRs.State != ValidationStateSecure {
				// DS is not secure (indeterminate, bogus, or insecure), so zone should have the same state
				zone := &Zone{
					ZoneName: name,
					State:    dsRRs.State,
				}
				rrcache.ZoneMap.Set(name, zone)
				if rrcache.Verbose {
					log.Printf("ValidateDNSKEYs: zone %q not in ZoneMap but DS is %s; marking zone as %s and returning", name, ValidationStateToString[dsRRs.State], ValidationStateToString[dsRRs.State])
				}
				return dsRRs.State, nil
			}
		}
	}

	// OPTIMIZATION: Check for cached DS first (common case)
	// For root, there is no DS by definition, so skip this check
	var dsRRs *CachedRRset
	if name != "." {
		dsRRs = rrcache.Get(name, dns.TypeDS)
		// If DS exists but is not secure, we cannot validate DNSKEYs
		if dsRRs != nil && dsRRs.State != ValidationStateSecure {
			// Mark zone with same state as DS and return
			zone, ok := rrcache.ZoneMap.Get(name)
			if !ok {
				zone = &Zone{
					ZoneName: name,
					State:    dsRRs.State,
				}
				rrcache.ZoneMap.Set(name, zone)
			} else {
				zone.SetState(dsRRs.State)
				rrcache.ZoneMap.Set(name, zone)
			}
			if rrcache.Verbose {
				log.Printf("ValidateDNSKEYs: DS for %q is %s; cannot validate DNSKEYs, returning %s", name, ValidationStateToString[dsRRs.State], ValidationStateToString[dsRRs.State])
			}
			return dsRRs.State, nil
		}
	}

	// If DS exists and is secure, use it directly (fast path)
	if dsRRs != nil && dsRRs.RRset != nil && len(dsRRs.RRset.RRs) > 0 && dsRRs.State == ValidationStateSecure {
		// Use DS-based validation (common case)
		for _, rr := range dsRRs.RRset.RRs {
			ds, ok := rr.(*dns.DS)
			if !ok {
				continue
			}
			valid, _ := ValidateDNSKEYRRsetUsingDS(rrset, ds, name, rrcache.Verbose)
			if !valid {
				continue
			}
			// Add all DNSKEYs from the validated RRset to DnskeyCache
			minTTL := GetMinTTL(rrset.RRs)
			exp := time.Now().Add(minTTL)
			for _, krr := range rrset.RRs {
				if dk, ok := krr.(*dns.DNSKEY); ok {
					dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
						Name:  dns.Fqdn(dk.Hdr.Name),
						Keyid: dk.KeyTag(),
						State: ValidationStateSecure,
						// Trusted:    true,
						Dnskey:     *dk,
						Expiration: exp,
					})
				}
			}
			if rrcache.Verbose {
				log.Printf("ValidateDNSKEYs: added %d DNSKEYs to DnskeyCache for %q", len(rrset.RRs), name)
			}
			return ValidationStateSecure, nil
		}
		if rrcache.Verbose {
			log.Printf("ValidateDNSKEYs: no DS-backed DNSKEY/RRSIG combination validated for %s", name)
		}
		return ValidationStateBogus, nil
	}

	// No cached DS or DS not secure - check for TA initialization alternatives
	// Check for trust anchor DNSKEYs and seeded DS records
	var taKeys []*CachedDnskeyRRset
	var seededDSs []*CachedRRset

	// Check for trust anchor DNSKEYs
	for item := range dkc.Map.IterBuffered() {
		if item.Val.Name == name && item.Val.TrustAnchor && item.Val.State == ValidationStateSecure {
			taKeys = append(taKeys, &item.Val)
		}
	}
	// Check for seeded DS RRset (indicates DS-based TA initialization)
	if dsRRs == nil || dsRRs.State != ValidationStateSecure {
		if seededDS := rrcache.Get(name, dns.TypeDS); seededDS != nil && seededDS.State == ValidationStateSecure {
			seededDSs = append(seededDSs, seededDS)
		}
	}

	// If we have direct DNSKEY trust anchors, try those first
	if len(taKeys) > 0 {
		for _, taKey := range taKeys {
			// Validate using direct DNSKEY trust anchor
			valid, _ := ValidateDNSKEYRRsetSignature(rrset, taKey.Keyid, name, &taKey.Dnskey, rrcache.Verbose)
			if !valid {
				continue
			}
			// Add all DNSKEYs from the validated RRset to DnskeyCache
			// Preserve TrustAnchor flag if DNSKEY was already in cache as trust anchor
			minTTL := GetMinTTL(rrset.RRs)
			exp := time.Now().Add(minTTL)
			for _, krr := range rrset.RRs {
				if dk, ok := krr.(*dns.DNSKEY); ok {
					keyid := dk.KeyTag()
					trustAnchor := false
					if existing := dkc.Get(name, keyid); existing != nil {
						trustAnchor = existing.TrustAnchor
					}
					dkc.Set(dns.Fqdn(dk.Hdr.Name), keyid, &CachedDnskeyRRset{
						Name:        dns.Fqdn(dk.Hdr.Name),
						Keyid:       keyid,
						State:       ValidationStateSecure,
						TrustAnchor: trustAnchor, // Preserve trust anchor flag
						Dnskey:      *dk,
						Expiration:  exp,
					})
				}
			}
			if rrcache.Verbose {
				log.Printf("ValidateDNSKEYs: added %d DNSKEYs to DnskeyCache for %q", len(rrset.RRs), name)
			}
			return ValidationStateSecure, nil
		}
		// none of the TA keys validated, return bogus
		return ValidationStateBogus, nil
	}

	// If we get here then there is no secure DS to validate against, so existence of seeded DS are the last hope
	// If we have seeded DS records, try those
	if len(seededDSs) > 0 {
		if rrcache.Verbose {
			log.Printf("ValidateDNSKEYs: no DS RRset for %q but has %d seeded DS", name, len(seededDSs))
		}
		// If we're in TA initialization with seeded DS records, validate using those
		// Validate against seeded DS records
		for _, seededDS := range seededDSs {
			if seededDS.RRset == nil || len(seededDS.RRset.RRs) == 0 {
				continue
			}
			for _, rr := range seededDS.RRset.RRs {
				ds, ok := rr.(*dns.DS)
				if !ok {
					continue
				}
				valid, _ := ValidateDNSKEYRRsetUsingDS(rrset, ds, name, rrcache.Verbose)
				if !valid {
					continue
				}
				// Add all DNSKEYs from the validated RRset to DnskeyCache
				minTTL := GetMinTTL(rrset.RRs)
				exp := time.Now().Add(minTTL)
				for _, krr := range rrset.RRs {
					if dk, ok := krr.(*dns.DNSKEY); ok {
						dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &CachedDnskeyRRset{
							Name:  dns.Fqdn(dk.Hdr.Name),
							Keyid: dk.KeyTag(),
							State: ValidationStateSecure,
							// Trusted:    true,
							Dnskey:     *dk,
							Expiration: exp,
						})
					}
				}
				if rrcache.Verbose {
					log.Printf("ValidateDNSKEYs: added %d DNSKEYs to DnskeyCache for %q (validated against seeded DS)", len(rrset.RRs), name)
				}
				return ValidationStateSecure, nil
			}
		}
		// None of the seeded DS records validated
		if rrcache.Verbose {
			log.Printf("ValidateDNSKEYs: no DNSKEY/RRSIG combination validated against seeded DS for %s", name)
		}
		return ValidationStateBogus, nil
	}

	// No DS, no TA keys, no seededDSs - cannot validate
	if rrcache.Verbose {
		if name == "." {
			log.Printf("ValidateDNSKEYs: root zone (no public DS by definition, no trust anchors found)")
		} else {
			log.Printf("ValidateDNSKEYs: no DS RRset for %q and no trust anchors found", name)
		}
	}
	return ValidationStateIndeterminate, nil
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
		vstate, err := rrcache.ValidateRRset(ctx, set, fetcher)
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
		return ValidationStateIndeterminate, rcode, nil // NSEC3 present, we do not yet verify them, but we assume they are secure
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