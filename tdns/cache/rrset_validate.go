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

// RRsetFetcher is a function type for fetching RRsets by querying authoritative servers.
// It takes a context, query name, query type, and a map of authoritative servers,
// and returns the fetched RRset or an error.
type RRsetFetcher func(ctx context.Context, qname string, qtype uint16, servers map[string]*AuthServer) (*core.RRset, error)

// ValidateRRset attempts to validate the provided RRset using DNSKEYs present in the DnskeyCache.
// If a required signer key is missing, it will query for the signer's DNSKEY via the recursive
// engine and retry using keys from the cache. Only keys marked as Trusted are accepted for
// successful validation. Returns true if at least one signature validates and is time-valid.
func (rrcache *RRsetCacheT) ValidateRRset(ctx context.Context, rrset *core.RRset, fetcher RRsetFetcher, verbose bool) (bool, ValidationState,error) {
	if rrset == nil {
		log.Printf("ValidateRRset: rrset is nil; nothing to validate")
		return false, ValidationStateNone, fmt.Errorf("rrset is nil; nothing to validate")
	}

	dkc := rrcache.DnskeyCache

	if rrcache.Debug {
		log.Printf("ValidateRRset: start: owner=%q type=%s sigs=%d rrs=%d",
			rrset.Name, dns.TypeToString[rrset.RRtype], len(rrset.RRSIGs), len(rrset.RRs))
	}
	// Special-case DNSKEY RRset validation: must anchor via DS and the specific KSK
	if rrset.RRtype == dns.TypeDNSKEY {
		return rrcache.ValidateDNSKEYs(ctx, rrset, fetcher, verbose)
	}
	if len(rrset.RRSIGs) == 0 {
		if rrcache.Debug {
			log.Printf("ValidateRRset: no RRSIGs present for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
		}
		return false, ValidationStateInsecure, nil // XXX: THis is wrong, we must know if the zone is insecure or not
	}
	if rrcache.Debug {
		log.Printf("ValidateRRset: start: owner=%q type=%s sigs=%d rrs=%d",
			rrset.Name, dns.TypeToString[rrset.RRtype], len(rrset.RRSIGs), len(rrset.RRs))
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
					// Add fetched keys to cache (not trusted by default). Trust must be established elsewhere.
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
					_, vstate, err := rrcache.ValidateDNSKEYs(ctx, dkeys, fetcher, verbose)
					if err != nil {
						log.Printf("ValidateRRset: failed validating DNSKEYs for %q: %v", signer, err)
						return false, vstate, err
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
									Validated:  true,
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
			return true, ValidationStateSecure, nil
		}
		if rrcache.Verbose {
			log.Printf("ValidateRRset: signature time INVALID for %s %s using %s::%d (inc=%d exp=%d now=%d)",
				rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid, sig.Inception, sig.Expiration, time.Now().UTC().Unix())
		}
	}
	if rrcache.Verbose {
		log.Printf("ValidateRRset: no acceptable signature validated for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
	}
	return false, ValidationStateInsecure, nil
}

// ValidateDNSKEYs validates a DNSKEY RRset using DS from the parent and the specific KSK named in the RRSIG.
// Steps:
// 1) Identify signer (apex) and key tag from an RRSIG covering DNSKEY.
// 2) Find the matching DNSKEY in the RRset (should be KSK).
// 3) Ensure a validated DS RRset for this apex exists in the cache.
// 4) Match the DNSKEY against any DS digest present.
// 5) Verify the DNSKEY RRset RRSIG with the matched DNSKEY and time window.
func (rrcache *RRsetCacheT) ValidateDNSKEYs(ctx context.Context, rrset *core.RRset, fetcher RRsetFetcher, verbose bool) (bool, ValidationState, error) {
	if rrset == nil {
		log.Printf("ValidateDNSKEYs: rrset is nil; nothing to validate")
		return false, ValidationStateNone, fmt.Errorf("rrset is nil; nothing to validate")
	}

	if rrset.RRtype == dns.TypeNS {
		fmt.Printf("ValidateDNSKEYs: rrset: %+v\n", rrset.String())
	}
	if len(rrset.RRSIGs) == 0 {
		if verbose {
			log.Printf("ValidateDNSKEYs: no signatures for %s", rrset.Name)
		}
		return false, ValidationStateInsecure, nil // XXX: THis is wrong, we must know if the zone is insecure or not
	}

	dkc := rrcache.DnskeyCache
	// fmt.Printf("ValidateDNSKEYs: dkc: %+v\n", dkc.Map.Keys())

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
		return false, ValidationStateBogus, nil // A DNSKEY RRset w/o RRSIGs is bogus
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
		return false, ValidationStateBogus, nil // A DNSKEY RRset signed by a key not in the RRset is bogus
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
			return false, ValidationStateIndeterminate, nil // XXX: No trust anchor for root
		}
		if err := chosenSig.Verify(&ta.Dnskey, rrset.RRs); err != nil {
			if verbose {
				log.Printf("ValidateDNSKEYs: root signature verify FAILED: %v", err)
			}
			return false, ValidationStateBogus, nil // XXX: No trust anchor for root
		}
		if !WithinValidityPeriod(chosenSig.Inception, chosenSig.Expiration, time.Now().UTC()) {
			if verbose {
				log.Printf("ValidateDNSKEYs: root signature time INVALID (inc=%d exp=%d now=%d)",
					chosenSig.Inception, chosenSig.Expiration, time.Now().UTC().Unix())
			}
			return false, ValidationStateBogus, nil // XXX: No trust anchor for root
		}
		if verbose {
			log.Printf("ValidateDNSKEYs: SUCCESS for root with keytag=%d", keyid)
		}
		return true, ValidationStateSecure, nil
	}
	// 3) Retrieve DS RRset for this apex from cache and require it to be validated
	var dsRRs *CachedRRset
	if rrcache != nil {
		dsRRs = rrcache.Get(name, dns.TypeDS)
	}
	if dsRRs == nil || dsRRs.RRset == nil || len(dsRRs.RRset.RRs) == 0 {
		if verbose {
			log.Printf("ValidateDNSKEYs: validated DS RRset for %s not present in cache", name)
		}
		return false, ValidationStateIndeterminate, nil // XXX: No validated DS RRset for this apex
	}

	if dsRRs.State != ValidationStateSecure {
		if verbose {
			log.Printf("ValidateDNSKEYs: validated DS RRset for %s is not secure", name)
		}
		return false, ValidationStateBogus, nil // XXX: If there is a DS RRset, it must be secure
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
		return false, ValidationStateBogus, nil // XXX: No DS matched the DNSKEY
	}
	// 5) Verify the DNSKEY RRset signature with signerKey and time window
	if err := chosenSig.Verify(signerKey, rrset.RRs); err != nil {
		if verbose {
			log.Printf("ValidateDNSKEYs: signature verify FAILED for %s: %v", name, err)
		}
		return false, ValidationStateBogus, nil // XXX: Signature verify failed
	}
	if !WithinValidityPeriod(chosenSig.Inception, chosenSig.Expiration, time.Now().UTC()) {
		if verbose {
			log.Printf("ValidateDNSKEYs: signature time INVALID for %s (inc=%d exp=%d now=%d)",
				name, chosenSig.Inception, chosenSig.Expiration, time.Now().UTC().Unix())
		}
		return false, ValidationStateBogus, nil // XXX: Signature time invalid
	}
	if verbose {
		log.Printf("ValidateDNSKEYs: SUCCESS for %s with keytag=%d", name, keyid)
	}
	return true, ValidationStateSecure, nil
}

func (rrcache *RRsetCacheT) ValidateNegativeResponse(ctx context.Context, qname string, qtype uint16, negAuthority []*core.RRset, fetcher RRsetFetcher) (bool, ValidationState, error) {
	if len(negAuthority) == 0 {
		return false, ValidationStateNone, fmt.Errorf("no negative authority RRsets to validate")
	}

	if qtype == dns.TypeDNSKEY {
		// Cannot validate negative DNSKEY responses without the zone's DNSKEYs; treat as bogus
		if rrcache.Debug {
			log.Printf("ValidateNegativeResponse: skipping validation for DNSKEY negative response at %q", qname)
		}
		return false, ValidationStateBogus, nil // XXX: Cannot validate negative DNSKEY responses without the zone's DNSKEYs
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
		return false, ValidationStateIndeterminate, fmt.Errorf("no SOA found in negative authority for %s", qname)
	}
	zoneName := dns.CanonicalName(soarrset.Name)
	if !strings.HasSuffix(qnameCanon, zoneName) {
		return false, ValidationStateBogus, nil // XXX: The zone name does not match the qname
	}
	if !hasSignatures {
		return true, ValidationStateInsecure, nil // XXX: Need to know if zone is secure, but for now: No signatures, so we are insecure
	}
	for _, set := range negAuthority {
		if set == nil {
			continue
		}
		if len(set.RRSIGs) == 0 {
			continue // XXX: Here we need to know if the zone is insecure or not, for now: no signatures, so we are insecure
		}
		_, vstate, err := rrcache.ValidateRRset(ctx, set, fetcher, rrcache.Debug)
		if err != nil {
			return false, vstate, err
		}
		// The Auth section has a set of RRsets that prove non-existence. Each RRset must validate for the proof to be valid
		if vstate == ValidationStateBogus || vstate == ValidationStateIndeterminate {
			return false, vstate, fmt.Errorf("negative authority RRset for %s is bogus or indeterminate", qname)
		}
	}

	// NSEC case: If there are NSECs then they must cover the qname and the wildcard
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
		if !coveredQname || !coveredWildcard { // XXX: This is incomplete, it does not deal with compact denial of existence.
			return false, ValidationStateBogus, nil // XXX: The NSECs do not cover the qname and the wildcard
		}
		return true, ValidationStateSecure, nil // NSECs present, we do not yet veryfy them, but we assume they are secure so we are secure
	}

	// NSEC3 case
	if nsec3Present {
		return true, ValidationStateSecure, nil // NSEC3 present, we do not yet veryfy them, but we assume they are secure so we are secure
	}

	// No NSEC, no NSEC3, must know if zone is secure or insecure
	return false, ValidationStateInsecure, nil // XXX: Need to know if zone is secure, but for now: No NSECs or NSEC3, so we are insecure
}

// From Mieks DNS lib:
// const year68 = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits.

// ValidityPeriod uses RFC1982 serial arithmetic to calculate
// if a signature period is valid. If t is the zero time, the
// current time is taken other t is. Returns true if the signature
// is valid at the given time, otherwise returns false.

const year68     = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits

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