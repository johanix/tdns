/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
	core "github.com/johanix/tdns/tdns/core"
)

var DnskeyCache = NewDnskeyCache()

func NewDnskeyCache() *DnskeyCacheT {
	return &DnskeyCacheT{
		Map: cmap.New[CachedDnskeyRRset](),
	}
}

func (dkc *DnskeyCacheT) Get(zonename string, keyid uint16) *CachedDnskeyRRset {
	lookupKey := fmt.Sprintf("%s::%d", zonename, keyid)
	tmp, ok := dkc.Map.Get(lookupKey)
	if !ok {
		return nil
	}
	if tmp.Expiration.Before(time.Now()) {
		dkc.Map.Remove(lookupKey)
		log.Printf("DnskeyCache: Removed expired key %s", lookupKey)
		return nil
	}
	return &tmp
}

func (dkc *DnskeyCacheT) Set(zonename string, keyid uint16, cdr *CachedDnskeyRRset) {
	lookupKey := fmt.Sprintf("%s::%d", zonename, keyid)
	dkc.Map.Set(lookupKey, *cdr)
}

// ValidateRRset attempts to validate the provided RRset using DNSKEYs present in the DnskeyCache.
// If a required signer key is missing, it will query for the signer's DNSKEY via the recursive
// engine and retry using keys from the cache. Only keys marked as Trusted are accepted for
// successful validation. Returns true if at least one signature validates and is time-valid.
func (dkc *DnskeyCacheT) xxxValidateRRset(ctx context.Context, rrcache *RRsetCacheT, rrset *core.RRset, verbose bool) (bool, error) {
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
func (dkc *DnskeyCacheT) xxxValidateDNSKEYs(ctx context.Context, rrcache *RRsetCacheT, rrset *core.RRset, verbose bool) (bool, error) {
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

// var RRsetCache = NewRRsetCache()

func NewRRsetCache(lg *log.Logger, verbose, debug bool, options map[ImrOption]string) *RRsetCacheT {
	var client = map[Transport]*DNSClient{}
	// var t Transport
	// Default ports per transport
	client[TransportDo53] = NewDNSClient(TransportDo53, "53", nil)
	client[TransportDoT] = NewDNSClient(TransportDoT, "853", nil)
	client[TransportDoH] = NewDNSClient(TransportDoH, "443", nil)
	client[TransportDoQ] = NewDNSClient(TransportDoQ, "8853", nil)

	opts := cloneImrOptions(options)

	return &RRsetCacheT{
		RRsets:                 NewCmap[CachedRRset](),
		Servers:                NewCmap[[]string](),               // servers stored as []string{ "1.2.3.4:53", "9.8.7.6:53"}
		ServerMap:              NewCmap[map[string]*AuthServer](), // servers stored as map[nsname]*AuthServer{}
		Logger:                 lg,
		Verbose:                verbose,
		Debug:                  debug,
		DNSClient:              client,
		Options:                opts,
		transportQueryInFlight: make(map[string]struct{}),
		nsRevalidateInFlight:   make(map[string]struct{}),
		tlsaQueryInFlight:      make(map[string]struct{}),
	}
}

func cloneImrOptions(src map[ImrOption]string) map[ImrOption]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[ImrOption]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (rrcache *RRsetCacheT) Get(qname string, qtype uint16) *CachedRRset {
	
	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	crrset, ok := rrcache.RRsets.Get(lookupKey)
	if !ok {
		return nil
	}
	// Expiration-based eviction
	if crrset.Expiration.Before(time.Now()) {
		rrcache.RRsets.Remove(lookupKey)
		if rrcache.Debug {
			log.Printf("RRsetCache: Removed expired key %s (%s)", lookupKey, dns.TypeToString[qtype])
		}
		// If an NS RRset expired, also remove its server mappings for that zone
		if qtype == dns.TypeNS {
			rrcache.ServerMap.Remove(qname)
			if rrcache.Debug {
				log.Printf("RRsetCache: Removed ServerMap entry for zone %s due to NS expiry", qname)
			}
		}
		return nil
	}
	return &crrset
}

func (rrcache *RRsetCacheT) Set(qname string, qtype uint16, crrset *CachedRRset) {
	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	if rrcache.Debug {
		fmt.Printf("rrcache: Adding key %s (%s) to cache\n", lookupKey, dns.TypeToString[qtype])
	}

	if crrset == nil {
		log.Printf("RRsetCache:Set: nil crrset for key %s - ignored", lookupKey)
		return
	}
	
	// Compute min TTL and set Expiration accordingly when RRset present
	if crrset.RRset != nil && len(crrset.RRset.RRs) > 0 {
		minTTL := crrset.RRset.RRs[0].Header().Ttl
		for _, rr := range crrset.RRset.RRs[1:] {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		// Apply a small TTL floor for NS RRsets only when learned via referral, to avoid instant drop
		if qtype == dns.TypeNS && crrset.Context == ContextReferral && minTTL == 0 {
			if rrcache.Debug {
				log.Printf("RRsetCache:Set: NS minTTL was 0 for %q (Context=Referral); applying floor 10s", qname)
			}
			minTTL = 10
		}
		if rrcache.Debug && qtype == dns.TypeNS {
			log.Printf("RRsetCache:Set: NS minTTL=%ds for zone %q (Context=%s)", minTTL, qname, CacheContextToString[crrset.Context])
		}
		crrset.Ttl = minTTL
		crrset.Expiration = time.Now().Add(time.Duration(minTTL) * time.Second)
	} else if crrset.Expiration.IsZero() && crrset.Ttl > 0 {
		// For negative/no-RRset entries, if Expiration not set but TTL is provided
		crrset.Expiration = time.Now().Add(time.Duration(crrset.Ttl) * time.Second)
	}

	rrcache.RRsets.Set(lookupKey, *crrset)
}

// FlushDomain removes cached RRsets at or below the provided domain.
// When keepStructural is true, NS/DS/DNSKEY RRsets and the address
// records for their nameservers are preserved.
func (rrcache *RRsetCacheT) FlushDomain(domain string, keepStructural bool) (int, error) {
	if rrcache == nil {
		return 0, fmt.Errorf("rrcache is nil")
	}
	domain = dns.CanonicalName(domain)
	if domain == "" || domain == "." {
		return 0, fmt.Errorf("invalid domain %q", domain)
	}

	var nsHosts map[string]struct{}
	if keepStructural {
		nsHosts = make(map[string]struct{})
		for item := range rrcache.RRsets.IterBuffered() {
			cr := item.Val
			if cr.Name == "" || !isSubdomainOf(cr.Name, domain) {
				continue
			}
			if cr.RRtype != dns.TypeNS || cr.RRset == nil {
				continue
			}
			for _, rr := range cr.RRset.RRs {
				ns, ok := rr.(*dns.NS)
				if !ok {
					continue
				}
				nsHosts[dns.CanonicalName(ns.Ns)] = struct{}{}
			}
		}
	}

	var keysToRemove []string
	for item := range rrcache.RRsets.IterBuffered() {
		key := item.Key
		cr := item.Val
		if cr.Name == "" || !isSubdomainOf(cr.Name, domain) {
			continue
		}
		if keepStructural && isStructuralRRset(&cr, nsHosts) {
			continue
		}
		keysToRemove = append(keysToRemove, key)
	}

	for _, key := range keysToRemove {
		rrcache.RRsets.Remove(key)
	}
	removed := len(keysToRemove)

	if !keepStructural && removed > 0 {
		var auxKeys []string
		for item := range rrcache.Servers.IterBuffered() {
			if isSubdomainOf(item.Key, domain) {
				auxKeys = append(auxKeys, item.Key)
			}
		}
		for _, key := range auxKeys {
			rrcache.Servers.Remove(key)
		}
		auxKeys = auxKeys[:0]
		for item := range rrcache.ServerMap.IterBuffered() {
			if isSubdomainOf(item.Key, domain) {
				auxKeys = append(auxKeys, item.Key)
			}
		}
		for _, key := range auxKeys {
			rrcache.ServerMap.Remove(key)
		}
	}

	return removed, nil
}

func isStructuralRRset(cr *CachedRRset, nsHosts map[string]struct{}) bool {
	if cr == nil {
		return false
	}
	switch cr.RRtype {
	case dns.TypeNS, dns.TypeDS, dns.TypeDNSKEY:
		return true
	case dns.TypeA, dns.TypeAAAA:
		if nsHosts == nil {
			return false
		}
		_, ok := nsHosts[dns.CanonicalName(cr.Name)]
		return ok
	default:
		return false
	}
}

func isSubdomainOf(name, parent string) bool {
	name = dns.CanonicalName(name)
	parent = dns.CanonicalName(parent)
	if parent == "." {
		return true
	}
	if name == parent {
		return true
	}
	suffix := "." + strings.TrimSuffix(parent, ".") + "."
	return strings.HasSuffix(name, suffix)
}

func (rrcache *RRsetCacheT) hasOption(opt ImrOption) bool {
	if rrcache == nil || len(rrcache.Options) == 0 {
		return false
	}
	_, ok := rrcache.Options[opt]
	return ok
}

const (
	transportQueryReasonObservation = "opportunistic-signal"
	transportQueryReasonNewServer   = "new-auth-server"
)

func (rrcache *RRsetCacheT) transportSignalRRType() uint16 {
	if rrcache == nil {
		return dns.TypeSVCB
	}
	if val, ok := rrcache.Options[ImrOptTransportSignalType]; ok {
		switch strings.ToLower(val) {
		case "tsync":
			return TypeTSYNC
		}
	}
	return dns.TypeSVCB
}

func (rrcache *RRsetCacheT) transportSignalCached(owner string) bool {
	if owner == "" || rrcache == nil {
		return false
	}
	if c := rrcache.Get(owner, rrcache.transportSignalRRType()); c != nil && c.RRset != nil && len(c.RRset.RRs) > 0 {
		return true
	}
	return false
}

func (rrcache *RRsetCacheT) maybeQueryTransportSignal(ctx context.Context, owner string, reason string) {
	if owner == "" || rrcache == nil || ctx == nil {
		return
	}
	switch reason {
	case transportQueryReasonObservation:
		if !(rrcache.hasOption(ImrOptQueryForTransport) || rrcache.hasOption(ImrOptAlwaysQueryForTransport)) {
			return
		}
	case transportQueryReasonNewServer:
		if !rrcache.hasOption(ImrOptAlwaysQueryForTransport) {
			return
		}
	default:
		if !(rrcache.hasOption(ImrOptQueryForTransport) || rrcache.hasOption(ImrOptAlwaysQueryForTransport)) {
			return
		}
	}
	rrcache.launchTransportSignalQuery(ctx, owner, reason)
}

func (rrcache *RRsetCacheT) launchTransportSignalQuery(ctx context.Context, owner string, reason string) {
	if owner == "" || ctx == nil || rrcache == nil {
		return
	}
	if rrcache.transportSignalCached(owner) {
		return
	}
	if !rrcache.markTransportQuery(owner) {
		return
	}
	go func() {
		defer rrcache.clearTransportQuery(owner)
		queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		rrtype := rrcache.transportSignalRRType()
		if rrcache.Debug {
			log.Printf("Transport signal query (%s): querying %s %s", reason, owner, dns.TypeToString[rrtype])
		}
		if _, err := rrcache.ImrQuery(queryCtx, owner, rrtype, dns.ClassINET, nil); err != nil {
			if rrcache.Debug {
				log.Printf("Transport signal query (%s) failed for %s %s: %v", reason, owner, dns.TypeToString[rrtype], err)
			}
		}
	}()
}

func (rrcache *RRsetCacheT) markTransportQuery(owner string) bool {
	rrcache.transportQueryMu.Lock()
	defer rrcache.transportQueryMu.Unlock()
	if rrcache.transportQueryInFlight == nil {
		rrcache.transportQueryInFlight = make(map[string]struct{})
	}
	if _, exist := rrcache.transportQueryInFlight[owner]; exist {
		return false
	}
	rrcache.transportQueryInFlight[owner] = struct{}{}
	return true
}

func (rrcache *RRsetCacheT) clearTransportQuery(owner string) {
	rrcache.transportQueryMu.Lock()
	defer rrcache.transportQueryMu.Unlock()
	if rrcache.transportQueryInFlight == nil {
		return
	}
	delete(rrcache.transportQueryInFlight, owner)
}

func (rrcache *RRsetCacheT) lookupSOARRset(name string) *core.RRset {
	if rrcache == nil {
		return nil
	}
	cur := dns.Fqdn(strings.TrimSpace(name))
	visitedRoot := false
	for cur != "" {
		if c := rrcache.Get(cur, dns.TypeSOA); c != nil && c.RRset != nil && len(c.RRset.RRs) > 0 {
			return c.RRset
		}
		if cur == "." {
			if visitedRoot {
				break
			}
			visitedRoot = true
			continue
		}
		labels := dns.SplitDomainName(cur)
		if len(labels) <= 1 {
			cur = "."
			continue
		}
		cur = strings.Join(labels[1:], ".") + "."
	}
	return nil
}

func (rrcache *RRsetCacheT) maybeQueryTLSA(ctx context.Context, base string) {
	if rrcache == nil || ctx == nil || !rrcache.hasOption(ImrOptQueryForTransportTLSA) {
		return
	}
	base = dns.Fqdn(strings.TrimSpace(base))
	if base == "." || base == "" {
		return
	}
	targets := []string{
		dns.Fqdn(fmt.Sprintf("_853._udp.%s", base)),
		dns.Fqdn(fmt.Sprintf("_853._tcp.%s", base)),
	}
	for _, owner := range targets {
		if !rrcache.markTLSAQuery(owner) {
			continue
		}
		go func(owner string) {
			defer rrcache.clearTLSAQuery(owner)
			queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			resp, err := rrcache.ImrQuery(queryCtx, owner, dns.TypeTLSA, dns.ClassINET, nil)
			if err != nil || resp == nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 {
				return
			}
			rr := resp.RRset
			validated := false
			if len(rr.RRSIGs) > 0 {
				if ok, _ := rrcache.ValidateRRset(queryCtx, DnskeyCache, rr, rrcache.Debug); ok {
					validated = true
				}
			}
			baseHint := baseFromTLSAOwner(owner)
			rrcache.storeTLSAForServer(baseHint, owner, rr, validated)
		}(owner)
	}
}

func (rrcache *RRsetCacheT) markTLSAQuery(owner string) bool {
	rrcache.tlsaQueryMu.Lock()
	defer rrcache.tlsaQueryMu.Unlock()
	if rrcache.tlsaQueryInFlight == nil {
		rrcache.tlsaQueryInFlight = make(map[string]struct{})
	}
	if _, ok := rrcache.tlsaQueryInFlight[owner]; ok {
		return false
	}
	rrcache.tlsaQueryInFlight[owner] = struct{}{}
	return true
}

func (rrcache *RRsetCacheT) clearTLSAQuery(owner string) {
	rrcache.tlsaQueryMu.Lock()
	defer rrcache.tlsaQueryMu.Unlock()
	if rrcache.tlsaQueryInFlight == nil {
		return
	}
	delete(rrcache.tlsaQueryInFlight, owner)
}

// A stub is a static mapping from a zone name to a list of addresses (later probably AuthServers)
func (rrcache *RRsetCacheT) AddStub(zone string, servers []AuthServer) error {
	authservers := map[string]*AuthServer{}
	for _, server := range servers {
		tmpauthserver := &AuthServer{
			Name:     server.Name,
			Addrs:    server.Addrs,
			Alpn:     server.Alpn,
			Src:      "stub",
			ConnMode: server.ConnMode,
		}
		// New: prefer explicit transport signal string when provided
		if server.TransportSignal != "" {
			kvMap, err := ParseTransportString(server.TransportSignal)
			if err != nil {
				log.Printf("AddStub: invalid transport string for %s: %q: %v", server.Name, server.TransportSignal, err)
			} else {
				// build weights and order by weight desc (stable)
				type pair struct {
					k string
					w uint8
				}
				var pairs []pair
				for k, v := range kvMap {
					pairs = append(pairs, pair{k: k, w: v})
				}
				slices.SortFunc(pairs, func(a, b pair) int {
					if a.w == b.w {
						if a.k < b.k {
							return -1
						}
						if a.k > b.k {
							return 1
						}
						return 0
					}
					if a.w > b.w {
						return -1
					}
					return 1
				})
				var transports []Transport
				var alpnOrder []string
				weights := map[Transport]uint8{}
				for _, p := range pairs {
					t, err := StringToTransport(p.k)
					if err != nil {
						log.Printf("AddStub: unknown transport %q for %s", p.k, server.Name)
						continue
					}
					transports = append(transports, t)
					alpnOrder = append(alpnOrder, p.k)
					weights[t] = p.w
				}
				tmpauthserver.Alpn = alpnOrder
				tmpauthserver.Transports = transports
				if len(transports) > 0 {
					tmpauthserver.PrefTransport = transports[0]
				}
				tmpauthserver.TransportWeights = weights
			}
		} else {
			// Back-compat: use ALPN order to set transports (no weights)
			if len(server.Alpn) == 0 {
				tmpauthserver.Alpn = []string{"do53"}
				tmpauthserver.Transports = []Transport{TransportDo53}
				tmpauthserver.TransportWeights = map[Transport]uint8{TransportDo53: 100}
				tmpauthserver.PrefTransport = TransportDo53
			} else {
				tmpauthserver.Alpn = server.Alpn
				var transports []Transport
				weights := map[Transport]uint8{}
				for _, alpn := range server.Alpn {
					if t, err := StringToTransport(alpn); err == nil {
						transports = append(transports, t)
						weights[t] = 100
					}
				}
				tmpauthserver.Transports = transports
				tmpauthserver.TransportWeights = weights
				if len(transports) > 0 {
					tmpauthserver.PrefTransport = transports[0]
				}
			}
		}
		authservers[server.Name] = tmpauthserver
	}
	if Globals.Debug {
		fmt.Printf("rrcache: Adding stubs for zone %s to cache\n", zone)
	}
	rrcache.ServerMap.Set(zone, authservers)
	return nil
}

func (rrcache *RRsetCacheT) AddServers(zone string, sm map[string]*AuthServer) error {
	serverMap, ok := rrcache.ServerMap.Get(zone)
	if !ok {
		serverMap = map[string]*AuthServer{}
	}
	for name, server := range sm {
		if _, exist := serverMap[name]; !exist {
			serverMap[name] = server
		} else {
			for _, addr := range server.Addrs {
				if !slices.Contains(serverMap[name].Addrs, addr) {
					serverMap[name].Addrs = append(serverMap[name].Addrs, addr)
				}
			}
			for _, alpn := range server.Alpn {
				t, err := StringToTransport(alpn)
				if err != nil {
					log.Printf("rrcache.AddServers: error from StringToTransport: %v", err)
					// Skip invalid ALPN value
					continue 
				} else if !slices.Contains(serverMap[name].Alpn, alpn) {
					serverMap[name].Alpn = append(serverMap[name].Alpn, alpn)
				}
				if !slices.Contains(serverMap[name].Transports, t) {
					serverMap[name].Transports = append(serverMap[name].Transports, t)
				}
			}
			// Merge/overwrite transport weights if provided
			if len(server.TransportWeights) > 0 {
				if serverMap[name].TransportWeights == nil {
					serverMap[name].TransportWeights = make(map[Transport]uint8)
				}
				for k, v := range server.TransportWeights {
					serverMap[name].TransportWeights[k] = v
				}
				// Set preferred transport from provided order if available
				if len(server.Transports) > 0 {
					serverMap[name].PrefTransport = server.Transports[0]
				}
			}
		}
		// Only set preferred transport if we have valid transports
		if len(serverMap[name].Transports) > 0 {
			serverMap[name].PrefTransport = serverMap[name].Transports[0]
		}
	}
	if Globals.Debug {
		fmt.Printf("rrcache: Adding servers for zone %s to cache\n", zone)
	}
	rrcache.ServerMap.Set(zone, serverMap)
	return nil
}

func tlsaOwnersForServer(base string, server *AuthServer) []string {
	base = dns.Fqdn(strings.TrimSpace(base))
	if base == "." || base == "" {
		return nil
	}
	owners := map[string]struct{}{}
	addOwner := func(proto string) {
		owner := dns.Fqdn(fmt.Sprintf("_853._%s.%s", proto, base))
		owners[owner] = struct{}{}
	}
	if server != nil {
		for _, t := range server.Transports {
			switch t {
			case TransportDoT:
				addOwner("tcp")
			case TransportDoQ:
				addOwner("udp")
			}
		}
	}
	if len(owners) == 0 {
		addOwner("tcp")
	}
	var result []string
	for owner := range owners {
		result = append(result, owner)
	}
	sort.Strings(result)
	return result
}

func baseFromTLSAOwner(owner string) string {
	owner = dns.Fqdn(strings.TrimSpace(owner))
	if owner == "." || owner == "" {
		return ""
	}
	prefixes := []string{"_853._udp.", "_853._tcp."}
	for _, prefix := range prefixes {
		if strings.HasPrefix(owner, prefix) {
			return owner[len(prefix):]
		}
	}
	return ""
}

func cloneRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		out = append(out, dns.Copy(rr))
	}
	return out
}

func (rrcache *RRsetCacheT) storeTLSAForServer(base, owner string, rrset *core.RRset, validated bool) {
	if rrcache == nil || rrset == nil || len(rrset.RRs) == 0 {
		return
	}
	base = dns.Fqdn(strings.TrimSpace(base))
	if base == "." || base == "" {
		return
	}
	owner = dns.Fqdn(strings.TrimSpace(owner))
	if owner == "." || owner == "" {
		return
	}
	for zone, sm := range rrcache.ServerMap.Items() {
		server, ok := sm[base]
		if !ok {
			continue
		}
		server.mu.Lock()
		if server.TLSARecords == nil {
			server.TLSARecords = make(map[string]*CachedRRset)
		}
		server.TLSARecords[owner] = &CachedRRset{
			Name:   owner,
			RRtype: dns.TypeTLSA,
			RRset: &core.RRset{
				Name:   owner,
				Class:  dns.ClassINET,
				RRtype: dns.TypeTLSA,
				RRs:    cloneRRs(rrset.RRs),
				RRSIGs: cloneRRs(rrset.RRSIGs),
			},
			Context:    ContextAnswer,
			Validated:  validated,
			Expiration: time.Now().Add(getMinTTL(rrset.RRs)),
		}
		server.mu.Unlock()
		rrcache.ServerMap.Set(zone, sm)
	}
}

func (rrcache *RRsetCacheT) PrimeWithHints(hintsfile string) error {
	// Verify root hints file exists
	if _, err := os.Stat(hintsfile); err != nil {
		return fmt.Errorf("Root hints file %s not found: %v", hintsfile, err)
	}

	log.Printf("PrimeWithHints: reading root hints %s", hintsfile)
	// Read and parse root hints file
	data, err := os.ReadFile(hintsfile)
	if err != nil {
		return fmt.Errorf("Error reading root hints file %s: %v", hintsfile, err)
	}
	zp := dns.NewZoneParser(strings.NewReader(string(data)), ".", hintsfile)
	zp.SetIncludeAllowed(true)

	// Maps to collect NS and A/AAAA records
	nsRecords := []dns.RR{}
	glueRecords := map[string][]dns.RR{}
	nsMap := map[string]bool{}
	authMap := map[string]*AuthServer{}

	var rootns []string

	// Parse all records from the root hints file
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch rr.Header().Rrtype {
		case dns.TypeNS:
			if rr.Header().Name != "." {
				log.Printf("Non-root NS record among hints: %v. Ignored.", rr.String())
				continue
			}
			nsRecords = append(nsRecords, rr)
			nsname := rr.(*dns.NS).Ns
			nsMap[nsname] = true
			authMap[nsname] = &AuthServer{
				Name:          nsname,
				Alpn:          []string{"do53"},
				Transports:    []Transport{TransportDo53},
				Src:           "hint",
				PrefTransport: TransportDo53,
			}
			rootns = append(rootns, nsname)
			log.Printf("PrimeWithHints: adding server for root: name %q: %+v", nsname, authMap[nsname])

		case dns.TypeA, dns.TypeAAAA:
			// log.Printf("PWH: read address RR: %s", rr.String())
			name := rr.Header().Name
			glueRecords[name] = append(glueRecords[name], rr)
		}
	}

	if err := zp.Err(); err != nil {
		return fmt.Errorf("Error parsing root hints file %s: %v", hintsfile, err)
	}

	// Store NS records for root
	if len(nsRecords) > 0 {
		log.Printf("Found %d NS RRs", len(nsRecords))
		rrcache.Set(".", dns.TypeNS, &CachedRRset{
			Name:    ".",
			RRtype:  dns.TypeNS,
			Context: ContextHint,
			RRset: &core.RRset{
				Name:   ".",
				RRtype: dns.TypeNS,
				Class:  dns.ClassINET,
				RRs:    nsRecords,
				RRSIGs: nil, // No DNSSEC in root hints
			},
		})
	} else {
		return fmt.Errorf("No NS records found in root hints file %s", hintsfile)
	}

	// Store root zone data
	// cache.Data["."] = rootData
	var servers []string

	// Store glue records for root nameservers
	log.Printf("Found %d glue records", len(glueRecords))
	for name, rrs := range glueRecords {
		if !nsMap[name] {
			log.Printf("*** Glue record for a non-root nameserver found: %v. Ignored.", name)
			continue
		}

		// Group records by type (A or AAAA)
		typeGroups := map[uint16][]dns.RR{}
		tmpsrv := authMap[name]
		for _, rr := range rrs {
			rrtype := rr.Header().Rrtype
			typeGroups[rrtype] = append(typeGroups[rrtype], rr)
			switch rr.Header().Rrtype {
			case dns.TypeA:
				servers = append(servers, net.JoinHostPort(rr.(*dns.A).A.String(), "53"))
				tmpsrv.Addrs = append(tmpsrv.Addrs, rr.(*dns.A).A.String())
			case dns.TypeAAAA:
				servers = append(servers, net.JoinHostPort(rr.(*dns.AAAA).AAAA.String(), "53"))
				tmpsrv.Addrs = append(tmpsrv.Addrs, rr.(*dns.AAAA).AAAA.String())
			}
		}
		authMap[name] = tmpsrv
		log.Printf("PrimeWithHints: adding addrs to server for root: name %q: %+v", name, authMap[name])

		// Create RRset for each type
		for rrtype, records := range typeGroups {
			rrcache.Set(name, rrtype, &CachedRRset{
				Name:    name,
				RRtype:  rrtype,
				Context: ContextHint,
				RRset: &core.RRset{
					Name:   name,
					Class:  dns.ClassINET,
					RRtype: rrtype,
					RRs:    records,
					RRSIGs: nil, // No DNSSEC in root hints
				},
			})
		}

		// cache.Data[name] = ownerData
	}

	rrcache.ServerMap.Set(".", authMap)
	rrcache.Servers.Set(".", servers)

	log.Printf("PrimeWithHints: serverMap:")
	for k, v := range authMap {
		log.Printf("server: %q data: %+v", k, v)
	}

	// dump.P(authMap)

	// rrset, _, _, err := rrcache.IterativeDNSQuery(".", dns.TypeNS, rootns, true) // force re-query bypassing cache
	rrset, _, _, err := rrcache.IterativeDNSQuery(context.Background(), ".", dns.TypeNS, authMap, true) // force re-query bypassing cache
	if err != nil {
		return fmt.Errorf("Error priming RRsetCache with root hints: %v", err)
	}
	if rrset == nil {
		return fmt.Errorf("No NS records found in root hints file %s", hintsfile)
	}

	log.Printf("*** RRsetCache: primed with these roots: %v", rootns)

	rrcache.Primed = true

	return nil
}
