package cache

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	core "github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
)

// TrustAnchor represents a cached DNSKEY along with validation metadata.
type TrustAnchor struct {
	Name       string
	Keyid      uint16
	Validated  bool
	Trusted    bool
	IsConfigTA bool
	Dnskey     dns.DNSKEY // just this key
	RRset      *core.RRset
	Expiration time.Time
}

// DnskeyCacheT stores TrustAnchors keyed by zone+keyid.
type DnskeyCacheT struct {
	Map cmap.ConcurrentMap[string, TrustAnchor]
}

func NewDnskeyCache() *DnskeyCacheT {
	return &DnskeyCacheT{
		Map: cmap.New[TrustAnchor](),
	}
}

func (dkc *DnskeyCacheT) Get(zonename string, keyid uint16) *TrustAnchor {
	lookupKey := cacheKey(zonename, keyid)
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

func (dkc *DnskeyCacheT) Set(zonename string, keyid uint16, ta *TrustAnchor) {
	lookupKey := cacheKey(zonename, keyid)
	dkc.Map.Set(lookupKey, *ta)
}

// ValidateRRset attempts to validate the provided RRset using DNSKEYs present in the cache.
// Missing signer keys are requested through the provided RRFetcher.
func (dkc *DnskeyCacheT) ValidateRRset(ctx context.Context, fetcher RRFetcher, rrset *core.RRset, verbose bool) (bool, error) {
	if verbose {
		log.Printf("ValidateRRset: start: owner=%q type=%s sigs=%d rrs=%d",
			rrset.Name, dns.TypeToString[rrset.RRtype], len(rrset.RRSIGs), len(rrset.RRs))
	}
	if rrset != nil && rrset.RRtype == dns.TypeDNSKEY {
		return dkc.ValidateDNSKEYs(ctx, fetcher, rrset, verbose)
	}
	if rrset == nil || len(rrset.RRSIGs) == 0 {
		if verbose {
			log.Printf("ValidateRRset: no RRSIGs present for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
		}
		return false, nil
	}
	for _, rr := range rrset.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			if verbose {
				log.Printf("ValidateRRset: skipping non-RRSIG in RRSIGs slice: %T", rr)
			}
			continue
		}
		signer := dns.Fqdn(sig.SignerName)
		keyid := sig.KeyTag
		if verbose {
			log.Printf("ValidateRRset: evaluating signature: signer=%q keyid=%d covered=%s inception=%d expiration=%d",
				signer, keyid, dns.TypeToString[sig.TypeCovered], sig.Inception, sig.Expiration)
		}
		ta := dkc.Get(signer, keyid)
		if ta == nil && ctx != nil {
			if verbose {
				log.Printf("ValidateRRset: TA %q::%d not in cache; attempting to obtain keys", signer, keyid)
			}
			if rrset.RRtype == dns.TypeDNSKEY && (rrset.Name == "" || dns.Fqdn(rrset.Name) == signer) {
				seedUntrustedKeys(dkc, rrset, verbose)
			} else if fetcher != nil {
				if err := dkc.fetchAndCacheKeys(ctx, fetcher, signer, verbose); err != nil && verbose {
					log.Printf("ValidateRRset: failed fetching DNSKEY for %q: %v", signer, err)
				}
			} else if verbose {
				log.Printf("ValidateRRset: no fetcher configured; cannot obtain DNSKEYs for %q", signer)
			}
			ta = dkc.Get(signer, keyid)
		}
		if ta == nil || !ta.Trusted {
			if verbose {
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
		if core.WithinValidityPeriod(sig.Inception, sig.Expiration, time.Now().UTC()) {
			if verbose {
				log.Printf("ValidateRRset: SUCCESS for %s %s using %s::%d",
					rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid)
			}
			return true, nil
		}
		if verbose {
			log.Printf("ValidateRRset: signature time INVALID for %s %s using %s::%d (inc=%d exp=%d now=%d)",
				rrset.Name, dns.TypeToString[rrset.RRtype], signer, keyid, sig.Inception, sig.Expiration, time.Now().UTC().Unix())
		}
	}
	if verbose {
		log.Printf("ValidateRRset: no acceptable signature validated for %s %s", rrset.Name, dns.TypeToString[rrset.RRtype])
	}
	return false, nil
}

func (dkc *DnskeyCacheT) fetchAndCacheKeys(ctx context.Context, fetcher RRFetcher, signer string, verbose bool) error {
	dkeys, err := fetcher.FetchDNSKEY(ctx, signer)
	if err != nil || dkeys == nil || len(dkeys.RRs) == 0 {
		return err
	}
	if verbose {
		log.Printf("ValidateRRset: fetched %d DNSKEY RRs for %q", len(dkeys.RRs), signer)
	}
	minTTL := dkeys.RRs[0].Header().Ttl
	for _, krr := range dkeys.RRs[1:] {
		if krr.Header().Ttl < minTTL {
			minTTL = krr.Header().Ttl
		}
	}
	exp := time.Now().Add(time.Duration(minTTL) * time.Second)
	for _, krr := range dkeys.RRs {
		if dk, ok := krr.(*dns.DNSKEY); ok {
			dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &TrustAnchor{
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
	if ok, _ := dkc.ValidateDNSKEYs(ctx, fetcher, dkeys, verbose); ok {
		if verbose {
			log.Printf("ValidateRRset: signer DNSKEY RRset for %q validated; promoting keys to trusted", signer)
		}
		for _, krr := range dkeys.RRs {
			if dk, ok := krr.(*dns.DNSKEY); ok {
				dkc.Set(dns.Fqdn(dk.Hdr.Name), dk.KeyTag(), &TrustAnchor{
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
	return nil
}

func seedUntrustedKeys(dkc *DnskeyCacheT, rrset *core.RRset, verbose bool) {
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
			name := dns.Fqdn(dk.Hdr.Name)
			if existing := dkc.Get(name, dk.KeyTag()); existing != nil {
				if existing.Trusted {
					if verbose {
						log.Printf("ValidateRRset: skipping overwrite of trusted key %s::%d", name, dk.KeyTag())
					}
					continue
				}
				if existing.IsConfigTA {
					if verbose {
						log.Printf("ValidateRRset: skipping overwrite of config trust anchor %s::%d", name, dk.KeyTag())
					}
					continue
				}
			}
			if verbose {
				log.Printf("ValidateRRset: caching DNSKEY (untrusted) %s::%d exp=%v", name, dk.KeyTag(), exp)
			}
			dkc.Set(name, dk.KeyTag(), &TrustAnchor{
				Name:       name,
				Keyid:      dk.KeyTag(),
				Validated:  false,
				Trusted:    false,
				IsConfigTA: false,
				Dnskey:     *dk,
				Expiration: exp,
			})
		}
	}
}

// ValidateDNSKEYs validates a DNSKEY RRset using DS from the parent.
func (dkc *DnskeyCacheT) ValidateDNSKEYs(ctx context.Context, fetcher RRFetcher, rrset *core.RRset, verbose bool) (bool, error) {
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
	if name == "." {
		if ta := dkc.Get(name, keyid); ta != nil && ta.Trusted {
			if err := chosenSig.Verify(&ta.Dnskey, rrset.RRs); err == nil &&
				core.WithinValidityPeriod(chosenSig.Inception, chosenSig.Expiration, time.Now().UTC()) {
				if verbose {
					log.Printf("ValidateDNSKEYs: SUCCESS for root with keytag=%d", keyid)
				}
				return true, nil
			}
		}
		if verbose {
			log.Printf("ValidateDNSKEYs: no trusted TA for root keyid=%d", keyid)
		}
		return false, nil
	}
	var dsRRset *core.RRset
	var dsValidated bool
	if fetcher != nil {
		dsRRset, dsValidated = fetcher.GetDS(name)
	}
	if dsRRset == nil || !dsValidated || len(dsRRset.RRs) == 0 {
		if verbose {
			log.Printf("ValidateDNSKEYs: validated DS RRset for %s not present in cache", name)
		}
		return false, nil
	}
	var dsMatch bool
	for _, rr := range dsRRset.RRs {
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
	if err := chosenSig.Verify(signerKey, rrset.RRs); err != nil {
		if verbose {
			log.Printf("ValidateDNSKEYs: signature verify FAILED for %s: %v", name, err)
		}
		return false, nil
	}
	if !core.WithinValidityPeriod(chosenSig.Inception, chosenSig.Expiration, time.Now().UTC()) {
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

func cacheKey(name string, keyid uint16) string {
	return dns.Fqdn(name) + "::" + strconv.FormatUint(uint64(keyid), 10)
}


