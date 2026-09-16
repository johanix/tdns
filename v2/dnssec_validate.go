/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// signerHoldsRRset is cache.SignerHoldsRRset for the RRsets this validator is
// given. AuthDNSQuery and lookupRRset build them from the records alone, and
// the IMR's rule takes a missing name for the root, which no signer but the
// root can hold; the first record's owner stands in for it.
func signerHoldsRRset(rrset *core.RRset, sig *dns.RRSIG) bool {
	named := *rrset
	if named.Name == "" && len(named.RRs) > 0 {
		named.Name = named.RRs[0].Header().Name
	}
	return cache.SignerHoldsRRset(&named, sig)
}

// XXX: This should not be a method of ZoneData, but rather a function.
func (zd *ZoneData) ValidateRRset(rrset *core.RRset, verbose bool) (bool, error) {
	if len(rrset.RRSIGs) == 0 {
		return false, nil // is it an error if there is no RRSIG?
	}

	for _, rr := range rrset.RRSIGs {
		zd.Logger.Printf("ValidateRRset: trying to validate: %s", rr.String())
		if _, ok := rr.(*dns.RRSIG); !ok {
			zd.Logger.Printf("ValidateRRset: Error: not an RRSIG: %s", rr.String())
			continue
		}
		rrsig := rr.(*dns.RRSIG)
		zd.Logger.Printf("RRset is signed by \"%s\".", rrsig.SignerName)
		// A signer that cannot hold the RRset did not sign it, whatever key it
		// names. Decided before FindDnskey, which fetches and caches the
		// DNSKEYs of whatever delegation the signer's name is found under.
		if !signerHoldsRRset(rrset, rrsig) {
			zd.Logger.Printf("ValidateRRset: signer %q cannot hold the RRset (labels=%d); signature ignored",
				rrsig.SignerName, rrsig.Labels)
			continue
		}
		ta, err := zd.FindDnskey(rrsig.SignerName, rrsig.KeyTag)
		if err != nil {
			msg := fmt.Sprintf("Error from FindDnskey(%s, %d): %v", rrsig.SignerName, rrsig.KeyTag, err)
			zd.Logger.Print(msg)
			return false, errors.New(msg)
		}
		if ta == nil {
			// don't yet know how to lookup and validate new keys
			msg := fmt.Sprintf("Error: key \"%s\" is unknown.", rrsig.SignerName)
			zd.Logger.Print(msg)
			return false, errors.New(msg)
		}

		keyrr := ta.Dnskey

		var valid bool
		err = rrsig.Verify(&keyrr, rrset.RRs)
		if err != nil {
			zd.Logger.Printf("= Error from sig.Verify(): %v", err)
		} else {
			zd.Logger.Printf("* RRSIG verified correctly")
			valid = true
		}

		time_ok := cache.WithinValidityPeriod(rrsig.Inception, rrsig.Expiration, time.Now().UTC())
		if verbose {
			if time_ok {
				zd.Logger.Printf("* RRSIG is within its validity period")
				time_ok = true
			} else {
				zd.Logger.Printf("= RRSIG is NOT within its validity period")
			}
		}
		return valid && time_ok, nil

	}

	return false, nil
}

// If key not found *CachedDnskeyRRset is returned with nil value
func (zd *ZoneData) FindDnskey(signer string, keyid uint16) (*cache.CachedDnskeyRRset, error) {
	cdr := cache.DnskeyCache.Get(signer, keyid)

	if cdr != nil {
		return cdr, nil
	}

	zd.Logger.Printf("FindDnskey: Request for DNSKEY with id %s::%d not found in cache, will fetch.", signer, keyid)

	cdd := zd.FindDelegation(signer, true)
	if cdd == nil {
		return nil, fmt.Errorf("FindDnskey: Error: No delegation data for %s", signer)
	}

	valid, err := zd.ValidateChildDnskeys(cdd, true)
	if err != nil {
		return nil, err
	}

	if !valid {
		zd.Logger.Printf("FindDnskey: Error: DNSKEY RRset for %q is not valid", signer)
		return nil, fmt.Errorf("FindDnskey: Error: DNSKEY RRset for %s is not valid", signer)
	}

	cdr = cache.DnskeyCache.Get(signer, keyid)
	return cdr, nil
}

// lookupChildRRset indirects the query to a child's nameservers, which
// AuthDNSQuery always sends to port 53, so that ValidateChildDnskeys and the
// delegation arm of lookupRRset can be driven in a test without a listener on
// a privileged port.
//
// Production code MUST NOT reassign this. Tests reassign it and restore the
// original via t.Cleanup.
var lookupChildRRset = func(zd *ZoneData, qname string, qtype uint16, addrs []string, verbose bool) (*core.RRset, error) {
	return zd.LookupChildRRsetNG(qname, qtype, addrs, verbose)
}

// ValidateChildDnskeys: we have the ChildDelegationData for the child zone,
// containing both the NS RRset and the DS RRset.
// 1. Fetch the child DNSKEY RRset from one of the child nameservers
// 2. Find the child KSKs that match the DS that we have
// 3. Verify the child DNSKEY RRset against one of those KSKs
// 4. Store the KSKs and the ZSKs in the DnskeyCache
// 5. Return true if the child DNSKEY RRset is validated
func (zd *ZoneData) ValidateChildDnskeys(cdd *ChildDelegationData, verbose bool) (bool, error) {

	addrs, err := ChildGlueRRsToAddrs(cdd.A_glue, cdd.AAAA_glue)
	if err != nil {
		return false, err
	}

	dnskeyrrset, err := lookupChildRRset(zd, cdd.ChildName, dns.TypeDNSKEY, addrs, verbose)
	if err != nil {
		return false, err
	}

	if dnskeyrrset == nil {
		return false, fmt.Errorf("ValidateChildDnskeys: Error: No DNSKEY RRset found for child zone %s", cdd.ChildName)
	}

	var minTTL uint32
	if len(dnskeyrrset.RRs) > 0 {
		minTTL = dnskeyrrset.RRs[0].Header().Ttl
		for _, rr := range dnskeyrrset.RRs {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}

	var ksks []*dns.DNSKEY
	for _, rr := range dnskeyrrset.RRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			// if dnskey.Flags != 257 {
			if dnskey.Flags&0x0001 == 0 { // ZSK
				continue
			}
			keyid := dnskey.KeyTag()
			for _, ds := range cdd.DS_rrset.RRs {
				if dsrr, ok := ds.(*dns.DS); ok {
					if dsrr.KeyTag == keyid {
						zd.Logger.Printf("ValidateChildDnskeys: found matching DS for keyid %d", keyid)
						// Compute the DS from the DNSKEY
						computedDS := dnskey.ToDS(dsrr.DigestType)
						if computedDS == nil {
							zd.Logger.Printf("ValidateChildDnskeys: failed to compute DS for DNSKEY")
							continue
						}

						// Compare the computed DS with the DS record from the parent zone
						// Use constant-time comparison to prevent timing side-channel attacks
						if subtle.ConstantTimeCompare([]byte(strings.ToLower(computedDS.Digest)), []byte(strings.ToLower(dsrr.Digest))) == 1 {
							zd.Logger.Printf("ValidateChildDnskeys: DNSKEY %d matches DS record", keyid)
							ksks = append(ksks, dnskey)
							break
						}
						zd.Logger.Printf("ValidateChildDnskeys: DNSKEY does not match DS record")
					}
				}
			}
		}
	}

	if len(ksks) == 0 {
		return false, fmt.Errorf("no valid KSK found for child zone %s", cdd.ChildName)
	}

	// RFC 4035 section 5.2: the RRset is authenticated by a key that matches
	// the DS. Not by ValidateRRset: FindDnskey takes any key held for the
	// signer, an ancestor's or a ZSK from an earlier fetch, and for a key tag
	// not held it fetches and validates this RRset again, without end.
	if !zd.dnskeysSignedByKsk(dnskeyrrset, ksks, verbose) {
		return false, fmt.Errorf("failed to validate DNSKEY RRset for child zone %s", cdd.ChildName)
	}

	// Add the KSKs to the DnskeyCache, now that the RRset they are in is valid
	for _, ksk := range ksks {
		keyname := ksk.Header().Name
		keyid := ksk.KeyTag()
		expiration := time.Now().Add(time.Duration(minTTL) * time.Second)
		cdr := cache.CachedDnskeyRRset{
			Name:       keyname,
			Keyid:      keyid,
			RRset:      dnskeyrrset,
			State:      cache.ValidationStateSecure,
			Dnskey:     *ksk,
			Expiration: expiration,
		}
		cache.DnskeyCache.Set(keyname, keyid, &cdr)
		zd.Logger.Printf("ValidateChildDnskeys: Stored KSK in DnskeyCache with key %s::%d and expiration %v", keyname, keyid, expiration)
	}

	// Add ZSKs to the DnskeyCache
	for _, rr := range dnskeyrrset.RRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if dnskey.Flags == 256 { // ZSK
				keyname := dnskey.Header().Name
				keyid := dnskey.KeyTag()
				// lookupKey := fmt.Sprintf("%s::%d", keyname, keyid)
				expiration := time.Now().Add(time.Duration(minTTL) * time.Second)
				cdr := cache.CachedDnskeyRRset{
					Name:       keyname,
					Keyid:      keyid,
					RRset:      dnskeyrrset,
					State:      cache.ValidationStateSecure,
					Dnskey:     *dnskey,
					Expiration: expiration,
				}
				cache.DnskeyCache.Set(keyname, keyid, &cdr)
				zd.Logger.Printf("ValidateChildDnskeys: Stored ZSK in DnskeyCache with key %s::%d and expiration %v", keyname, keyid, expiration)
			}
		}
	}

	return true, nil
}

// dnskeysSignedByKsk reports whether one of the signatures on a child's DNSKEY
// RRset was made by one of ksks, the keys in it that match the parent's DS,
// and is within its validity period. Every signature is tried: during a KSK
// rollover the RRset also carries one by a KSK the DS does not name yet.
func (zd *ZoneData) dnskeysSignedByKsk(rrset *core.RRset, ksks []*dns.DNSKEY, verbose bool) bool {
	now := time.Now().UTC()
	for _, rr := range rrset.RRSIGs {
		rrsig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		for _, ksk := range ksks {
			// Verify checks these too; checked here so that only a KSK the
			// signature names is tried.
			if rrsig.KeyTag != ksk.KeyTag() || rrsig.Algorithm != ksk.Algorithm ||
				!core.EqualNames(rrsig.SignerName, ksk.Header().Name) {
				continue
			}
			if err := rrsig.Verify(ksk, rrset.RRs); err != nil {
				zd.Logger.Printf("ValidateChildDnskeys: RRSIG by KSK %d does not verify: %v", ksk.KeyTag(), err)
				continue
			}
			if !cache.WithinValidityPeriod(rrsig.Inception, rrsig.Expiration, now) {
				zd.Logger.Printf("ValidateChildDnskeys: RRSIG by KSK %d is not within its validity period", ksk.KeyTag())
				continue
			}
			if verbose {
				zd.Logger.Printf("ValidateChildDnskeys: DNSKEY RRset verified by KSK %d", ksk.KeyTag())
			}
			return true
		}
	}
	return false
}
