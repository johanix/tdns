/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"errors"
	"fmt"
	"strings"
	"time"

	cache "github.com/johanix/tdns/tdns/cache"
	core "github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
)

// This is mostly used for debugging of the DNSSEC validation code
// func (zd *ZoneData) LookupAndValidateRRset(qname string, qtype uint16) (string, error) {
//	zd.Logger.Printf("LookupAndValidateRRset: Looking up %s %s in DNS", qname, dns.TypeToString[qtype])
//	rrset, err := zd.LookupRRset(qname, qtype, true)
//	if err != nil {
//		return fmt.Sprintf("error from LookupRRset(%s, %s): %v", qname, dns.TypeToString[qtype], err), err
//	}
//	if rrset == nil {
//		return fmt.Sprintf("LookupRRset(%s, %s) returned nil", qname, dns.TypeToString[qtype]), fmt.Errorf("LookupRRset(%s, %s) returned nil", qname, dns.TypeToString[qtype])
//	}
//	valid, err := zd.ValidateRRset(rrset, true)
//	if err != nil {
//		return fmt.Sprintf("error from ValidateRRset(%s, %s): %v", qname, dns.TypeToString[qtype], err), err
//	}

//	msg := fmt.Sprintf("LookupAndValidateRRset: Found %s %s RRset (validated: %v)", qname, dns.TypeToString[qtype], valid)
//	zd.Logger.Printf(msg)
//	return msg, nil
//}

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

// ValidateChildDnskeys: we have the ChildDelegationData for the child zone,
// containing both the NS RRset and the DS RRset.
// 1. Fetch the child DNSKEY RRset from one of the child nameservers
// 2. Verify the child KSK against the DS that we have
// 3. Verify the child DNSKEY RRset against the verified KSK
// 4. Store the child DNSKEY RRset in the TrustAnchor store
// 5. Return true if the child DNSKEY RRset is validated
func (zd *ZoneData) ValidateChildDnskeys(cdd *ChildDelegationData, verbose bool) (bool, error) {

	addrs, err := ChildGlueRRsToAddrs(cdd.A_glue, cdd.AAAA_glue)
	if err != nil {
		return false, err
	}

	dnskeyrrset, err := zd.LookupChildRRsetNG(cdd.ChildName, dns.TypeDNSKEY, addrs, verbose)
	if err != nil {
		return false, err
	}

	kskValidated := false

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
						if strings.EqualFold(computedDS.Digest, dsrr.Digest) {
							zd.Logger.Printf("ValidateChildDnskeys: DNSKEY matches DS record. Adding to TAStore.")

							// Store the KSK in the DnskeyCache
							keyname := dnskey.Header().Name
							expiration := time.Now().Add(time.Duration(minTTL) * time.Second)
							cdr := cache.CachedDnskeyRRset{
								Name:       keyname,
								Keyid:      keyid,
								RRset:      dnskeyrrset,
								// Trusted:    true,
								State:      cache.ValidationStateSecure,
								Dnskey:     *dnskey,
								Expiration: expiration,
							}
							cache.DnskeyCache.Set(keyname, keyid, &cdr)
							zd.Logger.Printf("ValidateChildDnskeys: Stored KSK in TAStore with key %s::%d and expiration %v", keyname, keyid, expiration)
							kskValidated = true
						} else {
							zd.Logger.Printf("ValidateChildDnskeys: DNSKEY does not match DS record")
						}
					}
				}
			}
		}
	}

	if !kskValidated {
		return false, fmt.Errorf("no valid KSK found for child zone %s", cdd.ChildName)
	}

	// Validate the entire DNSKEY RRset
	valid, err := zd.ValidateRRset(dnskeyrrset, verbose)
	if err != nil || !valid {
		return false, fmt.Errorf("failed to validate DNSKEY RRset for child zone %s", cdd.ChildName)
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
					// Trusted:    true,
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
