/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	// "github.com/gookit/goutil/dump"
)

// The general idea is to iterate over all SIG RRs in the Additional section of the update to find
// all keys that signed the update. Then iterate over all the located keys to see which key, if any,
// successfully validates the update.

// XXX: This should perhaps not be a method of ZoneData, but rather of KeyDB.
func (zd *ZoneData) ValidateUpdate(r *dns.Msg, us *UpdateStatus) error {
	msgbuf, err := r.Pack()
	if err != nil {
		zd.Logger.Printf("= Error from msg.Pack(): %v", err)
		us.ValidationRcode = dns.RcodeFormatError
		return err
	}

	if len(r.Extra) == 0 { // there is no signature on the update
		us.ValidationRcode = dns.RcodeFormatError
		us.Validated = false
		us.ValidatedByTrustedKey = false
		return fmt.Errorf("Update has no signature")
	}

	var sig *dns.SIG
	var ok bool

	// Iterate over all SIG RRs in the Additional section of the update to find all keys that
	// signed the update.
	// log.Printf("ValidateAndTrustUpdate: There are %d RRs in the Additional section of the update", len(r.Extra))
	for idx, rr := range r.Extra {
		log.Printf("ValidateUpdate: RR %d in Additional is a %T", idx, rr)
		var sig0key *Sig0Key
		if _, ok := rr.(*dns.SIG); !ok {
			log.Printf("ValidateUpdate: RR in Additional is not a SIG RR (%T), continuing", rr)
			continue
		}

		sig, ok = rr.(*dns.SIG)
		if !ok {
			// This RR is not a SIG RR (this may be a protocol violation, I don't remember)
			continue
		}

		keyid := sig.RRSIG.KeyTag
		signername := sig.RRSIG.SignerName
		log.Printf("* Update is signed by SIG(0) key \"%s\" (keyid %d).", signername, keyid)

		// We have the name and keyid of the key that generated this signature. There are now
		// four possible alternatives for locating the key:
		// 1. The key is in the TrustStore (either as a child key or a key for an auth zone)
		// 2. The key is in the KeyStore (as a key for an auth zone). This should only happen if (1) is true.
		// 3. The key is published in the child zone and we can look it up via DNS (and hopefully validate it)
		// 4. The key is not to be found anywhere, but the update is a self-signed upload of a SIG(0)
		//    key for the same zone (i.e. the key is in the update as a KEY RR).
		// If all these fail and we don't find the key then the update must be rejected.

		// 1. Is the key in the TrustStore?
		sig0key, err = zd.FindSig0TrustedKey(signername, keyid)
		if err == nil && sig0key != nil {
			log.Printf("* The SIG(0) key \"%s\" (keyid %d) was found in the TrustStore (validated: %v trusted: %v)",
				      signername, keyid, sig0key.Validated, sig0key.Trusted)
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig0Key: sig0key})
			continue // key found
		} else {
			log.Printf("* The SIG(0) key \"%s\" (keyid %d) was NOT found in the TrustStore", signername, keyid)
		}

		// 2. Is the key in the KeyStore?. I don't think this is correct. If we want to be able
		// to validate against keys in the KeyStore, then those keys should have their public
		// parts promoted to the TrustStore (and we now do that automatically).

		// sig0key, err = zd.Keystore(signername, keyid)
		// if err == nil && sig0key != nil {
		//		us.Signers = append(us.Signers, Sig0Signer{Name: signername, KeyId: keyid, Sig0Key: sig0key})
		//		continue // key found
		//	} else {
		//		us.Log("* Failed to find a SIG(0) key for \"%s\" (keyid %d) in the KeyStore",
		//			signername, keyid)
		//	}

		// 3. Try to find the key via DNS in the child zone
		sig0key, err = zd.FindSig0KeyViaDNS(signername, keyid)
		if err == nil && sig0key != nil {
			log.Printf("* The SIG(0) key \"%s\" (keyid %d) was found via DNS lookup", signername, keyid)
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig0Key: sig0key})
			continue // key found
		} else {
			log.Printf("* The SIG(0) key \"%s\" (keyid %d) was NOT found via DNS lookup", signername, keyid)
		}

		// Last chance: Is the key in the update?
		if len(r.Ns) != 1 {
			log.Printf("-- Update does not consist of a single SIG(0) key, so this cannot be a self-signed KEY upload")
			continue
		}

		// Extract the RR from the update hoping that it is a KEY record
		switch tmp := r.Ns[0].(type) {
		case *dns.KEY:
			sig0key = &Sig0Key{
				Name:   signername,
				Key:    *tmp,
				Source: "child-key-upload",
			}
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig0Key: sig0key})
			us.Data = "key"
			us.Type = "TRUSTSTORE-UPDATE"
			log.Printf("* The update is a self-signed KEY upload for the SIG(0) key \"%s\" (keyid %d)", signername, keyid)
			continue
		default:
			log.Printf("-- Update is not a SIG(0) key, so this cannot be a self-signed KEY upload")
			continue
		}
	}

	// At this point we have a set of zero or more keys that match the signername and keyid for a
	// SIG validating the update. Now we must iterate over the keys to see if any of them actually
	// verify correctly.

	for _, signer := range us.Signers {
		keyrr := signer.Sig0Key.Key
		err = sig.Verify(&keyrr, msgbuf)
		if err != nil {
			// This key failed to validate the update. Try the next key.
			log.Printf("-- The signature by the SIG(0) key \"%s\" (keyid %d) failed to verify the update: %v", signer.Name, signer.KeyId, err)
			log.Printf("Current time: %v, inception: %v, expiration: %v", time.Now(), sig.Inception, sig.Expiration)
			continue
		}

		// Ok, we have a signature that validated.
		if WithinValidityPeriod(sig.Inception, sig.Expiration, time.Now().UTC()) {
			us.Log("* The signature by the SIG(0) key \"%s\" (keyid %d) is within its validity period", signer.Name, signer.KeyId)
		} else {
			log.Printf("-- The signature by the SIG(0) key \"%s\" (keyid %d) is NOT within its validity period", signer.Name, signer.KeyId)
			us.ValidationRcode = dns.RcodeBadTime
			// This key validated the signature, but the signature is not within its validity period.
			// Try the next key.
			continue
		}

		log.Printf("* Update validated by known and validated key.")
		us.ValidationRcode = dns.RcodeSuccess
		us.Validated = true // Now at least one key has validated the update
		signer.Validated = true
		continue
	}

	// When we get here then we have tried to validate all signatures and the result is in
	// the us.Signers data.
	return nil
}

// Evaluate the keys that signed the update and determine the trust status of the update.
func (zd *ZoneData) TrustUpdate(r *dns.Msg, us *UpdateStatus) error {
	// dump.P(us)
	if len(us.Signers) == 0 {
		return fmt.Errorf("Update is not signed by any key")
	}
	for _, key := range us.Signers {
		if key.Sig0Key.Trusted {
			zd.Logger.Printf("* Update is signed by trusted SIG(0) key \"%s\" (keyid %d).", key.Name, key.KeyId)
			us.SignatureType = "by-trusted"
			us.ValidatedByTrustedKey = true
			return nil
		}
		if key.Sig0Key.DnssecValidated {
			us.SignatureType = "by-dnssec-validated"
			return nil
		}
		if key.Sig0Key.Source == "child-key-upload" {
			us.SignatureType = "self-signed"
			return nil
		}
	}
	// If we get here then the update is not signed by any trusted, or DNSSEC validated key. Nor
	// is it self-signed.
	us.ValidationRcode = dns.RcodeBadKey
	return fmt.Errorf("Update is signed by %s (keyid %d) which is neither a trusted SIG(0) key nor a DNSSEC validated key", us.Signers[0].Name, us.Signers[0].KeyId)
}

func (zd *ZoneData) FindSig0KeyViaDNS(signer string, keyid uint16) (*Sig0Key, error) {
	zd.Logger.Printf("FindSig0KeyViaDNS: Looking up SIG(0) key %s (keyid %d) in DNS", signer, keyid)
	rrset, err := zd.LookupRRset(signer, dns.TypeKEY, true)
	if err != nil {
		return nil, err
	}
	if rrset == nil {
		return nil, fmt.Errorf("SIG(0) key %s (keyid %d) not found in DNS", signer, keyid)
	}
	valid, err := zd.ValidateRRset(rrset, true)
	if err != nil {
		return nil, err
	}

	zd.Logger.Printf("FindSig0KeyViaDNS: Found %s KEY RRset (validated: %v)", signer, valid)

	for _, rr := range rrset.RRs {
		if keyrr, ok := rr.(*dns.KEY); ok {
			if keyrr.KeyTag() == keyid {
				sk := Sig0Key{
					Name:      signer,
					Keyid:     keyid,
					Validated: valid,
					Source:    "dns",
					Key:       *keyrr,
				}
				// Sig0Store.Map.Set(signer+"::"+string(keyrr.KeyTag()), sk)
				return &sk, nil
			}
		}
	}
	return nil, nil
}
