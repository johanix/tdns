/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"time"

	"github.com/johanix/tdns/v2/cache"
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
		lgDns.Error("ValidateUpdate: error from msg.Pack()", "err", err)
		us.ValidationRcode = dns.RcodeFormatError
		return err
	}

	if len(r.Extra) == 0 { // there is no signature on the update
		us.ValidationRcode = dns.RcodeFormatError
		us.Validated = false
		us.ValidatedByTrustedKey = false
		return fmt.Errorf("update has no signature")
	}

	var sig *dns.SIG
	var ok bool

	// Iterate over all SIG RRs in the Additional section of the update to find all keys that
	// signed the update.
	// log.Printf("ValidateAndTrustUpdate: There are %d RRs in the Additional section of the update", len(r.Extra))
	for idx, rr := range r.Extra {
		lgDns.Debug("ValidateUpdate: examining Additional RR", "index", idx, "type", fmt.Sprintf("%T", rr))
		var sig0key *Sig0Key
		if _, ok := rr.(*dns.SIG); !ok {
			lgDns.Debug("ValidateUpdate: RR in Additional is not a SIG RR, continuing", "type", fmt.Sprintf("%T", rr))
			continue
		}

		sig, ok = rr.(*dns.SIG)
		if !ok {
			// This RR is not a SIG RR (this may be a protocol violation, I don't remember)
			continue
		}

		keyid := sig.RRSIG.KeyTag
		signername := sig.RRSIG.SignerName
		lgDns.Info("ValidateUpdate: update is signed by SIG(0) key", "signer", signername, "keyid", keyid)

		// We have the name and keyid of the key that generated this signature. There are now
		// four possible alternatives for locating the key:
		// 1. The key is in the TrustStore (either as a child key or a key for an auth zone)
		// 2. OBE: The key is in the KeyStore (as a key for an auth zone). This should only happen if (1) is true.
		// 3. The key is published in the child zone and we can look it up via DNS (and hopefully validate it)
		// 4. The key is not to be found anywhere, but the update is a self-signed upload of a SIG(0)
		//    key for the same zone (i.e. the key is in the update as a KEY RR).
		// If all these fail and we don't find the key then the update must be rejected.

		// 1. Is the key in the TrustStore?
		sig0key, err = zd.FindSig0TrustedKey(signername, keyid)
		if err == nil && sig0key != nil {
			lgDns.Info("ValidateUpdate: SIG(0) key found in TrustStore",
				"signer", signername, "keyid", keyid, "validated", sig0key.Validated, "trusted", sig0key.Trusted)
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig0Key: sig0key})
			continue // key found
		} else {
			lgDns.Debug("ValidateUpdate: SIG(0) key NOT found in TrustStore", "signer", signername, "keyid", keyid)
		}

		// 2. Is the key in the KeyStore?. I don't think this is correct. If we want to be able
		// to validate against keys in the KeyStore, then those keys should have their public
		// parts promoted to the TrustStore (and we now do that automatically).

		// 3. Try to find the key via DNS in the child zone
		// XXX: This is not ideal. In the future keys that are not in the TrustStore should be promoted to
		// trusted via some sort of TrustBootstrapper a la RFC8078.

		// BERRA TODO flytta
		sig0key, err = zd.FindSig0KeyViaDNS(signername, keyid)
		if err == nil && sig0key != nil {
			lgDns.Info("ValidateUpdate: SIG(0) key found via DNS lookup", "signer", signername, "keyid", keyid)
			// ok, great that we found the key. but if this is a self-signed key upload then we still need to
			// signal it as such. so lets check if the update is a KEY RR for the same zone
			if len(r.Ns) == 1 {
				if key, ok := r.Ns[0].(*dns.KEY); ok {
					if key.KeyTag() == keyid && key.Algorithm == sig.RRSIG.Algorithm {
						lgDns.Info("ValidateUpdate: update is a self-signed KEY upload", "signer", signername, "keyid", keyid)
						sig0key.Key = *key
						sig0key.PublishedInDNS = true
						sig0key.Source = "child-key-upload"
						us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig0Key: sig0key})
						us.Data = "key"
						us.Type = "TRUSTSTORE-UPDATE"
						continue // key found
					}
				}
			}

			sig0key.PublishedInDNS = true
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig0Key: sig0key})
			continue // key found
		} else {
			lgDns.Debug("ValidateUpdate: SIG(0) key NOT found via DNS lookup", "signer", signername, "keyid", keyid)
		}

		// Last chance: Is the key in the update?
		if len(r.Ns) != 1 {
			lgDns.Debug("ValidateUpdate: update does not consist of a single SIG(0) key, not a self-signed KEY upload")
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
			lgDns.Info("ValidateUpdate: update is a self-signed KEY upload", "signer", signername, "keyid", keyid)
			continue
		default:
			lgDns.Debug("ValidateUpdate: update is not a SIG(0) key, not a self-signed KEY upload")
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
			lgDns.Warn("ValidateUpdate: signature verification failed", "signer", signer.Name, "keyid", signer.KeyId, "err", err)
			lgDns.Debug("ValidateUpdate: timing details", "currentTime", time.Now(), "inception", sig.Inception, "expiration", sig.Expiration)
			continue
		}

		// Ok, we have a signature that validated.
		if cache.WithinValidityPeriod(sig.Inception, sig.Expiration, time.Now().UTC()) {
			us.Log("* The signature by the SIG(0) key \"%s\" (keyid %d) is within its validity period", signer.Name, signer.KeyId)
		} else {
			lgDns.Warn("ValidateUpdate: signature NOT within validity period", "signer", signer.Name, "keyid", signer.KeyId)
			us.ValidationRcode = dns.RcodeBadTime
			// This key validated the signature, but the signature is not within its validity period.
			// Try the next key.
			continue
		}

		lgDns.Info("ValidateUpdate: update validated by known and validated key")
		us.ValidationRcode = dns.RcodeSuccess
		us.Validated = true // Now at least one key has validated the update
		signer.Validated = true
		continue
	}

	// When we get here then we have tried to validate all signatures and the result is in
	// the us.Signers data.
	return nil
}

// BERRA TODO kolla om man kan förbättra detta, så man kan skicka en EDE
// Evaluate the keys that signed the update and determine the trust status of the update.
func (zd *ZoneData) TrustUpdate(r *dns.Msg, us *UpdateStatus) error {
	// dump.P(us)
	if len(us.Signers) == 0 {
		return fmt.Errorf("update has no signature")
	}
	for _, key := range us.Signers {
		// dump.P(key)
		if key.Sig0Key.Trusted {
			lgDns.Info("TrustUpdate: update signed by trusted SIG(0) key", "signer", key.Name, "keyid", key.KeyId)
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
	return fmt.Errorf("update is signed by %s (keyid %d) which is neither a trusted SIG(0) key nor a DNSSEC validated key", us.Signers[0].Name, us.Signers[0].KeyId)
}

func (zd *ZoneData) FindSig0KeyViaDNS(signer string, keyid uint16) (*Sig0Key, error) {
	lgDns.Debug("FindSig0KeyViaDNS: looking up SIG(0) key in DNS", "signer", signer, "keyid", keyid)
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

	lgDns.Debug("FindSig0KeyViaDNS: found KEY RRset", "signer", signer, "validated", valid)

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
