/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
	// "github.com/gookit/goutil/dump"
)

// The general idea is to iterate over all SIG RRs in the Additional section of the update to find
// all keys that signed the update. Then iterate over all the located keys to see which key, if any,
// successfully validates the update.

// XXX: This should perhaps not be a method of ZoneData, but rather of KeyDB.
func (zd *ZoneData) ValidateUpdate(r *dns.Msg, us *UpdateStatus) error {
	// Fail closed by default. Each branch that successfully verifies a
	// signature lifts ValidationRcode to RcodeSuccess (or another specific
	// rcode such as RcodeBadTime for "verified but outside validity
	// window"). RcodeFormatError early-returns overwrite this for
	// structural problems. Without this default, an UPDATE that arrives
	// with a SIG(0) signature but no key successfully verifies it would
	// land at the function's end with the zero-valued ValidationRcode
	// (RcodeSuccess), causing the responder to return NOERROR for an
	// update it actually rejected.
	us.ValidationRcode = dns.RcodeBadSig

	var extraTypes []string
	for _, rr := range r.Extra {
		extraTypes = append(extraTypes, fmt.Sprintf("%s(%d)", dns.TypeToString[rr.Header().Rrtype], rr.Header().Rrtype))
	}
	lgDns.Info("ValidateUpdate: message details", "compress", r.Compress, "id", r.Id, "extra_count", len(r.Extra), "extra_types", extraTypes, "ns_count", len(r.Ns), "question", len(r.Question), "answer", len(r.Answer))

	// SIG(0) verification has to run over the wire bytes of the message
	// as it was signed. miekg/dns gives us the parsed *dns.Msg and we
	// re-pack it to obtain those bytes. This round-trip is supposed to
	// be the identity, but it isn't for §2.5.2 delete-RRset records
	// (RFC 2136): an Update RR with class ANY and rdlength 0.
	//
	// On unpack, miekg looks at the type byte and constructs the typed
	// RR (e.g. *dns.DS, *dns.A, *dns.RRSIG) with all rdata fields at
	// their zero values, then short-circuits via noRdata(h) before
	// calling rr.unpack(). The resulting struct has empty fields. So
	// far so good — except that on re-pack, miekg's per-type pack()
	// unconditionally serializes the fixed-size scalar fields. For
	// example *dns.DS.pack writes KeyTag (2) + Algorithm (1) +
	// DigestType (1) + Digest (variable, 0 bytes when empty) = 4 bytes
	// of phantom rdata. The repack ends up 4 bytes longer than the
	// wire, the SIG hash is computed over the wrong bytes, and
	// signature verification fails with "dns: bad signature".
	//
	// Types whose rdata is a single domain name (NS, CNAME, PTR, MX,
	// SOA, ...) escape this because packDomainName special-cases the
	// empty string at msg.go:211 — comment there literally says "Ok,
	// for instance when dealing with update RR without any rdata."
	// That handling was added for delete-RRset records but only covers
	// the domain-name field. Types with fixed scalar fields (DS,
	// DNSKEY, A, AAAA, RRSIG, SVCB, ...) all repack with phantom rdata.
	//
	// We believe this is a bug in miekg/dns. The local fork carries a
	// fix on the unpack path (commit 8da19b0b on branch mldsa44-sig0):
	// CLASS=ANY+Rdlength=0 records now return *dns.ANY directly from
	// UnpackRRWithHeader, matching what high-level RemoveRRset already
	// produces and what §2.5.3 (CLASS=ANY+TYPE=ANY) already does. With
	// that patch this loop is a self-replacement no-op.
	//
	// We keep the workaround in mainline tdns so consumers building
	// against unpatched upstream miekg/dns don't need the fork. Remove
	// when the fix lands upstream and minimum miekg/dns ≥ vX.Y.Z is
	// pinned in go.mod.
	//
	// Until then we patch the parsed message here: any §2.5.2 record
	// (class ANY, rdlength 0) is replaced with a *dns.ANY placeholder
	// before re-pack. *dns.ANY's pack() correctly writes 0 bytes,
	// so the repack matches the wire and SIG verification succeeds.
	for i, rr := range r.Ns {
		if rr == nil {
			continue
		}
		h := rr.Header()
		if h.Class == dns.ClassANY && h.Rdlength == 0 {
			r.Ns[i] = &dns.ANY{Hdr: *h}
		}
	}

	msgbuf, err := r.Pack()
	if err != nil {
		lgDns.Error("ValidateUpdate: error from msg.Pack()", "err", err)
		us.ValidationRcode = dns.RcodeFormatError
		us.RejectionEDE = edns0.EDESig0FormatError
		return err
	}
	lgDns.Info("ValidateUpdate: packed message", "buflen", len(msgbuf), "first32", fmt.Sprintf("%x", msgbuf[:min(32, len(msgbuf))]))

	if len(r.Extra) == 0 { // there is no signature on the update
		us.ValidationRcode = dns.RcodeFormatError
		us.RejectionEDE = edns0.EDESig0FormatError
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
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig: sig, Sig0Key: sig0key})
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
						us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig: sig, Sig0Key: sig0key})
						us.Data = "key"
						us.Type = "TRUSTSTORE-UPDATE"
						continue // key found
					}
				}
			}

			sig0key.PublishedInDNS = true
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig: sig, Sig0Key: sig0key})
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
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig: sig, Sig0Key: sig0key})
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

	// Iterate by index so signer.Validated writes back into the
	// slice (the previous range-over-value form mutated a copy).
	//
	// EVERY signer is verified; we deliberately do NOT stop at the first
	// success. signer.Validated is a PER-SIGNER property ("this signer's own
	// signature verified over the message bytes") and TrustUpdate reads it to
	// decide whether a given signer may confer trust. Breaking on the first
	// success left every later signer at Validated=false, which made trust
	// depend on SIG RR ORDER: in a dual-signed rollover UPDATE (old trusted
	// key + new not-yet-trusted key, both signing genuinely), if the untrusted
	// key's SIG happened to come first the trusted key was never verified,
	// TrustUpdate skipped it on !key.Validated, and a legitimate rollover was
	// refused. Reversing the SIG order accepted the very same message.
	//
	// The aggregate fields (ValidationRcode / RejectionEDE / Validated /
	// SignerName) still mean "at least one signature verified", so a later
	// FAILING signer must not overwrite an earlier success — every failure
	// path below is guarded on !us.Validated, which is what the old `break`
	// was really protecting. First success wins for SignerName.
	//
	// This does not weaken the check TrustUpdate relies on: a forged SIG
	// naming a trusted key still fails Verify(), keeps Validated=false, and is
	// still skipped there. The signer set is bounded by the discovery loop
	// above, which only appends signers whose key was actually locatable.
	for i := range us.Signers {
		signer := &us.Signers[i]
		// Use the per-signer SIG, not the outer sig variable (which
		// holds whichever SIG was last parsed in the discovery loop
		// above). For a single-signature UPDATE this is the same
		// pointer, but for multi-signature UPDATEs the discovery
		// loop iterated multiple SIG RRs and would have left the
		// outer sig pointing at the last one.
		ssig := signer.Sig
		if ssig == nil {
			continue
		}
		keyrr := signer.Sig0Key.Key
		err = ssig.Verify(&keyrr, msgbuf)
		if err != nil {
			// This key failed to validate the update. Categorize the
			// failure: if NOW is outside the signature's validity
			// window, the most likely cause is clock skew between
			// the signer and verifier — that's BADTIME, not BADSIG.
			// Detecting it here (rather than via fragile string
			// matching on miekg/dns's "dns: bad time" error string)
			// is robust to library version changes. Phase 11 of the
			// rollover overhaul: surface this as a specific rcode +
			// EDE so the child operator can diagnose clock skew
			// without parent-side log access.
			//
			// Guarded on !us.Validated: an earlier signer may already have
			// verified, and this failure must not downgrade that success.
			if !us.Validated {
				if !cache.WithinValidityPeriod(ssig.Inception, ssig.Expiration, time.Now().UTC()) {
					us.ValidationRcode = dns.RcodeBadTime
					us.RejectionEDE = edns0.EDESig0BadTime
				} else if us.RejectionEDE == 0 {
					us.RejectionEDE = edns0.EDESig0BadSignature
				}
			}
			lgDns.Warn("ValidateUpdate: signature verification failed", "signer", signer.Name, "keyid", signer.KeyId, "err", err)
			lgDns.Debug("ValidateUpdate: timing details", "currentTime", time.Now(), "inception", ssig.Inception, "expiration", ssig.Expiration)
			continue
		}

		// Ok, we have a signature that validated.
		if !cache.WithinValidityPeriod(ssig.Inception, ssig.Expiration, time.Now().UTC()) {
			lgDns.Warn("ValidateUpdate: signature NOT within validity period", "signer", signer.Name, "keyid", signer.KeyId)
			// Guarded: must not downgrade an earlier signer's success.
			if !us.Validated {
				us.ValidationRcode = dns.RcodeBadTime
				us.RejectionEDE = edns0.EDESig0BadTime
			}
			// This key validated the signature, but the signature is not within its validity period.
			// Try the next key.
			continue
		}

		// Signature is valid and within its validity period. Mark THIS signer
		// unconditionally — that is the per-signer fact TrustUpdate consumes.
		lgDns.Info("ValidateUpdate: signature within validity period", "signer", signer.Name, "keyid", signer.KeyId)
		lgDns.Info("ValidateUpdate: update validated by known and validated key")
		signer.Validated = true

		// Aggregate status: record the first success and leave it alone
		// thereafter, so SignerName stays stable and a later signer cannot
		// churn the rcode/EDE.
		if !us.Validated {
			us.ValidationRcode = dns.RcodeSuccess
			us.RejectionEDE = 0 // success — clear any prior key's failure EDE
			us.Validated = true // Now at least one key has validated the update
			us.SignerName = signer.Name
		}
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
		// No locatable signing key for any SIG in the UPDATE. This branch
		// also covers a fully-unsigned UPDATE (no SIG RR at all): both map
		// to BADKEY(17). Per draft-ietf-dnsop-delegation-mgmt-via-ddns-02
		// §"RCODE BADKEY", an unknown key is a definitive BADKEY so the
		// child falls back to bootstrapping its key into the receiver.
		// Conflating "unsigned" with "unknown key" is a deliberate choice:
		// a child re-bootstrapping off its own unsigned UPDATE is harmless.
		us.ValidationRcode = dns.RcodeBadKey
		us.RejectionEDE = edns0.EDESig0KeyNotKnown
		return fmt.Errorf("update has no locatable signing key")
	}

	// A key was located but no signature actually verified over the message
	// bytes (forged/tampered signature, or one outside its validity window).
	// ValidateUpdate already recorded the precise failure (BadSig / BadTime
	// plus the matching EDE); do NOT fall through to the trust checks below,
	// which read only the key's stored flags. Without this guard a trusted
	// key's KeyTag placed over tampered bytes would be reported as trusted
	// (us.ValidatedByTrustedKey=true) while ValidationRcode is still BadSig.
	// ApproveUpdate also hard-rejects a non-Success ValidationRcode, but we
	// fail closed here so the trust flags are never set for an unverified
	// signature. A well-formed self-signed key upload verifies, so it has
	// Validated=true and is unaffected.
	if !us.Validated {
		if us.RejectionEDE == 0 {
			us.RejectionEDE = edns0.EDESig0BadSignature
		}
		return fmt.Errorf("update signed by %s (keyid %d) but no signature verified", us.Signers[0].Name, us.Signers[0].KeyId)
	}

	for _, key := range us.Signers {
		// dump.P(key)
		// A located key confers trust ONLY if its OWN signature verified over
		// the message bytes. us.Validated above is an aggregate ("at least one
		// signature verified"), which is not sufficient here: ValidateUpdate's
		// discovery loop appends a signer for every SIG RR matched on
		// SignerName+KeyTag alone, before any signature is checked, so a signer
		// whose signature then failed to verify is still present with
		// Validated=false. Without this per-signer check, a multi-SIG(0) UPDATE
		// could pair a genuine signature from an untrusted key with a forged SIG
		// naming a trusted key and be granted "by-trusted" status even though
		// the trusted key's signature was never verified. That would also defeat
		// the untrusted-KEY-delete refusal in ApproveTrustUpdate, which is gated
		// on us.ValidatedByTrustedKey.
		//
		// ValidateUpdate verifies every signer (it does not stop at the first
		// success), so in a legitimately dual-signed rollover UPDATE both the
		// old and the new key carry Validated=true and the loop below finds the
		// trusted one regardless of SIG RR order.
		if !key.Validated {
			continue
		}
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
	// A signature verified with a located key that is nonetheless neither
	// trusted, DNSSEC-validated, nor a self-signed upload. Per ddns-02
	// §"Communication in Case of Errors" the key is known but not (or no
	// longer) trusted, so respond REFUSED carrying EDE KEY-KNOWN-NOT-TRUSTED
	// — distinct from BADKEY, which means the key is unknown.
	us.ValidationRcode = dns.RcodeRefused
	us.RejectionEDE = edns0.EDESig0KeyKnownButNotTrusted
	return fmt.Errorf("update is signed by %s (keyid %d) which is known but not trusted", us.Signers[0].Name, us.Signers[0].KeyId)
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
