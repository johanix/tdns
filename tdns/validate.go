/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// 1. Find the child NS RRset
// 2. Find the address of each NS
// 3. Query child NS for <qname, qtype>

func (zd *ZoneData) LookupAndValidateRRset(qname string, qtype uint16,
	verbose bool) (*RRset, bool, error) {
	rrset, err := zd.LookupRRset(qname, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("LookupAndValidateRRset: Error from LookupRRset: %v", err)
		return nil, false, err
	}

	if rrset == nil {
		zd.Logger.Printf("LookupAndValidateRRset: No RRset returned from LookupRRset(%s, %s)", qname, dns.TypeToString[qtype])
		return nil, false, nil
	}

	valid, err := zd.ValidateRRset(rrset, verbose)
	if err != nil {
		zd.Logger.Printf("LookupAndValidateRRset: Error from ValidateRRset: %v", err)
		return nil, false, err
	}

	return rrset, valid, nil
}

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
func (zd *ZoneData) ValidateRRset(rrset *RRset, verbose bool) (bool, error) {
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
			zd.Logger.Printf("%s", msg)
			return false, fmt.Errorf(msg)
		}
		if ta == nil {
			// don't yet know how to lookup and validate new keys
			msg := fmt.Sprintf("Error: key \"%s\" is unknown.", rrsig.SignerName)
			zd.Logger.Printf("%s", msg)
			return false, fmt.Errorf(msg)
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

		time_ok := WithinValidityPeriod(rrsig.Inception,
			rrsig.Expiration, time.Now())
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

func (zd *ZoneData) LookupRRset(qname string, qtype uint16, verbose bool) (*RRset, error) {
	zd.Logger.Printf("LookupRRset: looking up %s %s", qname, dns.TypeToString[qtype])
	var rrset *RRset
	var wildqname string
	origqname := qname

	// Is answer in this zone or further down?
	if !zd.NameExists(qname) {
		// Here we should do wildcard expansion like in QueryResponder()
		wildqname = "*." + strings.Join(strings.Split(qname, ".")[1:], ".")
		log.Printf("---> Checking for existence of wildcard %s", wildqname)
		if !zd.NameExists(wildqname) {
			// no, nothing
			zd.Logger.Printf("*** No data for %s in %s", wildqname, zd.ZoneName)
			return nil, nil
		}
		origqname = qname
		qname = wildqname
		zd.Logger.Printf("*** %s is a wildcard expansion from %s", origqname, wildqname)
	}

	owner, err := zd.GetOwner(qname)

	if len(owner.RRtypes) == 0 {
		// No, nothing.
		zd.Logger.Printf("*** No data for %s in %s", qname, zd.ZoneName)
		return nil, nil // nothing found, but this is not an error
	}

	// Check for qname + CNAME: defer this to later.

	// Check for child delegation
	cdd, v4glue, v6glue := zd.FindDelegation(qname, true)
	// if childns != nil {
	if cdd != nil && cdd.NS_rrset != nil {
		zd.Logger.Printf("LRRset: found a delegation for %s in known zone %s",
			qname, zd.ZoneName)

		rrset, err = zd.LookupChildRRset(qname, qtype, v4glue, v6glue, verbose)
		if err != nil {
			zd.Logger.Printf("LookupRRset: Error from LookupChildRRset: %v", err)
		}
		return rrset, err
	} else {
		zd.Logger.Printf("*** %s is not a child delegation from %s", qname, zd.ZoneName)
	}

	zd.Logger.Printf("*** Current data for owner name=%s: RRtypes: ", owner.Name)
	for k, v := range owner.RRtypes {
		zd.Logger.Printf("%s: %d RRs ", dns.TypeToString[k], len(v.RRs))
	}

	// Must instantiate the rrset if not found above
	if rrset == nil {
		rrset = &RRset{}
	}

	// Check for exact match qname + qtype
	if _, ok := owner.RRtypes[qtype]; ok && len(owner.RRtypes[qtype].RRs) > 0 {
		zd.Logger.Printf("*** %d RRs: %v", len(owner.RRtypes[qtype].RRs), owner.RRtypes[qtype].RRs)
		// XXX: Dont forget that we also need to deal with CNAMEs in here
		if qname == origqname {
			rrset.RRs = owner.RRtypes[qtype].RRs
			rrset.RRSIGs = owner.RRtypes[qtype].RRSIGs
		} else {
			tmp := WildcardReplace(owner.RRtypes[qtype].RRs, qname, origqname)
			rrset.RRs = tmp
			tmp = WildcardReplace(owner.RRtypes[qtype].RRSIGs, qname, origqname)
			rrset.RRSIGs = tmp
		}
	}

	for _, rr := range rrset.RRs {
		zd.Logger.Printf("%s", rr.String())
	}
	for _, rr := range rrset.RRSIGs {
		zd.Logger.Printf("%s", rr.String())
	}

	log.Printf("LookupRRset: done. rrset=%v", rrset)
	return rrset, err
}

// XXX: This should die in favor of LookupChildRRsetNG
func (zd *ZoneData) LookupChildRRset(qname string, qtype uint16,
	v4glue, v6glue *RRset, verbose bool) (*RRset, error) {

	var servers []string

	for _, glue := range v4glue.RRs {
		servers = append(servers, net.JoinHostPort(glue.(*dns.A).A.String(), "53"))
	}
	for _, glue := range v6glue.RRs {
		servers = append(servers, net.JoinHostPort(glue.(*dns.AAAA).AAAA.String(), "53"))
	}

	rrset, _, err := AuthDNSQuery(qname, zd.Logger, servers, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("LCRRset: Error from AuthDNSQuery: %v", err)
	}
	zd.Logger.Printf("LCRRset: looked up %s %s (%d RRs):", qname, dns.TypeToString[qtype], len(rrset.RRs))
	// log.Printf("LookupChildRRset: done. rrset=%v", rrset)
	return rrset, err
}

func (zd *ZoneData) LookupChildRRsetNG(qname string, qtype uint16,
	addrs []string, verbose bool) (*RRset, error) {

	rrset, _, err := AuthDNSQuery(qname, zd.Logger, addrs, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("LCRRsetNG: Error from AuthDNSQuery: %v", err)
	}
	zd.Logger.Printf("LCRRsetNG: looked up %s %s (%d RRs):",
		qname, dns.TypeToString[qtype], len(rrset.RRs))
	log.Printf("LookupChildRRsetNG: done. rrset=%v", rrset)
	return rrset, err
}

func ChildGlueRRsetsToAddrs(v4glue, v6glue []*RRset) ([]string, error) {
	var addrs []string
	for _, nsname := range v4glue {
		for _, glue := range nsname.RRs {
			addrs = append(addrs, net.JoinHostPort(glue.(*dns.A).A.String(), "53"))
		}
	}

	for _, nsname := range v6glue {
		for _, glue := range nsname.RRs {
			addrs = append(addrs, net.JoinHostPort(glue.(*dns.AAAA).AAAA.String(), "53"))
		}
	}
	return addrs, nil
}

func AuthDNSQuery(qname string, lg *log.Logger, nameservers []string,
	rrtype uint16, verbose bool) (*RRset, int, error) {
	var rrset RRset
	var rcode int

	// c := dns.Client{Net: "tcp"}

	m := new(dns.Msg)
	m.SetQuestion(qname, rrtype)
	m.SetEdns0(4096, true)
	for _, ns := range nameservers {
		if ns[len(ns)-3:] != ":53" {
			ns = net.JoinHostPort(ns, "53")
		}
		if verbose {
			// lg.Printf("AuthDNSQuery: using nameserver %s for <%s, %s> query\n",
			// 	ns, qname, dns.TypeToString[rrtype])
		}
		r, err := dns.Exchange(m, ns)
		// r, _, err := c.Exchange(m, ns)
		if err != nil && verbose {
			lg.Printf("AuthDNSQuery: Error from dns.Exchange: %v", err)
			continue // go to next server
		}

		if r != nil {
			rcode = r.MsgHdr.Rcode
			if len(r.Answer) != 0 {
				for _, rr := range r.Answer {
					switch t := rr.Header().Rrtype; t {
					case rrtype:
						rrset.RRs = append(rrset.RRs, rr)
					case dns.TypeRRSIG:
						rrset.RRSIGs = append(rrset.RRSIGs, rr)
					default:
						lg.Printf("Got a %s RR when looking for %s %s",
							dns.TypeToString[t], qname,
							dns.TypeToString[rrtype])
					}
				}
				return &rrset, rcode, nil
			} else {
				if rcode == dns.StringToRcode["NOERROR"] {
					return &rrset, rcode, nil // no point in continuing
				}
				continue // go to next server
			}
		} else {
			continue // go to next server
		}
	}
	return &rrset, rcode, fmt.Errorf("No Answers found from any auth server looking up '%s %s'.\n",
		qname, dns.TypeToString[rrtype])
}

// XXX: This should not be a method of ZoneData, but rather a function.
// If key not found *TrustAnchor is nil
func (zd *ZoneData) FindDnskey(signer string, keyid uint16) (*TrustAnchor, error) {
	mapkey := signer + "::" + string(keyid)
	ta, ok := DnskeyCache.Map.Get(mapkey)
	if !ok {
		zd.Logger.Printf("FindDnskey: Request for DNSKEY with id %s: not found, will fetch.", mapkey)
		rrset, err := zd.LookupRRset(signer, dns.TypeDNSKEY, true)
		if err != nil {
			return nil, err
		}
		valid, err := zd.ValidateRRset(rrset, true)
		if err != nil {
			return nil, err
		}
		zd.Logger.Printf("FindDnskey: Found %s DNSKEY RRset (validated)", signer)
		for _, rr := range rrset.RRs {
			if dnskeyrr, ok := rr.(*dns.DNSKEY); ok {
				DnskeyCache.Map.Set(signer+"::"+string(dnskeyrr.KeyTag()),
					TrustAnchor{
						Name:      signer,
						Validated: valid,
						Dnskey:    *dnskeyrr,
					})
			}
		}
		ta, ok = DnskeyCache.Map.Get(mapkey)
	}
	return &ta, nil
}

// XXX: This should not be a method of ZoneData, but rather a function.
// If key not found *TrustAnchor is nil
func (zd *ZoneData) xxxFindSig0TrustedKey(signer string, keyid uint16) (*Sig0Key, error) {
	mapkey := fmt.Sprintf("%s::%d", signer, keyid)

	// 1. Try to fetch the key from the Sig0Store cache
	if sk, ok := Sig0Store.Map.Get(mapkey); ok {
		return &sk, nil
	}

	const (
		fetchsig0trustanchor = "SELECT validated, trusted, keyrr FROM Sig0TrustStore WHERE zonename=? AND keyid=?"
	)

	// 2. Try to fetch the key from the Sig0TrustStore database
	rows, err := zd.KeyDB.Query(fetchsig0trustanchor, signer, keyid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var validated, trusted bool
		var keyrrstr string
		err = rows.Scan(&validated, &trusted, &keyrrstr)
		if err != nil {
			return nil, err
		}
		rr, err := dns.NewRR(keyrrstr)
		if err != nil {
			return nil, err
		}
		keyrr, ok := rr.(*dns.KEY)
		if !ok {
			return nil, fmt.Errorf("FindSig0TrustedKey: Error: SIG(0) key %s in KeyDB is not a KEY RR", signer)
		}
		sk := Sig0Key{
			Name:      signer,
			Validated: validated,
			Trusted:   trusted,
			Key:       *keyrr,
		}
		Sig0Store.Map.Set(mapkey, sk)
		return &sk, nil
	}

	// 3. Try to fetch the key from the Sig0KeyStore database.
	// XXX: Note that if the key is present and active in the KeyStore (because it is for a
	// zone that we are authoritative for) but not in the TrustStore then we will import it
	// into the TrustStore automatically.

	sak, err := zd.KeyDB.GetSig0ActiveKeys(signer)
	if err != nil {
		return nil, err
	}

	if len(sak.Keys) > 0 {
		for _, key := range sak.Keys {
			if key.KeyRR.KeyTag() == keyid {
				// This key that is present and active in the KeyStore is not present in the TrustStore
				// Let's add it now.

				return &Sig0Key{
					Name:      signer,
					Validated: true,
					Trusted:   true,
					Key:       key.KeyRR,
				}, nil
			}
		}
	}

	// 4. Try to fetch the key by looking up and validating the KEY RRset via DNS
	zd.Logger.Printf("FindSig0TrustedKey: SIG(0) key with id %s: not found in TrustStore, will fetch via DNS.", mapkey)
	rrset, err := zd.LookupRRset(signer, dns.TypeKEY, true)
	if err != nil {
		return nil, err
	}
	if rrset == nil {
		return nil, fmt.Errorf("SIG(0) trusted key %s not found", signer)
	}
	valid, err := zd.ValidateRRset(rrset, true)
	if err != nil {
		return nil, err
	}
	zd.Logger.Printf("FindSig0TrustedKey: Found %s KEY RRset (validated)", signer)
	for _, rr := range rrset.RRs {
		if keyrr, ok := rr.(*dns.KEY); ok {
			sk := Sig0Key{
				Name:      signer,
				Validated: valid,
				Key:       *keyrr,
			}
			Sig0Store.Map.Set(signer+"::"+string(keyrr.KeyTag()), sk)
			return &sk, nil
		}
	}

	return nil, fmt.Errorf("SIG(0) trusted key %s not found in TrustStore", signer)
}

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
	for _, rr := range r.Extra {
		var sig0key *Sig0Key
		if _, ok := rr.(*dns.SIG); !ok {
			us.Log("ValidateAndTrustUpdate: RR in Additional is not a SIG RR, continuing")
			continue
		}

		sig, ok = r.Extra[0].(*dns.SIG)
		if !ok {
			// This RR is not a SIG RR (this may be a protocol violation, I don't remember)
			continue
		}

		keyid := sig.RRSIG.KeyTag
		signername := sig.RRSIG.SignerName
		us.Log("* Update is signed by SIG(0) key \"%s\" (keyid %d).", signername, keyid)

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
			us.Log("* The SIG(0) key \"%s\" (keyid %d) was found in the TrustStore", signername, keyid)
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig0Key: sig0key})
			continue // key found
		} else {
			us.Log("* The SIG(0) key \"%s\" (keyid %d) was NOT found in the TrustStore",
				signername, keyid)
		}

		// 2. Is the key in the KeyStore?. I don't think this is correct. If we want to be able
		// to validate against keys in the KeyStore, then those keys should have their public
		// parts promoted to the TrustStore automatically (and we now do that automatically).

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
			us.Log("* The SIG(0) key \"%s\" (keyid %d) was found via DNS lookup", signername, keyid)
			us.Signers = append(us.Signers, Sig0UpdateSigner{Name: signername, KeyId: keyid, Sig0Key: sig0key})
			continue // key found
		} else {
			us.Log("* The SIG(0) key \"%s\" (keyid %d) was NOT found via DNS lookup", signername, keyid)
		}

		// Last chance: Is the key in the update?
		if len(r.Ns) != 1 {
			us.Log("-- Update does not consist of a single SIG(0) key, so this cannot be a self-signed KEY upload")
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
			us.Log("* The update is a self-signed KEY upload for the SIG(0) key \"%s\" (keyid %d)", signername, keyid)
			continue
		default:
			us.Log("-- Update is not a SIG(0) key, so this cannot be a self-signed KEY upload")
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
			us.Log("-- The signature by the SIG(0) key \"%s\" (keyid %d) failed to verify the update: %v", signer.Name, signer.KeyId, err)
			continue
		}

		// Ok, we have a signature that validated.
		if WithinValidityPeriod(sig.Inception, sig.Expiration, time.Now()) {
			us.Log("* The signature by the SIG(0) key \"%s\" (keyid %d) is within its validity period", signer.Name, signer.KeyId)
		} else {
			us.Log("-- The signature by the SIG(0) key \"%s\" (keyid %d) is NOT within its validity period", signer.Name, signer.KeyId)
			us.ValidationRcode = dns.RcodeBadTime
			// This key validated the signature, but the signature is not within its validity period.
			// Try the next key.
			continue
		}

		us.Log("* Update validated by known and validated key.")
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
	for _, key := range us.Signers {
		if key.Sig0Key.Trusted {
			zd.Logger.Printf("* Update is signed by trusted SIG(0) key \"%s\" (keyid %d).", key.Name, key.KeyId)
			us.SignatureType = "by-trusted"
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
	return fmt.Errorf("Update is not signed by a trusted SIG(0) key")
}

// ValidateChildDnskeys: we have the ChildDelegationData for the child zone,
// containing both the NS RRset and the DS RRset.
// 1. Fetch the child DNSKEY RRset from one of the child nameservers
// 2. Verify the child KSK against the DS that we have
// 3. Verify the child DNSKEY RRset against the verified KSK
// 4. Store the child DNSKEY RRset in the TrustAnchor store
// 5. Return true if the child DNSKEY RRset is validated
func (zd *ZoneData) ValidateChildDnskeys(cdd *ChildDelegationData, verbose bool) (bool, error) {

	addrs, err := ChildGlueRRsetsToAddrs(cdd.A_rrsets, cdd.AAAA_rrsets)
	if err != nil {
		return false, err
	}

	dnskeyrrset, err := zd.LookupChildRRsetNG(cdd.ChildName, dns.TypeDNSKEY, addrs, verbose)
	if err != nil {
		return false, err
	}

	kskValidated := false

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
						if computedDS.Digest == dsrr.Digest {
							zd.Logger.Printf("ValidateChildDnskeys: DNSKEY matches DS record. Adding to TAStore.")
							// DNSKEY is verified against the DS record

							// Store the KSK in the DnskeyCache
							keyname := dnskey.Header().Name
							lookupKey := keyname + "::" + fmt.Sprint(keyid)
							expiration := time.Now().Add(time.Duration(dnskey.Header().Ttl) * time.Second)
							ta := TrustAnchor{
								Name:       keyname,
								Validated:  true,
								Dnskey:     *dnskey,
								Expiration: expiration,
							}
							DnskeyCache.Map.Set(lookupKey, ta)
							zd.Logger.Printf("ValidateChildDnskeys: Stored KSK in TAStore with key %s and expiration %v", lookupKey, expiration)
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
		return false, fmt.Errorf("No valid KSK found for child zone %s", cdd.ChildName)
	}

	// Validate the entire DNSKEY RRset
	valid, err := zd.ValidateRRset(dnskeyrrset, verbose)
	if err != nil || !valid {
		return false, fmt.Errorf("Failed to validate DNSKEY RRset for child zone %s", cdd.ChildName)
	}

	// Add ZSKs to the TAStore
	for _, rr := range dnskeyrrset.RRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if dnskey.Flags == 256 { // ZSK
				keyname := dnskey.Header().Name
				keyid := dnskey.KeyTag()
				lookupKey := fmt.Sprintf("%s::%d", keyname, keyid)
				expiration := time.Now().Add(time.Duration(dnskey.Header().Ttl) * time.Second)
				ta := TrustAnchor{
					Name:       keyname,
					Validated:  true,
					Dnskey:     *dnskey,
					Expiration: expiration,
				}
				DnskeyCache.Map.Set(lookupKey, ta)
				zd.Logger.Printf("ValidateChildDnskeys: Stored ZSK in DnskeyCache with key %s and expiration %v", lookupKey, expiration)
			}
		}
	}

	return true, nil
}

// From Mieks DNS lib:
// const year68 = 1 << 31 // For RFC1982 (Serial Arithmetic) calculations in 32 bits.

// ValidityPeriod uses RFC1982 serial arithmetic to calculate
// if a signature period is valid. If t is the zero time, the
// current time is taken other t is. Returns true if the signature
// is valid at the given time, otherwise returns false.
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

// ValidityPeriod uses RFC1982 serial arithmetic to calculate
// if a signature period is valid. If t is the zero time, the
// current time is taken other t is. Returns true if the signature
// is valid at the given time, otherwise returns false.
func xxxSIGValidityPeriod(sig *dns.SIG, t time.Time) bool {
	var utc int64
	if t.IsZero() {
		utc = time.Now().UTC().Unix()
	} else {
		utc = t.UTC().Unix()
	}
	modi := (int64(sig.Inception) - utc) / year68
	mode := (int64(sig.Expiration) - utc) / year68
	ti := int64(sig.Inception) + modi*year68
	te := int64(sig.Expiration) + mode*year68
	return ti <= utc && utc <= te
}

func xxxRRSIGValidityPeriod(rrsig *dns.RRSIG, t time.Time) bool {
	var utc int64
	if t.IsZero() {
		utc = time.Now().UTC().Unix()
	} else {
		utc = t.UTC().Unix()
	}
	modi := (int64(rrsig.Inception) - utc) / year68
	mode := (int64(rrsig.Expiration) - utc) / year68
	ti := int64(rrsig.Inception) + modi*year68
	te := int64(rrsig.Expiration) + mode*year68
	return ti <= utc && utc <= te
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
