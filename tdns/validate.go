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
			msg := fmt.Sprintf("Error from FindDnskey(%s, %d): %v",
				rrsig.SignerName, rrsig.KeyTag, err)
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
	childns, v4glue, v6glue := zd.FindDelegation(qname, true)
	if childns != nil {
		zd.Logger.Printf("LRRset: found a delegation for %s in known zone %s",
			qname, zd.ZoneName)

		rrset, err = zd.LookupChildRRset(qname, qtype, v4glue, v6glue, verbose)
		if err != nil {
			zd.Logger.Printf("LookupRRset: Error from LookupChildRRset: %v", err)
		}
	} else {
		zd.Logger.Printf("*** %s is not a child delegation from %s", qname, zd.ZoneName)
	}

	zd.Logger.Printf("*** owner=%s has RRtypes: ", owner.Name)
	for k, v := range owner.RRtypes {
		zd.Logger.Printf("%s: %d RRs ", dns.TypeToString[k], len(v.RRs))
	}

	// Must instantiate the rrset
	// rrset = &RRset{}

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

func (zd *ZoneData) LookupChildRRset(qname string, qtype uint16,
	v4glue, v6glue *RRset, verbose bool) (*RRset, error) {

	var servers []string

	for _, glue := range v4glue.RRs {
		servers = append(servers, glue.(*dns.A).A.String())
	}
	for _, glue := range v6glue.RRs {
		servers = append(servers, glue.(*dns.AAAA).AAAA.String())
	}

	rrset, _, err := AuthDNSQuery(qname, zd.Logger, servers, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("LCRRset: Error from AuthDNSQuery: %v", err)
	}
	zd.Logger.Printf("LCRRset: looked up %s %s (%d RRs):",
		qname, dns.TypeToString[qtype], len(rrset.RRs))
	log.Printf("LookupChildRRset: done. rrset=%v", rrset)
	return rrset, err
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
			lg.Printf("AuthDNSQuery: using nameserver %s for <%s, %s> query\n",
				ns, qname, dns.TypeToString[rrtype])
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

// If key not found *TrustAnchor is nil
func (zd *ZoneData) FindDnskey(signer string, keyid uint16) (*TrustAnchor, error) {
	mapkey := signer + "::" + string(keyid)
	ta, ok := TAStore.Map.Get(mapkey)
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
				TAStore.Map.Set(signer+"::"+string(dnskeyrr.KeyTag()),
					TrustAnchor{
						Name:      signer,
						Validated: valid,
						Dnskey:    *dnskeyrr,
					})
			}
		}
	}
	ta, ok = TAStore.Map.Get(mapkey)
	return &ta, nil
}

// If key not found *TrustAnchor is nil
func (zd *ZoneData) FindSig0key(signer string, keyid uint16) (*Sig0Key, error) {
	mapkey := fmt.Sprintf("%s::%d", signer, keyid)
	sk, ok := Sig0Store.Map.Get(mapkey)
	if !ok {
		zd.Logger.Printf("FindSig0key: Request for KEY with id %s: not found, will fetch.", mapkey)
		rrset, err := zd.LookupRRset(signer, dns.TypeKEY, true)
		if err != nil {
			return nil, err
		}
		if rrset == nil {
			return nil, fmt.Errorf("SIG(0) key %s not found", signer)
		}
		valid, err := zd.ValidateRRset(rrset, true)
		if err != nil {
			return nil, err
		}
		zd.Logger.Printf("FindSig0key: Found %s KEY RRset (validated)", signer)
		for _, rr := range rrset.RRs {
			if keyrr, ok := rr.(*dns.KEY); ok {
				Sig0Store.Map.Set(signer+"::"+string(keyrr.KeyTag()),
					Sig0Key{
						Name:      signer,
						Validated: valid,
						Key:       *keyrr,
					})
			}
		}
	}
	sk, ok = Sig0Store.Map.Get(mapkey)
	return &sk, nil
}

func (zd *ZoneData) ValidateUpdate(r *dns.Msg) (uint8, string, error) {
	if len(r.Extra) == 0 {
		// there is no signature on the update
		return dns.RcodeFormatError, "", nil
	}

	if _, ok := r.Extra[0].(*dns.SIG); !ok {
		// there is no SIG(0) signature on the update
		return dns.RcodeFormatError, "", nil
	}

	sig := r.Extra[0].(*dns.SIG)
	log.Printf("* Update is signed by \"%s\".", sig.RRSIG.SignerName)
	msgbuf, err := r.Pack()
	if err != nil {
		log.Printf("= Error from msg.Pack(): %v", err)
		return dns.RcodeFormatError, "", nil
	}

	sig0key, err := zd.FindSig0key(sig.RRSIG.SignerName, sig.RRSIG.KeyTag)
	if err != nil || sig0key == nil {
		log.Printf("* Error: update signed by unknown key \"%s\"",
			sig.RRSIG.SignerName)
		return dns.RcodeBadKey, sig.RRSIG.SignerName, nil
	}

	keyrr := sig0key.Key

	log.Printf("tdns.Validate(): signer name: \"%s\"", sig.RRSIG.SignerName)

	err = sig.Verify(&keyrr, msgbuf)
	if err != nil {
		log.Printf("= Error from sig.Verify(): %v", err)
		log.Printf("signername=%s, keyrr=%s", sig.RRSIG.SignerName, keyrr.String())
		return dns.RcodeBadSig, sig.RRSIG.SignerName, err
	} else {
		log.Printf("* Update SIG verified correctly")
	}

	if WithinValidityPeriod(sig.Inception, sig.Expiration, time.Now()) {
		log.Printf("* Update SIG is within its validity period")
	} else {
		log.Printf("= Update SIG is NOT within its validity period")
		return dns.RcodeBadTime, sig.RRSIG.SignerName, nil
	}

	if sig0key.Validated {
		log.Printf("* Update by known and validated key. All ok.")
		return dns.RcodeSuccess, sig.RRSIG.SignerName, nil
	}
	log.Printf("= Update signed by known but unvalidated key. ")
	return dns.RcodeBadKey, sig.RRSIG.SignerName, nil
}
