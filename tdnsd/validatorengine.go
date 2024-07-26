/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"log"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/spf13/viper"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

type CacheRRset struct {
	RRset     *tdns.RRset
	Validated bool
	Expires   time.Time
}

type RRsetCache cmap.ConcurrentMap[string, CacheRRset]

func NewRRsetCache() *RRsetCache {
	cache := cmap.New[CacheRRset]()
	return (*RRsetCache)(&cache)
}

// The ValidatorEngine is responsible for validating RRsets on request. The reason to have it as a separate
// goroutine is to easier be able to keep state and minimize complexity in other parts of the code. Note that
// this is not intended as a general DNSSEC validator, it only aims at being able to validate RRsets in zones
// that we are authoritative for, or in child zones of authoritative zones.

// The common case will be that the RRset is in a child zone, and the delegation is signed. In this case, the
// validator will check that the delegation is correct, and that the child zone is signed.

func ValidatorEngine(conf *Config, stopch chan struct{}) {
	var validatorch = conf.Internal.ValidatorCh
	var vr tdns.ValidatorRequest

	if !viper.GetBool("validator.active") {
		log.Printf("ValidatorEngine is NOT active.")
		for range validatorch {
			log.Printf("ValidatorEngine: ValidatorEngine is not active, but got a request: %v", vr)
			continue // ensure that we keep reading to keep the channel open
		}
	} else {
		log.Printf("ValidatorEngine: Starting")
	}

	// var DnskeyCache = NewRRsetCache()

	var rrset *tdns.RRset
	// var owner
	var rrtype string

	for vr = range validatorch {
		rrset = vr.RRset
		resp := tdns.ValidatorResponse{
			Validated: false,
			Msg:       "ValidatorEngine: request to validate a RRset",
		}

		if rrset == nil {
			log.Printf("ValidatorEngine: request to validate a nil RRset")
			continue
		}

		if len(rrset.RRs) == 0 {
			log.Printf("ValidatorEngine: request to validate an empty RRset")
			continue
		}

		ownername := rrset.RRs[0].Header().Name
		rrtype = dns.TypeToString[rrset.RRs[0].Header().Rrtype]
		log.Printf("ValidatorEngine: request to validate %s %s (%d RRs)", ownername, rrtype, len(rrset.RRs))

		// Is the RRset in a part of the namespace that we know anything about?
		zd, _ := tdns.FindZone(ownername)
		if zd == nil {
			log.Printf("ValidatorEngine: RRset %s %s is not in or below a zone we know anything about", ownername, rrtype)
			continue
		}

		cdd, _, _ := zd.FindDelegation(ownername, true)
		if cdd == nil {
			// If we get here the RRset is in the auth zone represented by zd.
			log.Printf("ValidatorEngine: the %s %s RRset is not in a child zone, but in the %s auth zone. Validated=true", ownername, rrtype, zd.ZoneName)
			owner, err := zd.GetOwner(ownername) // XXX: dnssec_ok = true: doesn't really matter here.
			if err != nil {
				resp.Msg = fmt.Sprintf("ValidatorEngine: error fetching the %s %s RRset from the ZoneData: %v", ownername, rrtype, err)
				log.Print(resp.Msg)
				vr.Response <- resp
				continue
			}

			if owner == nil {
				// XXX: If we get here, then the owner name is not in the zone, but in a child zone (if it exists at all).
				resp.Msg = fmt.Sprintf("ValidatorEngine: the %s %s RRset is not in the auth zone %s. Validated=false", ownername, rrtype, zd.ZoneName)
				log.Print(resp.Msg)
				vr.Response <- resp
				continue
			}

			// XXX: If we get here, then the owner name is either authoritative in the zone, or the exact name of a delegation.
			// If it is a delegation, then there is an NS RRset.
			resp.Msg = fmt.Sprintf("ValidatorEngine: the %s %s RRset is in the auth zone %s. Validated=true", ownername, rrtype, zd.ZoneName)
			log.Print(resp.Msg)
			resp.Validated = true
			vr.Response <- resp
			continue
		} else {
			// XXX: If we get here, then the RRset is in a child zone with an existing delegation
			log.Printf("ValidatorEngine: RRset %s %s is in a child zone with an existing delegation. Validated=true", ownername, rrtype)
			// To validate an RRset in a child zone, we need to:

			// 1. Check that the delegation is signed. If not ==> fail
			if cdd.DS_rrset == nil {
				resp.Msg = fmt.Sprintf("ValidatorEngine: RRset %s %s is below an unsigned delegation", ownername, rrtype)
				log.Print(resp.Msg)
				vr.Response <- resp
				continue
			}
			// 2. Find the child DNSKEY RRset and verify the KSK against the DS that we have. If not ==> fail
			valid, err := zd.ValidateChildDnskeys(cdd, true)
			if err != nil {
				resp.Msg = fmt.Sprintf("ValidatorEngine: Error from ValidateChildDnskeys: %v", err)
				log.Print(resp.Msg)
				vr.Response <- resp
				continue
			}

			if !valid {
				resp.Msg = fmt.Sprintf("ValidatorEngine: Child %s DNSKEY RRset is not valid", ownername)
				log.Print(resp.Msg)
				vr.Response <- resp
				continue
			}

			// 4. Verify the RRset against the verified child DNSKEY that was used to sign the RRset. If not ==> fail
			valid, err = zd.ValidateRRset(rrset, true)
			if err != nil {
				resp.Msg = fmt.Sprintf("ValidatorEngine: Error from ValidateRRset(%v): %v", rrset, err)
				log.Print(resp.Msg)
				// resp.Validated = false
				vr.Response <- resp
				continue
			}
			if !valid {
				resp.Msg = fmt.Sprintf("ValidatorEngine: %s %s RRset did not validate", ownername, rrtype)
				log.Print(resp.Msg)
				// resp.Validated = false
				vr.Response <- resp
				continue
			}
			// 5. If all above checks pass, then the RRset is validated.
			resp.Msg = fmt.Sprintf("ValidatorEngine: %s %s RRset is validated", ownername, rrtype)
			log.Print(resp.Msg)
			resp.Validated = true
			vr.Response <- resp
			continue
		}
	}
}
