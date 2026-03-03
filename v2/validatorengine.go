/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// The ValidatorEngine is responsible for validating RRsets on request. The reason to have it as a separate
// goroutine is to easier be able to keep state and minimize complexity in other parts of the code. Note that
// this is not intended as a general DNSSEC validator, it only aims at being able to validate RRsets in zones
// that we are authoritative for, or in child zones of authoritative zones.

// The common case will be that the RRset is in a child zone, and the delegation is signed. In this case, the
// validator will check that the delegation is correct, and that the child zone is signed.

func ValidatorEngine(ctx context.Context, conf *Config) {
	var validatorch = conf.Internal.ValidatorCh
	var vr ValidatorRequest
	var ok bool

	if !viper.GetBool("validator.active") {
		lgEngine.Info("validator engine not active")
		for {
			select {
			case <-ctx.Done():
				lgEngine.Info("validator engine terminating (inactive mode)", "reason", "context cancelled")
				return
			case vr, ok = <-validatorch:
				if !ok {
					lgEngine.Info("validator engine terminating", "reason", "validatorch closed")
					return
				}
			}
			lgEngine.Warn("validator engine not active but received request", "request", vr)
			continue // ensure that we keep reading to keep the channel open
		}
	} else {
		lgEngine.Info("validator engine starting")
	}

	// var DnskeyCache = NewRRsetCache()

	var rrset *core.RRset
	// var owner
	var rrtype string

	for {
		select {
		case <-ctx.Done():
			lgEngine.Info("validator engine terminating", "reason", "context cancelled")
			return
		case vr, ok = <-validatorch:
			if !ok {
				lgEngine.Info("validator engine terminating", "reason", "validatorch closed")
				return
			}
		}
		rrset = vr.RRset
		resp := ValidatorResponse{
			Validated: false,
			Msg:       "ValidatorEngine: request to validate a RRset",
		}

		if rrset == nil {
			lgEngine.Warn("request to validate a nil RRset")
			continue
		}

		if len(rrset.RRs) == 0 {
			lgEngine.Warn("request to validate an empty RRset")
			continue
		}

		ownername := rrset.RRs[0].Header().Name
		rrtype = dns.TypeToString[rrset.RRs[0].Header().Rrtype]
		lgEngine.Debug("validating RRset", "owner", ownername, "rrtype", rrtype, "count", len(rrset.RRs))

		// Is the RRset in a part of the namespace that we know anything about?
		zd, _ := FindZone(ownername)
		if zd == nil {
			lgEngine.Warn("RRset not in or below a known zone", "owner", ownername, "rrtype", rrtype)
			continue
		}

		cdd := zd.FindDelegation(ownername, true)
		if cdd == nil {
			// If we get here the RRset is in the auth zone represented by zd.
			lgEngine.Debug("RRset is in auth zone, not a child zone", "owner", ownername, "rrtype", rrtype, "zone", zd.ZoneName)
			owner, err := zd.GetOwner(ownername) // XXX: dnssec_ok = true: doesn't really matter here.
			if err != nil {
				resp.Msg = fmt.Sprintf("ValidatorEngine: error fetching the %s %s RRset from the ZoneData: %v", ownername, rrtype, err)
				lgEngine.Error("error fetching RRset from ZoneData", "owner", ownername, "rrtype", rrtype, "error", err)
				vr.Response <- resp
				continue
			}

			if owner == nil {
				// XXX: If we get here, then the owner name is not in the zone, but in a child zone (if it exists at all).
				resp.Msg = fmt.Sprintf("ValidatorEngine: the %s %s RRset is not in the auth zone %s. Validated=false", ownername, rrtype, zd.ZoneName)
				lgEngine.Debug("RRset not in auth zone", "owner", ownername, "rrtype", rrtype, "zone", zd.ZoneName)
				vr.Response <- resp
				continue
			}

			// XXX: If we get here, then the owner name is either authoritative in the zone, or the exact name of a delegation.
			// If it is a delegation, then there is an NS RRset.
			resp.Msg = fmt.Sprintf("ValidatorEngine: the %s %s RRset is in the auth zone %s. Validated=true", ownername, rrtype, zd.ZoneName)
			lgEngine.Info("RRset validated in auth zone", "owner", ownername, "rrtype", rrtype, "zone", zd.ZoneName)
			resp.Validated = true
			vr.Response <- resp
			continue
		} else {
			// XXX: If we get here, then the RRset is in a child zone with an existing delegation
			lgEngine.Debug("RRset is in child zone with existing delegation", "owner", ownername, "rrtype", rrtype)
			// To validate an RRset in a child zone, we need to:

			// 1. Check that the delegation is signed. If not ==> fail
			if cdd.DS_rrset == nil {
				resp.Msg = fmt.Sprintf("ValidatorEngine: RRset %s %s is below an unsigned delegation", ownername, rrtype)
				lgEngine.Warn("RRset below unsigned delegation", "owner", ownername, "rrtype", rrtype)
				vr.Response <- resp
				continue
			}
			// 2. Find the child DNSKEY RRset and verify the KSK against the DS that we have. If not ==> fail
			valid, err := zd.ValidateChildDnskeys(cdd, true)
			if err != nil {
				resp.Msg = fmt.Sprintf("ValidatorEngine: Error from ValidateChildDnskeys: %v", err)
				lgEngine.Error("ValidateChildDnskeys failed", "owner", ownername, "error", err)
				vr.Response <- resp
				continue
			}

			if !valid {
				resp.Msg = fmt.Sprintf("ValidatorEngine: Child %s DNSKEY RRset is not valid", ownername)
				lgEngine.Warn("child DNSKEY RRset not valid", "owner", ownername)
				vr.Response <- resp
				continue
			}

			// 4. Verify the RRset against the verified child DNSKEY that was used to sign the RRset. If not ==> fail
			valid, err = zd.ValidateRRset(rrset, true)
			if err != nil {
				resp.Msg = fmt.Sprintf("ValidatorEngine: Error from ValidateRRset(%v): %v", rrset, err)
				lgEngine.Error("ValidateRRset failed", "owner", ownername, "rrtype", rrtype, "error", err)
				// resp.Validated = false
				vr.Response <- resp
				continue
			}
			if !valid {
				resp.Msg = fmt.Sprintf("ValidatorEngine: %s %s RRset did not validate", ownername, rrtype)
				lgEngine.Warn("RRset did not validate", "owner", ownername, "rrtype", rrtype)
				// resp.Validated = false
				vr.Response <- resp
				continue
			}
			// 5. If all above checks pass, then the RRset is validated.
			resp.Msg = fmt.Sprintf("ValidatorEngine: %s %s RRset is validated", ownername, rrtype)
			lgEngine.Info("RRset validated", "owner", ownername, "rrtype", rrtype)
			resp.Validated = true
			vr.Response <- resp
			continue
		}
	}
}
