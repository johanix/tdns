/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

const (
	// Private EDE codes (above 512)
	EDESig0KeyNotKnown            uint16 = 513
	EDESig0KeyKnownButNotTrusted  uint16 = 514
	EDEDelegationSyncNotSupported uint16 = 515
	EDEZoneFrozen                 uint16 = 516
	EDEZoneNotFound               uint16 = 517
	EDEZoneUpdatesNotAllowed      uint16 = 518
	EDEMPZoneXfrFailure           uint16 = 519
	EDEMPParentSyncFailure        uint16 = 520
	EDEReporterOptionNotFound     uint16 = 521
    EDETsigRequired               uint16 = 522
	EDETsigValidationFailure      uint16 = 523
)

var EDECodeToString = map[uint16]string{
	EDESig0KeyNotKnown:            "SIG(0) key not known",
	EDESig0KeyKnownButNotTrusted:  "SIG(0) key known, but not yet trusted",
	EDEDelegationSyncNotSupported: "Delegation sync via DNS UPDATE is not supported",
	EDEZoneFrozen:                 "Zone is frozen, updates not currently possible",
	EDEZoneNotFound:               "Zone not found",
	EDEZoneUpdatesNotAllowed:      "Zone does not allow DNS UPDATE",
	EDEMPZoneXfrFailure:           "Zone XFR between providers failed",
	EDEMPParentSyncFailure:        "Parent sync by provider failed",
	EDEReporterOptionNotFound:     "Expected Reporter option not found",
	EDETsigRequired:               "TSIG required",
	EDETsigValidationFailure:      "TSIG validation failure",
}

// AttachEDEToResponse attaches an Extended DNS Error (EDE) option to the DNS response
func AttachEDEToResponse(msg *dns.Msg, edeCode uint16) {
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	ede := new(dns.EDNS0_EDE)
	ede.InfoCode = edeCode
	// ede.ExtraText = EDECodeToMsg[edeCode]
	if s, ok := EDECodeToString[edeCode]; ok {
		ede.ExtraText = s
	} else if s, ok := dns.ExtendedErrorCodeToString[edeCode]; ok {
		ede.ExtraText = s
	}

	opt.Option = append(opt.Option, ede)
}

func AddEDEToOPT(opt *dns.OPT, edeCode uint16) {
    ede := new(dns.EDNS0_EDE)
    ede.InfoCode = edeCode
    if s, ok := EDECodeToString[edeCode]; ok {
		ede.ExtraText = s
    } else if s, ok := dns.ExtendedErrorCodeToString[edeCode]; ok {
		ede.ExtraText = s
	}

	opt.Option = append(opt.Option, ede)
}

func EDEToString(edeCode uint16) (string, bool) {
    if s, ok := EDECodeToString[edeCode]; ok {
		return s, true
    } else if s, ok := dns.ExtendedErrorCodeToString[edeCode]; ok {
		return s, true
	}
	
	return "", false
}

func ExtractEDEFromMsg(msg *dns.Msg) (bool, uint16, string) {
	// log.Printf("ExtractEDEFromMsg: msg.Extra: %+v", msg.Extra)
	var edemsg string
	for _, extra := range msg.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			// log.Printf("ExtractEDEFromMsg: opt.Option: %+v", opt.Option)
			for _, option := range opt.Option {
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					privede, privexist := EDECodeToString[ede.InfoCode]
					stdede, stdexist := dns.ExtendedErrorCodeToString[ede.InfoCode]
					switch {
					case ede.ExtraText != "":
						edemsg = ede.ExtraText
					case privexist:
						edemsg = privede
					case stdexist:
						edemsg = stdede

					default:
						edemsg = fmt.Sprintf("Unknown EDE code: %d", ede.InfoCode)
					}
					// log.Printf("EDE Code: %d, EDE Message: %s EDE local code2msg: %s", ede.InfoCode, ede.ExtraText, edemsg)
					return true, ede.InfoCode, edemsg
				}
			}
		}
	}
	return false, 0, ""
}
