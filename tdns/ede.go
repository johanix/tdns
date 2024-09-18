/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
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
)

var EDECodeToMsg = map[uint16]string{
	EDESig0KeyNotKnown:            "SIG(0) key not known",
	EDESig0KeyKnownButNotTrusted:  "SIG(0) key known, but not yet trusted",
	EDEDelegationSyncNotSupported: "Delegation sync via DNS UPDATE is not supported",
	EDEZoneFrozen:                 "Zone is frozen, updates not currently possible",
	EDEZoneNotFound:               "Zone not found",
	EDEZoneUpdatesNotAllowed:      "Zone does not allow DNS UPDATE",
}

// AttachEDEToResponse attaches an Extended DNS Error (EDE) option to the DNS response
func AttachEDEToResponse(msg *dns.Msg, edeCode uint16) {
	opt := msg.IsEdns0()
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		msg.Extra = append(msg.Extra, opt)
	}

	ede := new(dns.EDNS0_EDE)
	ede.InfoCode = edeCode
	ede.ExtraText = EDECodeToMsg[edeCode]

	opt.Option = append(opt.Option, ede)
}

func AddEDEToOPT(opt *dns.OPT, edeCode uint16) {
	ede := new(dns.EDNS0_EDE)
	ede.InfoCode = edeCode
	ede.ExtraText = EDECodeToMsg[edeCode]

	opt.Option = append(opt.Option, ede)
}
