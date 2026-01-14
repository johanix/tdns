/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

// MsgOptions is a struct that contains the EDNS0 options from a message PLUS the traditional DNS flags RD, CD,
type MsgOptions struct {
	RD            bool
	CD            bool
	DO            bool
	CO            bool // RFC 9824: Compact Ok bit (bit 14 in OPT header TTL)
	OtsOptIn      bool
	OtsOptOut     bool
	HasEROption   bool            // True if ER option is present
	ErAgentDomain string          // RFC9567: DNS Error Reporting agent domain
	KeyState      *KeyStateOption // KeyState option if present
}

type EDNS0Option struct {
	Code uint16
	Data []byte
}

func ExtractFlagsAndEDNS0Options(r *dns.Msg) (*MsgOptions, error) {
	msgoptions := &MsgOptions{}
	msgoptions.CD = r.MsgHdr.CheckingDisabled
	msgoptions.RD = r.MsgHdr.RecursionDesired

	opt := r.IsEdns0()
	if opt == nil {
		return msgoptions, nil
	}

	// Extract DO bit (DNSSEC OK) - bit 15
	msgoptions.DO = opt.Do()

	// Extract CO bit (Compact Ok) - bit 14 (RFC 9824)
	msgoptions.CO = (opt.Hdr.Ttl & (1 << 14)) != 0

	// Loop once through all EDNS0 options and extract them based on their code
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			switch localOpt.Code {
			case EDNS0_OTS_OPTION_CODE:
				// Extract OTS option (1 octet payload)
				if len(localOpt.Data) == 1 {
					payload := localOpt.Data[0]
					msgoptions.OtsOptIn = payload == OTS_OPT_IN
					msgoptions.OtsOptOut = payload == OTS_OPT_OUT
				} else {
					return nil, fmt.Errorf("LEDNS0_LOCAL: OTS option data length is not 1")
				}
			case EDNS0_ER_OPTION_CODE:
				// Extract ER option (domain name in DNS wire format)
				if len(localOpt.Data) > 0 {
					domain, _, err := dns.UnpackDomainName(localOpt.Data, 0)
					if err == nil && domain != "" {
						msgoptions.ErAgentDomain = domain
						msgoptions.HasEROption = true
					}
				}
			case EDNS0_KEYSTATE_OPTION_CODE:
				// Extract KeyState option
				keystate, err := ParseKeyStateOption(localOpt)
				if err == nil {
					msgoptions.KeyState = keystate
				}
			}
		}
	}

	return msgoptions, nil
}
