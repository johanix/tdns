/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"github.com/miekg/dns"
)

// MsgOptions is a struct that contains the EDNS0 options from a message PLUS the traditional DNS flags RD, CD,
type MsgOptions struct {
	RD            bool
	CD            bool
	DO            bool
	CO            bool            // RFC 9824: Compact Ok bit (bit 14 in OPT header TTL)
	PR            bool            // Privacy Requested bit (bit 12 in OPT header TTL) - requires encrypted transport
	OotsOptIn     bool            // OOTS EDNS option present (opt-in by presence; -03)
	HasEROption   bool            // True if ER option is present
	ErAgentDomain string          // RFC9567: DNS Error Reporting agent domain
	KeyState      *KeyStateOption // KeyState option if present
	UDPSize       uint16          // Client-advertised EDNS UDP payload size (RFC 6891)
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
		msgoptions.UDPSize = dns.MinMsgSize
		return msgoptions, nil
	}

	msgoptions.UDPSize = RequestUDPSize(r)

	// Extract DO bit (DNSSEC OK) - bit 15
	msgoptions.DO = opt.Do()

	// Extract CO bit (Compact Ok) - bit 14 (RFC 9824)
	msgoptions.CO = (opt.Hdr.Ttl & (1 << 14)) != 0

	// Extract PR bit (Privacy Requested) - bit 12 (requires encrypted transport)
	msgoptions.PR = (opt.Hdr.Ttl & (1 << EDNS0_PR_FLAG_BIT)) != 0

	// Loop once through all EDNS0 options and extract them based on their code
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			switch localOpt.Code {
			case EDNS0_OOTS_OPTION_CODE:
				// -03: OPTION-LENGTH MUST be 0; presence alone is opt-in.
				msgoptions.OotsOptIn = true
			case EDNS0_ER_OPTION_CODE:
				// Extract ER option (domain name in DNS wire format)
				if len(localOpt.Data) > 0 {
					domain, _, err := dns.UnpackDomainName(localOpt.Data, 0)
					if err == nil && domain != "" && len(domain) <= 255 {
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

// RequestUDPSize returns the EDNS UDP payload size advertised in r. Per RFC
// 6891: no OPT ⇒ 512; OPT UDP size < 512 ⇒ treat as 512.
func RequestUDPSize(r *dns.Msg) uint16 {
	if r == nil {
		return dns.MinMsgSize
	}
	opt := r.IsEdns0()
	if opt == nil {
		return dns.MinMsgSize
	}
	size := opt.UDPSize()
	if size < dns.MinMsgSize {
		return dns.MinMsgSize
	}
	return size
}

// EnsureResponseOPT makes the response m carry an EDNS(0) OPT record whenever
// the query r carried one. RFC 6891 §6.1.1 requires a compliant responder to
// include an OPT in the response to any request that carried an OPT; omitting
// it can make a strict resolver downgrade to plain DNS (dropping the DO bit and
// breaking DNSSEC validation). The OPT advertises version 0 and udpsize (the
// server's own reassembly capacity) and copies the DO bit from the query, as
// mandated by RFC 3225 §3.
//
// It is deliberately a no-op in two cases:
//   - the query carried no OPT: a plain-DNS query gets a plain-DNS reply; and
//   - m already carries an OPT: the EDE / KeyState paths build their own OPT,
//     and a second SetEdns0 would append a duplicate OPT to the Additional
//     section.
//
// The OPT is attached with an empty option list, leaving room for EDE (or any
// other option) to be appended later on error paths (AttachEDEToResponse finds
// and reuses this OPT rather than creating a second one).
func EnsureResponseOPT(m, r *dns.Msg, udpsize uint16) {
	if m == nil || r == nil {
		return
	}
	reqOpt := r.IsEdns0()
	if reqOpt == nil {
		return
	}
	if m.IsEdns0() != nil {
		return
	}
	m.SetEdns0(udpsize, reqOpt.Do())
}
