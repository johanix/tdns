/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

// AddOOTSOption adds a zero-length OOTS EDNS0 option to an existing OPT RR.
// draft-johani-dnsop-transport-signaling-03: OPTION-LENGTH MUST be 0;
// presence of the option is the opt-in signal.
func AddOOTSOption(opt *dns.OPT) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}

	option := &dns.EDNS0_LOCAL{
		Code: EDNS0_OOTS_OPTION_CODE,
		Data: nil, // OPTION-LENGTH = 0
	}
	opt.Option = append(opt.Option, option)
	return nil
}

// ExtractOOTSOption reports whether the OOTS EDNS0 option is present on opt.
// Presence alone is the opt-in signal; any payload is ignored.
func ExtractOOTSOption(opt *dns.OPT) bool {
	if opt == nil {
		return false
	}
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_OOTS_OPTION_CODE {
				return true
			}
		}
	}
	return false
}

// HasOOTSOption checks if an OPT RR contains an OOTS option.
func HasOOTSOption(opt *dns.OPT) bool {
	return ExtractOOTSOption(opt)
}

// IsOOTSEnabled is true when the OOTS option is present (opt-in by presence).
func IsOOTSEnabled(opt *dns.OPT) bool {
	return ExtractOOTSOption(opt)
}

// RemoveOOTSOption removes the OOTS EDNS0 option from an OPT RR.
func RemoveOOTSOption(opt *dns.OPT) {
	if opt == nil {
		return
	}

	var newOptions []dns.EDNS0
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_OOTS_OPTION_CODE {
				continue
			}
		}
		newOptions = append(newOptions, option)
	}

	opt.Option = newOptions
}

// AddOOTSToMessage adds an EDNS0 OPT RR to a message (if needed) and includes
// the zero-length OOTS option.
func AddOOTSToMessage(msg *dns.Msg) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	RemoveOOTSOption(opt)
	return AddOOTSOption(opt)
}
