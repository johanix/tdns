/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

// AddOTSOption adds a zero-length OOTS EDNS0 option to an existing OPT RR.
// draft-johani-dnsop-transport-signaling-03: OPTION-LENGTH MUST be 0;
// presence of the option is the opt-in signal.
func AddOTSOption(opt *dns.OPT) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}

	option := &dns.EDNS0_LOCAL{
		Code: EDNS0_OTS_OPTION_CODE,
		Data: nil, // OPTION-LENGTH = 0
	}
	opt.Option = append(opt.Option, option)
	return nil
}

// ExtractOTSOption reports whether the OOTS EDNS0 option is present on opt.
// Presence alone is the opt-in signal; any payload is ignored.
func ExtractOTSOption(opt *dns.OPT) bool {
	if opt == nil {
		return false
	}
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_OTS_OPTION_CODE {
				return true
			}
		}
	}
	return false
}

// HasOTSOption checks if an OPT RR contains an OOTS option.
func HasOTSOption(opt *dns.OPT) bool {
	return ExtractOTSOption(opt)
}

// IsOTSEnabled is true when the OOTS option is present (opt-in by presence).
func IsOTSEnabled(opt *dns.OPT) bool {
	return ExtractOTSOption(opt)
}

// RemoveOTSOption removes the OOTS EDNS0 option from an OPT RR.
func RemoveOTSOption(opt *dns.OPT) {
	if opt == nil {
		return
	}

	var newOptions []dns.EDNS0
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_OTS_OPTION_CODE {
				continue
			}
		}
		newOptions = append(newOptions, option)
	}

	opt.Option = newOptions
}

// AddOTSToMessage adds an EDNS0 OPT RR to a message (if needed) and includes
// the zero-length OOTS option.
func AddOTSToMessage(msg *dns.Msg) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	RemoveOTSOption(opt)
	return AddOTSOption(opt)
}
