/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

// EDNS0 OTS option constants
const (
	// OTS payload values
	OTS_OPT_IN  = 1
	OTS_OPT_OUT = 2
)

// AddOTSOption adds an OTS EDNS0 option to an existing OPT RR
// payload should be either OTS_OPT_IN or OTS_OPT_OUT
func AddOTSOption(opt *dns.OPT, payload uint8) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}

	if payload != OTS_OPT_IN && payload != OTS_OPT_OUT {
		return fmt.Errorf("invalid OTS payload value: %d (must be %d or %d)",
			payload, OTS_OPT_IN, OTS_OPT_OUT)
	}

	// Create the option data (1 octet payload)
	optionData := []byte{payload}

	// Create the EDNS0 option
	option := &dns.EDNS0_LOCAL{
		Code: EDNS0_OTS_OPTION_CODE,
		Data: optionData,
	}

	// Add the option to the OPT RR
	opt.Option = append(opt.Option, option)

	return nil
}

// ExtractOTSOption extracts the OTS EDNS0 option from an OPT RR
// Returns the payload value and true if found, or 0 and false if not found
func ExtractOTSOption(opt *dns.OPT) (uint8, bool) {
	if opt == nil {
		return 0, false
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_OTS_OPTION_CODE {
				if len(localOpt.Data) == 1 {
					return localOpt.Data[0], true
				}
			}
		}
	}

	return 0, false
}

// HasOTSOption checks if an OPT RR contains an OTS option
func HasOTSOption(opt *dns.OPT) bool {
	_, found := ExtractOTSOption(opt)
	return found
}

// IsOTSEnabled checks if OTS is enabled (OPT_IN) in the given OPT RR
func IsOTSEnabled(opt *dns.OPT) bool {
	payload, found := ExtractOTSOption(opt)
	if !found {
		return false
	}
	return payload == OTS_OPT_IN
}

// RemoveOTSOption removes the OTS EDNS0 option from an OPT RR
func RemoveOTSOption(opt *dns.OPT) {
	if opt == nil {
		return
	}

	var newOptions []dns.EDNS0
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_OTS_OPTION_CODE {
				continue // Skip this option
			}
		}
		newOptions = append(newOptions, option)
	}

	opt.Option = newOptions
}

// AddEDNS0WithOTS adds an EDNS0 OPT RR to a message and includes the OTS option
func AddOTSToMessage(msg *dns.Msg, otsPayload uint8) error {

	if msg == nil {
		return fmt.Errorf("message is nil")
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	// Avoid duplicates if called multiple times
	RemoveOTSOption(opt)
	return AddOTSOption(opt, otsPayload)
}
