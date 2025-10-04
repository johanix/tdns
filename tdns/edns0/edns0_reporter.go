/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

const (
	EDNS0_REPORTER_OPTION_CODE = 65002
)

// AddReporterOption adds an EDNS0 Reporter option to an existing OPT RR
// payload should be an EDE
func AddReporterOption(opt *dns.OPT, payload uint8) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}
	
	if payload != OTS_OPT_IN && payload != OTS_OPT_OUT {
		return fmt.Errorf("invalid Reporter payload value: %d (must be %d or %d)", 
			payload, OTS_OPT_IN, OTS_OPT_OUT)
	}
	
	// Create the option data (1 octet payload)
	optionData := []byte{payload}
	
	// Create the EDNS0 option
	option := &dns.EDNS0_LOCAL{
		Code: EDNS0_REPORTER_OPTION_CODE,
		Data: optionData,
	}
	
	// Add the option to the OPT RR
	opt.Option = append(opt.Option, option)
	
	return nil
}

// ExtractReporterOption extracts the Reporter EDNS0 option from an OPT RR
// Returns the payload value and true if found, or 0 and false if not found
func ExtractReporterOption(opt *dns.OPT) (uint8, bool) {
	if opt == nil {
		return 0, false
	}
	
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_REPORTER_OPTION_CODE {
				if len(localOpt.Data) == 1 {
					return localOpt.Data[0], true
				}
			}
		}
	}
	
	return 0, false
}

// HasReporterOption checks if an OPT RR contains an Reporter option
func HasReporterOption(opt *dns.OPT) bool {
	_, found := ExtractReporterOption(opt)
	return found
}

// IsReporterEnabled checks if Reporter is enabled (OPT_IN) in the given OPT RR
func IsReporterEnabled(opt *dns.OPT) bool {
	payload, found := ExtractReporterOption(opt)
	if !found {
		return false
	}
	return payload == OTS_OPT_IN
}

// RemoveReporterOption removes the Reporter EDNS0 option from an OPT RR
func RemoveReporterOption(opt *dns.OPT) {
	if opt == nil {
		return
	}
	
	var newOptions []dns.EDNS0
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_REPORTER_OPTION_CODE {
				continue // Skip this option
			}
		}
		newOptions = append(newOptions, option)
	}
	
	opt.Option = newOptions
}

// AddReporterToMessage adds an EDNS0 OPT RR to a message and includes the Reporter option
func AddReporterToMessage(msg *dns.Msg, reporterPayload uint8) error {
    
	if msg == nil {
		return fmt.Errorf("message is nil")
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	// Avoid duplicates if called multiple times
	RemoveReporterOption(opt)
	return AddReporterOption(opt, reporterPayload)
}
 
