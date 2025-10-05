/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

type ReporterOption struct {
	EDECode uint16
	Severity uint8
	ZoneName string
	Sender string
	Details string
}

func ReporterOptionToEDNS0Local(reporterOption *ReporterOption) (*dns.EDNS0_LOCAL, error) {
	if reporterOption == nil {
		return nil, fmt.Errorf("reporterOption is nil")
	}

	zoneLen := len(reporterOption.ZoneName)
	senderLen := len(reporterOption.Sender)
	detailsLen := len(reporterOption.Details)
	if zoneLen > 255 || senderLen > 255 || detailsLen > 255 {
		return nil, fmt.Errorf("field too long: zone=%d sender=%d details=%d (max 255)", zoneLen, senderLen, detailsLen)
	}

	data := make([]byte, 6+zoneLen+senderLen+detailsLen)
	data[0] = byte(reporterOption.EDECode >> 8)
	data[1] = byte(reporterOption.EDECode & 0xFF)
	data[2] = reporterOption.Severity
	data[3] = byte(zoneLen)
	data[4] = byte(senderLen)
	data[5] = byte(detailsLen)

	off := 6
	copy(data[off:], []byte(reporterOption.ZoneName))
	off += zoneLen
	copy(data[off:], []byte(reporterOption.Sender))
	off += senderLen
	copy(data[off:], []byte(reporterOption.Details))

	return &dns.EDNS0_LOCAL{
			Code: EDNS0_REPORTER_OPTION_CODE,
			Data: data,
		}, nil
}

// AddReporterOption adds an EDNS0 Reporter option to an existing OPT RR
// payload should be an EDE
func AddReporterOption(opt *dns.OPT, edns0local *dns.EDNS0_LOCAL) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}
	
	if edns0local.Code != EDNS0_REPORTER_OPTION_CODE {
		return fmt.Errorf("invalid Reporter payload value: %d (must be %d)", 
			edns0local.Code, EDNS0_REPORTER_OPTION_CODE)
	}

	// Add the option to the OPT RR
	opt.Option = append(opt.Option, edns0local)
	
	return nil
}

// ExtractReporterOption extracts the Reporter EDNS0 option from an OPT RR
// Returns the payload value and true if found, or 0 and false if not found
func ExtractReporterOption(opt *dns.OPT) (*ReporterOption, bool) {
	if opt == nil {
		return nil, false
	}
	
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_REPORTER_OPTION_CODE {
				data := localOpt.Data
				if len(data) < 6 {
					return nil, false
				}
				zoneLen := int(data[3])
				senderLen := int(data[4])
				detailsLen := int(data[5])
				needed := 6 + zoneLen + senderLen + detailsLen
				if len(data) < needed {
					return nil, false
				}
				off := 6
				zone := string(data[off : off+zoneLen])
				off += zoneLen
				sender := string(data[off : off+senderLen])
				off += senderLen
				details := string(data[off : off+detailsLen])

				reporterOption := &ReporterOption{
					EDECode:  uint16(data[0])<<8 | uint16(data[1]),
					Severity: data[2],
					ZoneName: zone,
					Sender:   sender,
					Details:  details,
				}
				return reporterOption, true
			}
		}
	}
	
	return nil, false
}

// HasReporterOption checks if an OPT RR contains an Reporter option
func HasReporterOption(opt *dns.OPT) bool {
	_, found := ExtractReporterOption(opt)
	return found
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
func AddReporterOptionToMessage(msg *dns.Msg, reporterPayload *ReporterOption) error {
    
	if msg == nil {
		return fmt.Errorf("message is nil")
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	edns0local, err := ReporterOptionToEDNS0Local(reporterPayload)
	if err != nil {
		return fmt.Errorf("failed to convert ReporterOption to EDNS0_LOCAL: %w", err)
	}
	// Avoid duplicates if called multiple times
	RemoveReporterOption(opt)
	return AddReporterOption(opt, edns0local)
}
