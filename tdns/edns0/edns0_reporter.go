/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

type ReportOption struct {
	EDECode  uint16
	Severity uint8
	ZoneName string
	Sender   string
	Details  string
}

func ReportOptionToEDNS0Local(reportOption *ReportOption) (*dns.EDNS0_LOCAL, error) {
	if reportOption == nil {
		return nil, fmt.Errorf("reportOption is nil")
	}

	zoneLen := len(reportOption.ZoneName)
	senderLen := len(reportOption.Sender)
	detailsLen := len(reportOption.Details)
	if zoneLen > 255 || senderLen > 255 || detailsLen > 255 {
		return nil, fmt.Errorf("field too long: zone=%d sender=%d details=%d (max 255)", zoneLen, senderLen, detailsLen)
	}

	data := make([]byte, 6+zoneLen+senderLen+detailsLen)
	data[0] = byte(reportOption.EDECode >> 8)
	data[1] = byte(reportOption.EDECode & 0xFF)
	data[2] = reportOption.Severity
	data[3] = byte(zoneLen)
	data[4] = byte(senderLen)
	data[5] = byte(detailsLen)

	off := 6
	copy(data[off:], []byte(reportOption.ZoneName))
	off += zoneLen
	copy(data[off:], []byte(reportOption.Sender))
	off += senderLen
	copy(data[off:], []byte(reportOption.Details))

	return &dns.EDNS0_LOCAL{
		Code: EDNS0_REPORT_OPTION_CODE,
		Data: data,
	}, nil
}

// AddReportOption adds an EDNS(0) Report option to an existing OPT RR
// payload should be an EDE
func AddReportOption(opt *dns.OPT, edns0local *dns.EDNS0_LOCAL) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}

	if edns0local.Code != EDNS0_REPORT_OPTION_CODE {
		return fmt.Errorf("invalid Report payload value: %d (must be %d)",
			edns0local.Code, EDNS0_REPORT_OPTION_CODE)
	}

	// Add the option to the OPT RR
	opt.Option = append(opt.Option, edns0local)

	return nil
}

// ExtractReportOption extracts the Report EDNS(0) option from an OPT RR
// Returns the payload value and true if found, or 0 and false if not found
func ExtractReportOption(opt *dns.OPT) (*ReportOption, bool) {
	if opt == nil {
		return nil, false
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_REPORT_OPTION_CODE {
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

				reportOption := &ReportOption{
					EDECode:  uint16(data[0])<<8 | uint16(data[1]),
					Severity: data[2],
					ZoneName: zone,
					Sender:   sender,
					Details:  details,
				}
				return reportOption, true
			}
		}
	}

	return nil, false
}

// HasReportOption checks if an OPT RR contains an Report option
func HasReportOption(opt *dns.OPT) bool {
	_, found := ExtractReportOption(opt)
	return found
}

// RemoveReportOption removes the Report EDNS(0) option from an OPT RR
func RemoveReportOption(opt *dns.OPT) {
	if opt == nil {
		return
	}

	var newOptions []dns.EDNS0
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_REPORT_OPTION_CODE {
				continue // Skip this option
			}
		}
		newOptions = append(newOptions, option)
	}

	opt.Option = newOptions
}

// AddReportToMessage adds an EDNS(0) OPT RR to a message and includes the Report option
func AddReportOptionToMessage(msg *dns.Msg, reportPayload *ReportOption) error {

	if msg == nil {
		return fmt.Errorf("message is nil")
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	edns0local, err := ReportOptionToEDNS0Local(reportPayload)
	if err != nil {
		return fmt.Errorf("failed to convert ReportOption to EDNS0_LOCAL: %w", err)
	}
	// Avoid duplicates if called multiple times
	RemoveReportOption(opt)
	return AddReportOption(opt, edns0local)
}
