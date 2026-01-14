/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// ExtractEdns0EROption extracts the ER (Error Reporting) EDNS0 option from an OPT RR
// Returns the agent domain and true if found, or empty string and false if not found
// RFC9567: The ER option contains a domain name (the agent domain) in DNS wire format
func ExtractEdns0EROption(opt *dns.OPT) (string, bool) {
	if opt == nil {
		return "", false
	}

	for _, option := range opt.Option {
		// Check for EDNS0_LOCAL with ER option code (RFC9567 option code 18)
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_ER_OPTION_CODE {
				// Parse the domain name from the data
				// The data should contain a DNS wire-format domain name
				if len(localOpt.Data) > 0 {
					domain, _, err := dns.UnpackDomainName(localOpt.Data, 0)
					if err == nil && domain != "" {
						return domain, true
					}
				}
			}
		}
	}

	return "", false
}

// AddEROption adds an ER (Error Reporting) EDNS0 option to an existing OPT RR
// agentDomain is the domain name of the monitoring agent (RFC9567)
func AddEROption(opt *dns.OPT, agentDomain string) error {
	if opt == nil {
		return fmt.Errorf("LOPT RR is nil")
	}

	if agentDomain == "" {
		return fmt.Errorf("agent domain cannot be empty")
	}

	// Ensure domain is FQDN
	agentDomain = dns.Fqdn(agentDomain)

	// Validate domain name
	if _, ok := dns.IsDomainName(agentDomain); !ok {
		return fmt.Errorf("invalid agent domain name: %q", agentDomain)
	}

	if HasEROption(opt) {
		return fmt.Errorf("LER option already present")
	}

	// Pack the domain name into DNS wire format
	// Domain names in wire format can be up to 255 bytes (RFC1035)
	domainBytes := make([]byte, 255)
	off, err := dns.PackDomainName(agentDomain, domainBytes, 0, nil, false)
	if err != nil {
		return fmt.Errorf("failed to pack domain name: %w", err)
	}

	optionData := domainBytes[:off]

	// Create the EDNS0 option using EDNS0_LOCAL (RFC9567 option code 18)
	option := &dns.EDNS0_LOCAL{
		Code: EDNS0_ER_OPTION_CODE,
		Data: optionData,
	}

	// Add the option to the OPT RR
	opt.Option = append(opt.Option, option)

	return nil
}

// HasEROption checks if an OPT RR contains an ER option
func HasEROption(opt *dns.OPT) bool {
	_, found := ExtractEdns0EROption(opt)
	return found
}

// RemoveEROption removes the ER EDNS0 option from an OPT RR
func RemoveEROption(opt *dns.OPT) {
	if opt == nil {
		return
	}

	var newOptions []dns.EDNS0
	for _, option := range opt.Option {
		// Check for EDNS0_LOCAL with ER code (RFC9567 option code 18)
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_ER_OPTION_CODE {
				continue // Skip this option
			}
		}
		newOptions = append(newOptions, option)
	}

	opt.Option = newOptions
}

// AddERToMessage adds an EDNS(0) OPT RR to a message and includes the ER option
func AddERToMessage(msg *dns.Msg, agentDomain string) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	// Avoid duplicates if called multiple times
	RemoveEROption(opt)
	return AddEROption(opt, agentDomain)
}

// sendErrorResponse sends a FormatError response for invalid error channel queries
func sendErrorResponse(w dns.ResponseWriter, r *dns.Msg, format string, args ...interface{}) {
	log.Printf(format, args...)
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeFormatError)
	if err := w.WriteMsg(m); err != nil {
		log.Printf("ErrorChannelReporter: Error writing response: %v", err)
	}
}

// ErrorChannelReporter parses and prints an RFC9567 error channel query
// The QNAME format is: _er.<orig qtype as number>.<orig-qname>.<ede code>._er.<agent domain name>.
// This function extracts and displays the error information in a human-readable format
func ErrorChannelReporter(qname string, qtype uint16, w dns.ResponseWriter, r *dns.Msg) {
	// Remove trailing dot if present
	// qname = strings.TrimSuffix(qname, ".")

	log.Printf("ErrorChannelReporter: QNAME: %s", qname)
	// Parse the QNAME to extract error information
	// Format: _er.<orig qtype as number>.<orig-qname>.<ede code>._er.<agent domain name>
	// We need to find the second "_er" separator to split the QNAME

	// First, check that it starts with "_er."
	if !strings.HasPrefix(qname, "_er.") {
		sendErrorResponse(w, r, "ErrorChannelReporter: Invalid error channel QNAME format: %s (expected to start with '_er.')\n", qname)
		return
	}

	// Remove the leading "_er." prefix
	rest := strings.TrimPrefix(qname, "_er.")

	// Find the second "_er." separator
	erIndex := strings.LastIndex(rest, "._er.")
	if erIndex == -1 {
		sendErrorResponse(w, r, "ErrorChannelReporter: Invalid error channel QNAME format: %s (expected second '_er.' separator)\n", qname)
		return
	}

	// Split into the two parts
	firstPart := rest[:erIndex]     // <orig qtype>.<orig-qname>.<ede code>
	agentDomain := rest[erIndex+5:] // <agent domain name> (skip "._er.")

	if agentDomain == "" {
		sendErrorResponse(w, r, "ErrorChannelReporter: Empty agent domain in: %s\n", qname)
		return
	}
	agentDomain = dns.Fqdn(agentDomain)

	// Parse firstPart: <orig qtype>.<orig-qname>.<ede code>
	// We need to work backwards to find the EDE code (last component before _er)
	// and the original qname (everything between qtype and ede code)
	firstParts := strings.Split(firstPart, ".")
	if len(firstParts) < 3 {
		sendErrorResponse(w, r, "ErrorChannelReporter: Invalid error channel QNAME format: %s (expected: _er.<qtype>.<qname>.<ede>._er.<agent>)\n", qname)
		return
	}

	// Last component is the EDE code
	edeCodeStr := firstParts[len(firstParts)-1]
	edeCode, err := strconv.ParseUint(edeCodeStr, 10, 16)
	if err != nil {
		sendErrorResponse(w, r, "ErrorChannelReporter: Invalid EDE code in QNAME: %s\n", edeCodeStr)
		return
	}

	// First component is the original QTYPE
	origQtypeStr := firstParts[0]
	origQtype, err := strconv.ParseUint(origQtypeStr, 10, 16)
	if err != nil {
		sendErrorResponse(w, r, "ErrorChannelReporter: Invalid original QTYPE in QNAME: %s\n", origQtypeStr)
		return
	}

	// Everything in between is the original QNAME
	originalQname := strings.Join(firstParts[1:len(firstParts)-1], ".")
	if originalQname == "" {
		sendErrorResponse(w, r, "ErrorChannelReporter: Empty original QNAME in: %s\n", qname)
		return
	}
	originalQname = dns.Fqdn(originalQname)

	// Get EDE code description
	edeText, ok := EDEToString(uint16(edeCode))
	if !ok {
		edeText = fmt.Sprintf("Unknown EDE code: %d", edeCode)
	}

	// Get QTYPE name
	qtypeName := dns.TypeToString[uint16(origQtype)]
	if qtypeName == "" {
		qtypeName = fmt.Sprintf("TYPE%d", origQtype)
	}

	// Print the error report
	log.Printf("ErrorChannelReport: EDE Code: %d (%s), Original Query: %s %s, Agent Domain: %s, From: %s\n",
		edeCode, edeText, originalQname, qtypeName, agentDomain, w.RemoteAddr())

	// Send a successful response (the query itself is the report)
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	if err := w.WriteMsg(m); err != nil {
		log.Printf("ErrorChannelReporter: Error writing response: %v", err)
	}
}
