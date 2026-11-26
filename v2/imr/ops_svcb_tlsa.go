package imr

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// ParseTLSAString parses a TLSA RDATA string of the form "usage selector matching data".
func ParseTLSAString(s string) (*dns.TLSA, error) {
	fields := strings.Fields(s)
	if len(fields) < 4 {
		return nil, fmt.Errorf("tlsa: expected at least 4 fields, got %d", len(fields))
	}
	parseUint8 := func(tok, label string) (uint8, error) {
		v, err := strconv.ParseUint(tok, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("tlsa: invalid %s %q: %v", label, tok, err)
		}
		return uint8(v), nil
	}
	usage, err := parseUint8(fields[0], "usage")
	if err != nil {
		return nil, err
	}
	selector, err := parseUint8(fields[1], "selector")
	if err != nil {
		return nil, err
	}
	matching, err := parseUint8(fields[2], "matching type")
	if err != nil {
		return nil, err
	}
	dataHex := strings.Join(fields[3:], "")
	dataHex = strings.ReplaceAll(dataHex, " ", "")
	if len(dataHex) == 0 {
		return nil, fmt.Errorf("tlsa: empty certificate data")
	}
	if _, err := hex.DecodeString(dataHex); err != nil {
		return nil, fmt.Errorf("tlsa: invalid hex data: %v", err)
	}
	return &dns.TLSA{
		Hdr:          dns.RR_Header{Name: ".", Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
		Usage:        usage,
		Selector:     selector,
		MatchingType: matching,
		Certificate:  strings.ToUpper(dataHex),
	}, nil
}
