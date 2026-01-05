package tdns

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

// MarshalTLSAToString renders a TLSA record to the "usage selector matching data" representation.
func MarshalTLSAToString(tlsa *dns.TLSA) (string, error) {
	if tlsa == nil {
		return "", fmt.Errorf("tlsa: nil record")
	}
	cert := strings.ReplaceAll(tlsa.Certificate, " ", "")
	if len(cert) == 0 {
		return "", fmt.Errorf("tlsa: empty certificate data")
	}
	if _, err := hex.DecodeString(cert); err != nil {
		return "", fmt.Errorf("tlsa: invalid certificate hex: %v", err)
	}
	return fmt.Sprintf("%d %d %d %s",
		tlsa.Usage,
		tlsa.Selector,
		tlsa.MatchingType,
		strings.ToUpper(cert),
	), nil
}

// ParseTLSAFromSvcbLocal parses a private SVCB TLSA key into a dns.TLSA.
func ParseTLSAFromSvcbLocal(local *dns.SVCBLocal) (*dns.TLSA, error) {
	if local == nil {
		return nil, fmt.Errorf("tlsa: nil svcb local param")
	}
	if uint16(local.Key()) != SvcbTLSAKey {
		return nil, fmt.Errorf("tlsa: unexpected SVCB key %d", local.Key())
	}
	return ParseTLSAString(string(local.Data))
}

// TLSAToSvcbLocal marshals a TLSA record into a private SVCB key/value pair.
func TLSAToSvcbLocal(tlsa *dns.TLSA) (*dns.SVCBLocal, error) {
	val, err := MarshalTLSAToString(tlsa)
	if err != nil {
		return nil, err
	}
	return &dns.SVCBLocal{
		KeyCode: dns.SVCBKey(SvcbTLSAKey),
		Data:    []byte(val),
	}, nil
}
