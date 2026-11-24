package tdns

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

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
