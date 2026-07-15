/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package options

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

const DefaultEDNSUDPSize = 4096

// ParseBufsizeFlag recognizes dig-style +bufsize=N and the +bufsiz=N
// abbreviation. ucarg must already be uppercased.
func ParseBufsizeFlag(ucarg string) (value string, ok bool) {
	for _, prefix := range []string{"+BUFSIZE=", "+BUFSIZ="} {
		if strings.HasPrefix(ucarg, prefix) {
			val := strings.TrimPrefix(ucarg, prefix)
			return val, true
		}
	}
	return "", false
}

// ParseEDNSUDPSize validates and normalizes an EDNS UDP payload size. Per RFC
// 6891, values below 512 are treated as 512.
func ParseEDNSUDPSize(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("+bufsize requires a valid integer (e.g. +bufsize=512)")
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("+bufsize=%d out of range (0-65535)", n)
	}
	if n < int(dns.MinMsgSize) {
		n = int(dns.MinMsgSize)
	}
	return uint16(n), nil
}

// EDNSUDPSizeFromMap returns the OPT UDP payload size for a dog options map.
func EDNSUDPSizeFromMap(opts map[string]string) (uint16, error) {
	raw, ok := opts["bufsize"]
	if !ok || raw == "" {
		return DefaultEDNSUDPSize, nil
	}
	return ParseEDNSUDPSize(raw)
}
