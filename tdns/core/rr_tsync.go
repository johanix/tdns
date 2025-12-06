/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 */

package core

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func init() {
	RegisterTsyncRR()
}

// TSYNC is a private/custom RRtype similar in style to DSYNC.
// RDATA fields:
// - Type: uint16 (the RRtype variant within TSYNC namespace; typically dns.TypeTSYNC)
// - Transports: string (e.g., "doq=30,dot=20")
// - V4addr: comma-separated list of IPv4 addresses
// - V6addr: comma-separated list of IPv6 addresses
type TSYNC struct {
	Type       uint16
	Alias      string
	Transports string
	V4addr     string
	V6addr     string
}

func NewTSYNC() dns.PrivateRdata { return new(TSYNC) }

func (rd TSYNC) String() string {
	// Render keyed form in stable order, always including keys
	return fmt.Sprintf("%s %q %q %q",
		rd.Alias,
		fmt.Sprintf("transport=%s", rd.Transports),
		fmt.Sprintf("v4=%s", rd.V4addr),
		fmt.Sprintf("v6=%s", rd.V6addr),
	)
}

func (rd *TSYNC) Parse(txt []string) error {
	// Accept either 4 tokens (<TYPE> <transports> <v4addr> <v6addr>) or 3 tokens (<transports> <v4addr> <v6addr>)
	// Also accept empty/missing v4/v6 as empty strings.
	if len(txt) < 1 {
		return errors.New("TSYNC: missing fields")
	}
	var t uint16
	idx := 0
	if len(txt) >= 4 {
		// First token may be the type mnemonic
		if tt := dns.StringToType[txt[0]]; tt != 0 {
			t = tt
			idx = 1
		} else {
			// first token is not a type mnemonic, treat all tokens as data
			t = TypeTSYNC
			idx = 0
		}
	} else if len(txt) >= 1 {
		// No explicit type token provided; default to TypeTSYNC
		t = TypeTSYNC
		idx = 0
	}

	// Collect remaining fields; support keyed tokens in arbitrary order and legacy positional
	var alias, transports, v4addr, v6addr string
	// Helper to assign legacy positionally
	assignPositional := func(val string) {
		if alias == "" {
			alias = dns.Fqdn(val)
			return
		}
		if transports == "" {
			transports = val
			return
		}
		if v4addr == "" {
			v4addr = val
			return
		}
		if v6addr == "" {
			v6addr = val
			return
		}
	}

	for ; idx < len(txt); idx++ {
		raw := strings.TrimSpace(txt[idx])
		raw = stripQuotes(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "=") {
			kv := strings.SplitN(raw, "=", 2)
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			val := strings.TrimSpace(kv[1])
			val = stripQuotes(val)
			switch key {
			case "alias":
				alias = dns.Fqdn(val)
			case "transport", "transports":
				transports = val
			case "v4", "ipv4", "ipv4addrs", "ipv4addr", "ipv4s":
				v4addr = val
			case "v6", "ipv6", "ipv6addrs", "ipv6addr", "ipv6s":
				v6addr = val
			default:
				// Unknown key; treat as positional fallback to avoid hard failure
				assignPositional(raw)
			}
		} else {
			// No key, legacy positional token
			assignPositional(raw)
		}
	}

	rd.Type = t
	if alias == "" {
		return fmt.Errorf("TSYNC: alias is required (use '.' for none)")
	}
	// Ensure alias is a valid FQDN
	alias = dns.Fqdn(alias)
	if _, ok := dns.IsDomainName(alias); !ok {
		return fmt.Errorf("TSYNC: invalid alias domain name: %q", alias)
	}
	rd.Alias = alias
	rd.Transports = transports
	rd.V4addr = v4addr
	rd.V6addr = v6addr
	return nil
}

func (rd *TSYNC) Pack(buf []byte) (int, error) {
	var off int
	var err error

	off, err = packUint16(rd.Type, buf, off)
	if err != nil {
		return off, err
	}
	off, err = dns.PackDomainName(rd.Alias, buf, off, nil, false)
	if err != nil {
		return off, err
	}
	off, err = packString(rd.Transports, buf, off)
	if err != nil {
		return off, err
	}
	off, err = packString(rd.V4addr, buf, off)
	if err != nil {
		return off, err
	}
	off, err = packString(rd.V6addr, buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rd *TSYNC) Unpack(buf []byte) (int, error) {
	var off int
	var err error

	rd.Type, off, err = unpackUint16(buf, off)
	if err != nil {
		return off, err
	}
	// Alias is mandatory - if buffer ends here, it's an error
	if off == len(buf) {
		return off, errors.New("TSYNC: missing mandatory Alias field")
	}
	rd.Alias, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, err
	}
	// Validate that Alias is not empty
	if rd.Alias == "" {
		return off, errors.New("TSYNC: Alias field cannot be empty")
	}
	// Remaining fields are optional - if buffer ends, set to empty strings
	if off == len(buf) {
		rd.Transports = ""
		rd.V4addr = ""
		rd.V6addr = ""
		return off, nil
	}
	rd.Transports, off, err = unpackString(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		rd.V4addr = ""
		rd.V6addr = ""
		return off, nil
	}
	rd.V4addr, off, err = unpackString(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		rd.V6addr = ""
		return off, nil
	}
	rd.V6addr, off, err = unpackString(buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rd *TSYNC) Copy(dest dns.PrivateRdata) error {
	// Copy via field assignment (safe, strings are immutable header pairs)
	d, ok := dest.(*TSYNC)
	if !ok {
		return fmt.Errorf("TSYNC: Copy: dest is not a *TSYNC")
	}
	d.Type = rd.Type
	d.Alias = rd.Alias
	d.Transports = rd.Transports
	d.V4addr = rd.V4addr
	d.V6addr = rd.V6addr
	return nil
}

func (rd *TSYNC) Len() int {
	// 2 bytes for Type +
	// for each string: 2 bytes length + len(data)
	// Alias uses domain name wire format: sum(1+len(label)) + root(1)
	aliasLen := domainNameWireLen(rd.Alias)
	return 2 + aliasLen + 2 + len(rd.Transports) + 2 + len(rd.V4addr) + 2 + len(rd.V6addr)
}

func RegisterTsyncRR() error {
	dns.PrivateHandle("TSYNC", TypeTSYNC, NewTSYNC)
	return nil
}

// Helpers for packing/unpacking length-prefixed strings (uint16 length)
func packString(s string, msg []byte, off int) (int, error) {
	var err error
	off, err = packUint16(uint16(len(s)), msg, off)
	if err != nil {
		return off, err
	}
	if off+len(s) > len(msg) {
		return off, errors.New("overflow packing string")
	}
	copy(msg[off:], []byte(s))
	return off + len(s), nil
}

func unpackString(msg []byte, off int) (string, int, error) {
	l, off1, err := unpackUint16(msg, off)
	if err != nil {
		return "", off1, err
	}
	if int(off1)+int(l) > len(msg) {
		return "", len(msg), errors.New("overflow unpacking string")
	}
	s := string(msg[off1 : off1+int(l)])
	return s, off1 + int(l), nil
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// domainNameWireLen returns the length in bytes of a domain name in DNS wire format.
// It is sum(1+len(label)) for each label plus the root label (1). "." => 1.
func domainNameWireLen(name string) int {
	n := dns.Fqdn(strings.TrimSpace(name))
	if n == "." {
		return 1
	}
	labels := dns.SplitDomainName(n)
	// Start with 1 for the root label
	total := 1
	for _, lbl := range labels {
		total += 1 + len(lbl)
	}
	return total
}
