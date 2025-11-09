/*
 * Copyright (c) 2024 Johan Stenstam
 */
package tdns

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Private-use SVCB key code for pct (percentage) distribution
// RFC 9460 reserves 65280–65534 for private use.
const SVCBKeyPct uint16 = 65280

// ParsePctString parses a pct string like "doq=30,dot=20" into a map.
// - Keys are lower-cased and trimmed
// - Values must be integers in [0,100]
// - Duplicate keys are rejected
func ParsePctString(s string) (map[string]uint8, error) {
    pct := make(map[string]uint8)
    s = strings.TrimSpace(s)
    if s == "" {
        return pct, nil
    }
    parts := strings.Split(s, ",")
    for _, p := range parts {
        kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
        if len(kv) != 2 {
            return nil, fmt.Errorf("pct: bad token %q (want key=value)", p)
        }
        k := strings.ToLower(strings.TrimSpace(kv[0]))
        vstr := strings.TrimSpace(kv[1])
        if k == "" || vstr == "" {
            return nil, fmt.Errorf("pct: empty key or value in %q", p)
        }
        if _, exists := pct[k]; exists {
            return nil, fmt.Errorf("pct: duplicate key %q", k)
        }
        v64, err := strconv.ParseUint(vstr, 10, 8)
        if err != nil {
            return nil, fmt.Errorf("pct: bad value for %q: %v", k, err)
        }
        v := uint8(v64)
        if v > 100 {
            return nil, fmt.Errorf("pct: value for %q out of range: %d", k, v)
        }
        pct[k] = v
    }
    return pct, nil
}

// MarshalPct converts a pct map back to a canonical string (sorted by key).
func MarshalPct(pct map[string]uint8) string {
    if len(pct) == 0 {
        return ""
    }
    keys := make([]string, 0, len(pct))
    for k := range pct {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    var b strings.Builder
    for i, k := range keys {
        if i > 0 {
            b.WriteByte(',')
        }
        b.WriteString(k)
        b.WriteByte('=')
        b.WriteString(strconv.Itoa(int(pct[k])))
    }
    return b.String()
}

// GetAlpn extracts the ALPN protocols from an SVCB RR (from SVCBAlpn param).
func GetAlpn(svcb *dns.SVCB) []string {
    var alpn []string
    if svcb == nil {
        return alpn
    }
    for _, kv := range svcb.Value {
        if a, ok := kv.(*dns.SVCBAlpn); ok {
            for _, v := range a.Alpn {
                alpn = append(alpn, strings.ToLower(v))
            }
        }
    }
    return alpn
}

// ValidatePctAgainstAlpn ensures all keys in pct exist in the ALPN list and sum ≤ 100.
// A sum < 100 is allowed (implies remainder to do53 by policy at use-time).
func ValidatePctAgainstAlpn(pct map[string]uint8, alpn []string) error {
    // Build set of allowed keys from ALPN
    allowed := make(map[string]bool, len(alpn))
    for _, a := range alpn {
        allowed[strings.ToLower(a)] = true
    }
    var sum int
    for k, v := range pct {
        if !allowed[k] {
            return fmt.Errorf("pct: key %q not present in alpn", k)
        }
        sum += int(v)
        if sum > 100 {
            return fmt.Errorf("pct: total exceeds 100 (>%d)", 100)
        }
    }
    return nil
}

// ComputeDo53Remainder returns the implicit remainder for do53 (clip at 0).
func ComputeDo53Remainder(pct map[string]uint8) uint8 {
    var sum int
    for _, v := range pct {
        sum += int(v)
    }
    if sum >= 100 {
        return 0
    }
    return uint8(100 - sum)
}

// SetPctParam sets or replaces the private-use pct parameter on the SVCB RR.
// It validates against the RR's ALPN list.
func SetPctParam(svcb *dns.SVCB, pct map[string]uint8) error {
    if svcb == nil {
        return fmt.Errorf("SetPctParam: nil svcb")
    }
    if err := ValidatePctAgainstAlpn(pct, GetAlpn(svcb)); err != nil {
        return err
    }
    // Marshal
    value := MarshalPct(pct)
    // Replace existing or append new
    replaced := false
    for i, kv := range svcb.Value {
        if local, ok := kv.(*dns.SVCBLocal); ok {
            if uint16(local.Key()) == SVCBKeyPct {
                local.Data = []byte(value)
                svcb.Value[i] = local
                replaced = true
                break
            }
        }
    }
    if !replaced {
        svcb.Value = append(svcb.Value, &dns.SVCBLocal{KeyCode: dns.SVCBKey(SVCBKeyPct), Data: []byte(value)})
    }
    return nil
}

// GetPctParam fetches and parses the pct parameter from the SVCB RR, if present.
func GetPctParam(svcb *dns.SVCB) (map[string]uint8, bool, error) {
    if svcb == nil {
        return nil, false, fmt.Errorf("GetPctParam: nil svcb")
    }
    for _, kv := range svcb.Value {
        if local, ok := kv.(*dns.SVCBLocal); ok {
            if uint16(local.Key()) == SVCBKeyPct {
                m, err := ParsePctString(string(local.Data))
                if err != nil {
                    return nil, true, err
                }
                return m, true, nil
            }
        }
    }
    return nil, false, nil
}

// BuildServerSVCB is a convenience builder that applies ALPN and PCT with validation.
func BuildServerSVCB(name string, alpn []string, pct map[string]uint8) (*dns.SVCB, error) {
    svcb := &dns.SVCB{
        Hdr: dns.RR_Header{
            Name:   dns.Fqdn(name),
            Rrtype: dns.TypeSVCB,
            Class:  dns.ClassINET,
            Ttl:    120,
        },
        Priority: 1,
        Target:   dns.Fqdn(name),
    }
    if len(alpn) > 0 {
        svcb.Value = append(svcb.Value, &dns.SVCBAlpn{Alpn: alpn})
    }
    if pct != nil {
        if err := SetPctParam(svcb, pct); err != nil {
            return nil, err
        }
    }
    return svcb, nil
}

// ValidateExplicitServerSVCB validates an explicit SVCB RR for server use.
// It checks pct against the ALPN list, if pct is present. If pct is absent,
// the record is accepted as-is. If pct is present but alpn is missing, it's invalid.
func ValidateExplicitServerSVCB(svcb *dns.SVCB) error {
    if svcb == nil {
        return fmt.Errorf("ValidateExplicitServerSVCB: nil svcb")
    }
    alpn := GetAlpn(svcb)
    pct, hasPct, err := GetPctParam(svcb)
    if err != nil {
        return fmt.Errorf("invalid pct value: %w", err)
    }
    if hasPct {
        if len(alpn) == 0 {
            return fmt.Errorf("pct present but alpn missing")
        }
        if err := ValidatePctAgainstAlpn(pct, alpn); err != nil {
            return err
        }
    }
    return nil
}


