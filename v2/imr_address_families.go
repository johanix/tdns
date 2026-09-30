/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"strings"
)

// ParseAddressFamilies reads imrengine.address-families: the address families
// the resolver uses to reach authoritative servers, ipv4, ipv6 or both. Both is
// the default, and what an empty list means.
//
// On a host where one family does not work -- an IPv6 address and default
// route that lead nowhere, say -- leaving it out stops the queries and address
// lookups that could only fail. With one family only, the resolver also shows
// what that family alone reaches.
func ParseAddressFamilies(list []string) (v4, v6 bool, err error) {
	if len(list) == 0 {
		return true, true, nil
	}
	for _, f := range list {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "ipv4":
			v4 = true
		case "ipv6":
			v6 = true
		default:
			return false, false, fmt.Errorf("unknown address family %q (want ipv4, ipv6, or both)", f)
		}
	}
	return v4, v6, nil
}

// sameAddressFamilies reports whether two address-families lists mean the same.
func sameAddressFamilies(a, b []string) bool {
	a4, a6, aerr := ParseAddressFamilies(a)
	b4, b6, berr := ParseAddressFamilies(b)
	return a4 == b4 && a6 == b6 && (aerr == nil) == (berr == nil)
}
