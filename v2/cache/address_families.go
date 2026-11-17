/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"sync/atomic"

	"github.com/miekg/dns"
)

// familyPolicy is which address families the resolver sends its queries over
// (imrengine.outbound-address-families). Every AuthServer the cache creates
// shares its cache's policy, and AddAddr and SetAddrs drop an address of a
// family the policy leaves out. The family is then simply absent: the address
// is never queried, and a nameserver left with no address of its own family is
// looked up as one that came without glue.
type familyPolicy struct {
	noV4 atomic.Bool
	noV6 atomic.Bool
}

// allows reports whether addr may be used. An address whose family cannot be
// told is left alone.
func (p *familyPolicy) allows(addr string) bool {
	if p == nil {
		return true
	}
	switch familyOf(addr) {
	case FamilyV4:
		return !p.noV4.Load()
	case FamilyV6:
		return !p.noV6.Load()
	}
	return true
}

// filter returns the addresses in addrs that p allows.
func (p *familyPolicy) filter(addrs []string) []string {
	if p == nil {
		return addrs
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if p.allows(a) {
			out = append(out, a)
		}
	}
	return out
}

// SetAddressFamilies sets which address families the resolver uses. At least
// one of v4 and v6 must be true (the caller checks). It applies to addresses
// added from now on: the resolver sets it before it primes.
func (rrcache *RRsetCacheT) SetAddressFamilies(v4, v6 bool) {
	if rrcache.families == nil {
		return
	}
	rrcache.families.noV4.Store(!v4)
	rrcache.families.noV6.Store(!v6)
}

// AddressTypes returns the address record types of the families in use, A
// before AAAA: the types to ask for when a nameserver's addresses are looked up.
func (rrcache *RRsetCacheT) AddressTypes() []uint16 {
	var types []uint16
	if rrcache.families == nil || !rrcache.families.noV4.Load() {
		types = append(types, dns.TypeA)
	}
	if rrcache.families == nil || !rrcache.families.noV6.Load() {
		types = append(types, dns.TypeAAAA)
	}
	return types
}
