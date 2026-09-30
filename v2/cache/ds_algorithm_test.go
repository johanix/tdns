/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"testing"

	"github.com/miekg/dns"
)

// ValidateDNSKEYRRsetUsingDS matches a DS to a key by key tag and algorithm,
// then digest (RFC 4035 section 5.2). A DS naming another algorithm, with the
// key's tag and digest, matches nothing. The key must be a zone key; the SEP
// flag is not required.
func TestValidateDNSKEYRRsetUsingDSChecksTheAlgorithm(t *testing.T) {
	k := newZoneKey(t, negCache(t), secZone, false)
	if k.key.Flags&dns.SEP != 0 || k.key.Flags&dns.ZONE == 0 {
		t.Fatalf("test setup: flags %d, want a zone key without SEP", k.key.Flags)
	}
	keys := k.sign(t, dns.Copy(k.key))
	ds := k.key.ToDS(dns.SHA256)

	if ok, key := ValidateDNSKEYRRsetUsingDS(keys, ds, secZone, false); !ok || key == nil {
		t.Fatalf("the key's own DS: %v; want it to match", ok)
	}
	for _, alg := range []uint8{dns.RSASHA256, dns.ECDSAP256SHA256, 208} {
		other := dns.Copy(ds).(*dns.DS)
		other.Algorithm = alg
		if ok, _ := ValidateDNSKEYRRsetUsingDS(keys, other, secZone, false); ok {
			t.Errorf("a DS naming algorithm %d matched an algorithm %d key", alg, k.key.Algorithm)
		}
	}
}
