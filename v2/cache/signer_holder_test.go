/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

// A signer above a zone held Secure that holds the RRset did not sign it: the
// Secure zone signs what it holds. Consulting the named signer's zone state
// first let an RRSIG that merely named a zone held Insecure make the RRset
// Insecure, unverified.
func TestASignerAboveASecureHolderDidNotSignIt(t *testing.T) {
	const ds = " 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	cases := []struct {
		name string
		sign func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) *core.RRset
		want ValidationState
	}{
		{"a DS in the name of an insecure ancestor", func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) *core.RRset {
			rrcache.ZoneMap.Set("example.", &Zone{ZoneName: "example.", State: ValidationStateInsecure})
			return strayKey(t, "example.").sign(t, rrFrom(t, secKid+ds))
		}, ValidationStateBogus},
		{"a DS in the name of an unrelated insecure zone", func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) *core.RRset {
			rrcache.ZoneMap.Set("other.", &Zone{ZoneName: "other.", State: ValidationStateInsecure})
			return strayKey(t, "other.").sign(t, rrFrom(t, secKid+ds))
		}, ValidationStateBogus},
		{"data of a secure child signed in its parent's name", func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) *core.RRset {
			rrcache.ZoneMap.Set(secKid, &Zone{ZoneName: secKid, State: ValidationStateSecure})
			return k.sign(t, rrFrom(t, kidWWW+" 300 IN A 192.0.2.2"))
		}, ValidationStateBogus},
		{"the parent's own DS", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) *core.RRset {
			return k.sign(t, rrFrom(t, secKid+ds))
		}, ValidationStateSecure},
		{"the parent's NSEC at a secure child's cut", func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) *core.RRset {
			rrcache.ZoneMap.Set(secKid, &Zone{ZoneName: secKid, State: ValidationStateSecure})
			return k.sign(t, rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" NS DS RRSIG NSEC"))
		}, ValidationStateSecure},
		{"the secure child's own apex NSEC", func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) *core.RRset {
			rrcache.ZoneMap.Set(secKid, &Zone{ZoneName: secKid, State: ValidationStateSecure})
			return newZoneKey(t, rrcache, secKid, false).sign(t, rrFrom(t, secKid+" 300 IN NSEC "+kidWWW+" NS SOA RRSIG NSEC DNSKEY"))
		}, ValidationStateSecure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			set := c.sign(t, rrcache, k)
			got, err := rrcache.ValidateRRset(context.Background(), set, nil)
			if err != nil {
				t.Fatalf("ValidateRRset: %v", err)
			}
			if got != c.want {
				t.Errorf("state %s, want %s", ValidationStateToString[got], ValidationStateToString[c.want])
			}
		})
	}
}
