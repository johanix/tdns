/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"testing"

	"github.com/miekg/dns"
)

// A DS is usable when its algorithm can be verified and its digest type
// computed. Without an installed answer, every algorithm counts as supported.
func TestDSUsable(t *testing.T) {
	ds := func(alg, digest uint8) *dns.DS {
		return &dns.DS{Hdr: dns.RR_Header{Name: secKid, Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag: 1, Algorithm: alg, DigestType: digest, Digest: "00"}
	}
	SetAlgorithmSupported(nil)
	if !dsUsable(ds(208, dns.SHA256)) {
		t.Error("with no answer installed, algorithm 208 is not usable")
	}

	SetAlgorithmSupported(func(alg uint8) bool { return alg != 208 })
	t.Cleanup(func() { SetAlgorithmSupported(nil) })
	for _, c := range []struct {
		alg, digest uint8
		usable      bool
	}{
		{dns.ED25519, dns.SHA1, true},
		{dns.ED25519, dns.SHA256, true},
		{dns.ED25519, dns.SHA384, true},
		{dns.ED25519, dns.GOST94, false},
		{dns.ED25519, 99, false},
		{208, dns.SHA256, false},
	} {
		if got := dsUsable(ds(c.alg, c.digest)); got != c.usable {
			t.Errorf("DS algorithm %d digest type %d: usable %v, want %v", c.alg, c.digest, got, c.usable)
		}
		// The exported name, which the chain walk calls, is the same rule.
		if got := DSUsable(ds(c.alg, c.digest)); got != c.usable {
			t.Errorf("DSUsable: DS algorithm %d digest type %d: usable %v, want %v", c.alg, c.digest, got, c.usable)
		}
	}
	if noUsableDS([]dns.RR{ds(208, dns.SHA256), ds(dns.ED25519, dns.SHA256)}) {
		t.Error("one usable DS beside an unusable one: reported as none usable")
	}
	if !noUsableDS([]dns.RR{ds(208, dns.SHA256), ds(dns.ED25519, 99)}) {
		t.Error("no usable DS: reported as some usable")
	}
	if noUsableDS(nil) {
		t.Error("no DS at all: reported as no usable DS")
	}
}
