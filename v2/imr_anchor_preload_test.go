/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"path/filepath"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// The anchors must be in place before priming asks the root anything. A start
// whose priming cannot even begin -- no root hints to read -- is the cleanest
// place to see it: whatever InitImrEngine loaded before priming is in the DNSKEY
// cache, and nothing after it ran.
func TestInitImrEngineLoadsTrustAnchorsBeforePriming(t *testing.T) {
	const anchor = "anchor-preload.example."
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: anchor, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	if _, err := k.Generate(256); err != nil {
		t.Fatal(err)
	}

	savedImr := Globals.ImrEngine
	defer func() { Globals.ImrEngine = savedImr }()
	// InitImrEngine builds its cache over the process-wide DNSKEY cache; take the
	// test's anchor back out of it.
	t.Cleanup(func() {
		for key, v := range cache.DnskeyCache.Map.Items() {
			if v.Name == anchor {
				cache.DnskeyCache.Map.Remove(key)
			}
		}
	})

	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.Imr.RootHints = filepath.Join(t.TempDir(), "no-such-hints")
	conf.Imr.TrustAnchorDNSKEY = k.String()

	if err := conf.InitImrEngine(context.Background(), true); err == nil {
		t.Fatal("InitImrEngine succeeded with no root hints to read")
	}
	got := cache.DnskeyCache.Get(anchor, k.KeyTag())
	if got == nil || !got.TrustAnchor {
		t.Fatalf("configured trust anchor not loaded before priming: %+v", got)
	}
}
