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

// The anchors must be in place before priming asks the root anything.
// InitImrEngine loads them and sends nothing: priming is Start's. So after it,
// with root hints that could not even be read, the anchor is in the DNSKEY
// cache and the resolver is not Ready.
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

	if err := conf.InitImrEngine(context.Background()); err != nil {
		t.Fatalf("InitImrEngine sends nothing, and failed: %v", err)
	}
	select {
	case <-conf.Internal.ImrEngine.Ready():
		t.Fatal("Ready before anything was primed")
	default:
	}
	got := cache.DnskeyCache.Get(anchor, k.KeyTag())
	if got == nil || !got.TrustAnchor {
		t.Fatalf("configured trust anchor not loaded before priming: %+v", got)
	}
}
