package tdns

import (
	"context"
	"testing"
)

func TestResolvePrimaries_literalIP(t *testing.T) {
	res := resolvePrimaries(context.Background(), nil, []PeerConf{{Addr: "192.0.2.1", Key: "K1"}})
	if len(res.Unresolved) != 0 || len(res.KeyCollisions) != 0 {
		t.Fatalf("unexpected warnings: unresolved=%v collisions=%v", res.Unresolved, res.KeyCollisions)
	}
	if len(res.Resolved) != 1 {
		t.Fatalf("want 1 resolved, got %d", len(res.Resolved))
	}
	if res.Resolved[0].Addr != "192.0.2.1:53" || res.Resolved[0].Key != "K1" {
		t.Fatalf("got %+v", res.Resolved[0])
	}
}

func TestResolvePrimaries_preservesPort(t *testing.T) {
	res := resolvePrimaries(context.Background(), nil, []PeerConf{{Addr: "192.0.2.1:5353", Key: NOKEY}})
	if len(res.Resolved) != 1 || res.Resolved[0].Addr != "192.0.2.1:5353" {
		t.Fatalf("got %+v", res.Resolved)
	}
}

func TestResolvePrimaries_dedupSameAddr(t *testing.T) {
	res := resolvePrimaries(context.Background(), nil, []PeerConf{
		{Addr: "192.0.2.1:53", Key: "K1"},
		{Addr: "192.0.2.1:53", Key: "K1"},
	})
	if len(res.Resolved) != 1 {
		t.Fatalf("want dedup to 1, got %d: %+v", len(res.Resolved), res.Resolved)
	}
	if len(res.KeyCollisions) != 0 {
		t.Fatalf("same key should not collide: %v", res.KeyCollisions)
	}
}

func TestResolvePrimaries_keyCollision(t *testing.T) {
	res := resolvePrimaries(context.Background(), nil, []PeerConf{
		{Addr: "192.0.2.1:53", Key: "K1"},
		{Addr: "192.0.2.1:53", Key: "K2"},
	})
	if len(res.Resolved) != 1 || res.Resolved[0].Key != "K1" {
		t.Fatalf("want first key kept, got %+v", res.Resolved)
	}
	if len(res.KeyCollisions) != 1 || res.KeyCollisions[0] != "192.0.2.1:53" {
		t.Fatalf("want key collision recorded, got %v", res.KeyCollisions)
	}
}

func TestResolvePrimaries_unresolvedHostname(t *testing.T) {
	// With no IMR a hostname cannot be resolved here and is reported unresolved.
	res := resolvePrimaries(context.Background(), nil, []PeerConf{{Addr: "ns.example.invalid", Key: NOKEY}})
	if len(res.Resolved) != 0 {
		t.Fatalf("want no resolved addresses, got %+v", res.Resolved)
	}
	if len(res.Unresolved) != 1 || res.Unresolved[0] != "ns.example.invalid" {
		t.Fatalf("want unresolved entry, got %v", res.Unresolved)
	}
}

func TestResolvePrimaries_partialResolution(t *testing.T) {
	// A literal IP (no lookup) plus an unresolvable hostname (no IMR): the zone
	// is served from the IP, the hostname is reported unresolved.
	res := resolvePrimaries(context.Background(), nil, []PeerConf{
		{Addr: "192.0.2.1:53", Key: NOKEY},
		{Addr: "ns.example.invalid", Key: NOKEY},
	})
	if len(res.Resolved) != 1 || res.Resolved[0].Addr != "192.0.2.1:53" {
		t.Fatalf("want the IP served, got %+v", res.Resolved)
	}
	if len(res.Unresolved) != 1 || res.Unresolved[0] != "ns.example.invalid" {
		t.Fatalf("want the hostname unresolved, got %v", res.Unresolved)
	}
}

func TestSortV4First(t *testing.T) {
	got := sortV4First([]string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"})
	want := []string{"192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"}
	if len(got) != len(want) {
		t.Fatalf("len: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order: got %v want %v", got, want)
		}
	}
}

func TestBuildUpstreams(t *testing.T) {
	src := PeerConf{Addr: "ns.example.net", Key: "K1"}
	got := buildUpstreams([]string{"192.0.2.1", "2001:db8::1"}, "5353", src, "ns.example.net")
	if len(got) != 2 {
		t.Fatalf("want 2, got %+v", got)
	}
	if got[0].Addr != "192.0.2.1:5353" || got[0].Key != "K1" {
		t.Fatalf("v4 tuple wrong: %+v", got[0])
	}
	if got[1].Addr != "[2001:db8::1]:5353" || got[1].Key != "K1" {
		t.Fatalf("v6 tuple wrong: %+v", got[1])
	}
	// Do53 source: the resolved tuples must be identical to pre-XoT output —
	// in particular TLSName stays empty.
	if got[0].TLSName != "" || got[0].Transport != "" {
		t.Fatalf("do53 tuple gained XoT fields: %+v", got[0])
	}
}

func TestBuildUpstreams_DoTCarriesTLSNameAndAuth(t *testing.T) {
	src := PeerConf{
		Addr:      "ns.example.net",
		Key:       NOKEY,
		Transport: TransportDoT,
		TLSAuth:   TLSAuthDANE,
	}
	got := buildUpstreams([]string{"192.0.2.1", "2001:db8::1"}, "853", src, "ns.example.net")
	if len(got) != 2 {
		t.Fatalf("want 2, got %+v", got)
	}
	for i, up := range got {
		if up.Transport != TransportDoT || up.TLSAuth != TLSAuthDANE {
			t.Fatalf("tuple %d lost XoT fields: %+v", i, up)
		}
		// The source hostname must survive resolution on every tuple
		// (multi-address primaries all share the same SNI/DANE name).
		if up.TLSName != "ns.example.net" {
			t.Fatalf("tuple %d lost the hostname: %+v", i, up)
		}
	}
}

func TestBuildUpstreams_ExplicitTLSNameWins(t *testing.T) {
	src := PeerConf{
		Addr:      "xfr.example.net",
		Key:       NOKEY,
		Transport: TransportDoT,
		TLSAuth:   TLSAuthPin,
		Pins:      []string{"AAAA"},
		TLSName:   "ns2.example.net",
	}
	got := buildUpstreams([]string{"192.0.2.1"}, "853", src, "xfr.example.net")
	if len(got) != 1 || got[0].TLSName != "ns2.example.net" {
		t.Fatalf("explicit tls-name must not be overwritten: %+v", got)
	}
}

func TestResolvePrimaries_DoTIPLiteral(t *testing.T) {
	// An IP-literal DoT primary defaults to port 853 and keeps its XoT fields.
	res := resolvePrimaries(context.Background(), nil, []PeerConf{{
		Addr:      "192.0.2.1",
		Key:       NOKEY,
		Transport: TransportDoT,
		TLSAuth:   TLSAuthPin,
		Pins:      []string{"AAAA"},
		TLSName:   "ns1.example.net",
	}})
	if len(res.Resolved) != 1 {
		t.Fatalf("want 1 resolved, got %+v", res)
	}
	up := res.Resolved[0]
	if up.Addr != "192.0.2.1:853" {
		t.Fatalf("DoT default port should be 853: %+v", up)
	}
	if up.Transport != TransportDoT || up.TLSAuth != TLSAuthPin || up.TLSName != "ns1.example.net" || len(up.Pins) != 1 {
		t.Fatalf("XoT fields lost through resolution: %+v", up)
	}
}
