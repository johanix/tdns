package tdns

import (
	"net"
	"testing"
)

func TestResolvePrimaries_literalIP(t *testing.T) {
	res := resolvePrimaries([]PeerConf{{Addr: "192.0.2.1", Key: "K1"}})
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
	res := resolvePrimaries([]PeerConf{{Addr: "192.0.2.1:5353", Key: NOKEY}})
	if len(res.Resolved) != 1 || res.Resolved[0].Addr != "192.0.2.1:5353" {
		t.Fatalf("got %+v", res.Resolved)
	}
}

func TestResolvePrimaries_dedupSameAddr(t *testing.T) {
	res := resolvePrimaries([]PeerConf{
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
	res := resolvePrimaries([]PeerConf{
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
	res := resolvePrimaries([]PeerConf{{Addr: "tdns-nonexistent-test.invalid", Key: NOKEY}})
	if len(res.Resolved) != 0 {
		t.Fatalf("want no resolved addresses, got %+v", res.Resolved)
	}
	if len(res.Unresolved) != 1 || res.Unresolved[0] != "tdns-nonexistent-test.invalid" {
		t.Fatalf("want unresolved entry, got %v", res.Unresolved)
	}
}

func TestResolvePrimaries_localhostExpands(t *testing.T) {
	res := resolvePrimaries([]PeerConf{{Addr: "localhost", Key: "K1"}})
	if len(res.Unresolved) != 0 {
		t.Fatalf("localhost should resolve: unresolved=%v", res.Unresolved)
	}
	if len(res.Resolved) == 0 {
		t.Fatal("localhost produced no addresses")
	}
	for _, up := range res.Resolved {
		if up.Key != "K1" {
			t.Fatalf("key not copied: %+v", up)
		}
	}
	// v4 entries must precede any v6 entry.
	sawV6 := false
	for _, up := range res.Resolved {
		host, _, err := net.SplitHostPort(up.Addr)
		if err != nil {
			t.Fatalf("bad addr %q: %v", up.Addr, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			t.Fatalf("not an IP: %q", up.Addr)
		}
		if ip.To4() == nil {
			sawV6 = true
		} else if sawV6 {
			t.Fatalf("v4 address %q after v6 in ordering", up.Addr)
		}
	}
}
