package cache

import (
	"log"
	"os"
	"testing"
	"time"

	core "github.com/johanix/tdns/v0.x/core"
	"github.com/miekg/dns"
)

// TestNewDnskeyCache tests the creation of a new DnskeyCache
func TestNewDnskeyCache(t *testing.T) {
	dkc := NewDnskeyCache()
	if dkc == nil {
		t.Fatal("NewDnskeyCache() returned nil")
	}
	// Map is a value type (cmap.ConcurrentMap), not a pointer, so it's always initialized
	// We can test it's usable by trying to get a non-existent key
	_, _ = dkc.Map.Get("nonexistent")
}

// TestDnskeyCacheGetSet tests basic Get/Set operations on DnskeyCache
func TestDnskeyCacheGetSet(t *testing.T) {
	dkc := NewDnskeyCache()
	zonename := "example.com."
	keyid := uint16(12345)

	// Test Get on empty cache
	result := dkc.Get(zonename, keyid)
	if result != nil {
		t.Errorf("Get() on empty cache should return nil, got %v", result)
	}

	// Test Set and Get
	dnskey := dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zonename,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: 13, // ECDSAP256SHA256
		PublicKey: "testkey",
	}

	rrset := &core.RRset{
		Name:   zonename,
		RRtype: dns.TypeDNSKEY,
		Class:  dns.ClassINET,
		RRs:    []dns.RR{&dnskey},
	}

	cached := &CachedDnskeyRRset{
		Name:       zonename,
		Keyid:      keyid,
		State:      ValidationStateSecure,
		TrustAnchor: false,
		Dnskey:     dnskey,
		RRset:      rrset,
		Expiration: time.Now().Add(1 * time.Hour),
	}

	dkc.Set(zonename, keyid, cached)

	// Test Get after Set
	result = dkc.Get(zonename, keyid)
	if result == nil {
		t.Fatal("Get() after Set() should return non-nil")
	}
	if result.Name != zonename {
		t.Errorf("Get() returned wrong name: got %s, want %s", result.Name, zonename)
	}
	if result.Keyid != keyid {
		t.Errorf("Get() returned wrong keyid: got %d, want %d", result.Keyid, keyid)
	}
	if result.State != ValidationStateSecure {
		t.Errorf("Get() returned wrong state: got %d, want %d", result.State, ValidationStateSecure)
	}
}

// TestDnskeyCacheExpiration tests that expired entries are removed
func TestDnskeyCacheExpiration(t *testing.T) {
	dkc := NewDnskeyCache()
	zonename := "example.com."
	keyid := uint16(12345)

	dnskey := dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zonename,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: "testkey",
	}

	cached := &CachedDnskeyRRset{
		Name:       zonename,
		Keyid:      keyid,
		State:      ValidationStateSecure,
		Dnskey:     dnskey,
		Expiration: time.Now().Add(-1 * time.Hour), // Expired
	}

	dkc.Set(zonename, keyid, cached)

	// Get should return nil for expired entry
	result := dkc.Get(zonename, keyid)
	if result != nil {
		t.Errorf("Get() on expired entry should return nil, got %v", result)
	}
}

// TestNewRRsetCache tests the creation of a new RRsetCache
func TestNewRRsetCache(t *testing.T) {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	rrcache := NewRRsetCache(logger, false, false)
	if rrcache == nil {
		t.Fatal("NewRRsetCache() returned nil")
	}
	if rrcache.RRsets == nil {
		t.Fatal("RRsetCache.RRsets is nil")
	}
	if rrcache.Servers == nil {
		t.Fatal("RRsetCache.Servers is nil")
	}
	if rrcache.ServerMap == nil {
		t.Fatal("RRsetCache.ServerMap is nil")
	}
	if rrcache.DnskeyCache == nil {
		t.Fatal("RRsetCache.DnskeyCache is nil")
	}
}

// TestRRsetCacheGetSet tests basic Get/Set operations on RRsetCache
func TestRRsetCacheGetSet(t *testing.T) {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	rrcache := NewRRsetCache(logger, false, false)
	qname := "example.com."
	qtype := dns.TypeA

	// Test Get on empty cache
	result := rrcache.Get(qname, qtype)
	if result != nil {
		t.Errorf("Get() on empty cache should return nil, got %v", result)
	}

	// Create a test RRset
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{192, 0, 2, 1},
	}

	rrset := &core.RRset{
		Name:   qname,
		RRtype: qtype,
		Class:  dns.ClassINET,
		RRs:    []dns.RR{a},
	}

	cached := &CachedRRset{
		Name:    qname,
		RRtype:  qtype,
		Context: ContextAnswer,
		State:   ValidationStateSecure,
		RRset:   rrset,
		Ttl:     300,
	}

	rrcache.Set(qname, qtype, cached)

	// Test Get after Set
	result = rrcache.Get(qname, qtype)
	if result == nil {
		t.Fatal("Get() after Set() should return non-nil")
	}
	if result.Name != qname {
		t.Errorf("Get() returned wrong name: got %s, want %s", result.Name, qname)
	}
	if result.RRtype != qtype {
		t.Errorf("Get() returned wrong type: got %d, want %d", result.RRtype, qtype)
	}
	if result.State != ValidationStateSecure {
		t.Errorf("Get() returned wrong state: got %d, want %d", result.State, ValidationStateSecure)
	}
}

// TestIsSubdomainOf tests the isSubdomainOf helper function
func TestIsSubdomainOf(t *testing.T) {
	tests := []struct {
		name   string
		parent string
		want   bool
	}{
		{"example.com.", "com.", true},
		{"www.example.com.", "example.com.", true},
		{"example.com.", "example.com.", true},
		{"example.com.", ".", true},
		{"example.com.", "net.", false},
		{"example.com.", "www.example.com.", false},
		{"", ".", true},
		{".", ".", true},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_of_"+tt.parent, func(t *testing.T) {
			got := isSubdomainOf(tt.name, tt.parent)
			if got != tt.want {
				t.Errorf("isSubdomainOf(%q, %q) = %v, want %v", tt.name, tt.parent, got, tt.want)
			}
		})
	}
}

// TestNewAuthServer tests the creation of a new AuthServer
func TestNewAuthServer(t *testing.T) {
	as := NewAuthServer("ns.example.com.")
	if as == nil {
		t.Fatal("NewAuthServer() returned nil")
	}
	if as.Name != "ns.example.com." {
		t.Errorf("NewAuthServer() returned wrong name: got %s, want ns.example.com.", as.Name)
	}
	if len(as.Alpn) == 0 || as.Alpn[0] != "do53" {
		t.Errorf("NewAuthServer() should default to do53, got %v", as.Alpn)
	}
	if as.Src != "unknown" {
		t.Errorf("NewAuthServer() should default Src to 'unknown', got %s", as.Src)
	}

	// Test nil case
	asNil := NewAuthServer("")
	if asNil != nil {
		t.Error("NewAuthServer(\"\") should return nil")
	}
}

