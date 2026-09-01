/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The resolver cache, indexed by names that arrive from other servers.
 *
 * A recursive resolver has no say in how the names it caches are spelled. Its
 * own 0x20 randomisation (RFC-draft, widely deployed) sends a different mixture
 * of upper and lower case on every query, and the answer echoes it; the RRs in
 * that answer carry whatever case the authoritative server stores. So a cache
 * keyed by the exact bytes stores the same name repeatedly and finds it never.
 */
package cache

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func testCache(t *testing.T) *RRsetCacheT {
	t.Helper()
	return NewRRsetCache(log.New(os.Stderr, "", 0), false, false)
}

func aRRset(t *testing.T, owner, addr string) *core.RRset {
	t.Helper()
	rr, err := dns.NewRR(owner + " 300 IN A " + addr)
	if err != nil {
		t.Fatalf("building %s A %s: %v", owner, addr, err)
	}
	return &core.RRset{Name: owner, RRtype: dns.TypeA, RRs: []dns.RR{rr}}
}

// Cached under one spelling, found under every other. Without this the resolver
// re-queries upstream for a name it already holds, on every query, for ever.
func TestRRsetCacheIsCaseInsensitive(t *testing.T) {
	rrcache := testCache(t)
	rrcache.Set("WWW.Example.COM.", dns.TypeA, &CachedRRset{
		Name:       "WWW.Example.COM.",
		RRtype:     dns.TypeA,
		RRset:      aRRset(t, "WWW.Example.COM.", "192.0.2.1"),
		Expiration: time.Now().Add(time.Hour),
	})

	for _, spelling := range []string{
		"WWW.Example.COM.", "www.example.com.", "WWW.EXAMPLE.COM.", "wWw.ExAmPlE.cOm.",
	} {
		if got := rrcache.Get(spelling, dns.TypeA); got == nil {
			t.Errorf("Get(%q, A) = nil -- a cached name was not found", spelling)
		}
	}

	// The type half of the composite key must still discriminate, or "folding
	// the key" would have quietly turned the cache into a per-name cache.
	if got := rrcache.Get("www.example.com.", dns.TypeAAAA); got != nil {
		t.Error("Get(AAAA) returned the A entry: the qtype half of the key stopped working")
	}
	if got := rrcache.Get("other.example.com.", dns.TypeA); got != nil {
		t.Error("Get on an uncached name returned something")
	}
}

// One name is one entry however it was spelled when stored. Two entries for one
// name is worse than a miss: which one is served depends on nothing.
func TestRRsetCacheSpellingsAreOneEntry(t *testing.T) {
	rrcache := testCache(t)
	for _, spelling := range []string{"www.example.com.", "WWW.EXAMPLE.COM.", "Www.Example.Com."} {
		rrcache.Set(spelling, dns.TypeA, &CachedRRset{
			Name: spelling, RRtype: dns.TypeA,
			RRset:      aRRset(t, spelling, "192.0.2.1"),
			Expiration: time.Now().Add(time.Hour),
		})
	}
	if n := rrcache.RRsets.Count(); n != 1 {
		t.Errorf("cache holds %d entries for one name, want 1", n)
	}
}

func TestDnskeyCacheIsCaseInsensitive(t *testing.T) {
	dkc := NewDnskeyCache()
	dkc.Set("Example.COM.", 12345, &CachedDnskeyRRset{
		Name: "Example.COM.", Keyid: 12345,
		Expiration: time.Now().Add(time.Hour),
	})

	for _, spelling := range []string{"Example.COM.", "example.com.", "EXAMPLE.COM."} {
		if got := dkc.Get(spelling, 12345); got == nil {
			t.Errorf("DnskeyCache.Get(%q, 12345) = nil", spelling)
		}
	}
	if got := dkc.Get("example.com.", 54321); got != nil {
		t.Error("a different keyid returned the entry: the keyid half of the key stopped working")
	}
}

// The name-keyed indexes: zone state, per-zone server sets, the global server
// map, and the TLSA cache. Each is reached with a name that came off the wire.
func TestCacheNameIndexesAreCaseInsensitive(t *testing.T) {
	rrcache := testCache(t)

	rrcache.ZoneMap.Set("Example.COM.", &Zone{ZoneName: "Example.COM."})
	rrcache.Servers.Set("Example.COM.", []string{"192.0.2.1:53"})
	rrcache.ServerMap.Set("Example.COM.", map[string]*AuthServer{"ns1.example.com.": {Name: "ns1.example.com."}})
	rrcache.AuthServerMap.Set("NS1.Example.COM.", &AuthServer{Name: "NS1.Example.COM."})

	for _, spelling := range []string{"example.com.", "EXAMPLE.COM.", "Example.COM."} {
		if _, ok := rrcache.ZoneMap.Get(spelling); !ok {
			t.Errorf("ZoneMap.Get(%q) missed", spelling)
		}
		if _, ok := rrcache.Servers.Get(spelling); !ok {
			t.Errorf("Servers.Get(%q) missed", spelling)
		}
		if _, ok := rrcache.ServerMap.Get(spelling); !ok {
			t.Errorf("ServerMap.Get(%q) missed", spelling)
		}
	}
	for _, spelling := range []string{"ns1.example.com.", "NS1.EXAMPLE.COM."} {
		if _, ok := rrcache.AuthServerMap.Get(spelling); !ok {
			t.Errorf("AuthServerMap.Get(%q) missed", spelling)
		}
	}

	// GetOrCreateAuthServer exists to guarantee one instance per nameserver.
	// Keyed by raw bytes it guaranteed one per SPELLING, so per-server state --
	// health, transport capability, TLSA -- was silently split.
	first := rrcache.GetOrCreateAuthServer("ns2.example.com.")
	again := rrcache.GetOrCreateAuthServer("NS2.EXAMPLE.COM.")
	if first != again {
		t.Error("GetOrCreateAuthServer returned two instances for one nameserver")
	}
}

// isSubdomainOf decides what a cache flush removes and which cached zone is
// closest to a name.
//
// A characterisation test, not a regression test: the previous implementation
// canonicalised both names and added the leading dot, so it already got these
// right. The properties are worth pinning anyway, because the two traps below
// -- "ample.com." against "example.com.", and case -- are exactly what a future
// simplification to strings.HasSuffix would reintroduce.
func TestIsSubdomainOfIsADNSTest(t *testing.T) {
	for _, tc := range []struct {
		name, parent string
		want         bool
		why          string
	}{
		{"www.example.com.", "example.com.", true, "plain subdomain"},
		{"example.com.", "example.com.", true, "a name is inside itself"},
		{"WWW.EXAMPLE.COM.", "example.com.", true, "case must not matter"},
		{"www.example.com.", "EXAMPLE.COM.", true, "either side"},
		{"anything.", ".", true, "everything is under the root"},

		{"example.com.", "ample.com.", false, "NOT a subdomain: the byte suffix matches but the label does not"},
		{"notexample.com.", "example.com.", false, "same trap"},
		{"example.com.", "www.example.com.", false, "the other way round"},
		{"example.org.", "example.com.", false, "unrelated"},
	} {
		if got := isSubdomainOf(tc.name, tc.parent); got != tc.want {
			t.Errorf("isSubdomainOf(%q, %q) = %v, want %v -- %s",
				tc.name, tc.parent, got, tc.want, tc.why)
		}
	}
}

// FindClosestKnownZone picks which cached delegation to start iterating from.
// Picking a wrong one sends the query to servers that are not authoritative for
// it; picking none restarts from the root.
func TestFindClosestKnownZoneIsCaseInsensitive(t *testing.T) {
	rrcache := testCache(t)
	if err := rrcache.AddServers("Example.COM.", map[string]*AuthServer{
		"ns1.example.com.": {Name: "ns1.example.com."},
	}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}

	for _, qname := range []string{
		"www.example.com.", "WWW.EXAMPLE.COM.", "www.EXAMPLE.com.", "WWW.example.com.",
	} {
		zone, servers, err := rrcache.FindClosestKnownZone(qname)
		if err != nil {
			t.Errorf("FindClosestKnownZone(%q): %v", qname, err)
			continue
		}
		if !core.EqualNames(zone, "example.com.") || len(servers) == 0 {
			t.Errorf("FindClosestKnownZone(%q) = %q with %d servers, want example.com.",
				qname, zone, len(servers))
		}
	}

	// And it must not match across a label boundary: "ample.com." is not an
	// ancestor of "example.com." however similar the bytes look.
	if zone, _, _ := rrcache.FindClosestKnownZone("host.ample.com."); core.EqualNames(zone, "example.com.") {
		t.Error("FindClosestKnownZone matched example.com. for a name under ample.com.")
	}
}

// A negative answer is only believable from the zone that holds the name. The
// gate is a bailiwick test on the SOA owner in the authority section, and it
// used to be a byte-wise suffix with no leading dot -- so an SOA for "ample."
// authorised a denial for "example.", a forged NXDOMAIN one label away from the
// real zone. Case was already handled here; the label boundary was not.
func TestNegativeResponseNeedsAnSOAInBailiwick(t *testing.T) {
	rrcache := testCache(t)

	soaFor := func(owner string) []*core.RRset {
		t.Helper()
		rr, err := dns.NewRR(owner + " 3600 IN SOA ns." + owner + " hostmaster." + owner +
			" 1 7200 1800 604800 7200")
		if err != nil {
			t.Fatalf("building SOA for %q: %v", owner, err)
		}
		return []*core.RRset{{Name: owner, RRtype: dns.TypeSOA, RRs: []dns.RR{rr}}}
	}

	// The trap: "ample.com." is not an ancestor of "www.example.com.", however
	// well the bytes line up.
	state, _, err := rrcache.ValidateNegativeResponse(context.Background(),
		"www.example.com.", dns.TypeA, dns.RcodeNameError, soaFor("ample.com."), nil)
	if err != nil {
		t.Fatalf("ValidateNegativeResponse: %v", err)
	}
	if state != ValidationStateBogus {
		t.Errorf("an SOA for ample.com. was accepted as authorising a denial for "+
			"www.example.com. (state=%v) -- a forged denial one label from the real zone", state)
	}

	// And the same name spelled differently must still be in bailiwick, or the
	// gate would simply reject everything.
	state, _, err = rrcache.ValidateNegativeResponse(context.Background(),
		"WWW.EXAMPLE.COM.", dns.TypeA, dns.RcodeNameError, soaFor("Example.COM."), nil)
	if err != nil {
		t.Fatalf("ValidateNegativeResponse: %v", err)
	}
	if state == ValidationStateBogus {
		t.Error("a mis-cased but in-bailiwick SOA was rejected as out of zone")
	}
}

// TLSA owners arrive from the wire under the _853._udp / _853._tcp prefixes.
// The prefix test ran on the name as received, so an upstream that upcased the
// prefix produced no base name and the server's TLSA records were ignored.
func TestBaseFromTLSAOwnerIgnoresCase(t *testing.T) {
	for _, tc := range []struct{ owner, want string }{
		{"_853._tcp.ns1.example.com.", "ns1.example.com."},
		{"_853._TCP.ns1.example.com.", "ns1.example.com."},
		{"_853._UDP.NS1.Example.COM.", "NS1.Example.COM."},
		{"ns1.example.com.", ""},
		{".", ""},
	} {
		if got := baseFromTLSAOwner(tc.owner); got != tc.want {
			t.Errorf("baseFromTLSAOwner(%q) = %q, want %q", tc.owner, got, tc.want)
		}
	}
}

// The per-zone server map is a plain map held inside a NameMap. The OUTER key
// (the zone) folds because NameMap folds it. The INNER key (the nameserver) is
// a name off the wire too, and it has to fold by the same function on both
// sides -- an insert under the spelling an upstream used and a lookup under the
// canonical form are the same miss as any other.
//
// Two things depend on that map finding its entries: transport-signal
// application (`_dns.<ns>` SVCB/TSYNC answers) and in-bailiwick glue
// revalidation, which looks up the hosts collectInBailiwickNS returns.
func TestServerMapInnerKeysFold(t *testing.T) {
	rrcache := testCache(t)

	// Stored under the spelling an upstream happened to send.
	if err := rrcache.AddServers("Example.COM.", map[string]*AuthServer{
		"NS1.Example.COM.": {Name: "NS1.Example.COM."},
		"ns2.example.com.": {Name: "ns2.example.com."},
	}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}

	sm, ok := rrcache.ServerMapCopy("EXAMPLE.COM.")
	if !ok {
		t.Fatal("ServerMapCopy missed the zone; the outer key did not fold")
	}
	if len(sm) != 2 {
		t.Fatalf("server map has %d entries, want 2: %v", len(sm), sm)
	}

	for _, spelling := range []string{
		"ns1.example.com.", "NS1.Example.COM.", "NS1.EXAMPLE.COM.", "nS1.eXaMpLe.CoM.",
	} {
		if _, ok := sm[ServerKey(spelling)]; !ok {
			t.Errorf("sm[ServerKey(%q)] missed -- a nameserver stored under one "+
				"spelling is not found under another, so its transport signals "+
				"and glue revalidation are dropped", spelling)
		}
	}
	if _, ok := sm[ServerKey("ns3.example.com.")]; ok {
		t.Error("a nameserver that was never stored was found")
	}

	// And the keys really are canonical, not merely reachable through the
	// helper: collectInBailiwickNS hands canonical names straight to this map.
	for k := range sm {
		if k != core.CanonicalizeName(k) {
			t.Errorf("server map key %q is not canonical", k)
		}
	}
}

// TLSA records are keyed by (nameserver, owner) inside ServerTLSA. The outer
// map folds; the inner one is a plain map that was keyed with
// dns.CanonicalName, which is right about case but rewrites non-UTF-8 octets.
func TestTLSAKeysFoldOnBothLevels(t *testing.T) {
	rrcache := testCache(t)
	owner := "_853._tcp.ns1.example.com."

	rr, err := dns.NewRR(owner + " 300 IN TLSA 3 1 1 " +
		"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	if err != nil {
		t.Fatalf("building the TLSA: %v", err)
	}
	rrcache.StoreTLSAForServer("NS1.Example.COM.", owner,
		&core.RRset{Name: owner, RRtype: dns.TypeTLSA, RRs: []dns.RR{rr}},
		ValidationStateSecure)

	for _, base := range []string{"ns1.example.com.", "NS1.EXAMPLE.COM.", "NS1.Example.COM."} {
		for _, own := range []string{owner, "_853._TCP.NS1.EXAMPLE.COM."} {
			if got := rrcache.LookupTLSAForServer(base, own); got == nil {
				t.Errorf("LookupTLSAForServer(%q, %q) = nil; stored under a "+
					"different spelling of the same two names", base, own)
			}
		}
	}
	if got := rrcache.LookupTLSAForServer("ns2.example.com.", owner); got != nil {
		t.Error("a TLSA was returned for a nameserver it was not stored under")
	}

	// And the reason these keys use core.CanonicalizeName rather than
	// dns.CanonicalName, which agrees with it on every ASCII name above.
	// dns.CanonicalName runs the name through strings.Map, so a lone 0xfe and a
	// lone 0xff both come back as U+FFFD and the two nameservers share one
	// bucket -- whichever was stored second answers for both.
	store := func(base string) {
		rr, err := dns.NewRR(owner + " 300 IN TLSA 3 1 1 " +
			"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
		if err != nil {
			t.Fatalf("building the TLSA: %v", err)
		}
		rrcache.StoreTLSAForServer(base, base,
			&core.RRset{Name: base, RRtype: dns.TypeTLSA, RRs: []dns.RR{rr}},
			ValidationStateSecure)
	}
	fe, ff := "ns\xfe1.example.", "ns\xff1.example."
	store(fe)
	store(ff)
	if rrcache.LookupTLSAForServer(fe, fe) == nil || rrcache.LookupTLSAForServer(ff, ff) == nil {
		t.Error("a TLSA stored under a name with a raw octet could not be read back")
	}
	if rrcache.LookupTLSAForServer(fe, ff) != nil || rrcache.LookupTLSAForServer(ff, fe) != nil {
		t.Error("two nameservers differing only by a non-UTF-8 octet share one TLSA bucket")
	}
}

// FlushAll keeps the root NS RRset and the glue for the nameservers it names.
// It collects those nameserver names into a set, then walks the cache deciding
// what to keep by looking each owner up in that set -- so the set has to be
// built and read with ONE function. It was built with CanonicalizeName and read
// with dns.CanonicalName, which agree on every ASCII name and part company on
// the first octet that is not valid UTF-8. At that point the priming glue is
// flushed as though it were ordinary cached data, and the resolver has to start
// from the hints again.
func TestFlushAllKeepsRootGlueKeyedConsistently(t *testing.T) {
	rrcache := testCache(t)
	const nsName = "ns\xff1.root-servers.example."

	rootNS, err := dns.NewRR(". 3600 IN NS " + nsName)
	if err != nil {
		t.Fatalf("building the root NS: %v", err)
	}
	rrcache.Set(".", dns.TypeNS, &CachedRRset{
		Name: ".", RRtype: dns.TypeNS,
		RRset:      &core.RRset{Name: ".", RRtype: dns.TypeNS, RRs: []dns.RR{rootNS}},
		Expiration: time.Now().Add(time.Hour),
	})
	rrcache.Set(nsName, dns.TypeA, &CachedRRset{
		Name: nsName, RRtype: dns.TypeA,
		RRset:      aRRset(t, "ns1.root-servers.example.", "192.0.2.1"),
		Expiration: time.Now().Add(time.Hour),
	})
	// Something ordinary, which FlushAll is supposed to remove.
	rrcache.Set("www.example.com.", dns.TypeA, &CachedRRset{
		Name: "www.example.com.", RRtype: dns.TypeA,
		RRset:      aRRset(t, "www.example.com.", "192.0.2.2"),
		Expiration: time.Now().Add(time.Hour),
	})

	rrcache.FlushAll()

	if got := rrcache.Get(nsName, dns.TypeA); got == nil {
		t.Error("glue for a root nameserver was flushed: the set of root NS hosts " +
			"was built with one key function and read with another")
	}
	if got := rrcache.Get(".", dns.TypeNS); got == nil {
		t.Error("the root NS RRset itself was flushed")
	}
	if got := rrcache.Get("www.example.com.", dns.TypeA); got != nil {
		t.Error("FlushAll kept ordinary cached data; it is supposed to remove it")
	}
}
