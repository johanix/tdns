/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"net"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A wildcard listener names this host's addresses, not every address. It used
// to match anything, so a server listening on 0.0.0.0 or [::] took every
// in-bailiwick NS name as its own and published its transports under other
// providers' nameservers -- in every zone, under the server-wide option.

// stubLocalAddrs makes ips this host's interface addresses for the test, with
// an empty cache before and after.
func stubLocalAddrs(t *testing.T, ips ...string) *int {
	t.Helper()
	calls := 0
	prev := interfaceAddrs
	interfaceAddrs = func() ([]net.Addr, error) {
		calls++
		var out []net.Addr
		for _, s := range ips {
			out = append(out, &net.IPNet{IP: net.ParseIP(s)})
		}
		return out, nil
	}
	localAddrSnap.Store(nil)
	t.Cleanup(func() { interfaceAddrs = prev; localAddrSnap.Store(nil) })
	return &calls
}

func addrRRset(t *testing.T, rr string) *core.RRset {
	t.Helper()
	r, err := dns.NewRR(rr)
	if err != nil {
		t.Fatal(err)
	}
	return &core.RRset{Name: r.Header().Name, RRtype: r.Header().Rrtype, RRs: []dns.RR{r}}
}

func TestAWildcardListenerMatchesOnlyThisHostsAddresses(t *testing.T) {
	stubLocalAddrs(t, "192.0.2.53", "2001:db8::53")
	for _, listener := range []string{"0.0.0.0:53", "[::]:53", "0.0.0.0", "[::]"} {
		for _, tc := range []struct {
			rr   string
			want bool
		}{
			{"ns.example. 3600 IN A 192.0.2.53", true},
			{"ns.example. 3600 IN AAAA 2001:db8::53", true},
			{"ns.example. 3600 IN A 198.51.100.7", false},
			{"ns.example. 3600 IN AAAA 2001:db8::99", false},
		} {
			if got := matchesConfiguredAddrs([]string{listener}, addrRRset(t, tc.rr)); got != tc.want {
				t.Errorf("listener %q, %s: match %v, want %v", listener, tc.rr, got, tc.want)
			}
		}
	}
}

func TestAnExplicitListenerMatchesItsOwnAddress(t *testing.T) {
	calls := stubLocalAddrs(t, "192.0.2.2")
	for _, tc := range []struct {
		listener, rr string
		want         bool
	}{
		{"127.0.0.1:53", "ns.example. 3600 IN A 127.0.0.1", true},
		{"127.0.0.1", "ns.example. 3600 IN A 127.0.0.1", true},
		{"[2001:db8::1]:53", "ns.example. 3600 IN AAAA 2001:db8::1", true},
		// Compared as addresses, so a non-canonical spelling matches too.
		{"2001:DB8:0::1", "ns.example. 3600 IN AAAA 2001:db8::1", true},
		// A local address that is not a listener is not this server's NS
		// address when the listeners are explicit.
		{"192.0.2.1:53", "ns.example. 3600 IN A 192.0.2.2", false},
	} {
		if got := matchesConfiguredAddrs([]string{tc.listener}, addrRRset(t, tc.rr)); got != tc.want {
			t.Errorf("listener %q, %s: match %v, want %v", tc.listener, tc.rr, got, tc.want)
		}
	}
	if *calls != 0 {
		t.Errorf("explicit listeners read the host's addresses %d time(s)", *calls)
	}
}

// The responder asks per response, so the host's addresses are read at most
// once per interval; a failed read keeps the last good answer.
func TestLocalAddrsReadsTheSystemAtMostOncePerInterval(t *testing.T) {
	calls := stubLocalAddrs(t, "192.0.2.53")
	localAddrs()
	localAddrs()
	if *calls != 1 {
		t.Errorf("read the system %d times, want 1", *calls)
	}

	localAddrSnap.Store(&localAddrSnapshot{ips: []net.IP{net.ParseIP("192.0.2.53")}, at: time.Now().Add(-2 * localAddrsMaxAge)})
	interfaceAddrs = func() ([]net.Addr, error) { return nil, errors.New("no interfaces") }
	if got := localAddrs(); len(got) != 1 || !got[0].Equal(net.ParseIP("192.0.2.53")) {
		t.Errorf("a failed read lost the last good answer: %v", got)
	}

	localAddrSnap.Store(nil)
	if got := localAddrs(); got != nil {
		t.Errorf("a failed first read invented addresses: %v", got)
	}
}

// The join: a zone shared with another provider, a wildcard listener and the
// server-wide option. Only this server's NS name gets a signal; the other
// provider's in-bailiwick name gets none.
func TestAWildcardListenerSignalsOnlyForThisServersNS(t *testing.T) {
	stubLocalAddrs(t, "127.0.0.1")
	const z = "shared.sig.example."
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
ns2.`+z+`	3600	IN	A	192.0.2.2
`, "0.0.0.0:53")
	delete(zd.Options, OptAddTransportSignal)
	serverOptions(zd, map[AuthOption]string{AuthOptAddTransportSignal: "true"})

	runTransportSignalPostpass(conf)
	if !served(zd, "_dns.ns1."+z, dns.TypeSVCB) {
		t.Fatal("no signal for this server's own NS name behind a wildcard listener")
	}
	if served(zd, "_dns.ns2."+z, dns.TypeSVCB) {
		t.Fatal("a wildcard listener claimed the other provider's NS name and published this server's transports under it")
	}
}
