/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The SOA probe half of transfer-src (#409). ZoneTransferIn bound the source
// and DoTransfer's probe did not, so against a primary that only permits the
// published address the transfer worked and the probe did not -- and since
// every refresh begins with a probe, the zone never transferred at all.

// TestBindClientSrcTransportAndAddrType pins the two things that differ from
// the transfer path, both of which fail in ways that look like an unreachable
// primary rather than like a bug here.
//
// The address TYPE has to match the transport: the probe defaults to UDP, and a
// *net.TCPAddr LocalAddr -- the type dialTransferConn correctly uses -- makes
// the dial fail with a mismatched address type.
//
// The family has to be pinned in Net, in the spelling matching the transport
// already selected, or a dual-stack hostname upstream can resolve to the family
// the bound source is not in.
func TestBindClientSrcTransportAndAddrType(t *testing.T) {
	for _, tc := range []struct {
		name     string
		startNet string
		upstream string
		src      string
		wantNet  string
		wantUDP  bool // else TCP
	}{
		{"udp default", "", "192.0.2.10:53", "192.0.2.1", "udp4", true},
		{"udp explicit", "udp", "192.0.2.10:53", "192.0.2.1", "udp4", true},
		{"udp v6", "", "[2001:db8::10]:53", "2001:db8::1", "udp6", true},
		{"tcp", "tcp", "192.0.2.10:53", "192.0.2.1", "tcp4", false},
		{"tcp v6", "tcp", "[2001:db8::10]:53", "2001:db8::1", "tcp6", false},
		{"xot", "tcp-tls", "192.0.2.10:853", "192.0.2.1", "tcp4-tls", false},
		{"xot v6", "tcp-tls", "[2001:db8::10]:853", "2001:db8::1", "tcp6-tls", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &dns.Client{Net: tc.startNet}
			got := bindClientSrc(context.Background(), c, tc.upstream, []string{tc.src})
			if got == nil {
				t.Fatalf("no source bound for %s with src %s", tc.upstream, tc.src)
			}
			if !got.Equal(net.ParseIP(tc.src)) {
				t.Errorf("bound %v, want %s", got, tc.src)
			}
			if c.Net != tc.wantNet {
				t.Errorf("Net = %q, want %q", c.Net, tc.wantNet)
			}
			if c.Dialer == nil {
				t.Fatal("Dialer not set; nothing would bind")
			}
			switch la := c.Dialer.LocalAddr.(type) {
			case *net.UDPAddr:
				if !tc.wantUDP {
					t.Errorf("LocalAddr is *net.UDPAddr, want *net.TCPAddr for %q", tc.wantNet)
				}
			case *net.TCPAddr:
				if tc.wantUDP {
					t.Errorf("LocalAddr is *net.TCPAddr, want *net.UDPAddr for %q", tc.wantNet)
				}
			default:
				t.Errorf("LocalAddr has unexpected type %T", la)
			}
			// A Dialer with no timeout would wait out the OS default on an
			// unreachable primary, which the probe loop is not built for.
			if c.Dialer.Timeout <= 0 {
				t.Error("Dialer.Timeout not set; the probe would hang on a dead primary")
			}
		})
	}
}

// A family with no configured source must leave the client untouched, so the
// probe dials unbound. An operator naming only a v4 source must not thereby
// break every v6 upstream -- the same forgiving default pickTransferSrc applies.
func TestBindClientSrcLeavesUnmatchedFamilyAlone(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream string
		srcs     []string
	}{
		{"v6 upstream, only v4 sources", "[2001:db8::10]:53", []string{"192.0.2.1"}},
		{"v4 upstream, only v6 sources", "192.0.2.10:53", []string{"2001:db8::1"}},
		{"no sources at all", "192.0.2.10:53", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &dns.Client{}
			if got := bindClientSrc(context.Background(), c, tc.upstream, tc.srcs); got != nil {
				t.Errorf("bound %v, want nothing", got)
			}
			if c.Net != "" || c.Dialer != nil {
				t.Errorf("client was modified: Net=%q Dialer=%v", c.Net, c.Dialer)
			}
		})
	}
	if bindClientSrc(context.Background(), nil, "192.0.2.10:53", []string{"192.0.2.1"}) != nil {
		t.Error("a nil client should be handled, not dereferenced")
	}
}

// THE ONE WITH TEETH, and the same trick TestDialTransferConnBindsSource uses.
//
// Probing loopback from a loopback source passes whether or not the source is
// ever bound -- the kernel picks a loopback source anyway. So the assertion
// that distinguishes the two is that binding an address the host does NOT have
// must FAIL: without the bind the probe succeeds, with it the kernel refuses.
//
// It also exercises the real miekg dial path with a real UDP LocalAddr, which
// is where a *net.TCPAddr would blow up.
func TestSoaProbeActuallyBindsSource(t *testing.T) {
	const zone = "probe.example."
	addr, stop := startTestSOAServer(t, zone, 42, dns.RcodeSuccess)
	defer stop()

	probe := func(srcs []string) error {
		c := &dns.Client{Timeout: 2 * time.Second}
		bindClientSrc(context.Background(), c, addr, srcs)
		m := new(dns.Msg)
		m.SetQuestion(zone, dns.TypeSOA)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _, err := c.ExchangeContext(ctx, m, addr)
		return err
	}

	// Unbound: the baseline. If this fails the test tells us nothing.
	if err := probe(nil); err != nil {
		t.Fatalf("unbound probe failed, so the loopback server is not answering: %v", err)
	}

	// Bound to an address the host has: must still work. This is the case that
	// would break if the LocalAddr were the wrong type for the transport.
	if err := probe([]string{"127.0.0.1"}); err != nil {
		t.Fatalf("probe bound to 127.0.0.1 failed: %v", err)
	}

	// Bound to an address the host does not have: must fail. Deleting the
	// bind from bindClientSrc makes this one, and only this one, go green.
	if err := probe([]string{"192.0.2.1"}); err == nil {
		t.Error("probe bound to an unassignable source succeeded; " +
			"the source is not being bound at all")
	}
}
