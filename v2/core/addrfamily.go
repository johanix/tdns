/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// AddrFamily restricts the IP family a DNSClient uses to reach a server: dig's
// -4 and -6. The zero value is no restriction, so every existing caller keeps
// the dual-stack behaviour it has always had.
type AddrFamily uint8

const (
	FamilyAny  AddrFamily = iota // no restriction
	FamilyIPv4                   // IPv4 only (-4)
	FamilyIPv6                   // IPv6 only (-6)
)

// OptionAddrFamily is the key under which a caller's string option map carries
// the family, as the value of Suffix: "4" or "6", absent for no restriction.
// dog's option map is handed to the printing and transfer code in package
// tdns, which reads this key rather than growing another parameter.
const OptionAddrFamily = "ipfamily"

func (f AddrFamily) String() string {
	switch f {
	case FamilyIPv4:
		return "IPv4"
	case FamilyIPv6:
		return "IPv6"
	default:
		return "any"
	}
}

// Suffix is the one character Go appends to a network name to restrict it:
// "4" for udp4/tcp4, "6" for udp6/tcp6, "" for none.
func (f AddrFamily) Suffix() string {
	switch f {
	case FamilyIPv4:
		return "4"
	case FamilyIPv6:
		return "6"
	default:
		return ""
	}
}

// Flag is the command-line spelling: "-4", "-6", or "" for none.
func (f AddrFamily) Flag() string {
	if s := f.Suffix(); s != "" {
		return "-" + s
	}
	return ""
}

// ParseAddrFamily is the inverse of Suffix. The empty string is no
// restriction; anything but "", "4" and "6" is an error rather than a silent
// fall back to dual-stack, because a query meant to stay on IPv6 that goes out
// over IPv4 instead is the failure -6 exists to prevent.
func ParseAddrFamily(s string) (AddrFamily, error) {
	switch s {
	case "":
		return FamilyAny, nil
	case "4":
		return FamilyIPv4, nil
	case "6":
		return FamilyIPv6, nil
	}
	return FamilyAny, fmt.Errorf("unknown address family %q (want 4 or 6)", s)
}

// Network turns a Go network name into its family-restricted form: "udp"
// becomes "udp6" for FamilyIPv6, and "tcp-tls" (miekg's DoT) becomes
// "tcp6-tls". Any family already on base is replaced, so applying it twice
// cannot produce "tcp46".
func (f AddrFamily) Network(base string) string {
	tlsSuffix := ""
	if b, ok := strings.CutSuffix(base, "-tls"); ok {
		base, tlsSuffix = b, "-tls"
	}
	base = strings.TrimRight(base, "46")
	return base + f.Suffix() + tlsSuffix
}

// Allows says whether host may be dialled under f. literal is false when host
// is not an IP address (a name): nothing can be said about it without
// resolving it, and the dial will fail by itself if it has no address of the
// right family. For a literal, allowed is whether it belongs to f. An
// IPv4-mapped IPv6 address (::ffff:192.0.2.1) counts as IPv4, which is the
// family it is dialled over.
func (f AddrFamily) Allows(host string) (allowed, literal bool) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return true, false
	}
	switch f {
	case FamilyIPv4:
		return ip.Unmap().Is4(), true
	case FamilyIPv6:
		return !ip.Unmap().Is4(), true
	default:
		return true, true
	}
}

// WithAddrFamily restricts every connection the client makes to one IP family.
//
// It must reach each transport, not just the dns.Client ones: a -6 that applied
// to Do53 and DoT but let DoH and DoQ resolve to an A record and connect over
// IPv4 would claim a restriction it did not enforce. A name server is resolved
// for the restricted family only, and an address literal of the other family
// fails to dial.
//
// FamilyAny leaves the client as NewDNSClient built it.
func WithAddrFamily(f AddrFamily) DNSClientOption {
	return func(c *DNSClient) {
		c.AddrFamily = f
		if f == FamilyAny {
			return
		}
		// Do53 (UDP, and the TCP fallback) and DoT: miekg takes the network
		// name straight to net.Dialer, which accepts udp4/tcp6/... and, for
		// "tcp6-tls", strips the suffix itself.
		for _, cl := range []*dns.Client{c.DNSClientUDP, c.DNSClientTCP, c.DNSClientTLS} {
			if cl != nil {
				cl.Net = f.Network(cl.Net)
			}
		}
		// DoH: net/http dials "tcp" itself, so substitute the dialer.
		if c.HTTPClient != nil {
			if tr, ok := c.HTTPClient.Transport.(*http.Transport); ok {
				tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, f.Network(network), addr)
				}
			}
		}
		// DoQ is handled where the connection is made, in dialQUIC.
	}
}
