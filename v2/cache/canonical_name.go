/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"bytes"
	"strings"

	"github.com/miekg/dns"
)

// canonicalLabelOctets returns a presentation-format label as the octets it
// stands for, with US-ASCII A-Z folded to lower case and nothing else touched
// (RFC 4034 §6.2). "\065" and "\A" are both one octet; a label compared in its
// escaped text form would order "\000" by the backslash it does not contain.
func canonicalLabelOctets(label string) []byte {
	out := make([]byte, 0, len(label))
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c == '\\' && i+1 < len(label) {
			if i+3 < len(label) && isDigit(label[i+1]) && isDigit(label[i+2]) && isDigit(label[i+3]) {
				c = (label[i+1]-'0')*100 + (label[i+2]-'0')*10 + (label[i+3] - '0')
				i += 3
			} else {
				i++
				c = label[i]
			}
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// canonicalNameCompare orders two names as RFC 4034 §6.1 does: labels compared
// from the right, each as an octet string, and a name that is a proper suffix of
// the other sorting first. Returns -1, 0 or +1.
//
// A plain string comparison is not this order. It compares from the left, so
// "unbound.nlnetlabs.nl." sorts after "org." and "a.zzz.example." before
// "b.example.", which is how NSEC coverage came to accept records that do not
// cover the name at all.
func canonicalNameCompare(a, b string) int {
	al := dns.SplitDomainName(dns.Fqdn(a))
	bl := dns.SplitDomainName(dns.Fqdn(b))
	for i, j := len(al)-1, len(bl)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := bytes.Compare(canonicalLabelOctets(al[i]), canonicalLabelOctets(bl[j])); c != 0 {
			return c
		}
	}
	switch {
	case len(al) < len(bl):
		return -1
	case len(al) > len(bl):
		return 1
	}
	return 0
}

// closestEncloser is the closest encloser of qname that an NXDOMAIN NSEC proves
// (RFC 4035 §5.4): the longest ancestor of qname it shares with the NSEC's owner
// or its next name, never above the zone apex and never qname itself.
func closestEncloser(qname string, nsec *dns.NSEC, zone string) string {
	labels := dns.SplitDomainName(dns.Fqdn(qname))
	n := dns.CompareDomainName(qname, nsec.Hdr.Name)
	if m := dns.CompareDomainName(qname, nsec.NextDomain); m > n {
		n = m
	}
	if z := dns.CountLabel(zone); n < z {
		n = z
	}
	if n >= len(labels) {
		n = len(labels) - 1
	}
	if n <= 0 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[len(labels)-n:], "."))
}

// wildcardAt is the wildcard name directly below an encloser.
func wildcardAt(encloser string) string {
	if encloser == "." {
		return "*."
	}
	return "*." + dns.Fqdn(encloser)
}
