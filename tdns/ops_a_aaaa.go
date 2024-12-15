/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishAddrRR(name, addr string) error {
	if _, valid := dns.IsDomainName(name); !valid {
		return fmt.Errorf("invalid domain name: %s (must be a FQDN)", name)
	}
	var rr dns.RR

	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() != nil {
			rr = &dns.A{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    120,
				},
				A: ip,
			}
		} else {
			rr = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    120,
				},
				AAAA: ip,
			}
		}
	} else {
		return fmt.Errorf("invalid IP address: %s", addr)
	}

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{rr},
		InternalUpdate: true,
	}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout while sending update request")
	}

	return nil
}

func (zd *ZoneData) UnpublishAddrRR(name, addr string) error {
	if _, valid := dns.IsDomainName(name); !valid {
		return fmt.Errorf("invalid domain name: %s (must be a FQDN)", name)
	}
	var rr dns.RR

	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() != nil {
			rr = &dns.A{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassANY,
					Ttl:    0,
				},
				A: ip,
			}
		} else {
			rr = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassANY,
					Ttl:    0,
				},
				AAAA: ip,
			}
		}
	} else {
		return fmt.Errorf("invalid IP address: %s", addr)
	}

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{rr},
		InternalUpdate: true,
	}

	return nil
}
