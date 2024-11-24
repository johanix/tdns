/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishAddrRR(name, addr string) error {
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

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{rr},
		InternalUpdate: true,
	}

	return nil
}

func (zd *ZoneData) UnpublishAddrRR(name, addr string) error {
	var rr dns.RR
	var err error

	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() != nil {
			rr, err = dns.NewRR(fmt.Sprintf("%s 0 ANY A 0", name))
		} else {
			rr, err = dns.NewRR(fmt.Sprintf("%s 0 ANY AAAA 0", name))
		}
		if err != nil {
			return err
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
