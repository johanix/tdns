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

func createAddrRR(name string, addr string, ttl uint32, class uint16) (dns.RR, error) {
	if _, valid := dns.IsDomainName(name); !valid {
		return nil, fmt.Errorf("invalid domain name: %s (must be a FQDN)", name)
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", addr)
	}

	hdr := dns.RR_Header{
		Name:  name,
		Class: class,
		Ttl:   ttl,
	}

	if ip.To4() != nil {
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: ip}, nil
	}

	hdr.Rrtype = dns.TypeAAAA
	return &dns.AAAA{Hdr: hdr, AAAA: ip}, nil
}

func (zd *ZoneData) PublishAddrRR(name, addr string) error {
	rr, err := createAddrRR(name, addr, 120, dns.ClassINET)
	if err != nil {
		return err
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
	rr, err := createAddrRR(name, addr, 0, dns.ClassANY)
	if err != nil {
		return err
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
