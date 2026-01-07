/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"
	"strings"
	"time"

	core "github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishSvcbRR(name string, port uint16, value []dns.SVCBKeyValue) error {
	if Globals.Debug {
		log.Printf("PublishSvcbRR: received request to publish SVCB record for %q, port: %d, value: %+v", name, port, value)
	}
	name = dns.Fqdn(name)
	if _, valid := dns.IsDomainName(name); !valid {
		return fmt.Errorf("invalid domain name: %q (must be a FQDN)", name)
	}

	if !strings.HasSuffix(name, zd.ZoneName) {
		return fmt.Errorf("PublishSvcbRR: name %q is not a subdomain of %q", name, zd.ZoneName)
	}

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishSvcbRR: KeyDB.UpdateQ is nil")
	}

	if Globals.Debug {
		log.Printf("PublishSvcbRR: DEBUG: name: %q, port: %d, value: %+v", name, port, value)
	}

	svcb := dns.SVCB{
		Priority: 1,
		Target:   dns.Fqdn(name),
		Value:    value,
	}
	svcb.Hdr = dns.RR_Header{
		Name:   name,
		Rrtype: dns.TypeSVCB,
		Class:  dns.ClassINET,
		Ttl:    120,
	}

	log.Printf("PublishSvcbRR: publishing SVCB RR: %s", svcb.String())

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishSVCBRR: KeyDB.UpdateQ is nil")
	}

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&svcb},
		InternalUpdate: true,
	}:
		// Successfully sent to the channel
	case <-time.After(5 * time.Second):
		return fmt.Errorf("PublishSVCBRR: timed out while sending update request")
	}

	return nil
}

func (zd *ZoneData) UnpublishSvcbRR(name string) error {
	name = dns.Fqdn(name)
	if _, valid := dns.IsDomainName(name); !valid {
		return fmt.Errorf("invalid domain name: %s (must be a FQDN)", name)
	}

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("UnpublishSvcbRR: KeyDB.UpdateQ is nil")
	}

	anti_svcb_rr := &dns.SVCB{
		Priority: 1,
		Target:   dns.Fqdn(name),
	}
	anti_svcb_rr.Hdr = dns.RR_Header{
		Name:   name,
		Rrtype: dns.TypeSVCB,
		Class:  dns.ClassANY,
		Ttl:    0,
	}

	select {
	case zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{anti_svcb_rr},
		InternalUpdate: true,
	}:
		// Successfully sent to the channel
	case <-time.After(5 * time.Second):
		return fmt.Errorf("UnpublishSvcbRR: timed out while sending update request")
	}

	return nil
}

func LookupSVCB(name string) (*core.RRset, error) {
	return RecursiveDNSQueryWithConfig(dns.Fqdn(name), dns.TypeSVCB, 3*time.Second, 3)
}
