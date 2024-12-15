/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishSvcbRR(name string, port uint16, value []dns.SVCBKeyValue) error {
	name = dns.Fqdn(name)
	if _, valid := dns.IsDomainName(name); !valid {
		return fmt.Errorf("invalid domain name: %s (must be a FQDN)", name)
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

	log.Printf("PublishSVCBRR: publishing SVCB RR: %s", svcb.String())

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishSVCBRR: KeyDB.UpdateQ is nil")
	}

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&svcb},
		InternalUpdate: true,
	}

	return nil
}

func (zd *ZoneData) UnpublishSvcbRR(name string) error {
	name = dns.Fqdn(name)
	if _, valid := dns.IsDomainName(name); !valid {
		return fmt.Errorf("invalid domain name: %s (must be a FQDN)", name)
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

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{anti_svcb_rr},
		InternalUpdate: true,
	}

	return nil
}

func LookupSVCB(name string) (*RRset, error) {
	clientConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to load DNS client configuration: %v", err)
	}
	if len(clientConfig.Servers) == 0 {
		return nil, fmt.Errorf("no DNS servers found in client configuration")
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeSVCB)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, clientConfig.Servers[0]+":53")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup %s SVCB record: %v", name, err)
	}
	if len(r.Answer) == 0 {
		return nil, fmt.Errorf("no %s SVCB records found", name)
	}

	// var svcbRecords []*dns.SVCB
	var rrset RRset
	for _, ans := range r.Answer {
		if svcb, ok := ans.(*dns.SVCB); ok {
			rrset.RRs = append(rrset.RRs, svcb)
			continue
		}
		if rrsig, ok := ans.(*dns.RRSIG); ok {
			if rrsig.TypeCovered == dns.TypeSVCB {
				rrset.RRSIGs = append(rrset.RRSIGs, rrsig)
			}
			continue
		}
	}
	return &rrset, nil
}
