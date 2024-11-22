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

	//	if port != 0 {
	//		e := new(dns.SVCBPort)
	//		e.Port = port
	//		svcb.Value = append(svcb.Value, e)
	//	}

	//	for k, v := range params {
	//		switch k {
	//		case "ipv4hint", "ipv6hint":
	//			var e string
	//			if k == "ipv4hint" {
	//				e = new(dns.SVCBIPv4Hint)
	//			} else if k == "ipv6hint" {
	//				e = new(dns.SVCBIPv6Hint)
	//			}
	//			ip := net.ParseIP(v)
	//			e.Hint = []net.IP{ip}
	//			svcb.Value = append(svcb.Value, e)
	//		}
	//	}

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
	anti_svcb_rr, err := dns.NewRR(fmt.Sprintf("%s 0 IN SVCB 1 0 %s", name, name))
	if err != nil {
		return err
	}
	anti_svcb_rr.Header().Class = dns.ClassANY // XXX: dns.NewRR fails to parse a CLASS ANY SVCB RRset, so we set the class manually.

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
