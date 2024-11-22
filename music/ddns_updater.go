/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type DdnsUpdater struct {
}

func init() {
	Updaters["ddns"] = &DdnsUpdater{}
}

func (u *DdnsUpdater) SetChannels(fetch, update chan SignerOp) {
	// no-op
}

func (u *DdnsUpdater) SetApi(api Api) {
	// no-op
}

func (u *DdnsUpdater) GetApi() Api {
	// no-op
	return Api{}
}

func (signer *Signer) NewDnsClient() dns.Client {
	var c dns.Client
	if signer.UseTcp {
		c = dns.Client{Net: "tcp"}
	} else {
		log.Printf("DDNS: Accessing signer %s via UDP. This is a debugging mechanism only",
			signer.Name)
		c = dns.Client{Net: "udp"}
	}
	return c
}

func (signer *Signer) PrepareTSIGExchange(c *dns.Client, m *dns.Msg) error {
	if signer.UseTSIG {
		m.SetTsig(signer.Auth.TSIGName, signer.Auth.TSIGAlg, 300, time.Now().Unix())
		c.TsigSecret = map[string]string{signer.Auth.TSIGName: signer.Auth.TSIGKey}
		// log.Printf("DDNS: FetchRRset: TsigSecret: %v", c.TsigSecret)
	} else {
		log.Printf("PrepareTSIGExchange: accessing signer %s without TSIG. This is a debugging mechanism only", signer.Name)
	}
	return nil
}

func (u *DdnsUpdater) Update(signer *Signer, zone, fqdn string,
	inserts, removes *[][]dns.RR) error {
	inserts_len := 0
	removes_len := 0
	if inserts != nil {
		for _, insert := range *inserts {
			inserts_len += len(insert)
		}
	}
	if removes != nil {
		for _, remove := range *removes {
			removes_len += len(remove)
		}
	}
	if viper.GetString("log.ddns") == "debug" {
		log.Printf("DDNS Updater: signer: %s, zone: %s, fqdn: %s inserts: %d removes: %d\n",
			signer.Name, zone, fqdn, inserts_len, removes_len)
	}
	if inserts_len == 0 && removes_len == 0 {
		return fmt.Errorf("Inserts and removes empty, nothing to do")
	}

	if signer.Address == "" {
		return fmt.Errorf("No ip|host for signer %s", signer.Name)
	}
	if signer.Auth.TSIGKey == "" {
		return fmt.Errorf("No TSIG for signer %s", signer.Name)
	}

	c := signer.NewDnsClient()
	m := new(dns.Msg)
	m.SetUpdate(fqdn)
	if inserts != nil {
		for _, insert := range *inserts {
			m.Insert(insert)
		}
	}
	if removes != nil {
		for _, remove := range *removes {
			m.Remove(remove)
		}
	}

	signer.PrepareTSIGExchange(&c, m)

	in, _, err := c.Exchange(m, signer.Address+":"+signer.Port) // TODO: add DnsAddress or solve this in a better way
	if err != nil {
		if viper.GetString("log.ddns") == "debug" {
			log.Printf("Update msg that caused error:\n%v\n", m.String())
		}
		return err
	}
	if in.MsgHdr.Rcode != dns.RcodeSuccess {
		if viper.GetString("log.ddns") == "debug" {
			log.Printf("Update msg that caused error:\n%v\n", m.String())
			log.Printf("Response:\n%v\n", in.String())
		}
		return fmt.Errorf("Update failed, RCODE = %s", dns.RcodeToString[in.MsgHdr.Rcode])
	}

	return nil
}

func (u *DdnsUpdater) RemoveRRset(signer *Signer, zone, fqdn string, rrsets [][]dns.RR) error {
	rrsets_len := 0
	for _, rrset := range rrsets {
		rrsets_len += len(rrset)
	}
	if rrsets_len == 0 {
		return fmt.Errorf("rrset(s) is empty, nothing to do")
	}

	if signer.Address == "" {
		return fmt.Errorf("No ip|host for signer %s", signer.Name)
	}
	if signer.Auth.TSIGKey == "" {
		return fmt.Errorf("No TSIG for signer %s", signer.Name)
	}

	c := signer.NewDnsClient()
	m := new(dns.Msg)
	m.SetUpdate(fqdn)
	for _, rrset := range rrsets {
		m.RemoveRRset(rrset)
	}

	signer.PrepareTSIGExchange(&c, m)

	in, _, err := c.Exchange(m, signer.Address+":"+signer.Port) // TODO: add DnsAddress or solve this in a better way
	if err != nil {
		return err
	}
	if in.MsgHdr.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Update failed, RCODE = %s", dns.RcodeToString[in.MsgHdr.Rcode])
	}

	return nil
}

func (u *DdnsUpdater) FetchRRset(signer *Signer, zone, fqdn string,
	rrtype uint16) (error, []dns.RR) {
	log.Printf("DDNS: FetchRRset: signer: %s zone: %s fqdn: %s rrtype: %s", signer.Name, zone, fqdn, dns.TypeToString[rrtype])
	if signer.Address == "" {
		return fmt.Errorf("No ip|host for signer %s", signer.Name), []dns.RR{}
	}
	if signer.Auth.TSIGKey == "" {
		return fmt.Errorf("No TSIG for signer %s", signer.Name), []dns.RR{}
	}

	c := signer.NewDnsClient()
	m := new(dns.Msg)
	m.SetQuestion(fqdn, rrtype)
	// m.SetEdns0(4096, true)

	signer.PrepareTSIGExchange(&c, m)

	r, _, err := c.Exchange(m, signer.Address+":"+signer.Port) // TODO: add DnsAddress or solve this in a better way
	if err != nil {
		log.Printf("DDNS: FetchRRset: dns.Exchange error: err: %v r: %v", err, r)
		return err, []dns.RR{}
	}

	if r.MsgHdr.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Fetch of %s RRset failed, RCODE = %s", dns.TypeToString[rrtype], dns.RcodeToString[r.MsgHdr.Rcode]), []dns.RR{}
	}

	log.Printf("Length of %s answer from %s: %d RRs\n",
		dns.TypeToString[rrtype],
		signer.Name+":"+signer.Port, len(r.Answer))

	var rrs []dns.RR

	// XXX: Here we want to filter out all RRs that are of other types than the
	//      rrtype we're looking for. It would be much better to have a general
	//      check for a.(type) == rrtype, but I have not figured out how.

	for _, a := range r.Answer {
		switch dns.TypeToString[rrtype] {

		case "DNSKEY":
			rr, ok := a.(*dns.DNSKEY)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "CDS":
			rr, ok := a.(*dns.CDS)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "CDNSKEY":
			rr, ok := a.(*dns.CDNSKEY)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "NS":
			rr, ok := a.(*dns.NS)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "DS":
			rr, ok := a.(*dns.DS)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "SOA":
			rr, ok := a.(*dns.SOA)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		case "CSYNC":
			rr, ok := a.(*dns.CSYNC)
			if !ok {
				continue
			}
			rrs = append(rrs, rr)

		}
	}

	return nil, rrs
}
