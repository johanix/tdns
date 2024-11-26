/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"fmt"
	"log"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func LocateSidecar(identity string, method tdns.MsignerMethod) (*Sidecar, error) {
	log.Printf("LocateSidecar: identity: %s, method: %s", identity, tdns.MsignerMethodToString[method])
	sidecar := Sidecar{Identity: identity, Method: method}
	// var err error
	resolverAddress := viper.GetString("resolver.address")
	c := new(dns.Client)

	lookupSVCB := func(prefix, identity string) (*dns.SVCB, error) {
		svcbName := prefix + "." + identity
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(svcbName), dns.TypeSVCB)
		r, _, err := c.Exchange(m, resolverAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup SVCB record for %s: %v", svcbName, err)
		}
		if len(r.Answer) == 0 {
			return nil, fmt.Errorf("no SVCB record found for %s", svcbName)
		}
		return r.Answer[0].(*dns.SVCB), nil
	}

	switch method {
	case tdns.MsignerMethodDNS:
		svcbRR, err := lookupSVCB("dns", identity)
		if err != nil {
			return nil, err
		}
		for _, kv := range svcbRR.Value {
			switch kv.Key() {
			case dns.SVCB_IPV4HINT:
				ipv4Hints := kv.(*dns.SVCBIPv4Hint)
				//				for _, ip := range ipv4Hints.Hint {
				//					sidecar.Addresses = append(sidecar.Addresses, ip.String())
				//				}
				log.Printf("SVCB_IPV4HINT: %v", ipv4Hints)
			case dns.SVCB_IPV6HINT:
				ipv6Hints := kv.(*dns.SVCBIPv6Hint)
				for _, ip := range ipv6Hints.Hint {
					sidecar.Addresses = append(sidecar.Addresses, ip.String())
				}
			case dns.SVCB_PORT:
				port := kv.(*dns.SVCBPort)
				sidecar.Port = uint16(port.Port)
			}
		}

		// Look up "dns.{identity}" KEY to get the public SIG(0) key
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("dns."+identity), dns.TypeKEY)
		r, _, err := c.Exchange(m, resolverAddress)
		if err != nil || len(r.Answer) == 0 {
			return nil, fmt.Errorf("failed to lookup KEY record for %s: %v", "dns."+identity, err)
		}

		for _, ans := range r.Answer {
			if k, ok := ans.(*dns.KEY); ok {
				sidecar.KeyRR = k
				break
			}
		}
		if sidecar.KeyRR == nil {
			return nil, fmt.Errorf("no valid KEY record found for %s", "dns."+identity)
		}

	case tdns.MsignerMethodAPI:
		svcbRR, err := lookupSVCB("api", identity)
		if err != nil {
			return nil, err
		}
		for _, kv := range svcbRR.Value {
			switch kv.Key() {
			case dns.SVCB_IPV4HINT:
				ipv4Hints := kv.(*dns.SVCBIPv4Hint)
				for _, ip := range ipv4Hints.Hint {
					sidecar.Addresses = append(sidecar.Addresses, ip.String())
				}
			case dns.SVCB_IPV6HINT:
				ipv6Hints := kv.(*dns.SVCBIPv6Hint)
				for _, ip := range ipv6Hints.Hint {
					sidecar.Addresses = append(sidecar.Addresses, ip.String())
				}
			case dns.SVCB_PORT:
				port := kv.(*dns.SVCBPort)
				sidecar.Port = uint16(port.Port)
			}
		}

		tlsaQname := fmt.Sprintf("_%d._tcp.api.%s", sidecar.Port, identity)
		log.Printf("SVCB indicates port=%d, TLSA should be located at %s", sidecar.Port, tlsaQname)

		// Look up "api.{identity}" TLSA to verify the cert
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(tlsaQname), dns.TypeTLSA)
		r, _, err := c.Exchange(m, resolverAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup TLSA record for %s: %v", tlsaQname, err)
		}
		if len(r.Answer) == 0 {
			return nil, fmt.Errorf("no TLSA record found for %s", tlsaQname)
		}

		for _, ans := range r.Answer {
			if t, ok := ans.(*dns.TLSA); ok {
				sidecar.TlsaRR = t
				break
			}
		}
		if sidecar.TlsaRR == nil {
			return nil, fmt.Errorf("no valid TLSA record found for %s", tlsaQname)
		}

	default:
		return nil, fmt.Errorf("unknown Sidecar sync method: %+v", method)
	}

	return &sidecar, nil
}

func IdentifySidecars(zonename string) ([]dns.RR, []*Sidecar, error) {
	resolverAddress := viper.GetString("resolver.address")
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zonename), tdns.TypeMSIGNER)

	r, _, err := c.Exchange(m, resolverAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup MSIGNER RRset for %s: %v", zonename, err)
	}

	if len(r.Answer) == 0 {
		return nil, nil, fmt.Errorf("no MSIGNER records found for %s", zonename)
	}

	var msigners []dns.RR
	var sidecars []*Sidecar

	for _, ans := range r.Answer {
		if prr, ok := ans.(*dns.PrivateRR); ok {
			if prr.Header().Rrtype != tdns.TypeMSIGNER {
				continue
			}
			msigner := prr.Data.(*tdns.MSIGNER)
			msigners = append(msigners, prr)
			sidecar, err := LocateSidecar(msigner.Target, msigner.Method)
			if err != nil {
				log.Printf("Warning: failed to locate sidecar %s: %v", msigner.Target, err)
				continue
			}
			sidecars = append(sidecars, sidecar)
		}
	}

	if len(sidecars) == 0 {
		return nil, nil, fmt.Errorf("no valid sidecars found for %s", zonename)
	}

	return msigners, sidecars, nil
}
