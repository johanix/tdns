/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"fmt"
	"log"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// var Sidecars = cmap.New[*Sidecar]()

// Returns true if the sidecar is new (not previously known)
func (ss *Sidecars) LocateSidecar(identity string, method tdns.MsignerMethod) (bool, *Sidecar, error) {
	log.Printf("LocateSidecar: identity: %s, method: %s", identity, tdns.MsignerMethodToString[method])

	newSidecar := false
	sidecar, ok := ss.S.Get(identity)
	if !ok {
		sidecar = &Sidecar{Identity: identity, Details: map[tdns.MsignerMethod]SidecarDetails{}}
		ss.S.Set(identity, sidecar)
		newSidecar = true
	}

	if !newSidecar && sidecar.Details[method].LastUpdate.After(time.Now().Add(-1*time.Hour)) {
		log.Printf("LocateSidecar: Sidecar %s method %s was updated less than an hour ago, not updating again", identity, tdns.MsignerMethodToString[method])
		return false, sidecar, nil
	}

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
		if tdns.Globals.Debug {
			log.Printf("SVCB record found for %s: %s", svcbName, r.Answer[0].String())
		}
		return r.Answer[0].(*dns.SVCB), nil
	}

	tmp := sidecar.Details[method]
	switch method {
	case tdns.MsignerMethodDNS:
		svcbRR, err := lookupSVCB("dns", identity)
		if err != nil {
			return false, nil, err
		}
		for _, kv := range svcbRR.Value {
			switch kv.Key() {
			case dns.SVCB_IPV4HINT:
				ipv4Hints := kv.(*dns.SVCBIPv4Hint)
				for _, ip := range ipv4Hints.Hint {
					tmp.Addrs = append(tmp.Addrs, ip.String())
				}
			case dns.SVCB_IPV6HINT:
				ipv6Hints := kv.(*dns.SVCBIPv6Hint)
				for _, ip := range ipv6Hints.Hint {
					tmp.Addrs = append(tmp.Addrs, ip.String())
				}
			case dns.SVCB_PORT:
				port := kv.(*dns.SVCBPort)
				tmp.Port = uint16(port.Port)
			}
		}

		// Look up "dns.{identity}" KEY to get the public SIG(0) key
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("dns."+identity), dns.TypeKEY)
		r, _, err := c.Exchange(m, resolverAddress)
		if err != nil || len(r.Answer) == 0 {
			return false, nil, fmt.Errorf("failed to lookup KEY record for %s: %v", "dns."+identity, err)
		}

		for _, ans := range r.Answer {
			if k, ok := ans.(*dns.KEY); ok {
				tmp.KeyRR = k
				break
			}
		}
		if tmp.KeyRR == nil {
			return false, nil, fmt.Errorf("no valid KEY record found for %s", "dns."+identity)
		}
		sidecar.DnsMethod = true

	case tdns.MsignerMethodAPI:
		svcbRR, err := lookupSVCB("api", identity)
		if err != nil {
			return false, nil, err
		}
		for _, kv := range svcbRR.Value {
			switch kv.Key() {
			case dns.SVCB_IPV4HINT:
				ipv4Hints := kv.(*dns.SVCBIPv4Hint)
				for _, ip := range ipv4Hints.Hint {
					tmp.Addrs = append(tmp.Addrs, ip.String())
				}
			case dns.SVCB_IPV6HINT:
				ipv6Hints := kv.(*dns.SVCBIPv6Hint)
				for _, ip := range ipv6Hints.Hint {
					tmp.Addrs = append(tmp.Addrs, ip.String())
				}
			case dns.SVCB_PORT:
				port := kv.(*dns.SVCBPort)
				tmp.Port = uint16(port.Port)
			}
		}

		tlsaQname := fmt.Sprintf("_%d._tcp.api.%s", tmp.Port, identity)
		log.Printf("SVCB indicates port=%d, TLSA should be located at %s", tmp.Port, tlsaQname)

		// Look up "api.{identity}" TLSA to verify the cert
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(tlsaQname), dns.TypeTLSA)
		r, _, err := c.Exchange(m, resolverAddress)
		if err != nil {
			return false, nil, fmt.Errorf("failed to lookup TLSA record for %s: %v", tlsaQname, err)
		}
		if len(r.Answer) == 0 {
			return false, nil, fmt.Errorf("no TLSA record found for %s", tlsaQname)
		}

		for _, ans := range r.Answer {
			if t, ok := ans.(*dns.TLSA); ok {
				tmp.TlsaRR = t
				break
			}
		}
		if tmp.TlsaRR == nil {
			return false, nil, fmt.Errorf("no valid TLSA record found for %s", tlsaQname)
		}

		// Look up "api.{identity}" URI record
		m = new(dns.Msg)
		m.SetQuestion(dns.Fqdn("api."+identity), dns.TypeURI)
		r, _, err = c.Exchange(m, resolverAddress)
		if err != nil {
			return false, nil, fmt.Errorf("failed to lookup URI record for %s: %v", "api."+identity, err)
		}
		if len(r.Answer) == 0 {
			return false, nil, fmt.Errorf("no URI record found for %s", "api."+identity)
		}

		for _, ans := range r.Answer {
			if u, ok := ans.(*dns.URI); ok {
				tmp.UriRR = u
				break
			}
		}
		if tmp.UriRR == nil {
			return false, nil, fmt.Errorf("no valid URI record found for %s", "api."+identity)
		}
		tmp.BaseUri = strings.Replace(tmp.UriRR.Target, "{TARGET}", identity, 1)
		tmp.BaseUri = strings.Replace(tmp.BaseUri, "{PORT}", fmt.Sprintf("%d", tmp.Port), 1)
		sidecar.ApiMethod = true

	default:
		return false, nil, fmt.Errorf("unknown Sidecar sync method: %+v", method)
	}

	tmp.LastUpdate = time.Now()
	sidecar.Details[method] = tmp

	return newSidecar, sidecar, nil
}

func (ss *Sidecars) IdentifySidecars(zonename string) ([]dns.RR, []*Sidecar, error) {
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
			new, sidecar, err := ss.LocateSidecar(msigner.Target, msigner.Method)
			if err != nil {
				log.Printf("Warning: failed to locate sidecar %s: %v", msigner.Target, err)
				sidecar = nil
				ss.S.Remove(msigner.Target)
				continue
			}
			if new {
				log.Printf("New sidecar %s discovered", msigner.Target)
			}
			sidecars = append(sidecars, sidecar)
		}
	}

	if len(ss.S.Keys()) == 0 {
		return nil, nil, fmt.Errorf("no valid sidecars found for %s", zonename)
	} else {
		log.Printf("Found %d sidecars for %s", len(ss.S.Keys()), zonename)
	}

	return msigners, sidecars, nil
}
