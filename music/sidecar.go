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

func SidecarToString(sidecar *Sidecar) string {
	return fmt.Sprintf("* Sidecar %s (API: %v, DNS: %v): last HB %s", sidecar.Identity,
		sidecar.Methods["API"], sidecar.Methods["DNS"], sidecar.Details[tdns.MsignerMethodDNS].LastHB.Format(time.RFC3339))
}

// Returns true if the sidecar is new (not previously known)
func (ss *Sidecars) LocateSidecar(identity string, method tdns.MsignerMethod) (bool, *Sidecar, error) {
	log.Printf("LocateSidecar: identity: %s, method: %s", identity, tdns.MsignerMethodToString[method])

	var knownSidecars string
	for _, sidecar := range ss.S.Items() {
		knownSidecars += SidecarToString(sidecar) + "\n"
	}
	log.Printf("LocateSidecar: known sidecars:\n%v", knownSidecars)

	newSidecar := false
	sidecar, ok := ss.S.Get(identity)
	if !ok {
		log.Printf("LocateSidecar: Sidecar %s not found, creating new", identity)
		sidecar = &Sidecar{
			Identity: identity,
			Details:  map[tdns.MsignerMethod]SidecarDetails{},
			Methods:  map[string]bool{},
		}
		ss.S.Set(identity, sidecar)
		newSidecar = true
	}

	knownSidecars = ""
	for _, sidecar := range ss.S.Items() {
		knownSidecars += SidecarToString(sidecar) + "\n"
	}
	log.Printf("LocateSidecar: known sidecars (post check):\n%v", knownSidecars)

	if !newSidecar && sidecar.Details[method].LastHB.After(time.Now().Add(-1*time.Hour)) {
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

	details := sidecar.Details[method]
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
					details.Addrs = append(details.Addrs, ip.String())
				}
			case dns.SVCB_IPV6HINT:
				ipv6Hints := kv.(*dns.SVCBIPv6Hint)
				for _, ip := range ipv6Hints.Hint {
					details.Addrs = append(details.Addrs, ip.String())
				}
			case dns.SVCB_PORT:
				port := kv.(*dns.SVCBPort)
				details.Port = uint16(port.Port)
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
				details.KeyRR = k
				break
			}
		}
		if details.KeyRR == nil {
			return false, nil, fmt.Errorf("no valid KEY record found for %s", "dns."+identity)
		}
		sidecar.Methods["DNS"] = true
		details.LastHB = time.Now()
		sidecar.Details[method] = details

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
					details.Addrs = append(details.Addrs, ip.String())
				}
			case dns.SVCB_IPV6HINT:
				ipv6Hints := kv.(*dns.SVCBIPv6Hint)
				for _, ip := range ipv6Hints.Hint {
					details.Addrs = append(details.Addrs, ip.String())
				}
			case dns.SVCB_PORT:
				port := kv.(*dns.SVCBPort)
				details.Port = uint16(port.Port)
			}
		}

		tlsaQname := fmt.Sprintf("_%d._tcp.api.%s", details.Port, identity)
		log.Printf("SVCB indicates port=%d, TLSA should be located at %s", details.Port, tlsaQname)

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
				details.TlsaRR = t
				break
			}
		}
		if details.TlsaRR == nil {
			return false, nil, fmt.Errorf("no valid TLSA record found for %s", tlsaQname)
		}

		log.Printf("TLSA record found for %s: %s", tlsaQname, details.TlsaRR.String())
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
				details.UriRR = u
				break
			}
		}
		if details.UriRR == nil {
			return false, nil, fmt.Errorf("no valid URI record found for %s", "api."+identity)
		}

		log.Printf("URI record found for %s: %s", "api."+identity, details.UriRR.String())
		details.BaseUri = strings.Replace(details.UriRR.Target, "{TARGET}", identity, 1)
		details.BaseUri = strings.Replace(details.BaseUri, "{PORT}", fmt.Sprintf("%d", details.Port), 1)
		details.BaseUri = strings.TrimSuffix(details.BaseUri, "/")
		log.Printf("BaseUri: %s", details.BaseUri)
		sidecar.Methods["API"] = true
		details.LastHB = time.Now()
		sidecar.Details[method] = details
		err = sidecar.NewMusicSyncApiClient(identity, details.BaseUri, "", "", "tlsa")
		if err != nil {
			return false, nil, fmt.Errorf("failed to create MUSIC API client for %s: %v", identity, err)
		}

	default:
		return false, nil, fmt.Errorf("unknown Sidecar sync method: %+v", method)
	}

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
