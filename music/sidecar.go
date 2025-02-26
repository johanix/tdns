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

// var MSAs = cmap.New[*MSA]()

func MSAToString(msa *MSA) string {
	return fmt.Sprintf("* MSA %s (API: %v, DNS: %v): last HB %s", msa.Identity,
		msa.Methods["API"], msa.Methods["DNS"], msa.Details[tdns.HsyncMethodDNS].LastHB.Format(time.RFC3339))
}

// Returns true if the MSA is new (not previously known)
func (ss *MSAs) LocateMSA(identity string, method tdns.HsyncMethod) (bool, *MSA, error) {
	log.Printf("LocateMSA: identity: %s, method: %s", identity, tdns.HsyncMethodToString[method])

	var knownMSAs string
	for _, msa := range ss.S.Items() {
		knownMSAs += MSAToString(msa) + "\n"
	}
	log.Printf("LocateMSA: known MSAs:\n%v", knownMSAs)

	newMSA := false
	msa, ok := ss.S.Get(identity)
	if !ok {
		log.Printf("LocateMSA: MSA %s not found, creating new", identity)
		msa = &MSA{
			Identity: identity,
			Details:  map[tdns.HsyncMethod]MSADetails{},
			Methods:  map[string]bool{},
		}
		ss.S.Set(identity, msa)
		newMSA = true
	}

	knownMSAs = ""
	for _, msa := range ss.S.Items() {
		knownMSAs += MSAToString(msa) + "\n"
	}
	log.Printf("LocateMSA: known msas (post check):\n%v", knownMSAs)

	if !newMSA && sidecar.Details[method].LastHB.After(time.Now().Add(-1*time.Hour)) {
		log.Printf("LocateMSA: MSA %s method %s was updated less than an hour ago, not updating again", identity, tdns.HsyncMethodToString[method])
		return false, msa, nil
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

	details := msa.Details[method]
	switch method {
	case tdns.HsyncMethodDNS:
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
		msa.Methods["DNS"] = true
		details.LastHB = time.Now()
		msa.Details[method] = details

	case tdns.MSAMethodAPI:
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
		msa.Methods["API"] = true
		details.LastHB = time.Now()
		msa.Details[method] = details
		err = wMusicSyncApiClient(identity, details.BaseUri, "", "", "tlsa")
		if err != nil {
			return false, nil, fmt.Errorf("failed to create MUSIC API client for %s: %v", identity, err)
		}

	default:
		return false, nil, fmt.Errorf("unknown MSA sync method: %+v", method)
	}

	return newMSA, msa, nil
}

func (ss *MSC) IdentifyMSAs(zonename string) ([]dns.RR, []*MSA, error) {
	resolverAddress := viper.GetString("resolver.address")
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zonename), tdns.TypeHSYNC)

	r, _, err := c.Exchange(m, resolverAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup HSYNC RRset for %s: %v", zonename, err)
	}

	if len(r.Answer) == 0 {
		return nil, nil, fmt.Errorf("no HSYNC records found for %s", zonename)
	}

	var hsyncs []dns.RR
	var msas []*MSA

	for _, ans := range r.Answer {
		if prr, ok := ans.(*dns.PrivateRR); ok {
			if prr.Header().Rrtype != tdns.TypeHSYNC {
				continue
			}
			hsync := prr.Data.(*tdns.HSYNC)
			hsyncs = append(hsyncs, prr)
			new, msa, err := ss.LocateMSA(hsync.Target, hsync.Method)
			if err != nil {
				log.Printf("Warning: failed to locate MSA %s: %v", hsync.Target, err)
				msa = nil
				ss.S.Remove(hsync.Target)
				continue
			}
			if new {
				log.Printf("New MSA %s discovered", hsync.Target)
			}
			msas = append(msas, msa)
		}
	}

	if len(ss.S.Keys()) == 0 {
		return nil, nil, fmt.Errorf("no valid MSAs found for %s", zonename)
	} else {
		log.Printf("Found %d MSAs for %s", len(ss.S.Keys()), zonename)
	}

	return hsyncs, MSAs, nil
}

// CleanCopy returns a copy of the MSA with the Api.ApiClient.Client set to nil
// as that can not be marshalled to JSON.
func (s *MSA) CleanCopy() *MSA {
	log.Printf("CleanCopy: MSA %s: %+v", s.Identity, s.Details)
	c := *s             // Create a shallow copy of the MSA
	c.Api = &MusicApi{} // Create a new MusicApi instance
	c.Api = s.Api
	if s.Api != nil {
		c.Api.ApiClient = &tdns.ApiClient{} // Create a new ApiClient instance
		c.Api.ApiClient = s.Api.ApiClient
		if s.Api.ApiClient != nil {
			c.Api.ApiClient.Client = nil // Set the Client to nil
		}
	}
	c.Details = make(map[tdns.HsyncMethod]MSADetails)
	for method, details := range s.Details {
		c.Details[method] = details // Copy the details
	}
	return &c
}
