/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type Agent struct {
	Identity string
	Details  map[string]AgentDetails // "dns" or "https"
	Methods  map[string]bool
	Api      *ApiClient
}

type AgentDetails struct {
	Addrs   []string
	Port    uint16
	BaseUri string
	UriRR   *dns.URI
	KeyRR   *dns.KEY  // for DNS transport
	TlsaRR  *dns.TLSA // for HTTPS transport
	LastHB  time.Time
}

func (a *Agents) LocateAgent(identity string) (bool, *Agent, error) {
	log.Printf("LocateAgent: looking up agent %s", identity)

	// Check if we already know this agent
	agent, exists := a.S.Get(identity)
	if exists && agent.Details["dns"].LastHB.After(time.Now().Add(-1*time.Hour)) {
		log.Printf("LocateAgent: agent %s already known and recent", identity)
		return false, agent, nil
	}

	if !exists {
		agent = &Agent{
			Identity: identity,
			Details:  map[string]AgentDetails{},
			Methods:  map[string]bool{},
		}
		a.S.Set(identity, agent)
	}

	resolverAddress := viper.GetString("resolver.address")
	c := new(dns.Client)

	// Look up URIs for both transports
	for _, transport := range []string{"dns", "https"} {
		svcname := fmt.Sprintf("_%s._tcp.%s", transport, identity)
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(svcname), dns.TypeURI)
		r, _, err := c.Exchange(m, resolverAddress)
		if err != nil || len(r.Answer) == 0 {
			continue // this transport not available
		}

		var uri *dns.URI
		for _, ans := range r.Answer {
			if u, ok := ans.(*dns.URI); ok {
				uri = u
				break
			}
		}
		if uri == nil {
			continue
		}

		details := agent.Details[transport]
		details.UriRR = uri

		// Get the target name from the URI
		targetName := strings.TrimSuffix(uri.Target, ".")

		// Look up SVCB for the target
		m = new(dns.Msg)
		m.SetQuestion(dns.Fqdn(targetName), dns.TypeSVCB)
		r, _, err = c.Exchange(m, resolverAddress)
		if err != nil || len(r.Answer) == 0 {
			continue
		}

		svcb := r.Answer[0].(*dns.SVCB)
		for _, kv := range svcb.Value {
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

		// Look up either KEY (DNS) or TLSA (HTTPS)
		if transport == "dns" {
			m = new(dns.Msg)
			m.SetQuestion(dns.Fqdn(targetName), dns.TypeKEY)
			r, _, err = c.Exchange(m, resolverAddress)
			if err == nil && len(r.Answer) > 0 {
				for _, ans := range r.Answer {
					if k, ok := ans.(*dns.KEY); ok {
						details.KeyRR = k
						break
					}
				}
			}
		} else {
			tlsaName := fmt.Sprintf("_%d._tcp.%s", details.Port, targetName)
			m = new(dns.Msg)
			m.SetQuestion(dns.Fqdn(tlsaName), dns.TypeTLSA)
			r, _, err = c.Exchange(m, resolverAddress)
			if err == nil && len(r.Answer) > 0 {
				for _, ans := range r.Answer {
					if t, ok := ans.(*dns.TLSA); ok {
						details.TlsaRR = t
						break
					}
				}
			}
		}

		if (transport == "dns" && details.KeyRR != nil) ||
			(transport == "https" && details.TlsaRR != nil) {
			details.LastHB = time.Now()
			details.BaseUri = strings.Replace(uri.Target, "{PORT}", fmt.Sprintf("%d", details.Port), 1)
			details.BaseUri = strings.TrimSuffix(details.BaseUri, "/")
			agent.Methods[transport] = true
			agent.Details[transport] = details
		}
	}

	if !agent.Methods["dns"] && !agent.Methods["https"] {
		a.S.Remove(identity)
		return false, nil, fmt.Errorf("no valid transport found for agent %s", identity)
	}

	return true, agent, nil
}

// CleanCopy returns a copy of the Agent without any sensitive data
func (a *Agent) CleanCopy() *Agent {
	return &Agent{
		Identity: a.Identity,
		Methods:  a.Methods,
		Details: map[string]AgentDetails{
			"dns": {
				Addrs:   a.Details["dns"].Addrs,
				Port:    a.Details["dns"].Port,
				BaseUri: a.Details["dns"].BaseUri,
				LastHB:  a.Details["dns"].LastHB,
			},
			"https": {
				Addrs:   a.Details["https"].Addrs,
				Port:    a.Details["https"].Port,
				BaseUri: a.Details["https"].BaseUri,
				LastHB:  a.Details["https"].LastHB,
			},
		},
	}
}

// IdentifyAgents looks for HSYNC records in a zone and identifies agents we need to sync with
func (a *Agents) IdentifyAgents(zd *ZoneData, ourIdentity string) ([]*Agent, error) {
	var agents []*Agent

	rrset, err := zd.GetRRset(zd.ZoneName, TypeHSYNC)
	if err != nil {
		return nil, fmt.Errorf("error getting HSYNC records: %v", err)
	}

	// Look for HSYNC records where Target is NOT our identity
	for _, rr := range rrset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				if hsync.Target == ourIdentity {
					continue
				}
				// Found another agent, try to locate it
				new, agent, err := a.LocateAgent(hsync.Target)
				if err != nil {
					log.Printf("Warning: failed to locate agent %s: %v", hsync.Target, err)
					continue
				}
				if new {
					agents = append(agents, agent)
				}
			}
		}
	}

	return agents, nil
}

func AgentToString(a *Agent) string {
	if a == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s", a.Identity)
}
