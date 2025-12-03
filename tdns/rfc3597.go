/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func xxxParentZone(z, imr string) (string, error) {
	labels := strings.Split(z, ".")
	var parent string

	if len(labels) == 1 {
		return z, nil
	} else if len(labels) > 1 {
		upone := dns.Fqdn(strings.Join(labels[1:], "."))

		m := new(dns.Msg)
		m.SetQuestion(upone, dns.TypeSOA)
		m.SetEdns0(4096, true)
		m.CheckingDisabled = true

		r, err := dns.Exchange(m, imr)
		if err != nil {
			// return fmt.Sprintf("Error from dns.Exchange: %v\n", err)
			return "", err
		}
		if r != nil {
			if len(r.Answer) != 0 {
				parent = r.Answer[0].Header().Name
				return parent, nil
			}
			if len(r.Ns) > 0 {
				for _, rr := range r.Ns {
					if rr.Header().Rrtype == dns.TypeSOA {
						parent = r.Ns[0].Header().Name
						return parent, nil
					}
				}
			}

			log.Printf("ParentZone: ERROR: Failed to locate parent of '%s' via Answer and Authority. Now guessing.", z)
			return upone, fmt.Errorf("failed to located parent of '%s' via Answer and Authority", z)
		}
	}
	log.Printf("ParentZone: had difficulties splitting zone '%s'\n", z)
	return z, fmt.Errorf("failed to split zone name '%s' into labels", z)
}

func (imr *Imr) ParentZone(z string) (string, error) {
	labels := strings.Split(z, ".")
	var parent string

	if len(labels) == 1 {
		return z, nil
	} else if len(labels) > 1 {
		upone := dns.Fqdn(strings.Join(labels[1:], "."))

		// Query for SOA at the potential parent zone name using ImrQuery
		ctx := context.Background()
		resp, err := imr.ImrQuery(ctx, upone, dns.TypeSOA, dns.ClassINET, nil)
		if err != nil {
			return "", err
		}

		// If we got an answer with SOA in Answer section, use that zone name
		if resp.RRset != nil && len(resp.RRset.RRs) > 0 {
			// Check if this is actually a SOA record
			for _, rr := range resp.RRset.RRs {
				if soa, ok := rr.(*dns.SOA); ok {
					parent = soa.Header().Name
					return parent, nil
				}
			}
			// If we got an answer but no SOA, the response is broken
			log.Printf("ParentZone: ERROR: Received answer for '%s' SOA query but no SOA record found. Response is broken.", upone)
			return "", fmt.Errorf("received answer for '%s' SOA query but no SOA record found", upone)
		}

		// If Answer is empty, this is a negative response
		// Check the cache for negative response data - extract SOA from NegAuthority
		// When a negative response is cached, the SOA RRset is stored in NegAuthority,
		// and the SOA owner name is the authoritative zone (the parent)
		if imr.Cache == nil {
			return "", fmt.Errorf("imr.Cache is nil")
		}
		cached := imr.Cache.Get(upone, dns.TypeSOA)
		if cached != nil && len(cached.NegAuthority) > 0 {
			// Look for SOA RRset in NegAuthority
			for _, negRRset := range cached.NegAuthority {
				if negRRset != nil && negRRset.RRtype == dns.TypeSOA && len(negRRset.RRs) > 0 {
					// Found SOA in negative authority
					for _, rr := range negRRset.RRs {
						if soa, ok := rr.(*dns.SOA); ok {
							parent = soa.Header().Name
							return parent, nil
						}
					}
					// Use the RRset name if SOA type assertion fails
					if negRRset.Name != "" {
						parent = negRRset.Name
						return parent, nil
					}
				}
			}
		}

		log.Printf("ParentZone: ERROR: Failed to locate parent of '%s' via Answer and Authority. Now guessing.", z)
		return upone, fmt.Errorf("failed to locate parent of '%s' via Answer and Authority", z)
	}
	log.Printf("ParentZone: had difficulties splitting zone '%s'\n", z)
	return z, fmt.Errorf("failed to split zone name '%s' into labels", z)
}

func (zd *ZoneData) FetchParentData(imr *Imr) error {
	var err error

	if zd.Parent == "" {
		// SetupIMR()
		zd.Logger.Printf("Identifying name of parent zone for %s", zd.ZoneName)
		zd.Parent, err = imr.ParentZone(zd.ZoneName)
		if err != nil {
			return err
		}
	}

	if len(zd.ParentNS) == 0 {
		zd.Logger.Printf("Fetching NS RRset for %s", zd.Parent)
		// m := new(dns.Msg)
		//m.SetQuestion(zd.Parent, dns.TypeNS)

		ctx := context.Background()
		resp, err := imr.ImrQuery(ctx, zd.Parent, dns.TypeNS, dns.ClassINET, nil)
		if err != nil {
			return err
		}
		if resp.RRset != nil && len(resp.RRset.RRs) > 0 {
			for _, rr := range resp.RRset.RRs {
				if ns, ok := rr.(*dns.NS); ok {
					zd.ParentNS = append(zd.ParentNS, ns.Ns)
				}
			}
		}
	}

	if len(zd.ParentServers) == 0 {
		zd.Logger.Printf("Identifying all IP addresses for parent zone %s nameservers", zd.Parent)
		for _, ns := range zd.ParentNS {
			for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				m := new(dns.Msg)
				m.SetQuestion(ns, rrtype)

				r, err := dns.Exchange(m, Globals.IMR)
				if err != nil {
					return err
				}
				if r != nil {
					if len(r.Answer) > 0 {
						for _, rr := range r.Answer {
							if rr.Header().Name == ns {
								switch rr := rr.(type) {
								case *dns.A:
									zd.ParentServers = append(zd.ParentServers, net.JoinHostPort(rr.A.String(), "53"))
								case *dns.AAAA:
									zd.ParentServers = append(zd.ParentServers, net.JoinHostPort(rr.AAAA.String(), "53"))
								default:
									return fmt.Errorf("unexpected RRtype: %s (should be %s)",
										dns.TypeToString[rr.Header().Rrtype],
										dns.TypeToString[rrtype])
								}
							}
						}
					}
				}
			}
		}
	}

	zd.Logger.Printf("FetchParentData for parent %s: all done", zd.Parent)
	return nil
}
