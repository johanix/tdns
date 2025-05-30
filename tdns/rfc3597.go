/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func ParentZone(z, imr string) (string, error) {
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

func (zd *ZoneData) FetchParentData() error {
	var err error

	if zd.Parent == "" {
		SetupIMR()
		zd.Logger.Printf("Identifying name of parent zone for %s", zd.ZoneName)
		zd.Parent, err = ParentZone(zd.ZoneName, Globals.IMR)
		if err != nil {
			return err
		}
	}

	if len(zd.ParentNS) == 0 {
		zd.Logger.Printf("Fetching NS RRset for %s", zd.Parent)
		m := new(dns.Msg)
		m.SetQuestion(zd.Parent, dns.TypeNS)

		r, err := dns.Exchange(m, Globals.IMR)
		if err != nil {
			return err
		}
		if r != nil {
			if len(r.Answer) > 0 {
				for _, rr := range r.Answer {
					if rr.Header().Rrtype == dns.TypeNS && rr.Header().Name == zd.Parent {
						zd.ParentNS = append(zd.ParentNS, rr.(*dns.NS).Ns)
					}
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
