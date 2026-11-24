/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func (zd *ZoneData) FetchParentData(imr *Imr) error {
	parent, err := zd.ResolveParentVia(imr)
	if err != nil {
		return err
	}

	if len(zd.ParentNS) == 0 {
		zd.Logger.Printf("Fetching NS RRset for %s", parent)
		// m := new(dns.Msg)
		//m.SetQuestion(zd.Parent, dns.TypeNS)

		ctx := context.Background()
		resp, err := imr.ImrQuery(ctx, parent, dns.TypeNS, dns.ClassINET, nil)
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
		zd.Logger.Printf("Identifying all IP addresses for parent zone %s nameservers", parent)
		ctx := context.Background()
		for _, ns := range zd.ParentNS {
			for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				resp, err := imr.ImrQuery(ctx, ns, rrtype, dns.ClassINET, nil)
				if err != nil {
					return err
				}
				if resp != nil && resp.RRset != nil && len(resp.RRset.RRs) > 0 {
					for _, rr := range resp.RRset.RRs {
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

	zd.Logger.Printf("FetchParentData for parent %s: all done", parent)
	return nil
}
