/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
        "fmt"
	"github.com/miekg/dns"
	"log"
	"net"
//	"strings"
)

// 1. Find the child NS RRset
// 2. Find the address of each NS
// 3. Query child NS for <qname, qtype>

func (zd *ZoneData) LookupChildRRset(qname string, qtype uint16, verbose bool) (*RRset, error) {
     var rrset *RRset
     var servers []string
     
     nsrrs, v4glue, v6glue := zd.FindDelegation(qname, true)
     if nsrrs == nil {
     	zd.Logger.Printf("LCRRset: did not find a delegation for %s in known zone %s",
				   qname, zd.ZoneName)
     	return nil, nil
     }
     for _, glue := range v4glue.RRs {
     	 servers = append(servers, glue.(*dns.A).A.String())
     }
     for _, glue := range v6glue.RRs {
     	 servers = append(servers, glue.(*dns.AAAA).AAAA.String())
     }

     rrset, _, err := AuthDNSQuery(qname, zd.Logger, servers, qtype, verbose)
     if err != nil {
     	zd.Logger.Printf("LCRRset: Error from AuthDNSQuery: %v", err)
     }
     zd.Logger.Printf("LCRRset: looked up %s %s (%d RRs):",
     				qname, dns.TypeToString[qtype], len(rrset.RRs))
     for _, rr := range rrset.RRs {
     	 zd.Logger.Printf("%s", rr.String())
     }
     for _, rr := range rrset.RRSIGs {
     	 zd.Logger.Printf("%s", rr.String())
     }

     return rrset, err
}

func AuthDNSQuery(qname string, lg *log.Logger, nameservers []string,
	rrtype uint16, verbose bool) (*RRset, int, error) {
	var rrset RRset
	var rcode int

//	c := dns.Client{Net: "tcp"}

	m := new(dns.Msg)
	m.SetQuestion(qname, rrtype)
	m.SetEdns0(4096, true)
	for _, ns := range nameservers {
		if ns[len(ns)-3:] != ":53" {
			ns = net.JoinHostPort(ns, "53")
		}
		if verbose {
			lg.Printf("AuthDNSQuery: using nameserver %s for <%s, %s> query\n",
				ns, qname, dns.TypeToString[rrtype])
		}
		r, err := dns.Exchange(m, ns)
		// r, _, err := c.Exchange(m, ns)
		if err != nil && verbose {
			lg.Printf("AuthDNSQuery: Error from dns.Exchange: %v", err)
			continue // go to next server
		}

		if r != nil {
			rcode = r.MsgHdr.Rcode
			if len(r.Answer) != 0 {
				// if verbose {
				//	fmt.Printf("AuthDNSQueryNG: Found %s %s RR\n",
				//		qname, dns.TypeToString[rrtype])
				// }
				for _, rr := range r.Answer {
				    switch t := rr.Header().Rrtype; t {
				    case rrtype:
					rrset.RRs = append(rrset.RRs, rr)
				    case dns.TypeRRSIG:
					rrset.RRSIGs = append(rrset.RRSIGs, rr)
				    default:
					lg.Printf("Got a %s RR when looking for %s %s",
						       dns.TypeToString[t], qname,
						       dns.TypeToString[rrtype])
				    }
				}
				return &rrset, rcode, nil
			} else {
				// log.Printf("ADNSQ: <%s,%s> Answer was empty, next server\n",
				// 		   qname, dns.TypeToString[rrtype])
				if rcode == dns.StringToRcode["NOERROR"] {
					return &rrset, rcode, nil // no point in continuing
				}
				continue // go to next server
			}
		} else {
			// log.Printf("ADNSQ: <%s,%s> dns.Msg was empty, next server\n",
			// 		      qname, dns.TypeToString[rrtype])
			continue // go to next server
		}
	}
	return &rrset, rcode, fmt.Errorf("No Answers found from any auth server looking up '%s %s'.\n",
		qname, dns.TypeToString[rrtype])
}
