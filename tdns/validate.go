/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"strings"
)

func (zd *ZoneData) LookupAndValidateRRset(qname string, qtype uint16,
	verbose bool) (*RRset, bool, error) {
	rrset, err := zd.LookupRRset(qname, qtype, verbose)
	if err != nil {
		zd.Logger.Printf("LookupAndValidateRRset: Error from LookupRRset: %v", err)
		return nil, false, err
	}

	if rrset == nil {
		zd.Logger.Printf("LookupAndValidateRRset: No RRset returned from LookupRRset(%s, %s)",
							  qname, dns.TypeToString[qtype])
		return nil, false, nil
	}

	// XXX: Add validation
	valid := true

	return rrset, valid, nil
}

func (zd *ZoneData) LookupRRset(qname string, qtype uint16, verbose bool) (*RRset, error) {
	var rrset *RRset
	var wildqname string
	origqname := qname

	// Is answer in this zone or further down?
	if !zd.NameExists(qname) {
		// Here we should do wildcard expansion like in QueryResponder()
		wildqname = "*." + strings.Join(strings.Split(qname, ".")[1:], ".")
		// log.Printf("---> Checking for existence of wildcard %s", wildqname)
		if !zd.NameExists(wildqname) {
			// no, nothing
			zd.Logger.Printf("*** No data for %s in %s", wildqname, zd.ZoneName)
			return nil, nil
		}
		origqname = qname
		qname = wildqname
		zd.Logger.Printf("*** %s is a wildcard expansion from %s",
			origqname, wildqname)
	}

	owner, err := zd.GetOwner(qname)

	if len(owner.RRtypes) == 0 {
		// No, nothing.
		zd.Logger.Printf("*** No data for %s in %s", qname, zd.ZoneName)
		return nil, nil // nothing found, but this is not an error
	}

	// Check for qname + CNAME: defer this to later.

	// Check for child delegation
	childns, v4glue, v6glue := zd.FindDelegation(qname, true)
	if childns != nil {
		zd.Logger.Printf("LRRset: found a delegation for %s in known zone %s",
			qname, zd.ZoneName)

		rrset, err = zd.LookupChildRRset(qname, qtype, v4glue, v6glue, verbose)
		if err != nil {
			zd.Logger.Printf("LookupRRset: Error from LookupChildRRset: %v", err)
		}
	}
	zd.Logger.Printf("*** %s is not a child delegation from %s", qname, zd.ZoneName)

	zd.Logger.Printf("*** owner=%s has RRtypes: ", owner.Name)
	for k, v := range owner.RRtypes {
		zd.Logger.Printf("%s: %d RRs ", dns.TypeToString[k], len(v.RRs))
	}

	// Must instantiate the rrset
	rrset = &RRset{}

	// Check for exact match qname + qtype
	if _, ok := owner.RRtypes[qtype]; ok && len(owner.RRtypes[qtype].RRs) > 0 {
		zd.Logger.Printf("*** %d RRs: %v", len(owner.RRtypes[qtype].RRs), owner.RRtypes[qtype].RRs)
		// XXX: Dont forget that we also need to deal with CNAMEs in here
		if qname == origqname {
			rrset.RRs = owner.RRtypes[qtype].RRs
			rrset.RRSIGs = owner.RRtypes[qtype].RRSIGs
		} else {
			tmp := WildcardReplace(owner.RRtypes[qtype].RRs, qname, origqname)
			rrset.RRs = tmp
			tmp = WildcardReplace(owner.RRtypes[qtype].RRSIGs, qname, origqname)
			rrset.RRSIGs = tmp
		}
	}

	for _, rr := range rrset.RRs {
		zd.Logger.Printf("%s", rr.String())
	}
	for _, rr := range rrset.RRSIGs {
		zd.Logger.Printf("%s", rr.String())
	}

	return rrset, err
}

func (zd *ZoneData) LookupChildRRset(qname string, qtype uint16,
	v4glue, v6glue *RRset, verbose bool) (*RRset, error) {

	var servers []string

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
	return rrset, err
}

func AuthDNSQuery(qname string, lg *log.Logger, nameservers []string,
	rrtype uint16, verbose bool) (*RRset, int, error) {
	var rrset RRset
	var rcode int

	// c := dns.Client{Net: "tcp"}

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
				if rcode == dns.StringToRcode["NOERROR"] {
					return &rrset, rcode, nil // no point in continuing
				}
				continue // go to next server
			}
		} else {
			continue // go to next server
		}
	}
	return &rrset, rcode, fmt.Errorf("No Answers found from any auth server looking up '%s %s'.\n",
		qname, dns.TypeToString[rrtype])
}

