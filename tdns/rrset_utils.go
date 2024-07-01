/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

func AuthQuery(qname, ns string, rrtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, rrtype)

	if Globals.Debug {
		// fmt.Printf("DEBUG: Query:\n%s\n", m.String())
		fmt.Printf("Sending query %s %s to nameserver \"%s\"\n", qname,
			dns.TypeToString[rrtype], ns)
	}

	res, err := dns.Exchange(m, ns)

	if err != nil {
		//	       	  log.Fatalf("AuthQuery: Error from dns.Exchange(%s, %s, %s): %v",
		//				       qname, dns.TypeToString[rrtype], ns, err)
		return []dns.RR{}, err
	}

	if res.Rcode != dns.RcodeSuccess {
		//		log.Fatalf("Error: Query for %s %s received rcode: %s",
		//			qname, dns.TypeToString[rrtype], dns.RcodeToString[res.Rcode])
		return []dns.RR{}, fmt.Errorf("Query for %s %s received rcode: %s",
			qname, dns.TypeToString[rrtype],
			dns.RcodeToString[res.Rcode])
	}

	var rrs []dns.RR

	if len(res.Answer) > 0 {
		if Globals.Debug {
			fmt.Printf("Looking up %s %s RRset:\n", qname, dns.TypeToString[rrtype])
		}
		for _, rr := range res.Answer {
			if rr.Header().Rrtype == rrtype {
				if Globals.Debug {
					fmt.Printf("%s\n", rr.String())
				}

				rrs = append(rrs, rr)

			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
			} else {
				log.Fatalf("Error: answer is not an %s RR: %s", dns.TypeToString[rrtype], rr.String())
			}
		}
		return rrs, nil
	}

	if len(res.Ns) > 0 {
		if Globals.Debug {
			fmt.Printf("Looking up %s %s RRset:\n", qname, dns.TypeToString[rrtype])
		}
		for _, rr := range res.Ns {
			if rr.Header().Rrtype == rrtype && rr.Header().Name == qname {
				if Globals.Debug {
					fmt.Printf("%s\n", rr.String())
				}

				rrs = append(rrs, rr)

			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
			} else {
				// Should not be fatal. Happens when querying parent for glue
				// log.Fatalf("Error: answer is not an %s RR: %s", dns.TypeToString[rrtype], rr.String())
			}
		}
		if len(rrs) > 0 { // found something
			return rrs, nil
		}
	}

	if len(res.Extra) > 0 {
		if Globals.Debug {
			fmt.Printf("Looking up %s %s RRset:\n", qname, dns.TypeToString[rrtype])
		}
		for _, rr := range res.Extra {
			if rr.Header().Rrtype == rrtype && rr.Header().Name == qname {
				if Globals.Debug {
					fmt.Printf("%s\n", rr.String())
				}

				rrs = append(rrs, rr)

			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
			} else {
				// Should not be fatal.
				// log.Fatalf("Error: answer is not an %s RR: %s", dns.TypeToString[rrtype], rr.String())
			}
		}
		return rrs, nil
	}

	return rrs, nil
}

func RRsetDiffer(zone string, newrrs, oldrrs []dns.RR, rrtype uint16, lg *log.Logger) (bool, []dns.RR, []dns.RR) {
	var match, rrsets_differ bool
	typestr := dns.TypeToString[rrtype]
	adds := []dns.RR{}
	removes := []dns.RR{}

	if Globals.Debug {
		lg.Printf("*** RRD: Comparing %s RRsets for %s:", typestr, zone)
		lg.Printf("-------- Old set for %s %s:", zone, typestr)
		for _, rr := range oldrrs {
			lg.Printf("%s", rr.String())
		}
		lg.Printf("-------- New set for %s %s:", zone, typestr)
		for _, rr := range newrrs {
			lg.Printf("%s", rr.String())
		}
	}
	// compare oldrrs to newrrs
	for _, orr := range oldrrs {
		if dns.TypeToString[orr.Header().Rrtype] == "RRSIG" {
			continue
		}
		match = false
		for _, nrr := range newrrs {
			if dns.IsDuplicate(orr, nrr) {
				match = true
				break
			}
		}
		// if we get here w/o match then this orr has no equal nrr
		if !match {
			rrsets_differ = true
			removes = append(removes, orr)
		}
	}

	// compare newrrs to oldrrs
	for _, nrr := range newrrs {
		if dns.TypeToString[nrr.Header().Rrtype] == "RRSIG" {
			continue
		}
		match = false
		for _, orr := range oldrrs {
			if dns.IsDuplicate(nrr, orr) {
				match = true
				break
			}
		}
		// if we get here w/o match then this nrr has no equal orr
		if !match {
			rrsets_differ = true
			adds = append(adds, nrr)
		}
	}
	if Globals.Verbose {
		lg.Printf("*** RRD: RRsetDiffer: Zone %s %s rrsets_differ: %v\n***Adds: %v\n***Removes: %v", zone, typestr, rrsets_differ, adds, removes)
	}
	return rrsets_differ, adds, removes
}

func (rrset *RRset) RemoveRR(rr dns.RR) {
	log.Printf("RemoveRR: Trying to remove '%s' from RRset %s %s", rr.String(), rrset.Name, dns.TypeToString[rr.Header().Rrtype])
	for i, r := range rrset.RRs {
		log.Printf("RemoveRR: Comparing:\n%s\n%s\n", r.String(), rr.String())
		if dns.IsDuplicate(r, rr) {
			rrset.RRs = append(rrset.RRs[:i], rrset.RRs[i+1:]...)
			rrset.RRSIGs = []dns.RR{}
			log.Printf("RemoveRR: *REMOVED* '%s' from RRset %s %s", rr.String(), rrset.Name, dns.TypeToString[rr.Header().Rrtype])
			return
		}
	}
}
