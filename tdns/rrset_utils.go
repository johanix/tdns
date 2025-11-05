/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
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
				return []dns.RR{}, fmt.Errorf("Error: answer is not an %s RR: %s", dns.TypeToString[rrtype], rr.String())
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

// AuthQueryNG is the same as AuthQuery, but returns an RRset instead of a []dns.RR
// to be able to keep any RRSIGs. AuthQuery should be phased out.
// ns must be in addr:port format
type AuthQueryRequest struct {
	qname     string
	ns        string
	rrtype    uint16
	transport string
	response  chan *AuthQueryResponse
}

type AuthQueryResponse struct {
	rrset *RRset
	err   error
}

func AuthQueryEngine(ctx context.Context, requests chan AuthQueryRequest) {
	log.Printf("*** AuthQueryEngine: Starting ***	")

	tcpclient := new(dns.Client)
	tcpclient.Net = "tcp"

	for req := range requests {
		log.Printf("*** AuthQueryEngine: Received request for %s %s from %s ***", req.qname, dns.TypeToString[req.rrtype], req.ns)
		rrset := RRset{
			Name: req.qname,
		}

		m := new(dns.Msg)
		m.SetQuestion(req.qname, req.rrtype)
		// Set the DNSSEC OK (DO) bit in the EDNS0 options
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetDo()
		m.Extra = append(m.Extra, opt)

		if Globals.Debug {
			fmt.Printf("Sending query %s %s to nameserver \"%s\"\n", req.qname,
				dns.TypeToString[req.rrtype], req.ns)
		}

		var err error
		var res *dns.Msg

		switch req.transport {
		case "tcp":
			res, _, err = tcpclient.Exchange(m, req.ns)
		default:
			res, err = dns.Exchange(m, req.ns)
		}

		if err != nil {
			req.response <- &AuthQueryResponse{&rrset, err}
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			req.response <- &AuthQueryResponse{&rrset, fmt.Errorf("Query for %s %s received rcode: %s",
				req.qname, dns.TypeToString[req.rrtype], dns.RcodeToString[res.Rcode])}
			continue
		}

		if len(res.Answer) > 0 {
			if Globals.Debug {
				fmt.Printf("Looking up %s %s RRset:\n", req.qname, dns.TypeToString[req.rrtype])
			}
			for _, rr := range res.Answer {
				if rr.Header().Rrtype == req.rrtype {
					if Globals.Debug {
						fmt.Printf("%s\n", rr.String())
					}

					rrset.RRs = append(rrset.RRs, rr)

				} else if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == req.rrtype {
					rrset.RRSIGs = append(rrset.RRSIGs, rr)
				} else {
					log.Printf("AuthQueryNG: Error: answer is not an %s RR: %s", dns.TypeToString[req.rrtype], rr.String())
				}
			}
			req.response <- &AuthQueryResponse{&rrset, nil}
			continue
		}

		if len(res.Ns) > 0 {
			if Globals.Debug {
				fmt.Printf("Looking up %s %s RRset:\n", req.qname, dns.TypeToString[req.rrtype])
			}
			for _, rr := range res.Ns {
				if rr.Header().Rrtype == req.rrtype && rr.Header().Name == req.qname {
					if Globals.Debug {
						fmt.Printf("AuthQueryNG: Found: %s\n", rr.String())
					}

					rrset.RRs = append(rrset.RRs, rr)

				} else if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == req.rrtype {
					rrset.RRSIGs = append(rrset.RRSIGs, rr)
				}
			}
			if len(rrset.RRs) > 0 {
				req.response <- &AuthQueryResponse{&rrset, nil}
				continue
			}
		}

		if len(res.Extra) > 0 {
			if Globals.Debug {
				fmt.Printf("Looking up %s %s RRset:\n", req.qname, dns.TypeToString[req.rrtype])
			}
			for _, rr := range res.Extra {
				if rr.Header().Rrtype == req.rrtype && rr.Header().Name == req.qname {
					if Globals.Debug {
						fmt.Printf("%s\n", rr.String())
					}

					rrset.RRs = append(rrset.RRs, rr)

				} else if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == req.rrtype {
					rrset.RRSIGs = append(rrset.RRSIGs, rr)
				}
			}
			req.response <- &AuthQueryResponse{&rrset, nil}
			continue
		}

		req.response <- &AuthQueryResponse{&rrset, nil}
	}
}

func (scanner *Scanner) AuthQueryNG(qname, ns string, rrtype uint16, transport string) (*RRset, error) {
	//	requests := make(chan AuthQueryRequest)
	//defer close(requests)

	response := make(chan *AuthQueryResponse)
	defer close(response)

	//	go AuthQueryEngine(requests)

	scanner.AuthQueryQ <- AuthQueryRequest{
		qname:     qname,
		ns:        ns,
		rrtype:    rrtype,
		transport: transport,
		response:  response,
	}

	resp := <-response
	return resp.rrset, resp.err
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

func (rrset *RRset) Copy() *RRset {
	new_rrset := RRset{
		Name:   rrset.Name,
		RRs:    []dns.RR{},
		RRSIGs: []dns.RR{},
	}
	new_rrset.RRs = append(new_rrset.RRs, rrset.RRs...)
	new_rrset.RRSIGs = append(new_rrset.RRSIGs, rrset.RRSIGs...)
	return &new_rrset
}

// Add adds a RR to the RRset if it is not already present.
func (rrset *RRset) Add(rr dns.RR) {
	for _, rr2 := range rrset.RRs {
		if dns.IsDuplicate(rr, rr2) {
			// log.Printf("rrset.Add: RR already present: %s", rr.String())
			return
		}
	}
	// log.Printf("rrset.Add: Adding RR: %s to RRset\n%v", rr.String(), rrset.RRs)
	rrset.RRs = append(rrset.RRs, rr)
}

// Delete deletes a RR from the RRset if it is present.
func (rrset *RRset) Delete(rr dns.RR) {
	for i, rr2 := range rrset.RRs {
		if dns.IsDuplicate(rr, rr2) {
			// log.Printf("rrset.Delete: Found RR: %s in RRset\n%v", rr.String(), rrset.RRs)
			rrset.RRs = append(rrset.RRs[:i], rrset.RRs[i+1:]...)
			return
		}
	}
	// log.Printf("rrset.Delete: RR not found: %s", rr.String())
}
