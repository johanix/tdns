/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	core "github.com/johanix/tdns/tdns/core"
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
	rrset *core.RRset
	err   error
}

func AuthQueryEngine(ctx context.Context, requests chan AuthQueryRequest) {
	log.Printf("*** AuthQueryEngine: Starting ***")

	tcpclient := new(dns.Client)
	tcpclient.Net = "tcp"

	// After cancellation, keep draining requests for a short window to avoid leaving senders blocked.
	ctxCh := ctx.Done()
	shuttingDown := false
	var drainTimer *time.Timer

	for {
		var timeout <-chan time.Time
		if shuttingDown {
			if drainTimer == nil {
				drainTimer = time.NewTimer(500 * time.Millisecond)
			} else {
				timeout = drainTimer.C
			}
		}
		select {
		case <-ctxCh:
			shuttingDown = true
			ctxCh = nil
			if drainTimer == nil {
				drainTimer = time.NewTimer(500 * time.Millisecond)
			}
			continue
		case <-timeout:
			return
		case req, ok := <-requests:
			if !ok {
				log.Println("AuthQueryEngine: requests channel closed")
				return
			}
			if shuttingDown {
				if drainTimer != nil {
					if !drainTimer.Stop() {
						select {
						case <-drainTimer.C:
						default:
						}
					}
					drainTimer.Reset(500 * time.Millisecond)
				}
				rrset := core.RRset{Name: req.qname}
				req.response <- &AuthQueryResponse{&rrset, ctx.Err()}
				continue
			}

			log.Printf("*** AuthQueryEngine: Received request for %s %s from %s ***", req.qname, dns.TypeToString[req.rrtype], req.ns)
			rrset := core.RRset{
				Name: req.qname,
			}

			m := new(dns.Msg)
			m.SetQuestion(req.qname, req.rrtype)
			// m.SetEdns0 creates the OPT record (if not present), sets the DO bit, and adds it to the Additional (Extra) section.
			m.SetEdns0(dns.DefaultMsgSize, true)
			// No need to manually set OPT header fields; SetEdns0 initializes them.

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
}

func (scanner *Scanner) AuthQueryNG(qname, ns string, rrtype uint16, transport string) (*core.RRset, error) {
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

func xxxRRsetDiffer(zone string, newrrs, oldrrs []dns.RR, rrtype uint16, lg *log.Logger) (bool, []dns.RR, []dns.RR) {
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

