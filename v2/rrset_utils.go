/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func AuthQuery(qname, ns string, rrtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, rrtype)

	lg.Debug("AuthQuery: sending query", "qname", qname, "rrtype", dns.TypeToString[rrtype], "ns", ns)

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
		lg.Debug("AuthQuery: looking up RRset from answer", "qname", qname, "rrtype", dns.TypeToString[rrtype])
		for _, rr := range res.Answer {
			if rr.Header().Rrtype == rrtype {
				lg.Debug("AuthQuery: found RR", "rr", rr.String())

				rrs = append(rrs, rr)

			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
				_ = ok // suppress unused variable warning
			} else {
				return []dns.RR{}, fmt.Errorf("error: answer is not an %s RR: %s", dns.TypeToString[rrtype], rr.String())
			}
		}
		return rrs, nil
	}

	if len(res.Ns) > 0 {
		lg.Debug("AuthQuery: looking up RRset from authority", "qname", qname, "rrtype", dns.TypeToString[rrtype])
		for _, rr := range res.Ns {
			if rr.Header().Rrtype == rrtype && rr.Header().Name == qname {
				lg.Debug("AuthQuery: found RR", "rr", rr.String())

				rrs = append(rrs, rr)

			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
				_ = ok // suppress unused variable warning
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
		lg.Debug("AuthQuery: looking up RRset from additional", "qname", qname, "rrtype", dns.TypeToString[rrtype])
		for _, rr := range res.Extra {
			if rr.Header().Rrtype == rrtype && rr.Header().Name == qname {
				lg.Debug("AuthQuery: found RR", "rr", rr.String())

				rrs = append(rrs, rr)

			} else if _, ok := rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
				_ = ok // suppress unused variable warning
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
	// denial: for an authoritative answer with no records of the type, the
	// authority section that proves it, grouped into RRsets.
	denial []*core.RRset
	err    error
}

func AuthQueryEngine(ctx context.Context, requests chan AuthQueryRequest) {
	lg.Info("AuthQueryEngine: starting")

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
				lg.Info("AuthQueryEngine: requests channel closed")
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
				req.response <- &AuthQueryResponse{rrset: &rrset, err: ctx.Err()}
				continue
			}

			lg.Debug("AuthQueryEngine: received request", "qname", req.qname, "rrtype", dns.TypeToString[req.rrtype], "ns", req.ns)
			// RRtype and Class too: the scanner hands this RRset to the IMR's
			// validator, which looks up cached verdicts and special-cases
			// DNSKEY by rrset.RRtype.
			rrset := core.RRset{
				Name:   req.qname,
				Class:  dns.ClassINET,
				RRtype: req.rrtype,
			}

			m := new(dns.Msg)
			m.SetQuestion(req.qname, req.rrtype)
			// m.SetEdns0 creates the OPT record (if not present), sets the DO bit, and adds it to the Additional (Extra) section.
			m.SetEdns0(dns.DefaultMsgSize, true)
			// No need to manually set OPT header fields; SetEdns0 initializes them.

			lg.Debug("AuthQueryEngine: sending query", "qname", req.qname, "rrtype", dns.TypeToString[req.rrtype], "ns", req.ns)

			var err error
			var res *dns.Msg

			switch req.transport {
			case "tcp":
				res, _, err = tcpclient.Exchange(m, req.ns)
			default:
				res, err = dns.Exchange(m, req.ns)
			}

			if err != nil {
				req.response <- &AuthQueryResponse{rrset: &rrset, err: err}
				continue
			}

			if res.Rcode != dns.RcodeSuccess {
				req.response <- &AuthQueryResponse{rrset: &rrset, err: fmt.Errorf("Query for %s %s received rcode: %s",
					req.qname, dns.TypeToString[req.rrtype], dns.RcodeToString[res.Rcode])}
				continue
			}

			// Only an authoritative reply says anything about the child's data.
			// A lame server, or one that hosts only the parent and answers with
			// its referral, would otherwise have its records -- in that case the
			// parent's NS set -- compared as the child's.
			if !res.Authoritative {
				req.response <- &AuthQueryResponse{rrset: &rrset, err: fmt.Errorf("non-authoritative response for %s %s: the server is not authoritative for the zone",
					req.qname, dns.TypeToString[req.rrtype])}
				continue
			}

			if len(res.Answer) > 0 {
				lg.Debug("AuthQueryEngine: looking up RRset from answer", "qname", req.qname, "rrtype", dns.TypeToString[req.rrtype])
				for _, rr := range res.Answer {
					if rr.Header().Rrtype == req.rrtype {
						lg.Debug("AuthQueryEngine: found RR", "rr", rr.String())

						rrset.RRs = append(rrset.RRs, rr)

					} else if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == req.rrtype {
						rrset.RRSIGs = append(rrset.RRSIGs, rr)
					} else {
						lg.Warn("AuthQueryEngine: answer is not expected RR type", "expectedRrtype", dns.TypeToString[req.rrtype], "rr", rr.String())
					}
				}
				req.response <- &AuthQueryResponse{rrset: &rrset}
				continue
			}

			if len(res.Ns) > 0 {
				lg.Debug("AuthQueryEngine: looking up RRset from authority", "qname", req.qname, "rrtype", dns.TypeToString[req.rrtype])
				for _, rr := range res.Ns {
					if rr.Header().Rrtype == req.rrtype && rr.Header().Name == req.qname {
						lg.Debug("AuthQueryEngine: found RR", "rr", rr.String())

						rrset.RRs = append(rrset.RRs, rr)

					} else if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == req.rrtype {
						rrset.RRSIGs = append(rrset.RRSIGs, rr)
					}
				}
				if len(rrset.RRs) > 0 {
					req.response <- &AuthQueryResponse{rrset: &rrset}
					continue
				}
			}

			if len(res.Extra) > 0 {
				lg.Debug("AuthQueryEngine: looking up RRset from additional", "qname", req.qname, "rrtype", dns.TypeToString[req.rrtype])
				for _, rr := range res.Extra {
					if rr.Header().Rrtype == req.rrtype && rr.Header().Name == req.qname {
						lg.Debug("AuthQueryEngine: found RR", "rr", rr.String())

						rrset.RRs = append(rrset.RRs, rr)

					} else if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == req.rrtype {
						rrset.RRSIGs = append(rrset.RRSIGs, rr)
					}
				}
			}

			resp := &AuthQueryResponse{rrset: &rrset}
			if len(rrset.RRs) == 0 {
				// An authoritative NODATA. The authority section is the
				// proof of it: the SOA, and in a signed zone the NSEC or
				// NSEC3 records and their RRSIGs. Kept, so that a scan that
				// must see an absence proven can validate it (#779).
				resp.denial = authorityRRsets(res.Ns)
			}
			req.response <- resp
		}
	}
}

func (scanner *Scanner) AuthQueryNG(qname, ns string, rrtype uint16, transport string) (*core.RRset, error) {
	rrset, _, err := scanner.authQueryWithDenial(qname, ns, rrtype, transport)
	return rrset, err
}

// authQueryWithDenial is AuthQueryNG, and for an authoritative answer with no
// records of the type, the authority section that proves there are none,
// grouped into RRsets (authorityRRsets).
func (scanner *Scanner) authQueryWithDenial(qname, ns string, rrtype uint16, transport string) (*core.RRset, []*core.RRset, error) {
	response := make(chan *AuthQueryResponse)
	defer close(response)

	scanner.AuthQueryQ <- AuthQueryRequest{
		qname:     qname,
		ns:        ns,
		rrtype:    rrtype,
		transport: transport,
		response:  response,
	}

	resp := <-response
	return resp.rrset, resp.denial, resp.err
}
