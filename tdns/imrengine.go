/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/miekg/dns"
)

type ImrRequest struct {
	Qname      string
	Qtype      uint16
	Qclass     uint16
	ResponseCh chan ImrResponse
}

type ImrResponse struct {
	RRset     *RRset
	Validated bool
	Error     bool
	ErrorMsg  string
	Msg       string
}

// The RecursorEngine is a simple caching DNS recursor. It is not a fully fledged, all singing,
// all dancing recursive server. It is just intended to get the job done for the particular cases
// that we need to support.

// var RecursorCache *RRsetCacheNG

func (conf *Config) RecursorEngine(ctx context.Context) {
	var recursorch = conf.Internal.RecursorCh

	if !viper.GetBool("recursorengine.active") {
		log.Printf("RecursorEngine is NOT active.")
		for {
			select {
			case <-ctx.Done():
				log.Printf("RecursorEngine: terminating due to context cancelled (inactive mode)")
				return
			case rrq, ok := <-recursorch:
				if !ok {
					return
				}
				log.Printf("RecursorEngine: not active, but got a request: %v", rrq)
				continue // ensure that we keep reading to keep the channel open
			}
		}
	} else {
		log.Printf("RecursorEngine: Starting")
	}

	// 1. Create the cache
	var err error
	// RecursorCache, err = NewRRsetCacheNG(viper.GetString("recursorengine.root-hints"))
	rrcache := NewRRsetCache(log.Default(), conf.ImrEngine.Verbose, conf.ImrEngine.Debug, conf.ImrEngine.Options)
	if !rrcache.Primed {
		err = rrcache.PrimeWithHints(viper.GetString("recursorengine.root-hints"))
		if err != nil {
			Shutdowner(conf, fmt.Sprintf("RecursorEngine: failed to initialize RecursorCache w/ root hints: %v", err))
		}
		if len(conf.ImrEngine.Stubs) > 0 {
			for _, stub := range conf.ImrEngine.Stubs {
				stubservers := []string{}
				for _, server := range stub.Servers {
					stubservers = append(stubservers, server.Name+" ("+strings.Join(server.Addrs, ", ")+")")
				}
				log.Printf("RecursorEngine: adding stub %q with servers %s", stub.Zone, strings.Join(stubservers, ", "))
				rrcache.AddStub(stub.Zone, stub.Servers)
			}
		}
	}

	conf.Internal.RRsetCache = rrcache

	// Initialize trust anchors (DS/DNSKEY) and validate root (.) DNSKEY and NS
	if err := initializeImrTrustAnchors(ctx, rrcache, conf); err != nil {
		log.Printf("RecursorEngine: trust anchor initialization failed: %v", err)
	}

	// Start the ImrEngine (i.e. the recursive nameserver responding to queries with RD bit set)
	go rrcache.ImrEngine(ctx, conf)

	for {
		select {
		case <-ctx.Done():
			log.Printf("RecursorEngine: terminating due to context cancelled (active mode)")
			return
		case rrq, ok := <-recursorch:
			if !ok {
				return
			}
			if rrq.ResponseCh == nil {
				log.Printf("RecursorEngine: received nil or invalid request (no response channel)")
				continue
			}
			if Globals.Debug {
				log.Printf("RecursorEngine: received query for %s %s %s", rrq.Qname, dns.ClassToString[rrq.Qclass], dns.TypeToString[rrq.Qtype])
				fmt.Printf("RecursorEngine: received query for %s %s %s\n", rrq.Qname, dns.ClassToString[rrq.Qclass], dns.TypeToString[rrq.Qtype])
			}
			// resp := ImrResponse{
			//			Validated: false,
			// Msg:       "RecursorEngine: request to look up a RRset",
			// }
			var resp *ImrResponse

			// 1. Is the answer in the cache?
			crrset := rrcache.Get(rrq.Qname, rrq.Qtype)
			if crrset != nil {
				if Globals.Debug {
					fmt.Printf("RecursorEngine: cache hit for %s %s %s\n", rrq.Qname, dns.ClassToString[rrq.Qclass], dns.TypeToString[rrq.Qtype])
				}
				resp = &ImrResponse{
					RRset: crrset.RRset,
				}
				rrq.ResponseCh <- *resp
			} else {
				var err error
				if Globals.Debug {
					log.Printf("Recursor: <qname, qtype> tuple <%q, %s> not known, needs to be queried for", rrq.Qname, dns.TypeToString[rrq.Qtype])
					fmt.Printf("Recursor: <qname, qtype> tuple <%q, %s> not known, needs to be queried for\n", rrq.Qname, dns.TypeToString[rrq.Qtype])
				}

				resp, err = rrcache.ImrQuery(ctx, rrq.Qname, rrq.Qtype, rrq.Qclass, nil)
				if err != nil {
					log.Printf("Error from IterateOverQuery: %v", err)
				} else if resp == nil {
					resp = &ImrResponse{
						Error:    true,
						ErrorMsg: fmt.Sprintf("ImrQuery: no response from ImrQuery"),
					}
				}
				rrq.ResponseCh <- *resp
			}
		}
	}
}

func (rrcache *RRsetCacheT) ImrQuery(ctx context.Context, qname string, qtype uint16, qclass uint16, respch chan *ImrResponse) (*ImrResponse, error) {
	if Globals.Debug {
		log.Printf("ImrQuery: <%s, %s> not known, needs to be queried for", qname, dns.TypeToString[qtype])
	}
	maxiter := 12

	resp := ImrResponse{
		Validated: false,
		Msg:       "ImrEngine: request to look up a RRset",
	}

	// If a response channel is provided, use it to send responses
	if respch != nil {
		defer func() {
			respch <- &resp
		}()
	}

	crrset := rrcache.Get(qname, qtype)
	if crrset != nil {
		resp.RRset = crrset.RRset
		return &resp, nil
	}

	for {
		if maxiter <= 0 {
			log.Printf("*** ImrQuery: max iterations reached. Giving up.")
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Max iterations reached. Giving up.")
			return &resp, fmt.Errorf("Max iterations reached. Giving up.")
		} else {
			maxiter--
		}
		bestmatch, authservers, err := rrcache.FindClosestKnownZone(qname)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error from FindClosestKnownZone: %v", err)
			return &resp, err
		}
		log.Printf("ImrQuery: best zone match for qname %q seems to be %q", qname, bestmatch)
		// ss := servers

		switch {
		case len(authservers) == 0:
			log.Printf("*** ImrResponder:we have no server addresses for zone %q needed to query for %q", bestmatch, qname)
			cnsrrset := rrcache.Get(bestmatch, dns.TypeNS)
			if cnsrrset == nil {
				log.Printf("*** ImrResponder: we also have no nameservers for zone %q, giving up", bestmatch)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Failed to resolve query %q, %s, using any nameserver address", qname, dns.TypeToString[qtype])
				return &resp, nil
			}

			log.Printf("*** but we do have the nameserver names: %v", cnsrrset.RRset.RRs)

			// Create response channel for A and AAAA queries
			respch := make(chan *ImrResponse, len(cnsrrset.RRset.RRs)*2) // *2 for both A and AAAA
			// Note: We don't need to close the channel here as it will be garbage collected
			// when it goes out of scope, even if there are still pending writes to it

			// Launch parallel queries for each nameserver
			err := rrcache.CollectNSAddresses(ctx, cnsrrset.RRset, respch)
			if err != nil {
				log.Printf("Error from CollectNSAddresses: %v", err)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Error from CollectNSAddresses: %v", err)
				return &resp, err
			}

			// Process a bounded number of responses until we get a usable address
			want := len(cnsrrset.RRset.RRs) * 2
			for i := 0; i < want; i++ {
				var rrresp *ImrResponse
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case rrresp = <-respch:
				case <-time.After(3 * time.Second):
					rrresp = nil
				}
				if rrresp == nil || rrresp.RRset == nil {
					continue
				}

				for _, rr := range rrresp.RRset.RRs {
					switch rr := rr.(type) {
					case *dns.A:
						// servers = []]string{rr.A.String()}
						authservers[rr.Header().Name] = &AuthServer{
							Name:          rr.Header().Name,
							Addrs:         []string{rr.A.String()},
							Alpn:          []string{"do53"},
							Transports:    []Transport{TransportDo53},
							PrefTransport: TransportDo53,
							Src:           "answer",
							Expire:        time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
						}
						if Globals.Debug {
							log.Printf("ImrResponder: using resolved A address: %+v", authservers)
						}
					case *dns.AAAA:
						// servers = []string{rr.AAAA.String()}
						authservers[rr.Header().Name] = &AuthServer{
							Name:          rr.Header().Name,
							Addrs:         []string{rr.AAAA.String()},
							Alpn:          []string{"do53"},
							Transports:    []Transport{TransportDo53},
							PrefTransport: TransportDo53,
							Src:           "answer",
							Expire:        time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
						}
						if Globals.Debug {
							log.Printf("ImrResponder: using resolved AAAA address: %+v", authservers)
						}
					}

					rrset, rcode, context, err := rrcache.IterativeDNSQuery(ctx, qname, qtype, authservers, false)
					if err != nil {
						log.Printf("Error from IterativeDNSQuery: %v", err)
						continue
					}
					if rrset != nil {
						if Globals.Debug {
							log.Printf("ImrQuery: received response from IterativeDNSQuery:")
							for _, rr := range rrset.RRs {
								log.Printf("ImrQuery: %s", rr.String())
							}
						}
						resp.RRset = rrset
						return &resp, nil
					}
					if rcode == dns.RcodeNameError {
						// this is a negative response, which we need to figure out how to represent
						log.Printf("ImrQuery: received NXDOMAIN for qname %q, no point in continuing", qname)
						resp.Msg = "NXDOMAIN (negative response type 3)"
						return &resp, nil
					}
					switch context {
					case ContextReferral:
						continue // if all is good we will now hit the new referral and get further
					case ContextNoErrNoAns:
						resp.Msg = "negative response type 0"
						return &resp, nil
					}
				}
			}

			// If we get here, we tried all responses without finding a usable address
			log.Printf("*** ImrQuery: failed to resolve query %q, %s, using any nameserver address", qname, dns.TypeToString[qtype])
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Failed to resolve query %q, %s, using any nameserver address", qname, dns.TypeToString[qtype])
			return &resp, nil

		case len(authservers) < 4:
			// ss = servers
		default:
			// ss = servers[:3]
			// ss = append(servers, "...")
		}

		if Globals.Debug {
			auths := []string{}
			for name, _ := range authservers {
				auths = append(auths, name)
			}
			log.Printf("ImrQuery: sending query \"%s %s\" to %d auth servers: %s", qname, dns.TypeToString[qtype], len(authservers), strings.Join(auths, ", "))
		}

		rrset, rcode, context, err := rrcache.IterativeDNSQuery(ctx, qname, qtype, authservers, false)
		// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error from IterativeDNSQuery: %v", err)
			return &resp, err
		}

		if rrset != nil {
			if Globals.Debug {
				log.Printf("ImrQuery: received response from IterativeDNSQuery:")
				for _, rr := range rrset.RRs {
					log.Printf("ImrQuery: %s", rr.String())
				}
			}
			resp.RRset = rrset
			return &resp, nil
		}
		if rcode == dns.RcodeNameError {
			// this is a negative response, which we need to figure out how to represent
			log.Printf("ImrQuery: received NXDOMAIN for qname %q, no point in continuing", qname)
			resp.Msg = "NXDOMAIN (negative response type 3)"
			return &resp, nil
		}
		switch context {
		case ContextReferral:
			continue // if all is good we will now hit the new referral and get further
		case ContextNoErrNoAns:
			resp.Msg = CacheContextToString[context]
			return &resp, nil
		}
	}
}

func (rrcache *RRsetCacheT) ImrResponder(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, dnssec_ok bool) {
	rd_bit := r.MsgHdr.RecursionDesired
	m := new(dns.Msg)
	m.RecursionAvailable = true

	crrset := rrcache.Get(qname, qtype)
	if crrset != nil {
		switch {
		case crrset.Rcode == uint8(dns.RcodeNameError) && crrset.Context == ContextNXDOMAIN:
			m.SetRcode(r, dns.RcodeNameError)
			if !appendNegAuthorityToMessage(m, crrset.NegAuthority, dnssec_ok) && crrset.RRset != nil {
				appendSOAToMessage(crrset.RRset, dnssec_ok, m)
			}
			if dnssec_ok && len(crrset.NegAuthority) > 0 && rrcache.ValidateNegativeResponse(ctx, qname, qtype, crrset.NegAuthority) {
				m.AuthenticatedData = true
			} else if crrset.Validated {
				m.AuthenticatedData = true
			}
			w.WriteMsg(m)
			return
		case crrset.Rcode == uint8(dns.RcodeSuccess) && crrset.Context == ContextNoErrNoAns &&
			qtype != dns.TypeSOA:
			m.SetRcode(r, dns.RcodeSuccess)
			if !appendNegAuthorityToMessage(m, crrset.NegAuthority, dnssec_ok) && crrset.RRset != nil {
				appendSOAToMessage(crrset.RRset, dnssec_ok, m)
			}
			if dnssec_ok && len(crrset.NegAuthority) > 0 && rrcache.ValidateNegativeResponse(ctx, qname, qtype, crrset.NegAuthority) {
				m.AuthenticatedData = true
			} else if crrset.Validated {
				m.AuthenticatedData = true
			}
			w.WriteMsg(m)
			return
		case crrset.Rcode == uint8(dns.RcodeSuccess) && crrset.Context == ContextAnswer &&
			crrset.RRset != nil && crrset.RRset.RRtype == qtype:
			m.SetRcode(r, dns.RcodeSuccess)
			m.Answer = crrset.RRset.RRs
			if dnssec_ok {
				m.Answer = append(m.Answer, crrset.RRset.RRSIGs...)
			}
			if crrset.Validated {
				m.AuthenticatedData = true
			}
			w.WriteMsg(m)
			return
		}
	}

	m.SetRcode(r, dns.RcodeServerFailure)
	if rd_bit {
		log.Printf("ImrResponder: <qname, qtype> tuple <%q, %s> not known, needs to be queried for", qname, dns.TypeToString[qtype])
		maxiter := 12

		for {
			if maxiter <= 0 {
				log.Printf("*** ImrResponder: max iterations reached. Giving up.")
				return
			} else {
				maxiter--
			}
			bestmatch, authservers, err := rrcache.FindClosestKnownZone(qname)
			if err != nil {
				// resp.Error = true
				// resp.ErrorMsg = fmt.Sprintf("Error from FindClosestKnownZone: %v", err)
				// m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}
			log.Printf("ImrResponder: best zone match for qname %q seems to be %q", qname, bestmatch)

			switch {
			case len(authservers) == 0:
				log.Printf("*** ImrResponder:we have no server addresses for zone %q needed to query for %q", bestmatch, qname)
				cnsrrset := rrcache.Get(bestmatch, dns.TypeNS)
				if cnsrrset == nil {
					log.Printf("*** ImrResponder: we also have no nameservers for zone %q, giving up", bestmatch)
					// m.SetRcode(r, dns.RcodeServerFailure)
					w.WriteMsg(m)
					return
				}

				log.Printf("*** but we do have the nameserver names: %v", cnsrrset.RRset.RRs)

				// Create response channel for A and AAAA queries
				respch := make(chan *ImrResponse, len(cnsrrset.RRset.RRs)*2) // *2 for both A and AAAA
				// Note: We don't need to close the channel here as it will be garbage collected
				// when it goes out of scope, even if there are still pending writes to it

				// Launch parallel queries for each nameserver
				err := rrcache.CollectNSAddresses(ctx, cnsrrset.RRset, respch)
				if err != nil {
					log.Printf("Error from CollectNSAddresses: %v", err)
					// m.SetRcode(r, dns.RcodeServerFailure)
					w.WriteMsg(m)
					return
				}

				// Process a bounded number of responses until we get a usable address
				want := len(cnsrrset.RRset.RRs) * 2
				for i := 0; i < want; i++ {
					var resp *ImrResponse
					select {
					case <-ctx.Done():
						m.SetRcode(r, dns.RcodeServerFailure)
						w.WriteMsg(m)
						return
					case resp = <-respch:
					case <-time.After(3 * time.Second):
						resp = nil
					}
					if resp == nil || resp.RRset == nil {
						continue
					}

					for _, rr := range resp.RRset.RRs {
						nsname := rr.Header().Name
						switch rr := rr.(type) {
						case *dns.A:
							// servers = []]string{rr.A.String()}
							authservers[nsname] = &AuthServer{
								Name:          nsname,
								Addrs:         []string{rr.A.String()},
								Alpn:          []string{"do53"},
								Transports:    []Transport{TransportDo53},
								PrefTransport: TransportDo53,
								Src:           "answer",
								Expire:        time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
							}
							log.Printf("ImrResponder: using resolved A address: %+v", authservers[nsname])
						case *dns.AAAA:
							// servers = []string{rr.AAAA.String()}
							authservers[nsname] = &AuthServer{
								Name:          nsname,
								Addrs:         []string{rr.AAAA.String()},
								Alpn:          []string{"do53"},
								Transports:    []Transport{TransportDo53},
								PrefTransport: TransportDo53,
								Src:           "answer",
								Expire:        time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
							}
							log.Printf("ImrResponder: using resolved AAAA address: %v", authservers[nsname])
						}
						rrset, rcode, context, err := rrcache.IterativeDNSQuery(ctx, qname, qtype, authservers, false)
						if err != nil {
							log.Printf("Error from IterativeDNSQuery: %v", err)
							continue
						}
						done, err := rrcache.ProcessAuthDNSResponse(ctx, qname, qtype, rrset, rcode, context, dnssec_ok, m, w, r)
						if err != nil {
							return
						}
						if done {
							return
						}
						continue // try next nameserver
					}
				}

				// If we get here, we tried all responses without finding a usable address
				log.Printf("*** ImrResponder: failed to resolve query %q, %s, using any nameserver address", qname, dns.TypeToString[qtype])
				// m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}

			log.Printf("ImrResponder: sending query to %d authservers: %+v", len(authservers), authservers)
			rrset, rcode, context, err := rrcache.IterativeDNSQuery(ctx, qname, qtype, authservers, false)
			// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
			if err != nil {
				w.WriteMsg(m)
				return
			}
			done, err := rrcache.ProcessAuthDNSResponse(ctx, qname, qtype, rrset, rcode, context, dnssec_ok, m, w, r)
			if err != nil {
				return
			}
			if done {
				return
			}
			continue
		}
	} else {
		log.Printf("Recursor: <qname, qtype> tuple <%q, %s> not known, needs to be queried for but RD bit is not set", qname, dns.TypeToString[qtype])
		m.SetRcode(r, dns.RcodeRefused)
		m.Ns = append(m.Ns, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
			Txt: []string{"not in cache, and RD bit not set"},
		})
		w.WriteMsg(m)
		return
	}
}

// returns true if we have a response (i.e. we're done), false if we have an error
// all errors are treated as "done"
func (rrcache *RRsetCacheT) ProcessAuthDNSResponse(ctx context.Context, qname string, qtype uint16, rrset *RRset, rcode int, context CacheContext, dnssec_ok bool, m *dns.Msg, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	log.Printf("ProcessAuthDNSResponse: qname: %q, rrset: %+v, rcode: %d, context: %d, dnssec_ok: %v", qname, rrset, rcode, context, dnssec_ok)
	m.SetRcode(r, rcode)
	if rrset != nil {
		log.Printf("ImrResponder: received response from IterativeDNSQuery:")
		for _, rr := range rrset.RRs {
			log.Printf("ImrResponder: %s", rr.String())
		}
		m.Answer = rrset.RRs
		if dnssec_ok {
			m.Answer = append(m.Answer, rrset.RRSIGs...)
		}
		// Set AD if this RRset is validated (from cache or on-the-fly)
		var validated bool
		if rrcache != nil {
			if c := rrcache.Get(rrset.Name, rrset.RRtype); c != nil && c.Validated {
				validated = true
			} else {
				if ok, _ := DnskeyCache.ValidateRRset(ctx, rrcache, rrset, rrcache.Debug); ok {
					validated = true
				}
			}
		}
		if validated {
			m.AuthenticatedData = true
		}
		w.WriteMsg(m)
		return true, nil
	}
	switch context {
	case ContextNXDOMAIN:
		m.SetRcode(r, dns.RcodeNameError)
		rrcache.serveNegativeResponse(ctx, qname, qtype, dnssec_ok, m, r)
		w.WriteMsg(m)
		return true, nil
	case ContextReferral:
		// continue // if all is good we will now hit the new referral and get further
		return false, nil
	case ContextNoErrNoAns:
		m.SetRcode(r, dns.RcodeSuccess)
		rrcache.serveNegativeResponse(ctx, qname, qtype, dnssec_ok, m, r)
		w.WriteMsg(m)
		return true, nil
	}
	return false, nil
}

func appendSOAToMessage(soa *RRset, dnssecOK bool, m *dns.Msg) {
	if soa == nil || m == nil {
		return
	}
	for _, rr := range soa.RRs {
		if rr == nil {
			continue
		}
		m.Ns = append(m.Ns, dns.Copy(rr))
	}
	if dnssecOK {
		for _, sig := range soa.RRSIGs {
			if sig == nil {
				continue
			}
			m.Ns = append(m.Ns, dns.Copy(sig))
		}
	}
}

func appendNegAuthorityToMessage(m *dns.Msg, neg []*RRset, dnssecOK bool) bool {
	if m == nil || len(neg) == 0 {
		return false
	}
	var appended bool
	for _, set := range neg {
		if set == nil {
			continue
		}
		for _, rr := range set.RRs {
			if rr == nil {
				continue
			}
			m.Ns = append(m.Ns, dns.Copy(rr))
			appended = true
		}
		if dnssecOK {
			for _, sig := range set.RRSIGs {
				if sig == nil {
					continue
				}
				m.Ns = append(m.Ns, dns.Copy(sig))
				appended = true
			}
		}
	}
	return appended
}

func buildNegAuthorityFromMsg(src *dns.Msg) []*RRset {
	if src == nil || len(src.Ns) == 0 {
		return nil
	}
	type key struct {
		name   string
		rrtype uint16
	}
	var order []key
	sets := make(map[key]*RRset)
	get := func(name string, rrtype uint16) *RRset {
		k := key{dns.CanonicalName(name), rrtype}
		if rs, ok := sets[k]; ok {
			return rs
		}
		rs := &RRset{Name: k.name, Class: dns.ClassINET, RRtype: rrtype}
		sets[k] = rs
		order = append(order, k)
		return rs
	}
	for _, raw := range src.Ns {
		if raw == nil {
			continue
		}
		switch rr := raw.(type) {
		case *dns.RRSIG:
			set := get(rr.Header().Name, rr.TypeCovered)
			set.RRSIGs = append(set.RRSIGs, dns.Copy(rr))
		default:
			set := get(raw.Header().Name, raw.Header().Rrtype)
			set.RRs = append(set.RRs, dns.Copy(raw))
		}
	}
	var out []*RRset
	for _, k := range order {
		if rs := sets[k]; rs != nil && (len(rs.RRs) > 0 || len(rs.RRSIGs) > 0) {
			out = append(out, rs)
		}
	}
	return out
}

func (rrcache *RRsetCacheT) serveNegativeResponse(ctx context.Context, qname string, qtype uint16, dnssecOK bool, resp *dns.Msg, src *dns.Msg) bool {
	if resp == nil {
		return false
	}
	var neg []*RRset
	cached := rrcache.Get(qname, qtype)
	if cached != nil && len(cached.NegAuthority) > 0 {
		neg = cached.NegAuthority
		if appendNegAuthorityToMessage(resp, neg, dnssecOK) {
			if dnssecOK {
				if rrcache.ValidateNegativeResponse(ctx, qname, qtype, neg) {
					resp.AuthenticatedData = true
				}
			} else if cached.Validated {
				resp.AuthenticatedData = true
			}
			return true
		}
	}
	if cached != nil && cached.RRset != nil {
		appendSOAToMessage(cached.RRset, dnssecOK, resp)
		if cached.Validated {
			resp.AuthenticatedData = true
		}
		return true
	}
	neg = buildNegAuthorityFromMsg(src)
	if len(neg) > 0 && appendNegAuthorityToMessage(resp, neg, dnssecOK) {
		if dnssecOK && rrcache.ValidateNegativeResponse(ctx, qname, qtype, neg) {
			resp.AuthenticatedData = true
		}
		return true
	}
	appendSOAFromMsg(src, dnssecOK, resp)
	return true
}

func (rrcache *RRsetCacheT) appendCachedNegativeSOA(qname string, qtype uint16, dnssecOK bool, m *dns.Msg) bool {
	if rrcache == nil || m == nil {
		return false
	}
	cached := rrcache.Get(qname, qtype)
	if cached == nil || cached.RRset == nil {
		return false
	}
	appendSOAToMessage(cached.RRset, dnssecOK, m)
	if cached.Validated {
		m.AuthenticatedData = true
	}
	return true
}

func appendSOAFromMsg(r *dns.Msg, dnssecOK bool, m *dns.Msg) {
	if r == nil || len(r.Ns) == 0 {
		return
	}
	var soaRRset *RRset
	for _, rr := range r.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			if soaRRset == nil {
				soaRRset = &RRset{Name: rr.Header().Name, RRtype: dns.TypeSOA}
			}
			soaRRset.RRs = append(soaRRset.RRs, rr)
		case dns.TypeRRSIG:
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeSOA {
				if soaRRset == nil {
					soaRRset = &RRset{Name: rr.Header().Name, RRtype: dns.TypeSOA}
				}
				soaRRset.RRSIGs = append(soaRRset.RRSIGs, rr)
			}
		}
	}
	if soaRRset != nil {
		appendSOAToMessage(soaRRset, dnssecOK, m)
	}
}

func (rrcache *RRsetCacheT) FindClosestKnownZone(qname string) (string, map[string]*AuthServer, error) {
	// Iterate through known zone names and return the longest match.
	var bestmatch string
	// var servers []string
	var servers map[string]*AuthServer
	if Globals.Debug {
		log.Printf("FindClosestKnownZone: checking qname %q against %d zones with data in cache", qname, rrcache.Servers.Count())
	}
	// for item := range rrcache.Servers.IterBuffered() {
	//	z := item.Key
	//	ss := item.Val
	//	if strings.HasSuffix(qname, z) && len(z) > len(bestmatch) {
	//		bestmatch = z
	//		servers = ss
	//	}
	// }
	for item := range rrcache.ServerMap.IterBuffered() {
		z := item.Key
		ss := item.Val
		if strings.HasSuffix(qname, z) && len(z) > len(bestmatch) {
			bestmatch = z
			servers = ss
		}
	}

	if Globals.Debug {
		auths := []string{}
		for name, _ := range servers {
			auths = append(auths, name)
		}
		log.Printf("FindClosestKnownZone: authservers for zone %q: %s", qname, strings.Join(auths, ", "))
	}
	return bestmatch, servers, nil
}

func (rrcache *RRsetCacheT) ImrEngine(ctx context.Context, conf *Config) error {
	ImrHandler := createImrHandler(ctx, conf, rrcache)
	dns.HandleFunc(".", ImrHandler)

	addresses := viper.GetStringSlice("imrengine.addresses")
	if CaseFoldContains(conf.ImrEngine.Transports, "do53") {
		log.Printf("ImrEngine: UDP/TCP addresses: %v", addresses)
		servers := make([]*dns.Server, 0, len(addresses)*2)
		for _, addr := range addresses {
			for _, net := range []string{"udp", "tcp"} {
				server := &dns.Server{
					Addr: addr,
					Net:  net,
					// MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
				}
				servers = append(servers, server)
				go func(s *dns.Server, addr, net string) {
					log.Printf("ImrEngine: serving on %s (%s)\n", addr, net)
					// Must bump the buffer size of incoming UDP msgs, as updates
					// may be much larger then queries
					// s.UDPSize = dns.DefaultMsgSize // 4096
					if err := s.ListenAndServe(); err != nil {
						log.Printf("Failed to setup the %s server: %s", net, err.Error())
					} else {
						log.Printf("ImrEngine: listening on %s/%s", addr, net)
					}
				}(server, addr, net)
			}
		}
		// Graceful shutdown of Do53 servers
		go func() {
			<-ctx.Done()
			log.Printf("ImrEngine: ctx cancelled: shutting down Do53 servers (%d)", len(servers))
			for _, s := range servers {
				done := make(chan struct{})
				go func(s *dns.Server) {
					defer close(done)
					if err := s.Shutdown(); err != nil {
						log.Printf("ImrEngine: error shutting down Do53 server %s/%s: %v", s.Addr, s.Net, err)
					}
				}(s)
				select {
				case <-done:
					// ok
				case <-time.After(5 * time.Second):
					log.Printf("ImrEngine: timeout waiting for Do53 server shutdown %s/%s", s.Addr, s.Net)
				}
			}
		}()
	} else {
		log.Printf("ImrEngine: Not serving on transport Do53 (normal UDP/TCP)")
	}

	certFile := viper.GetString("imrengine.certfile")
	keyFile := viper.GetString("imrengine.keyfile")
	certKey := true

	if certFile == "" || keyFile == "" {
		log.Println("ImrEngine: no certificate file or key file provided. Not starting DoT, DoH or DoQ service.")
		certKey = false
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("ImrEngine: certificate file %q does not exist. Not starting DoT, DoH or DoQ service.", certFile)
		certKey = false
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("ImrEngine: key file %q does not exist. Not starting DoT, DoH or DoQ service.", keyFile)
		certKey = false
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("ImrEngine: failed to load certificate: %v. Not starting DoT, DoH or DoQ service.", err)
		certKey = false
	}

	if certKey {
		// Strip port numbers from addresses before proceeding to modern transports
		tmp := make([]string, len(addresses))
		for i, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				log.Printf("Failed to parse address %s: %v", addr, err)
				tmp[i] = addr // Keep original if parsing fails
			} else {
				tmp[i] = host
			}
		}
		addresses = tmp

		if CaseFoldContains(conf.ImrEngine.Transports, "dot") {
			err := DnsDoTEngine(ctx, conf, addresses, &cert, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoT server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoT")
		}

		if CaseFoldContains(conf.ImrEngine.Transports, "doh") {
			err := DnsDoHEngine(ctx, conf, addresses, certFile, keyFile, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoH server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoH")
		}

		if CaseFoldContains(conf.ImrEngine.Transports, "doq") {
			err := DnsDoQEngine(ctx, conf, addresses, &cert, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoQ server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoQ")
		}
	}
	return nil
}

// initializeImrTrustAnchors loads trust anchors from config:
// - DS/DNSKEY strings (single)
// - trust-anchor-file (multiple lines)
// For each anchored name, it loads direct DNSKEY TAs (trusted), matches DS→DNSKEY(s),
// validates the anchored DNSKEY RRset and then validates the NS RRset for that name.
func initializeImrTrustAnchors(ctx context.Context, rrcache *RRsetCacheT, conf *Config) error {
	// Only act if we have any trust-anchor configured
	taDS := strings.TrimSpace(conf.ImrEngine.TrustAnchorDS)
	taDNSKEY := strings.TrimSpace(conf.ImrEngine.TrustAnchorDNSKEY)
	taFile := strings.TrimSpace(conf.ImrEngine.TrustAnchorFile)
	if taDS == "" && taDNSKEY == "" && taFile == "" {
		return nil
	}

	// Collect DS and DNSKEY anchors keyed by name
	dsByName := map[string][]*dns.DS{}
	dnskeysByName := map[string][]*dns.DNSKEY{}

	// If DNSKEY TA is provided, add it directly
	if taDNSKEY != "" {
		rr, err := dns.NewRR(taDNSKEY)
		if err != nil {
			return fmt.Errorf("failed to parse trust_anchor_dnskey: %v", err)
		}
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			return fmt.Errorf("trust_anchor_dnskey is not a DNSKEY RR: %T", rr)
		}
		name := dns.Fqdn(dk.Hdr.Name)
		dnskeysByName[name] = append(dnskeysByName[name], dk)
	}

	// If DS TA is provided, remember it for matching after fetching DNSKEY RRset
	if taDS != "" {
		rr, err := dns.NewRR(taDS)
		if err != nil {
			return fmt.Errorf("failed to parse trust_anchor_ds: %v", err)
		}
		ds, ok := rr.(*dns.DS)
		if !ok {
			return fmt.Errorf("trust_anchor_ds is not a DS RR: %T", rr)
		}
		name := dns.Fqdn(ds.Hdr.Name)
		dsByName[name] = append(dsByName[name], ds)
		log.Printf("initializeImrTrustAnchors: configured DS TA for %s keytag=%d digesttype=%d", name, ds.KeyTag, ds.DigestType)
	}

	// If trust-anchor-file is provided, read and parse all RRs
	if taFile != "" {
		data, err := os.ReadFile(taFile)
		if err != nil {
			return fmt.Errorf("failed to read trust-anchor-file %q: %v", taFile, err)
		}
		lines := strings.Split(string(data), "\n")
		for _, ln := range lines {
			s := strings.TrimSpace(ln)
			if s == "" || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "#") {
				continue
			}
			rr, err := dns.NewRR(s)
			if err != nil {
				log.Printf("initializeImrTrustAnchors: skipping unparsable line in %s: %q: %v", taFile, s, err)
				continue
			}
			switch t := rr.(type) {
			case *dns.DNSKEY:
				name := dns.Fqdn(t.Hdr.Name)
				dnskeysByName[name] = append(dnskeysByName[name], t)
			case *dns.DS:
				name := dns.Fqdn(t.Hdr.Name)
				dsByName[name] = append(dsByName[name], t)
			default:
				log.Printf("initializeImrTrustAnchors: ignoring non-TA RR in %s: %s", taFile, rr.String())
			}
		}
	}

	// Add direct DNSKEY anchors to cache as trusted
	for name, list := range dnskeysByName {
		log.Printf("initializeImrTrustAnchors: zone %q has DNSKEY TAs", name)
		exp := time.Now().Add(365 * 24 * time.Hour)
		for _, dk := range list {
			log.Printf("initializeImrTrustAnchors: zone %q adding DNSKEY TA (keyid: %d)\n", name, dk.KeyTag())
			DnskeyCache.Set(name, dk.KeyTag(), &CachedDnskeyRRset{
				Name:        name,
				Keyid:       dk.KeyTag(),
				Validated:   true,
				Trusted:     true,
				TrustAnchor: true,
				Dnskey:      *dk,
				Expiration:  exp,
			})
			log.Printf("initializeImrTrustAnchors: zone %q added DNSKEY TA (keyid: %d) (expires %v)", name, dk.KeyTag(), exp)
		}
	}

	// For each anchored name we know about (from DS or direct DNSKEY), fetch and validate
	seenNames := map[string]bool{}
	for name := range dnskeysByName {
		seenNames[name] = true
	}
	for name := range dsByName {
		seenNames[name] = true
	}
	for anchorName := range seenNames {
		// Seed DS RRset from trust anchors (if provided) into cache as validated,
		// so DNSKEY validation can find a validated DS RRset.
		if dslist := dsByName[anchorName]; len(dslist) > 0 {
			var rrds []dns.RR
			var minTTL uint32
			for i, ds := range dslist {
				rrds = append(rrds, ds)
				if i == 0 || ds.Hdr.Ttl < minTTL {
					minTTL = ds.Hdr.Ttl
				}
			}
			// Fallback TTL if not present in TA (e.g., config without TTL)
			if minTTL == 0 {
				minTTL = 86400
			}
			dsRRset := &RRset{
				Name:   anchorName,
				Class:  dns.ClassINET,
				RRtype: dns.TypeDS,
				RRs:    rrds,
				// No RRSIGs for TA-seeded DS; considered trusted
			}
			rrcache.Set(anchorName, dns.TypeDS, &CachedRRset{
				Name:       anchorName,
				RRtype:     dns.TypeDS,
				RRset:      dsRRset,
				Context:    ContextPriming,
				Validated:  true,
				Expiration: time.Now().Add(time.Duration(minTTL) * time.Second),
			})
			if Globals.Debug {
				log.Printf("initializeImrTrustAnchors: seeded validated DS RRset for %s with %d DS (TTL=%d)", anchorName, len(rrds), minTTL)
			}
		}

		// Fetch the DNSKEY RRset for the anchor, using current known servers
		serverMap, ok := rrcache.ServerMap.Get(anchorName)
		if !ok || len(serverMap) == 0 {
			// fallback to root servers if we do not have a server mapping for this name yet
			serverMap, ok = rrcache.ServerMap.Get(".")
			if !ok || len(serverMap) == 0 {
				return fmt.Errorf("no known servers for %q to fetch DNSKEY", anchorName)
			}
		}
		rrset, _, _, err := rrcache.IterativeDNSQuery(ctx, anchorName, dns.TypeDNSKEY, serverMap, false)
		if err != nil {
			return fmt.Errorf("failed to fetch %s DNSKEY: %v", anchorName, err)
		}
		if rrset == nil || len(rrset.RRs) == 0 {
			return fmt.Errorf("no %s DNSKEY RRset found", anchorName)
		}

		// Compute min TTL for expiration of added anchors
		var minTTL uint32
		if len(rrset.RRs) > 0 {
			minTTL = rrset.RRs[0].Header().Ttl
			for _, rr := range rrset.RRs[1:] {
				if rr.Header().Ttl < minTTL {
					minTTL = rr.Header().Ttl
				}
			}
		}
		exp := time.Now().Add(time.Duration(minTTL) * time.Second)

		// If DS present, match and add corresponding DNSKEY(s) to the TA store (trusted)
		if dslist := dsByName[anchorName]; len(dslist) > 0 {
			for _, rr := range rrset.RRs {
				dk, ok := rr.(*dns.DNSKEY)
				if !ok {
					continue
				}
				keyid := dk.KeyTag()
				for _, ds := range dslist {
					// match keytag first
					if ds.KeyTag != keyid {
						continue
					}
					computed := dk.ToDS(ds.DigestType)
					if computed == nil {
						continue
					}
					if strings.EqualFold(computed.Digest, ds.Digest) {
						cdr := CachedDnskeyRRset{
							Name:       dns.Fqdn(dk.Hdr.Name),
							Keyid:      keyid,
							Validated:  true,
							Trusted:    true,
							Dnskey:     *dk,
							Expiration: exp,
						}
						DnskeyCache.Set(cdr.Name, cdr.Keyid, &cdr)
						log.Printf("initializeImrTrustAnchors: DS matched DNSKEY %s::%d (expires %v)", cdr.Name, cdr.Keyid, exp)
					}
				}
			}
		}

		// Validate the DNSKEY RRset using the TA(s) in DnskeyCache
		valid, err := DnskeyCache.ValidateRRset(ctx, rrcache, rrset, true)
		if err != nil || !valid {
			return fmt.Errorf("failed to validate %s DNSKEY RRset: %v", anchorName, err)
		}
		// Mark cached DNSKEY RRset as validated
		if crr := rrcache.Get(anchorName, dns.TypeDNSKEY); crr != nil {
			crr.Validated = true
			rrcache.Set(anchorName, dns.TypeDNSKEY, crr)
		}
		// Since the DNSKEY RRset validated, mark all contained DNSKEYs as validated/trusted in DnskeyCache
		for _, rr := range rrset.RRs {
			if dk, ok := rr.(*dns.DNSKEY); ok {
				DnskeyCache.Set(anchorName, dk.KeyTag(), &CachedDnskeyRRset{
					Name:       anchorName,
					Keyid:      dk.KeyTag(),
					Validated:  true,
					Trusted:    true,
					Dnskey:     *dk,
					Expiration: exp,
				})
			}
		}

		// Fetch and validate the NS RRset for the anchor zone
		nsRRset, _, _, err := rrcache.IterativeDNSQuery(ctx, anchorName, dns.TypeNS, serverMap, false)
		if err != nil {
			return fmt.Errorf("failed to fetch %s NS RRset: %v", anchorName, err)
		}
		if nsRRset == nil || len(nsRRset.RRs) == 0 {
			return fmt.Errorf("no %s NS RRset found", anchorName)
		}
		valid, err = DnskeyCache.ValidateRRset(ctx, rrcache, nsRRset, true)
		if err != nil || !valid {
			return fmt.Errorf("failed to validate %s NS RRset: %v", anchorName, err)
		}
		// Mark cached NS RRset as validated
		if crr := rrcache.Get(anchorName, dns.TypeNS); crr != nil {
			crr.Validated = true
			rrcache.Set(anchorName, dns.TypeNS, crr)
		}
	}
	return nil
}

func createImrHandler(ctx context.Context, conf *Config, rrcache *RRsetCacheT) func(w dns.ResponseWriter, r *dns.Msg) {
	//	dnsupdateq := conf.Internal.DnsUpdateQ
	//	dnsnotifyq := conf.Internal.DnsNotifyQ
	//	kdb := conf.Internal.KeyDB

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name
		var dnssec_ok bool
		opt := r.IsEdns0()
		if opt != nil {
			dnssec_ok = opt.Do()
		}
		rd := r.MsgHdr.RecursionDesired
		// log.Printf("RecursionDesired: %v", rd)
		// log.Printf("DNSSEC OK: %v", dnssec_ok)

		qtype := r.Question[0].Qtype
		log.Printf("ImrHandler: received query for \"%s %s\" from %s (opcode: %s (%d))", qname, dns.TypeToString[qtype], w.RemoteAddr(), dns.OpcodeToString[r.Opcode], r.Opcode)

		switch r.Opcode {
		case dns.OpcodeNotify, dns.OpcodeUpdate:
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return

		case dns.OpcodeQuery:
			log.Printf("ImrHandler: Lookup request for \"%s %s\" (RD: %v, DO: %v) from %s", qname, dns.TypeToString[qtype], rd, dnssec_ok, w.RemoteAddr())

			qname = strings.ToLower(qname)
			if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
				DotServerQnameResponse(qname, w, r)
				return
			}

			rrcache.ImrResponder(ctx, w, r, qname, qtype, dnssec_ok)
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s", dns.OpcodeToString[r.Opcode])
		}
	}
}

func DotServerQnameResponse(qname string, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	qname = strings.ToLower(qname)
	// if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
	log.Printf("DnsHandler: Qname is '%s', which is not a known zone, but likely a query for the .server CH tld", qname)
	switch qname {
	case "id.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		v := viper.GetString("server.id")
		if v == "" {
			v = "tdnsd - an authoritative name server for experiments and POCs"
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 3600}, Txt: []string{v},
		})
	case "version.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		v := viper.GetString("server.version")
		if v == "" {
			v = fmt.Sprintf("%s version %s", Globals.App.Name, Globals.App.Version)
		} else if strings.Contains(v, "{version}") {
			v = strings.Replace(v, "{version}", Globals.App.Version, -1)
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 3600}, Txt: []string{v},
		})
	case "authors.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 3600},
			Txt: []string{
				"Johan Stenstam <johan.stenstam@internetstiftelsen.se>",
				"Erik Bergström <erik.bergstrom@internetstiftelsen.se>",
				"Leon Fernandez <leon.fernandez@internetstiftelsen.se>",
			},
		})

	case "hostname.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		v := viper.GetString("server.hostname")
		if v == "" {
			v = "a.random.internet.host."
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 3600}, Txt: []string{v},
		})
	default:
	}
	w.WriteMsg(m)
}
