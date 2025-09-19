/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
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

func (conf *Config) RecursorEngine(stopch chan struct{}) {
	var recursorch = conf.Internal.RecursorCh

	if !viper.GetBool("recursorengine.active") {
		log.Printf("RecursorEngine is NOT active.")
		for rrq := range recursorch {
			log.Printf("RecursorEngine: not active, but got a request: %v", rrq)
			continue // ensure that we keep reading to keep the channel open
		}
	} else {
		log.Printf("RecursorEngine: Starting")
	}

	// 1. Create the cache
	var err error
	// RecursorCache, err = NewRRsetCacheNG(viper.GetString("recursorengine.root-hints"))
	rrcache := NewRRsetCache(log.Default(), conf.ImrEngine.Verbose, conf.ImrEngine.Debug)
	if !rrcache.Primed {
		err = rrcache.PrimeWithHints(viper.GetString("recursorengine.root-hints"))
		if err != nil {
			Shutdowner(conf, fmt.Sprintf("RecursorEngine: failed to initialize RecursorCache w/ root hints: %v", err))
		}
		if len(conf.ImrEngine.Stubs) > 0 {
			for _, stub := range conf.ImrEngine.Stubs {
				log.Printf("RecursorEngine: adding stub %q with servers %+v", stub.Zone, stub.Servers)
				rrcache.AddStub(stub.Zone, stub.Servers)
			}
		}
	}

	conf.Internal.RRsetCache = rrcache

	// Start the ImrEngine (i.e. the recursive nameserver responding to queries with RD bit set)
	go rrcache.ImrEngine(conf, stopch)

	for rrq := range recursorch {
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
		} else {
			var err error
			log.Printf("Recursor: <qname, qtype> tuple <%q, %s> not known, needs to be queried for", rrq.Qname, dns.TypeToString[rrq.Qtype])
			fmt.Printf("Recursor: <qname, qtype> tuple <%q, %s> not known, needs to be queried for\n", rrq.Qname, dns.TypeToString[rrq.Qtype])
			resp, err = rrcache.ImrQuery(rrq.Qname, rrq.Qtype, rrq.Qclass, nil)
			if err != nil {
				log.Printf("Error from IterateOverQuery: %v", err)
			}
		}
		if rrq.ResponseCh != nil {
			rrq.ResponseCh <- *resp
		}
	}
}

func (rrcache *RRsetCacheT) ImrQuery(qname string, qtype uint16, qclass uint16, respch chan *ImrResponse) (*ImrResponse, error) {
	log.Printf("ImrQuery: <%s, %s> not known, needs to be queried for", qname, dns.TypeToString[qtype])
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
			return nil, fmt.Errorf("Max iterations reached. Giving up.")
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
			err := rrcache.CollectNSAddresses(cnsrrset.RRset, respch)
			if err != nil {
				log.Printf("Error from CollectNSAddresses: %v", err)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Error from CollectNSAddresses: %v", err)
				return &resp, err
			}

			// Process responses until we get a usable address
			for rrresp := range respch {
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
						log.Printf("ImrResponder: using resolved A address: %+v", authservers)
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
						log.Printf("ImrResponder: using resolved AAAA address: %+v", authservers)
					}

					rrset, rcode, context, err := rrcache.IterativeDNSQuery(qname, qtype, authservers, false)
					if err != nil {
						log.Printf("Error from IterativeDNSQuery: %v", err)
						continue
					}
					if rrset != nil {
						log.Printf("ImrQuery: received response from IterativeDNSQuery:")
						for _, rr := range rrset.RRs {
							log.Printf("ImrQuery: %s", rr.String())
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

		log.Printf("ImrQuery: sending query to %d auth servers: %+v", len(authservers), authservers)
		rrset, rcode, context, err := rrcache.IterativeDNSQuery(qname, qtype, authservers, false)
		// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error from IterativeDNSQuery: %v", err)
			return &resp, err
		}

		if rrset != nil {
			log.Printf("ImrQuery: received response from IterativeDNSQuery:")
			for _, rr := range rrset.RRs {
				log.Printf("ImrQuery: %s", rr.String())
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

func (rrcache *RRsetCacheT) ImrResponder(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, dnssec_ok bool) {
	rd_bit := r.MsgHdr.RecursionDesired
	m := new(dns.Msg)
	m.RecursionAvailable = true

	crrset := rrcache.Get(qname, qtype)
	if crrset != nil {
		m.SetRcode(r, dns.RcodeSuccess)
		// resp.RRset = crrset.RRset
		m.Answer = crrset.RRset.RRs
		if dnssec_ok {
			m.Answer = append(m.Answer, crrset.RRset.RRSIGs...)
		}
		// XXX: need to fill in more things in the response msg
		w.WriteMsg(m)
		return
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
				err := rrcache.CollectNSAddresses(cnsrrset.RRset, respch)
				if err != nil {
					log.Printf("Error from CollectNSAddresses: %v", err)
					// m.SetRcode(r, dns.RcodeServerFailure)
					w.WriteMsg(m)
					return
				}

				// Process responses until we get a usable address
				for resp := range respch {
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
						rrset, rcode, context, err := rrcache.IterativeDNSQuery(qname, qtype, authservers, false)
						if err != nil {
							log.Printf("Error from IterativeDNSQuery: %v", err)
							continue
						}
						done, err := ProcessAuthDNSResponse(qname, rrset, rcode, context, dnssec_ok, m, w, r)
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
			rrset, rcode, context, err := rrcache.IterativeDNSQuery(qname, qtype, authservers, false)
			// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
			if err != nil {
				w.WriteMsg(m)
				return
			}
			done, err := ProcessAuthDNSResponse(qname, rrset, rcode, context, dnssec_ok, m, w, r)
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
func ProcessAuthDNSResponse(qname string, rrset *RRset, rcode int, context CacheContext, dnssec_ok bool, m *dns.Msg, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
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
		w.WriteMsg(m)
		return true, nil
	}
	if rcode == dns.RcodeNameError {
		// this is a negative response, which we need to figure out how to represent
		log.Printf("ImrResponder: received NXDOMAIN for qname %q, no point in continuing", qname)
		// resp.Msg = "NXDOMAIN (negative response type 3)"
		// m.SetRcode(r, rcode)
		// XXX: we need the contents of the Authority section here
		w.WriteMsg(m)
		return true, nil
	}
	switch context {
	case ContextReferral:
		// continue // if all is good we will now hit the new referral and get further
		return false, nil
	case ContextNoErrNoAns:
		// resp.Msg = "negative response type 0"
		// break outerLoop
		m.SetRcode(r, dns.RcodeSuccess)
		w.WriteMsg(m)
		return true, nil
	}
	return false, nil
}

func (rrcache *RRsetCacheT) FindClosestKnownZone(qname string) (string, map[string]*AuthServer, error) {
	// Iterate through known zone names and return the longest match.
	var bestmatch string
	// var servers []string
	var servers map[string]*AuthServer
	log.Printf("FindClosestKnownZone: checking qname %q against %d zones with data in cache", qname, rrcache.Servers.Count())
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

	log.Printf("FindClosestKnownZone: authservers for zone %q: %+v", qname, servers)
	return bestmatch, servers, nil
}

func (rrcache *RRsetCacheT) ImrEngine(conf *Config, done chan struct{}) error {
	ImrHandler := createImrHandler(conf, rrcache)
	dns.HandleFunc(".", ImrHandler)

	addresses := viper.GetStringSlice("imrengine.addresses")
	if CaseFoldContains(conf.ImrEngine.Transports, "do53") {
		log.Printf("ImrEngine: UDP/TCP addresses: %v", addresses)
		for _, addr := range addresses {
			for _, net := range []string{"udp", "tcp"} {
				go func(addr, net string) {
					log.Printf("ImrEngine: serving on %s (%s)\n", addr, net)
					server := &dns.Server{
						Addr: addr,
						Net:  net,
						// MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
					}

					// Must bump the buffer size of incoming UDP msgs, as updates
					// may be much larger then queries
					// server.UDPSize = dns.DefaultMsgSize // 4096
					if err := server.ListenAndServe(); err != nil {
						log.Printf("Failed to setup the %s server: %s", net, err.Error())
					} else {
						log.Printf("ImrEngine: listening on %s/%s", addr, net)
					}
				}(addr, net)
			}
		}
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
			err := DnsDoTEngine(conf, addresses, &cert, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoT server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoT")
		}

		if CaseFoldContains(conf.ImrEngine.Transports, "doh") {
			err := DnsDoHEngine(conf, addresses, certFile, keyFile, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoH server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoH")
		}

		if CaseFoldContains(conf.ImrEngine.Transports, "doq") {
			err := DnsDoQEngine(conf, addresses, &cert, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoQ server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoQ")
		}
	}
	return nil
}

func createImrHandler(conf *Config, rrcache *RRsetCacheT) func(w dns.ResponseWriter, r *dns.Msg) {
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
		log.Printf("RecursionDesired: %v", rd)
		// log.Printf("DNSSEC OK: %v", dnssec_ok)

		qtype := r.Question[0].Qtype
		log.Printf("ImrHandler: qname: %s qtype: %s opcode: %s (%d)", qname, dns.TypeToString[qtype], dns.OpcodeToString[r.Opcode], r.Opcode)

		switch r.Opcode {
		case dns.OpcodeNotify, dns.OpcodeUpdate:
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return

		case dns.OpcodeQuery:
			log.Printf("Lookup request for %s %s from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())

			qname = strings.ToLower(qname)
			if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
				DotServerQnameResponse(qname, w, r)
				return
			}

			go rrcache.ImrResponder(w, r, qname, qtype, dnssec_ok)
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
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{v},
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
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{v},
		})
	case "authors.server.":
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
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
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{v},
		})
	default:
	}
	w.WriteMsg(m)
}
