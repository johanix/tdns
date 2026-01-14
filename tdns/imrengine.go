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
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"

	cache "github.com/johanix/tdns/tdns/cache"
	core  "github.com/johanix/tdns/tdns/core"
	edns0 "github.com/johanix/tdns/tdns/edns0"
	"github.com/miekg/dns"
)

type Imr struct {
	Cache       *cache.RRsetCacheT
	DnskeyCache *cache.DnskeyCacheT
	Options     map[ImrOption]string
	LineWidth   int // used to truncate long lines in logging and output (eg. DNSKEYs and RRSIGs)
	Verbose     bool
	Debug       bool
	Quiet       bool // if true, suppress informational logging (useful for CLI tools)
}

type ImrRequest struct {
	Qname      string
	Qtype      uint16
	Qclass     uint16
	ResponseCh chan ImrResponse
}

type ImrResponse struct {
	RRset     *core.RRset
	Validated bool
	Error     bool
	ErrorMsg  string
	Msg       string
}

// The ImrEngine is a simple caching DNS recursor. It is not a fully fledged, all singing,
// all dancing recursive server. It is just intended to get the job done for the particular cases
// that we need to support.

func (conf *Config) ImrEngine(ctx context.Context, quiet bool) error {
	var recursorch = conf.Internal.RecursorCh

	// IMR is active by default unless explicitly set to false
	isActive := conf.Imr.Active == nil || *conf.Imr.Active

	if !isActive {
		if !quiet {
			log.Printf("ImrEngine is NOT active (imrengine.active explicitly set to false).")
		}
		for {
			select {
			case <-ctx.Done():
				if !quiet {
					log.Printf("ImrEngine: terminating due to context cancelled (inactive mode)")
				}
				return nil
			case rrq, ok := <-recursorch:
				if !ok {
					return nil
				}
				if !quiet {
					log.Printf("ImrEngine: not active, but got a request: %v", rrq)
				}
				continue // ensure that we keep reading to keep the channel open
			}
		}
	} else {
		if !quiet {
			log.Printf("ImrEngine: Starting")
		}
	}

	// 1. Create the cache
	var err error
	rrcache := cache.NewRRsetCache(log.Default(), conf.Imr.Verbose, conf.Imr.Debug)
	rrcache.Quiet = quiet // Set quiet flag early, before any logging

	conf.Internal.RRsetCache = rrcache
	imr := &Imr{
		Cache:       rrcache,
		DnskeyCache: rrcache.DnskeyCache, // Use the same DnskeyCache instance as the cache
		Options:     conf.Imr.Options,
		LineWidth:   130, // default line width for truncating long lines in logging and output
		Verbose:     conf.Imr.Verbose,
		Debug:       conf.Imr.Debug,
		Quiet:       quiet, // Set quiet flag early, before any logging
	}

	if !rrcache.IsPrimed() {
		err = rrcache.PrimeWithHints(conf.Imr.RootHints, imr.IterativeDNSQueryFetcher())
		if err != nil {
			Shutdowner(conf, fmt.Sprintf("ImrEngine: failed to initialize RecursorCache w/ root hints: %v", err))
		}
		if len(conf.Imr.Stubs) > 0 {
			for _, stub := range conf.Imr.Stubs {
				stubservers := []string{}
				for _, server := range stub.Servers {
					stubservers = append(stubservers, server.Name+" ("+strings.Join(server.Addrs, ", ")+")")
				}
				if !quiet {
					log.Printf("ImrEngine: adding stub %q with servers %s", stub.Zone, strings.Join(stubservers, ", "))
				}
				imr.Cache.AddStub(stub.Zone, stub.Servers)
			}
		}
	}

	// Initialize trust anchors (DS/DNSKEY) and validate root (.) DNSKEY and NS
	if err := imr.initializeImrTrustAnchors(ctx, conf); err != nil {
		if !quiet {
			log.Printf("ImrEngine: trust anchor initialization failed: %v", err)
		}
	}

	// Start the ImrEngine (i.e. the recursive nameserver responding to queries with RD bit set)
	go imr.StartImrEngineListeners(ctx, conf)

	conf.Internal.ImrEngine = imr
	Globals.ImrEngine = imr

	for {
		select {
		case <-ctx.Done():
			if !quiet {
				log.Printf("ImrEngine: terminating due to context cancelled (active mode)")
			}
			return nil
		case rrq, ok := <-recursorch:
			if !ok {
				return nil
			}
			if rrq.ResponseCh == nil {
				if !quiet {
					log.Printf("ImrEngine: received nil or invalid request (no response channel)")
				}
				continue
			}
			if Globals.Debug {
				log.Printf("ImrEngine: received query for %s %s %s", rrq.Qname, dns.ClassToString[rrq.Qclass], dns.TypeToString[rrq.Qtype])
				fmt.Printf("ImrEngine: received query for %s %s %s\n", rrq.Qname, dns.ClassToString[rrq.Qclass], dns.TypeToString[rrq.Qtype])
			}

			var resp *ImrResponse

			// 1. Is the answer in the cache?
			crrset := imr.Cache.Get(rrq.Qname, rrq.Qtype)
			if crrset != nil {
				// Only use cached answer if it's a direct answer or negative response.
				// Don't use referrals, glue, hints, priming, or failures - issue a direct query instead
				// to get DNSSEC signatures and upgrade the quality of the data.
				switch crrset.Context {
				case cache.ContextAnswer, cache.ContextNoErrNoAns, cache.ContextNXDOMAIN:
					// These are direct answers or negative responses - safe to use
					if Globals.Debug {
						fmt.Printf("ImrEngine: cache hit for %s %s %s (context=%s)\n", rrq.Qname, dns.ClassToString[rrq.Qclass], dns.TypeToString[rrq.Qtype], cache.CacheContextToString[crrset.Context])
					}
					resp = &ImrResponse{
						RRset: crrset.RRset,
					}
					rrq.ResponseCh <- *resp
					continue // Skip query, we have a good answer
				case cache.ContextReferral, cache.ContextGlue, cache.ContextHint, cache.ContextPriming, cache.ContextFailure:
					// These are indirect - issue a direct query to upgrade quality and get DNSSEC signatures
					if Globals.Debug {
						log.Printf("ImrEngine: found <%s, %s> in cache with context=%s, but issuing direct query to upgrade quality and get DNSSEC signatures", rrq.Qname, dns.TypeToString[rrq.Qtype], cache.CacheContextToString[crrset.Context])
					}
					// Fall through to issue query
				default:
					// Unknown context - be safe and issue query
					if Globals.Debug {
						log.Printf("ImrEngine: found <%s, %s> in cache with unknown context=%s, issuing query", rrq.Qname, dns.TypeToString[rrq.Qtype], cache.CacheContextToString[crrset.Context])
					}
					// Fall through to issue query
				}
			}
			// Cache miss or indirect context - issue query
			{
				var err error
				if Globals.Debug {
					log.Printf("ImrEngine: <qname, qtype> tuple <%q, %s> not known, needs to be queried for", rrq.Qname, dns.TypeToString[rrq.Qtype])
					fmt.Printf("ImrEngine: <qname, qtype> tuple <%q, %s> not known, needs to be queried for\n", rrq.Qname, dns.TypeToString[rrq.Qtype])
				}

				resp, err = imr.ImrQuery(ctx, rrq.Qname, rrq.Qtype, rrq.Qclass, nil)
				if err != nil {
					log.Printf("ImrEngine: Error from ImrQuery: %v", err)
				} else if resp == nil {
					resp = &ImrResponse{
						Error:    true,
						ErrorMsg: fmt.Sprintf("ImrEngine: no response from ImrQuery"),
					}
				}
				rrq.ResponseCh <- *resp
			}
		}
	}
}

func (imr *Imr) ImrQuery(ctx context.Context, qname string, qtype uint16, qclass uint16, respch chan *ImrResponse) (*ImrResponse, error) {
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
			select {
			case respch <- &resp:
				// sent successfully
			case <-time.After(2 * time.Second):
				log.Printf("ImrQuery: timed out sending response to channel for <%s, %s>", qname, dns.TypeToString[qtype])
			}
		}()
	}

	//	dump.P(imr)

	crrset := imr.Cache.Get(qname, qtype)
	if crrset != nil {
		// Only use cached answer if it's a direct answer or negative response.
		// Don't use referrals, glue, hints, priming, or failures - issue a direct query instead
		// to get DNSSEC signatures and upgrade the quality of the data.
		switch crrset.Context {
		case cache.ContextAnswer, cache.ContextNoErrNoAns, cache.ContextNXDOMAIN:
			// These are direct answers or negative responses - safe to use
			if Globals.Debug {
				log.Printf("ImrQuery: found answer to <%s, %s> in cache (context=%s)", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
			}
			resp.RRset = crrset.RRset
			return &resp, nil
		case cache.ContextReferral, cache.ContextGlue, cache.ContextHint, cache.ContextPriming, cache.ContextFailure:
			// These are indirect - issue a direct query to upgrade quality and get DNSSEC signatures
			if Globals.Debug {
				log.Printf("ImrQuery: found <%s, %s> in cache with context=%s, but issuing direct query to upgrade quality and get DNSSEC signatures", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
			}
			// Fall through to issue query
		default:
			// Unknown context - be safe and issue query
			if Globals.Debug {
				log.Printf("ImrQuery: found <%s, %s> in cache with unknown context=%s, issuing query", qname, dns.TypeToString[qtype], cache.CacheContextToString[crrset.Context])
			}
			// Fall through to issue query
		}
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
		bestmatch, authservers, err := imr.Cache.FindClosestKnownZone(qname)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error from FindClosestKnownZone: %v", err)
			return &resp, err
		}
		if !imr.Quiet {
			log.Printf("ImrQuery: best zone match for qname %q seems to be %q", qname, bestmatch)
		}
		// ss := servers

		switch {
		case len(authservers) == 0:
			// Use helper function to resolve NS addresses
			done, err := imr.resolveNSAddresses(ctx, bestmatch, qname, qtype, authservers, func(authservers map[string]*cache.AuthServer) (bool, error) {
				rrset, rcode, context, err := imr.IterativeDNSQuery(ctx, qname, qtype, authservers, false)
				if err != nil {
					log.Printf("Error from IterativeDNSQuery: %v", err)
					// return false, nil // Continue trying
					return false, err
				}
				if rrset != nil {
					if Globals.Debug {
						log.Printf("ImrQuery: received response from IterativeDNSQuery:")
						for _, rr := range rrset.RRs {
							log.Printf("ImrQuery: %s", rr.String())
						}
					}
					resp.RRset = rrset
					return true, nil // Success, stop trying
				}
				if rcode == dns.RcodeNameError {
					// this is a negative response, which we need to figure out how to represent
					if !imr.Quiet {
						log.Printf("ImrQuery: received NXDOMAIN for qname %q, no point in continuing", qname)
					}
					resp.Msg = "NXDOMAIN (negative response type 3)"
					return true, nil // Success (negative response), stop trying
				}
				switch context {
				case cache.ContextReferral:
					return false, nil // Continue trying
				case cache.ContextNoErrNoAns:
					resp.Msg = "negative response type 0"
					return true, nil // Success (negative response), stop trying
				}
				return false, nil // Continue trying
			})
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return &resp, err
			}
			if done {
				return &resp, nil
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
			for name := range authservers {
				auths = append(auths, name)
			}
			log.Printf("ImrQuery: sending query \"%s %s\" to %d auth servers: %s", qname, dns.TypeToString[qtype], len(authservers), strings.Join(auths, ", "))
		}

		rrset, rcode, context, err := imr.IterativeDNSQuery(ctx, qname, qtype, authservers, false)
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
		case cache.ContextReferral:
			continue // if all is good we will now hit the new referral and get further
		case cache.ContextNoErrNoAns:
			resp.Msg = cache.CacheContextToString[context]
			return &resp, nil
		}
	}
}

// processAddressRecords processes A and AAAA records from an RRset and adds them to authservers
func (imr *Imr) processAddressRecords(rrset *core.RRset, authservers map[string]*cache.AuthServer) {
	if rrset == nil {
		return
	}
	for _, rr := range rrset.RRs {
		var nsname string
		var addr string
		var rrType string
		var ttl uint32
		switch rr := rr.(type) {
		case *dns.A:
			nsname = rr.Header().Name
			addr = rr.A.String()
			rrType = "A"
			ttl = rr.Header().Ttl
		case *dns.AAAA:
			nsname = rr.Header().Name
			addr = rr.AAAA.String()
			rrType = "AAAA"
			ttl = rr.Header().Ttl
		default:
			continue
		}

		// Use shared AuthServer instance (ensures single instance per nameserver)
		server := imr.Cache.GetOrCreateAuthServer(nsname)
		server.AddAddr(addr)
		server.SetSrc("answer")
		server.SetExpire(time.Now().Add(time.Duration(ttl) * time.Second))
		authservers[nsname] = server
		if Globals.Debug {
			log.Printf("processAddressRecords: using resolved %s address: %+v", rrType, authservers[nsname])
		}
	}
}

// resolveNSAddresses resolves nameserver addresses when authservers is empty.
// It calls onResponse for each successful address resolution, allowing the caller
// to handle the response appropriately. Returns true if a response was successfully
// handled, false if no usable address was found, and an error if something went wrong.
func (imr *Imr) resolveNSAddresses(ctx context.Context, bestmatch string, qname string, qtype uint16,
	authservers map[string]*cache.AuthServer,
	onResponse func(authservers map[string]*cache.AuthServer) (bool, error)) (bool, error) {

	log.Printf("resolveNSAddresses: we have no server addresses for zone %q needed to query for %q", bestmatch, qname)
	cnsrrset := imr.Cache.Get(bestmatch, dns.TypeNS)
	if cnsrrset == nil {
		log.Printf("resolveNSAddresses: we also have no nameservers for zone %q, giving up", bestmatch)
		return false, fmt.Errorf("no nameservers for zone %q", bestmatch)
	}

	log.Printf("resolveNSAddresses: but we do have the nameserver names: %v", cnsrrset.RRset.RRs)

	// Create response channel for A and AAAA queries
	respch := make(chan *ImrResponse, len(cnsrrset.RRset.RRs)*2) // *2 for both A and AAAA
	// Note: We don't need to close the channel here as it will be garbage collected
	// when it goes out of scope, even if there are still pending writes to it

	// Launch parallel queries for each nameserver
	err := imr.CollectNSAddresses(ctx, cnsrrset.RRset, respch)
	if err != nil {
		log.Printf("resolveNSAddresses: Error from CollectNSAddresses: %v", err)
		return false, err
	}

	// Process a bounded number of responses until we get a usable address
	want := len(cnsrrset.RRset.RRs) * 2
	for i := 0; i < want; i++ {
		var rrresp *ImrResponse
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case rrresp = <-respch:
		case <-time.After(3 * time.Second):
			rrresp = nil
		}
		if rrresp == nil || rrresp.RRset == nil {
			continue
		}

		// Process A/AAAA records and add to authservers
		imr.processAddressRecords(rrresp.RRset, authservers)

		// Call the callback to handle the response
		done, err := onResponse(authservers)
		if err != nil {
			return false, err
		}
		if done {
			return true, nil
		}
	}

	// If we get here, we tried all responses without finding a usable address
	log.Printf("resolveNSAddresses: failed to resolve query %q, %s, using any nameserver address", qname, dns.TypeToString[qtype])
	return false, nil
}

func (imr *Imr) ImrResponder(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, msgoptions *edns0.MsgOptions) {
	m := new(dns.Msg)
	m.RecursionAvailable = true

	crrset := imr.Cache.Get(qname, qtype)
	if crrset != nil {
		switch {
		case crrset.Rcode == uint8(dns.RcodeNameError) && crrset.Context == cache.ContextNXDOMAIN:
			m.SetRcode(r, dns.RcodeNameError)
			if !appendNegAuthorityToMessage(m, crrset.NegAuthority, msgoptions) && crrset.RRset != nil {
				appendSOAToMessage(crrset.RRset, msgoptions, m)
			}
			// if dnssec_ok && len(crrset.NegAuthority) > 0 && imr.Cache.ValidateNegativeResponse(ctx, qname, qtype, crrset.NegAuthority, imr.IterativeDNSQueryFetcher()) {
			//	m.AuthenticatedData = true
			// } else if crrset.Validated {
			//	m.AuthenticatedData = true
			// }
			m.AuthenticatedData = crrset.State == cache.ValidationStateSecure
			w.WriteMsg(m)
			return
		case crrset.Rcode == uint8(dns.RcodeSuccess) && crrset.Context == cache.ContextNoErrNoAns &&
			qtype != dns.TypeSOA:
			m.SetRcode(r, dns.RcodeSuccess)
			if !appendNegAuthorityToMessage(m, crrset.NegAuthority, msgoptions) && crrset.RRset != nil {
				appendSOAToMessage(crrset.RRset, msgoptions, m)
			}
			// if dnssec_ok && len(crrset.NegAuthority) > 0 && imr.Cache.ValidateNegativeResponse(ctx, qname, qtype, crrset.NegAuthority, imr.IterativeDNSQueryFetcher()) {
			//	m.AuthenticatedData = true
			// } else if crrset.Validated {
			//	m.AuthenticatedData = true
			// }
			m.AuthenticatedData = crrset.State == cache.ValidationStateSecure
			w.WriteMsg(m)
			return
		case crrset.Rcode == uint8(dns.RcodeSuccess) && crrset.Context == cache.ContextAnswer &&
			crrset.RRset != nil && crrset.RRset.RRtype == qtype:
			if !msgoptions.CD && (crrset.EDECode != 0 || crrset.State == cache.ValidationStateBogus) {
				m.Answer = nil
				m.Ns = nil
				m.SetRcode(r, dns.RcodeServerFailure)
				if crrset.EDECode != 0 {
					edns0.AttachEDEToResponseWithText(m, crrset.EDECode, crrset.EDEText, msgoptions.DO)
				}
				w.WriteMsg(m)
				return
			}
			m.SetRcode(r, dns.RcodeSuccess)
			m.Answer = crrset.RRset.RRs
			if msgoptions.DO {
				m.Answer = append(m.Answer, crrset.RRset.RRSIGs...)
			}
			// if crrset.Validated {
			//	m.AuthenticatedData = true
			// }
			m.AuthenticatedData = crrset.State == cache.ValidationStateSecure
			w.WriteMsg(m)
			return
		}
	}

	m.SetRcode(r, dns.RcodeServerFailure)
	if msgoptions.RD {
		log.Printf("ImrResponder: <qname, qtype> tuple <%q, %s> not known, needs to be queried for", qname, dns.TypeToString[qtype])
		maxiter := 12

		for {
			if maxiter <= 0 {
				log.Printf("*** ImrResponder: max iterations reached. Giving up.")
				return
			} else {
				maxiter--
			}
			bestmatch, authservers, err := imr.Cache.FindClosestKnownZone(qname)
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
				// Use helper function to resolve NS addresses
				// Note: The callback is called after processing each A/AAAA response.
				// We try the query for each address we discover, similar to the original code.
				done, err := imr.resolveNSAddresses(ctx, bestmatch, qname, qtype, authservers, func(authservers map[string]*cache.AuthServer) (bool, error) {
					// Try querying with the current set of authservers
					rrset, rcode, context, err := imr.IterativeDNSQuery(ctx, qname, qtype, authservers, false)
					if err != nil {
						log.Printf("Error from IterativeDNSQuery: %v", err)
						return false, nil // Continue trying with next address
					}
					done, err := imr.ProcessAuthDNSResponse(ctx, qname, qtype, rrset, rcode, context, msgoptions, m, w, r)
					if err != nil {
						return true, err // Error occurred, stop trying
					}
					if done {
						return true, nil // Success, stop trying
					}
					return false, nil // Continue trying with next address
				})
				if err != nil {
					m.SetRcode(r, dns.RcodeServerFailure)
					w.WriteMsg(m)
					return
				}
				if done {
					return
				}
				// If we get here, we tried all responses without finding a usable address
				log.Printf("*** ImrResponder: failed to resolve query %q, %s, using any nameserver address", qname, dns.TypeToString[qtype])
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}

			if Globals.Verbose {
				log.Printf("ImrResponder: sending \"%s %s\" query to %d authservers for %q", qname, dns.TypeToString[qtype],
					len(authservers), bestmatch)
			}
			rrset, rcode, context, err := imr.IterativeDNSQuery(ctx, qname, qtype, authservers, false)
			// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
			if err != nil {
				w.WriteMsg(m)
				return
			}
			done, err := imr.ProcessAuthDNSResponse(ctx, qname, qtype, rrset, rcode, context, msgoptions, m, w, r)
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
func (imr *Imr) ProcessAuthDNSResponse(ctx context.Context, qname string, qtype uint16, rrset *core.RRset, rcode int, context cache.CacheContext, msgoptions *edns0.MsgOptions, m *dns.Msg, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	log.Printf("ProcessAuthDNSResponse: qname: %q, rrset: %+v, rcode: %d, context: %d, DO: %v, CD: %v", qname, rrset, rcode, context, msgoptions.DO, msgoptions.CD)
	m.SetRcode(r, rcode)
	if rrset != nil {
		log.Printf("ImrResponder: received response from IterativeDNSQuery:")
		for _, rr := range rrset.RRs {
			log.Printf("ImrResponder: %s", rr.String())
		}
		m.Answer = rrset.RRs
		if msgoptions.DO {
			m.Answer = append(m.Answer, rrset.RRSIGs...)
		}
		// Set AD if this RRset is ValidationStateSecure (from cache or on-the-fly)
		vstate := cache.ValidationStateNone
		var err error
		shouldValidate := msgoptions.DO && !msgoptions.CD
		if imr.Cache != nil && shouldValidate {
			if c := imr.Cache.Get(rrset.Name, rrset.RRtype); c != nil && c.State == cache.ValidationStateSecure {
				vstate = c.State
			} else {
				vstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, rrset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
				if err != nil {
					log.Printf("ProcessAuthDNSResponse: failed to validate RRset: %v", err)
					m.SetRcode(r, dns.RcodeServerFailure)
					w.WriteMsg(m)
					return false, err
				}
			}
		}
		if vstate == cache.ValidationStateSecure && shouldValidate {
			m.AuthenticatedData = true
			w.WriteMsg(m)
			return true, nil
		}
		if !shouldValidate {
			w.WriteMsg(m)
			return true, nil
		}

		m.Answer = nil
		m.Ns = nil
		m.SetRcode(r, dns.RcodeServerFailure)
		edeCode, edeText := imr.Cache.MarkRRsetBogus(qname, qtype, rrset, msgoptions.DO)
		if msgoptions.DO && edeCode != 0 {
			edns0.AttachEDEToResponseWithText(m, edeCode, edeText, msgoptions.DO)
		}
		w.WriteMsg(m)
		return true, nil
	}
	switch context {
	case cache.ContextNXDOMAIN:
		m.SetRcode(r, dns.RcodeNameError)
		imr.serveNegativeResponse(ctx, qname, qtype, msgoptions, m, r)
		w.WriteMsg(m)
		return true, nil
	case cache.ContextReferral:
		// continue // if all is good we will now hit the new referral and get further
		return false, nil
	case cache.ContextNoErrNoAns:
		m.SetRcode(r, dns.RcodeSuccess)
		imr.serveNegativeResponse(ctx, qname, qtype, msgoptions, m, r)
		w.WriteMsg(m)
		return true, nil
	}
	return false, nil
}

func appendSOAToMessage(soa *core.RRset, msgoptions *edns0.MsgOptions, m *dns.Msg) {
	if soa == nil || m == nil {
		return
	}
	for _, rr := range soa.RRs {
		if rr == nil {
			continue
		}
		m.Ns = append(m.Ns, dns.Copy(rr))
	}
	if msgoptions.DO {
		for _, sig := range soa.RRSIGs {
			if sig == nil {
				continue
			}
			m.Ns = append(m.Ns, dns.Copy(sig))
		}
	}
}

func appendNegAuthorityToMessage(m *dns.Msg, neg []*core.RRset, msgoptions *edns0.MsgOptions) bool {
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
		if msgoptions.DO {
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

func buildNegAuthorityFromMsg(src *dns.Msg) []*core.RRset {
	if src == nil || len(src.Ns) == 0 {
		return nil
	}
	type key struct {
		name   string
		rrtype uint16
	}
	var order []key
	sets := make(map[key]*core.RRset)
	get := func(name string, rrtype uint16) *core.RRset {
		k := key{dns.CanonicalName(name), rrtype}
		if rs, ok := sets[k]; ok {
			return rs
		}
		rs := &core.RRset{Name: k.name, Class: dns.ClassINET, RRtype: rrtype}
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
	var out []*core.RRset
	for _, k := range order {
		if rs := sets[k]; rs != nil && (len(rs.RRs) > 0 || len(rs.RRSIGs) > 0) {
			out = append(out, rs)
		}
	}
	return out
}

func (imr *Imr) serveNegativeResponse(ctx context.Context, qname string, qtype uint16, msgoptions *edns0.MsgOptions, resp *dns.Msg, src *dns.Msg) bool {
	if resp == nil {
		return false
	}
	cached := imr.Cache.Get(qname, qtype)

	if msgoptions.CD {
		if cached != nil && cached.RRset != nil {
			appendSOAToMessage(cached.RRset, msgoptions, resp)
			return true
		}
		appendSOAFromMsg(src, msgoptions, resp)
		return true
	}

	if !msgoptions.DO {
		if cached != nil && cached.RRset != nil {
			appendSOAToMessage(cached.RRset, msgoptions, resp)
			if cached.State == cache.ValidationStateSecure {
				resp.AuthenticatedData = true
			}
			attachNegativeEDE(resp, msgoptions, cached)
			return true
		}
		attachNegativeEDE(resp, msgoptions, cached)
		appendSOAFromMsg(src, msgoptions, resp)
		return true
	}

	var neg []*core.RRset
	if cached != nil && len(cached.NegAuthority) > 0 {
		neg = cached.NegAuthority
		if appendNegAuthorityToMessage(resp, neg, msgoptions) {
			if cached.State == cache.ValidationStateSecure && msgoptions.DO {
				resp.AuthenticatedData = true
			}
			attachNegativeEDE(resp, msgoptions, cached)
			return true
		}
	}
	if cached != nil && cached.RRset != nil {
		appendSOAToMessage(cached.RRset, msgoptions, resp)
		if cached.State == cache.ValidationStateSecure {
			resp.AuthenticatedData = true
		}
		attachNegativeEDE(resp, msgoptions, cached)
		return true
	}
	neg = buildNegAuthorityFromMsg(src)
	if len(neg) > 0 && appendNegAuthorityToMessage(resp, neg, msgoptions) {
		// if msgoptions.DO && imr.Cache.ValidateNegativeResponse(ctx, qname, qtype, neg, imr.IterativeDNSQueryFetcher()) {
		//	resp.AuthenticatedData = true
		//}
		if cached != nil {
			resp.AuthenticatedData = cached.State == cache.ValidationStateSecure
		}
		attachNegativeEDE(resp, msgoptions, cached)
		return true
	}
	attachNegativeEDE(resp, msgoptions, cached)
	appendSOAFromMsg(src, msgoptions, resp)
	return true
}

func attachNegativeEDE(resp *dns.Msg, msgoptions *edns0.MsgOptions, cached *cache.CachedRRset) {
	if resp == nil || cached == nil || cached.EDECode == 0 {
		return
	}
	edns0.AttachEDEToResponseWithText(resp, cached.EDECode, cached.EDEText, msgoptions.DO)
}

func appendCachedNegativeSOA(rrcache *cache.RRsetCacheT, qname string, qtype uint16, msgoptions *edns0.MsgOptions, m *dns.Msg) bool {
	if rrcache == nil || m == nil {
		return false
	}
	cached := rrcache.Get(qname, qtype)
	if cached == nil || cached.RRset == nil {
		return false
	}
	appendSOAToMessage(cached.RRset, msgoptions, m)
	if cached.State == cache.ValidationStateSecure {
		m.AuthenticatedData = true
	}
	return true
}

func appendSOAFromMsg(r *dns.Msg, msgoptions *edns0.MsgOptions, m *dns.Msg) {
	if r == nil || len(r.Ns) == 0 {
		return
	}
	var soaRRset *core.RRset
	for _, rr := range r.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			if soaRRset == nil {
				soaRRset = &core.RRset{Name: rr.Header().Name, RRtype: dns.TypeSOA}
			}
			soaRRset.RRs = append(soaRRset.RRs, rr)
		case dns.TypeRRSIG:
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeSOA {
				if soaRRset == nil {
					soaRRset = &core.RRset{Name: rr.Header().Name, RRtype: dns.TypeSOA}
				}
				soaRRset.RRSIGs = append(soaRRset.RRSIGs, rr)
			}
		}
	}
	if soaRRset != nil {
		appendSOAToMessage(soaRRset, msgoptions, m)
	}
}

func (imr *Imr) StartImrEngineListeners(ctx context.Context, conf *Config) error {
	addresses := conf.Imr.Addresses
	if len(addresses) == 0 {
		if !imr.Quiet {
			log.Printf("ImrEngine: no addresses provided. The ImrEngine will only be an internal recursive resolver.")
		}
		return nil
	}

	ImrHandler := imr.createImrHandler(ctx, conf)

	// Create a local ServeMux for ImrEngine to avoid conflicts with other engines
	imrMux := dns.NewServeMux()
	imrMux.HandleFunc(".", ImrHandler)

	if CaseFoldContains(conf.Imr.Transports, "do53") {
		log.Printf("ImrEngine: UDP/TCP addresses: %v", addresses)
		servers := make([]*dns.Server, 0, len(addresses)*2)

		for _, addr := range addresses {
			for _, net := range []string{"udp", "tcp"} {
				server := &dns.Server{
					Addr:    addr,
					Net:     net,
					Handler: imrMux, // Use local mux instead of global handler
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

		if CaseFoldContains(conf.Imr.Transports, "dot") {
			err := DnsDoTEngine(ctx, conf, addresses, &cert, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoT server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoT")
		}

		if CaseFoldContains(conf.Imr.Transports, "doh") {
			err := DnsDoHEngine(ctx, conf, addresses, certFile, keyFile, ImrHandler)
			if err != nil {
				log.Printf("Failed to setup the DoH server: %s\n", err.Error())
			}
		} else {
			log.Printf("ImrEngine: Not serving on transport DoH")
		}

		if CaseFoldContains(conf.Imr.Transports, "doq") {
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

// parseTrustAnchorsFromConfig parses trust anchors from config and file into maps keyed by zone name.
// Returns maps of DS and DNSKEY trust anchors.
func (imr *Imr) parseTrustAnchorsFromConfig(conf *Config) (map[string][]*dns.DS, map[string][]*dns.DNSKEY, error) {
	dsByName := map[string][]*dns.DS{}
	dnskeysByName := map[string][]*dns.DNSKEY{}

	taDS := strings.TrimSpace(conf.Imr.TrustAnchorDS)
	taDNSKEY := strings.TrimSpace(conf.Imr.TrustAnchorDNSKEY)
	taFile := strings.TrimSpace(conf.Imr.TrustAnchorFile)

	// If DNSKEY TA is provided, add it directly
	if taDNSKEY != "" {
		rr, err := dns.NewRR(taDNSKEY)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse trust_anchor_dnskey: %v", err)
		}
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, nil, fmt.Errorf("trust_anchor_dnskey is not a DNSKEY RR: %T", rr)
		}
		name := dns.Fqdn(dk.Hdr.Name)
		dnskeysByName[name] = append(dnskeysByName[name], dk)
	}

	// If DS TA is provided, remember it for matching after fetching DNSKEY RRset
	if taDS != "" {
		rr, err := dns.NewRR(taDS)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse trust_anchor_ds: %v", err)
		}
		ds, ok := rr.(*dns.DS)
		if !ok {
			return nil, nil, fmt.Errorf("trust_anchor_ds is not a DS RR: %T", rr)
		}
		name := dns.Fqdn(ds.Hdr.Name)
		dsByName[name] = append(dsByName[name], ds)
		log.Printf("parseTrustAnchorsFromConfig: configured DS TA for %s keytag=%d digesttype=%d", name, ds.KeyTag, ds.DigestType)
	}

	// If trust-anchor-file is provided, read and parse all RRs
	if taFile != "" {
		data, err := os.ReadFile(taFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read trust-anchor-file %q: %v", taFile, err)
		}
		lines := strings.Split(string(data), "\n")
		for _, ln := range lines {
			s := strings.TrimSpace(ln)
			if s == "" || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "#") {
				continue
			}
			rr, err := dns.NewRR(s)
			if err != nil {
				log.Printf("parseTrustAnchorsFromConfig: skipping unparsable line in %s: %q: %v", taFile, s, err)
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
				log.Printf("parseTrustAnchorsFromConfig: ignoring non-TA RR in %s: %s", taFile, rr.String())
			}
		}
	}

	return dsByName, dnskeysByName, nil
}

// addDirectDNSKEYTrustAnchors adds direct DNSKEY trust anchors to the cache.
func (imr *Imr) addDirectDNSKEYTrustAnchors(dnskeysByName map[string][]*dns.DNSKEY) {
	for name, list := range dnskeysByName {
		log.Printf("initializeImrTrustAnchors: zone %q has DNSKEY TAs", name)
		exp := time.Now().Add(365 * 24 * time.Hour)
		for _, dk := range list {
			log.Printf("initializeImrTrustAnchors: zone %q adding DNSKEY TA (keyid: %d)", name, dk.KeyTag())
			imr.DnskeyCache.Set(name, dk.KeyTag(), &cache.CachedDnskeyRRset{
				Name:        name,
				Keyid:       dk.KeyTag(),
				State:       cache.ValidationStateSecure,
				TrustAnchor: true,
				Dnskey:      *dk,
				Expiration:  exp,
			})
			log.Printf("initializeImrTrustAnchors: zone %q added DNSKEY TA (keyid: %d) (expires %v)", name, dk.KeyTag(), exp)
		}
		// Add zone to ZoneMap as secure when DNSKEY trust anchor is added
		z, exists := imr.Cache.ZoneMap.Get(name)
		if !exists {
			z = &cache.Zone{
				ZoneName: name,
				State:    cache.ValidationStateSecure,
			}
		}
		z.SetState(cache.ValidationStateSecure)
		imr.Cache.ZoneMap.Set(name, z)
		if Globals.Debug {
			log.Printf("initializeImrTrustAnchors: zone %q added to ZoneMap as secure (DNSKEY trust anchor)", name)
		}
	}
}

// seedDSRRsetFromTrustAnchors seeds the DS RRset from trust anchors into the cache.
func (imr *Imr) seedDSRRsetFromTrustAnchors(anchorName string, dslist []*dns.DS) {
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
	dsRRset := &core.RRset{
		Name:   anchorName,
		Class:  dns.ClassINET,
		RRtype: dns.TypeDS,
		RRs:    rrds,
		// No RRSIGs for TA-seeded DS; considered trusted
	}
	imr.Cache.Set(anchorName, dns.TypeDS, &cache.CachedRRset{
		Name:       anchorName,
		RRtype:     dns.TypeDS,
		RRset:      dsRRset,
		Context:    cache.ContextPriming,
		State:      cache.ValidationStateSecure,
		Expiration: time.Now().Add(time.Duration(minTTL) * time.Second),
	})
	if Globals.Debug {
		log.Printf("initializeImrTrustAnchors: seeded validated DS RRset for %s with %d DS (TTL=%d)", anchorName, len(rrds), minTTL)
	}
}

// matchDSTrustAnchorsToDNSKEYs matches DS trust anchors to DNSKEYs in the fetched RRset.
func (imr *Imr) matchDSTrustAnchorsToDNSKEYs(anchorName string, dslist []*dns.DS, rrset *core.RRset, exp time.Time) {
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
				// This DNSKEY matches the DS trust anchor, so it's validated
				// Add it to DnskeyCache immediately so it can be used to validate the DNSKEY RRset's signatures
				cdr := cache.CachedDnskeyRRset{
					Name:        dns.Fqdn(dk.Hdr.Name),
					Keyid:       keyid,
					TrustAnchor: true,
					State:       cache.ValidationStateSecure,
					Dnskey:      *dk,
					Expiration:  exp,
				}
				imr.DnskeyCache.Set(cdr.Name, cdr.Keyid, &cdr)
				log.Printf("initializeImrTrustAnchors: DS matched DNSKEY %s::%d (expires %v)", cdr.Name, cdr.Keyid, exp)
			}
		}
	}
}

// validateDNSKEYRRsetUsingSeededDS attempts to validate a DNSKEY RRset using seeded DS trust anchors.
// Returns true if validation succeeded, false otherwise.
func (imr *Imr) validateDNSKEYRRsetUsingSeededDS(anchorName string, rrset *core.RRset, verbose bool) bool {
	name := dns.Fqdn(anchorName)
	seededDS := imr.Cache.Get(anchorName, dns.TypeDS)
	if seededDS == nil || seededDS.State != cache.ValidationStateSecure || seededDS.RRset == nil {
		return false
	}
	for _, rr := range seededDS.RRset.RRs {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		valid, _ := cache.ValidateDNSKEYRRsetUsingDS(rrset, ds, name, verbose)
		if valid {
			if verbose {
				log.Printf("validateDNSKEYRRsetUsingSeededDS: %s DNSKEY RRset validated using DS trust anchor (keytag=%d)", anchorName, ds.KeyTag)
			}
			return true
		}
	}
	return false
}

// validateDNSKEYRRsetUsingDirectTA attempts to validate a DNSKEY RRset using direct DNSKEY trust anchors.
// Returns true if validation succeeded, false otherwise.
func (imr *Imr) validateDNSKEYRRsetUsingDirectTA(anchorName string, rrset *core.RRset, verbose bool) bool {
	name := dns.Fqdn(anchorName)
	dkc := imr.DnskeyCache
	for item := range dkc.Map.IterBuffered() {
		if item.Val.Name == name && item.Val.TrustAnchor && item.Val.State == cache.ValidationStateSecure {
			valid, _ := cache.ValidateDNSKEYRRsetSignature(rrset, item.Val.Keyid, name, &item.Val.Dnskey, verbose)
			if valid {
				if verbose {
					log.Printf("validateDNSKEYRRsetUsingDirectTA: %s DNSKEY RRset validated using direct DNSKEY trust anchor (keytag=%d)", anchorName, item.Val.Keyid)
				}
				return true
			}
		}
	}
	return false
}

// createOrUpdateCachedDNSKEYRRset creates a new CachedRRset or updates an existing one with validated state.
func (imr *Imr) createOrUpdateCachedDNSKEYRRset(anchorName string, rrset *core.RRset, crr *cache.CachedRRset, vstate cache.ValidationState) *cache.CachedRRset {
	if crr == nil {
		// Create new cached RRset if it doesn't exist (shouldn't happen, but be safe)
		minTTL := cache.GetMinTTL(rrset.RRs)
		if minTTL <= 0 {
			minTTL = 86400 * time.Second
		}
		return &cache.CachedRRset{
			Name:       anchorName,
			RRtype:     dns.TypeDNSKEY,
			Rcode:      uint8(dns.RcodeSuccess),
			RRset:      rrset,
			Context:    cache.ContextPriming,
			State:      vstate,
			Expiration: time.Now().Add(minTTL),
		}
	}
	// Update existing cached RRset
	crr.State = vstate
	return crr
}

// validateAndCacheDNSKEYRRset validates the DNSKEY RRset using trust anchors directly,
// bypassing the normal validation chain which may fail for indeterminate zones.
// It uses helper functions to validate against DS TAs and direct DNSKEY TAs.
func (imr *Imr) validateAndCacheDNSKEYRRset(ctx context.Context, anchorName string, rrset *core.RRset) error {
	// Check if the DNSKEY RRset is already validated in cache (from IterativeDNSQuery)
	crr := imr.Cache.Get(anchorName, dns.TypeDNSKEY)
	var vstate cache.ValidationState
	if crr != nil && crr.State == cache.ValidationStateSecure {
		// Already validated, use the cached state
		vstate = crr.State
		if Globals.Debug {
			log.Printf("initializeImrTrustAnchors: %s DNSKEY RRset already validated in cache", anchorName)
		}
	} else {
		// Not validated yet, validate using trust anchors directly
		// This bypasses the normal validation chain which may fail for indeterminate zones
		verbose := Globals.Debug
		validated := false

		// First, try validation using seeded DS trust anchors
		if imr.validateDNSKEYRRsetUsingSeededDS(anchorName, rrset, verbose) {
			validated = true
		}

		// If DS validation didn't work, try direct DNSKEY trust anchors
		if !validated {
			if imr.validateDNSKEYRRsetUsingDirectTA(anchorName, rrset, verbose) {
				validated = true
			}
		}

		if !validated {
			log.Printf("validateAndCacheDNSKEYRRset: %q DNSKEY RRset failed to validate using trust anchors", anchorName)
			return fmt.Errorf("failed to validate %q DNSKEY RRset using trust anchors", anchorName)
		}

		vstate = cache.ValidationStateSecure
		// Update cached RRset with validated state
		crr = imr.createOrUpdateCachedDNSKEYRRset(anchorName, rrset, crr, vstate)
		imr.Cache.Set(anchorName, dns.TypeDNSKEY, crr)
	}
	return nil
}

// updateDNSKEYCacheFromRRset updates the DNSKEY cache from a validated RRset, preserving trust anchor flags.
func (imr *Imr) updateDNSKEYCacheFromRRset(anchorName string, rrset *core.RRset, exp time.Time, dnskeysByName map[string][]*dns.DNSKEY) {
	// Since the DNSKEY RRset validated, mark all contained DNSKEYs as validated in DnskeyCache.
	// IMPORTANT: Preserve TrustAnchor flag if a DNSKEY was already marked as a trust anchor.
	// Check both the cache and the dnskeysByName map to determine if a DNSKEY is a trust anchor.
	trustAnchorKeys := map[uint16]bool{}
	if dnskeyList, exists := dnskeysByName[anchorName]; exists {
		for _, dk := range dnskeyList {
			trustAnchorKeys[dk.KeyTag()] = true
		}
	}

	for _, rr := range rrset.RRs {
		if dk, ok := rr.(*dns.DNSKEY); ok {
			keyid := dk.KeyTag()
			// Check if this DNSKEY was already in the cache as a trust anchor
			existing := imr.DnskeyCache.Get(anchorName, keyid)
			trustAnchor := false
			if existing != nil {
				trustAnchor = existing.TrustAnchor
			}
			// Also check if this DNSKEY was in the original trust anchor list
			if !trustAnchor && trustAnchorKeys[keyid] {
				trustAnchor = true
			}
			cdr := cache.CachedDnskeyRRset{
				Name:        anchorName,
				Keyid:       keyid,
				State:       cache.ValidationStateSecure,
				TrustAnchor: trustAnchor, // Preserve trust anchor flag
				Dnskey:      *dk,
				Expiration:  exp,
			}
			imr.DnskeyCache.Set(anchorName, keyid, &cdr)
			if trustAnchor {
				log.Printf("initializeImrTrustAnchors: DNSKEY %s::%d (trust anchor, expires %v)", cdr.Name, cdr.Keyid, exp)
			} else {
				log.Printf("initializeImrTrustAnchors: DNSKEY %s::%d (expires %v)", cdr.Name, cdr.Keyid, exp)
			}
		}
	}
}

// validateNSRRsetForAnchor validates the NS RRset for a trust anchor zone.
func (imr *Imr) validateNSRRsetForAnchor(ctx context.Context, anchorName string, serverMap map[string]*cache.AuthServer) {
	// Fetch and validate the NS RRset for the anchor zone (non-fatal - continue even if it fails)
	nsRRset, _, _, err := imr.IterativeDNSQuery(ctx, anchorName, dns.TypeNS, serverMap, true)
	if err != nil {
		log.Printf("initializeImrTrustAnchors: warning: failed to fetch %s NS RRset: %v (continuing)", anchorName, err)
		return
	}
	if nsRRset == nil || len(nsRRset.RRs) == 0 {
		log.Printf("initializeImrTrustAnchors: warning: no %s NS RRset found (continuing)", anchorName)
		return
	}
	// Check if the NS RRset is already validated in cache (from IterativeDNSQuery)
	nsCrr := imr.Cache.Get(anchorName, dns.TypeNS)
	var nsVstate cache.ValidationState
	if nsCrr != nil && nsCrr.State == cache.ValidationStateSecure {
		// Already validated, use the cached state
		nsVstate = nsCrr.State
		if Globals.Debug {
			log.Printf("initializeImrTrustAnchors: %s NS RRset already validated in cache", anchorName)
		}
	} else {
		// Not validated yet, validate it now
		nsVstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, nsRRset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
		if err != nil {
			log.Printf("initializeImrTrustAnchors: warning: failed to validate %s NS RRset: %v (continuing)", anchorName, err)
			return
		}
		if nsVstate != cache.ValidationStateSecure {
			log.Printf("initializeImrTrustAnchors: warning: %q NS RRset failed to validate (vstate: %s) (continuing)", anchorName, cache.ValidationStateToString[nsVstate])
			return
		}
		// Update cached NS RRset with validated state
		if nsCrr == nil {
			// Create new cached RRset if it doesn't exist (shouldn't happen, but be safe)
			minTTL := cache.GetMinTTL(nsRRset.RRs)
			if minTTL <= 0 {
				minTTL = 86400 * time.Second
			}
			nsCrr = &cache.CachedRRset{
				Name:       anchorName,
				RRtype:     dns.TypeNS,
				Rcode:      uint8(dns.RcodeSuccess),
				RRset:      nsRRset,
				Context:    cache.ContextPriming,
				State:      nsVstate,
				Expiration: time.Now().Add(minTTL),
			}
		} else {
			// Update existing cached RRset
			nsCrr.State = nsVstate
		}
		imr.Cache.Set(anchorName, dns.TypeNS, nsCrr)
	}
}

// processTrustAnchorZone processes a single trust anchor zone: fetches, validates, and caches DNSKEY and NS RRsets.
func (imr *Imr) processTrustAnchorZone(ctx context.Context, anchorName string, dsByName map[string][]*dns.DS, dnskeysByName map[string][]*dns.DNSKEY) error {
	log.Printf("initializeImrTrustAnchors: processing anchor %q", anchorName)

	// Seed DS RRset from trust anchors (if provided) into cache as validated,
	// so DNSKEY validation can find a validated DS RRset.
	if dslist := dsByName[anchorName]; len(dslist) > 0 {
		imr.seedDSRRsetFromTrustAnchors(anchorName, dslist)
	}

	// Fetch the DNSKEY RRset for the anchor, using current known servers
	serverMap, ok := imr.Cache.ServerMap.Get(anchorName)
	if !ok || len(serverMap) == 0 {
		// fallback to root servers if we do not have a server mapping for this name yet
		serverMap, ok = imr.Cache.ServerMap.Get(".")
		if !ok || len(serverMap) == 0 {
			return fmt.Errorf("no known servers for %q to fetch DNSKEY", anchorName)
		}
	}
	rrset, _, _, err := imr.IterativeDNSQuery(ctx, anchorName, dns.TypeDNSKEY, serverMap, true)
	if err != nil {
		return fmt.Errorf("failed to fetch %s DNSKEY: %v", anchorName, err)
	}
	if rrset == nil || len(rrset.RRs) == 0 {
		return fmt.Errorf("no %s DNSKEY RRset found", anchorName)
	}

	minTTL := cache.GetMinTTL(rrset.RRs)
	exp := time.Now().Add(minTTL)

	// If DS present, match and add corresponding DNSKEY(s) to the TA store (trusted)
	if dslist := dsByName[anchorName]; len(dslist) > 0 {
		imr.matchDSTrustAnchorsToDNSKEYs(anchorName, dslist, rrset, exp)
	}

	// Validate and cache the DNSKEY RRset
	if err := imr.validateAndCacheDNSKEYRRset(ctx, anchorName, rrset); err != nil {
		return err
	}

	// Update DNSKEY cache from validated RRset, preserving trust anchor flags
	imr.updateDNSKEYCacheFromRRset(anchorName, rrset, exp, dnskeysByName)

	// Add zone to ZoneMap as secure when DNSKEY RRset validates (DS trust anchor validated)
	z, exists := imr.Cache.ZoneMap.Get(anchorName)
	if !exists {
		z = &cache.Zone{
			ZoneName: anchorName,
			State:    cache.ValidationStateIndeterminate,
		}
	}
	z.SetState(cache.ValidationStateSecure)
	imr.Cache.ZoneMap.Set(anchorName, z)
	if Globals.Debug {
		log.Printf("initializeImrTrustAnchors: zone %q added to ZoneMap as secure (DS trust anchor validated)", anchorName)
	}

	// Validate NS RRset (non-fatal)
	imr.validateNSRRsetForAnchor(ctx, anchorName, serverMap)

	return nil
}

// initializeImrTrustAnchors loads trust anchors from config:
// - DS/DNSKEY strings (single)
// - trust-anchor-file (multiple lines)
// For each anchored name, it loads direct DNSKEY TAs (trusted), matches DS→DNSKEY(s),
// validates the anchored DNSKEY RRset and then validates the NS RRset for that name.
func (imr *Imr) initializeImrTrustAnchors(ctx context.Context, conf *Config) error {
	// Only act if we have any trust-anchor configured
	taDS := strings.TrimSpace(conf.Imr.TrustAnchorDS)
	taDNSKEY := strings.TrimSpace(conf.Imr.TrustAnchorDNSKEY)
	taFile := strings.TrimSpace(conf.Imr.TrustAnchorFile)
	if taDS == "" && taDNSKEY == "" && taFile == "" {
		return nil
	}

	// Parse trust anchors from config and file
	dsByName, dnskeysByName, err := imr.parseTrustAnchorsFromConfig(conf)
	if err != nil {
		return err
	}

	// Add direct DNSKEY trust anchors to cache first
	imr.addDirectDNSKEYTrustAnchors(dnskeysByName)

	// Collect all anchor names (from both DS and DNSKEY trust anchors)
	seenNames := map[string]bool{}
	for name := range dnskeysByName {
		seenNames[name] = true
	}
	for name := range dsByName {
		seenNames[name] = true
	}

	// Process zones in deterministic order: root first, then others sorted
	anchorNames := make([]string, 0, len(seenNames))
	hasRoot := false
	for name := range seenNames {
		if name == "." {
			hasRoot = true
		} else {
			anchorNames = append(anchorNames, name)
		}
	}
	sort.Strings(anchorNames)
	if hasRoot {
		anchorNames = append([]string{"."}, anchorNames...)
	}
	log.Printf("initializeImrTrustAnchors: processing %d anchored names in order: %v", len(anchorNames), anchorNames)

	// Process each trust anchor zone
	for _, anchorName := range anchorNames {
		if err := imr.processTrustAnchorZone(ctx, anchorName, dsByName, dnskeysByName); err != nil {
			return err
		}
	}

	return nil
}

func (imr *Imr) createImrHandler(ctx context.Context, conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
	//	dnsupdateq := conf.Internal.DnsUpdateQ
	//	dnsnotifyq := conf.Internal.DnsNotifyQ
	//	kdb := conf.Internal.KeyDB

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name
		// var dnssec_ok bool
		msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(r)
		if err != nil {
			log.Printf("ImrHandler: error extracting EDNS0 options: %v", err)
		}

		qtype := r.Question[0].Qtype
		log.Printf("ImrHandler: received query for \"%s %s\" from %s (opcode: %s (%d))", qname, dns.TypeToString[qtype], w.RemoteAddr(), dns.OpcodeToString[r.Opcode], r.Opcode)

		switch r.Opcode {
		case dns.OpcodeNotify, dns.OpcodeUpdate:
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return

		case dns.OpcodeQuery:
			log.Printf("ImrHandler: Lookup request for \"%s %s\" (RD: %v, DO: %v) from %s", qname, dns.TypeToString[qtype], msgoptions.RD, msgoptions.DO, w.RemoteAddr())

			qname = strings.ToLower(qname)
			if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
				DotServerQnameResponse(qname, w, r)
				return
			}

			imr.ImrResponder(ctx, w, r, qname, qtype, msgoptions)
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
