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

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

var lgImr = Logger("engine")

type Imr struct {
	Cache       *cache.RRsetCacheT
	DnskeyCache *cache.DnskeyCacheT
	Options     map[ImrOption]string
	LineWidth   int // used to truncate long lines in logging and output (eg. DNSKEYs and RRSIGs)
	Verbose     bool
	Debug       bool
	Quiet       bool        // if true, suppress informational logging (useful for CLI tools)
	DebugLog    *log.Logger // non-nil when imr debug logging is enabled
	// RequireDnssecValidation: when true, security-sensitive lookups (TLSA, etc.) require
	// a secure DNSSEC validation state. Default true; set false in lab environments where
	// the full DNSSEC chain is not yet established.
	RequireDnssecValidation bool
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

// InitImrEngine creates and initializes the Imr (cache, stubs, debug logging)
// and wires it into conf.Internal.ImrEngine and Globals.ImrEngine. This is
// safe to call synchronously before other engines start, guaranteeing that the
// Imr is available by the time transport bridges and agent registries are created.
//
// Apps that need the IMR available early (e.g. mpagent) call this before
// StartEngine("ImrEngine", ...). Apps that don't need early availability can
// just call ImrEngine() which calls InitImrEngine() internally if needed.
//
// Idempotent: if conf.Internal.ImrEngine is already set, returns nil without
// touching any state. The IMR is a process singleton by intent — its priming
// cache, root hints, and validation state are expensive to construct and
// would diverge between two instances. The guard at the top of this function
// makes that singleton property hold by construction, regardless of which
// application initialises the IMR or in what order. First-init wins; the
// `quiet` parameter on subsequent calls is ignored.
//
// IMPORTANT: tdns-mp depends on this split. The mpagent calls InitImrEngine()
// synchronously at startup so that conf.Internal.ImrEngine is guaranteed
// non-nil before transport bridges and agent registries are created. Without
// this, the *tdnsmp.Imr embedding wraps a nil *tdns.Imr and promoted method
// calls panic. Do not fold InitImrEngine back into ImrEngine without updating
// tdns-mp/v2/start_agent.go.
func (conf *Config) InitImrEngine(quiet bool) error {
	// Idempotency guard: IMR is a process singleton. Subsequent calls are
	// no-ops; first-init wins.
	if conf.Internal.ImrEngine != nil {
		lgImr.Debug("InitImrEngine: already initialized, returning existing instance")
		return nil
	}

	// 1. Create the cache
	rrcache := cache.NewRRsetCache(log.Default(), conf.Imr.Verbose, conf.Imr.Debug)
	rrcache.Quiet = quiet

	conf.Internal.RRsetCache = rrcache
	requireDnssec := true // default: enforce DNSSEC validation
	if conf.Imr.RequireDnssecValidation != nil {
		requireDnssec = *conf.Imr.RequireDnssecValidation
	}
	imr := &Imr{
		Cache:                   rrcache,
		DnskeyCache:             rrcache.DnskeyCache,
		Options:                 conf.Imr.Options,
		LineWidth:               130,
		Verbose:                 conf.Imr.Verbose,
		Debug:                   conf.Imr.Debug,
		Quiet:                   quiet,
		RequireDnssecValidation: requireDnssec,
	}

	if conf.Imr.Logging.Enabled {
		logfile := conf.Imr.Logging.File
		if logfile == "" {
			logfile = "/var/log/tdns/imr-debug.log"
		}
		f, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			lgImr.Error("failed to open IMR debug log file, debug logging disabled", "file", logfile, "err", err)
		} else {
			imr.DebugLog = log.New(f, "", log.Ldate|log.Ltime|log.Lmicroseconds)
			lgImr.Info("IMR debug logging enabled", "file", logfile)
			dl := imr.DebugLog
			RegisterImrOutboundQueryHook(func(ctx context.Context, qname string, qtype uint16, serverName, serverAddr string, transport core.Transport) error {
				dl.Printf("OUTBOUND qname=%s qtype=%s server=%s addr=%s transport=%s",
					qname, dns.TypeToString[qtype], serverName, serverAddr, core.TransportToString[transport])
				return nil
			})
			RegisterImrResponseHook(func(ctx context.Context, qname string, qtype uint16, serverName, serverAddr string, transport core.Transport, response *dns.Msg, rcode int) {
				var ans []string
				if response != nil {
					for _, rr := range response.Answer {
						ans = append(ans, rr.String())
					}
				}
				dl.Printf("RESPONSE qname=%s qtype=%s server=%s addr=%s transport=%s rcode=%s answer=%v",
					qname, dns.TypeToString[qtype], serverName, serverAddr,
					core.TransportToString[transport], dns.RcodeToString[rcode], ans)
			})
		}
	}

	if !rrcache.IsPrimed() {
		err := rrcache.PrimeWithHints(conf.Imr.RootHints, imr.IterativeDNSQueryFetcher())
		if err != nil {
			return fmt.Errorf("failed to initialize RecursorCache w/ root hints: %v", err)
		}
		if len(conf.Imr.Stubs) > 0 {
			for _, stub := range conf.Imr.Stubs {
				stubservers := []string{}
				for i := range stub.Servers {
					server := &stub.Servers[i]
					stubservers = append(stubservers, server.Name+" ("+strings.Join(server.Addrs, ", ")+")")
				}
				lgImr.Info("adding stub", "zone", stub.Zone, "servers", strings.Join(stubservers, ", "))
				imr.Cache.AddStub(stub.Zone, stub.Servers)
			}
		}
	}

	conf.Internal.ImrEngine = imr
	Globals.ImrEngine = imr
	lgImr.Info("InitImrEngine: IMR initialized and available")
	return nil
}

func (conf *Config) ImrEngine(ctx context.Context, quiet bool) error {
	var recursorch = conf.Internal.RecursorCh

	// IMR is active by default unless explicitly set to false
	isActive := conf.Imr.Active == nil || *conf.Imr.Active

	if !isActive {
		lgImr.Warn("ImrEngine is NOT active (imrengine.active explicitly set to false)")
		for {
			select {
			case <-ctx.Done():
				lgImr.Info("terminating (inactive mode, context cancelled)")
				return nil
			case rrq, ok := <-recursorch:
				if !ok {
					return nil
				}
				lgImr.Warn("not active but got a request", "qname", rrq.Qname)
				continue // ensure that we keep reading to keep the channel open
			}
		}
	} else {
		lgImr.Info("ImrEngine starting")
	}

	// Initialize the Imr if not already done (e.g. by a prior InitImrEngine call).
	// Propagate the init error to the engine supervisor rather than calling
	// Shutdowner here — that would leave conf.Internal.ImrEngine nil and the
	// dereference below would panic.
	if conf.Internal.ImrEngine == nil {
		if err := conf.InitImrEngine(quiet); err != nil {
			return fmt.Errorf("ImrEngine: InitImrEngine failed: %w", err)
		}
	}
	imr := conf.Internal.ImrEngine

	// Initialize trust anchors (DS/DNSKEY) and validate root (.) DNSKEY and NS
	if err := imr.initializeImrTrustAnchors(ctx, conf); err != nil {
		lgImr.Warn("trust anchor initialization failed", "err", err)
	}

	// Start the ImrEngine (i.e. the recursive nameserver responding to queries with RD bit set)
	go imr.StartImrEngineListeners(ctx, conf)

	for {
		select {
		case <-ctx.Done():
			lgImr.Info("terminating (active mode, context cancelled)")
			return nil
		case rrq, ok := <-recursorch:
			if !ok {
				return nil
			}
			if rrq.ResponseCh == nil {
				lgImr.Warn("received nil or invalid request (no response channel)")
				continue
			}
			lgImr.Debug("received query", "qname", rrq.Qname, "qclass", dns.ClassToString[rrq.Qclass], "qtype", dns.TypeToString[rrq.Qtype])
			if imr.DebugLog != nil {
				imr.DebugLog.Printf("QUERY qname=%s qtype=%s", rrq.Qname, dns.TypeToString[rrq.Qtype])
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
					lgImr.Debug("cache hit", "qname", rrq.Qname, "qclass", dns.ClassToString[rrq.Qclass], "qtype", dns.TypeToString[rrq.Qtype], "context", cache.CacheContextToString[crrset.Context])
					if imr.DebugLog != nil {
						var rrs []string
						if crrset.RRset != nil {
							for _, rr := range crrset.RRset.RRs {
								rrs = append(rrs, rr.String())
							}
						}
						imr.DebugLog.Printf("CACHE-HIT qname=%s qtype=%s context=%s answer=%v",
							rrq.Qname, dns.TypeToString[rrq.Qtype],
							cache.CacheContextToString[crrset.Context], rrs)
					}
					resp = &ImrResponse{
						RRset: crrset.RRset,
					}
					rrq.ResponseCh <- *resp
					continue // Skip query, we have a good answer
				case cache.ContextReferral, cache.ContextGlue, cache.ContextHint, cache.ContextPriming, cache.ContextFailure:
					// These are indirect - issue a direct query to upgrade quality and get DNSSEC signatures
					lgImr.Debug("cache hit but indirect context, issuing direct query", "qname", rrq.Qname, "qtype", dns.TypeToString[rrq.Qtype], "context", cache.CacheContextToString[crrset.Context])
					if imr.DebugLog != nil {
						imr.DebugLog.Printf("CACHE-INDIRECT qname=%s qtype=%s context=%s, issuing fresh query",
							rrq.Qname, dns.TypeToString[rrq.Qtype], cache.CacheContextToString[crrset.Context])
					}
					// Fall through to issue query
				default:
					// Unknown context - be safe and issue query
					lgImr.Debug("cache hit with unknown context, issuing query", "qname", rrq.Qname, "qtype", dns.TypeToString[rrq.Qtype], "context", cache.CacheContextToString[crrset.Context])
					// Fall through to issue query
				}
			} else if imr.DebugLog != nil {
				imr.DebugLog.Printf("CACHE-MISS qname=%s qtype=%s, issuing fresh query", rrq.Qname, dns.TypeToString[rrq.Qtype])
			}
			// Cache miss or indirect context - issue query
			{
				var err error
				lgImr.Debug("not in cache, querying", "qname", rrq.Qname, "qtype", dns.TypeToString[rrq.Qtype])

				resp, err = imr.ImrQuery(ctx, rrq.Qname, rrq.Qtype, rrq.Qclass, nil)
				if err != nil {
					lgImr.Error("ImrQuery failed", "err", err)
				} else if resp == nil {
					resp = &ImrResponse{
						Error:    true,
						ErrorMsg: "ImrEngine: no response from ImrQuery",
					}
				}
				rrq.ResponseCh <- *resp
			}
		}
	}
}

func (imr *Imr) ImrQuery(ctx context.Context, qname string, qtype uint16, qclass uint16, respch chan *ImrResponse) (*ImrResponse, error) {
	lgImr.Debug("ImrQuery: not in cache, querying", "qname", qname, "qtype", dns.TypeToString[qtype])
	maxiter := 12

	resp := ImrResponse{
		Validated: false,
		Msg:       "ImrEngine: request to look up a RRset",
	}

	// validateResponse attempts DNSSEC validation of the response RRset.
	validateResponse := func() {
		if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
			return
		}
		vstate, err := imr.Cache.ValidateRRsetWithParentZone(ctx, resp.RRset,
			imr.IterativeDNSQueryFetcher(), imr.ParentZone)
		if err != nil {
			lgImr.Debug("ImrQuery: DNSSEC validation failed", "qname", qname, "qtype", dns.TypeToString[qtype], "err", err)
			return
		}
		if vstate == cache.ValidationStateSecure {
			resp.Validated = true
			lgImr.Debug("ImrQuery: DNSSEC validated", "qname", qname, "qtype", dns.TypeToString[qtype])
		}
	}

	// If a response channel is provided, use it to send responses
	if respch != nil {
		defer func() {
			select {
			case respch <- &resp:
				// sent successfully
			case <-time.After(2 * time.Second):
				lgImr.Warn("ImrQuery: timed out sending response to channel", "qname", qname, "qtype", dns.TypeToString[qtype])
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
			lgImr.Debug("ImrQuery: cache hit", "qname", qname, "qtype", dns.TypeToString[qtype], "context", cache.CacheContextToString[crrset.Context])
			resp.RRset = crrset.RRset
			if crrset.State == cache.ValidationStateSecure {
				resp.Validated = true
			} else {
				validateResponse()
			}
			return &resp, nil
		case cache.ContextReferral, cache.ContextGlue, cache.ContextHint, cache.ContextPriming, cache.ContextFailure:
			// These are indirect - issue a direct query to upgrade quality and get DNSSEC signatures
			lgImr.Debug("ImrQuery: cache hit but indirect context, issuing direct query", "qname", qname, "qtype", dns.TypeToString[qtype], "context", cache.CacheContextToString[crrset.Context])
			// Fall through to issue query
		default:
			// Unknown context - be safe and issue query
			lgImr.Debug("ImrQuery: cache hit with unknown context, issuing query", "qname", qname, "qtype", dns.TypeToString[qtype], "context", cache.CacheContextToString[crrset.Context])
			// Fall through to issue query
		}
	}

	for {
		if maxiter <= 0 {
			lgImr.Warn("ImrQuery: max iterations reached, giving up")
			resp.Error = true
			resp.ErrorMsg = "max iterations reached, giving up"
			return &resp, fmt.Errorf("max iterations reached, giving up")
		} else {
			maxiter--
		}
		bestmatch, authservers, err := imr.Cache.FindClosestKnownZone(qname)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error from FindClosestKnownZone: %v", err)
			return &resp, err
		}
		lgImr.Debug("ImrQuery: best zone match", "qname", qname, "bestmatch", bestmatch)
		// ss := servers

		switch {
		case len(authservers) == 0:
			// Use helper function to resolve NS addresses
			done, err := imr.resolveNSAddresses(ctx, bestmatch, qname, qtype, authservers, func(authservers map[string]*cache.AuthServer) (bool, error) {
				rrset, rcode, context, _, err := imr.IterativeDNSQuery(ctx, qname, qtype, authservers, false, false) // PR not required for resolveNSAddresses
				if err != nil {
					lgImr.Error("IterativeDNSQuery failed", "err", err)
					// return false, nil // Continue trying
					return false, err
				}
				if rrset != nil {
					lgImr.Debug("ImrQuery: received response from IterativeDNSQuery", "count", len(rrset.RRs))
					resp.RRset = rrset
					return true, nil // Success, stop trying
				}
				if rcode == dns.RcodeNameError {
					// this is a negative response, which we need to figure out how to represent
					lgImr.Info("ImrQuery: received NXDOMAIN, no point in continuing", "qname", qname)
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
				validateResponse()
				return &resp, nil
			}
			// If we get here, we tried all responses without finding a usable address
			lgImr.Warn("ImrQuery: failed to resolve query using any nameserver address", "qname", qname, "qtype", dns.TypeToString[qtype])
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Failed to resolve query %q, %s, using any nameserver address", qname, dns.TypeToString[qtype])
			return &resp, nil

		case len(authservers) < 4:
			// ss = servers
		default:
			// ss = servers[:3]
			// ss = append(servers, "...")
		}

		lgImr.Debug("ImrQuery: sending query to auth servers", "qname", qname, "qtype", dns.TypeToString[qtype], "count", len(authservers))

		rrset, rcode, context, _, err := imr.IterativeDNSQuery(ctx, qname, qtype, authservers, false, false) // PR not required for resolveNSAddresses
		// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error from IterativeDNSQuery: %v", err)
			return &resp, err
		}

		if rrset != nil {
			lgImr.Debug("ImrQuery: received response from IterativeDNSQuery", "count", len(rrset.RRs))
			resp.RRset = rrset
			validateResponse()
			return &resp, nil
		}
		if rcode == dns.RcodeNameError {
			// this is a negative response, which we need to figure out how to represent
			lgImr.Info("ImrQuery: received NXDOMAIN, no point in continuing", "qname", qname)
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
		lgImr.Debug("processAddressRecords: using resolved address", "rrtype", rrType, "nsname", nsname, "addr", addr)
	}
}

// resolveNSAddresses resolves nameserver addresses when authservers is empty.
// It calls onResponse for each successful address resolution, allowing the caller
// to handle the response appropriately. Returns true if a response was successfully
// handled, false if no usable address was found, and an error if something went wrong.
func (imr *Imr) resolveNSAddresses(ctx context.Context, bestmatch string, qname string, qtype uint16,
	authservers map[string]*cache.AuthServer,
	onResponse func(authservers map[string]*cache.AuthServer) (bool, error)) (bool, error) {

	lgImr.Info("resolveNSAddresses: no server addresses", "zone", bestmatch, "qname", qname)
	cnsrrset := imr.Cache.Get(bestmatch, dns.TypeNS)
	if cnsrrset == nil {
		lgImr.Warn("resolveNSAddresses: no nameservers either, giving up", "zone", bestmatch)
		return false, fmt.Errorf("no nameservers for zone %q", bestmatch)
	}

	lgImr.Debug("resolveNSAddresses: have nameserver names", "zone", bestmatch, "count", len(cnsrrset.RRset.RRs))

	// Create response channel for A and AAAA queries
	respch := make(chan *ImrResponse, len(cnsrrset.RRset.RRs)*2) // *2 for both A and AAAA
	// Note: We don't need to close the channel here as it will be garbage collected
	// when it goes out of scope, even if there are still pending writes to it

	// Launch parallel queries for each nameserver
	err := imr.CollectNSAddresses(ctx, cnsrrset.RRset, respch)
	if err != nil {
		lgImr.Error("resolveNSAddresses: CollectNSAddresses failed", "err", err)
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
	lgImr.Warn("resolveNSAddresses: failed to resolve query using any nameserver address", "qname", qname, "qtype", dns.TypeToString[qtype])
	return false, nil
}

func (imr *Imr) ImrResponder(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, msgoptions *edns0.MsgOptions) {
	m := new(dns.Msg)
	m.RecursionAvailable = true

	crrset := imr.Cache.Get(qname, qtype)
	if crrset != nil {
		// PR flag enforcement: if PR is set, skip cached data that came over unencrypted transport
		if msgoptions.PR && !core.IsEncryptedTransport(crrset.Transport) {
			lgImr.Debug("ImrResponder: PR flag set but cached data came over unencrypted transport, skipping cache", "qname", qname, "qtype", dns.TypeToString[qtype], "transport", core.TransportToString[crrset.Transport])
			crrset = nil // Force query over encrypted transport
		}
	}
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
			// Set PR flag in response if Answer came over encrypted transport
			if core.IsEncryptedTransport(crrset.Transport) {
				if err := edns0.SetPRFlagInMessage(m); err != nil {
					lgImr.Error("ImrResponder: failed to set PR flag in response", "err", err)
				}
			}
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
			// Set PR flag in response if Answer came over encrypted transport
			if core.IsEncryptedTransport(crrset.Transport) {
				if err := edns0.SetPRFlagInMessage(m); err != nil {
					lgImr.Error("ImrResponder: failed to set PR flag in response", "err", err)
				}
			}
			w.WriteMsg(m)
			return
		case crrset.Rcode == uint8(dns.RcodeSuccess) && crrset.Context == cache.ContextAnswer &&
			crrset.RRset != nil && crrset.RRset.RRtype == qtype:
			if !msgoptions.CD && (crrset.EDECode != 0 || crrset.State == cache.ValidationStateBogus) {
				lgImr.Debug("ImrResponder: returning SERVFAIL for bogus cached data", "qname", qname, "qtype", dns.TypeToString[qtype], "edeCode", crrset.EDECode, "state", cache.ValidationStateToString[crrset.State])
				m.Answer = nil
				m.Ns = nil
				m.SetRcode(r, dns.RcodeServerFailure)
				// Attach EDE if query had EDNS0 (check if request had OPT RR)
				hasEDNS0 := r.IsEdns0() != nil
				lgImr.Debug("ImrResponder: EDE details", "hasEDNS0", hasEDNS0, "edeCode", crrset.EDECode, "state", cache.ValidationStateToString[crrset.State])
				if crrset.EDECode != 0 && hasEDNS0 {
					edns0.AttachEDEToResponseWithText(m, crrset.EDECode, crrset.EDEText, msgoptions.DO)
					lgImr.Debug("ImrResponder: attached EDE code to response", "edeCode", crrset.EDECode)
				} else if crrset.State == cache.ValidationStateBogus && hasEDNS0 {
					// Attach EDE 6 (DNSSEC Bogus) if no specific EDE code is set and query had EDNS0
					edns0.AttachEDEToResponse(m, edns0.EDEDNSSECBogus)
					lgImr.Debug("ImrResponder: attached EDE 6 (DNSSEC Bogus) to response")
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
			// Set PR flag in response if Answer came over encrypted transport
			if core.IsEncryptedTransport(crrset.Transport) {
				if err := edns0.SetPRFlagInMessage(m); err != nil {
					lgImr.Error("ImrResponder: failed to set PR flag in response", "err", err)
				}
			}
			w.WriteMsg(m)
			return
		}
	}

	m.SetRcode(r, dns.RcodeServerFailure)
	if msgoptions.RD {
		lgImr.Debug("ImrResponder: not in cache, querying", "qname", qname, "qtype", dns.TypeToString[qtype])
		maxiter := 12

		for {
			if maxiter <= 0 {
				lgImr.Warn("ImrResponder: max iterations reached, giving up")
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
			lgImr.Debug("ImrResponder: best zone match", "qname", qname, "bestmatch", bestmatch)

			switch {
			case len(authservers) == 0:
				// Use helper function to resolve NS addresses
				// Note: The callback is called after processing each A/AAAA response.
				// We try the query for each address we discover, similar to the original code.
				done, err := imr.resolveNSAddresses(ctx, bestmatch, qname, qtype, authservers, func(authservers map[string]*cache.AuthServer) (bool, error) {
					// Try querying with the current set of authservers
					rrset, rcode, context, transport, err := imr.IterativeDNSQuery(ctx, qname, qtype, authservers, false, msgoptions.PR)
					if err != nil {
						lgImr.Error("IterativeDNSQuery failed", "err", err)
						return false, nil // Continue trying with next address
					}
					done, err := imr.ProcessAuthDNSResponse(ctx, qname, qtype, rrset, rcode, context, msgoptions, m, w, r, transport)
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
				lgImr.Warn("ImrResponder: failed to resolve query using any nameserver address", "qname", qname, "qtype", dns.TypeToString[qtype])
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}

			lgImr.Debug("ImrResponder: sending query to authservers", "qname", qname, "qtype", dns.TypeToString[qtype], "count", len(authservers), "zone", bestmatch)
			rrset, rcode, context, transport, err := imr.IterativeDNSQuery(ctx, qname, qtype, authservers, false, msgoptions.PR)
			// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
			if err != nil {
				// If PR flag is set and we can't get encrypted transport, return SERVFAIL+EDE
				if msgoptions.PR && strings.Contains(err.Error(), "PR flag requires encrypted transport") {
					m.SetRcode(r, dns.RcodeServerFailure)
					// Attach EDE only if query had EDNS0
					if r.IsEdns0() != nil {
						// Include zone name in EDE text for better diagnostics
						var edeText string
						if bestmatch != "" {
							edeText = fmt.Sprintf("Privacy requested but only unencrypted transport available for zone %s", bestmatch)
						} else {
							edeText = "Privacy requested but only unencrypted transport available"
						}
						edns0.AttachEDEToResponseWithText(m, edns0.EDEPrivacyRequestedUnavailable, edeText, msgoptions.DO)
					}
					w.WriteMsg(m)
					return
				}
				w.WriteMsg(m)
				return
			}
			done, err := imr.ProcessAuthDNSResponse(ctx, qname, qtype, rrset, rcode, context, msgoptions, m, w, r, transport)
			if err != nil {
				return
			}
			if done {
				return
			}
			continue
		}
	} else {
		lgImr.Info("not in cache and RD bit is not set, refusing", "qname", qname, "qtype", dns.TypeToString[qtype])
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
func (imr *Imr) ProcessAuthDNSResponse(ctx context.Context, qname string, qtype uint16, rrset *core.RRset, rcode int, context cache.CacheContext, msgoptions *edns0.MsgOptions, m *dns.Msg, w dns.ResponseWriter, r *dns.Msg, transport core.Transport) (bool, error) {
	lgImr.Debug("ProcessAuthDNSResponse", "qname", qname, "rcode", rcode, "context", context, "DO", msgoptions.DO, "CD", msgoptions.CD)
	m.SetRcode(r, rcode)
	if rrset != nil {
		lgImr.Debug("ProcessAuthDNSResponse: received response from IterativeDNSQuery", "count", len(rrset.RRs))
		m.Answer = rrset.RRs
		if msgoptions.DO {
			m.Answer = append(m.Answer, rrset.RRSIGs...)
		}
		// Set PR flag in response if Answer came over encrypted transport
		if core.IsEncryptedTransport(transport) {
			if err := edns0.SetPRFlagInMessage(m); err != nil {
				lgImr.Error("failed to set PR flag in response", "err", err)
			}
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
					lgImr.Error("failed to validate RRset", "qname", qname, "qtype", dns.TypeToString[qtype], "err", err)
					m.SetRcode(r, dns.RcodeServerFailure)
					// Attach EDE 6 (DNSSEC Bogus) if validation failed and query had EDNS0
					if r.IsEdns0() != nil {
						edns0.AttachEDEToResponse(m, edns0.EDEDNSSECBogus)
					}
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
		// Validation was attempted but failed (bogus or indeterminate)
		if vstate == cache.ValidationStateBogus {
			m.Answer = nil
			m.Ns = nil
			m.SetRcode(r, dns.RcodeServerFailure)
			edeCode, edeText := imr.Cache.MarkRRsetBogus(qname, qtype, rrset, msgoptions.DO)
			// Attach EDE if query had EDNS0 (check if request had OPT RR)
			if r.IsEdns0() != nil {
				if edeCode != 0 {
					edns0.AttachEDEToResponseWithText(m, edeCode, edeText, msgoptions.DO)
				} else {
					// Attach EDE 6 (DNSSEC Bogus) as fallback if no specific EDE code is available
					edns0.AttachEDEToResponse(m, edns0.EDEDNSSECBogus)
				}
			}
			w.WriteMsg(m)
			return true, nil
		}
		// Indeterminate or other validation state - return SERVFAIL without EDE
		m.Answer = nil
		m.Ns = nil
		m.SetRcode(r, dns.RcodeServerFailure)
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
			attachNegativeEDE(resp, msgoptions, cached, src)
			return true
		}
		attachNegativeEDE(resp, msgoptions, cached, src)
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
			attachNegativeEDE(resp, msgoptions, cached, src)
			return true
		}
	}
	if cached != nil && cached.RRset != nil {
		appendSOAToMessage(cached.RRset, msgoptions, resp)
		if cached.State == cache.ValidationStateSecure {
			resp.AuthenticatedData = true
		}
		attachNegativeEDE(resp, msgoptions, cached, src)
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
		attachNegativeEDE(resp, msgoptions, cached, src)
		return true
	}
	attachNegativeEDE(resp, msgoptions, cached, src)
	appendSOAFromMsg(src, msgoptions, resp)
	return true
}

func attachNegativeEDE(resp *dns.Msg, msgoptions *edns0.MsgOptions, cached *cache.CachedRRset, req *dns.Msg) {
	if resp == nil || cached == nil || cached.EDECode == 0 {
		return
	}
	// Only attach EDE if the original request had EDNS0
	if req != nil && req.IsEdns0() != nil {
		edns0.AttachEDEToResponseWithText(resp, cached.EDECode, cached.EDEText, msgoptions.DO)
	}
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
			lgImr.Info("no addresses provided, will only be an internal recursive resolver")
		}
		return nil
	}

	ImrHandler := imr.createImrHandler(ctx, conf)

	// Create a local ServeMux for ImrEngine to avoid conflicts with other engines
	imrMux := dns.NewServeMux()
	imrMux.HandleFunc(".", ImrHandler)

	if CaseFoldContains(conf.Imr.Transports, "do53") {
		lgImr.Info("starting Do53 listeners", "addresses", addresses)
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
					lgImr.Info("serving", "addr", addr, "net", net)
					// Must bump the buffer size of incoming UDP msgs, as updates
					// may be much larger then queries
					// s.UDPSize = dns.DefaultMsgSize // 4096
					if err := s.ListenAndServe(); err != nil {
						lgImr.Error("failed to setup server", "net", net, "err", err)
					} else {
						lgImr.Info("listening", "addr", addr, "net", net)
					}
				}(server, addr, net)
			}
		}
		// Graceful shutdown of Do53 servers
		go func() {
			<-ctx.Done()
			lgImr.Info("shutting down Do53 servers", "count", len(servers))
			for _, s := range servers {
				done := make(chan struct{})
				go func(s *dns.Server) {
					defer close(done)
					if err := s.Shutdown(); err != nil {
						lgImr.Error("error shutting down Do53 server", "addr", s.Addr, "net", s.Net, "err", err)
					}
				}(s)
				select {
				case <-done:
					// ok
				case <-time.After(5 * time.Second):
					lgImr.Warn("timeout waiting for Do53 server shutdown", "addr", s.Addr, "net", s.Net)
				}
			}
		}()
	} else {
		lgImr.Info("not serving on transport Do53")
	}

	certFile := viper.GetString("imrengine.certfile")
	keyFile := viper.GetString("imrengine.keyfile")
	certKey := true

	if certFile == "" || keyFile == "" {
		lgImr.Warn("no certificate or key file provided, not starting DoT/DoH/DoQ")
		certKey = false
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		lgImr.Warn("certificate file does not exist, not starting DoT/DoH/DoQ", "certFile", certFile)
		certKey = false
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		lgImr.Warn("key file does not exist, not starting DoT/DoH/DoQ", "keyFile", keyFile)
		certKey = false
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		lgImr.Warn("failed to load certificate, not starting DoT/DoH/DoQ", "err", err)
		certKey = false
	}

	if certKey {
		// Strip port numbers from addresses before proceeding to modern transports
		tmp := make([]string, len(addresses))
		for i, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				lgImr.Warn("failed to parse address", "addr", addr, "err", err)
				tmp[i] = addr // Keep original if parsing fails
			} else {
				tmp[i] = host
			}
		}
		addresses = tmp

		if CaseFoldContains(conf.Imr.Transports, "dot") {
			err := DnsDoTEngine(ctx, conf, addresses, &cert, ImrHandler)
			if err != nil {
				lgImr.Error("failed to setup DoT server", "err", err)
			}
		} else {
			lgImr.Info("not serving on transport DoT")
		}

		if CaseFoldContains(conf.Imr.Transports, "doh") {
			err := DnsDoHEngine(ctx, conf, addresses, certFile, keyFile, ImrHandler)
			if err != nil {
				lgImr.Error("failed to setup DoH server", "err", err)
			}
		} else {
			lgImr.Info("not serving on transport DoH")
		}

		if CaseFoldContains(conf.Imr.Transports, "doq") {
			err := DnsDoQEngine(ctx, conf, addresses, &cert, ImrHandler)
			if err != nil {
				lgImr.Error("failed to setup DoQ server", "err", err)
			}
		} else {
			lgImr.Info("not serving on transport DoQ")
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
		lgImr.Info("configured DS trust anchor", "zone", name, "keytag", ds.KeyTag, "digesttype", ds.DigestType)
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
				lgImr.Warn("skipping unparsable line in trust anchor file", "file", taFile, "line", s, "err", err)
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
				lgImr.Warn("ignoring non-TA RR in trust anchor file", "file", taFile, "rr", rr.String())
			}
		}
	}

	return dsByName, dnskeysByName, nil
}

// addDirectDNSKEYTrustAnchors adds direct DNSKEY trust anchors to the cache.
func (imr *Imr) addDirectDNSKEYTrustAnchors(dnskeysByName map[string][]*dns.DNSKEY) {
	for name, list := range dnskeysByName {
		lgImr.Info("zone has DNSKEY trust anchors", "zone", name)
		exp := time.Now().Add(365 * 24 * time.Hour)
		for _, dk := range list {
			lgImr.Info("adding DNSKEY trust anchor", "zone", name, "keyid", dk.KeyTag())
			imr.DnskeyCache.Set(name, dk.KeyTag(), &cache.CachedDnskeyRRset{
				Name:        name,
				Keyid:       dk.KeyTag(),
				State:       cache.ValidationStateSecure,
				TrustAnchor: true,
				Dnskey:      *dk,
				Expiration:  exp,
			})
			lgImr.Info("added DNSKEY trust anchor", "zone", name, "keyid", dk.KeyTag(), "expires", exp)
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
		lgImr.Debug("zone added to ZoneMap as secure via DNSKEY trust anchor", "zone", name)
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
	lgImr.Debug("seeded validated DS RRset from trust anchors", "zone", anchorName, "count", len(rrds), "ttl", minTTL)
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
				lgImr.Info("DS matched DNSKEY", "zone", cdr.Name, "keyid", cdr.Keyid, "expires", exp)
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
			lgImr.Debug("DNSKEY RRset validated using DS trust anchor", "zone", anchorName, "keytag", ds.KeyTag)
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
				lgImr.Debug("DNSKEY RRset validated using direct DNSKEY trust anchor", "zone", anchorName, "keytag", item.Val.Keyid)
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
		lgImr.Debug("DNSKEY RRset already validated in cache", "zone", anchorName)
		// vstate not needed here as we're using cached state
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
			lgImr.Error("DNSKEY RRset failed to validate using trust anchors", "zone", anchorName)
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
				lgImr.Info("cached DNSKEY", "zone", cdr.Name, "keyid", cdr.Keyid, "trustAnchor", true, "expires", exp)
			} else {
				lgImr.Info("cached DNSKEY", "zone", cdr.Name, "keyid", cdr.Keyid, "expires", exp)
			}
		}
	}
}

// validateNSRRsetForAnchor validates the NS RRset for a trust anchor zone.
func (imr *Imr) validateNSRRsetForAnchor(ctx context.Context, anchorName string, serverMap map[string]*cache.AuthServer) {
	// Fetch and validate the NS RRset for the anchor zone (non-fatal - continue even if it fails)
	nsRRset, _, _, _, err := imr.IterativeDNSQuery(ctx, anchorName, dns.TypeNS, serverMap, true, false) // PR not required for trust anchor initialization
	if err != nil {
		lgImr.Warn("failed to fetch NS RRset for trust anchor zone", "zone", anchorName, "err", err)
		return
	}
	if nsRRset == nil || len(nsRRset.RRs) == 0 {
		lgImr.Warn("no NS RRset found for trust anchor zone", "zone", anchorName)
		return
	}
	// Check if the NS RRset is already validated in cache (from IterativeDNSQuery)
	nsCrr := imr.Cache.Get(anchorName, dns.TypeNS)
	var nsVstate cache.ValidationState
	if nsCrr != nil && nsCrr.State == cache.ValidationStateSecure {
		// Already validated, use the cached state
		lgImr.Debug("NS RRset already validated in cache", "zone", anchorName)
		// nsVstate not needed here as we're using cached state
	} else {
		// Not validated yet, validate it now
		nsVstate, err = imr.Cache.ValidateRRsetWithParentZone(ctx, nsRRset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
		if err != nil {
			lgImr.Warn("failed to validate NS RRset for trust anchor zone", "zone", anchorName, "err", err)
			return
		}
		if nsVstate != cache.ValidationStateSecure {
			lgImr.Warn("NS RRset failed to validate for trust anchor zone", "zone", anchorName, "vstate", cache.ValidationStateToString[nsVstate])
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
	lgImr.Info("processing trust anchor zone", "zone", anchorName)

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
	rrset, _, _, _, err := imr.IterativeDNSQuery(ctx, anchorName, dns.TypeDNSKEY, serverMap, true, false) // PR not required for trust anchor initialization
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
	lgImr.Debug("zone added to ZoneMap as secure via DS trust anchor", "zone", anchorName)

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
	lgImr.Info("processing trust anchor zones", "count", len(anchorNames), "names", anchorNames)

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
			lgImr.Error("error extracting EDNS0 options", "err", err)
		}

		qtype := r.Question[0].Qtype
		lgImr.Debug("received query", "qname", qname, "qtype", dns.TypeToString[qtype], "from", w.RemoteAddr(), "opcode", dns.OpcodeToString[r.Opcode])

		switch r.Opcode {
		case dns.OpcodeNotify, dns.OpcodeUpdate:
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return

		case dns.OpcodeQuery:
			lgImr.Debug("lookup request", "qname", qname, "qtype", dns.TypeToString[qtype], "RD", msgoptions.RD, "DO", msgoptions.DO, "from", w.RemoteAddr())

			qname = strings.ToLower(qname)
			if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
				DotServerQnameResponse(qname, w, r)
				return
			}

			// Run IMR client query hooks (dependency analysis, RPZ, etc.)
			hookCtx := ctx
			for _, hook := range getImrClientQueryHooks() {
				newCtx, response := hook(hookCtx, w, r, qname, qtype, msgoptions)
				if newCtx != nil {
					hookCtx = newCtx
				}
				if response != nil {
					w.WriteMsg(response)
					return
				}
			}
			imr.ImrResponder(hookCtx, w, r, qname, qtype, msgoptions)
			return

		default:
			lgImr.Error("unable to handle message type", "opcode", dns.OpcodeToString[r.Opcode])
		}
	}
}

func DotServerQnameResponse(qname string, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	qname = strings.ToLower(qname)
	// if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
	lgImr.Debug("query for .server CH TLD", "qname", qname)
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
