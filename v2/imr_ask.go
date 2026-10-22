/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// serverReply is what one response does to a server walk. done stops the
// walk with the result; otherwise the next server is tried.
type serverReply struct {
	done      bool
	rrset     *core.RRset
	rcode     int
	cacheCtx  cache.CacheContext
	transport core.Transport
	err       error
}

func replyDone(rrset *core.RRset, rcode int, cctx cache.CacheContext, transport core.Transport, err error) serverReply {
	return serverReply{done: true, rrset: rrset, rcode: rcode, cacheCtx: cctx, transport: transport, err: err}
}

func replyNext() serverReply { return serverReply{} }

// askServers sends one question to serverMap. Each response that is not a
// transport failure is handed to dispatch. bookLameness is how a probe keeps
// a refusal from being recorded against the zone: the original query still
// records it.
func (imr *Imr) askServers(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, serversZone string, privacy edns0.PrivacyLevel, bookLameness bool, dispatch func(server *cache.AuthServer, addr, nsname string, wire core.Transport, r *dns.Msg) serverReply) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	lg := imr.Cache.Logger

	var rrset core.RRset
	var rcode int

	withOOTS := imr.Options[ImrOptUseTransportSignals] != "false"
	m, err := buildQuery(qname, qtype, withOOTS)
	if err != nil {
		lg.Printf("IterativeDNSQuery: Error building query: %v", err)
		return nil, 0, cache.ContextFailure, core.TransportDo53, err
	}

	dnskeyBypass := imr.dnskeyTransportBypass(qname, qtype, privacy)
	if qtype == dns.TypeDNSKEY {
		imr.noteDNSKEYLookup(dnskeyBypass)
	}

	// Under strict privacy, verify up front that at least one server has an
	// encrypted transport available: failing here names the actual reason,
	// rather than letting the walk below run out of tuples and report a
	// generic dead end. Opportunistic privacy has no such precondition --
	// falling back to cleartext is exactly what it asked for.
	//
	// Availability is asked of candidateTransports (hasStrictCandidate) rather
	// than computed here, so the precheck and the tuple selection below cannot
	// disagree. A hand-rolled scan did disagree in two ways: it read
	// server.Transports without a nil check, where candidateTransports handles
	// a nil entry (as prioritizeServers does), and it counted an encrypted
	// transport of weight 0 or 1 as available, where candidateTransports
	// excludes it.
	//
	// A server may also have no encrypted transport only because it has not
	// told us yet: the zone was met a moment ago, through the referral that
	// brought us here. Its transports are learned before the query gives up on
	// it, or the first strict query to every new zone failed (#776).
	if privacy == edns0.PrivacyStrict && !hasStrictCandidate(serverMap, qname) &&
		!imr.awaitTransportSignals(ctx, qname, serverMap) {
		zoneName, _, _ := imr.Cache.FindClosestKnownZoneFor(qname, qtype)
		return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
			privacyUnavailable(zoneName, "no servers have encrypted transports available (zone=%s)", zoneName)
	}

	// Prioritize (server, addr, transport) tuples. The privacy level is
	// applied here so tryServer no longer needs to filter.
	//
	// Two-attempt outer loop: if the first pass exhausts every tuple
	// without an answer, try resolving any NS names in the zone whose
	// addresses were not provided as glue (typical for out-of-bailiwick
	// NS where the parent legally cannot glue them), then re-prioritize
	// with the expanded serverMap. Hard cap at 2 attempts to prevent
	// loops if resolution keeps producing nothing.
	var zoneName string
	var zone *cache.Zone
	var prioritized []ServerAddrXportTuple
	var (
		lastNS, lastAddr string
		lastTransport    core.Transport
		lastErr          error
		attempts         int
	)
	dnskeyAttempted := map[cache.AddrXport]bool{}
	addresslessAtStart := map[string]bool{}
	for key, srv := range serverMap {
		if len(srv.GetAddrs()) == 0 {
			addresslessAtStart[key] = true
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		zoneName, zone, prioritized = imr.prioritizeServers(qname, qtype, serverMap, privacy)
		if Globals.Debug {
			lg.Printf("IterativeDNSQuery: prioritized %d (server,addr,transport) tuples (from %d servers) attempt=%d", len(prioritized), len(serverMap), attempt+1)
		}

		for _, tuple := range prioritized {
			select {
			case <-ctx.Done():
				return nil, 0, cache.ContextFailure, core.TransportDo53, walkErr(zoneName, lastNS, lastAddr, lastTransport, attempts, lastErr, ctx.Err())
			default:
			}
			server := tuple.Server
			addr := tuple.Addr
			nsname := tuple.NSName
			transport := tuple.Transport

			effTransport := transport
			if dnskeyBypass {
				eff := imr.preferredDNSKEYTransport(server)
				key := cache.AddrXport{Addr: addr, Transport: eff}
				if dnskeyAttempted[key] {
					continue
				}
				dnskeyAttempted[key] = true
				effTransport = eff
			}

			lastNS, lastAddr, lastTransport = nsname, addr, transport
			attempts++

			if Globals.Debug {
				lg.Printf("IterativeDNSQuery: using nameserver %s@%s over %s (ALPN: %v) for <%s, %s> query\n",
					addr, nsname, core.TransportToString[effTransport], server.GetAlpn(), qname, dns.TypeToString[qtype])
			}

			r, _, wireTransport, err := imr.tryServer(ctx, server, addr, transport, m, qname, qtype, dnskeyBypass, trafficClass(ctx, privacy))
			lastTransport = wireTransport
			if err != nil {
				lastErr = err
				continue
			}
			if r == nil {
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: nil response from tryServer(dns.Exchange) qname=%s, qtype=%s", qname, dns.TypeToString[qtype])
				}
				continue
			}
			if Globals.Debug {
				lg.Printf("IterativeDNSQuery: response from tryServer(dns.Exchange) qname=%s, qtype=%s:\n%s", qname, dns.TypeToString[qtype], PrintMsgFull(r, imr.LineWidth))
			}

			for _, hook := range getImrResponseHooks() {
				hook(ctx, qname, qtype, server.Name, addr, wireTransport, r, r.MsgHdr.Rcode)
			}

			rcode = r.MsgHdr.Rcode

			switch rcode {
			case dns.RcodeRefused, dns.RcodeNotAuth, dns.RcodeServerFailure, dns.RcodeNotImplemented:
				if !bookLameness {
					continue
				}
				if !refusalIndicatesLameness(qtype, rcode) {
					if Globals.Debug {
						lg.Printf("IterativeDNSQuery: %s from %s@%s for a DS query (%s) — parent-side data, not evidence of lameness; not recording a backoff",
							dns.RcodeToString[rcode], addr, nsname, qname)
					}
					continue
				}
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: %s response from %s@%s over %s for %s %s (likely lame delegation for zone %q)",
						dns.RcodeToString[rcode], addr, nsname, core.TransportToString[wireTransport], qname, dns.TypeToString[qtype], zoneName)
				}
				if zone != nil {
					zone.RecordZoneAddressFailureForRcode(addr, wireTransport, uint8(rcode), Globals.Debug)
				} else {
					server.RecordAddressFailureForRcode(addr, wireTransport, uint8(rcode))
				}
				continue
			case dns.RcodeSuccess:
				if zone != nil {
					zone.RecordZoneAddressSuccess(addr, wireTransport)
				}
			default:
				if zone != nil {
					zone.RecordZoneAddressSuccess(addr, wireTransport)
				}
			}

			rep := dispatch(server, addr, nsname, wireTransport, r)
			if rep.done {
				return rep.rrset, rep.rcode, rep.cacheCtx, rep.transport, rep.err
			}
		}
		if attempt == 0 {
			added := imr.expandServerMapWithMissingNSSince(ctx, qname, qtype, serverMap, addresslessAtStart)
			if added > 0 {
				if Globals.Debug {
					lg.Printf("IterativeDNSQuery: expanded serverMap with %d previously-unresolved NS addresses; retrying", added)
				}
				continue
			}
		}
		break
	}
	// Every server was tried and none answered. The error names the zone and
	// the last server so the failure is diagnosable without the IMR log.
	if privacy == edns0.PrivacyStrict {
		base := privacyUnavailable(zoneName, "no answers found from any server with encrypted transport for '%s %s'", qname, dns.TypeToString[qtype])
		return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53, walkErr(zoneName, lastNS, lastAddr, lastTransport, attempts, lastErr, base)
	}
	base := fmt.Errorf("IterativeDNSQuery: no Answers found from any auth server looking up '%s %s'", qname, dns.TypeToString[qtype])
	return &rrset, rcode, cache.ContextNoErrNoAns, core.TransportDo53, walkErr(zoneName, lastNS, lastAddr, lastTransport, attempts, lastErr, base)
}

// dispatchClientQuery is the response handling the iterative walk had inline.
// A finished answer, a negative, or a referral ends the walk. Anything else
// tries the next server.
func (imr *Imr) dispatchClientQuery(ctx context.Context, qname string, qtype uint16, force bool, visitedZones map[string]bool, serversZone string, privacy edns0.PrivacyLevel, server *cache.AuthServer, addr, nsname string, wire core.Transport, r *dns.Msg) serverReply {
	rcode := r.MsgHdr.Rcode

	if len(r.Answer) != 0 {
		// Parse any transport signal for this specific server even on final answers.
		// server is a shared instance across all zones, so modifications are visible everywhere.
		imr.parseTransportForServerFromAdditional(ctx, server, r)
		tmprrset, rcode2, ctx2, transport2, err, done := imr.handleAnswer(ctx, qname, qtype, r, force, wire, privacy)
		if err != nil || done {
			return replyDone(tmprrset, rcode2, ctx2, transport2, err)
		}
		// If not done, fall through to process referral glue embedded with answers.
		nsRRs, zonename, nsMap := extractReferral(r, qname, qtype)
		if len(nsRRs.RRs) > 0 && referralLeavesZone(zonename, serversZone) {
			serverMap, err := imr.ParseAdditionalForNSAddrs(ctx, "authority", nsRRs, zonename, serversZone, nsMap, r)
			if err != nil {
				lgDns.Error("*** IterativeDNSQuery: Error from CollectNSAddressesFromAdditional",
					"collectnsaddressesfromadditional", err)
				return replyDone(nil, rcode, cache.ContextFailure, wire, err)
			}
			if len(serverMap) == 0 {
				return replyDone(nil, rcode, cache.ContextReferral, wire, nil)
			}
			rrset, rcode, cacheCtx, transport, err := imr.IterativeDNSQueryWithLoopDetection(ctx, qname, qtype, serverMap, zonename, force, visitedZones, privacy)
			return replyDone(rrset, rcode, cacheCtx, transport, err)
		}
		return replyNext()
	}

	// A negative answer with an empty authority section (RFC 2308 types 3,
	// and the NODATA form of it) is classified too when it is authoritative
	// (#830); anything else without an authority section falls through as before.
	if len(r.Ns) != 0 || (r.Authoritative && (rcode == dns.RcodeNameError || rcode == dns.RcodeSuccess)) {
		kind := classifyResponse(qname, qtype, r)
		lgDns.Debug("IterativeDNSQuery: classified response",
			"qname", qname, "qtype", dns.TypeToString[qtype],
			"kind", responseKindToString(kind), "rcode", dns.RcodeToString[rcode],
			"answerCount", len(r.Answer), "authorityCount", len(r.Ns))

		switch kind {
		case responseKindNegativeNoData, responseKindNegativeNXDOMAIN:
			if ctxNeg, rcodeNeg, handled := imr.handleNegative(qname, qtype, r, wire, serversZone); handled {
				return replyDone(nil, rcodeNeg, ctxNeg, wire, nil)
			}
			// If not handled, fall through to try the next server.
			if rcode == dns.RcodeNameError {
				lgDns.Debug("IterativeDNSQuery: NXDOMAIN response lacked usable SOA",
					"qname", qname, "qtype", dns.TypeToString[qtype])
			}
			return replyNext()
		case responseKindReferral:
			// A referral hands the lookup to a zone below the one these
			// servers serve. An NS RRset for that zone itself, or for one
			// above it, is not a referral. Following it would reach the loop
			// check in handleReferral, which aborts the whole lookup (#829).
			if _, refZone, _ := extractReferral(r, qname, qtype); !referralLeavesZone(refZone, serversZone) {
				// With AA set and the zone's own NS RRset, the server is
				// answering NODATA without an SOA (#830). A referral below
				// the zone keeps its meaning even with AA set, as some
				// servers set it on referrals; NS for a zone above is an
				// upward referral, and lame whatever the AA bit.
				if r.Authoritative && rcode == dns.RcodeSuccess && core.EqualNames(refZone, serversZone) {
					if ctxNeg, rcodeNeg, handled := imr.handleNegative(qname, qtype, r, wire, serversZone); handled {
						return replyDone(nil, rcodeNeg, ctxNeg, wire, nil)
					}
				}
				// Otherwise the server is lame for the zone: try the next one.
				// The fallback below still resolves the zone's glue-less nameservers.
				lgDns.Debug("IterativeDNSQuery: NS RRset does not lead below the zone being queried;"+
					" treating the server as lame and trying the next one",
					"qname", qname, "qtype", dns.TypeToString[qtype],
					"zone", serversZone, "ns_owner", refZone, "server", nsname, "addr", addr,
					"aa", r.Authoritative)
				return replyNext()
			}
			rrset, rcode, cacheCtx, transport, err := imr.handleReferral(ctx, qname, qtype, r, force, visitedZones, serversZone, wire, privacy, nil)
			return replyDone(rrset, rcode, cacheCtx, transport, err)
		case responseKindError:
			lgDns.Debug("IterativeDNSQuery: treating response as error",
				"qname", qname, "qtype", dns.TypeToString[qtype],
				"rcode", dns.RcodeToString[rcode])
			return replyNext()
		case responseKindUnknown:
			lgDns.Debug("IterativeDNSQuery: responseKindUnknown, trying next server",
				"qname", qname, "qtype", dns.TypeToString[qtype])
			return replyNext()
		default:
			// Should not reach here, but be defensive.
			lgDns.Debug("IterativeDNSQuery: unexpected response kind, trying next server",
				"kind", kind, "qname", qname, "qtype", dns.TypeToString[qtype])
			return replyNext()
		}
	}

	if rcode == dns.RcodeSuccess {
		return replyDone(&core.RRset{}, rcode, cache.ContextFailure, wire, nil) // no point in continuing
	}
	return replyNext()
}
