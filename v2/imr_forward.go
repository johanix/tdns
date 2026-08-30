/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// IMR forwarding: a forward zone routes every query for names at or below the
// zone to one or more upstream RECURSIVE resolvers (RD=1) instead of walking
// the delegation tree. "zone: ." forwards everything. This differs from a stub
// zone, which pre-seeds the server map with AUTHORITATIVE servers and still
// iterates (RD=0, referrals followed).
//
// The forward decision is taken inside IterativeDNSQueryWithLoopDetection,
// after the cache check, so every internal consumer of the iterative path —
// the responder, ImrQuery, the CNAME chase, NS-address resolution and the
// validator's RRsetFetcher — is forwarded consistently, and cached answers
// still short-circuit.
//
// Forwarding is forward-only: when every upstream of the matching zone fails,
// the query fails (SERVFAIL); there is no fallback to iteration. The forward
// table is built once at init and is read-only afterwards (no reload path,
// same as stubs).

// ForwardUpstream is one upstream resolver of a ForwardZone, with its own
// DNS client carrying the upstream's transport, port and TLS settings.
// The per-upstream client is what makes non-standard ports work: the shared
// clients in RRsetCacheT.DNSClient bake one port per transport process-wide.
type ForwardUpstream struct {
	Addr      string // bare IP literal
	Port      string
	Transport core.Transport
	Label     string // "addr:port/transport", for logs and hooks
	Client    core.DNSClienter
}

// ForwardZone is the runtime form of an ImrForwardConf entry.
type ForwardZone struct {
	Zone      string // canonical FQDN
	Labels    int    // dns.CountLabel(Zone), precomputed for specificity checks
	TrustAD   bool
	Upstreams []*ForwardUpstream
}

func (fz *ForwardZone) hasEncryptedUpstream() bool {
	for _, up := range fz.Upstreams {
		if core.IsEncryptedTransport(up.Transport) {
			return true
		}
	}
	return false
}

// forwardTransportDefaults maps a transport to its standard port.
var forwardTransportDefaults = map[core.Transport]string{
	core.TransportDo53:    "53",
	core.TransportDo53TCP: "53",
	core.TransportDoT:     "853",
	core.TransportDoH:     "443",
	core.TransportDoQ:     "853", // RFC 9250
}

// buildForwardUpstream validates one ImrUpstreamConf and constructs its
// runtime form, including the dedicated DNS client.
func buildForwardUpstream(zone string, u ImrUpstreamConf) (*ForwardUpstream, error) {
	if net.ParseIP(u.Addr) == nil {
		return nil, fmt.Errorf("forward zone %s: upstream addr %q is not an IP address (hostnames are not supported)", zone, u.Addr)
	}

	transport := core.TransportDo53
	switch u.Transport {
	case "", "udp":
		// "udp" is accepted here as an alias for do53 (UDP with TC=1 and
		// transient-error TCP fallback); it is not a global transport name.
	default:
		var err error
		transport, err = core.StringToTransport(u.Transport)
		if err != nil {
			return nil, fmt.Errorf("forward zone %s: upstream %s: %v", zone, u.Addr, err)
		}
	}

	port := forwardTransportDefaults[transport]
	if u.Port != 0 {
		port = fmt.Sprintf("%d", u.Port)
	}

	var tlsConfig *tls.Config
	if core.IsEncryptedTransport(transport) {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: u.TLSServerName, // empty: crypto/tls verifies against the dialed IP's SANs
		}
		if u.Insecure {
			tlsConfig.InsecureSkipVerify = true
		}
		if transport == core.TransportDoQ {
			// NewDNSClient only fills these when handed a nil config.
			tlsConfig.NextProtos = []string{"doq"}
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	} else if u.TLSServerName != "" || u.Insecure {
		return nil, fmt.Errorf("forward zone %s: upstream %s: tls-server-name/insecure are only meaningful for dot, doh or doq", zone, u.Addr)
	}

	return &ForwardUpstream{
		Addr:      u.Addr,
		Port:      port,
		Transport: transport,
		Label:     fmt.Sprintf("%s/%s", net.JoinHostPort(u.Addr, port), core.TransportToString[transport]),
		Client:    core.NewDNSClient(transport, port, tlsConfig),
	}, nil
}

// BuildImrForwards validates the configured forward zones and returns the
// runtime table, sorted most-specific first so the first suffix match in
// forwardZoneFor is the longest one.
func BuildImrForwards(conf []ImrForwardConf) ([]*ForwardZone, error) {
	if len(conf) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	forwards := make([]*ForwardZone, 0, len(conf))
	for _, fc := range conf {
		if fc.Zone == "" {
			return nil, fmt.Errorf("forward zone without a zone name")
		}
		zone := dns.Fqdn(core.CanonicalizeName(fc.Zone))
		if _, ok := dns.IsDomainName(zone); !ok {
			return nil, fmt.Errorf("forward zone %q is not a valid domain name", fc.Zone)
		}
		if seen[zone] {
			return nil, fmt.Errorf("forward zone %s is configured twice", zone)
		}
		seen[zone] = true
		if len(fc.Upstreams) == 0 {
			return nil, fmt.Errorf("forward zone %s has no upstreams", zone)
		}
		fz := &ForwardZone{
			Zone:    zone,
			Labels:  dns.CountLabel(zone),
			TrustAD: fc.TrustAD,
		}
		for _, u := range fc.Upstreams {
			up, err := buildForwardUpstream(zone, u)
			if err != nil {
				return nil, err
			}
			fz.Upstreams = append(fz.Upstreams, up)
		}
		forwards = append(forwards, fz)
	}
	sort.SliceStable(forwards, func(i, j int) bool {
		return forwards[i].Labels > forwards[j].Labels
	})
	return forwards, nil
}

// forwardZoneFor returns the forward zone responsible for qname, or nil when
// the query should be resolved iteratively. The most specific configured
// forward zone wins; a configured stub zone that is MORE specific than that
// forward zone wins over it (its names are reachable by direct iteration).
func (imr *Imr) forwardZoneFor(qname string) *ForwardZone {
	if len(imr.Forwards) == 0 {
		return nil
	}
	q := dns.Fqdn(core.CanonicalizeName(qname))
	var best *ForwardZone
	for _, fz := range imr.Forwards { // sorted most-specific first
		if dns.IsSubDomain(fz.Zone, q) {
			best = fz
			break
		}
	}
	if best == nil {
		return nil
	}
	for _, sz := range imr.stubZones {
		if dns.CountLabel(sz) > best.Labels && dns.IsSubDomain(sz, q) {
			return nil
		}
	}
	return best
}

// forwardQuery resolves <qname, qtype> by sending a recursive query to the
// forward zone's upstreams, in configured order, until one produces a usable
// response. The return signature matches IterativeDNSQueryWithLoopDetection,
// whose forward hook is the only caller.
//
// Answers are processed by the same machinery as iterative responses:
// handleAnswer (validate locally, cache, chase CNAMEs) unless the zone has
// trust-ad set, and handleNegative for NXDOMAIN/NODATA. A referral-shaped
// response from a recursive upstream is nonsense and counts as a failure.
func (imr *Imr) forwardQuery(ctx context.Context, qname string, qtype uint16, fz *ForwardZone, force bool, requireEncrypted bool) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	// Mirror the iterative path's PR-flag precheck. The error string is
	// load-bearing: ImrResponder matches on "PR flag requires encrypted
	// transport" to attach the EDE.
	if requireEncrypted && !fz.hasEncryptedUpstream() {
		return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
			fmt.Errorf("PR flag requires encrypted transport but no upstream of forward zone %s is encrypted", fz.Zone)
	}

	m := new(dns.Msg)
	m.SetQuestion(qname, qtype) // SetQuestion sets RD=1
	m.SetEdns0(4096, true)

	var lastErr error
	attempts := 0
	for _, up := range fz.Upstreams {
		if requireEncrypted && !core.IsEncryptedTransport(up.Transport) {
			continue
		}
		select {
		case <-ctx.Done():
			return nil, 0, cache.ContextFailure, core.TransportDo53,
				fmt.Errorf("forward zone %s: %v (attempts=%d, last error: %v)", fz.Zone, ctx.Err(), attempts, lastErr)
		default:
		}
		for _, hook := range getImrOutboundQueryHooks() {
			if err := hook(ctx, qname, qtype, up.Label, up.Addr, up.Transport); err != nil {
				return nil, 0, cache.ContextFailure, up.Transport, err
			}
		}
		attempts++
		if Globals.Debug {
			imr.Cache.Logger.Printf("forwardQuery: forwarding <%s, %s> (zone %s) to upstream %s",
				qname, dns.TypeToString[qtype], fz.Zone, up.Label)
		}
		r, _, err := up.Client.Exchange(m, up.Addr, Globals.Debug && !imr.Quiet)
		if err != nil {
			lgDns.Debug("forwardQuery: upstream error", "qname", qname, "qtype", dns.TypeToString[qtype],
				"upstream", up.Label, "err", err)
			lastErr = err
			continue
		}
		if r == nil {
			lastErr = fmt.Errorf("nil response from upstream %s", up.Label)
			continue
		}
		for _, hook := range getImrResponseHooks() {
			hook(ctx, qname, qtype, up.Label, up.Addr, up.Transport, r, r.MsgHdr.Rcode)
		}
		switch r.MsgHdr.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			// Usable; process below.
		default:
			lastErr = fmt.Errorf("upstream %s answered %s", up.Label, dns.RcodeToString[r.MsgHdr.Rcode])
			continue
		}

		if len(r.Answer) > 0 {
			if fz.TrustAD {
				rrset, rcode, cctx, xport := imr.acceptForwardedAnswer(qname, qtype, r, up.Transport)
				if rrset == nil {
					lastErr = fmt.Errorf("upstream %s answer held no usable RRs for %s %s", up.Label, qname, dns.TypeToString[qtype])
					continue
				}
				return rrset, rcode, cctx, xport, nil
			}
			rrset, rcode, cctx, xport, err, done := imr.handleAnswer(ctx, qname, qtype, r, force, up.Transport, requireEncrypted)
			if err != nil || done {
				return rrset, rcode, cctx, xport, err
			}
			lastErr = fmt.Errorf("upstream %s answer held no usable RRs for %s %s", up.Label, qname, dns.TypeToString[qtype])
			continue
		}

		switch classifyResponse(qname, qtype, r) {
		case responseKindNegativeNoData, responseKindNegativeNXDOMAIN:
			if cctx, rcode, handled := imr.handleNegative(qname, qtype, r, up.Transport); handled {
				return nil, rcode, cctx, up.Transport, nil
			}
			lastErr = fmt.Errorf("negative response from upstream %s lacked a usable SOA", up.Label)
			continue
		default:
			// Referral-shaped or malformed: a recursive upstream has no
			// business sending either.
			lastErr = fmt.Errorf("unusable response from upstream %s (rcode %s, %d answer, %d authority)",
				up.Label, dns.RcodeToString[r.MsgHdr.Rcode], len(r.Answer), len(r.Ns))
			continue
		}
	}
	return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
		fmt.Errorf("forward zone %s: no usable response for '%s %s' from any of its %d upstreams (attempts=%d, last error: %v)",
			fz.Zone, qname, dns.TypeToString[qtype], len(fz.Upstreams), attempts, lastErr)
}

// acceptForwardedAnswer implements trust-ad: the upstream's answer is taken
// as-is, including any CNAME chain, without local validation. The upstream's
// AD bit maps onto the cache validation state (AD=1 -> Secure, else
// Insecure), so the responder treats the data exactly as it treats locally
// validated data. Returns a nil RRset when the answer section held nothing
// usable, in which case the caller tries the next upstream.
func (imr *Imr) acceptForwardedAnswer(qname string, qtype uint16, r *dns.Msg, transport core.Transport) (*core.RRset, int, cache.CacheContext, core.Transport) {
	rrset := core.RRset{
		Name:   qname,
		Class:  dns.ClassINET,
		RRtype: qtype,
	}
	for _, rr := range r.Answer {
		switch t := rr.Header().Rrtype; t {
		case dns.TypeRRSIG:
			rrset.RRSIGs = append(rrset.RRSIGs, rr)
		case qtype, dns.TypeCNAME:
			rrset.RRs = append(rrset.RRs, rr)
		default:
			imr.Cache.Logger.Printf("acceptForwardedAnswer: ignoring %s RR in answer for %s %s",
				dns.TypeToString[t], qname, dns.TypeToString[qtype])
		}
	}
	if len(rrset.RRs) == 0 {
		return nil, r.MsgHdr.Rcode, cache.ContextFailure, transport
	}
	state := cache.ValidationStateInsecure
	if r.MsgHdr.AuthenticatedData {
		state = cache.ValidationStateSecure
	}
	imr.Cache.Set(qname, qtype, &cache.CachedRRset{
		Name:       qname,
		RRtype:     qtype,
		Rcode:      uint8(r.MsgHdr.Rcode),
		RRset:      &rrset,
		Context:    cache.ContextAnswer,
		State:      state,
		Expiration: time.Now().Add(cache.GetMinTTL(rrset.RRs)),
		Transport:  transport,
	})
	return &rrset, r.MsgHdr.Rcode, cache.ContextAnswer, transport
}
