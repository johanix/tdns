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
	"strings"
	"sync"
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
	Insecure  bool   // certificate verification disabled (encrypted transports only)
	Label     string // "addr:port/transport", for logs and hooks
	Client    core.DNSClienter

	// Reachability state, fed by the startup probe and by live queries.
	// "Reachable" means a DNS response arrived, whatever its rcode; only
	// transport-level failures (error / nil response) count as failures.
	mu          sync.Mutex
	queries     uint64 // exchange attempts (probe included)
	failures    uint64 // transport-level failures
	lastSuccess time.Time
	lastErrMsg  string
	lastErrTime time.Time
	failing     bool // last exchange was a transport-level failure
}

// recordSuccess and recordFailure update the upstream's reachability state
// and report whether it TRANSITIONED, so the caller knows to recompute the
// aggregate Upstream/ImrForward server error.
func (up *ForwardUpstream) recordSuccess() bool {
	up.mu.Lock()
	defer up.mu.Unlock()
	up.queries++
	up.lastSuccess = time.Now()
	was := up.failing
	up.failing = false
	return was
}

// recordFailure takes the failed exchange's START time and discards the
// failure entirely when a later exchange has already succeeded: Exchange is
// not cancellable, so a probe (or slow query) begun against a down upstream
// runs to its timeout even if the upstream came up — and a client query
// succeeded — in the meantime. Recording that stale observation would
// re-mark a healthy upstream failing and set a DEGRADED that lies until the
// next live query, which teaches operators to ignore the flag.
func (up *ForwardUpstream) recordFailure(start time.Time, err error) bool {
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.lastSuccess.After(start) {
		return false
	}
	up.queries++
	up.failures++
	up.lastErrMsg = err.Error()
	up.lastErrTime = time.Now()
	was := up.failing
	up.failing = true
	return !was
}

// authenticated reports whether this upstream's channel authenticates the
// server: an encrypted transport with certificate verification enabled.
// This is what trust-ad requires — an AD bit accepted over anything less is
// an attacker-settable "cache this as Secure" instruction.
func (up *ForwardUpstream) authenticated() bool {
	return core.IsEncryptedTransport(up.Transport) && !up.Insecure
}

// ForwardZone is the runtime form of an ImrForwardConf entry.
type ForwardZone struct {
	Zone      string // canonical FQDN
	Labels    int    // dns.CountLabel(Zone), precomputed for specificity checks
	TrustAD   bool
	Upstreams []*ForwardUpstream

	// Throttle for the all-upstreams-failed WARN, so a dead upstream under
	// query load does not turn the log into a firehose while still being
	// impossible to miss.
	logMu           sync.Mutex
	lastServfailLog time.Time
}

// noteAllUpstreamsFailed WARNs that a query was answered SERVFAIL because
// every upstream failed — at most once per throttle interval per zone.
// Before this existed the responder wrote the SERVFAIL without any log line,
// which is how a forwarding resolver could serve SERVFAIL for everything, for
// an hour, in silence (#443).
func (fz *ForwardZone) noteAllUpstreamsFailed(qname string, qtype uint16, attempts int, lastErr error) bool {
	const throttle = 30 * time.Second
	fz.logMu.Lock()
	now := time.Now()
	if now.Sub(fz.lastServfailLog) < throttle {
		fz.logMu.Unlock()
		return false
	}
	fz.lastServfailLog = now
	fz.logMu.Unlock()
	lgImr.Warn("forward zone: all upstreams failed, answering SERVFAIL (throttled: one line per 30s per zone)",
		"zone", fz.Zone, "qname", qname, "qtype", dns.TypeToString[qtype],
		"upstreams", len(fz.Upstreams), "attempts", attempts, "lastErr", lastErr)
	return true
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
		Insecure:  u.Insecure,
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
			// trust-ad caches the upstream's AD bit as ValidationStateSecure,
			// which the responder re-serves as AD=1. Over an unauthenticated
			// channel that bit is attacker-settable, so refuse the combination
			// outright rather than silently skipping the plaintext upstream.
			if fc.TrustAD && !up.authenticated() {
				return nil, fmt.Errorf("forward zone %s: trust-ad requires every upstream to be encrypted and verified (dot/doh/doq without insecure); upstream %s is not", zone, up.Label)
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
	// Local validation must be independent of the upstream's validator: with
	// CD=0 a validating upstream SERVFAILs data *it* considers bogus, so we
	// would never see the RRSIGs, never apply our own trust anchors, and
	// could not tell a validation failure from a dead upstream. CD=1 hands
	// us the data to judge ourselves. With trust-ad the roles reverse — the
	// upstream's validation is the product — so CD stays 0 there.
	if !fz.TrustAD {
		m.CheckingDisabled = true
	}

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
		start := time.Now()
		r, _, err := up.Client.Exchange(m, up.Addr, Globals.Debug && !imr.Quiet)
		if err == nil && r == nil {
			err = fmt.Errorf("nil response from upstream %s", up.Label)
		}
		if err != nil {
			lgDns.Debug("forwardQuery: upstream error", "qname", qname, "qtype", dns.TypeToString[qtype],
				"upstream", up.Label, "err", err)
			if up.recordFailure(start, err) {
				// Reachability transition: this line is the only INFO-level
				// trace of a mid-life upstream failure, so it must exist —
				// repeat failures stay at Debug above.
				lgImr.Warn("forward upstream unreachable", "zone", fz.Zone, "upstream", up.Label, "err", err)
				imr.updateForwardUpstreamError()
			}
			lastErr = err
			continue
		}
		if up.recordSuccess() {
			lgImr.Info("forward upstream recovered", "zone", fz.Zone, "upstream", up.Label)
			imr.updateForwardUpstreamError()
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
				if fz.TrustAD {
					imr.applyTrustADToNegative(qname, qtype, r.MsgHdr.AuthenticatedData)
				}
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
	fz.noteAllUpstreamsFailed(qname, qtype, attempts, lastErr)
	return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
		fmt.Errorf("forward zone %s: no usable response for '%s %s' from any of its %d upstreams (attempts=%d, last error: %v)",
			fz.Zone, qname, dns.TypeToString[qtype], len(fz.Upstreams), attempts, lastErr)
}

// updateForwardUpstreamError recomputes the aggregate Upstream/ImrForward
// server error from the per-upstream failing flags: set with the full list of
// failing upstreams while any is failing, cleared when none is. Called on
// reachability transitions and after the startup probe.
func (imr *Imr) updateForwardUpstreamError() {
	if imr.errorRegistry == nil {
		return
	}
	// Serialize scan + registry write; see fwdErrMu.
	imr.fwdErrMu.Lock()
	defer imr.fwdErrMu.Unlock()
	var failing []string
	for _, fz := range imr.Forwards {
		for _, up := range fz.Upstreams {
			up.mu.Lock()
			if up.failing {
				failing = append(failing, fmt.Sprintf("%s (zone %s: %s)", up.Label, fz.Zone, up.lastErrMsg))
			}
			up.mu.Unlock()
		}
	}
	if len(failing) == 0 {
		imr.errorRegistry.ClearImrForwardUpstreamError()
		return
	}
	imr.errorRegistry.SetImrForwardUpstreamError(
		fmt.Sprintf("%d forward upstream(s) unreachable: %s", len(failing), strings.Join(failing, "; ")))
}

// ProbeForwardUpstreams sends one recursive ". NS" probe to every forward
// upstream, in parallel, and records reachability. Failures are WARNed and
// aggregated into the Upstream/ImrForward server error (visible in `config
// status` as DEGRADED) — deliberately not fatal: refusing to start would
// recreate the boot-order race this probe exists to make visible. A failing
// upstream clears as soon as any later exchange against it succeeds.
func (imr *Imr) ProbeForwardUpstreams() {
	if len(imr.Forwards) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, fz := range imr.Forwards {
		for _, up := range fz.Upstreams {
			wg.Add(1)
			go func(zone string, up *ForwardUpstream) {
				defer wg.Done()
				_, _ = imr.probeForwardUpstream(zone, up)
			}(fz.Zone, up)
		}
	}
	wg.Wait()
	imr.updateForwardUpstreamError()
}

// applyTrustADToNegative maps the upstream's AD bit onto the negative entry
// handleNegative just cached, the same way acceptForwardedAnswer does for
// positives: AD=1 -> Secure, else Insecure. handleNegative's own local
// validation of the denial is overridden — under trust-ad the upstream's
// verdict IS the product, for negatives no less than for positives.
func (imr *Imr) applyTrustADToNegative(qname string, qtype uint16, ad bool) {
	crrset := imr.Cache.Get(qname, qtype)
	if crrset == nil {
		return
	}
	crrset.State = cache.ValidationStateInsecure
	if ad {
		crrset.State = cache.ValidationStateSecure
	}
	imr.Cache.Set(qname, qtype, crrset)
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
