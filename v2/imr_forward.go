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
// table is immutable once published; a config reload builds a whole new one
// and swaps it (imr_reload.go), so a query in flight keeps the table it
// started with.

// ForwardUpstream is one upstream resolver of a ForwardZone, with its own
// DNS client carrying the upstream's transport, port and TLS settings.
// The per-upstream client is what makes non-standard ports work: the shared
// clients in RRsetCacheT.DNSClient bake one port per transport process-wide.
type ForwardUpstream struct {
	Addr      string // bare IP literal
	Port      string
	Transport core.Transport
	Insecure  bool // certificate verification disabled (encrypted transports only)
	// TLSServerName is the name the certificate is verified against (empty:
	// the dialed IP must be in a SAN). Kept alongside the client that was
	// built from it so the config identity of an upstream can be compared
	// without reaching into the client's TLS config.
	TLSServerName string
	Label         string // "addr:port/transport", for logs and hooks
	Client        core.DNSClienter

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
// failure entirely when a later exchange has already succeeded: a probe (or
// slow query) begun against a down upstream runs to its timeout even if the
// upstream came up — and a client query succeeded — in the meantime.
// Recording that stale observation would re-mark a healthy upstream failing
// and set a DEGRADED that lies until the next live query, which teaches
// operators to ignore the flag. (Cancellation shortens that window but does
// not close it: an upstream that accepts and stalls still runs to its
// deadline unless someone cancels the ctx.)
func (up *ForwardUpstream) recordFailure(start time.Time, err error) bool {
	up.mu.Lock()
	defer up.mu.Unlock()
	// A superseded failure was still an exchange attempt: count it in
	// queries, but leave failures and the failing flag to the fresher
	// success it lost against.
	up.queries++
	if up.lastSuccess.After(start) {
		return false
	}
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
// Time budget for one forward query, divided among the zone's upstreams (#470).
//
// Every upstream used to share a single deadline, so a blackholed first
// upstream — one that drops rather than refuses — consumed the whole of it and
// the second was never really tried. Measured before the fix: a first upstream
// that refused was failed over in 0s; one that dropped SERVFAILed at 8s with a
// healthy second upstream configured.
const (
	// forwardMinAttempt is the least time in which an attempt could
	// plausibly succeed. A TLS 1.3 handshake plus a query is comfortably
	// 300-400ms on a slow link, and DoH over HTTP/2 more, so a slice below
	// this cannot produce an answer for the transports that most need the
	// fallback. An upstream whose slice would be smaller is NOT attempted,
	// which is a different thing from being attempted and failing — see
	// the starved handling in forwardQuery.
	forwardMinAttempt = 500 * time.Millisecond

	// forwardDefaultBudget is what gets divided when the caller's context
	// carries no deadline. It is the client timeout, so a single upstream
	// behaves exactly as it did before this split existed.
	forwardDefaultBudget = core.DefaultClientTimeout
)

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
			// Refused rather than resolved: "verify against this anchor" and
			// "verify nothing" cannot both be meant, and silently honouring
			// either one is the worst outcome -- a config that names a CA file
			// and does not use it reads as verified and is not.
			if u.CAFile != "" {
				return nil, fmt.Errorf("forward zone %s: upstream %s: ca-file and insecure are mutually exclusive (ca-file names a trust anchor; insecure skips verification entirely)", zone, u.Addr)
			}
			tlsConfig.InsecureSkipVerify = true
		}
		if u.CAFile != "" {
			// Parsed now rather than at dial time so a missing or unparseable
			// anchor is a config error, not a resolution failure hours later.
			// loadCAPool memoizes by mtime, so pointing several upstreams at
			// one anchor reads it once.
			pool, err := loadCAPool(u.CAFile)
			if err != nil {
				return nil, fmt.Errorf("forward zone %s: upstream %s: %v", zone, u.Addr, err)
			}
			tlsConfig.RootCAs = pool
		}
		if transport == core.TransportDoQ {
			// NewDNSClient only fills these when handed a nil config.
			tlsConfig.NextProtos = []string{"doq"}
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	} else if u.TLSServerName != "" || u.Insecure || u.CAFile != "" {
		return nil, fmt.Errorf("forward zone %s: upstream %s: tls-server-name/insecure/ca-file are only meaningful for dot, doh or doq", zone, u.Addr)
	}

	return &ForwardUpstream{
		Addr:          u.Addr,
		Port:          port,
		Transport:     transport,
		Insecure:      u.Insecure,
		TLSServerName: u.TLSServerName,
		Label:         fmt.Sprintf("%s/%s", net.JoinHostPort(u.Addr, port), core.TransportToString[transport]),
		Client:        core.NewDNSClient(transport, port, tlsConfig),
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
	// One snapshot for the whole decision: a reload swapping the table
	// mid-way must not let a stub from the new table veto a forward from
	// the old one.
	table := imr.zoneTable()
	if len(table.forwards) == 0 {
		return nil
	}
	q := dns.Fqdn(core.CanonicalizeName(qname))
	var best *ForwardZone
	for _, fz := range table.forwards { // sorted most-specific first
		if dns.IsSubDomain(fz.Zone, q) {
			best = fz
			break
		}
	}
	if best == nil {
		return nil
	}
	for _, sz := range table.stubs {
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

	// Eligible upstreams are resolved BEFORE the loop because the time budget
	// is divided among them: the split needs to know how many there are, and
	// the requireEncrypted skip changes that count.
	eligible := make([]*ForwardUpstream, 0, len(fz.Upstreams))
	for _, up := range fz.Upstreams {
		if requireEncrypted && !core.IsEncryptedTransport(up.Transport) {
			continue
		}
		eligible = append(eligible, up)
	}

	// The budget is whichever is tighter: what the caller still allows, or the
	// client timeout. Taking only the latter would let a query outlive the
	// deadline its caller set.
	budget := forwardDefaultBudget
	if dl, ok := ctx.Deadline(); ok {
		if r := time.Until(dl); r < budget {
			budget = r
		}
	}
	overallDeadline := time.Now().Add(budget)

	var lastErr error
	attempts := 0
	starved := 0
	for i, up := range eligible {
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
		// Front-loaded halving of what is LEFT, not of the original budget:
		// an upstream that refuses in 5ms donates its unused time to whoever
		// follows, which is what keeps the already-working fast-failure case
		// fast. The last upstream takes the whole remainder rather than its
		// geometric share — the alternative leaves budget unspent on a query
		// that is about to fail anyway.
		remaining := time.Until(overallDeadline)
		slice := remaining / 2
		if i == len(eligible)-1 {
			slice = remaining
		}
		if slice < forwardMinAttempt {
			// Not attempted. Deliberately not a failure: recording it would
			// mark a healthy upstream unreachable because an earlier one was
			// slow, which is exactly the DEGRADED-on-healthy-infrastructure
			// half of #470.
			starved++
			lastErr = fmt.Errorf("upstream %s not attempted: %v left, below the %v an attempt needs",
				up.Label, remaining.Round(time.Millisecond), forwardMinAttempt)
			lgDns.Debug("forwardQuery: upstream starved", "qname", qname, "upstream", up.Label,
				"remaining", remaining, "floor", forwardMinAttempt)
			continue
		}

		attemptCtx, cancelAttempt := context.WithTimeout(ctx, slice)
		start := time.Now()
		// Cancellable (#435): with a plain Exchange, ordered failover could
		// only move on between upstreams, so a hung first upstream cost the
		// full client timeout before the second was even tried. The bounded
		// attemptCtx is what makes that cancellation happen on schedule
		// rather than only when the caller gives up (#470).
		r, _, err := core.ExchangeCtx(attemptCtx, up.Client, m, up.Addr, Globals.Debug && !imr.Quiet)
		// Truncated by its own slice, with the caller still waiting: the
		// upstream ran out of TIME, it did not fail.
		truncated := attemptCtx.Err() != nil && ctx.Err() == nil
		cancelAttempt()
		if err == nil && r == nil {
			err = fmt.Errorf("nil response from upstream %s", up.Label)
		}
		if err != nil && truncated {
			starved++
			lastErr = fmt.Errorf("upstream %s did not answer within its %v of the budget",
				up.Label, slice.Round(time.Millisecond))
			lgDns.Debug("forwardQuery: upstream slice expired", "qname", qname,
				"upstream", up.Label, "slice", slice)
			continue
		}
		if cerr := ctx.Err(); cerr != nil && err != nil {
			// Abandoned, not failed. The ctx.Done() check at the top of the
			// loop stops us between upstreams; this one is needed because a
			// cancel now reaches the exchange itself, and recording it would
			// mark a healthy upstream unreachable — and set a DEGRADED that
			// outlives the shutdown that caused it. Same guard, same reason,
			// as probeForwardUpstream and tryServer.
			return nil, 0, cache.ContextFailure, up.Transport,
				fmt.Errorf("forward zone %s: %w (attempts=%d, last error: %v)", fz.Zone, cerr, attempts, lastErr)
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
	// starved is reported separately from attempts because the two call for
	// different action: attempts that failed say something about the
	// upstreams, whereas starved ones say the budget was too small to try
	// them -- usually because an earlier upstream is blackholing.
	starvedNote := ""
	if starved > 0 {
		starvedNote = fmt.Sprintf(", starved=%d", starved)
	}
	return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
		fmt.Errorf("forward zone %s: no usable response for '%s %s' from any of its %d upstreams (attempts=%d%s, last error: %v)",
			fz.Zone, qname, dns.TypeToString[qtype], len(fz.Upstreams), attempts, starvedNote, lastErr)
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
	for _, fz := range imr.ForwardZones() {
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

// ProbeForwardUpstreams sends one recursive probe (the forward zone's SOA)
// to every forward upstream, in parallel, and records reachability. Failures
// are WARNed and aggregated into the Upstream/ImrForward server error
// (visible in `config status` as DEGRADED) — deliberately not fatal:
// refusing to start would recreate the boot-order race this probe exists to
// make visible. A failing upstream clears as soon as any later exchange
// against it succeeds. A cancelled ctx abandons the probes, in-flight ones
// included.
func (imr *Imr) ProbeForwardUpstreams(ctx context.Context) {
	forwards := imr.ForwardZones()
	if len(forwards) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, fz := range forwards {
		for _, up := range fz.Upstreams {
			wg.Add(1)
			go func(zone string, up *ForwardUpstream) {
				defer wg.Done()
				_, _ = imr.probeForwardUpstream(ctx, zone, up)
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
