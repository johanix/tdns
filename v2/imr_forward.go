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
	edns0 "github.com/johanix/tdns/v2/edns0"
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
	// failing means "this upstream is not usable right now", set either by a
	// transport-level failure (immediately) or by a run of slice timeouts
	// (recordSliceTimeout). Reported, not selected on.
	failing bool
	// sliceTimeouts counts CONSECUTIVE attempts that ran out of their slice
	// of the query budget rather than failing (#470). Any other outcome --
	// a success or a transport-level failure -- resets it. Separate from
	// failures because one of them is not evidence and several are; see
	// recordSliceTimeout.
	sliceTimeouts uint64

	// Quarantine is a CONFIG verdict, not a reachability one: the upstream
	// is unusable as configured, so it is never dialled and can never become
	// `failing`. Set when the table is built and changed only by a reload —
	// but under mu all the same, because carryForwardUpstreams shares one
	// upstream object between the outgoing and incoming tables while queries
	// are still running on the old one.
	quarantined   bool
	quarantineWhy string
}

// quarantine marks the upstream unusable and records why. Idempotent.
func (up *ForwardUpstream) quarantine(reason string) {
	up.mu.Lock()
	defer up.mu.Unlock()
	up.quarantined = true
	up.quarantineWhy = reason
}

// adoptQuarantineFrom copies src's build-time verdict onto up. Called by
// carryForwardUpstreams: the carried object keeps its reachability counters
// but must take the NEW config's verdict, because the two are independent —
// upstreamKey does not include the zone's TrustAD, so an upstream quarantined
// for trust-ad reasons has an unchanged key after `trust-ad:` is removed and
// would otherwise carry its quarantine into a config that no longer earns it.
func (up *ForwardUpstream) adoptQuarantineFrom(src *ForwardUpstream) {
	q, why := src.quarantineState()
	up.mu.Lock()
	defer up.mu.Unlock()
	up.quarantined, up.quarantineWhy = q, why
}

// quarantineState reports the verdict and its reason.
func (up *ForwardUpstream) quarantineState() (bool, string) {
	up.mu.Lock()
	defer up.mu.Unlock()
	return up.quarantined, up.quarantineWhy
}

// isQuarantined is quarantineState without the reason, for the query path.
func (up *ForwardUpstream) isQuarantined() bool {
	up.mu.Lock()
	defer up.mu.Unlock()
	return up.quarantined
}

// recordSuccess and recordFailure update the upstream's reachability state
// and report whether it TRANSITIONED, so the caller knows to recompute the
// aggregate Upstream/ImrForward server error.
func (up *ForwardUpstream) recordSuccess() bool {
	up.mu.Lock()
	defer up.mu.Unlock()
	up.queries++
	up.lastSuccess = time.Now()
	// An answer ends any run of slice timeouts: what the run is evidence of
	// is an upstream that never answers, and this one just did.
	up.sliceTimeouts = 0
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
	// A transport-level failure ends any run of slice timeouts, for the same
	// reason a success does: the run is a claim about CONSECUTIVE attempts
	// that answered nothing, and this attempt is a different observation. A
	// refused connection in particular says the upstream is reachable and
	// declining, which is not what "never answers" describes -- and nothing is
	// lost by resetting, because the line below has already marked it failing
	// on the stronger evidence.
	up.sliceTimeouts = 0
	up.lastErrMsg = err.Error()
	up.lastErrTime = time.Now()
	was := up.failing
	up.failing = true
	return !was
}

// recordSliceTimeout records an attempt that used up its whole slice of the
// query budget without answering, and reports whether the upstream TRANSITIONED
// to failing -- which takes forwardSliceTimeoutsBeforeFailing of them in a row.
//
// This exists because a blackholed upstream is otherwise the one failure mode
// `config status` never reports. It is dialled, it consumes its slice, and the
// query path deliberately does NOT call recordFailure for it (that suppression
// is #470's second half: an attempt cut short must not mark a healthy upstream
// unreachable). The consequence, left alone, is that the upstream doing the
// damage stays green while every query pays half its budget to it.
//
// One timeout is genuinely not evidence: an attempt gets at least
// forwardMinAttempt, which is a floor rather than a guarantee, and a slow DoH
// upstream on a bad path can exceed it and still be working. A run of them
// with NOTHING ELSE in between -- no answer, and no transport failure either,
// both of which reset the count -- is a different claim, and it is the true
// one.
//
// Same staleness guard as recordFailure, for the same reason: an observation
// that a later success has already contradicted must not re-mark the upstream.
func (up *ForwardUpstream) recordSliceTimeout(start time.Time) bool {
	up.mu.Lock()
	defer up.mu.Unlock()
	up.queries++
	if up.lastSuccess.After(start) {
		return false
	}
	up.sliceTimeouts++
	if up.sliceTimeouts < forwardSliceTimeoutsBeforeFailing {
		return false
	}
	// Deliberately not counted in failures: nothing here observed a transport
	// failure. lastErrMsg carries what actually happened, because "failing"
	// with no error text is the kind of status line nobody can act on.
	up.lastErrMsg = fmt.Sprintf("no answer within its slice of the query budget, %d times running",
		up.sliceTimeouts)
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
func (fz *ForwardZone) noteAllUpstreamsFailed(qname string, qtype uint16, live, attempts int, lastErr error) bool {
	if !fz.throttleServfailLog() {
		return false
	}
	lgImr.Warn("forward zone: all upstreams failed, answering SERVFAIL (throttled: one line per 30s per zone)",
		"zone", fz.Zone, "qname", qname, "qtype", dns.TypeToString[qtype],
		"upstreams", live, "attempts", attempts, "lastErr", lastErr)
	return true
}

// noteQuarantined is noteAllUpstreamsFailed for the zone that never had a
// usable upstream to fail: same throttle, same "do not serve SERVFAIL in
// silence" reason (#443), different cause.
func (fz *ForwardZone) noteQuarantined(qname string, qtype uint16, why string) bool {
	if !fz.throttleServfailLog() {
		return false
	}
	lgImr.Warn("forward zone is quarantined, answering SERVFAIL (throttled: one line per 30s per zone)",
		"zone", fz.Zone, "qname", qname, "qtype", dns.TypeToString[qtype], "reason", why)
	return true
}

// throttleServfailLog reports whether this zone may emit a SERVFAIL-cause
// line now, and takes the slot if so.
func (fz *ForwardZone) throttleServfailLog() bool {
	const throttle = 30 * time.Second
	fz.logMu.Lock()
	defer fz.logMu.Unlock()
	now := time.Now()
	if now.Sub(fz.lastServfailLog) < throttle {
		return false
	}
	fz.lastServfailLog = now
	return true
}

// liveUpstreams returns the upstreams that are usable as configured, in
// configured order. Everything that chooses or counts an upstream goes
// through this rather than ranging over fz.Upstreams directly.
func (fz *ForwardZone) liveUpstreams() []*ForwardUpstream {
	live := make([]*ForwardUpstream, 0, len(fz.Upstreams))
	for _, up := range fz.Upstreams {
		if !up.isQuarantined() {
			live = append(live, up)
		}
	}
	return live
}

// quarantineState reports whether the zone itself is quarantined — no usable
// upstream is left — and why. Derived on every call rather than stored: the
// only input is the per-upstream verdicts, and a derived answer cannot go
// stale behind a reload that changed them.
func (fz *ForwardZone) quarantineState() (bool, string) {
	if len(fz.Upstreams) == 0 {
		return true, "no upstreams configured"
	}
	var why []string
	for _, up := range fz.Upstreams {
		q, reason := up.quarantineState()
		if !q {
			return false, ""
		}
		why = append(why, fmt.Sprintf("%s: %s", up.Label, reason))
	}
	return true, "every upstream is quarantined (" + strings.Join(why, "; ") + ")"
}

// isQuarantined is quarantineState without the reason, for the query path.
func (fz *ForwardZone) isQuarantined() bool {
	q, _ := fz.quarantineState()
	return q
}

// hasEncryptedUpstream reports whether the zone can be served over an
// encrypted transport at all. Quarantined upstreams do not count: they are
// never dialled, so promising the PRIVACY guarantee on the strength of one
// would be a lie the query path could not keep.
//
// The liveUpstreams() call is load-bearing, not a tidy-up. Anything that
// selects or counts upstreams for the privacy path must go through it; a
// version that ranges fz.Upstreams directly both mis-answers this question
// and can hand a placeholder's nil Client to the query loop.
// TestForwardQuarantineExcludedFromPrivacySelection fails if it is lost.
func (fz *ForwardZone) hasEncryptedUpstream() bool {
	for _, up := range fz.liveUpstreams() {
		if core.IsEncryptedTransport(up.Transport) {
			return true
		}
	}
	return false
}

// forwardUpstreamsForPrivacy returns the upstreams to try, in order, for a
// query carrying the given PRIVACY level:
//
//   - PrivacyNone: the configured order, untouched. The operator's ordering is
//     a failover preference and nothing has asked us to override it.
//   - PrivacyOpportunistic: encrypted upstreams first, then the cleartext
//     ones, each group keeping its configured relative order. Preference, not
//     exclusion -- the client said cleartext is acceptable when there is
//     nothing better.
//   - PrivacyStrict: encrypted upstreams only.
//
// Starts from liveUpstreams(), not fz.Upstreams: a quarantined upstream is
// never dialled, so including one here would both distort the strict/
// opportunistic ordering and hand a placeholder's nil Client to the exchange.
// TestForwardQueryNeverDialsAQuarantinedUpstream fails if this reverts.
func forwardUpstreamsForPrivacy(fz *ForwardZone, privacy edns0.PrivacyLevel) []*ForwardUpstream {
	live := fz.liveUpstreams()
	if privacy == edns0.PrivacyNone {
		return live
	}
	encrypted := make([]*ForwardUpstream, 0, len(live))
	var cleartext []*ForwardUpstream
	for _, up := range live {
		if core.IsEncryptedTransport(up.Transport) {
			encrypted = append(encrypted, up)
			continue
		}
		cleartext = append(cleartext, up)
	}
	if privacy == edns0.PrivacyStrict {
		return encrypted
	}
	return append(encrypted, cleartext...)
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

	// forwardSliceTimeoutsBeforeFailing is how many slice timeouts in a row
	// it takes to call an upstream unreachable. See recordSliceTimeout for
	// why one is not enough and three is.
	forwardSliceTimeoutsBeforeFailing = 3

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

// ForwardDiag is one problem found while building the forward table. A diag
// with Dropped set means the configured entry could not enter the table at
// all; otherwise the entry is in the table with the offending upstream (or
// the whole zone) quarantined.
type ForwardDiag struct {
	Zone     string // "" when the entry had no usable zone name
	Upstream string // "" for a zone-level problem
	Msg      string
	Dropped  bool
}

func (d ForwardDiag) String() string {
	switch {
	case d.Zone == "":
		return d.Msg
	case d.Upstream == "":
		return fmt.Sprintf("forward zone %s: %s", d.Zone, d.Msg)
	default:
		return fmt.Sprintf("forward zone %s: upstream %s: %s", d.Zone, d.Upstream, d.Msg)
	}
}

// forwardDiagsError joins diags into the single error the reload path still
// refuses whole with.
func forwardDiagsError(diags []ForwardDiag) error {
	if len(diags) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(diags))
	for _, d := range diags {
		msgs = append(msgs, d.String())
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}

// BuildImrForwards validates the configured forward zones and returns the
// runtime table, sorted most-specific first so the first suffix match in
// forwardZoneFor is the longest one, together with a diagnostic per problem
// found.
//
// It does not fail whole (#475). A misconfigured upstream is QUARANTINED —
// present in the table, reported, never dialled — and a zone left with no
// usable upstream is quarantined in turn, so names under it SERVFAIL rather
// than silently falling back to iteration. The startup path serves what is
// left; the reload path turns any diag into a whole-config refusal
// (ReloadZones), because there it has a good running state to preserve.
//
// Two problems cannot be quarantined and are DROPPED instead, because
// quarantine needs a namespace to apply to and these have none: an entry
// with no usable zone name, and a duplicate of a zone already configured
// (the first definition stands).
func BuildImrForwards(conf []ImrForwardConf) ([]*ForwardZone, []ForwardDiag) {
	if len(conf) == 0 {
		return nil, nil
	}
	var diags []ForwardDiag
	seen := map[string]bool{}
	forwards := make([]*ForwardZone, 0, len(conf))
	for _, fc := range conf {
		if fc.Zone == "" {
			diags = append(diags, ForwardDiag{Msg: "forward zone without a zone name (dropped)", Dropped: true})
			continue
		}
		zone := dns.Fqdn(core.CanonicalizeName(fc.Zone))
		if _, ok := dns.IsDomainName(zone); !ok {
			diags = append(diags, ForwardDiag{
				Msg:     fmt.Sprintf("forward zone %q is not a valid domain name (dropped)", fc.Zone),
				Dropped: true,
			})
			continue
		}
		if seen[zone] {
			diags = append(diags, ForwardDiag{
				Zone: zone, Msg: "configured twice; this definition is dropped and the first one stands",
				Dropped: true,
			})
			continue
		}
		seen[zone] = true
		fz := &ForwardZone{
			Zone:    zone,
			Labels:  dns.CountLabel(zone),
			TrustAD: fc.TrustAD,
		}
		if len(fc.Upstreams) == 0 {
			// Kept in the table, not dropped: dropping it would hand every
			// name under the zone back to iteration, which is the one thing
			// a forward-only zone must never do silently.
			diags = append(diags, ForwardDiag{Zone: zone, Msg: "no upstreams configured; the zone is quarantined"})
		}
		for _, u := range fc.Upstreams {
			up, err := buildForwardUpstream(zone, u)
			if err != nil {
				up = placeholderUpstream(u, err.Error())
				diags = append(diags, ForwardDiag{Zone: zone, Upstream: up.Label, Msg: err.Error()})
				fz.Upstreams = append(fz.Upstreams, up)
				continue
			}
			// trust-ad caches the upstream's AD bit as ValidationStateSecure,
			// which the responder re-serves as AD=1. Over an unauthenticated
			// channel that bit is attacker-settable, so refuse to use the
			// upstream rather than silently serving an attacker's verdict.
			if fc.TrustAD && !up.authenticated() {
				const why = "trust-ad requires every upstream to be encrypted and verified (dot/doh/doq without insecure); this one is not"
				up.quarantine(why)
				diags = append(diags, ForwardDiag{Zone: zone, Upstream: up.Label, Msg: why})
			}
			fz.Upstreams = append(fz.Upstreams, up)
		}
		forwards = append(forwards, fz)
	}
	sort.SliceStable(forwards, func(i, j int) bool {
		return forwards[i].Labels > forwards[j].Labels
	})
	return forwards, diags
}

// placeholderUpstream is the table entry for an upstream that could not be
// built at all. It exists so `imr forward list` and `imr forward status` can
// still show the operator which configured upstream is broken and why —
// without it, a zone whose only upstream is unparseable would render as a
// zone with no upstreams. It carries no Client, so it is created ALREADY
// quarantined rather than left for the caller to mark: liveUpstreams is what
// keeps it away from anything that dials, and an unquarantined placeholder
// would be a nil client on the query path.
func placeholderUpstream(u ImrUpstreamConf, reason string) *ForwardUpstream {
	addr := u.Addr
	if addr == "" {
		addr = "<unset>"
	}
	label := addr
	// Keep the configured transport when it parses, so `forward status` does
	// not report a broken dot upstream as do53. When it is the transport that
	// is unparseable, do53 is just the zero value on an entry nothing dials.
	transport := core.TransportDo53
	if u.Transport != "" {
		label = addr + "/" + u.Transport
		if t, err := core.StringToTransport(u.Transport); err == nil {
			transport = t
		}
	}
	return &ForwardUpstream{
		Addr: u.Addr, Transport: transport, Label: label,
		quarantined: true, quarantineWhy: reason,
	}
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
func (imr *Imr) forwardQuery(ctx context.Context, qname string, qtype uint16, fz *ForwardZone, force bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	// A quarantined zone has no usable upstream, so there is nothing to try:
	// SERVFAIL without an exchange. Deliberately NOT a fallback to iteration
	// — forwarding is forward-only, and for a "zone: ." forward silently
	// iterating would change the resolution path for everything.
	if q, why := fz.quarantineState(); q {
		fz.noteQuarantined(qname, qtype, why)
		return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
			fmt.Errorf("forward zone %s is quarantined: %s", fz.Zone, why)
	}

	// Mirror the iterative path's strict-privacy precheck. ImrResponder
	// recognises the failure through errors.Is(ErrPrivacyUnavailable) and
	// attaches the EDE.
	if privacy == edns0.PrivacyStrict && !fz.hasEncryptedUpstream() {
		return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
			fmt.Errorf("%w: no upstream of forward zone %s is encrypted", ErrPrivacyUnavailable, fz.Zone)
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

	// The selection is what this query may use: quarantined upstreams are
	// already gone (forwardUpstreamsForPrivacy starts from liveUpstreams),
	// and the privacy level has ordered or filtered what remains. len(live)
	// is therefore what the SERVFAIL below should count -- and what the time
	// budget is divided among, which is why it is resolved before the loop.
	live := forwardUpstreamsForPrivacy(fz, privacy)

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
	for i, up := range live {
		select {
		case <-ctx.Done():
			return nil, 0, cache.ContextFailure, core.TransportDo53,
				fmt.Errorf("forward zone %s: %v (attempts=%d, last error: %v)", fz.Zone, ctx.Err(), attempts, lastErr)
		default:
		}
		// Front-loaded halving of what is LEFT, not of the original budget:
		// an upstream that refuses in 5ms donates its unused time to whoever
		// follows, which is what keeps the already-working fast-failure case
		// fast. The last upstream takes the whole remainder rather than its
		// geometric share — the alternative leaves budget unspent on a query
		// that is about to fail anyway.
		remaining := time.Until(overallDeadline)
		slice := remaining / 2
		if i == len(live)-1 {
			slice = remaining
		}
		if slice < forwardMinAttempt {
			// Not attempted. Deliberately not a failure: recording it would
			// mark a healthy upstream unreachable because an earlier one was
			// slow, which is exactly the DEGRADED-on-healthy-infrastructure
			// half of #470.
			//
			// Decided BEFORE the outbound hooks and before attempts++, because
			// neither is true of an upstream that is never dialled: the hook
			// contract is "called before the IMR sends a query" and its error
			// return skips a server, so firing it here would show an observer
			// — and let it veto — a query that does not happen; and the
			// SERVFAIL below distinguishes starved from attempts precisely so
			// an operator can tell "tried and failed" from "never got a turn".
			starved++
			lastErr = fmt.Errorf("upstream %s not attempted: %v left, below the %v an attempt needs",
				up.Label, remaining.Round(time.Millisecond), forwardMinAttempt)
			lgDns.Debug("forwardQuery: upstream starved", "qname", qname, "upstream", up.Label,
				"remaining", remaining, "floor", forwardMinAttempt)
			continue
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
			// Not recordFailure -- the attempt was cut short, and one of those
			// says nothing. A RUN of them says the upstream never answers, and
			// this is where that run is counted.
			if up.recordSliceTimeout(start) {
				lgImr.Warn("forward upstream unreachable", "zone", fz.Zone, "upstream", up.Label,
					"reason", "no answer within its slice of the query budget",
					"times", forwardSliceTimeoutsBeforeFailing)
				imr.updateForwardUpstreamError()
			}
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
			rrset, rcode, cctx, xport, err, done := imr.handleAnswer(ctx, qname, qtype, r, force, up.Transport, privacy)
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
	fz.noteAllUpstreamsFailed(qname, qtype, len(live), attempts, lastErr)
	// starved is reported separately from attempts because the two call for
	// different action: attempts that failed say something about the
	// upstreams, whereas starved ones say the budget was too small to try
	// them -- usually because an earlier upstream is blackholing.
	starvedNote := ""
	if starved > 0 {
		starvedNote = fmt.Sprintf(", starved=%d", starved)
	}
	// Under strict privacy the only upstreams tried were the encrypted ones,
	// so exhausting them IS the privacy failure: a cleartext upstream might
	// have answered, and the client forbade asking. Wrapping the sentinel is
	// what lets ImrResponder attach the EDE, and it mirrors what the iterative
	// path does when its encrypted tuples run out.
	if privacy == edns0.PrivacyStrict {
		return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
			fmt.Errorf("%w: forward zone %s had no usable response for '%s %s' from any of its encrypted upstreams (attempts=%d%s, last error: %v)",
				ErrPrivacyUnavailable, fz.Zone, qname, dns.TypeToString[qtype], attempts, starvedNote, lastErr)
	}
	return nil, dns.RcodeServerFailure, cache.ContextFailure, core.TransportDo53,
		fmt.Errorf("forward zone %s: no usable response for '%s %s' from any of its %d usable upstreams (attempts=%d%s, last error: %v)",
			fz.Zone, qname, dns.TypeToString[qtype], len(live), attempts, starvedNote, lastErr)
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
		// liveUpstreams, not fz.Upstreams: a quarantined upstream is not
		// dialled, so it is not unreachable — and one carried across a reload
		// that quarantined it could still hold a stale failing flag, which
		// would otherwise report the same upstream under both errors.
		for _, up := range fz.liveUpstreams() {
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

// updateForwardQuarantineError recomputes the two Config-category aggregates
// from the live table: zones that are not serving, and upstreams whose zones
// still serve without them. Unlike updateForwardUpstreamError this is not
// driven by traffic — quarantine changes only when the table is swapped — so
// it is called once per publish, from InitImrEngine and ReloadZones.
func (imr *Imr) updateForwardQuarantineError() {
	if imr.errorRegistry == nil {
		return
	}
	imr.fwdErrMu.Lock()
	defer imr.fwdErrMu.Unlock()
	var zones, ups []string
	for _, fz := range imr.ForwardZones() {
		if q, why := fz.quarantineState(); q {
			zones = append(zones, fmt.Sprintf("%s (%s)", fz.Zone, why))
			continue
		}
		// Only for a zone that is still serving: on a quarantined zone the
		// per-upstream detail is already in the zone's own reason, and
		// reporting it twice reads as two separate faults.
		for _, up := range fz.Upstreams {
			if q, why := up.quarantineState(); q {
				ups = append(ups, fmt.Sprintf("%s (zone %s: %s)", up.Label, fz.Zone, why))
			}
		}
	}
	if len(zones) == 0 {
		imr.errorRegistry.ClearImrForwardZoneError()
	} else {
		imr.errorRegistry.SetImrForwardZoneError(fmt.Sprintf(
			"%d forward zone(s) quarantined, names under them SERVFAIL: %s",
			len(zones), strings.Join(zones, "; ")))
	}
	if len(ups) == 0 {
		imr.errorRegistry.ClearImrForwardUpstreamConfigError()
	} else {
		imr.errorRegistry.SetImrForwardUpstreamConfigError(fmt.Sprintf(
			"%d forward upstream(s) quarantined, their zones serve with reduced redundancy: %s",
			len(ups), strings.Join(ups, "; ")))
	}
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
		// Quarantined upstreams are not probed: the probe exists to report
		// whether an upstream we intend to USE is answering, and we do not
		// intend to use these.
		for _, up := range fz.liveUpstreams() {
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
