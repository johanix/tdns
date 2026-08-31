/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The listeners.imr-debug-address window (#446): a loopback-only Do53
 * listener straight into an EMBEDDED resolver (tdns-auth, tdns-agent),
 * whose imr is otherwise internal by design. `dog @<addr> name type +norec`
 * peeks at the cache without a single outbound query; `ANY +norec`
 * enumerates every cached RRset at an owner; RD=1 drives the internal
 * resolver by hand. Debug-listener-only behaviors — the service listeners
 * keep RFC 8482 minimal-ANY and fall through to REFUSED on indirect cache
 * entries, exactly as before.
 */
package tdns

import (
	"context"
	"fmt"
	"net"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// validateImrDebugAddress enforces the design's hard rule: the debug window
// must be loopback (127/8 or ::1). Anything else is an open resolver hiding
// inside an auth server, and the config refuses to load. Shared by the
// daemon loader and ValidateConfig, so `config check` rejects identically.
func validateImrDebugAddress(addr string) error {
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listeners.imr-debug-address %q is not addr:port: %v", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("listeners.imr-debug-address %q: %q is not an IP address", addr, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("listeners.imr-debug-address %q must be loopback (127/8 or ::1): a non-loopback debug window is an open resolver", addr)
	}
	return nil
}

// startImrDebugListener binds the debug window (UDP+TCP) with the debug
// handler. Loopback-ness was enforced at config load; this re-checks anyway
// because the cost is one call and the failure mode is an open resolver.
func (imr *Imr) startImrDebugListener(ctx context.Context, addr string, conf *Config) {
	if err := validateImrDebugAddress(addr); err != nil {
		lgImr.Error("refusing to start the imr debug listener", "err", err)
		return
	}
	handler := imr.createImrDebugHandler(ctx, conf)
	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler)
	for _, netproto := range []string{"udp", "tcp"} {
		server := &dns.Server{Addr: addr, Net: netproto, Handler: mux}
		go func(s *dns.Server, netproto string) {
			lgImr.Info("imr debug listener serving", "addr", addr, "net", netproto)
			if err := s.ListenAndServe(); err != nil {
				lgImr.Error("imr debug listener failed", "addr", addr, "net", netproto, "err", err)
			}
		}(server, netproto)
		go func(s *dns.Server) {
			<-ctx.Done()
			_ = s.Shutdown()
		}(server)
	}
}

// createImrDebugHandler wraps the normal IMR handler with the two
// debug-only behaviors: ANY+norec enumerates the owner's cached RRsets, and
// a +norec query for a specific type serves the cache entry WHATEVER its
// context (the normal responder deliberately refuses indirect
// Referral/Glue/Hint entries) — with the entry's metadata (context,
// validation state, remaining lifetime) as a TXT record in Additional, and
// TTLs adjusted to remaining lifetime. Cache misses and RD=1 queries fall
// through to the normal handler.
func (imr *Imr) createImrDebugHandler(ctx context.Context, conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
	normal := imr.createImrHandler(ctx, conf)
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 || r.RecursionDesired {
			normal(w, r)
			return
		}
		q := r.Question[0]
		qname := core.CanonicalizeName(dns.Fqdn(q.Name))
		if q.Qtype == dns.TypeANY {
			imr.serveDebugANY(w, r, qname)
			return
		}
		if imr.serveDebugCachePeek(w, r, qname, q.Qtype) {
			return
		}
		normal(w, r) // cache miss: the normal REFUSED + explanatory TXT
	}
}

// debugMetaTXT renders one cache entry's metadata as a TXT for Additional.
func debugMetaTXT(owner string, cr *cache.CachedRRset) dns.RR {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0},
		Txt: []string{fmt.Sprintf("type=%s context=%s state=%s expires-in=%s",
			dns.TypeToString[cr.RRtype],
			cache.CacheContextToString[cr.Context],
			cache.ValidationStateToString[cr.State],
			time.Until(cr.Expiration).Truncate(time.Second))},
	}
}

// ttlAdjusted copies rrs with TTLs set to the entry's remaining lifetime —
// half the point of a cache peek. Expired-but-not-yet-reaped entries show 0.
func ttlAdjusted(rrs []dns.RR, expiration time.Time) []dns.RR {
	remaining := time.Until(expiration)
	if remaining < 0 {
		remaining = 0
	}
	ttl := uint32(remaining.Seconds())
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		cp := dns.Copy(rr)
		cp.Header().Ttl = ttl
		out = append(out, cp)
	}
	return out
}

// appendDebugEntry adds one cache entry's RRs, RRSIGs and metadata TXT to m.
func appendDebugEntry(m *dns.Msg, cr *cache.CachedRRset) {
	if cr.RRset != nil {
		m.Answer = append(m.Answer, ttlAdjusted(cr.RRset.RRs, cr.Expiration)...)
		m.Answer = append(m.Answer, ttlAdjusted(cr.RRset.RRSIGs, cr.Expiration)...)
	}
	for _, negSet := range cr.NegAuthority {
		m.Ns = append(m.Ns, ttlAdjusted(negSet.RRs, cr.Expiration)...)
		m.Ns = append(m.Ns, ttlAdjusted(negSet.RRSIGs, cr.Expiration)...)
	}
	m.Extra = append(m.Extra, debugMetaTXT(cr.Name, cr))
}

// serveDebugANY answers ANY+norec with every cached RRset at the owner.
func (imr *Imr) serveDebugANY(w dns.ResponseWriter, r *dns.Msg, qname string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	found := 0
	for item := range imr.Cache.RRsets.IterBuffered() {
		cr := item.Val
		if !core.EqualNames(cr.Name, qname) {
			continue
		}
		found++
		appendDebugEntry(m, &cr)
	}
	if found == 0 {
		m.SetRcode(r, dns.RcodeRefused)
		m.Ns = append(m.Ns, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
			Txt: []string{"no cached RRsets at this owner"},
		})
	}
	_ = w.WriteMsg(m)
}

// serveDebugCachePeek serves the (qname, qtype) cache entry whatever its
// context. Returns false on a miss, handing the query back to the normal
// handler's REFUSED path.
func (imr *Imr) serveDebugCachePeek(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16) bool {
	cr := imr.Cache.Get(qname, qtype)
	if cr == nil {
		return false
	}
	m := new(dns.Msg)
	m.SetRcode(r, int(cr.Rcode))
	m.RecursionAvailable = true
	m.AuthenticatedData = cr.State == cache.ValidationStateSecure
	appendDebugEntry(m, cr)
	_ = w.WriteMsg(m)
	return true
}
