/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const (
	defaultQminMaxIterations = 10
	defaultQminOneLabel      = 4
)

// validateQminTuning rejects a minimisation plan that cannot spread the
// hidden labels over the rounds that are left. Called after the defaults
// are filled in, so a nil pointer is a bug in that filling.
func validateQminTuning(t *ImrTuningConf) error {
	if t == nil || t.QminMaxIterations == nil || t.QminOneLabel == nil {
		return fmt.Errorf("imrengine.tuning.qmin-max-iterations: not set")
	}
	if *t.QminMaxIterations < 1 {
		return fmt.Errorf("imrengine.tuning.qmin-max-iterations: %d is below 1", *t.QminMaxIterations)
	}
	if *t.QminOneLabel < 0 || *t.QminOneLabel >= *t.QminMaxIterations {
		return fmt.Errorf("imrengine.tuning.qmin-one-label: %d must be at least 0 and less than qmin-max-iterations (%d)",
			*t.QminOneLabel, *t.QminMaxIterations)
	}
	return nil
}

// referralAdopt receives the zone and servers a referral cached, instead of
// the referral being followed under the name that was sent.
type referralAdopt struct {
	zone    string
	servers map[string]*cache.AuthServer
}

type probeKind int

const (
	probeNone probeKind = iota
	probeStepped
	probeReferred
	probeChased
	probeFailed
)

type probeResult struct {
	kind      probeKind
	zone      string
	servers   map[string]*cache.AuthServer
	rrset     *core.RRset
	rcode     int
	cacheCtx  cache.CacheContext
	transport core.Transport
	err       error
}

// qminCounters is one client request's minimisation state. rounds counts
// the probes one walk (one name and type) has sent. probes counts every
// probe under the request, and caps them at three times the per-walk maximum.
type qminCounters struct {
	mu     sync.Mutex
	rounds map[string]int
	probes int
	max    int
	one    int
}

type qminCtxKey struct{}

func (imr *Imr) qminOn() bool {
	return imr != nil && imr.Options != nil && imr.Options[ImrOptQnameMinimisation] == "true"
}

func (imr *Imr) qminLimits() (maxIter, oneLabel int) {
	maxIter, oneLabel = defaultQminMaxIterations, defaultQminOneLabel
	if imr != nil && imr.Tuning.QminMaxIterations != nil && *imr.Tuning.QminMaxIterations >= 1 {
		maxIter = *imr.Tuning.QminMaxIterations
	}
	if imr != nil && imr.Tuning.QminOneLabel != nil && *imr.Tuning.QminOneLabel >= 0 {
		oneLabel = *imr.Tuning.QminOneLabel
	}
	return maxIter, oneLabel
}

func (imr *Imr) withQmin(ctx context.Context) context.Context {
	if ctx.Value(qminCtxKey{}) != nil {
		return ctx
	}
	maxIter, oneLabel := imr.qminLimits()
	return context.WithValue(ctx, qminCtxKey{}, &qminCounters{
		rounds: map[string]int{},
		max:    maxIter,
		one:    oneLabel,
	})
}

func qminState(ctx context.Context) *qminCounters {
	st, _ := ctx.Value(qminCtxKey{}).(*qminCounters)
	return st
}

func qminWalkKey(qname string, qtype uint16) string {
	return core.CanonicalizeName(qname) + " " + dns.TypeToString[qtype]
}

func (st *qminCounters) used(key string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.rounds[key]
}

func (st *qminCounters) sent(key string) {
	st.mu.Lock()
	st.rounds[key]++
	st.probes++
	st.mu.Unlock()
}

func (st *qminCounters) atRequestCap() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.probes >= 3*st.max
}

// qminParent is the parent zone of name. The root is its own parent.
func qminParent(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// qminTarget is the name minimisation walks toward: the question name, or
// the parent of it when the question is a DS.
func qminTarget(qname string, qtype uint16) string {
	qname = dns.Fqdn(qname)
	if qtype == dns.TypeDS {
		return qminParent(qname)
	}
	return qname
}

// qminHidden is the labels of target below ancestor, left to right.
func qminHidden(ancestor, target string) []string {
	a := dns.SplitDomainName(ancestor)
	t := dns.SplitDomainName(target)
	if len(t) < len(a) {
		return nil
	}
	return t[:len(t)-len(a)]
}

// qminGroups splits hidden labels into logical labels, closest to the
// ancestor first. A consecutive run of labels that start with "_" is one.
func qminGroups(hidden []string) [][]string {
	var groups [][]string
	for i := len(hidden) - 1; i >= 0; {
		if strings.HasPrefix(hidden[i], "_") {
			end := i
			for i >= 0 && strings.HasPrefix(hidden[i], "_") {
				i--
			}
			groups = append(groups, append([]string(nil), hidden[i+1:end+1]...))
			continue
		}
		groups = append(groups, []string{hidden[i]})
		i--
	}
	return groups
}

// qminStep is how many logical labels the next round adds. The first
// oneLabel rounds add one. After that each round adds the labels still
// hidden divided by the rounds left, at least one. 0 means the walk is
// out of rounds.
func qminStep(hiddenLogical, used, maxIter, oneLabel int) int {
	if hiddenLogical <= 0 || used >= maxIter || maxIter < 1 {
		return 0
	}
	n := 1
	if used >= oneLabel {
		left := maxIter - used
		n = hiddenLogical / left
		if n < 1 {
			n = 1
		}
	}
	if n > hiddenLogical {
		n = hiddenLogical
	}
	return n
}

// qminTake is the name formed by adding n logical labels of target below
// ancestor, and how many were added.
func qminTake(ancestor, target string, n int) (string, int) {
	ancestor, target = dns.Fqdn(ancestor), dns.Fqdn(target)
	groups := qminGroups(qminHidden(ancestor, target))
	if n > len(groups) {
		n = len(groups)
	}
	if n <= 0 {
		return ancestor, 0
	}
	count := 0
	for i := 0; i < n; i++ {
		count += len(groups[i])
	}
	hidden := qminHidden(ancestor, target)
	labels := append(append([]string{}, hidden[len(hidden)-count:]...), dns.SplitDomainName(ancestor)...)
	if len(labels) == 0 {
		return ".", n
	}
	return dns.Fqdn(strings.Join(labels, ".")), n
}

// qminBatches is the label-plan for hidden logical labels. Tests use it.
func qminBatches(hidden, maxIter, oneLabel int) []int {
	var out []int
	used := 0
	for hidden > 0 {
		n := qminStep(hidden, used, maxIter, oneLabel)
		if n == 0 {
			break
		}
		out = append(out, n)
		hidden -= n
		used++
	}
	return out
}

// qminCacheHit is RFC 9156 step 5: a cached answer, NODATA or NXDOMAIN for
// the probe name and type A, or a CNAME the name owns. A referral, glue or
// hint does not count. force re-queries. Strict privacy skips a cleartext hit.
func (imr *Imr) qminCacheHit(name string, privacy edns0.PrivacyLevel, force bool) bool {
	if force {
		return false
	}
	if crr := imr.Cache.Get(name, dns.TypeA); crr != nil {
		switch crr.Context {
		case cache.ContextAnswer, cache.ContextNoErrNoAns, cache.ContextNXDOMAIN:
			if privacy == edns0.PrivacyStrict && !core.IsEncryptedTransport(crr.Transport) {
				return false
			}
			return true
		}
	}
	_, _, ok := imr.cachedLink(name, privacy)
	return ok
}

func (imr *Imr) askOriginal(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, serversZone string, force bool, visitedZones map[string]bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	return imr.askServers(ctx, qname, qtype, serverMap, serversZone, privacy, true,
		func(server *cache.AuthServer, addr, nsname string, wire core.Transport, r *dns.Msg) serverReply {
			return imr.dispatchClientQuery(ctx, qname, qtype, force, visitedZones, serversZone, privacy, server, addr, nsname, wire, r)
		})
}

// resolveMinimised sends the client's question, probing with type A until
// the servers being asked are known to hold the name. With the option off
// it sends the question as it was asked.
func (imr *Imr) resolveMinimised(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, serversZone string, force bool, visitedZones map[string]bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	if !imr.qminOn() {
		return imr.askOriginal(ctx, qname, qtype, serverMap, serversZone, force, visitedZones, privacy)
	}
	ctx = imr.withQmin(ctx)
	target := qminTarget(qname, qtype)
	zone := dns.Fqdn(serversZone)
	// No zone for these servers, or the servers are not at the target or
	// above it (a child's servers handed over for a DS): send the question.
	if serversZone == "" || !dns.IsSubDomain(zone, target) {
		return imr.askOriginal(ctx, qname, qtype, serverMap, serversZone, force, visitedZones, privacy)
	}
	st := qminState(ctx)
	key := qminWalkKey(qname, qtype)
	known := zone
	servers := serverMap
	for !core.EqualNames(known, target) {
		if st.used(key) >= st.max || st.atRequestCap() {
			break
		}
		hidden := len(qminGroups(qminHidden(known, target)))
		n := qminStep(hidden, st.used(key), st.max, st.one)
		if n == 0 {
			break
		}
		child, _ := qminTake(known, target, n)
		// The probe of the original name as A is the client's query.
		if qtype == dns.TypeA && core.EqualNames(child, qname) {
			break
		}
		if imr.qminCacheHit(child, privacy, force) {
			known = child
			continue
		}
		step := imr.sendProbe(ctx, qname, qtype, child, servers, zone, force, visitedZones, privacy)
		switch step.kind {
		case probeChased:
			return step.rrset, step.rcode, step.cacheCtx, step.transport, step.err
		case probeReferred:
			if step.zone == "" || len(step.servers) == 0 || !referralLeavesZone(step.zone, zone) {
				return imr.finishMinimised(ctx, qname, qtype, servers, zone, force, visitedZones, privacy)
			}
			zone = dns.Fqdn(step.zone)
			known = zone
			servers = step.servers
		case probeStepped:
			known = child
		default:
			return imr.finishMinimised(ctx, qname, qtype, servers, zone, force, visitedZones, privacy)
		}
	}
	return imr.finishMinimised(ctx, qname, qtype, servers, zone, force, visitedZones, privacy)
}

// finishMinimised sends the original question. A CNAME cached at the
// original name, by a probe, is chased: the cache short-circuit that would
// have done it ran before any probe.
func (imr *Imr) finishMinimised(ctx context.Context, qname string, qtype uint16, serverMap map[string]*cache.AuthServer, serversZone string, force bool, visitedZones map[string]bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error) {
	if !force && followsCNAME(ctx, qtype) {
		if _, target, ok := imr.cachedLink(qname, privacy); ok {
			return imr.chaseCNAME(ctx, qname, target, qtype, force, privacy)
		}
	}
	return imr.askOriginal(ctx, qname, qtype, serverMap, serversZone, force, visitedZones, privacy)
}

func (imr *Imr) sendProbe(ctx context.Context, qname string, qtype uint16, child string, serverMap map[string]*cache.AuthServer, serversZone string, force bool, visitedZones map[string]bool, privacy edns0.PrivacyLevel) probeResult {
	st := qminState(ctx)
	st.sent(qminWalkKey(qname, qtype))
	var step probeResult
	_, _, _, _, err := imr.askServers(ctx, child, dns.TypeA, serverMap, serversZone, privacy, false,
		func(server *cache.AuthServer, addr, nsname string, wire core.Transport, r *dns.Msg) serverReply {
			return imr.dispatchProbe(ctx, qname, qtype, child, force, visitedZones, serversZone, privacy, server, addr, nsname, wire, r, &step)
		})
	if step.kind == probeNone {
		step.kind = probeFailed
		step.err = err
	}
	return step
}

// dispatchProbe caches a probe response under the name that was sent and
// says how the walk continues. The response is not the client's answer,
// except a DNAME, which is chased from the original name.
func (imr *Imr) dispatchProbe(ctx context.Context, qname string, qtype uint16, child string, force bool, visitedZones map[string]bool, serversZone string, privacy edns0.PrivacyLevel, server *cache.AuthServer, addr, nsname string, wire core.Transport, r *dns.Msg, step *probeResult) serverReply {
	if dname := dnameAbove(r, child); dname != nil && len(dname.RRs) > 0 {
		d := dname.RRs[0].(*dns.DNAME)
		cn := &dns.CNAME{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: d.Hdr.Ttl},
			Target: synthesizeFromDNAME(qname, dname.Name, d.Target)}
		rrset, rcode, cctx, tr, err, done := imr.answerViaCNAME(ctx, qname, qtype, r, cn, force, wire, privacy)
		if !done {
			return replyNext()
		}
		step.kind = probeChased
		step.rrset, step.rcode, step.cacheCtx, step.transport, step.err = rrset, rcode, cctx, tr, err
		return replyDone(rrset, rcode, cctx, tr, err)
	}
	if cn := cnameAt(r, child); cn != nil {
		if _, err := imr.cacheCNAMELink(ctx, child, r, cn, wire); err != nil {
			return replyNext()
		}
		step.kind = probeStepped
		return replyDone(nil, dns.RcodeSuccess, cache.ContextAnswer, wire, nil)
	}
	if len(r.Answer) != 0 {
		imr.parseTransportForServerFromAdditional(ctx, server, r)
		_, _, _, _, err, done := imr.handleAnswer(ctx, child, dns.TypeA, r, force, wire, privacy)
		if err != nil || !done {
			if nsRRs, zonename, _ := extractReferral(r, child, dns.TypeA); len(nsRRs.RRs) > 0 && referralLeavesZone(zonename, serversZone) {
				return imr.adoptReferral(ctx, qname, r, force, visitedZones, serversZone, wire, privacy, step)
			}
			return replyNext()
		}
		step.kind = probeStepped
		return replyDone(nil, dns.RcodeSuccess, cache.ContextAnswer, wire, nil)
	}
	switch classifyResponse(child, dns.TypeA, r) {
	case responseKindNegativeNoData, responseKindNegativeNXDOMAIN:
		if _, _, handled := imr.handleNegative(child, dns.TypeA, r, wire, serversZone); !handled {
			return replyNext()
		}
		step.kind = probeStepped
		return replyDone(nil, r.MsgHdr.Rcode, cache.ContextNoErrNoAns, wire, nil)
	case responseKindReferral:
		if _, refZone, _ := extractReferral(r, child, dns.TypeA); !referralLeavesZone(refZone, serversZone) {
			return replyNext()
		}
		return imr.adoptReferral(ctx, qname, r, force, visitedZones, serversZone, wire, privacy, step)
	default:
		return replyNext()
	}
}

func (imr *Imr) adoptReferral(ctx context.Context, qname string, r *dns.Msg, force bool, visitedZones map[string]bool, serversZone string, wire core.Transport, privacy edns0.PrivacyLevel, step *probeResult) serverReply {
	var adopt referralAdopt
	_, _, _, _, err := imr.handleReferral(ctx, qname, dns.TypeA, r, force, visitedZones, serversZone, wire, privacy, &adopt)
	if err != nil || adopt.zone == "" || len(adopt.servers) == 0 || !referralLeavesZone(adopt.zone, serversZone) {
		return replyNext()
	}
	step.kind = probeReferred
	step.zone = adopt.zone
	step.servers = adopt.servers
	return replyDone(nil, dns.RcodeSuccess, cache.ContextReferral, wire, nil)
}
