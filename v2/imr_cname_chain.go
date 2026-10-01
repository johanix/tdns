/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Answers whose query name is a CNAME (#717).
//
// Each link of a chain is an RRset of its own: cached at its owner, with its own
// RRSIGs and its own verdict, like any other answer. A chain is never stored
// whole. It is followed -- through the cache, resolving whatever is missing --
// and its answer is assembled from the links when it is served: every CNAME in
// order, then the data or the denial at the chain's last name, with AD only if
// every part is Secure (RFC 4035 §3.2.3).
//
// The chain used to be cached as one RRset of mixed types, with no name, no
// type, no signatures past the first hop and no verdict. Its middle links were
// dropped, and it never came out Secure.

// followsCNAME reports whether a query for qtype, asked on ctx, follows a
// CNAME at the query name.
//
//   - A CNAME query asks for the CNAME itself.
//   - RRSIG and NSEC are the two types that sit beside a CNAME at its owner
//     (RFC 4035 §2.5).
//   - DS and DNSKEY follow when a DNS client asks (isClientQuery), as any
//     other type does: the answer is the chain, and the DS or DNSKEY at its
//     end (#875). Other validating resolvers answer the same.
//   - The resolver's own DS and DNSKEY questions do not follow
//     (cnameDeniesType). They ask about the name itself: a DS is the parent's
//     data about a delegation at it, a DNSKEY the keys of a zone with its apex
//     there. Following answered them with another name's records (#717).
func followsCNAME(ctx context.Context, qtype uint16) bool {
	switch qtype {
	case dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC:
		return false
	case dns.TypeDS, dns.TypeDNSKEY:
		return isClientQuery(ctx)
	}
	return true
}

// cnameDeniesType reports whether a CNAME at the query name is itself the
// answer to a query for qtype asked on ctx: that the name holds no qtype. So it
// is for the DS and DNSKEY questions the resolver asks for itself. A CNAME
// owner is neither a delegation nor a zone apex (RFC 2181 §10.1), so it holds
// neither a DS nor a DNSKEY.
//
// The answer is read from the link, cached at <name, CNAME> with its verdict
// like any other link (cnameAsNoData). Nothing is stored under <name, DS> or
// <name, DNSKEY>: the responder reads those first, and a client asking the
// same question is answered with the chain.
func cnameDeniesType(ctx context.Context, qtype uint16) bool {
	return (qtype == dns.TypeDS || qtype == dns.TypeDNSKEY) && !isClientQuery(ctx)
}

// cnameValidationKey carries, on the context of a CNAME link's validation, the
// owners of the links being validated (cacheCNAMELink).
//
// Validating an unsigned link at X asks the parent side for the DS at X
// (belowSecureZone), and validating one whose RRSIG names X as its signer asks
// for the DNSKEY at X. Either question is answered with the link itself, which
// would then be validated again, and so on without end (#717). A DS or DNSKEY
// question the resolver asks for itself at a name on this list is answered
// "none there" without asking (IterativeDNSQueryWithLoopDetection): X is a
// CNAME, so it has neither, and the validation going on above decides whether
// the CNAME is authentic.
type cnameValidationKey struct{}

// withCNAMEValidation adds owner to the links being validated on ctx.
func withCNAMEValidation(ctx context.Context, owner string) context.Context {
	owners, _ := ctx.Value(cnameValidationKey{}).([]string)
	return context.WithValue(ctx, cnameValidationKey{}, append(slices.Clone(owners), core.CanonicalizeName(owner)))
}

// validatingCNAME reports whether the link owned by name is being validated on
// ctx.
func validatingCNAME(ctx context.Context, name string) bool {
	if ctx == nil {
		return false
	}
	owners, _ := ctx.Value(cnameValidationKey{}).([]string)
	return slices.Contains(owners, core.CanonicalizeName(name))
}

// cachedLink returns the link qname owns in the cache, and its target: an
// answer holding a CNAME. Under strict privacy a link that arrived in
// cleartext does not count.
func (imr *Imr) cachedLink(qname string, privacy edns0.PrivacyLevel) (*cache.CachedRRset, string, bool) {
	link := imr.Cache.Get(qname, dns.TypeCNAME)
	if link == nil || link.Context != cache.ContextAnswer ||
		(privacy == edns0.PrivacyStrict && !core.IsEncryptedTransport(link.Transport)) {
		return nil, "", false
	}
	target, ok := cnameTarget(link.RRset)
	if !ok {
		return nil, "", false
	}
	return link, target, true
}

// cnameTarget returns the target of the CNAME in rrset, if it holds one.
func cnameTarget(rrset *core.RRset) (string, bool) {
	if rrset == nil {
		return "", false
	}
	for _, rr := range rrset.RRs {
		if c, ok := rr.(*dns.CNAME); ok {
			return c.Target, true
		}
	}
	return "", false
}

// cnameAt returns the CNAME in r's answer section that qname owns, if any.
func cnameAt(r *dns.Msg, qname string) *dns.CNAME {
	for _, rr := range r.Answer {
		if c, ok := rr.(*dns.CNAME); ok && core.EqualNames(c.Hdr.Name, qname) {
			return c
		}
	}
	return nil
}

// sigsFor returns the RRSIGs in rrs that owner holds over covered.
func sigsFor(rrs []dns.RR, owner string, covered uint16) []dns.RR {
	var sigs []dns.RR
	for _, rr := range rrs {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == covered && core.EqualNames(s.Hdr.Name, owner) {
			sigs = append(sigs, rr)
		}
	}
	return sigs
}

// dnameAbove returns the DNAME RRset in r's answer section whose owner is the
// closest proper ancestor of qname, with its RRSIGs; nil if there is none.
func dnameAbove(r *dns.Msg, qname string) *core.RRset {
	owner := ""
	for _, rr := range r.Answer {
		d, ok := rr.(*dns.DNAME)
		if !ok || core.EqualNames(d.Hdr.Name, qname) || !dns.IsSubDomain(d.Hdr.Name, qname) {
			continue
		}
		if owner == "" || dns.CountLabel(d.Hdr.Name) > dns.CountLabel(owner) {
			owner = d.Hdr.Name
		}
	}
	if owner == "" {
		return nil
	}
	rrset := &core.RRset{Name: owner, Class: dns.ClassINET, RRtype: dns.TypeDNAME,
		RRSIGs: sigsFor(r.Answer, owner, dns.TypeDNAME)}
	for _, rr := range r.Answer {
		if d, ok := rr.(*dns.DNAME); ok && core.EqualNames(d.Hdr.Name, owner) {
			rrset.RRs = append(rrset.RRs, rr)
		}
	}
	return rrset
}

// synthesizeFromDNAME returns the target of the CNAME that a DNAME at owner,
// pointing at target, synthesizes for qname (RFC 6672 §2.2): qname's labels
// below owner, followed by target. qname must be strictly below owner.
func synthesizeFromDNAME(qname, owner, target string) string {
	ql := dns.SplitDomainName(qname)
	prefix := strings.Join(ql[:len(ql)-dns.CountLabel(owner)], ".")
	if t := dns.Fqdn(target); t != "." {
		return prefix + "." + t
	}
	return prefix + "."
}

// cacheCNAMELink validates the CNAME that qname owns in r, caches it as an
// RRset of its own with its RRSIGs and its verdict, and returns the target the
// chain goes on to.
//
// A CNAME synthesized from a DNAME is unsigned: the DNAME carries the RRSIG
// (RFC 6672 §5.3.1). So the DNAME is validated and cached instead, and the
// CNAME takes its verdict (SynthesizedFrom). The chain follows the CNAME only
// as the DNAME synthesizes it: a CNAME that says otherwise is replaced by the
// synthesized one (RFC 6672 §3.2).
//
// The link is validated with qname on the context as a link being validated
// (cnameValidationKey): the resolver's own DS or DNSKEY question at qname,
// asked by that validation, is answered without being sent.
func (imr *Imr) cacheCNAMELink(ctx context.Context, qname string, r *dns.Msg, cn *dns.CNAME, transport core.Transport) (string, error) {
	ctx = withCNAMEValidation(ctx, qname)
	now := cache.Now()
	link := &core.RRset{Name: qname, Class: dns.ClassINET, RRtype: dns.TypeCNAME}
	// A link, or the DNAME that synthesized it, synthesized from a wildcard
	// is validated with the proof in the authority section, which is kept.
	authority := authorityRRsets(r.Ns)
	var verdict cache.AnswerVerdict
	var synthesizedFrom string
	if dname := dnameAbove(r, qname); dname != nil {
		d := dname.RRs[0].(*dns.DNAME)
		v, err := imr.Cache.ValidateAnswer(ctx, dname, authority, imr.IterativeDNSQueryFetcher())
		if err != nil {
			return "", fmt.Errorf("DNAME %s: %w", dname.Name, err)
		}
		imr.Cache.Set(dname.Name, dns.TypeDNAME, &cache.CachedRRset{
			Name: dname.Name, RRtype: dns.TypeDNAME, Rcode: uint8(dns.RcodeSuccess), RRset: dname,
			Context: cache.ContextAnswer, State: v.State, EDECode: v.EDECode, EDEText: v.EDEText,
			WildcardProof: v.Proof,
			Expiration:    now.Add(cache.GetMinTTL(dname.RRs)), Transport: transport,
		})
		target := synthesizeFromDNAME(qname, dname.Name, d.Target)
		if !core.EqualNames(cn.Target, target) {
			lgDns.Warn("handleAnswer: the CNAME differs from what its DNAME synthesizes; following the DNAME",
				"qname", qname, "cname", cn.Target, "dname", dname.Name, "synthesized", target)
		}
		link.RRs = []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: d.Hdr.Ttl},
			Target: target,
		}}
		verdict, synthesizedFrom = cache.AnswerVerdict{State: v.State}, dname.Name
	} else {
		link.RRs = []dns.RR{cn}
		link.RRSIGs = sigsFor(r.Answer, qname, dns.TypeCNAME)
		v, err := imr.Cache.ValidateAnswer(ctx, link, authority, imr.IterativeDNSQueryFetcher())
		if err != nil {
			return "", fmt.Errorf("CNAME %s: %w", qname, err)
		}
		verdict = v
	}
	imr.Cache.Set(qname, dns.TypeCNAME, &cache.CachedRRset{
		Name: qname, RRtype: dns.TypeCNAME, Rcode: uint8(dns.RcodeSuccess), RRset: link,
		Context: cache.ContextAnswer, State: verdict.State, EDECode: verdict.EDECode, EDEText: verdict.EDEText,
		WildcardProof: verdict.Proof,
		Expiration:    now.Add(cache.GetMinTTL(link.RRs)), Transport: transport,
		SynthesizedFrom: synthesizedFrom,
	})
	target, _ := cnameTarget(link)
	return target, nil
}

// answerViaCNAME handles an answer in which qname is a CNAME: it caches the
// link and follows the chain (chaseCNAME). It returns what the chain ends in:
// the data at its last name, or no RRset and that name's rcode and context
// for a denial. The responder builds the client's answer from the cached
// links (serveChain); internal callers want the data at the end.
func (imr *Imr) answerViaCNAME(ctx context.Context, qname string, qtype uint16, r *dns.Msg, cn *dns.CNAME, force bool, transport core.Transport, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error, bool) {
	target, err := imr.cacheCNAMELink(ctx, qname, r, cn, transport)
	if err != nil {
		lgDns.Error("handleAnswer: failed to validate a CNAME link", "qname", qname, "err", err)
		return nil, r.MsgHdr.Rcode, cache.ContextFailure, transport, err, false
	}
	final, rcode, context, chaseTransport, err := imr.chaseCNAME(ctx, qname, target, qtype, force, privacy)
	if err != nil {
		return nil, rcode, context, transport, err, true
	}
	// Downgrade to unencrypted if any hop was unencrypted.
	if !core.IsEncryptedTransport(transport) {
		chaseTransport = core.TransportDo53
	}
	return final, rcode, context, chaseTransport, nil, true
}

// cnameAsNoData answers the resolver's own DS or DNSKEY question at qname when
// qname is a CNAME (cnameDeniesType): the link is validated and cached as any
// link is (cacheCNAMELink), and the answer is that qname holds no qtype. The
// rcode is NOERROR whatever r's is: r's rcode belongs to the chain's last name
// (RFC 6604), and qname exists.
//
// The walk stops here, on the first server that answered. It used to find no
// qtype in the answer, try every other server, and fail; and as nothing was
// cached, the next question did the same (#875). The next question is now
// answered from the link (IterativeDNSQueryWithLoopDetection).
func (imr *Imr) cnameAsNoData(ctx context.Context, qname string, qtype uint16, r *dns.Msg, cn *dns.CNAME, transport core.Transport) (*core.RRset, int, cache.CacheContext, core.Transport, error, bool) {
	if _, err := imr.cacheCNAMELink(ctx, qname, r, cn, transport); err != nil {
		lgDns.Error("handleAnswer: failed to validate a CNAME link", "qname", qname, "err", err)
		return nil, r.MsgHdr.Rcode, cache.ContextFailure, transport, err, false
	}
	lgDns.Debug("handleAnswer: the name is a CNAME, which holds no "+dns.TypeToString[qtype], "qname", qname)
	return nil, dns.RcodeSuccess, cache.ContextNoErrNoAns, transport, nil, true
}

// chainOutcome is what serveChain did.
type chainOutcome int

const (
	chainAbsent     chainOutcome = iota // qname holds no CNAME; nothing written
	chainIncomplete                     // qname is a CNAME, part of the chain is missing; nothing written
	chainServed                         // a response has been written
)

// chainFreshGraceDefault is the grace freshChainGrace gives when the IMR has
// no query budget configured: the query-budget default.
const chainFreshGraceDefault = 8 * time.Second

// freshChainGrace is how long past its expiry an entry still counts when
// answering the query that has just resolved it: one query budget. An entry
// that expired longer ago than that was not valid at any moment of this
// query. A record with TTL 0 is stored already expired, and is still the
// answer to the query that fetched it.
func (imr *Imr) freshChainGrace() time.Duration {
	if b := imr.Tuning.QueryBudget; b > 0 {
		return b
	}
	return chainFreshGraceDefault
}

// chainEntry reads <name, t> for a chain. grace 0 reads the cache as it
// stands (Get): an expired entry is missing. A grace above 0 is for the query
// that has just resolved the chain: an entry that expired less than grace ago
// still counts (freshChainGrace). Under strict privacy an entry that arrived
// in cleartext counts as missing.
func (imr *Imr) chainEntry(name string, t uint16, privacy edns0.PrivacyLevel, grace time.Duration) *cache.CachedRRset {
	var e *cache.CachedRRset
	if grace <= 0 {
		e = imr.Cache.Get(name, t)
	} else if e = imr.Cache.Peek(name, t); e != nil && e.Expiration.Before(cache.Now().Add(-grace)) {
		e = nil
	}
	if e == nil || (privacy == edns0.PrivacyStrict && !core.IsEncryptedTransport(e.Transport)) {
		return nil
	}
	return e
}

// chainAt assembles from the cache the chain that starts at qname: its links
// in order, and the entry for <last name, qtype>, holding data or a denial.
// Entries are read with chainEntry and grace. started reports that qname holds
// a CNAME; final is nil when some part of the chain is missing. err reports a
// loop, or a chain longer than maxCNAMEChain.
func (imr *Imr) chainAt(qname string, qtype uint16, privacy edns0.PrivacyLevel, grace time.Duration) (links []*cache.CachedRRset, final *cache.CachedRRset, started bool, err error) {
	name := qname
	seen := map[string]bool{core.CanonicalizeName(qname): true}
	for {
		if len(links) > 0 {
			if e := imr.chainEntry(name, qtype, privacy, grace); e != nil {
				switch {
				case e.Context == cache.ContextAnswer && e.RRset != nil && e.RRset.RRtype == qtype && len(e.RRset.RRs) > 0:
					return links, e, true, nil
				case e.Context == cache.ContextNXDOMAIN || e.Context == cache.ContextNoErrNoAns:
					return links, e, true, nil
				}
			}
		}
		link := imr.chainEntry(name, dns.TypeCNAME, privacy, grace)
		target, isCNAME := "", false
		if link != nil && link.Context == cache.ContextAnswer {
			target, isCNAME = cnameTarget(link.RRset)
		}
		if !isCNAME {
			return nil, nil, len(links) > 0, nil
		}
		if link.SynthesizedFrom != "" && imr.chainEntry(link.SynthesizedFrom, dns.TypeDNAME, privacy, grace) == nil {
			return nil, nil, true, nil
		}
		if len(links) == maxCNAMEChain {
			return nil, nil, true, fmt.Errorf("CNAME chain from %s is longer than %d", qname, maxCNAMEChain)
		}
		links = append(links, link)
		t := core.CanonicalizeName(target)
		if seen[t] {
			return nil, nil, true, fmt.Errorf("CNAME loop: %s leads back to %s", name, target)
		}
		seen[t] = true
		name = target
	}
}

// serveChain answers r for <qname, qtype> when qname is a CNAME, from the
// chain in the cache (chainAt, with grace as there). It writes nothing when
// qname holds no CNAME (chainAbsent) or part of the chain is missing
// (chainIncomplete).
//
// Each part is judged by the rule for a single answer:
//   - a positive part (a link, or the data at the end) by dispositionFor, with
//     a verdict that says "could not tell yet" asked again, as
//     serveCachedPositive does;
//   - a synthesized CNAME by the verdict of its DNAME, which is served ahead of
//     it;
//   - a denial at the end by denialServfail, validated again when it is held
//     Indeterminate (revalidateDenial), and served with serveNegativeResponse.
//
// Any part that fails fails the answer, with that part's EDE. AD is set only
// when every part is Secure. The rcode is that of the chain's last name (RFC
// 6604).
func (imr *Imr) serveChain(ctx context.Context, w dns.ResponseWriter, r, m *dns.Msg, qname string, qtype uint16, msgoptions *edns0.MsgOptions, status edns0.PrivacyStatus, grace time.Duration) chainOutcome {
	links, final, started, err := imr.chainAt(qname, qtype, msgoptions.Privacy, grace)
	if err != nil {
		lgImr.Info("ImrResponder: refusing a CNAME chain", "qname", qname, "qtype", dns.TypeToString[qtype], "err", err)
		m.Answer, m.Ns = nil, nil
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return chainServed
	}
	if !started {
		return chainAbsent
	}
	if final == nil {
		return chainIncomplete
	}

	secure := true
	// The parts whose proofs, for answers synthesized from a wildcard, go in
	// the authority section; and an EDE that goes out beside the answer
	// (edeBeside), from any part.
	var proven []*cache.CachedRRset
	var beside struct {
		state cache.ValidationState
		code  uint16
		text  string
	}
	// judge applies the positive-answer rule to one part. False means the
	// part fails the answer, which has been written as a SERVFAIL.
	judge := func(e *cache.CachedRRset) bool {
		state, edeCode, edeText := e.State, e.EDECode, e.EDEText
		signed := e.RRset != nil && len(e.RRset.RRSIGs) > 0
		if !verdictReusable(state) && signed && !msgoptions.CD {
			// With the proof kept for a part synthesized from a wildcard.
			if v, err := imr.Cache.ValidateAnswer(ctx, e.RRset, e.WildcardProof, imr.IterativeDNSQueryFetcher()); err == nil {
				state, edeCode, edeText = v.State, v.EDECode, v.EDEText
			}
		}
		disp, ede := imr.dispositionFor(state, edeCode, signed, msgoptions)
		switch disp {
		case answerServfail:
			lgImr.Debug("ImrResponder: returning SERVFAIL for a CNAME chain with a part that did not validate",
				"qname", qname, "qtype", dns.TypeToString[qtype], "part", e.Name, "type", dns.TypeToString[e.RRtype],
				"state", cache.ValidationStateToString[state], "edeCode", ede)
			m.Answer, m.Ns = nil, nil
			m.SetRcode(r, dns.RcodeServerFailure)
			if r.IsEdns0() != nil {
				if edeCode != 0 && edeText != "" {
					edns0.AttachEDEToResponseWithText(m, edeCode, edeText, msgoptions.DO)
				} else {
					edns0.AttachEDEToResponse(m, ede)
				}
			}
			w.WriteMsg(m)
			return false
		case answerServe:
			secure = false
		}
		proven = append(proven, e)
		if edeBeside(state, edeCode) {
			beside.state, beside.code, beside.text = state, edeCode, edeText
		}
		return true
	}

	now := cache.Now()
	var answer []dns.RR
	lastName := qname
	for _, link := range links {
		verdict := link
		if link.SynthesizedFrom != "" {
			dname := imr.chainEntry(link.SynthesizedFrom, dns.TypeDNAME, msgoptions.Privacy, grace)
			if dname == nil {
				return chainIncomplete // gone since chainAt looked
			}
			verdict = dname
			answer = append(answer, dname.ServeAnswer(now, msgoptions.DO)...)
		}
		if !judge(verdict) {
			return chainServed
		}
		answer = append(answer, link.ServeAnswer(now, msgoptions.DO)...)
		lastName, _ = cnameTarget(link.RRset)
	}

	switch final.Context {
	case cache.ContextNXDOMAIN, cache.ContextNoErrNoAns:
		final = imr.revalidateDenial(ctx, final, msgoptions)
		if servfail, ede := imr.denialServfail(final, msgoptions); servfail {
			writeDenialServfail(w, r, m, ede)
			return chainServed
		}
		rcode := dns.RcodeSuccess
		if final.Context == cache.ContextNXDOMAIN {
			rcode = negativeRcode(final, msgoptions)
		}
		m.SetRcode(r, rcode)
		m.Answer = answer
		imr.serveNegativeResponse(ctx, lastName, qtype, msgoptions, m, r, final)
		m.AuthenticatedData = m.AuthenticatedData && secure && adWanted(r, msgoptions)
	default:
		if !judge(final) {
			return chainServed
		}
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = append(answer, final.ServeAnswer(now, msgoptions.DO)...)
		m.AuthenticatedData = secure && adWanted(r, msgoptions)
	}
	// Each part's proof once, after the denial's own records when the chain
	// ends in one.
	for _, e := range proven {
		appendWildcardProof(m, e, msgoptions)
	}
	attachAnswerEDE(m, r, beside.state, beside.code, beside.text, msgoptions)
	setPrivacyStatus(m, msgoptions, status)
	w.WriteMsg(m)
	return chainServed
}
