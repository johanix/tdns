/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
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

// followsCNAME reports whether a query for qtype follows a CNAME at the query
// name.
//
//   - A CNAME query asks for the CNAME itself.
//   - RRSIG and NSEC are the two types that sit beside a CNAME at its owner
//     (RFC 4035 §2.5).
//   - DS and DNSKEY are the validator's own questions, and a CNAME answers
//     neither. A DS is the parent's data about a delegation, which a CNAME
//     owner cannot be; a DNSKEY sits at a zone apex, which cannot be a CNAME
//     (RFC 2181 §10.1). Following one answered the question with another
//     name's records. It also recursed without end: validating an unsigned
//     link asks for the link owner's DS, and the answer to that was the link
//     again.
func followsCNAME(qtype uint16) bool {
	switch qtype {
	case dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDS, dns.TypeDNSKEY:
		return false
	}
	return true
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
func (imr *Imr) cacheCNAMELink(ctx context.Context, qname string, r *dns.Msg, cn *dns.CNAME, transport core.Transport) (string, error) {
	now := time.Now()
	link := &core.RRset{Name: qname, Class: dns.ClassINET, RRtype: dns.TypeCNAME}
	var vstate cache.ValidationState
	var synthesizedFrom string
	if dname := dnameAbove(r, qname); dname != nil {
		d := dname.RRs[0].(*dns.DNAME)
		state, err := imr.Cache.ValidateRRsetWithParentZone(ctx, dname, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
		if err != nil {
			return "", fmt.Errorf("DNAME %s: %w", dname.Name, err)
		}
		imr.Cache.Set(dname.Name, dns.TypeDNAME, &cache.CachedRRset{
			Name: dname.Name, RRtype: dns.TypeDNAME, Rcode: uint8(dns.RcodeSuccess), RRset: dname,
			Context: cache.ContextAnswer, State: state,
			Expiration: now.Add(cache.GetMinTTL(dname.RRs)), Transport: transport,
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
		vstate, synthesizedFrom = state, dname.Name
	} else {
		link.RRs = []dns.RR{cn}
		link.RRSIGs = sigsFor(r.Answer, qname, dns.TypeCNAME)
		state, err := imr.Cache.ValidateRRsetWithParentZone(ctx, link, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
		if err != nil {
			return "", fmt.Errorf("CNAME %s: %w", qname, err)
		}
		vstate = state
	}
	imr.Cache.Set(qname, dns.TypeCNAME, &cache.CachedRRset{
		Name: qname, RRtype: dns.TypeCNAME, Rcode: uint8(dns.RcodeSuccess), RRset: link,
		Context: cache.ContextAnswer, State: vstate,
		Expiration: now.Add(cache.GetMinTTL(link.RRs)), Transport: transport,
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

// chainAt assembles from the cache the chain that starts at qname: its links
// in order, and the entry for <last name, qtype>, holding data or a denial. ok
// is false when qname holds no CNAME, or when some part of the chain is not in
// the cache, so that the caller resolves it. err reports a loop, or a chain
// longer than maxCNAMEChain.
//
// Under strict privacy an entry that arrived in cleartext counts as missing.
func (imr *Imr) chainAt(qname string, qtype uint16, privacy edns0.PrivacyLevel) (links []*cache.CachedRRset, final *cache.CachedRRset, ok bool, err error) {
	usable := func(e *cache.CachedRRset) bool {
		return e != nil && !(privacy == edns0.PrivacyStrict && !core.IsEncryptedTransport(e.Transport))
	}
	name := qname
	seen := map[string]bool{core.CanonicalizeName(qname): true}
	for {
		if len(links) > 0 {
			if e := imr.Cache.Get(name, qtype); usable(e) {
				switch {
				case e.Context == cache.ContextAnswer && e.RRset != nil && e.RRset.RRtype == qtype && len(e.RRset.RRs) > 0:
					return links, e, true, nil
				case e.Context == cache.ContextNXDOMAIN || e.Context == cache.ContextNoErrNoAns:
					return links, e, true, nil
				}
			}
		}
		link := imr.Cache.Get(name, dns.TypeCNAME)
		if !usable(link) || link.Context != cache.ContextAnswer {
			return nil, nil, false, nil
		}
		target, isCNAME := cnameTarget(link.RRset)
		if !isCNAME {
			return nil, nil, false, nil
		}
		if link.SynthesizedFrom != "" && !usable(imr.Cache.Get(link.SynthesizedFrom, dns.TypeDNAME)) {
			return nil, nil, false, nil
		}
		if len(links) == maxCNAMEChain {
			return nil, nil, false, fmt.Errorf("CNAME chain from %s is longer than %d", qname, maxCNAMEChain)
		}
		links = append(links, link)
		t := core.CanonicalizeName(target)
		if seen[t] {
			return nil, nil, false, fmt.Errorf("CNAME loop: %s leads back to %s", name, target)
		}
		seen[t] = true
		name = target
	}
}

// serveChain answers r for <qname, qtype> when qname is a CNAME, from the
// chain in the cache (chainAt). It reports false, having written nothing, when
// there is no such chain or part of it is missing.
//
// Each part is judged by the rule for a single answer:
//   - a positive part (a link, or the data at the end) by dispositionFor, with
//     a verdict that says "could not tell yet" asked again, as
//     serveCachedPositive does;
//   - a synthesized CNAME by the verdict of its DNAME, which is served ahead of
//     it;
//   - a denial at the end by bogusDenial, and served with serveNegativeResponse.
//
// Any part that fails fails the answer, with that part's EDE. AD is set only
// when every part is Secure. The rcode is that of the chain's last name (RFC
// 6604).
func (imr *Imr) serveChain(ctx context.Context, w dns.ResponseWriter, r, m *dns.Msg, qname string, qtype uint16, msgoptions *edns0.MsgOptions, status edns0.PrivacyStatus) bool {
	links, final, ok, err := imr.chainAt(qname, qtype, msgoptions.Privacy)
	if err != nil {
		lgImr.Info("ImrResponder: refusing a CNAME chain", "qname", qname, "qtype", dns.TypeToString[qtype], "err", err)
		m.Answer, m.Ns = nil, nil
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return true
	}
	if !ok {
		return false
	}

	secure := true
	// judge applies the positive-answer rule to one part. False means the
	// part fails the answer, which has been written as a SERVFAIL.
	judge := func(e *cache.CachedRRset) bool {
		state := e.State
		signed := e.RRset != nil && len(e.RRset.RRSIGs) > 0
		if !verdictReusable(state) && signed && !msgoptions.CD {
			if v, err := imr.Cache.ValidateRRsetWithParentZone(ctx, e.RRset, imr.IterativeDNSQueryFetcher(), imr.ParentZone); err == nil {
				state = v
			}
		}
		disp, ede := imr.dispositionFor(state, e.EDECode, signed, msgoptions)
		switch disp {
		case answerServfail:
			lgImr.Debug("ImrResponder: returning SERVFAIL for a CNAME chain with a part that did not validate",
				"qname", qname, "qtype", dns.TypeToString[qtype], "part", e.Name, "type", dns.TypeToString[e.RRtype],
				"state", cache.ValidationStateToString[state], "edeCode", ede)
			m.Answer, m.Ns = nil, nil
			m.SetRcode(r, dns.RcodeServerFailure)
			if r.IsEdns0() != nil {
				if e.EDECode != 0 && e.EDEText != "" {
					edns0.AttachEDEToResponseWithText(m, e.EDECode, e.EDEText, msgoptions.DO)
				} else {
					edns0.AttachEDEToResponse(m, ede)
				}
			}
			w.WriteMsg(m)
			return false
		case answerServe:
			secure = false
		}
		return true
	}

	now := time.Now()
	var answer []dns.RR
	lastName := qname
	for _, link := range links {
		verdict := link
		if link.SynthesizedFrom != "" {
			dname := imr.Cache.Get(link.SynthesizedFrom, dns.TypeDNAME)
			if dname == nil {
				return false // expired since chainAt looked
			}
			verdict = dname
			answer = append(answer, dname.ServeAnswer(now, msgoptions.DO)...)
		}
		if !judge(verdict) {
			return true
		}
		answer = append(answer, link.ServeAnswer(now, msgoptions.DO)...)
		lastName, _ = cnameTarget(link.RRset)
	}

	switch final.Context {
	case cache.ContextNXDOMAIN, cache.ContextNoErrNoAns:
		if bogusDenial(final, msgoptions) {
			writeBogusDenial(w, r, m)
			return true
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
			return true
		}
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = append(answer, final.ServeAnswer(now, msgoptions.DO)...)
		m.AuthenticatedData = secure && adWanted(r, msgoptions)
	}
	setPrivacyStatus(m, msgoptions, status)
	w.WriteMsg(m)
	return true
}
