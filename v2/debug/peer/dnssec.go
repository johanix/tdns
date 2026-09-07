/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"fmt"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// This file decides invariants N3 and N6 by INSPECTION, never by cryptography.
//
// It checks that every RRset that must be signed carries an RRSIG naming a key
// the zone itself publishes, and that the NSEC chain closes. It does NOT
// verify a signature: that needs the algorithm implementations, which this
// tool deliberately does not link (it is a pure client, see the tdns-debug
// README). The failure this rig exists to catch — a state announced before it
// was signed — is a PRESENCE failure, and presence is what is checked here.

// IssueKind names a class of defect so a report can be grouped and a checker
// can act on one class without string-matching prose.
type IssueKind string

const (
	IssueUnsignedRRset IssueKind = "unsigned-rrset" // authoritative data with no usable RRSIG
	IssueOrphanRRSIG   IssueKind = "orphan-rrsig"   // RRSIG covering a type that is not there
	IssueForeignSigner IssueKind = "foreign-signer" // RRSIG by a key the zone does not publish
	IssueChainBreak    IssueKind = "nsec-chain"     // the NSEC chain does not close
	IssueChainMissing  IssueKind = "nsec-missing"   // an authoritative name is not in the chain
	IssueNoDNSKEY      IssueKind = "no-apex-dnskey" // signatures but no keys to check them against
)

type SigningIssue struct {
	Kind   IssueKind
	Owner  string
	Rrtype uint16
	Detail string
}

func (i SigningIssue) String() string {
	if i.Rrtype != 0 {
		return fmt.Sprintf("%s %s %s: %s", i.Kind, i.Owner, dns.TypeToString[i.Rrtype], i.Detail)
	}
	return fmt.Sprintf("%s %s: %s", i.Kind, i.Owner, i.Detail)
}

// SigningReport is the verdict on one served zone state.
type SigningReport struct {
	// Signed is the coarse question N3 asks first: does this state look signed
	// at all? A state announced with no DNSKEY and no RRSIG is the failure mode
	// §2.3 predicts of NOTIFY #1, and it needs no per-RRset detail to name.
	Signed bool
	// ChainSkipped explains why the NSEC chain was not checked, when it was
	// not. A skip is reported, never counted as a pass.
	ChainSkipped string
	// Checked counts the RRsets that required a signature.
	Checked int
	Issues  []SigningIssue
}

// FullySigned is invariant N6: signed, and nothing wrong with how.
func (r SigningReport) FullySigned() bool { return r.Signed && len(r.Issues) == 0 }

func (r SigningReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "signed=%v rrsets_checked=%d issues=%d", r.Signed, r.Checked, len(r.Issues))
	if r.ChainSkipped != "" {
		fmt.Fprintf(&b, "\n  NSEC chain SKIPPED: %s", r.ChainSkipped)
	}
	for _, i := range r.Issues {
		fmt.Fprintf(&b, "\n  %s", i)
	}
	return b.String()
}

// rrsetKey identifies one RRset.
type rrsetKey struct {
	Name string // canonical
	Type uint16
}

// rrsets groups a zone by owner and type, with owners canonicalised.
func rrsets(z *Zone) map[rrsetKey][]dns.RR {
	out := map[rrsetKey][]dns.RR{}
	for _, rr := range z.RRs() {
		h := rr.Header()
		out[rrsetKey{core.CanonicalizeName(h.Name), h.Rrtype}] = append(
			out[rrsetKey{core.CanonicalizeName(h.Name), h.Rrtype}], rr)
	}
	return out
}

// delegationPoints are the non-apex owners carrying an NS RRset. Everything
// strictly below one of these is out of bailiwick for the signer, and the
// delegation itself is signed only as to its DS and NSEC.
func delegationPoints(z *Zone) []string {
	apex := core.CanonicalizeName(dns.Fqdn(z.Origin))
	var out []string
	for k := range rrsets(z) {
		if k.Type == dns.TypeNS && k.Name != apex {
			out = append(out, k.Name)
		}
	}
	sort.Strings(out)
	return out
}

// signedTypeAt reports whether an RRset must carry an RRSIG.
//
// Not signed: RRSIG itself; anything strictly below a delegation (glue); and,
// at a delegation point, everything except DS and NSEC. Signing any of those
// would be the bug, so a rig that demanded signatures there would report the
// correct server as broken.
func signedTypeAt(name string, rrtype uint16, apex string, delegations []string) bool {
	if rrtype == dns.TypeRRSIG {
		return false
	}
	if name == apex {
		return true
	}
	for _, d := range delegations {
		if name == d {
			return rrtype == dns.TypeDS || rrtype == dns.TypeNSEC
		}
		if dns.IsSubDomain(d, name) {
			return false
		}
	}
	return true
}

// CheckSigning decides N6 (and supplies N3's Signed answer) for one zone state.
func CheckSigning(z *Zone) SigningReport {
	var rep SigningReport
	apex := core.CanonicalizeName(dns.Fqdn(z.Origin))
	sets := rrsets(z)
	delegations := delegationPoints(z)

	keys := map[uint32]uint8{} // keytag -> algorithm, from the apex DNSKEY RRset
	for _, rr := range sets[rrsetKey{apex, dns.TypeDNSKEY}] {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys[uint32(k.KeyTag())] = k.Algorithm
		}
	}

	var anyRRSIG bool
	for k := range sets {
		if k.Type == dns.TypeRRSIG {
			anyRRSIG = true
			break
		}
	}
	rep.Signed = len(keys) > 0 && anyRRSIG
	if anyRRSIG && len(keys) == 0 {
		rep.Issues = append(rep.Issues, SigningIssue{
			Kind: IssueNoDNSKEY, Owner: apex,
			Detail: "the zone carries RRSIGs but publishes no apex DNSKEY",
		})
	}
	if !rep.Signed {
		// Nothing further to say: an unsigned state has no signatures to be
		// wrong about, and reporting every RRset as unsigned would bury the
		// one fact that matters.
		return rep
	}

	// Index the RRSIGs by what they cover.
	covered := map[rrsetKey][]*dns.RRSIG{}
	for k, rrs := range sets {
		if k.Type != dns.TypeRRSIG {
			continue
		}
		for _, rr := range rrs {
			sig, ok := rr.(*dns.RRSIG)
			if !ok {
				continue
			}
			covered[rrsetKey{k.Name, sig.TypeCovered}] = append(
				covered[rrsetKey{k.Name, sig.TypeCovered}], sig)
		}
	}

	for k := range sets {
		if !signedTypeAt(k.Name, k.Type, apex, delegations) {
			continue
		}
		rep.Checked++
		sigs := covered[k]
		if len(sigs) == 0 {
			rep.Issues = append(rep.Issues, SigningIssue{
				Kind: IssueUnsignedRRset, Owner: k.Name, Rrtype: k.Type,
				Detail: "no RRSIG covers this RRset",
			})
			continue
		}
		usable := false
		for _, sig := range sigs {
			if !equalName(sig.SignerName, apex) {
				continue
			}
			if alg, ok := keys[uint32(sig.KeyTag)]; ok && alg == sig.Algorithm {
				usable = true
				break
			}
		}
		if !usable {
			rep.Issues = append(rep.Issues, SigningIssue{
				Kind: IssueForeignSigner, Owner: k.Name, Rrtype: k.Type,
				Detail: "no RRSIG names a key this zone publishes (keytag+algorithm)",
			})
		}
	}

	// An RRSIG for a type the owner does not have is left behind by an
	// incomplete republish — a signer that removed an RRset and kept its
	// signature.
	for k := range covered {
		if _, ok := sets[k]; !ok {
			rep.Issues = append(rep.Issues, SigningIssue{
				Kind: IssueOrphanRRSIG, Owner: k.Name, Rrtype: k.Type,
				Detail: "RRSIG covers a type the owner does not have",
			})
		}
	}

	rep.appendChainIssues(z, apex, sets, delegations)
	sort.Slice(rep.Issues, func(i, j int) bool { return rep.Issues[i].String() < rep.Issues[j].String() })
	return rep
}

// appendChainIssues checks that the NSEC chain closes and covers every
// authoritative name.
func (rep *SigningReport) appendChainIssues(z *Zone, apex string, sets map[rrsetKey][]dns.RR, delegations []string) {
	for k := range sets {
		if k.Type == dns.TypeNSEC3 || k.Type == dns.TypeNSEC3PARAM {
			rep.ChainSkipped = "zone uses NSEC3; only NSEC chains are checked"
			return
		}
	}

	next := map[string]string{}
	for k, rrs := range sets {
		if k.Type != dns.TypeNSEC {
			continue
		}
		for _, rr := range rrs {
			if n, ok := rr.(*dns.NSEC); ok {
				next[k.Name] = core.CanonicalizeName(n.NextDomain)
			}
		}
	}
	if len(next) == 0 {
		rep.ChainSkipped = "zone has no NSEC records (NSEC3, or black lies)"
		return
	}

	// Every name that carries authoritative data must be in the chain. Names
	// below a delegation must not be, and are not asked for.
	for k := range sets {
		if k.Type == dns.TypeRRSIG || k.Type == dns.TypeNSEC {
			continue
		}
		if !signedTypeAt(k.Name, k.Type, apex, delegations) {
			continue
		}
		if _, ok := next[k.Name]; !ok {
			rep.Issues = append(rep.Issues, SigningIssue{
				Kind: IssueChainMissing, Owner: k.Name,
				Detail: "authoritative name has no NSEC",
			})
		}
	}

	// One cycle through every NSEC owner, back to the apex.
	if _, ok := next[apex]; !ok {
		rep.Issues = append(rep.Issues, SigningIssue{
			Kind: IssueChainBreak, Owner: apex, Detail: "the apex has no NSEC, so the chain has no start",
		})
		return
	}
	seen := map[string]bool{}
	cur := apex
	for i := 0; i <= len(next); i++ {
		if seen[cur] {
			break
		}
		seen[cur] = true
		nxt, ok := next[cur]
		if !ok {
			rep.Issues = append(rep.Issues, SigningIssue{
				Kind: IssueChainBreak, Owner: cur,
				Detail: "the chain points here, but this name has no NSEC",
			})
			return
		}
		cur = nxt
	}
	if cur != apex {
		rep.Issues = append(rep.Issues, SigningIssue{
			Kind: IssueChainBreak, Owner: cur,
			Detail: "following the chain from the apex does not return to it",
		})
	}
	for owner := range next {
		if !seen[owner] {
			rep.Issues = append(rep.Issues, SigningIssue{
				Kind: IssueChainBreak, Owner: owner,
				Detail: "NSEC owner is not reachable by following the chain from the apex",
			})
		}
	}
}
