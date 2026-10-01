/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"slices"
	"strings"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ChainStatus is the per-link verdict of a chain walk. Same value set as
// the IMR's ValidationState, kept here as a separate type so the chase
// API doesn't drag cache internals into callers (dog is one such caller).
type ChainStatus int

const (
	ChainStatusUnknown       ChainStatus = iota
	ChainStatusSecure                    // verified link to parent + within validity
	ChainStatusInsecure                  // NSEC/NSEC3 proves no DS at parent (signed proof of unsignedness)
	ChainStatusIndeterminate             // chain unavailable (no DS, no proof, query failed, etc.)
	ChainStatusBogus                     // signature present but verify failed or out of validity
)

func (s ChainStatus) String() string {
	switch s {
	case ChainStatusSecure:
		return "secure"
	case ChainStatusInsecure:
		return "insecure"
	case ChainStatusBogus:
		return "bogus"
	case ChainStatusIndeterminate:
		return "indeterminate"
	default:
		return "unknown"
	}
}

// ChainLink is one zone-cut on the way from the trust anchor down to the
// leaf. For each zone we record what DS (if any) the parent gave us, what
// DNSKEY the zone itself gave us, which (if any) KSK matched the DS, and
// the verdict of validating the zone's DNSKEY RRset against that match.
type ChainLink struct {
	Zone       string        // FQDN of the zone at this cut
	ParentZone string        // the zone of the link above this one; "" for the root
	DS         []*dns.DS     // DS records seen at the parent for this zone (may be empty for insecure / root)
	DSSigs     []*dns.RRSIG  // RRSIG(DS) records, by the parent
	DNSKEY     []*dns.DNSKEY // DNSKEY records published by this zone
	DNSKEYSigs []*dns.RRSIG  // RRSIG(DNSKEY) records
	MatchedKSK *dns.DNSKEY   // DNSKEY whose tag+digest matched a DS at the parent
	Status     ChainStatus   // verdict for this link
	Notes      []string      // human-readable annotations (signer/keytag/sigtimes, errors)
}

// ChainLeaf is the final answer: the qname/qtype RRset and the result of
// verifying its RRSIG against the deepest zone's keys.
type ChainLeaf struct {
	Qname  string
	Qtype  uint16
	RRset  *core.RRset // nil when the name has no records of the type
	Rcode  int         // the rcode of the answer: NOERROR or NXDOMAIN
	Status ChainStatus
	Notes  []string
}

// ChainHop is the chain walked for one name of a CNAME chain, and the CNAME
// that name owns, as its leaf.
type ChainHop struct {
	Links []ChainLink
	Leaf  ChainLeaf
}

// ChainResult is the full structured chase output. Status is the overall
// verdict: the worst of every link and leaf, of every name in the CNAME
// chain (RFC 4035 section 3.2.3).
type ChainResult struct {
	Qname             string // the name asked for
	Qtype             uint16 // the type asked for
	TrustAnchorSource string // where the trust anchors came from (Chaser.TrustAnchorSource), or "none"
	// Aliases are the names of the CNAME chain before the last, in order,
	// each with the CNAME it owns as its leaf. Empty when qname owns no
	// CNAME.
	Aliases []ChainHop
	// Links and Leaf are for the last name of the chain: qname, or the
	// target of the last CNAME. Leaf.RRset is the answer.
	Links  []ChainLink // root-first, leaf zone last
	Leaf   ChainLeaf
	Status ChainStatus
}

// Chaser walks a DNSSEC chain by issuing DO=1 queries against a recursive
// resolver (or stub-friendly auth). Caller supplies the client + server;
// no internal caching, every Chase issues fresh queries.
type Chaser struct {
	Client core.DNSClienter // any DNSClienter implementation (W5)
	Server string           // bare host, the client adds the port
	// TrustAnchors hold the operator-trusted DS records keyed by zone
	// name (typically just "." for root). Used to validate the root
	// (or other configured TA's) DNSKEY at the top of the chain so
	// the root link reports Secure instead of Indeterminate. nil =
	// no anchors configured; the root link stays Indeterminate.
	TrustAnchors map[string][]*dns.DS
	// TrustAnchorSource says where TrustAnchors came from, for the output:
	// a file, a resolver's configuration, or the anchors compiled in. A
	// verdict reached with other anchors than the operator meant is one
	// that cannot be told apart from the right one otherwise.
	TrustAnchorSource string
}

// NewChaser returns a Chaser that talks to the given recursive resolver
// via the supplied DNSClienter. trustAnchors is optional; pass nil to
// run without TA verification (the root link will then be reported as
// Indeterminate).
func NewChaser(client core.DNSClienter, server string, trustAnchors []*dns.DS) *Chaser {
	tas := map[string][]*dns.DS{}
	for _, ds := range trustAnchors {
		name := core.CanonicalizeName(dns.Fqdn(ds.Hdr.Name))
		tas[name] = append(tas[name], ds)
	}
	return &Chaser{Client: client, Server: server, TrustAnchors: tas}
}

// anchorsFor returns the trust anchors configured for zone. Names compare
// without regard to case, as everywhere else in the walk: the zone comes from
// the query name, in the case it was asked in. NewChaser stores canonical
// keys; a map a caller filled itself is searched when the direct lookup
// misses.
func (c *Chaser) anchorsFor(zone string) []*dns.DS {
	zone = dns.Fqdn(zone)
	if tas, ok := c.TrustAnchors[core.CanonicalizeName(zone)]; ok {
		return tas
	}
	for name, tas := range c.TrustAnchors {
		if core.EqualNames(dns.Fqdn(name), zone) {
			return tas
		}
	}
	return nil
}

// Chase walks the chain from the root toward qname and verifies each
// zone cut. Returns a fully-populated ChainResult; the caller can then
// hand it to RenderChain for human display or inspect the structure
// programmatically (e.g., the IMR's future imr explain command).
func (c *Chaser) Chase(qname string, qtype uint16) (*ChainResult, error) {
	if c == nil || c.Client == nil {
		return nil, fmt.Errorf("chase: nil client")
	}
	qname = dns.Fqdn(qname)
	w := &chainWalk{c: c, now: time.Now().UTC(), cuts: map[string]*cutDecision{}}
	result := &ChainResult{Qname: qname, Qtype: qtype, TrustAnchorSource: c.TrustAnchorSource,
		Status: ChainStatusSecure}
	if result.TrustAnchorSource == "" && len(c.TrustAnchors) == 0 {
		result.TrustAnchorSource = "none"
	}

	// Each name of the CNAME chain is walked in turn, with the zone cuts
	// decided for the names before it, up to the resolver's limit on the
	// length of a chain (maxCNAMEChain).
	type hop struct {
		links []*ChainLink
		leaf  ChainLeaf
	}
	var hops []hop
	seen := map[string]bool{}
	for name := qname; ; {
		seen[core.CanonicalizeName(name)] = true
		links, leaf, target := w.walkName(name, qtype)
		hops = append(hops, hop{links, leaf})
		if target == "" {
			break
		}
		end := ""
		switch {
		case seen[core.CanonicalizeName(target)]:
			end = fmt.Sprintf("CNAME loop: %s is earlier in the chain", target)
		case len(hops) > maxCNAMEChain:
			end = fmt.Sprintf("CNAME chain longer than %d", maxCNAMEChain)
		}
		if end != "" {
			hops = append(hops, hop{leaf: ChainLeaf{Qname: target, Qtype: qtype, Status: ChainStatusIndeterminate, Notes: []string{end}}})
			break
		}
		name = target
	}

	// The links are copied once the whole chain is walked: a link reached
	// again for a later name may have gained notes.
	for i, h := range hops {
		ch := ChainHop{Leaf: h.leaf}
		for _, link := range h.links {
			ch.Links = append(ch.Links, *link)
			result.Status = worstStatus(result.Status, link.Status)
		}
		result.Status = worstStatus(result.Status, h.leaf.Status)
		if i < len(hops)-1 {
			result.Aliases = append(result.Aliases, ch)
			continue
		}
		result.Links, result.Leaf = ch.Links, ch.Leaf
	}
	return result, nil
}

// chainWalk is the state of one Chase: what was decided about each candidate
// zone cut, so that no candidate is asked about twice.
type chainWalk struct {
	c    *Chaser
	now  time.Time               // the time signatures are checked at
	cuts map[string]*cutDecision // by candidate name, canonical form
}

// cutDecision is what the walk made of a candidate zone cut: a link in the
// chain, or nothing (link nil), when the candidate is no zone cut.
type cutDecision struct {
	link *ChainLink
	// insecure is set for a delegation proven to have no DS the walk can
	// use: no chain of trust leads below it, and nothing below it is
	// checked.
	insecure bool
}

// chaseAnswer is the response to the question about the leaf, read by owner:
// only records the name asked for owns count.
type chaseAnswer struct {
	rrs       []dns.RR     // records of the type asked for
	sigs      []*dns.RRSIG // the RRSIGs over them
	cname     []dns.RR     // without rrs: the CNAME the name owns
	cnameSigs []*dns.RRSIG // its RRSIGs
	dname     string       // the owner of a DNAME above the name that synthesized the CNAME
	rcode     int          // NOERROR or NXDOMAIN
	err       error        // the query failed: no response, or another rcode
}

// walkName asks for name and qtype, walks the zone cuts from the root down to
// name, and judges the answer against the deepest of them.
//
// The answer is asked for first: what the name owns tells which candidates
// can be zone cuts at all.
//
// A name that owns a CNAME is no zone cut: a CNAME owner holds no other data
// (RFC 2181 section 10.1), neither the NS of a delegation nor the SOA of an
// apex. Its CNAME is the leaf, and walkName returns its target. A CNAME
// synthesized from a DNAME is not followed.
func (w *chainWalk) walkName(name string, qtype uint16) ([]*ChainLink, ChainLeaf, string) {
	ans := w.c.ask(name, qtype)
	alias := len(ans.cname) > 0
	zones := zoneCutsFromRoot(name) // root-first
	// DS records live at the PARENT zone, not at qname's own zone. So
	// for a DS leaf query, drop qname from the zone chain — the parent
	// becomes the deepest validated zone, and the leaf RRset is then
	// verified against that parent's DNSKEYs (whose ZSK signed the DS).
	// Without this, the chaser would try to fetch DS for qname itself
	// (a redundant second wire query to fetch what the leaf will get),
	// and even on success would attempt leaf verification against the
	// child zone's DNSKEYs — which never signed the DS.
	if (qtype == dns.TypeDS || alias) && len(zones) > 1 {
		zones = zones[:len(zones)-1]
	}
	links := w.links(zones)
	if !alias {
		return links, w.judgeLeaf(name, qtype, ans, links), ""
	}
	if len(links) > 0 {
		addNote(links[len(links)-1], fmt.Sprintf("%s: owns a CNAME, not a zone cut", name))
	}
	if ans.dname != "" && len(ans.cnameSigs) == 0 {
		leaf := ChainLeaf{Qname: name, Qtype: dns.TypeCNAME, Rcode: ans.rcode, Status: ChainStatusIndeterminate,
			RRset: &core.RRset{Name: name, Class: dns.ClassINET, RRtype: dns.TypeCNAME, RRs: ans.cname},
			Notes: []string{fmt.Sprintf("synthesized from the DNAME at %s; a DNAME is not followed", ans.dname)}}
		if len(links) > 0 && w.insecure(links[len(links)-1]) {
			leaf.Status = links[len(links)-1].Status
		}
		return links, leaf, ""
	}
	cname := chaseAnswer{rrs: ans.cname, sigs: ans.cnameSigs, rcode: ans.rcode}
	return links, w.judgeLeaf(name, dns.TypeCNAME, cname, links), ans.cname[0].(*dns.CNAME).Target
}

// links decides each candidate zone, root first, and returns the zone cuts
// among them. A candidate decided earlier in the same Chase is not asked
// about again.
//
// Below an insecure delegation nothing is checked, except a zone with a trust
// anchor of its own.
func (w *chainWalk) links(zones []string) []*ChainLink {
	var chain []*ChainLink
	insecure := false
	for _, zone := range zones {
		if insecure && len(w.c.anchorsFor(zone)) == 0 {
			addNote(chain[len(chain)-1], "names below an insecure delegation are not checked")
			continue
		}
		key := core.CanonicalizeName(zone)
		d, ok := w.cuts[key]
		if !ok {
			d = w.decide(zone, chain)
			w.cuts[key] = d
		}
		if d.link != nil {
			chain = append(chain, d.link)
			insecure = d.insecure
		}
	}
	return chain
}

// addNote adds note to link, unless it has it already: a link can be reached
// again by another name of the chase.
func addNote(link *ChainLink, note string) {
	if !slices.Contains(link.Notes, note) {
		link.Notes = append(link.Notes, note)
	}
}

// decide works out whether zone is a zone cut below chain, the links decided
// above it, and judges it if it is.
//
// A link is no better than the link above it (RFC 4035 section 5.2): its DS
// RRset is the parent's data, and proves something only when the parent's
// keys are trusted. The root has no link above, and a zone with a trust
// anchor of its own is vouched for by the anchor.
func (w *chainWalk) decide(zone string, chain []*ChainLink) *cutDecision {
	link := &ChainLink{Zone: zone}
	var above *ChainLink
	if len(chain) > 0 {
		above = chain[len(chain)-1]
		link.ParentZone = above.Zone
	}
	d := w.decideOwn(link, above)
	if d.link != nil && above != nil && len(w.c.anchorsFor(zone)) == 0 {
		capBelow(d.link, above)
	}
	return d
}

// capBelow makes link no better than above, the link above it, and says so
// when that changes its verdict.
func capBelow(link, above *ChainLink) {
	capped := worstStatus(link.Status, above.Status)
	if capped != link.Status {
		link.Notes = append(link.Notes, fmt.Sprintf("zone %s above is %s; this link can be no better", above.Zone, above.Status))
		link.Status = capped
	}
}

// decideOwn is decide for the link on its own: link.Status is its own
// verdict, before the link above caps it.
func (w *chainWalk) decideOwn(link, above *ChainLink) *cutDecision {
	zone := link.Zone
	// Fetch DS from the parent (skip for root, and for a zone with a trust
	// anchor of its own: the anchor vouches for its keys, as it does in the
	// resolver, which asks for no DS there either).
	if zone != "." && len(w.c.anchorsFor(zone)) == 0 {
		resp, err := w.c.query(zone, dns.TypeDS)
		if err != nil {
			link.Status = ChainStatusIndeterminate
			link.Notes = append(link.Notes, fmt.Sprintf("DS query failed: %v", err))
			return &cutDecision{link: link}
		}
		ds, dsSigs := ownedDS(resp.Answer, zone)
		if cname, _ := ownedRRs(resp.Answer, zone, dns.TypeCNAME); len(ds) == 0 && len(cname) > 0 {
			// A resolver that follows the CNAME for a DS question answers
			// with it, and the target's DS: the name is no zone cut.
			if above != nil {
				addNote(above, fmt.Sprintf("%s: owns a CNAME, not a zone cut", zone))
			}
			return &cutDecision{}
		}
		if len(ds) == 0 {
			return w.withoutDS(link, above, resp)
		}
		link.DS, link.DSSigs = ds, dsSigs
	}

	dsState := ChainStatusSecure
	if len(link.DS) > 0 {
		dsState = w.verifyDS(link, above)
		if unusable := unusableDS(link.DS); len(unusable) == len(link.DS) {
			return noUsableDS(link, dsState, unusable)
		}
	}
	w.judgeKeys(link)
	link.Status = worstStatus(link.Status, dsState)
	return &cutDecision{link: link}
}

// withoutDS decides zone, a candidate the parent side has no DS for, from
// the NSEC or NSEC3 records of the denial, verified with the keys of above,
// the link of the zone they must come from (RFC 4035 section 5.2, RFC 6840
// section 4.4, RFC 5155 sections 8.6, 8.9 and 9.2; cache.ProveDelegation,
// the resolver's reading of them):
//
//   - a delegation without DS, or an Opt-Out span that may hold one: an
//     Insecure link, and nothing below it is checked;
//   - a proof that needs NSEC3 records over the iteration limit, or more
//     hashes than allowed: an Indeterminate link;
//   - no delegation there, or nothing proven about one: no link, with a note
//     on the link above.
//
// Taking a candidate nothing is proven about as part of the zone above is
// safe: if it is in fact a zone cut, its data is signed with its own keys or
// not at all, and judged with the keys of the zone above it does not come out
// Secure. This replaces asking each candidate for its SOA and NS (#379),
// which took a name owning a CNAME for a zone cut.
func (w *chainWalk) withoutDS(link, above *ChainLink, resp *dns.Msg) *cutDecision {
	zone := link.Zone
	if above == nil {
		link.Status = ChainStatusIndeterminate
		link.Notes = append(link.Notes, "no DS, and no zone above to read a proof from")
		return &cutDecision{link: link}
	}
	nsecs, nsec3s := w.verifiedProof(resp.Ns, above)
	switch cache.ProveDelegation(zone, above.Zone, nsecs, nsec3s) {
	case cache.DelegationInsecure:
		link.Status = ChainStatusInsecure
		link.Notes = append(link.Notes, insecureProofNote(zone, nsecs))
		return &cutDecision{link: link, insecure: true}
	case cache.DelegationUnjudged:
		link.Status = ChainStatusIndeterminate
		link.Notes = append(link.Notes, fmt.Sprintf("no DS; the NSEC3 proof about it needs records over the iteration limit of %d, or more hashes than allowed: cannot judge",
			cache.NSEC3MaxIterations()))
		return &cutDecision{link: link}
	case cache.DelegationNone:
		addNote(above, fmt.Sprintf("%s: no DS, and the denial shows no delegation there", zone))
	default:
		addNote(above, fmt.Sprintf("%s: no DS and no proof about a cut; taken as part of %s", zone, above.Zone))
	}
	return &cutDecision{}
}

// verifiedProof returns the NSEC and NSEC3 records in authority, a message
// section, whose RRSIG by the zone of above verifies with its keys. Records
// signed by any other zone, or not at all, prove nothing here.
func (w *chainWalk) verifiedProof(authority []dns.RR, above *ChainLink) ([]*dns.NSEC, []*dns.NSEC3) {
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	if len(above.DNSKEY) == 0 {
		return nil, nil
	}
	for _, set := range authorityRRsets(authority) {
		if set.RRtype != dns.TypeNSEC && set.RRtype != dns.TypeNSEC3 {
			continue
		}
		if _, err := zoneSignature(set, above.Zone, above.DNSKEY, w.now); err != nil {
			continue
		}
		for _, rr := range set.RRs {
			switch r := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, r)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, r)
			}
		}
	}
	return nsecs, nsec3s
}

// insecureProofNote says what proved zone an insecure delegation: the NSEC
// at it, or the NSEC3 records.
func insecureProofNote(zone string, nsecs []*dns.NSEC) string {
	for _, nsec := range nsecs {
		if core.EqualNames(nsec.Hdr.Name, zone) {
			types := make([]string, 0, len(nsec.TypeBitMap))
			for _, t := range nsec.TypeBitMap {
				types = append(types, dns.TypeToString[t])
			}
			return fmt.Sprintf("no DS; NSEC %s -> %s %s: a delegation without DS (RFC 4035 section 5.2)",
				nsec.Hdr.Name, nsec.NextDomain, strings.Join(types, " "))
		}
	}
	return "no DS; NSEC3 proves a delegation without DS, or an Opt-Out span that may hold one (RFC 5155 sections 8.6 and 9.2)"
}

// unusableDS describes each DS in dss that names an algorithm this binary
// cannot verify or a digest type it cannot compute (cache.DSUsable).
func unusableDS(dss []*dns.DS) []string {
	var out []string
	for _, ds := range dss {
		if cache.DSUsable(ds) {
			continue
		}
		why := fmt.Sprintf("digest type %d not supported", ds.DigestType)
		if !cache.AlgorithmSupported(ds.Algorithm) {
			why = "algorithm not supported by this binary"
		}
		out = append(out, fmt.Sprintf("keytag=%d %s: %s", ds.KeyTag, algField(ds.Algorithm, true), why))
	}
	return out
}

// noUsableDS judges a link whose DS RRset holds no DS this binary can use.
// Verified, it is an insecure delegation: there is no supported path from
// the parent to the child, and the child is treated as if the parent had
// proven it has no DS (RFC 4035 section 5.2, RFC 6840 section 5.2). Not
// verified, it proves nothing, and the link takes dsState, the DS RRset's
// verdict. A trust anchor is not judged here: one that matches no key stays
// an error.
func noUsableDS(link *ChainLink, dsState ChainStatus, unusable []string) *cutDecision {
	note := "no DS this binary can use (" + strings.Join(unusable, "; ") + ")"
	if dsState != ChainStatusSecure {
		link.Status = dsState
		link.Notes = append(link.Notes, note)
		return &cutDecision{link: link}
	}
	link.Status = ChainStatusInsecure
	link.Notes = append(link.Notes, note+": an insecure delegation (RFC 4035 section 5.2)")
	return &cutDecision{link: link, insecure: true}
}

// verifyDS checks the RRSIG over link's DS RRset with the keys of above, the
// link of the parent zone: the parent signed it (RFC 4035 sections 5.2 and
// 5.3.1). It returns Secure when a signature verifies, Bogus when none does,
// and Indeterminate when the parent's keys are not there to check it with.
func (w *chainWalk) verifyDS(link, above *ChainLink) ChainStatus {
	if above == nil || len(above.DNSKEY) == 0 {
		parent := "the parent"
		if above != nil {
			parent = above.Zone
		}
		link.Notes = append(link.Notes, fmt.Sprintf("DS RRset not verified: no DNSKEY of %s to verify it with", parent))
		return ChainStatusIndeterminate
	}
	set := &core.RRset{Name: link.Zone, Class: dns.ClassINET, RRtype: dns.TypeDS, RRSIGs: rrsigsToRRs(link.DSSigs)}
	for _, ds := range link.DS {
		set.RRs = append(set.RRs, ds)
	}
	sig, err := zoneSignature(set, above.Zone, above.DNSKEY, w.now)
	if err != nil {
		link.Notes = append(link.Notes, fmt.Sprintf("DS RRset: %v", err))
		return ChainStatusBogus
	}
	link.Notes = append(link.Notes, fmt.Sprintf("DS RRset signed by %s keytag=%d: verified", above.Zone, sig.KeyTag))
	return ChainStatusSecure
}

// zoneSignature checks the RRSIGs over rrset that zone made, with keys, the
// zone's DNSKEY RRset (RFC 4035 section 5.3.1): only signatures whose signer
// is zone and can hold the RRset (cache.SignerHoldsRRset), and only keys with
// the Zone flag and protocol 3. It returns the signature that verified within
// its validity period at now, or why none did.
func zoneSignature(rrset *core.RRset, zone string, keys []*dns.DNSKEY, now time.Time) (*dns.RRSIG, error) {
	var sigs []dns.RR
	for _, rr := range rrset.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || sig.TypeCovered != rrset.RRtype || !core.EqualNames(sig.SignerName, zone) ||
			!cache.SignerHoldsRRset(rrset, sig) {
			continue
		}
		sigs = append(sigs, sig)
	}
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no RRSIG by %s", zone)
	}
	var zoneKeys []*dns.DNSKEY
	for _, k := range keys {
		if k.Flags&dns.ZONE != 0 && k.Protocol == 3 {
			zoneKeys = append(zoneKeys, k)
		}
	}
	signed := &core.RRset{Name: rrset.Name, Class: rrset.Class, RRtype: rrset.RRtype, RRs: rrset.RRs, RRSIGs: sigs}
	sig, _, err := signatureByOneOf(signed, zoneKeys, now)
	return sig, err
}

// judgeKeys fetches the DNSKEY RRset of link's zone and matches it against
// the DS records the parent gave, or against the trust anchor configured for
// the zone.
func (w *chainWalk) judgeKeys(link *ChainLink) {
	zone := link.Zone
	resp, err := w.c.query(zone, dns.TypeDNSKEY)
	if err != nil {
		link.Status = ChainStatusIndeterminate
		link.Notes = append(link.Notes, fmt.Sprintf("DNSKEY query failed: %v", err))
		return
	}
	dnskeys, sigs := ownedDNSKEY(resp.Answer, zone)
	link.DNSKEY = dnskeys
	link.DNSKEYSigs = sigs

	// Match DS (if any) to a DNSKEY and verify the DNSKEY RRset
	// signature with that KSK.
	if len(link.DS) > 0 {
		rrsetForValidate := dnskeyRRsetForValidator(zone, dnskeys, sigs)
		matched := false
		for _, ds := range link.DS {
			ok, ksk := cache.ValidateDNSKEYRRsetUsingDS(rrsetForValidate, ds, zone, false)
			if ok && ksk != nil {
				link.MatchedKSK = ksk
				link.Status = ChainStatusSecure
				link.Notes = append(link.Notes, fmt.Sprintf("DS keytag=%d matches KSK; DNSKEY RRset signature OK", ds.KeyTag))
				matched = true
				break
			}
		}
		if !matched {
			link.Status = ChainStatusBogus
			link.Notes = append(link.Notes, "DS at parent has no matching DNSKEY (or DNSKEY RRSIG failed)")
		}
	} else if tas := w.c.anchorsFor(zone); len(tas) > 0 {
		// TA-anchored zone (typically root). Treat the configured
		// DS records exactly the same way as a parent's
		// referral-supplied DS: match against the zone's DNSKEY
		// RRset and validate the RRset's signature with the
		// matched KSK. This is what makes the root link reach
		// Secure for a fully-signed chain.
		link.DS = tas
		rrsetForValidate := dnskeyRRsetForValidator(zone, dnskeys, sigs)
		matched := false
		for _, ds := range tas {
			ok, ksk := cache.ValidateDNSKEYRRsetUsingDS(rrsetForValidate, ds, zone, false)
			if ok && ksk != nil {
				link.MatchedKSK = ksk
				link.Status = ChainStatusSecure
				link.Notes = append(link.Notes, fmt.Sprintf("trust-anchor DS keytag=%d matches KSK; DNSKEY RRset signature OK", ds.KeyTag))
				matched = true
				break
			}
		}
		if !matched {
			link.Status = ChainStatusBogus
			link.Notes = append(link.Notes, "trust-anchor DS has no matching DNSKEY at this zone (KSK rolled? wrong TA?)")
		}
	} else {
		// No TA configured for this zone (typically the root).
		// Without a TA we have no way to anchor the chain; report
		// the link as Indeterminate so the overall verdict
		// reflects the missing anchor.
		link.Status = ChainStatusIndeterminate
		link.Notes = append(link.Notes, "no trust anchor configured for this zone")
	}
}

// judgeLeaf judges the answer for name and qtype against the deepest link of
// chain, the zone that holds it (RFC 4035 sections 4.3 and 5):
//
//   - below an insecure delegation it is Insecure, signed or not: no chain of
//     trust leads to it;
//   - an answer is Secure when an RRSIG by the deepest zone verifies with its
//     keys, and Bogus when none does, or when there is no RRSIG although the
//     zone is signed;
//   - in any case no better than the deepest link.
func (w *chainWalk) judgeLeaf(name string, qtype uint16, ans chaseAnswer, chain []*ChainLink) ChainLeaf {
	leaf := ChainLeaf{Qname: name, Qtype: qtype, Rcode: ans.rcode}
	if ans.err != nil {
		leaf.Status = ChainStatusIndeterminate
		leaf.Notes = append(leaf.Notes, fmt.Sprintf("answer query failed: %v", ans.err))
		return leaf
	}
	if len(ans.rrs) > 0 {
		leaf.RRset = &core.RRset{
			Name:   name,
			Class:  dns.ClassINET,
			RRtype: qtype,
			RRs:    ans.rrs,
			RRSIGs: rrsigsToRRs(ans.sigs),
		}
	}
	if len(chain) == 0 {
		leaf.Status = ChainStatusIndeterminate
		leaf.Notes = append(leaf.Notes, "no zone to verify the answer with")
		return leaf
	}
	deepest := chain[len(chain)-1]
	if w.insecure(deepest) {
		leaf.Status = deepest.Status
		leaf.Notes = append(leaf.Notes, fmt.Sprintf("zone %s is insecure: no chain of trust leads to the answer", deepest.Zone))
		return leaf
	}
	var own ChainStatus
	if leaf.RRset == nil {
		own = ChainStatusIndeterminate
		leaf.Notes = append(leaf.Notes, fmt.Sprintf("%s: the proof of the denial is not checked", negativeKind(ans.rcode)))
	} else {
		own = w.answerOwn(&leaf, deepest)
	}
	leaf.Status = worstStatus(deepest.Status, own)
	if leaf.Status != own {
		leaf.Notes = append(leaf.Notes, fmt.Sprintf("zone %s is %s; the answer can be no better", deepest.Zone, deepest.Status))
	}
	return leaf
}

// insecure reports whether link was proven an insecure delegation.
func (w *chainWalk) insecure(link *ChainLink) bool {
	d, ok := w.cuts[core.CanonicalizeName(link.Zone)]
	return ok && d.insecure
}

// answerOwn is the verdict on leaf's answer RRset alone, with the keys of
// deepest, the zone that holds it.
func (w *chainWalk) answerOwn(leaf *ChainLeaf, deepest *ChainLink) ChainStatus {
	rrset := leaf.RRset
	if len(rrset.RRSIGs) == 0 {
		if deepest.Status == ChainStatusSecure {
			leaf.Notes = append(leaf.Notes, fmt.Sprintf("no RRSIG, and zone %s is signed", deepest.Zone))
			return ChainStatusBogus
		}
		leaf.Notes = append(leaf.Notes, "no RRSIG")
		return ChainStatusIndeterminate
	}
	if len(deepest.DNSKEY) == 0 {
		leaf.Notes = append(leaf.Notes, fmt.Sprintf("no DNSKEY of %s to verify the answer with", deepest.Zone))
		return ChainStatusIndeterminate
	}
	if !hasSigner(rrset, deepest.Zone) {
		for _, signer := range signersOf(rrset) {
			if dns.IsSubDomain(deepest.Zone, signer) {
				leaf.Notes = append(leaf.Notes, fmt.Sprintf("signed by %s, which the chain did not reach", signer))
			} else {
				leaf.Notes = append(leaf.Notes, fmt.Sprintf("signed by %s, not by %s, the zone that holds it", signer, deepest.Zone))
			}
		}
		return ChainStatusBogus
	}
	sig, err := zoneSignature(rrset, deepest.Zone, deepest.DNSKEY, w.now)
	if err != nil {
		leaf.Notes = append(leaf.Notes, err.Error())
		return ChainStatusBogus
	}
	leaf.Notes = append(leaf.Notes, fmt.Sprintf("sig keytag=%d verified", sig.KeyTag))
	if wildcard, ok := expandedFrom(sig, leaf.Qname); ok {
		// RFC 4035 section 5.3.4: valid for the wildcard, the signature does
		// not show that the name itself does not exist.
		leaf.Notes = append(leaf.Notes, fmt.Sprintf("synthesized from %s; the proof that the name does not exist is not checked", wildcard))
		return ChainStatusIndeterminate
	}
	return ChainStatusSecure
}

// hasSigner reports whether an RRSIG over rrset names zone as its signer.
func hasSigner(rrset *core.RRset, zone string) bool {
	return slices.ContainsFunc(signersOf(rrset), func(s string) bool { return core.EqualNames(s, zone) })
}

// signersOf is the signer names of the RRSIGs over rrset, each once.
func signersOf(rrset *core.RRset) []string {
	var out []string
	for _, rr := range rrset.RRSIGs {
		if sig, ok := rr.(*dns.RRSIG); ok && !core.EqualNamesContains(out, sig.SignerName) {
			out = append(out, dns.Fqdn(sig.SignerName))
		}
	}
	return out
}

// expandedFrom reports whether sig, over records owned by owner, was made
// over a wildcard (RFC 4034 section 3.1.3, RFC 4035 section 5.3.2): its Labels
// field is below the label count of owner, a leading "*" not counted. It
// returns the wildcard.
func expandedFrom(sig *dns.RRSIG, owner string) (string, bool) {
	labels := dns.SplitDomainName(dns.Fqdn(owner))
	n := len(labels)
	if n > 0 && labels[0] == "*" {
		n--
	}
	if int(sig.Labels) >= n {
		return "", false
	}
	if sig.Labels == 0 {
		return "*.", true
	}
	return "*." + dns.Fqdn(strings.Join(labels[len(labels)-int(sig.Labels):], ".")), true
}

// negativeKind names a negative answer by its rcode.
func negativeKind(rcode int) string {
	if rcode == dns.RcodeNameError {
		return "NXDOMAIN"
	}
	return "NODATA"
}

// query asks the chaser's server for name and qtype, with DO set, and with
// CD set: a validator sets CD on its queries (RFC 6840 section 5.9), so that
// the server returns the data it has whatever its own verdict, and the walk
// judges it. A response with an rcode other than NOERROR or NXDOMAIN is an
// error: it says nothing about name, and it must not read as an absence.
func (c *Chaser) query(name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(4096, true)
	m.CheckingDisabled = true
	resp, _, err := c.Client.Exchange(m, c.Server, false)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("nil response")
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return resp, nil
	}
	rcode, ok := dns.RcodeToString[resp.Rcode]
	if !ok {
		rcode = fmt.Sprintf("rcode %d", resp.Rcode)
	}
	return nil, fmt.Errorf("%s", rcode)
}

// ask is query for the leaf, read by owner: the records of qtype name owns,
// or else the CNAME it owns, and the DNAME above it that synthesized that.
func (c *Chaser) ask(name string, qtype uint16) chaseAnswer {
	resp, err := c.query(name, qtype)
	if err != nil {
		return chaseAnswer{err: err}
	}
	ans := chaseAnswer{rcode: resp.Rcode}
	ans.rrs, ans.sigs = ownedRRs(resp.Answer, name, qtype)
	if len(ans.rrs) > 0 || qtype == dns.TypeCNAME {
		return ans
	}
	ans.cname, ans.cnameSigs = ownedRRs(resp.Answer, name, dns.TypeCNAME)
	if len(ans.cname) > 0 {
		ans.dname = dnameSynthesizing(resp.Answer, name, ans.cname[0].(*dns.CNAME).Target)
	}
	return ans
}

// dnameSynthesizing returns the owner of the DNAME in rrs, above name, that
// synthesizes a CNAME from name to target (RFC 6672 section 2.2), or "".
func dnameSynthesizing(rrs []dns.RR, name, target string) string {
	labels := dns.SplitDomainName(dns.Fqdn(name))
	for _, rr := range rrs {
		d, ok := rr.(*dns.DNAME)
		if !ok || core.EqualNames(d.Hdr.Name, name) || !dns.IsSubDomain(d.Hdr.Name, name) {
			continue
		}
		prefix := labels[:len(labels)-dns.CountLabel(d.Hdr.Name)]
		synthesized := strings.Join(prefix, ".") + "." + dns.Fqdn(d.Target)
		if d.Target == "." {
			synthesized = dns.Fqdn(strings.Join(prefix, "."))
		}
		if core.EqualNames(target, synthesized) {
			return d.Hdr.Name
		}
	}
	return ""
}

// ownedRRs returns the records of rrtype that name owns in rrs, and the
// RRSIGs over them that name owns. A response can hold records of the type
// asked for owned by another name -- the target of a CNAME -- and those are
// not the name's.
func ownedRRs(rrs []dns.RR, name string, rrtype uint16) ([]dns.RR, []*dns.RRSIG) {
	var out []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		if rr == nil || !core.EqualNames(rr.Header().Name, name) {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			if sig.TypeCovered == rrtype {
				sigs = append(sigs, sig)
			}
			continue
		}
		if rr.Header().Rrtype == rrtype {
			out = append(out, rr)
		}
	}
	return out, sigs
}

// ownedDS returns the DS records zone owns in rrs, and their RRSIGs.
func ownedDS(rrs []dns.RR, zone string) ([]*dns.DS, []*dns.RRSIG) {
	recs, sigs := ownedRRs(rrs, zone, dns.TypeDS)
	var dss []*dns.DS
	for _, rr := range recs {
		if ds, ok := rr.(*dns.DS); ok {
			dss = append(dss, ds)
		}
	}
	return dss, sigs
}

// ownedDNSKEY returns the DNSKEY records zone owns in rrs, and their RRSIGs.
func ownedDNSKEY(rrs []dns.RR, zone string) ([]*dns.DNSKEY, []*dns.RRSIG) {
	recs, sigs := ownedRRs(rrs, zone, dns.TypeDNSKEY)
	var keys []*dns.DNSKEY
	for _, rr := range recs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys, sigs
}

// zoneCutsFromRoot returns the candidate zone names from "." down to qname,
// one per label: for "www.example.com." it returns [".", "com.",
// "example.com.", "www.example.com."]. Which of them are zone cuts the walk
// works out from what the DS question at each of them gets.
func zoneCutsFromRoot(qname string) []string {
	qname = dns.Fqdn(qname)
	if qname == "." {
		return []string{"."}
	}
	labels := dns.SplitDomainName(qname)
	out := []string{"."}
	for i := len(labels) - 1; i >= 0; i-- {
		out = append(out, dns.Fqdn(strings.Join(labels[i:], ".")))
	}
	return out
}

// dnskeyRRsetForValidator wraps DNSKEY records and their RRSIGs into the
// core.RRset shape expected by cache.ValidateDNSKEYRRsetUsingDS.
func dnskeyRRsetForValidator(zone string, keys []*dns.DNSKEY, sigs []*dns.RRSIG) *core.RRset {
	rrset := &core.RRset{
		Name:   dns.Fqdn(zone),
		Class:  dns.ClassINET,
		RRtype: dns.TypeDNSKEY,
	}
	for _, k := range keys {
		rrset.RRs = append(rrset.RRs, k)
	}
	for _, s := range sigs {
		rrset.RRSIGs = append(rrset.RRSIGs, s)
	}
	return rrset
}

func rrsigsToRRs(sigs []*dns.RRSIG) []dns.RR {
	out := make([]dns.RR, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s)
	}
	return out
}

func worstStatus(a, b ChainStatus) ChainStatus {
	// Severity order: Secure < Insecure < Indeterminate < Bogus.
	// (A Bogus link is the worst-case "you should not trust this";
	// Indeterminate is "we couldn't decide".)
	rank := func(s ChainStatus) int {
		switch s {
		case ChainStatusSecure:
			return 0
		case ChainStatusInsecure:
			return 1
		case ChainStatusIndeterminate:
			return 2
		case ChainStatusBogus:
			return 3
		default:
			return 4
		}
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}
