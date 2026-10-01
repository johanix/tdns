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

// ChainResult is the full structured chase output. Status is the overall
// verdict (worst of any link plus the leaf).
type ChainResult struct {
	Qname             string      // the name asked for
	Qtype             uint16      // the type asked for
	TrustAnchorSource string      // where the trust anchors came from (Chaser.TrustAnchorSource), or "none"
	Links             []ChainLink // root-first, leaf zone last
	Leaf              ChainLeaf
	Status            ChainStatus
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
		name := dns.Fqdn(ds.Hdr.Name)
		tas[name] = append(tas[name], ds)
	}
	return &Chaser{Client: client, Server: server, TrustAnchors: tas}
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
	links, leaf := w.walkName(qname, qtype)
	result := &ChainResult{Qname: qname, Qtype: qtype, TrustAnchorSource: c.TrustAnchorSource,
		Leaf: leaf, Status: ChainStatusSecure}
	if result.TrustAnchorSource == "" && len(c.TrustAnchors) == 0 {
		result.TrustAnchorSource = "none"
	}
	for _, link := range links {
		result.Links = append(result.Links, *link)
		result.Status = worstStatus(result.Status, link.Status)
	}
	result.Status = worstStatus(result.Status, leaf.Status)
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
	rrs   []dns.RR     // records of the type asked for
	sigs  []*dns.RRSIG // the RRSIGs over them
	rcode int          // NOERROR or NXDOMAIN
	err   error        // the query failed: no response, or another rcode
}

// walkName asks for name and qtype, walks the zone cuts from the root down to
// name, and judges the answer against the deepest of them.
//
// The answer is asked for first: what the name owns tells which candidates
// can be zone cuts at all.
func (w *chainWalk) walkName(name string, qtype uint16) ([]*ChainLink, ChainLeaf) {
	ans := w.c.ask(name, qtype)
	zones := zoneCutsFromRoot(name) // root-first
	// DS records live at the PARENT zone, not at qname's own zone. So
	// for a DS leaf query, drop qname from the zone chain — the parent
	// becomes the deepest validated zone, and the leaf RRset is then
	// verified against that parent's DNSKEYs (whose ZSK signed the DS).
	// Without this, the chaser would try to fetch DS for qname itself
	// (a redundant second wire query to fetch what the leaf will get),
	// and even on success would attempt leaf verification against the
	// child zone's DNSKEYs — which never signed the DS.
	if qtype == dns.TypeDS && len(zones) > 1 {
		zones = zones[:len(zones)-1]
	}
	links := w.links(zones)
	return links, w.judgeLeaf(name, qtype, ans, links)
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
		if insecure && len(w.c.TrustAnchors[zone]) == 0 {
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
	if d.link != nil && above != nil && len(w.c.TrustAnchors[zone]) == 0 {
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
	if zone != "." && len(w.c.TrustAnchors[zone]) == 0 {
		resp, err := w.c.query(zone, dns.TypeDS)
		if err != nil {
			link.Status = ChainStatusIndeterminate
			link.Notes = append(link.Notes, fmt.Sprintf("DS query failed: %v", err))
			return &cutDecision{link: link}
		}
		ds, dsSigs := ownedDS(resp.Answer, zone)
		if len(ds) == 0 {
			// No DS at parent. Two very different cases:
			//
			//   (a) `zone` is not a zone cut at all — just a label
			//       boundary within the parent (e.g. www.iis.se, which
			//       has no NS/SOA of its own). It must NOT appear in the
			//       chain: the queried leaf is served from the enclosing
			//       zone, and its RRSIG validates against THAT zone's
			//       keys. Skip this candidate entirely, leaving the
			//       previous (real) zone as the deepest.
			//
			//   (b) `zone` is a genuine delegation with no DS — an
			//       unsigned/insecure child. Without NSEC/NSEC3 proof
			//       support here we report Indeterminate rather than
			//       Insecure (a full proof-of-no-DS walk is future work).
			cut, cutErr := w.c.isZoneCut(zone)
			if cutErr == nil && !cut {
				return &cutDecision{} // case (a): confirmed non-cut, drop it
			}
			// Case (b), or the zone-cut check itself failed: keep the
			// candidate on the Indeterminate path. A lookup failure must
			// not be mistaken for a non-cut (which would silently drop a
			// possibly-real delegation), so we do NOT skip on error.
			link.Status = ChainStatusIndeterminate
			if cutErr != nil {
				link.Notes = append(link.Notes, fmt.Sprintf("no DS at parent; zone-cut check failed: %v", cutErr))
			} else {
				link.Notes = append(link.Notes, "no DS record at parent (and no NSEC proof checked)")
			}
			return &cutDecision{link: link}
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
	} else if tas := w.c.TrustAnchors[zone]; len(tas) > 0 {
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
// chain.
func (w *chainWalk) judgeLeaf(name string, qtype uint16, ans chaseAnswer, chain []*ChainLink) ChainLeaf {
	leaf := ChainLeaf{Qname: name, Qtype: qtype, Rcode: ans.rcode}
	switch {
	case ans.err != nil:
		leaf.Status = ChainStatusIndeterminate
		leaf.Notes = append(leaf.Notes, fmt.Sprintf("answer query failed: %v", ans.err))
		return leaf
	case len(ans.rrs) == 0:
		leaf.Status = ChainStatusIndeterminate
		leaf.Notes = append(leaf.Notes, fmt.Sprintf("no answer RRs (%s)", negativeKind(ans.rcode)))
		return leaf
	}
	leaf.RRset = &core.RRset{
		Name:   name,
		Class:  dns.ClassINET,
		RRtype: qtype,
		RRs:    ans.rrs,
		RRSIGs: rrsigsToRRs(ans.sigs),
	}
	switch {
	case len(ans.sigs) == 0:
		leaf.Status = ChainStatusInsecure
		leaf.Notes = append(leaf.Notes, "no RRSIG present on answer")
	case len(chain) == 0 || len(chain[len(chain)-1].DNSKEY) == 0:
		leaf.Status = ChainStatusIndeterminate
		leaf.Notes = append(leaf.Notes, "no DNSKEY available for deepest zone — cannot verify")
	default:
		deepest := chain[len(chain)-1]
		leaf.Status, leaf.Notes = verifyLeafSig(leaf.RRset.RRs, ans.sigs, deepest.DNSKEY, deepest.Zone)
	}
	return leaf
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

// ask is query for the leaf, read by owner.
func (c *Chaser) ask(name string, qtype uint16) chaseAnswer {
	resp, err := c.query(name, qtype)
	if err != nil {
		return chaseAnswer{err: err}
	}
	rrs, sigs := ownedRRs(resp.Answer, name, qtype)
	return chaseAnswer{rrs: rrs, sigs: sigs, rcode: resp.Rcode}
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

// isZoneCut reports whether name is an actual zone apex — i.e. a
// delegation point — rather than merely a label boundary within a zone.
// A candidate like "www.iis.se" is NOT a zone cut: it has no NS/SOA of its
// own, so it must not be treated as a zone in the chase (doing so invents
// a phantom zone with no DS/DNSKEY and derails validation of the leaf,
// which is actually served from the enclosing zone). A cut exists when the
// name has an SOA (its own apex) or NS records (a delegation).
//
// The returned error distinguishes "definitely not a cut" (false, nil)
// from "could not determine" (false, err): a transient SOA/NS lookup
// failure must NOT be mistaken for a non-cut, or a real delegation could
// be silently dropped. The caller keeps such a candidate on the
// Indeterminate path instead of skipping it.
func (c *Chaser) isZoneCut(name string) (bool, error) {
	if ans := c.ask(name, dns.TypeSOA); ans.err != nil {
		return false, ans.err
	} else if len(ans.rrs) > 0 {
		return true, nil
	}
	if ans := c.ask(name, dns.TypeNS); ans.err != nil {
		return false, ans.err
	} else if len(ans.rrs) > 0 {
		return true, nil
	}
	return false, nil
}

// verifyLeafSig verifies the answer RRset's RRSIG against the deepest
// zone's DNSKEY RRset. Tries each (sig, key) pair until one validates,
// then returns Secure. If a sig was present but no key verified, returns
// Bogus. Otherwise Indeterminate.
func verifyLeafSig(rrs []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, zone string) (ChainStatus, []string) {
	var notes []string
	for _, sig := range sigs {
		for _, key := range keys {
			if sig.KeyTag != key.KeyTag() {
				continue
			}
			if !core.EqualNames(dns.Fqdn(sig.SignerName), dns.Fqdn(zone)) {
				continue
			}
			if err := sig.Verify(key, rrs); err != nil {
				notes = append(notes, fmt.Sprintf("sig keytag=%d verify failed: %v", sig.KeyTag, err))
				continue
			}
			if !cache.WithinValidityPeriod(sig.Inception, sig.Expiration, time.Now().UTC()) {
				notes = append(notes, fmt.Sprintf("sig keytag=%d outside validity window (inception=%d expiration=%d)", sig.KeyTag, sig.Inception, sig.Expiration))
				continue
			}
			notes = append(notes, fmt.Sprintf("sig keytag=%d verified", sig.KeyTag))
			return ChainStatusSecure, notes
		}
	}
	if len(sigs) > 0 {
		return ChainStatusBogus, notes
	}
	return ChainStatusIndeterminate, append(notes, "no usable signatures")
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
