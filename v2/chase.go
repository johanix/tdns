/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	algorithms "github.com/johanix/tdns/v2/algorithms"
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
	ParentZone string        // FQDN of the immediate parent zone; "" for root
	DS         []*dns.DS     // DS records seen at the parent for this zone (may be empty for insecure / root)
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
	RRset  *core.RRset
	Status ChainStatus
	Notes  []string
}

// ChainResult is the full structured chase output. Status is the overall
// verdict (worst of any link plus the leaf).
type ChainResult struct {
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
	zones := zoneCutsFromRoot(qname) // root-first
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
	result := &ChainResult{Status: ChainStatusSecure}

	for i, zone := range zones {
		link := ChainLink{Zone: zone}
		if i > 0 {
			link.ParentZone = zones[i-1]
		}

		// Fetch DS from the parent (skip for root).
		if i > 0 {
			ds, dsRRSIGs, err := c.queryDSAtParent(zone)
			if err != nil {
				link.Status = ChainStatusIndeterminate
				link.Notes = append(link.Notes, fmt.Sprintf("DS query failed: %v", err))
				result.Links = append(result.Links, link)
				result.Status = worstStatus(result.Status, ChainStatusIndeterminate)
				continue
			}
			link.DS = ds
			if len(ds) == 0 {
				// No DS at parent — chain is broken or zone is unsigned.
				// Without NSEC/NSEC3 proof support here, we report
				// Indeterminate rather than Insecure. A full proof-of-no-DS
				// walk is a future enhancement.
				link.Status = ChainStatusIndeterminate
				link.Notes = append(link.Notes, "no DS record at parent (and no NSEC proof checked)")
				result.Links = append(result.Links, link)
				result.Status = worstStatus(result.Status, ChainStatusIndeterminate)
				continue
			}
			_ = dsRRSIGs // future: validate DS signature against parent's DNSKEYs
		}

		// Fetch DNSKEY for this zone.
		dnskeys, sigs, err := c.queryDNSKEY(zone)
		if err != nil {
			link.Status = ChainStatusIndeterminate
			link.Notes = append(link.Notes, fmt.Sprintf("DNSKEY query failed: %v", err))
			result.Links = append(result.Links, link)
			result.Status = worstStatus(result.Status, ChainStatusIndeterminate)
			continue
		}
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
				result.Status = worstStatus(result.Status, ChainStatusBogus)
			}
		} else if tas := c.TrustAnchors[zone]; len(tas) > 0 {
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
				result.Status = worstStatus(result.Status, ChainStatusBogus)
			}
		} else {
			// No TA configured for this zone (typically the root).
			// Without a TA we have no way to anchor the chain; report
			// the link as Indeterminate so the overall verdict
			// reflects the missing anchor.
			link.Status = ChainStatusIndeterminate
			link.Notes = append(link.Notes, "no trust anchor configured for this zone")
			result.Status = worstStatus(result.Status, ChainStatusIndeterminate)
		}
		result.Links = append(result.Links, link)
	}

	// Leaf: query the target and verify the RRSIG against the deepest
	// zone's DNSKEY.
	leaf := ChainLeaf{Qname: qname, Qtype: qtype}
	rrs, sigs, err := c.queryRRset(qname, qtype)
	if err != nil {
		leaf.Status = ChainStatusIndeterminate
		leaf.Notes = append(leaf.Notes, fmt.Sprintf("answer query failed: %v", err))
	} else if len(rrs) == 0 {
		leaf.Status = ChainStatusIndeterminate
		leaf.Notes = append(leaf.Notes, "no answer RRs")
	} else {
		leaf.RRset = &core.RRset{
			Name:   qname,
			Class:  dns.ClassINET,
			RRtype: qtype,
			RRs:    rrs,
			RRSIGs: rrsigsToRRs(sigs),
		}
		if len(sigs) == 0 {
			leaf.Status = ChainStatusInsecure
			leaf.Notes = append(leaf.Notes, "no RRSIG present on answer")
		} else if len(result.Links) == 0 || len(result.Links[len(result.Links)-1].DNSKEY) == 0 {
			leaf.Status = ChainStatusIndeterminate
			leaf.Notes = append(leaf.Notes, "no DNSKEY available for deepest zone — cannot verify")
		} else {
			deepest := result.Links[len(result.Links)-1]
			leaf.Status, leaf.Notes = verifyLeafSig(leaf.RRset.RRs, sigs, deepest.DNSKEY, deepest.Zone)
		}
	}
	result.Leaf = leaf
	result.Status = worstStatus(result.Status, leaf.Status)
	return result, nil
}

// queryRRset issues qname/qtype +dnssec against the chaser's server and
// extracts the answer RRs and their RRSIGs.
func (c *Chaser) queryRRset(qname string, qtype uint16) ([]dns.RR, []*dns.RRSIG, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	resp, _, err := c.Client.Exchange(m, c.Server, false)
	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return nil, nil, fmt.Errorf("nil response")
	}
	var rrs []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == qtype {
			sigs = append(sigs, sig)
			continue
		}
		if rr.Header().Rrtype == qtype {
			rrs = append(rrs, rr)
		}
	}
	return rrs, sigs, nil
}

// queryDSAtParent fetches the DS RRset for `zone` (and any RRSIGs).
func (c *Chaser) queryDSAtParent(zone string) ([]*dns.DS, []*dns.RRSIG, error) {
	rrs, sigs, err := c.queryRRset(zone, dns.TypeDS)
	if err != nil {
		return nil, nil, err
	}
	var dss []*dns.DS
	for _, rr := range rrs {
		if ds, ok := rr.(*dns.DS); ok {
			dss = append(dss, ds)
		}
	}
	return dss, sigs, nil
}

// queryDNSKEY fetches the DNSKEY RRset for `zone` (and any RRSIGs).
func (c *Chaser) queryDNSKEY(zone string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	rrs, sigs, err := c.queryRRset(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, nil, err
	}
	var keys []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys, sigs, nil
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
			if dns.Fqdn(sig.SignerName) != dns.Fqdn(zone) {
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

// zoneCutsFromRoot returns the zone names from "." down to qname (the
// closest enclosing zone). E.g. for "p.axfr.net." returns
// [".", "net.", "axfr.net.", "p.axfr.net."]. For a leaf-only query
// where the qname IS a zone apex, the qname is included; for a query
// for a non-zone-apex name like "www.example.com." we cannot know
// without querying, so we conservatively include qname's parent
// (example.com.) as the deepest zone — the caller may want a NS lookup
// to refine this.
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

// algField formats an algorithm number for chain display. When
// algNames is set (dog +algchase), it appends the algorithm's registered
// name, e.g. "alg=214 (CROSSRSDPG128SMALL)" — or "alg=250 (unknown)" for
// a codepoint this binary has no metadata for. Otherwise it is the bare
// "alg=N".
func algField(alg uint8, algNames bool) string {
	if !algNames {
		return fmt.Sprintf("alg=%d", alg)
	}
	name, ok := algorithms.AlgorithmName(alg)
	if !ok {
		name = "unknown"
	}
	return fmt.Sprintf("alg=%d (%s)", alg, name)
}

// RenderChain formats a ChainResult as a human-readable tree on w. When
// algNames is set (dog +algchase), algorithm numbers in the DS and
// DNSKEY summaries are annotated with their registered names.
// Used by `dog sigchase` and (soon) by `imr explain`.
func RenderChain(result *ChainResult, w io.Writer, algNames bool) {
	if result == nil {
		fmt.Fprintln(w, "chain: nil result")
		return
	}
	fmt.Fprintf(w, "Chain validation for %s %s:\n\n", result.Leaf.Qname, dns.TypeToString[result.Leaf.Qtype])
	indent := ""
	for i, link := range result.Links {
		label := link.Zone
		if i == 0 {
			label = ". (root)"
		}
		fmt.Fprintf(w, "%s%s    [%s]\n", indent, label, link.Status)
		// Show DS / DNSKEY / matched-KSK summary
		if len(link.DS) > 0 {
			tags := make([]string, 0, len(link.DS))
			for _, ds := range link.DS {
				tags = append(tags, fmt.Sprintf("keytag=%d %s digest_type=%d", ds.KeyTag, algField(ds.Algorithm, algNames), ds.DigestType))
			}
			sort.Strings(tags)
			fmt.Fprintf(w, "%s   DS at parent:   %s\n", indent, strings.Join(tags, ", "))
		}
		if len(link.DNSKEY) > 0 {
			tags := make([]string, 0, len(link.DNSKEY))
			for _, k := range link.DNSKEY {
				role := "ZSK"
				if k.Flags&257 == 257 {
					role = "KSK"
				}
				tags = append(tags, fmt.Sprintf("%s keytag=%d %s", role, k.KeyTag(), algField(k.Algorithm, algNames)))
			}
			sort.Strings(tags)
			fmt.Fprintf(w, "%s   DNSKEY:         %s\n", indent, strings.Join(tags, ", "))
		}
		if link.MatchedKSK != nil {
			fmt.Fprintf(w, "%s   Matched KSK:    keytag=%d\n", indent, link.MatchedKSK.KeyTag())
		}
		for _, note := range link.Notes {
			fmt.Fprintf(w, "%s   note:           %s\n", indent, note)
		}
		fmt.Fprintln(w)
		indent += "  "
	}
	fmt.Fprintf(w, "%s%s %s    [%s]\n", indent, result.Leaf.Qname, dns.TypeToString[result.Leaf.Qtype], result.Leaf.Status)
	if result.Leaf.RRset != nil {
		for _, rr := range result.Leaf.RRset.RRs {
			fmt.Fprintf(w, "%s   %s\n", indent, rr.String())
		}
	}
	for _, note := range result.Leaf.Notes {
		fmt.Fprintf(w, "%s   note:           %s\n", indent, note)
	}
	fmt.Fprintf(w, "\nResult: %s\n", result.Status)
}
