/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"io"
	"sort"
	"strings"

	algorithms "github.com/johanix/tdns/v2/algorithms"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

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
	qname, qtype := result.Qname, result.Qtype
	if qname == "" {
		qname, qtype = result.Leaf.Qname, result.Leaf.Qtype
	}
	if result.TrustAnchorSource != "" {
		fmt.Fprintf(w, "Trust anchor: %s\n", result.TrustAnchorSource)
	}
	fmt.Fprintf(w, "Chain validation for %s %s:\n\n", qname, dns.TypeToString[qtype])
	shown := map[string]bool{}
	hops := append(append([]ChainHop{}, result.Aliases...), ChainHop{Links: result.Links, Leaf: result.Leaf})
	for i, hop := range hops {
		if i > 0 {
			fmt.Fprintf(w, "\nCNAME target %s %s:\n\n", hop.Leaf.Qname, dns.TypeToString[qtype])
		}
		renderHop(w, hop, shown, algNames)
	}
	fmt.Fprintf(w, "\nResult: %s\n", result.Status)
}

// renderHop prints the chain of one name of a CNAME chain, and its leaf.
// Links printed for an earlier name are not repeated: the deepest of them is
// one line, marked "(as above)", and the new links follow it.
func renderHop(w io.Writer, hop ChainHop, shown map[string]bool, algNames bool) {
	lastShown := -1
	for i, link := range hop.Links {
		if shown[core.CanonicalizeName(link.Zone)] {
			lastShown = i
		}
	}
	indent := ""
	for i, link := range hop.Links {
		switch {
		case i < lastShown:
		case i == lastShown:
			fmt.Fprintf(w, "%s%s    [%s]    (as above)\n\n", indent, linkLabel(link), link.Status)
		default:
			renderLink(w, link, indent, algNames)
			shown[core.CanonicalizeName(link.Zone)] = true
		}
		indent += "  "
	}
	renderLeaf(w, hop.Leaf, indent)
}

// linkLabel is how a link is named in the output.
func linkLabel(link ChainLink) string {
	if link.Zone == "." {
		return ". (root)"
	}
	return link.Zone
}

// renderLink prints one link of the chain, its DS, DNSKEY and notes.
func renderLink(w io.Writer, link ChainLink, indent string, algNames bool) {
	fmt.Fprintf(w, "%s%s    [%s]\n", indent, linkLabel(link), link.Status)
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
}

// renderLeaf prints the answer: its records and notes.
func renderLeaf(w io.Writer, leaf ChainLeaf, indent string) {
	fmt.Fprintf(w, "%s%s %s    [%s]\n", indent, leaf.Qname, dns.TypeToString[leaf.Qtype], leaf.Status)
	if leaf.RRset != nil {
		for _, rr := range leaf.RRset.RRs {
			fmt.Fprintf(w, "%s   %s\n", indent, rr.String())
		}
	}
	for _, rr := range leaf.Proof {
		fmt.Fprintf(w, "%s   %s\n", indent, rr.String())
	}
	for _, note := range leaf.Notes {
		fmt.Fprintf(w, "%s   note:           %s\n", indent, note)
	}
}
