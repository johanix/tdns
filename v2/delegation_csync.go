/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The parent's half of RFC 7477 CSYNC processing, as free functions.
//
// This is the NS/glue acceptance logic that used to live inline in the
// scanner's ProcessCSYNCNotify (D-3b of the ddns/keystate alignment plan).
// draft-ietf-dnsop-delegation-mgmt-via-ddns-02 §"Processing the UPDATE"
// requires a delegation change that arrives by DNS UPDATE to pass the same
// checks a CSYNC scanner would run, so the rules have to exist somewhere
// both callers can reach. The scanner is still the only caller; wiring the
// UPDATE path is the next change, and it is kept separate so this one is
// reviewable purely against "the scanner behaves identically".
//
// Everything that touches the network is injected (childRRsetFetcher), and
// everything that touches the parent's stored delegation is injected
// (currentGlueLookup), in the style of delegation_coherence.go's dnskeyFetcher.
// The log lines keep their ProcessCSYNCNotify prefix on purpose: this IS that
// function's body, and operators grep for it.

// childRRsetFetcher answers what the child's nameservers serve at (name,
// qtype): the RRset (nil or empty when there is none) and whether every
// nameserver that answered agreed. The scanner backs it with
// queryAllNSAndCompare; tests with a map.
type childRRsetFetcher func(ctx context.Context, name string, qtype uint16) (rrs []dns.RR, allInSync bool, err error)

// currentGlueLookup returns the glue RRset of qtype the parent currently
// publishes at owner, and whether the delegation data holds an entry for it at
// all. present is what decides whether removing an NS reports a glue change --
// an entry that exists but is empty still counts, as it always has.
type currentGlueLookup func(owner string, qtype uint16) (rrs []dns.RR, present bool)

// RFC 7477 §2.1.1.2: the two defined CSYNC flag bits.
const (
	csyncFlagImmediate  uint16 = 0x01
	csyncFlagSoaMinimum uint16 = 0x02
)

// errCsyncNotImmediate: tdns only implements immediate processing (RFC 7477
// §3.1 leaves the non-immediate schedule to the parent, and there is none).
var errCsyncNotImmediate = errors.New("CSYNC immediate flag not set, only immediate updates supported")

// csyncFlags returns the two defined flags, refusing a record that sets any
// other (RFC 7477 §2.1.1.2: a parent MUST NOT process a CSYNC with unknown
// flags).
func csyncFlags(c *dns.CSYNC) (immediate, useSoaMinimum bool, err error) {
	if c.Flags & ^(csyncFlagImmediate|csyncFlagSoaMinimum) != 0 {
		return false, false, fmt.Errorf("unknown CSYNC flags: 0x%04x", c.Flags)
	}
	return c.Flags&csyncFlagImmediate != 0, c.Flags&csyncFlagSoaMinimum != 0, nil
}

// csyncSuppressedBySoaMinimum implements the soaminimum flag (RFC 7477
// §2.1.1.2.1): with it set, a CSYNC whose serial is above the child's current
// SOA serial is not to be processed yet.
func csyncSuppressedBySoaMinimum(useSoaMinimum bool, c *dns.CSYNC, soaSerial uint32) bool {
	return useSoaMinimum && c.Serial > soaSerial
}

// csyncTypes is the CSYNC type bitmap in processing order: NS always first
// (RFC 7477 §3.2.1 -- glue depends on the NS set), then the rest as listed.
// NS is processed whether or not the bitmap names it, as it always has been.
func csyncTypes(c *dns.CSYNC) []uint16 {
	types := []uint16{dns.TypeNS}
	for _, t := range c.TypeBitMap {
		if t == dns.TypeNS {
			continue
		}
		types = append(types, t)
	}
	return types
}

// inBailiwickNSNames returns the names of the nameservers in nsRRs that lie
// inside zone -- the ones whose addresses the parent must carry as glue.
func inBailiwickNSNames(zone string, nsRRs []dns.RR) []string {
	var names []string
	for _, rr := range nsRRs {
		if ns, ok := rr.(*dns.NS); ok && NSInBailiwick(zone, ns) {
			names = append(names, ns.Ns)
		}
	}
	return names
}

func canonicalNameSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[core.CanonicalizeName(dns.Fqdn(n))] = true
	}
	return set
}

// csyncDelta is the change to the parent's delegation that processing a CSYNC
// implies: NS at the child's apex, glue at the in-bailiwick nameservers' names.
type csyncDelta struct {
	NSAdds, NSRemoves     []dns.RR
	GlueAdds, GlueRemoves []dns.RR
	Changed               bool
}

// computeCsyncDelta runs RFC 7477 §3.2 for the parent: for each type in
// processing order, compare what the child serves with what the parent
// publishes.
//
//   - NS: the child's apex NS RRset replaces the parent's. A fetch error, a
//     disagreement between the child's nameservers, or an empty RRset is
//     terminal (RFC 7477 §3.2.1 rejects an empty NS RRset).
//   - A / AAAA: glue only for nameservers inside the child zone, per
//     nameserver of the resulting NS set. A glue fetch that fails or on which
//     the child's nameservers disagree skips THAT nameserver and continues;
//     a nameserver no longer in the NS set has its stored glue removed.
//   - anything else in the bitmap is ignored.
//
// currentNS is the NS RRset the parent publishes for the child now. The glue
// pass falls back to it when the child's NS could not be determined, which the
// only current caller never produces: csyncTypes always puts NS in the list
// and first, so by the time a glue pass runs the NS pass has either populated
// the set or returned terminally. The fallback is kept because that invariant
// belongs to csyncTypes, not to this function -- a caller that assembles its
// own type list (step 2 will) does not inherit it.
func computeCsyncDelta(ctx context.Context, childZone string, types []uint16, currentNS []dns.RR,
	currentGlue currentGlueLookup, fetch childRRsetFetcher, lg *log.Logger, verbose, debug bool) (csyncDelta, error) {

	// The scanner always passes a logger, but this is a free function now and
	// the next caller is a different subsystem. Defaulting costs one line and
	// turns "forgot the logger" from a panic in the middle of a delegation
	// decision into silence.
	if lg == nil {
		lg = log.New(io.Discard, "", 0)
	}

	var d csyncDelta
	var newNSRRs []dns.RR // populated by the NS pass, used by the glue passes

	for _, t := range types {
		switch t {
		case dns.TypeNS:
			childNS, nsInSync, err := fetch(ctx, childZone, dns.TypeNS)
			if err != nil {
				lg.Printf("ProcessCSYNCNotify: %s: error querying NS: %v", childZone, err)
				return csyncDelta{}, fmt.Errorf("error querying NS: %v", err)
			}
			if !nsInSync {
				lg.Printf("ProcessCSYNCNotify: %s: child NS not in sync for NS RRset, aborting", childZone)
				return csyncDelta{}, errors.New("child nameservers not in sync for NS")
			}
			if len(childNS) == 0 {
				lg.Printf("ProcessCSYNCNotify: %s: empty NS RRset from child, rejecting per RFC 7477", childZone)
				return csyncDelta{}, errors.New("empty NS RRset from child, rejected")
			}
			newNSRRs = childNS

			changed, adds, removes := core.RRsetDiffer(childZone, newNSRRs, currentNS, dns.TypeNS, lg, verbose, debug)
			if changed {
				d.NSAdds, d.NSRemoves = adds, removes
				d.Changed = true
				lg.Printf("ProcessCSYNCNotify: %s: NS changed: %d adds, %d removes", childZone, len(adds), len(removes))
			} else {
				lg.Printf("ProcessCSYNCNotify: %s: NS unchanged", childZone)
			}

		case dns.TypeA, dns.TypeAAAA:
			typeStr := dns.TypeToString[t]

			effectiveNS := newNSRRs
			if len(effectiveNS) == 0 {
				effectiveNS = currentNS
			}
			newInBailiwick := inBailiwickNSNames(childZone, effectiveNS)
			oldInBailiwick := inBailiwickNSNames(childZone, currentNS)
			newNSSet := canonicalNameSet(newInBailiwick)
			oldNSSet := canonicalNameSet(oldInBailiwick)

			// Every in-bailiwick nameserver of the resulting NS set: glue from the child.
			for _, nsName := range newInBailiwick {
				nsCanon := core.CanonicalizeName(dns.Fqdn(nsName))

				newGlue, glueInSync, err := fetch(ctx, nsName, t)
				if err != nil {
					lg.Printf("ProcessCSYNCNotify: %s: error querying %s for %s: %v", childZone, typeStr, nsName, err)
					continue
				}
				if !glueInSync {
					lg.Printf("ProcessCSYNCNotify: %s: child NS not in sync for %s %s, skipping", childZone, nsName, typeStr)
					continue
				}

				if oldNSSet[nsCanon] {
					// Nameserver kept: diff its glue against what the parent holds.
					current, _ := currentGlue(nsName, t)
					changed, adds, removes := core.RRsetDiffer(nsName, newGlue, current, t, lg, verbose, debug)
					if changed {
						d.GlueAdds = append(d.GlueAdds, adds...)
						d.GlueRemoves = append(d.GlueRemoves, removes...)
						d.Changed = true
						lg.Printf("ProcessCSYNCNotify: %s: %s glue for %s changed: %d adds, %d removes", childZone, typeStr, nsName, len(adds), len(removes))
					}
				} else if len(newGlue) > 0 {
					// Nameserver new: all of its glue is an add.
					d.GlueAdds = append(d.GlueAdds, newGlue...)
					d.Changed = true
					lg.Printf("ProcessCSYNCNotify: %s: new NS %s, adding %d %s glue records", childZone, nsName, len(newGlue), typeStr)
				}
			}

			// Nameserver gone from the NS set: whatever glue the parent holds for it goes.
			for _, nsName := range oldInBailiwick {
				if newNSSet[core.CanonicalizeName(dns.Fqdn(nsName))] {
					continue
				}
				if glue, present := currentGlue(nsName, t); present {
					d.GlueRemoves = append(d.GlueRemoves, glue...)
					d.Changed = true
					lg.Printf("ProcessCSYNCNotify: %s: removed NS %s, removing %d %s glue records", childZone, nsName, len(glue), typeStr)
				}
			}

		default:
			lg.Printf("ProcessCSYNCNotify: %s: unknown RR type %s in CSYNC bitmap, skipping", childZone, dns.TypeToString[t])
		}
	}
	return d, nil
}
