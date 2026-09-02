/*
 * (c) Copyright Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"github.com/miekg/dns"
)

// What is left of the original CSYNC scanner: the in-bailiwick test and the
// per-zone "already processed" serial memory, both used by
// ProcessCSYNCNotify (scanner.go) via the extracted rules in
// delegation_csync.go. The earlier CheckCSYNC / CsyncAnalyze{NS,A,AAAA}
// path, which queried a single server through AuthQueryNG and had no callers,
// is gone.

// NSInBailiwick reports whether a nameserver name lies inside zone, and so
// needs glue.
//
// dns.IsSubDomain, not strings.HasSuffix: the latter compares bytes, so it is
// case-sensitive and blind to label boundaries -- it called ns.evilexample. in
// bailiwick for example., which on the CSYNC path meant looking for glue that
// does not exist and treating a sibling's nameserver as ours.
func NSInBailiwick(zone string, ns *dns.NS) bool {
	return dns.IsSubDomain(zone, ns.Ns)
}

// Check the minsoa in this CSYNC against the minsoa in the possible
// already stored CSYNC in the CsyncStatus table. If not found or old min_soa
// is lower, then update table.
var KnownCsyncMinSOAs = map[string]uint32{}

func (scanner *Scanner) ZoneCSYNCKnown(zone string, csyncrr *dns.CSYNC) bool {
	lg.Debug("ZoneCSYNCKnown: checking if CSYNC is known", "zone", zone)
	new_minsoa := csyncrr.Serial
	var old_minsoa uint32
	var ok bool

	if old_minsoa, ok = KnownCsyncMinSOAs[zone]; !ok {
		// This CSYNC is not previously known
		return false
	} else {
		return old_minsoa > new_minsoa
	}
	// unreachable: return true
}
