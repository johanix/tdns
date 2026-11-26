/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Answers synthesized from a wildcard, through the resolver: validated with
 * the proof that the name asked for does not exist, which is kept with the
 * answer and served beside it.
 */
package tdns

import (
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// An answer the resolver takes from a zone the server is authoritative for is
// the server's own data, and is not held to the proof. A zone signed elsewhere
// with NSEC3 and served here as a secondary has no proof to give: the
// authoritative side does not serve NSEC3 (denial.go).
func TestOwnNSEC3ZoneWildcardAnswerValidates(t *testing.T) {
	zd, _ := presignedSecondary(t, func(text string) string {
		return dropRecords("", "NSEC")(text) + "example.\t3600\tIN\tNSEC3PARAM\t1 0 0 -\n"
	})
	if zd.signsHere() {
		t.Fatal("test setup: the secondary signs")
	}
	upLog := &upstreamLog{}
	upAddr, upPort := startLoggedSignedForwardUpstream(t, nil, upLog)
	imr := newForwardTestImrWith(t, ImrEngineConf{Forward: rootForward(upAddr, upPort)}, ImrOptions{OwnZones: hostedZones{}})
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache

	m := askWith(t, imr, "x.wild.example.", dns.TypeTXT, true)
	if m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData || countType(m.Answer, dns.TypeTXT) != 1 {
		t.Errorf("%s AD=%v answer %v; want NOERROR, AD and the TXT", dns.RcodeToString[m.Rcode], m.AuthenticatedData, m.Answer)
	}
	if n := countType(m.Ns, dns.TypeNSEC) + countType(m.Ns, dns.TypeNSEC3); n != 0 {
		t.Errorf("test setup: %d NSEC/NSEC3 in authority; the zone was to send no proof", n)
	}
	requireUpstreamNotAsked(t, upLog, "example.")
}
