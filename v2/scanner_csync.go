/*
 * (c) Copyright Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"sync"

	core "github.com/johanix/tdns/v2/core"
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

// csyncProcessed holds, per child and per nameserver of the child, the serial
// of the last CSYNC processed from that nameserver, so that an older one is
// not processed again (RFC 7477 §3.1). Per nameserver, because the serial
// field may differ between the nameservers of one child (RFC 9975 §3.2): the
// serial one of them serves says nothing about the serial of another.
//
// Every scan runs in its own goroutine, so every access holds the lock.
// Concurrent writes to a Go map are a fatal runtime error that recover() does
// not catch: without the lock, a few children sending NOTIFY(CSYNC) at once
// could kill the server. The lock makes each access safe; it does not stop two
// overlapping scans of the same child from both processing one CSYNC.
var csyncProcessed = struct {
	sync.Mutex
	serials map[string]map[string]uint32 // child, then nameserver
}{serials: map[string]map[string]uint32{}}

func csyncProcessedKey(zone string) string { return core.CanonicalizeName(dns.Fqdn(zone)) }

// csyncProcessedSerial returns the serial of the last CSYNC processed for zone
// from nameserver ns.
func csyncProcessedSerial(zone, ns string) (uint32, bool) {
	csyncProcessed.Lock()
	defer csyncProcessed.Unlock()
	serial, ok := csyncProcessed.serials[csyncProcessedKey(zone)][csyncProcessedKey(ns)]
	return serial, ok
}

// recordCsyncProcessed remembers the serials of the CSYNC processed for zone,
// by the nameserver each came from. It replaces what was remembered for zone:
// a nameserver the CSYNC did not come from this time is forgotten, and the
// next CSYNC it serves is judged as its first.
func recordCsyncProcessed(zone string, serials map[string]uint32) {
	byNS := make(map[string]uint32, len(serials))
	for ns, serial := range serials {
		byNS[csyncProcessedKey(ns)] = serial
	}
	csyncProcessed.Lock()
	defer csyncProcessed.Unlock()
	csyncProcessed.serials[csyncProcessedKey(zone)] = byNS
}

// ZoneCSYNCKnown reports whether a CSYNC with a higher serial than csyncrr's
// has already been processed for zone from nameserver ns. The same serial is
// processed again.
func (scanner *Scanner) ZoneCSYNCKnown(zone, ns string, csyncrr *dns.CSYNC) bool {
	lg.Debug("ZoneCSYNCKnown: checking if CSYNC is known", "zone", zone, "nameserver", ns)
	last, ok := csyncProcessedSerial(zone, ns)
	return ok && last > csyncrr.Serial
}
