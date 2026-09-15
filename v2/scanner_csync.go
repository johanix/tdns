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

// csyncProcessed holds, per child, the serial of the last CSYNC processed, so
// that an older one is not processed again (RFC 7477 §3.1).
//
// Every scan runs in its own goroutine, so every access holds the lock.
// Concurrent writes to a Go map are a fatal runtime error that recover() does
// not catch: without the lock, a few children sending NOTIFY(CSYNC) at once
// could kill the server. The lock makes each access safe; it does not stop two
// overlapping scans of the same child from both processing one CSYNC.
var csyncProcessed = struct {
	sync.Mutex
	serials map[string]uint32
}{serials: map[string]uint32{}}

func csyncProcessedKey(zone string) string { return core.CanonicalizeName(dns.Fqdn(zone)) }

// csyncProcessedSerial returns the serial of the last CSYNC processed for zone.
func csyncProcessedSerial(zone string) (uint32, bool) {
	csyncProcessed.Lock()
	defer csyncProcessed.Unlock()
	serial, ok := csyncProcessed.serials[csyncProcessedKey(zone)]
	return serial, ok
}

// recordCsyncProcessed remembers that the CSYNC with serial was processed for
// zone.
func recordCsyncProcessed(zone string, serial uint32) {
	csyncProcessed.Lock()
	defer csyncProcessed.Unlock()
	csyncProcessed.serials[csyncProcessedKey(zone)] = serial
}

// ZoneCSYNCKnown reports whether a CSYNC with a higher serial than csyncrr's
// has already been processed for zone. The same serial is processed again.
func (scanner *Scanner) ZoneCSYNCKnown(zone string, csyncrr *dns.CSYNC) bool {
	lg.Debug("ZoneCSYNCKnown: checking if CSYNC is known", "zone", zone)
	last, ok := csyncProcessedSerial(zone)
	return ok && last > csyncrr.Serial
}
