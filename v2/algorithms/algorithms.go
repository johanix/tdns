// Package algorithms is tdns's runtime registry of DNSSEC signature
// algorithms — the bridge between miekg/dns's algorithm registry and
// the rest of tdns (CLI argument validation, --help text, key
// generation flows). Applications register an algorithm by codepoint
// and capability set; tdns code queries the registry to decide what
// names are valid input and what algorithms appear in --help.
//
// Built-in algorithms (RSASHA*, ECDSAP*, ED25519) are pre-registered
// at this package's init time. Out-of-tree algorithms (typically
// ML-DSA / SLH-DSA / Falcon / MAYO / SNOVA via the
// github.com/johanix/dnssec-algorithms subpackages) are registered
// by the application's main package:
//
//	import (
//	    algs "github.com/johanix/tdns/v2/algorithms"
//	    "github.com/johanix/dnssec-algorithms/mldsa44"
//	)
//
//	func init() {
//	    algs.Register(199, mldsa44.New(),
//	        algs.Capabilities{ForSIG0: true, ForDNSSEC: false})
//	}
//
// Applications that handle algorithm names but don't sign/verify
// themselves (cliv2 talking to a server) use [RegisterMetadata]
// instead — same name+codepoint+capability tracking without
// importing a heavyweight algorithm implementation.
package algorithms

import (
	"fmt"
	"sort"
	"sync"

	"github.com/miekg/dns"
)

// Capabilities describes how an algorithm may be used.
type Capabilities struct {
	// ForSIG0 means the algorithm is accepted for SIG(0) transaction
	// signing — KEY rdata, SIG(0) message authentication.
	ForSIG0 bool

	// ForDNSSEC means the algorithm is accepted for DNSSEC zone
	// signing — DNSKEY rdata, RRSIG over RRsets.
	ForDNSSEC bool
}

type entry struct {
	number uint8
	name   string
	caps   Capabilities
}

var (
	mu        sync.RWMutex
	byNumber  = map[uint8]entry{}
	byName    = map[string]uint8{}
)

// Register wires impl into miekg/dns's algorithm registry at the
// given codepoint and records the capability set so tdns code can
// query it. Panics on conflict (init-time pattern — the application
// must resolve duplicate codepoints itself).
func Register(num uint8, impl dns.Algorithm, caps Capabilities) {
	if err := dns.RegisterAlgorithm(num, impl); err != nil {
		panic(fmt.Sprintf("algorithms.Register(%d, %s): %v",
			num, impl.Name(), err))
	}
	registerMetadata(num, impl.Name(), caps)
}

// RegisterMetadata records an algorithm's codepoint, name, and
// capabilities without touching miekg/dns's registry. Used by
// binaries that only need name-aware UI (e.g. CLI argument
// validation, --help text) but don't sign or verify with the
// algorithm themselves. Panics on conflict.
func RegisterMetadata(num uint8, name string, caps Capabilities) {
	registerMetadata(num, name, caps)
}

func registerMetadata(num uint8, name string, caps Capabilities) {
	mu.Lock()
	defer mu.Unlock()
	if existing, ok := byNumber[num]; ok {
		panic(fmt.Sprintf("algorithms: codepoint %d already registered (was %s)",
			num, existing.name))
	}
	if existing, ok := byName[name]; ok {
		panic(fmt.Sprintf("algorithms: name %q already registered (was %d)",
			name, existing))
	}
	byNumber[num] = entry{number: num, name: name, caps: caps}
	byName[name] = num
}

// AlgorithmNumber returns the DNSSEC algorithm number registered for
// name, or 0, false if name is unknown. name is case-sensitive — the
// canonical form is the uppercase string the algorithm registered
// itself with (e.g. "MLDSA44").
func AlgorithmNumber(name string) (uint8, bool) {
	mu.RLock()
	defer mu.RUnlock()
	num, ok := byName[name]
	return num, ok
}

// AlgorithmName returns the registered name for codepoint num, or
// "", false if no algorithm is registered at that codepoint.
func AlgorithmName(num uint8) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := byNumber[num]
	if !ok {
		return "", false
	}
	return e.name, true
}

// Caps returns the capability set registered for codepoint num, or
// zero-value + false if num is unknown.
func Caps(num uint8) (Capabilities, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := byNumber[num]
	if !ok {
		return Capabilities{}, false
	}
	return e.caps, true
}

// SupportedSIG0 returns the names of all registered algorithms whose
// capabilities permit SIG(0) use, sorted by codepoint.
func SupportedSIG0() []string {
	return supportedWhere(func(c Capabilities) bool { return c.ForSIG0 })
}

// SupportedDNSSEC returns the names of all registered algorithms
// whose capabilities permit DNSSEC zone signing, sorted by
// codepoint.
func SupportedDNSSEC() []string {
	return supportedWhere(func(c Capabilities) bool { return c.ForDNSSEC })
}

func supportedWhere(pred func(Capabilities) bool) []string {
	mu.RLock()
	defer mu.RUnlock()
	matching := make([]entry, 0, len(byNumber))
	for _, e := range byNumber {
		if pred(e.caps) {
			matching = append(matching, e)
		}
	}
	sort.Slice(matching, func(i, j int) bool {
		return matching[i].number < matching[j].number
	})
	out := make([]string, len(matching))
	for i, e := range matching {
		out[i] = e.name
	}
	return out
}

// init pre-registers the algorithms built into miekg/dns. They aren't
// reachable through the Algorithm interface (built-ins use the
// per-algorithm switch arms, not the registry), but tdns code needs
// to know they exist for argument validation and --help output.
func init() {
	for _, b := range []struct {
		num  uint8
		name string
		caps Capabilities
	}{
		{dns.RSASHA256, "RSASHA256", Capabilities{ForSIG0: true, ForDNSSEC: true}},
		{dns.RSASHA512, "RSASHA512", Capabilities{ForSIG0: true, ForDNSSEC: true}},
		{dns.ECDSAP256SHA256, "ECDSAP256SHA256", Capabilities{ForSIG0: true, ForDNSSEC: true}},
		{dns.ECDSAP384SHA384, "ECDSAP384SHA384", Capabilities{ForSIG0: true, ForDNSSEC: true}},
		{dns.ED25519, "ED25519", Capabilities{ForSIG0: true, ForDNSSEC: true}},
	} {
		registerMetadata(b.num, b.name, b.caps)
	}
}
