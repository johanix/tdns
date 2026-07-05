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
	// signing — DNSKEY rdata, RRSIG over RRsets. It is the umbrella
	// capability; ForKSK and ForZSK refine which zone-signing role(s)
	// the algorithm may fill.
	ForDNSSEC bool

	// ForKSK means the algorithm may be used as a Key Signing Key;
	// ForZSK means it may be used as a Zone Signing Key. They refine
	// ForDNSSEC: an algorithm whose signature is small enough to sit on
	// every RRSIG is ForZSK; one whose signature is only tolerable in
	// the (occasional, TCP/DoT) DNSKEY response — e.g. a code-based
	// signature of several KiB — is ForKSK but not ForZSK. Both are
	// meaningless unless ForDNSSEC is set. A classical algorithm is
	// typically {ForDNSSEC, ForKSK, ForZSK} all true.
	ForKSK bool
	ForZSK bool
}

type entry struct {
	number uint8
	name   string
	caps   Capabilities
	// real is true when a genuine implementation was wired into
	// miekg/dns via Register, false for metadata-only entries
	// (RegisterMetadata). Only real algorithms can actually generate,
	// sign, or verify; metadata entries exist so name-aware UI can
	// recognize a codepoint the binary itself cannot use.
	real bool
}

var (
	mu       sync.RWMutex
	byNumber = map[uint8]entry{}
	byName   = map[string]uint8{}
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
	record(num, impl.Name(), caps, true)
}

// RegisterMetadata records an algorithm's codepoint, name, and
// capabilities without touching miekg/dns's registry. Used by
// binaries that only need name-aware UI (e.g. CLI argument
// validation, --help text) but don't sign or verify with the
// algorithm themselves. Panics on conflict.
func RegisterMetadata(num uint8, name string, caps Capabilities) {
	record(num, name, caps, false)
}

func record(num uint8, name string, caps Capabilities, real bool) {
	mu.Lock()
	defer mu.Unlock()

	if existing, ok := byNumber[num]; ok {
		// The codepoint is already known. The one legitimate case is
		// promotion: a metadata-only entry (RegisterMetadata) being
		// upgraded to a real one when the implementation is later wired
		// in via Register — the common shape once every app carries the
		// full metadata table and additionally links some impls. The
		// name and capabilities must agree; a disagreement is a genuine
		// bug, and two real registrations of one codepoint always are.
		if existing.name != name {
			panic(fmt.Sprintf("algorithms: codepoint %d already registered as %q, cannot re-register as %q",
				num, existing.name, name))
		}
		if existing.real && real {
			panic(fmt.Sprintf("algorithms: codepoint %d (%s) already has a real implementation registered",
				num, name))
		}
		if existing.caps != caps {
			panic(fmt.Sprintf("algorithms: codepoint %d (%s) capability mismatch between metadata and implementation registration",
				num, name))
		}
		// Promote metadata → real (or a redundant metadata-only repeat,
		// which is a harmless no-op). byName is already correct.
		if real && !existing.real {
			existing.real = true
			byNumber[num] = existing
		}
		return
	}

	if existing, ok := byName[name]; ok {
		panic(fmt.Sprintf("algorithms: name %q already registered (was %d)",
			name, existing))
	}
	byNumber[num] = entry{number: num, name: name, caps: caps, real: real}
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

// SupportedKSK returns the names of all registered algorithms usable
// as a Key Signing Key, sorted by codepoint.
func SupportedKSK() []string {
	return supportedWhere(func(c Capabilities) bool { return c.ForKSK })
}

// SupportedZSK returns the names of all registered algorithms usable
// as a Zone Signing Key, sorted by codepoint.
func SupportedZSK() []string {
	return supportedWhere(func(c Capabilities) bool { return c.ForZSK })
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

// AlgorithmInfo is a serializable view of one registry entry. It is
// the unit returned by [All] and is what a server reports to the CLI
// so the CLI can resolve names to codepoints without its own
// hardcoded table.
type AlgorithmInfo struct {
	Number    uint8  `json:"number"`
	Name      string `json:"name"`
	ForSIG0   bool   `json:"forsig0"`
	ForDNSSEC bool   `json:"fordnssec"`
	ForKSK    bool   `json:"forksk"`
	ForZSK    bool   `json:"forzsk"`
}

// All returns every genuinely-usable (real) algorithm, sorted by
// codepoint. Metadata-only entries are excluded: a server must not
// advertise algorithms it cannot actually generate, sign, or verify
// with. This is the authoritative set a server reports to the CLI.
func All() []AlgorithmInfo {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]AlgorithmInfo, 0, len(byNumber))
	for _, e := range byNumber {
		if !e.real {
			continue
		}
		out = append(out, AlgorithmInfo{
			Number:    e.number,
			Name:      e.name,
			ForSIG0:   e.caps.ForSIG0,
			ForDNSSEC: e.caps.ForDNSSEC,
			ForKSK:    e.caps.ForKSK,
			ForZSK:    e.caps.ForZSK,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Number < out[j].Number
	})
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
		// Classical algorithms have small signatures and are usable in
		// either DNSSEC role, so ForKSK and ForZSK are both set.
		{dns.RSASHA256, "RSASHA256", Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}},
		{dns.RSASHA512, "RSASHA512", Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}},
		{dns.ECDSAP256SHA256, "ECDSAP256SHA256", Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}},
		{dns.ECDSAP384SHA384, "ECDSAP384SHA384", Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}},
		{dns.ED25519, "ED25519", Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}},
	} {
		// Built-ins are genuinely usable (miekg/dns handles them via
		// its per-algorithm switch arms), so they are real.
		record(b.num, b.name, b.caps, true)
	}
}
