// Package algorithms is tdns's runtime registry of DNSSEC signature
// algorithms — the bridge between miekg/dns's algorithm registry and
// the rest of tdns (CLI argument validation, --help text, key
// generation flows). Applications register an algorithm by codepoint
// and capability set; tdns code queries the registry to decide what
// names are valid input and what algorithms appear in --help.
//
// Built-in algorithms (RSASHA*, ECDSAP*, ED25519) are pre-registered
// at this package's init time. So are ED448 and ML-DSA-44, which
// miekg/dns does not implement: this package registers their
// implementations for real, in every binary. ED448's comes from
// github.com/johanix/dnssec-algorithms/ed448, ML-DSA-44's from
// github.com/johanix/tdns/v2/algorithms/mldsa44. Out-of-tree algorithms
// (the other ML-DSA sizes, SLH-DSA, Falcon, MAYO, SNOVA, ... via the
// github.com/johanix/dnssec-algorithms subpackages) are registered by the
// application's main package, in code tdns-genalgs generates from the
// app's algs.list:
//
//	import (
//	    algs "github.com/johanix/tdns/v2/algorithms"
//	    "github.com/johanix/dnssec-algorithms/mldsa65"
//	)
//
//	func init() {
//	    algs.Register(200, mldsa65.New(),
//	        algs.Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true},
//	        algs.Facts{})
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

	"github.com/johanix/dnssec-algorithms/ed448"
	"github.com/johanix/tdns/v2/algorithms/mldsa44"
	"github.com/miekg/dns"
)

// MLDSA44 is the codepoint IANA assigned to ML-DSA-44. miekg/dns has no
// constant for it.
const MLDSA44 uint8 = 18

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

// Facts is static, machine-independent information about an algorithm,
// fixed by its specification (sizes, NIST level, maturity, description).
// It mirrors dnssec-algorithms/registry.Facts; the generated metadata
// carries it through so a binary can display it without a separate config
// file. All fields are optional — a zero value means "not provided" and
// is rendered as "-" by callers. Machine-dependent costs are deliberately
// NOT here (they belong in the measured, per-arch cost data).
type Facts struct {
	PubKeyBytes   int    `json:"pubkeybytes,omitempty"`
	SigBytes      int    `json:"sigbytes,omitempty"`
	SecKeyBytes   int    `json:"seckeybytes,omitempty"`
	SecurityLevel int    `json:"securitylevel,omitempty"`
	Maturity      string `json:"maturity,omitempty"`
	Description   string `json:"description,omitempty"`
}

type entry struct {
	number uint8
	name   string
	caps   Capabilities
	facts  Facts
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
	// selfRegistered holds the codepoints whose implementation this
	// package registers itself at init (ED448, ML-DSA-44).
	selfRegistered = map[uint8]bool{}
)

// Register wires impl into miekg/dns's algorithm registry at the
// given codepoint and records the capability set and static facts so
// tdns code can query them. Panics on conflict (init-time pattern — the
// application must resolve duplicate codepoints itself), except that
// registering an algorithm this package already registers itself, under
// the same name, is ignored (see isSelfRegistered).
func Register(num uint8, impl dns.Algorithm, caps Capabilities, facts Facts) {
	if isSelfRegistered(num, impl.Name()) {
		return
	}
	if err := dns.RegisterAlgorithm(num, impl); err != nil {
		panic(fmt.Sprintf("algorithms.Register(%d, %s): %v",
			num, impl.Name(), err))
	}
	record(num, impl.Name(), caps, facts, true)
}

// RegisterMetadata records an algorithm's codepoint, name, capabilities,
// and static facts without touching miekg/dns's registry. Used by
// binaries that only need name-aware UI (e.g. CLI argument validation,
// --help text) but don't sign or verify with the algorithm themselves.
// Panics on conflict, with the same exception as Register.
func RegisterMetadata(num uint8, name string, caps Capabilities, facts Facts) {
	if isSelfRegistered(num, name) {
		return
	}
	record(num, name, caps, facts, false)
}

// isSelfRegistered reports whether this package registered the
// implementation at num itself, under name. Code generated by tdns-genalgs
// registers it again when it comes from an older genalgs, or from a
// dnssec-algorithms checkout that still has a registry row for it. That
// repeat is ignored rather than a panic: this package's registration,
// capabilities and facts stand.
func isSelfRegistered(num uint8, name string) bool {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := byNumber[num]
	return ok && selfRegistered[num] && e.name == name
}

// registerSelf registers an implementation that ships with tdns, in every
// binary, and marks it as such for isSelfRegistered.
func registerSelf(num uint8, impl dns.Algorithm, caps Capabilities, facts Facts) {
	Register(num, impl, caps, facts)
	mu.Lock()
	defer mu.Unlock()
	selfRegistered[num] = true
}

func record(num uint8, name string, caps Capabilities, facts Facts, real bool) {
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
		// which is a harmless no-op). byName is already correct. Facts are
		// the same static data in both the metadata and the impl
		// registration; fill them in if the earlier entry lacked them.
		if existing.facts == (Facts{}) && facts != (Facts{}) {
			existing.facts = facts
		}
		if real && !existing.real {
			existing.real = true
		}
		byNumber[num] = existing
		return
	}

	if existing, ok := byName[name]; ok {
		panic(fmt.Sprintf("algorithms: name %q already registered (was %d)",
			name, existing))
	}
	byNumber[num] = entry{number: num, name: name, caps: caps, facts: facts, real: real}
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

// CapsReal is like [Caps] but returns ok=false for a metadata-only entry
// (one registered via RegisterMetadata but with no real implementation
// linked into this binary). Use it where accepting an algorithm implies
// the binary can actually generate/sign/verify with it — e.g. validating a
// DNSSEC policy's KSK/ZSK algorithms on a signing server, which must reject
// an algorithm it only knows the name of.
func CapsReal(num uint8) (Capabilities, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := byNumber[num]
	if !ok || !e.real {
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
	// Facts is the static, machine-independent enrichment (sizes, NIST
	// level, maturity, description). Carried so a server can report it to
	// the CLI listing, replacing the old algorithms.yaml enrichment file.
	Facts Facts `json:"facts"`
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
			Facts:     e.facts,
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
	// Classical algorithms have small signatures and are usable in either
	// DNSSEC role, so ForKSK and ForZSK are both set. Their facts (sizes;
	// RSA shown for a 2048-bit key) are inlined here because the generated
	// metadata only covers the registry (PQ) algorithms, not the miekg/dns
	// built-ins. These mirror dnssec-algorithms/registry AlgorithmFacts.
	dnssecCaps := Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}
	for _, b := range []struct {
		num   uint8
		name  string
		caps  Capabilities
		facts Facts
	}{
		{dns.RSASHA256, "RSASHA256", dnssecCaps, Facts{PubKeyBytes: 260, SigBytes: 256, SecKeyBytes: 1192, Maturity: "builtin", Description: "RSA with SHA-256 (RFC 5702); classical. Sizes for a 2048-bit key (variable)"}},
		{dns.RSASHA512, "RSASHA512", dnssecCaps, Facts{PubKeyBytes: 260, SigBytes: 256, SecKeyBytes: 1192, Maturity: "builtin", Description: "RSA with SHA-512 (RFC 5702); classical. Sizes for a 2048-bit key (variable)"}},
		{dns.ECDSAP256SHA256, "ECDSAP256SHA256", dnssecCaps, Facts{PubKeyBytes: 64, SigBytes: 64, SecKeyBytes: 32, Maturity: "builtin", Description: "ECDSA P-256 with SHA-256 (RFC 6605); classical, widely deployed"}},
		{dns.ECDSAP384SHA384, "ECDSAP384SHA384", dnssecCaps, Facts{PubKeyBytes: 96, SigBytes: 96, SecKeyBytes: 48, Maturity: "builtin", Description: "ECDSA P-384 with SHA-384 (RFC 6605); classical"}},
		{dns.ED25519, "ED25519", dnssecCaps, Facts{PubKeyBytes: 32, SigBytes: 64, SecKeyBytes: 32, Maturity: "builtin", Description: "Edwards-curve DSA (RFC 8080); classical"}},
	} {
		// Built-ins are genuinely usable (miekg/dns handles them via
		// its per-algorithm switch arms), so they are real.
		record(b.num, b.name, b.caps, b.facts, true)
	}

	// ED448 (RFC 8080) is a standard algorithm every validator is expected
	// to implement, so every binary gets it, like the built-ins above, and
	// not through an app's algs.list. It is NOT a built-in, though:
	// miekg/dns has the constant and the name but no implementation. It
	// must therefore go through Register, which wires the implementation
	// into miekg/dns (dns.RegisterAlgorithm) before recording it. In the
	// record loop above it would be listed as usable and fail to parse,
	// sign or verify at the first key. genalgs does not emit it:
	// dnssec-algorithms keeps ED448 out of its registry table.
	registerSelf(dns.ED448, ed448.New(), dnssecCaps,
		Facts{PubKeyBytes: 57, SigBytes: 114, SecKeyBytes: 57, Maturity: "builtin", Description: "Edwards-curve DSA (RFC 8080); classical"})

	// ML-DSA-44 (FIPS 204) has its IANA codepoint and a pure-Go
	// implementation, so every binary gets it too, whether or not the app
	// has an algs.list. It is usable in both roles, as in the
	// dnssec-algorithms registry; its 2420-byte signature makes KSK-only
	// the usual choice, and that is left to the operator's policy.
	// genalgs leaves it out of the files it generates.
	registerSelf(MLDSA44, mldsa44.New(), dnssecCaps,
		Facts{PubKeyBytes: 1312, SigBytes: 2420, SecKeyBytes: 2560, SecurityLevel: 2, Maturity: "final", Description: "ML-DSA-44 (FIPS 204), lattice"})
}
