/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"log"
	"sync"
	"time"

	core "github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
)

// type TAStore map[string]map[uint16]TrustAnchor
type DnskeyCacheT struct {
	Map cmap.ConcurrentMap[string, CachedDnskeyRRset]
}

type CachedDnskeyRRset struct {
	Name        string
	Keyid       uint16
	State       ValidationState
	// Trusted     bool
	TrustAnchor bool
	Dnskey      dns.DNSKEY  // just this key
	RRset       *core.RRset // complete RRset
	Expiration  time.Time
}

type CachedRRset struct {
	Name         string
	RRtype       uint16
	Rcode        uint8
	RRset        *core.RRset
	NegAuthority []*core.RRset
	Ttl          uint32
	Context      CacheContext
	// OBE Validated    bool
	// OBE Bogus        bool
	State      ValidationState
	Expiration time.Time
	EDECode    uint16
	EDEText    string
}

type RRsetCacheT struct {
	RRsets      *core.ConcurrentMap[string, CachedRRset]
	Servers     *core.ConcurrentMap[string, []string]
	ServerMap   *core.ConcurrentMap[string, map[string]*AuthServer] // map[zone]map[nsname]*AuthServer
	ZoneMap     *core.ConcurrentMap[string, *Zone]                  // map[zone]*Zone
	DnskeyCache *DnskeyCacheT
	DNSClient   map[core.Transport]*core.DNSClient
	//Options                map[ImrOption]string
	Primed                 bool
	Logger                 *log.Logger
	LineWidth              int
	Verbose                bool
	Debug                  bool
	Quiet                  bool // if true, suppress informational logging (useful for CLI tools)
	transportQueryMu       sync.Mutex
	transportQueryInFlight map[string]struct{}
	nsRevalidateMu         sync.Mutex
	nsRevalidateInFlight   map[string]struct{}
	tlsaQueryMu            sync.Mutex
	tlsaQueryInFlight      map[string]struct{}
}

type AuthServer struct {
	Name             string
	Addrs            []string
	Alpn             []string // {"do53", "doq", "dot", "doh"}
	Transports       []core.Transport
	PrefTransport    core.Transport           // "doq" | "dot" | "doh" | "do53"
	TransportWeights map[core.Transport]uint8 // percentage per transport (sum <= 100). Remainder -> do53
	// Optional config-only field for stubs: colon-separated transport weights, e.g. "doq:30,dot:70"
	// When provided in config, this overrides Alpn for building Transports/PrefTransport/TransportWeights.
	TransportSignal string                  `yaml:"transport" mapstructure:"transport"`
	ConnMode        ConnMode                `yaml:"connmode" mapstructure:"connmode"`
	TLSARecords     map[string]*CachedRRset // keyed by owner (_port._proto.name.), validated RRsets only
	// Stats (guarded by mu)
	mu                sync.Mutex
	TransportCounters map[core.Transport]uint64 // total queries attempted per transport
	Src               string                    // "answer", "glue", "hint", "priming", "stub", ...
	Expire            time.Time
}

type Zone struct {
	ZoneName         string
	Secure			 bool
}

func (as *AuthServer) ConnectionMode() ConnMode {
	if as == nil {
		return ConnModeLegacy
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.ConnMode
}

func (as *AuthServer) SnapshotTLSARecords() map[string]*CachedRRset {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.TLSARecords) == 0 {
		return nil
	}
	snap := make(map[string]*CachedRRset, len(as.TLSARecords))
	for owner, rec := range as.TLSARecords {
		snap[owner] = rec
	}
	return snap
}

// SnapshotCounters returns a copy of the per-transport counters.
func (as *AuthServer) SnapshotCounters() map[core.Transport]uint64 {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	out := make(map[core.Transport]uint64, len(as.TransportCounters))
	for t, c := range as.TransportCounters {
		out[t] = c
	}
	return out
}

func (as *AuthServer) IncrementTransportCounter(t core.Transport) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.TransportCounters == nil {
		as.TransportCounters = make(map[core.Transport]uint64)
	}
	as.TransportCounters[t]++
}

func (as *AuthServer) PromoteConnMode(target ConnMode) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.ConnMode < target {
		as.ConnMode = target
	}
}

type CacheContext uint8

const (
	ContextAnswer CacheContext = iota + 1
	ContextHint
	ContextPriming
	ContextReferral
	ContextNXDOMAIN
	ContextNoErrNoAns
	ContextGlue    // from additional section
	ContextFailure // some sort of general failure that we cannot sort out
)

var CacheContextToString = map[CacheContext]string{
	ContextAnswer:     "answer",
	ContextHint:       "hint",
	ContextPriming:    "priming",
	ContextReferral:   "referral",
	ContextNXDOMAIN:   "NXDOMAIN (negative response type 3)",
	ContextNoErrNoAns: "NOERROR, NODATA (negative response type 0)",
	ContextGlue:       "glue",
	ContextFailure:    "failure",
}

/*
type ImrOption uint8

const (
	ImrOptRevalidateNS ImrOption = iota + 1
	ImrOptQueryForTransport
	ImrOptAlwaysQueryForTransport
	ImrOptTransportSignalType
	ImrOptQueryForTransportTLSA
)

var ImrOptionToString = map[ImrOption]string{
	ImrOptRevalidateNS:            "revalidate-ns",
	ImrOptQueryForTransport:       "query-for-transport",
	ImrOptAlwaysQueryForTransport: "always-query-for-transport",
	ImrOptTransportSignalType:     "transport-signal-type",
	ImrOptQueryForTransportTLSA:   "query-for-transport-tlsa",
}

var StringToImrOption = map[string]ImrOption{
	"revalidate-ns":              ImrOptRevalidateNS,
	"query-for-transport":        ImrOptQueryForTransport,
	"always-query-for-transport": ImrOptAlwaysQueryForTransport,
	"transport-signal-type":      ImrOptTransportSignalType,
	"query-for-transport-tlsa":   ImrOptQueryForTransportTLSA,
}
*/

type ValidationState uint8

const (
	ValidationStateNone ValidationState = iota + 1
	ValidationStateInsecure
	ValidationStateSecure
	ValidationStateBogus
	ValidationStateIndeterminate
)

var ValidationStateToString = map[ValidationState]string{
	ValidationStateNone:          "none",
	ValidationStateInsecure:      "insecure",
	ValidationStateSecure:        "secure",
	ValidationStateBogus:         "bogus",
	ValidationStateIndeterminate: "indeterminate",
}
