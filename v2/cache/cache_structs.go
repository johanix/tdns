/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"log"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
)

// type TAStore map[string]map[uint16]TrustAnchor
type DnskeyCacheT struct {
	Map cmap.ConcurrentMap[string, CachedDnskeyRRset]
}

type CachedDnskeyRRset struct {
	Name  string
	Keyid uint16
	State ValidationState
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
	RRsets        *core.ConcurrentMap[string, CachedRRset]
	Servers       *core.ConcurrentMap[string, []string]
	ServerMap     *core.ConcurrentMap[string, map[string]*AuthServer] // map[zone]map[nsname]*AuthServer
	AuthServerMap *core.ConcurrentMap[string, *AuthServer]            // Global map: nsname -> *AuthServer (ensures single instance per nameserver)
	ZoneMap       *core.ConcurrentMap[string, *Zone]                  // map[zone]*Zone
	DnskeyCache   *DnskeyCacheT
	DNSClient     map[core.Transport]*core.DNSClient
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

type Zone struct {
	ZoneName string
	State    ValidationState
	// Zone-specific address backoffs: map[address]*AddressBackoff
	// Tracks per-zone, per-address failures (e.g., REFUSED for this zone from this address)
	AddressBackoffs map[string]*AddressBackoff
	mu              sync.Mutex // Protects State and AddressBackoffs
}

// GetState returns the current validation state of the zone.
// Thread-safe: acquires mu lock.
func (z *Zone) GetState() ValidationState {
	if z == nil {
		return ValidationStateNone
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.State
}

// SetState sets the validation state of the zone.
// Thread-safe: acquires mu lock.
func (z *Zone) SetState(state ValidationState) {
	if z == nil {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	z.State = state
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
