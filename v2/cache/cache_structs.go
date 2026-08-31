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
)

// type TAStore map[string]map[uint16]TrustAnchor
type DnskeyCacheT struct {
	Map *core.ConcurrentMap[string, CachedDnskeyRRset]
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
	Transport  core.Transport // Transport used to receive this data (for privacy tracking)
}

type RRsetCacheT struct {
	// RRsets is keyed by "<name>::<qtype>", so it stays a plain map; the name
	// half is folded where the key is built (Get/Set/Has/Remove below).
	// The rest are keyed by a bare DNS name and so are NameMaps, which fold for
	// themselves -- a resolver takes these names off the wire, where 0x20
	// randomisation means the same name arrives spelled differently every time.
	RRsets  *core.ConcurrentMap[string, CachedRRset]
	Servers *core.NameMap[[]string]
	// ServerMap is map[zone]map[nsname]*AuthServer.
	//
	// INVARIANT: the inner map stored under a zone is IMMUTABLE once
	// published. Changing a zone's servers means building a new map (or
	// copying the stored one) and Set-ing it — never writing into the map a
	// Get handed back. AddStub and AddServers are the two writers, and both
	// do exactly that.
	//
	// The invariant exists because IterativeDNSQuery writes into the server
	// map it is given (adding servers resolved from glue, pruning expired
	// ones). So a map that reaches a query MUST be a copy: use
	// ServerMapCopy, or FindClosestKnownZone, both of which copy for this
	// reason. A bare ServerMap.Get is for read-only inspection that stays
	// local (a status dump, a membership test) and must not escape into a
	// query — that asymmetry between the accessors, undocumented, is #345.
	ServerMap     *core.NameMap[map[string]*AuthServer]
	AuthServerMap *core.NameMap[*AuthServer]        // Global map: nsname -> *AuthServer (ensures single instance per nameserver)
	ZoneMap       *core.NameMap[*Zone]              // map[zone]*Zone
	ServerTLSA    *core.NameMap[*ServerTLSARecords] // nsname -> validated TLSA cache, decoupled from AuthServer instances
	DnskeyCache   *DnskeyCacheT
	DNSClient     map[core.Transport]core.DNSClienter
	//Options                map[ImrOption]string
	Primed               bool
	Logger               *log.Logger
	LineWidth            int
	Verbose              bool
	Debug                bool
	Quiet                bool // if true, suppress informational logging (useful for CLI tools)
	nsRevalidateMu       sync.Mutex
	nsRevalidateInFlight map[string]struct{}
}

// ServerTLSARecords is the validated TLSA cache for one nameserver, keyed by
// owner (_port._proto.name.). It lives at cache level (RRsetCacheT.ServerTLSA,
// keyed by the server's base name) rather than on the AuthServer instance, so a
// stub's private AuthServer and a discovery-shared instance for the same name
// share the TLSA cache WITHOUT sharing — and clobbering — address/transport
// state. Guarded by its own mutex.
type ServerTLSARecords struct {
	mu   sync.RWMutex
	recs map[string]*CachedRRset // keyed by owner
}

type Zone struct {
	ZoneName string
	State    ValidationState
	// Zone-specific address backoffs keyed by (address, transport).
	// Tracks per-zone, per-(address,transport) failures (e.g., REFUSED for
	// this zone from this address over a specific transport).
	AddressBackoffs map[AddrXport]*AddressBackoff
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
