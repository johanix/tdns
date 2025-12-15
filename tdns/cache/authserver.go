/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"

	core "github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
)

// AddressBackoff tracks backoff state for a single server address.
// Used to avoid repeatedly querying addresses that don't respond or have routing issues.
type AddressBackoff struct {
	NextTry      time.Time // When this address can be tried again
	FailureCount uint8     // Number of consecutive failures (1 = first failure, 2+ = second+ failure)
	LastError    string    // Last error message (stored when debug mode is enabled)
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
	Debug             bool // If true, store error messages in AddressBackoff.LastError
	// Backoff tracking (guarded by mu)
	AddressBackoffs map[string]*AddressBackoff // keyed by address string (e.g., "1.2.3.4:53" or "[2001:db8::1]:53")
}

// NewAuthServer creates a new AuthServer instance with default values.
// The name parameter is required and identifies the nameserver.
// All other fields are initialized with safe defaults:
//   - Alpn: ["do53"]
//   - Transports: [TransportDo53]
//   - PrefTransport: TransportDo53
//   - Src: "unknown"
//   - ConnMode: ConnModeLegacy
//   - Other fields: nil or zero values
func NewAuthServer(name string) *AuthServer {
	if name == "" {
		return nil
	}
	return &AuthServer{
		Name:          name,
		Alpn:          []string{"do53"},
		Transports:    []core.Transport{core.TransportDo53},
		PrefTransport: core.TransportDo53,
		Src:           "unknown",
		ConnMode:      ConnModeLegacy,
		// Other fields are zero-initialized:
		// Addrs: nil
		// TransportWeights: nil
		// TransportSignal: ""
		// TLSARecords: nil
		// TransportCounters: nil (will be initialized on first use)
		// Expire: zero time
		// Debug: false
		// AddressBackoffs: nil (will be initialized on first use)
	}
}

func (as *AuthServer) ConnectionMode() ConnMode {
	if as == nil {
		return ConnModeLegacy
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.ConnMode
}

// GetAddrs returns a copy of the addresses slice. Thread-safe.
func (as *AuthServer) GetAddrs() []string {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.Addrs) == 0 {
		return nil
	}
	addrs := make([]string, len(as.Addrs))
	copy(addrs, as.Addrs)
	return addrs
}

// AddAddr adds an address if it doesn't already exist. Thread-safe.
func (as *AuthServer) AddAddr(addr string) {
	if as == nil || addr == "" {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	for _, a := range as.Addrs {
		if a == addr {
			return // Already exists
		}
	}
	as.Addrs = append(as.Addrs, addr)
}

// SetAddrs sets the addresses slice. Thread-safe.
func (as *AuthServer) SetAddrs(addrs []string) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(addrs) == 0 {
		as.Addrs = nil
		return
	}
	as.Addrs = make([]string, len(addrs))
	copy(as.Addrs, addrs)
}

// GetAlpn returns a copy of the ALPN slice. Thread-safe.
func (as *AuthServer) GetAlpn() []string {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.Alpn) == 0 {
		return nil
	}
	alpn := make([]string, len(as.Alpn))
	copy(alpn, as.Alpn)
	return alpn
}

// AddAlpn adds an ALPN value if it doesn't already exist. Thread-safe.
func (as *AuthServer) AddAlpn(alpn string) {
	if as == nil || alpn == "" {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	for _, a := range as.Alpn {
		if a == alpn {
			return // Already exists
		}
	}
	as.Alpn = append(as.Alpn, alpn)
}

// SetAlpn sets the ALPN slice. Thread-safe.
func (as *AuthServer) SetAlpn(alpn []string) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(alpn) == 0 {
		as.Alpn = nil
		return
	}
	as.Alpn = make([]string, len(alpn))
	copy(as.Alpn, alpn)
}

// GetTransports returns a copy of the transports slice. Thread-safe.
func (as *AuthServer) GetTransports() []core.Transport {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.Transports) == 0 {
		return nil
	}
	transports := make([]core.Transport, len(as.Transports))
	copy(transports, as.Transports)
	return transports
}

// AddTransport adds a transport if it doesn't already exist. Thread-safe.
func (as *AuthServer) AddTransport(t core.Transport) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	for _, tr := range as.Transports {
		if tr == t {
			return // Already exists
		}
	}
	as.Transports = append(as.Transports, t)
}

// SetTransports sets the transports slice. Thread-safe.
func (as *AuthServer) SetTransports(transports []core.Transport) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(transports) == 0 {
		as.Transports = nil
		return
	}
	as.Transports = make([]core.Transport, len(transports))
	copy(as.Transports, transports)
}

// GetSrc returns the source string. Thread-safe.
func (as *AuthServer) GetSrc() string {
	if as == nil {
		return ""
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.Src
}

// SetSrc sets the source string if it's more specific than the current value. Thread-safe.
func (as *AuthServer) SetSrc(src string) {
	if as == nil || src == "" {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.Src == "" || as.Src == "unknown" {
		as.Src = src
	}
}

// ForceSetSrc sets the source string unconditionally. Thread-safe.
func (as *AuthServer) ForceSetSrc(src string) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Src = src
}

// GetDebug returns the debug flag. Thread-safe.
func (as *AuthServer) GetDebug() bool {
	if as == nil {
		return false
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.Debug
}

// SetDebug sets the debug flag. Thread-safe.
func (as *AuthServer) SetDebug(debug bool) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Debug = debug
}

// PromoteDebug sets debug to true if not already set. Thread-safe.
func (as *AuthServer) PromoteDebug() {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if !as.Debug {
		as.Debug = true
	}
}

// GetExpire returns the expiration time. Thread-safe.
func (as *AuthServer) GetExpire() time.Time {
	if as == nil {
		return time.Time{}
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.Expire
}

// SetExpire sets the expiration time. Thread-safe.
func (as *AuthServer) SetExpire(expire time.Time) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Expire = expire
}

// GetPrefTransport returns the preferred transport. Thread-safe.
func (as *AuthServer) GetPrefTransport() core.Transport {
	if as == nil {
		return core.TransportDo53
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.PrefTransport
}

// SetPrefTransport sets the preferred transport. Thread-safe.
func (as *AuthServer) SetPrefTransport(t core.Transport) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	as.PrefTransport = t
}

// GetTransportWeights returns a copy of the transport weights map. Thread-safe.
func (as *AuthServer) GetTransportWeights() map[core.Transport]uint8 {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.TransportWeights) == 0 {
		return nil
	}
	weights := make(map[core.Transport]uint8, len(as.TransportWeights))
	for k, v := range as.TransportWeights {
		weights[k] = v
	}
	return weights
}

// SetTransportWeight sets a single transport weight. Thread-safe.
func (as *AuthServer) SetTransportWeight(t core.Transport, weight uint8) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.TransportWeights == nil {
		as.TransportWeights = make(map[core.Transport]uint8)
	}
	as.TransportWeights[t] = weight
}

// MergeTransportWeights merges the provided weights into the existing map. Thread-safe.
func (as *AuthServer) MergeTransportWeights(weights map[core.Transport]uint8) {
	if as == nil || len(weights) == 0 {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.TransportWeights == nil {
		as.TransportWeights = make(map[core.Transport]uint8)
	}
	for k, v := range weights {
		as.TransportWeights[k] = v
	}
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

// SnapshotAddressBackoffs returns a copy of the address backoff map.
// Only includes addresses that are currently in backoff (NextTry > now).
func (as *AuthServer) SnapshotAddressBackoffs(now time.Time) map[string]*AddressBackoff {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.AddressBackoffs == nil || len(as.AddressBackoffs) == 0 {
		return nil
	}
	snap := make(map[string]*AddressBackoff)
	for addr, backoff := range as.AddressBackoffs {
		if backoff.NextTry.After(now) {
			// Create a copy of the backoff struct
			snap[addr] = &AddressBackoff{
				NextTry:      backoff.NextTry,
				FailureCount: backoff.FailureCount,
				LastError:    backoff.LastError,
			}
		}
	}
	if len(snap) == 0 {
		return nil
	}
	return snap
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

// IsAddressAvailable returns true if the given address is not in backoff or backoff has expired.
// Thread-safe: acquires mu lock.
func (as *AuthServer) IsAddressAvailable(addr string) bool {
	if as == nil {
		return false
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.AddressBackoffs == nil {
		return true // No backoffs recorded, address is available
	}
	backoff, exists := as.AddressBackoffs[addr]
	if !exists {
		return true // No backoff for this address
	}
	// Check if backoff has expired
	return time.Now().After(backoff.NextTry)
}

// categorizeError analyzes the error and returns the appropriate backoff duration.
// Routing errors (no route to host) get 1 hour immediately as they're unlikely to resolve soon.
// Timeout errors get 2 minutes as they might be temporary.
// Other errors default to 2 minutes for first failure, 1 hour for subsequent failures.
// categorizeError selects a backoff duration based on the provided error text and
// whether this is the first failure for an address.
//
// Rules:
// - If err is nil: return 2 minutes for a first failure, 1 hour otherwise.
// - If the error text indicates a routing failure (contains "no route to host",
//   "network is unreachable", or "host unreachable"): return 1 hour.
// - If the error text indicates a timeout (contains "timeout", "i/o timeout", or
//   "deadline exceeded"): return 2 minutes.
// categorizeError determines the backoff duration to apply for an address failure
// based on the provided error and whether this is the first consecutive failure.
// Behavior:
// - If err is nil: return 2 minutes for a first failure, 1 hour otherwise.
// - If the error message contains routing indicators ("no route to host", "network is unreachable", "host unreachable"): return 1 hour.
// - If the error message contains timeout indicators ("timeout", "i/o timeout", "deadline exceeded"): return 2 minutes.
// - For all other errors: return 2 minutes for a first failure, 1 hour otherwise.

func categorizeError(err error, isFirstFailure bool) time.Duration {
	if err == nil {
		// No error provided, use default behavior
		if isFirstFailure {
			return 2 * time.Minute
		}
		return 1 * time.Hour
	}
	errStr := err.Error()

	// Check for routing errors - these are unlikely to resolve soon, so backoff 1 hour immediately
	if strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "host unreachable") {
		return 1 * time.Hour
	}

	// Check for timeout errors - these might be temporary, so backoff 2 minutes
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded") {
		return 2 * time.Minute
	}

	// Other errors: 2 minutes for first failure, 1 hour for subsequent
	if isFirstFailure {
		return 2 * time.Minute
	}
	return 1 * time.Hour
}

// RecordAddressFailure records a failure for the given address and sets appropriate backoff.
// The error parameter is analyzed to determine backoff duration:
//   - Routing errors ("no route to host"): 1 hour immediately
//   - Timeout errors: 2 minutes
//   - Other errors: 2 minutes for first failure, 1 hour for subsequent failures
//
// If as.Debug is true, the error message is stored in LastError for debugging purposes.
// Thread-safe: acquires mu lock.
func (as *AuthServer) RecordAddressFailure(addr string, err error) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.AddressBackoffs == nil {
		as.AddressBackoffs = make(map[string]*AddressBackoff)
	}
	backoff, exists := as.AddressBackoffs[addr]
	errMsg := ""
	if as.Debug && err != nil {
		errMsg = err.Error()
	}
	if !exists {
		// First failure: determine backoff based on error type
		backoffDuration := categorizeError(err, true)
		as.AddressBackoffs[addr] = &AddressBackoff{
			NextTry:      time.Now().Add(backoffDuration),
			FailureCount: 1,
			LastError:    errMsg,
		}
		return
	}
	// Subsequent failure: determine backoff based on error type
	backoffDuration := categorizeError(err, false)
	backoff.NextTry = time.Now().Add(backoffDuration)
	backoff.LastError = errMsg      // Update last error even if not first failure
	if backoff.FailureCount < 255 { // Prevent overflow
		backoff.FailureCount++
	}
}

// RecordAddressFailureForRcode records a failure for the given address based on a DNS response code.
// Thread-safe: acquires mu lock.
func (as *AuthServer) RecordAddressFailureForRcode(addr string, rcode uint8) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.AddressBackoffs == nil {
		as.AddressBackoffs = make(map[string]*AddressBackoff)
	}
	backoff, exists := as.AddressBackoffs[addr]

	// Determine backoff duration based on rcode
	var backoffDuration time.Duration
	var errMsg string
	switch rcode {
	case dns.RcodeNotImplemented:
		backoffDuration = 1 * time.Hour
		if as.Debug {
			errMsg = fmt.Sprintf("rcode=%d", rcode)
		}
	default:
		// For other rcodes, use default behavior (2 min first, 1 hour subsequent)
		if !exists {
			backoffDuration = 2 * time.Minute
		} else {
			backoffDuration = 1 * time.Hour
		}
		if as.Debug {
			errMsg = fmt.Sprintf("rcode=%d", rcode)
		}
	}

	if !exists {
		// First failure
		as.AddressBackoffs[addr] = &AddressBackoff{
			NextTry:      time.Now().Add(backoffDuration),
			FailureCount: 1,
			LastError:    errMsg,
		}
		return
	}
	// Subsequent failure
	backoff.NextTry = time.Now().Add(backoffDuration)
	if as.Debug {
		backoff.LastError = errMsg
	}
	if backoff.FailureCount < 255 { // Prevent overflow
		backoff.FailureCount++
	}
}

// RecordAddressSuccess clears any backoff for the given address.
// Thread-safe: acquires mu lock.
func (as *AuthServer) RecordAddressSuccess(addr string) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.AddressBackoffs != nil {
		delete(as.AddressBackoffs, addr)
		// If map is empty, we could nil it out, but keeping it is fine for efficiency
	}
}

// AllAddressesInBackoff returns true if all addresses for this server are currently in backoff.
// Thread-safe: acquires mu lock once for the entire operation.
func (as *AuthServer) AllAddressesInBackoff() bool {
	if as == nil {
		return false
	}
	as.mu.Lock()
	defer as.mu.Unlock()

	// Copy Addrs while holding the lock to avoid TOCTOU
	if len(as.Addrs) == 0 {
		return false
	}
	addrs := make([]string, len(as.Addrs))
	copy(addrs, as.Addrs)

	// Check backoffs while still holding the same lock
	if as.AddressBackoffs == nil || len(as.AddressBackoffs) == 0 {
		return false // No backoffs recorded
	}
	now := time.Now()
	for _, addr := range addrs {
		backoff, exists := as.AddressBackoffs[addr]
		if !exists {
			return false // At least one address has no backoff
		}
		if now.After(backoff.NextTry) {
			return false // At least one address's backoff has expired
		}
	}
	return true // All addresses are in active backoff
}

// GetAvailableAddresses returns a list of addresses that are currently available (not in backoff).
// Thread-safe: acquires mu lock once for the entire operation.
func (as *AuthServer) GetAvailableAddresses() []string {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()

	// Copy Addrs while holding the lock to avoid TOCTOU
	if len(as.Addrs) == 0 {
		return nil
	}
	addrs := make([]string, len(as.Addrs))
	copy(addrs, as.Addrs)

	// Check backoffs while still holding the same lock
	var available []string
	now := time.Now()
	for _, addr := range addrs {
		if as.AddressBackoffs == nil {
			available = append(available, addr)
			continue
		}
		backoff, exists := as.AddressBackoffs[addr]
		if !exists || now.After(backoff.NextTry) {
			available = append(available, addr)
		}
	}
	return available
}
