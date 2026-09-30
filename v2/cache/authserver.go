/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// AddressBackoff tracks backoff state for a single (address, transport) tuple.
// Used to avoid repeatedly querying addresses that don't respond or have routing issues.
type AddressBackoff struct {
	NextTry      time.Time // When this address can be tried again
	FailureCount uint8     // Number of consecutive failures (1 = first failure, 2+ = second+ failure)
	LastError    string    // Last error message (stored when debug mode is enabled)
}

// AddrXport keys backoff state by both address and transport. A timeout on
// (1.2.3.4:53, DoT) does not poison (1.2.3.4:53, Do53) or vice versa: that
// would conflate problems with the TLS path with problems with the address.
type AddrXport struct {
	Addr      string
	Transport core.Transport
}

// RTTEstimate is an exponentially-weighted moving average of observed
// round-trip times for one (address, transport) tuple. It feeds the
// prioritizeServers sort so the IMR prefers faster paths.
type RTTEstimate struct {
	EMA          time.Duration // exponential moving average
	Samples      uint32        // number of samples folded in
	LastSample   time.Duration // most recent observation
	LastSampleAt time.Time     // wall-clock time of LastSample
}

type AuthServer struct {
	Name string
	// Addrs holds BARE IP literals (e.g. "192.0.2.1" or "2001:db8::1"),
	// NOT host:port. The port is added by core.DNSClient.Exchange via
	// net.JoinHostPort(addr, c.Port) at dial time. Passing a host:port
	// string through AddAddr makes JoinHostPort produce
	// "[1.2.3.4:53]:53" because of the embedded colon, after which Dial
	// tries to resolve "1.2.3.4:53" as a hostname and fails with
	// "no such host". Always pass bare IPs.
	Addrs            []string
	Alpn             []string // {"do53", "doq", "dot", "doh"}
	Transports       []core.Transport
	TransportWeights map[core.Transport]uint8 // independent oots weights [0,100]; Do53 is ultimate fallback
	// Optional config-only field for stubs: colon-separated transport weights, e.g. "doq:30,dot:70"
	// When provided in config, this overrides Alpn for building Transports/TransportWeights.
	TransportSignal string   `yaml:"transport" mapstructure:"transport"`
	ConnMode        ConnMode `yaml:"connmode" mapstructure:"connmode"`
	// Received is the transport signal as the server sent it (or the stub's
	// configuration gave it), before the absence defaults that
	// TransportWeights carries for selection; nil when there was none.
	// Guarded by mu, and set in the same step as the weights.
	Received *ReceivedSignal
	// Stats (guarded by mu)
	mu                sync.Mutex
	TransportCounters map[core.Transport]uint64                    // queries ATTEMPTED per transport (transport chosen)
	UsedCounters      map[core.Transport]uint64                    // queries whose answer was CARRIED, by actual wire transport
	LastUsed          map[core.Transport]time.Time                 // when an answer was last CARRIED, by actual wire transport
	UsedByClass       [NumTrafficClasses]map[core.Transport]uint64 // UsedCounters split by whose query it was
	FailedCounters    map[core.Transport]uint64                    // attempts that ERRORED, by actual wire transport (see tryServer)
	TruncatedCount    uint64                                       // Do53/UDP responses TC=1 truncated and retried over TCP
	Src               string                                       // "answer", "glue", "hint", "priming", "stub", ...
	// configuredAddrs holds the addresses the operator configured for this
	// server (a stub's, via AddStub), in canonical form. Addresses added
	// later, from glue or a lookup, are not in it.
	configuredAddrs map[string]struct{}
	Expire          time.Time
	Debug           bool // If true, store error messages in AddressBackoff.LastError
	// Backoff tracking (guarded by mu). Keyed by (address, transport): a
	// failure on (1.2.3.4:53, DoT) does not block (1.2.3.4:53, Do53).
	AddressBackoffs map[AddrXport]*AddressBackoff
	// RTT estimates (guarded by mu). Used by prioritizeServers to prefer
	// faster (address, transport) tuples.
	RTTEstimates map[AddrXport]*RTTEstimate
}

// NewAuthServer creates a new AuthServer instance with default values.
// The name parameter is required and identifies the nameserver.
// All other fields are initialized with safe defaults:
//   - Alpn: ["do53"]
//   - Transports: [TransportDo53]
//   - Src: "unknown"
//   - ConnMode: ConnModeLegacy
//   - Other fields: nil or zero values
func NewAuthServer(name string) *AuthServer {
	if name == "" {
		log.Printf("NewAuthServer: called with empty name, returning nil")
		return nil
	}
	return &AuthServer{
		Name:       name,
		Alpn:       []string{"do53"},
		Transports: []core.Transport{core.TransportDo53},
		Src:        "unknown",
		ConnMode:   ConnModeLegacy,
		// Other fields are zero-initialized:
		// Addrs: nil
		// TransportWeights: nil
		// TransportSignal: ""
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

// canonicalAddr returns an IP literal in canonical form ("0:0::1" → "::1"), and
// anything else unchanged.
func canonicalAddr(addr string) string {
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	return addr
}

// SetConfiguredAddrs records addrs as the addresses the operator configured
// for this server. Thread-safe.
func (as *AuthServer) SetConfiguredAddrs(addrs []string) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	as.configuredAddrs = make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		as.configuredAddrs[canonicalAddr(a)] = struct{}{}
	}
}

// IsConfiguredAddr reports whether the operator configured addr for this
// server (SetConfiguredAddrs). Thread-safe.
func (as *AuthServer) IsConfiguredAddr(addr string) bool {
	if as == nil {
		return false
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	_, ok := as.configuredAddrs[canonicalAddr(addr)]
	return ok
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

// SetTransportsIfNone sets the transports slice only when the server has
// none, checking and setting under one lock so that a transport signal
// installed meanwhile is not replaced. Thread-safe.
func (as *AuthServer) SetTransportsIfNone(transports []core.Transport) {
	if as == nil || len(transports) == 0 {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.Transports) > 0 {
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

// SetTransportWeights replaces the entire transport weights map. Thread-safe.
func (as *AuthServer) SetTransportWeights(weights map[core.Transport]uint8) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(weights) == 0 {
		as.TransportWeights = nil
		return
	}
	as.TransportWeights = make(map[core.Transport]uint8, len(weights))
	for k, v := range weights {
		as.TransportWeights[k] = v
	}
}

// SetTransportSignal installs what a transport signal says about the server:
// its transports, their ALPN names, their weights, and the signal as received,
// as one change under the lock. The resolver reads them while background
// lookups write them, and a reader must never see the weights of one signal
// with the transports of another. The arguments are the caller's to give away.
// Thread-safe.
func (as *AuthServer) SetTransportSignal(transports []core.Transport, alpn []string, weights map[core.Transport]uint8, received *ReceivedSignal) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Transports = transports
	as.Alpn = alpn
	as.TransportWeights = weights
	as.Received = received
}

// SetReceivedSignal records the signal as received, for the paths that set the
// weights by other means (a stub's configuration, an operator's override).
// Thread-safe.
func (as *AuthServer) SetReceivedSignal(received *ReceivedSignal) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	as.Received = received
}

// GetSignalState returns copies of the transports, their weights and the
// signal as received, read together under the lock, so that a report never
// pairs the weights of one signal with the received form of another.
// Thread-safe.
func (as *AuthServer) GetSignalState() ([]core.Transport, map[core.Transport]uint8, *ReceivedSignal) {
	if as == nil {
		return nil, nil, nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	transports := append([]core.Transport(nil), as.Transports...)
	return transports, copyMap(as.TransportWeights), as.Received.clone()
}

// GetReceivedSignal returns a copy of the signal as received, or nil.
// Thread-safe.
func (as *AuthServer) GetReceivedSignal() *ReceivedSignal {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.Received.clone()
}

// GetTransportSignal returns copies of the transports and their weights,
// read together under the lock. Thread-safe.
func (as *AuthServer) GetTransportSignal() ([]core.Transport, map[core.Transport]uint8) {
	if as == nil {
		return nil, nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	transports := append([]core.Transport(nil), as.Transports...)
	var weights map[core.Transport]uint8
	if len(as.TransportWeights) > 0 {
		weights = make(map[core.Transport]uint8, len(as.TransportWeights))
		for k, v := range as.TransportWeights {
			weights[k] = v
		}
	}
	return transports, weights
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

// SnapshotAddressBackoffs returns a copy of the (address, transport) backoff
// map. Only includes entries that are currently in backoff (NextTry > now).
func (as *AuthServer) SnapshotAddressBackoffs(now time.Time) map[AddrXport]*AddressBackoff {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.AddressBackoffs) == 0 {
		return nil
	}
	snap := make(map[AddrXport]*AddressBackoff)
	for key, backoff := range as.AddressBackoffs {
		if backoff.NextTry.After(now) {
			snap[key] = &AddressBackoff{
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

// IncrementUsedCounter records that a query's answer was carried over transport
// t — the ACTUAL wire transport, which for Do53 may be Do53TCP after a fallback.
//
// class says whose query it was: a client's, by the PRIVACY level it carried,
// or the resolver's own.
func (as *AuthServer) IncrementUsedCounter(t core.Transport, class TrafficClass) {
	if as == nil {
		return
	}
	if class >= NumTrafficClasses {
		class = ClassInternal
	}
	now := time.Now()
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.UsedCounters == nil {
		as.UsedCounters = make(map[core.Transport]uint64)
		as.LastUsed = make(map[core.Transport]time.Time)
	}
	as.UsedCounters[t]++
	as.LastUsed[t] = now
	if as.UsedByClass[class] == nil {
		as.UsedByClass[class] = make(map[core.Transport]uint64)
	}
	as.UsedByClass[class][t]++
}

// IncrementFailedCounter records a failed attempt over transport t (e.g. an
// unreachable DoQ the server advertised). tryServer passes the actual wire
// transport, so a TC=1-then-TCP failure counts against Do53TCP.
func (as *AuthServer) IncrementFailedCounter(t core.Transport) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.FailedCounters == nil {
		as.FailedCounters = make(map[core.Transport]uint64)
	}
	as.FailedCounters[t]++
}

// IncrementTruncated records one Do53/UDP response that was TC=1 truncated and
// retried over TCP (a size-driven upgrade, not a failure).
func (as *AuthServer) IncrementTruncated() {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	as.TruncatedCount++
}

// TransportStats is a consistent point-in-time snapshot of a server's
// per-transport usage counters plus its truncation count. Attempted = queries
// initiated (by the transport chosen); Used = queries whose answer was carried
// (by the actual wire transport), and LastUsed when each was last; Failed =
// attempts that errored (by the actual wire transport); Truncated = Do53/UDP
// responses TC=1 truncated and retried over TCP.
type TransportStats struct {
	Attempted   map[core.Transport]uint64
	Used        map[core.Transport]uint64
	UsedByClass [NumTrafficClasses]map[core.Transport]uint64 // Used, split by TrafficClass
	LastUsed    map[core.Transport]time.Time
	Failed      map[core.Transport]uint64
	Truncated   uint64
}

// SnapshotTransportStats returns a consistent copy of all per-transport usage
// counters and the truncation count under a single lock.
func (as *AuthServer) SnapshotTransportStats() TransportStats {
	var ts TransportStats
	if as == nil {
		return ts
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	ts.Attempted = copyMap(as.TransportCounters)
	ts.Used = copyMap(as.UsedCounters)
	for c := range as.UsedByClass {
		ts.UsedByClass[c] = copyMap(as.UsedByClass[c])
	}
	ts.LastUsed = copyMap(as.LastUsed)
	ts.Failed = copyMap(as.FailedCounters)
	ts.Truncated = as.TruncatedCount
	return ts
}

// TakeTransportStats returns the same snapshot as SnapshotTransportStats and
// clears the counters in the same step, so that no query counted between the
// two is lost: it lands either in this snapshot or in the next period.
func (as *AuthServer) TakeTransportStats() TransportStats {
	var ts TransportStats
	if as == nil {
		return ts
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	// The maps are handed over, not copied: the counters start again from nil.
	ts = TransportStats{
		Attempted:   as.TransportCounters,
		Used:        as.UsedCounters,
		UsedByClass: as.UsedByClass,
		LastUsed:    as.LastUsed,
		Failed:      as.FailedCounters,
		Truncated:   as.TruncatedCount,
	}
	as.TransportCounters, as.UsedCounters, as.LastUsed, as.FailedCounters = nil, nil, nil, nil
	as.UsedByClass = [NumTrafficClasses]map[core.Transport]uint64{}
	as.TruncatedCount = 0
	return ts
}

func copyMap[V any](m map[core.Transport]V) map[core.Transport]V {
	if len(m) == 0 {
		return nil
	}
	out := make(map[core.Transport]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SnapshotTransportCounters returns a thread-safe copy of the transport counters.
func (as *AuthServer) SnapshotTransportCounters() map[core.Transport]uint64 {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.TransportCounters == nil {
		return nil
	}
	snap := make(map[core.Transport]uint64, len(as.TransportCounters))
	for k, v := range as.TransportCounters {
		snap[k] = v
	}
	return snap
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

// IsAddrXportAvailable returns true if the (address, transport) tuple is not
// in backoff (or its backoff has expired). Thread-safe.
func (as *AuthServer) IsAddrXportAvailable(addr string, t core.Transport) bool {
	if as == nil {
		return false
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.AddressBackoffs == nil {
		return true
	}
	backoff, exists := as.AddressBackoffs[AddrXport{Addr: addr, Transport: t}]
	if !exists {
		return true
	}
	return time.Now().After(backoff.NextTry)
}

// isRoutingError reports whether the error string indicates a
// host- or network-level routing failure ("no route to host" etc.).
// These are unlikely to recover on a short timescale, so the policy
// applies its RoutingFailure backoff (typically 1h) immediately.
func isRoutingError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "host unreachable")
}

// categorizeError selects a backoff duration based on (a) whether
// the error indicates a routing failure and (b) the previous backoff
// state for this address-key. nil prev means "first failure ever".
// Otherwise the duration grows geometrically per the current
// BackoffPolicy, capped at MaxFailure and randomised by JitterFraction.
func categorizeError(err error, prev *AddressBackoff) time.Duration {
	if isRoutingError(err) {
		return applyJitter(GetBackoffPolicy().RoutingFailure)
	}
	var count uint8
	if prev != nil {
		count = prev.FailureCount
	}
	return applyJitter(exponentialBackoff(count))
}

// RecordAddressFailure records a failure for the given (address, transport)
// tuple and applies a backoff per the active BackoffPolicy. Routing-class
// errors get an immediate long backoff; everything else uses an exponential
// schedule based on the previous failure count for this tuple. If as.Debug is
// true, the error message is stored in LastError. Thread-safe.
func (as *AuthServer) RecordAddressFailure(addr string, t core.Transport, err error) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.AddressBackoffs == nil {
		as.AddressBackoffs = make(map[AddrXport]*AddressBackoff)
	}
	key := AddrXport{Addr: addr, Transport: t}
	backoff, exists := as.AddressBackoffs[key]
	errMsg := ""
	if as.Debug && err != nil {
		errMsg = err.Error()
	}
	if !exists {
		as.AddressBackoffs[key] = &AddressBackoff{
			NextTry:      time.Now().Add(categorizeError(err, nil)),
			FailureCount: 1,
			LastError:    errMsg,
		}
		return
	}
	backoff.NextTry = time.Now().Add(categorizeError(err, backoff))
	backoff.LastError = errMsg
	if backoff.FailureCount < 255 {
		backoff.FailureCount++
	}
}

// RecordAddressFailureForRcode records a failure for the given
// (address, transport) tuple based on a DNS response code. NOTIMP is treated
// as a "broken implementation" signal and gets the full LameDelegation
// backoff immediately. Other rcodes follow the standard exponential
// schedule. Thread-safe.
func (as *AuthServer) RecordAddressFailureForRcode(addr string, t core.Transport, rcode uint8) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.AddressBackoffs == nil {
		as.AddressBackoffs = make(map[AddrXport]*AddressBackoff)
	}
	key := AddrXport{Addr: addr, Transport: t}
	backoff, exists := as.AddressBackoffs[key]

	var backoffDuration time.Duration
	if rcode == dns.RcodeNotImplemented {
		backoffDuration = applyJitter(GetBackoffPolicy().LameDelegation)
	} else {
		var count uint8
		if exists {
			count = backoff.FailureCount
		}
		backoffDuration = applyJitter(exponentialBackoff(count))
	}
	errMsg := ""
	if as.Debug {
		errMsg = fmt.Sprintf("rcode=%d", rcode)
	}

	if !exists {
		as.AddressBackoffs[key] = &AddressBackoff{
			NextTry:      time.Now().Add(backoffDuration),
			FailureCount: 1,
			LastError:    errMsg,
		}
		return
	}
	backoff.NextTry = time.Now().Add(backoffDuration)
	if as.Debug {
		backoff.LastError = errMsg
	}
	if backoff.FailureCount < 255 {
		backoff.FailureCount++
	}
}

// RecordAddressSuccess clears any backoff for the given (address, transport)
// tuple. Thread-safe.
func (as *AuthServer) RecordAddressSuccess(addr string, t core.Transport) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.AddressBackoffs != nil {
		delete(as.AddressBackoffs, AddrXport{Addr: addr, Transport: t})
	}
}

// rttEMAAlpha is the smoothing factor for RTT EMA updates. Lower values
// react more slowly to changes; higher values are noisier. 0.25 gives
// each new sample 25% weight and 75% to the running average.
const rttEMAAlpha = 0.25

// rttDecayFactor is the per-pick decay applied to every OTHER tuple's
// EMA whenever RecordRTT is called for one tuple. Drives exploration:
// see the comment in RecordRTT. 0.98 (~2% per pick) gives a slow loser
// (200ms vs 20ms winner) ~114 picks of grace before it gets re-probed
// — fast enough to notice topology changes within a few minutes of
// steady traffic, slow enough to avoid thrashing.
const rttDecayFactor = 0.98

// RecordRTT folds a new observation into the running RTT estimate for the
// given (address, transport). Non-positive rtts are ignored. Thread-safe.
func (as *AuthServer) RecordRTT(addr string, t core.Transport, rtt time.Duration) {
	if as == nil || rtt <= 0 {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.RTTEstimates == nil {
		as.RTTEstimates = make(map[AddrXport]*RTTEstimate)
	}
	key := AddrXport{Addr: addr, Transport: t}
	r, ok := as.RTTEstimates[key]
	if !ok {
		r = &RTTEstimate{EMA: rtt, Samples: 1}
	} else {
		r.EMA = time.Duration(rttEMAAlpha*float64(rtt) + (1-rttEMAAlpha)*float64(r.EMA))
		if r.Samples < ^uint32(0) {
			r.Samples++
		}
	}
	r.LastSample = rtt
	r.LastSampleAt = time.Now()
	as.RTTEstimates[key] = r

	// Decay every OTHER tuple's EMA by rttDecayFactor. This is the
	// exploration mechanism: pure-greedy RTT sort would make a winning
	// tuple win forever, never re-probing its alternates even if they
	// have gotten faster (or the winner has gotten slower). Decaying
	// losers ~2% per pick of someone else means each loser's EMA drifts
	// toward zero at a rate proportional to traffic volume; once a
	// loser's decayed EMA dips below the winner's actual EMA, the sort
	// picks it, it gets a fresh sample, and the system either re-ranks
	// (it really did get faster) or partially restores its EMA via the
	// usual alpha=0.25 averaging (still slow — but now we know that
	// recently). Frequency of re-exploration auto-scales with query
	// rate: busy servers re-probe quickly, quiet ones slowly.
	for okey, or := range as.RTTEstimates {
		if okey == key {
			continue
		}
		or.EMA = time.Duration(float64(or.EMA) * rttDecayFactor)
	}
}

// GetRTT returns the smoothed RTT estimate for the given (address, transport)
// tuple, and ok=true if a usable sample exists. Samples older than the
// active BackoffPolicy.MaxFailure are treated as expired (ok=false) so the
// sort path re-probes them. Thread-safe.
func (as *AuthServer) GetRTT(addr string, t core.Transport) (time.Duration, bool) {
	if as == nil {
		return 0, false
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	r, ok := as.RTTEstimates[AddrXport{Addr: addr, Transport: t}]
	if !ok {
		return 0, false
	}
	if time.Since(r.LastSampleAt) > GetBackoffPolicy().MaxFailure {
		return 0, false
	}
	return r.EMA, true
}

// SnapshotRTTEstimates returns a copy of the RTT-estimate map. Useful for
// observability dumps. Thread-safe.
func (as *AuthServer) SnapshotRTTEstimates() map[AddrXport]*RTTEstimate {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.RTTEstimates) == 0 {
		return nil
	}
	snap := make(map[AddrXport]*RTTEstimate, len(as.RTTEstimates))
	for k, v := range as.RTTEstimates {
		snap[k] = &RTTEstimate{
			EMA:          v.EMA,
			Samples:      v.Samples,
			LastSample:   v.LastSample,
			LastSampleAt: v.LastSampleAt,
		}
	}
	return snap
}
