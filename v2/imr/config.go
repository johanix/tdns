/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"fmt"
	"os"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
)

// Config is RESOLVER behavior only. The listener keys (addresses,
// transports, certfile/keyfile) moved to the shared listeners: block (#446):
// tdns-imr's service listens there, and an embedded imr (tdns-auth,
// tdns-agent) is internal by design — its only listener is the loopback
// listeners.imr-debug-address window.
type Config struct {
	// Active is the daemon's (tdns's ImrEngine): if nil or true, the IMR is
	// active, and only false disables it. New does not read it.
	Active    *bool  `yaml:"active" mapstructure:"active"`
	RootHints string `yaml:"root-hints" mapstructure:"root-hints"` // Path to root hints file. If empty, uses compiled-in hints.
	// OutboundAddressFamilies is which address families the resolver sends its
	// queries to authoritative servers over: ipv4, ipv6, or both (the default).
	// What it listens on is listeners.addresses. See ParseAddressFamilies.
	OutboundAddressFamilies []string             `yaml:"outbound-address-families" mapstructure:"outbound-address-families"`
	Stubs                   []StubConf           `yaml:"stubs"`
	Forward                 []ForwardConf        `yaml:"forward" mapstructure:"forward"`
	OptionsStrs             []string             `yaml:"options" mapstructure:"options"`
	Options                 map[ImrOption]string `yaml:"-" mapstructure:"-"`
	// Trust anchors for recursive validation. Provide either DS or DNSKEY as
	// full RR text (zonefile format). DS is preferred as it is more convenient.
	// Both tags are load bearing, because the daemon's Config is decoded by two different
	// tag conventions: the daemon's decodeConfigMap sets TagName "yaml"
	// (parseconfig.go), while viper.Unmarshal -- used by config check and the
	// CLI roots -- keys off mapstructure and falls back to the field name.
	// With a yaml tag only, as these three had, the daemon read the key and
	// config check did not: checkImrTrustAnchors saw "" and reported "no
	// trust anchor configured" for a resolver that in fact had one.
	TrustAnchorDS     string `yaml:"trust-anchor-ds" mapstructure:"trust-anchor-ds"`
	TrustAnchorDNSKEY string `yaml:"trust-anchor-dnskey" mapstructure:"trust-anchor-dnskey"`
	// Unbound-style file with one RR per line (DNSKEY and/or DS). Absolute path.
	TrustAnchorFile string `yaml:"trust-anchor-file" mapstructure:"trust-anchor-file"`
	Verbose         bool
	Debug           bool
	Logging         LoggingConf `yaml:"logging" mapstructure:"logging"`
	// RequireDnssecValidation: when true (default), TLSA and other security-sensitive
	// records must have a secure DNSSEC validation state. Set to false to allow
	// indeterminate/insecure records during lab/development when the full DNSSEC
	// chain is not yet established.
	RequireDnssecValidation *bool `yaml:"require-dnssec-validation" mapstructure:"require-dnssec-validation"`
	// Tuning holds runtime-tunable behaviour knobs (backoff, RTT,
	// address-family tracking, discovery state, etc.). All fields
	// are optional in YAML; LoadTuningDefaults fills zero values.
	Tuning TuningConf `yaml:"tuning" mapstructure:"tuning"`
	// ClientStats: per-client transport counters (imr_client_stats.go).
	ClientStats ClientStatsConf `yaml:"client-stats" mapstructure:"client-stats"`
	// Testing holds switches for black-box test harnesses, not for production.
	// `config check` warns about any that is set. See
	// docs/2026-09-28-imr-deckard-test-clock-and-switches.md.
	Testing TestingConf `yaml:"testing" mapstructure:"testing"`
}

// TestingConf holds the resolver's test-harness switches.
type TestingConf struct {
	// Priming false seeds the cache from the root hints and marks it primed,
	// without the live ". NS" query. A harness such as Deckard starts its
	// scripted servers only once the resolver accepts connections, and the
	// resolver listens only once priming has succeeded: without this switch it
	// never becomes ready there.
	Priming *bool `yaml:"priming" mapstructure:"priming"`

	// Faketime makes the resolver's data time -- what signatures, cache
	// expiry and served TTLs are measured against -- a test clock read from
	// a libfaketime timestamp file: $FAKETIME_TIMESTAMP_FILE, or FaketimeFile.
	// Deckard fakes the time this way, and libfaketime cannot reach a Go
	// binary. Timeouts, backoffs and RTTs stay on real time.
	Faketime bool `yaml:"faketime" mapstructure:"faketime"`
	// FaketimeFile names the timestamp file, and turns the test clock on.
	FaketimeFile string `yaml:"faketime-file" mapstructure:"faketime-file"`

	// RootRefresh false stops the refresh of the root NS before it expires.
	// The test clock implies it: the refresh waits in real time for an
	// expiry stamped in data time.
	RootRefresh *bool `yaml:"root-refresh" mapstructure:"root-refresh"`
}

// SkipPriming reports whether testing.priming is set to false.
func (t TestingConf) SkipPriming() bool { return t.Priming != nil && !*t.Priming }

// FaketimeOn reports whether the test clock is configured.
func (t TestingConf) FaketimeOn() bool { return t.Faketime || t.FaketimeFile != "" }

// FaketimePath is the timestamp file the test clock reads: faketime-file, or
// else $FAKETIME_TIMESTAMP_FILE.
func (t TestingConf) FaketimePath() string {
	if t.FaketimeFile != "" {
		return t.FaketimeFile
	}
	return os.Getenv("FAKETIME_TIMESTAMP_FILE")
}

// SkipRootRefresh reports whether the root NS refresh is off: root-refresh is
// false, or the test clock is on.
func (t TestingConf) SkipRootRefresh() bool {
	return t.FaketimeOn() || (t.RootRefresh != nil && !*t.RootRefresh)
}

// Validate refuses a root refresh asked for beside the test clock, which
// cannot run it.
func (t TestingConf) Validate() error {
	if t.FaketimeOn() && t.RootRefresh != nil && *t.RootRefresh {
		return fmt.Errorf("root-refresh: true cannot be combined with faketime: the refresh waits in real time for an expiry in data time")
	}
	return nil
}

// ClientStatsConf switches the per-client transport counters on. They
// record client addresses, so they are off by default. They are set up with
// the listeners, at startup: changing Enabled needs a restart, not a reload.
type ClientStatsConf struct {
	Enabled    bool `yaml:"enabled" mapstructure:"enabled"`
	MaxClients int  `yaml:"max-clients" mapstructure:"max-clients"` // 0: DefaultClientStatsMax
}

// Validate refuses a negative max-clients rather than taking it for the
// default: a sign typo should not quietly become 4096.
func (c ClientStatsConf) Validate() error {
	if c.MaxClients < 0 {
		return fmt.Errorf("imrengine.client-stats.max-clients: %d is negative; use 0 for the default (%d)", c.MaxClients, DefaultClientStatsMax)
	}
	return nil
}

// TuningConf holds runtime-tunable behaviour knobs for the IMR.
// Fields are exposed as YAML / mapstructure for config files;
// LoadTuningDefaults fills zero values with sensible defaults so
// callers can just embed an empty TuningConf and have it work.
type TuningConf struct {
	Backoff       BackoffConf       `yaml:"backoff" mapstructure:"backoff"`
	AddressFamily AddressFamilyConf `yaml:"address-family" mapstructure:"address-family"`
	Discovery     DiscoveryConf     `yaml:"discovery" mapstructure:"discovery"`
	QueryBudget   time.Duration     `yaml:"query-budget" mapstructure:"query-budget"`
	// UpgradeIndirectCacheHits controls whether cache hits with an
	// indirect context (Glue, Referral, Hint) trigger a fresh query
	// to "upgrade" the data quality. nil = legacy behaviour (true).
	// tdns-mp overrides this to false in its default config to cut
	// gossip-driven query volume.
	UpgradeIndirectCacheHits *bool `yaml:"upgrade-indirect-cache-hits" mapstructure:"upgrade-indirect-cache-hits"`
	// CacheMaxTTL and CacheMinTTL bound, in seconds, how long data learned
	// from the network stays in the cache -- and so the TTL clients are
	// served. Same names, units and defaults as Unbound: max 86400, min 0 (no
	// floor). Seconds rather than a duration because they are TTLs, and so an
	// unbound.conf value can be copied as it stands. When min > max, max wins.
	CacheMaxTTL uint32 `yaml:"cache-max-ttl" mapstructure:"cache-max-ttl"`
	CacheMinTTL uint32 `yaml:"cache-min-ttl" mapstructure:"cache-min-ttl"`
	// ZoneStateRecheck is how long a zone's Indeterminate or Insecure
	// validation state stands before the resolver looks at the zone again: an
	// Indeterminate zone has its chain followed afresh, an Insecure one has its
	// parent asked for a DS. Default 30s. See cache.ZoneStateRecheck.
	ZoneStateRecheck time.Duration `yaml:"zone-state-recheck" mapstructure:"zone-state-recheck"`
	// NSEC3MaxIterations is the most NSEC3 hash iterations the validator
	// computes a proof for (RFC 9276 section 3.2). A denial that needs NSEC3
	// records above it is served without AD, with EDE 27; a zone cut they
	// would prove is not judged. Default 10 (cache.DefaultNSEC3MaxIterations);
	// 0 is allowed, and then only zones with no extra iterations validate.
	NSEC3MaxIterations *uint16 `yaml:"nsec3-max-iterations" mapstructure:"nsec3-max-iterations"`
}

// DefaultCacheMaxTTL is Unbound's cache-max-ttl default: one day.
const DefaultCacheMaxTTL = 86400

// defaultDiscoveryStrictWait is the default of DiscoveryConf.StrictWait.
const defaultDiscoveryStrictWait = 2 * time.Second

// BackoffConf tunes per-(address, transport) backoff behaviour
// after a failed query. Replaces the hardcoded 2 min / 1 h constants
// that lived in cache/authserver.go.
type BackoffConf struct {
	FirstFailure   time.Duration `yaml:"first-failure" mapstructure:"first-failure"`
	MaxFailure     time.Duration `yaml:"max-failure" mapstructure:"max-failure"`
	Multiplier     float64       `yaml:"multiplier" mapstructure:"multiplier"`
	JitterFraction float64       `yaml:"jitter-fraction" mapstructure:"jitter-fraction"`
	RoutingFailure time.Duration `yaml:"routing-failure" mapstructure:"routing-failure"`
	LameDelegation time.Duration `yaml:"lame-delegation" mapstructure:"lame-delegation"`
}

// AddressFamilyConf tunes per-process IPv4/IPv6 reachability
// tracking (deprioritise a family after N distinct failures in a
// sliding window, probe periodically to detect recovery).
type AddressFamilyConf struct {
	WindowDuration   time.Duration `yaml:"window-duration" mapstructure:"window-duration"`
	FailureThreshold int           `yaml:"failure-threshold" mapstructure:"failure-threshold"`
	SuspectDuration  time.Duration `yaml:"suspect-duration" mapstructure:"suspect-duration"`
	ProbeInterval    time.Duration `yaml:"probe-interval" mapstructure:"probe-interval"`
}

// DiscoveryConf tunes the discovery state machine used for
// transport-signal (SVCB / TSYNC) and TLSA lookups, replacing
// the fire-and-forget goroutine pattern.
type DiscoveryConf struct {
	RetryAfterFailure time.Duration `yaml:"retry-after-failure" mapstructure:"retry-after-failure"`
	MaxFailures       int           `yaml:"max-failures" mapstructure:"max-failures"`
	// StrictWait bounds how long a query waits for the transport signals
	// of servers it knows nothing about, before it gives up on them: a
	// strict-privacy query, or any query left with no transport it may use
	// (#1065). The query's own deadline cuts it shorter. Default 2s.
	StrictWait time.Duration `yaml:"strict-wait" mapstructure:"strict-wait"`
}

// LoadTuningDefaults fills missing or invalid fields with sensible
// defaults. Any non-positive duration, zero/negative integer count,
// or out-of-range Multiplier / JitterFraction is treated as "unset"
// and replaced, and an absent NSEC3MaxIterations gets the default. 0 is a
// valid NSEC3MaxIterations, so it is a pointer. UpgradeIndirectCacheHits is
// left nil intentionally —
// callers check nil-vs-explicit to distinguish "use legacy
// behaviour" from an explicit toggle. Safe to call repeatedly.
func LoadTuningDefaults(t *TuningConf) {
	if t == nil {
		return
	}
	// Backoff
	if t.Backoff.FirstFailure <= 0 {
		t.Backoff.FirstFailure = 15 * time.Second
	}
	if t.Backoff.MaxFailure <= 0 {
		t.Backoff.MaxFailure = 1 * time.Hour
	}
	if t.Backoff.MaxFailure < t.Backoff.FirstFailure {
		// Configured MaxFailure shorter than FirstFailure is nonsense;
		// clamp upward so categorizeError can never produce a backoff
		// shorter than the first-attempt baseline.
		t.Backoff.MaxFailure = t.Backoff.FirstFailure
	}
	if t.Backoff.Multiplier <= 0 {
		t.Backoff.Multiplier = 3.0
	}
	if t.Backoff.JitterFraction < 0 || t.Backoff.JitterFraction >= 1 {
		t.Backoff.JitterFraction = 0.25
	}
	if t.Backoff.RoutingFailure <= 0 {
		t.Backoff.RoutingFailure = 1 * time.Hour
	}
	if t.Backoff.LameDelegation <= 0 {
		// RFC 9520 section 3.2: a resolution failure MUST NOT be cached for
		// longer than 5 minutes, and a shunned zone server is exactly that.
		t.Backoff.LameDelegation = 5 * time.Minute
	}
	// AddressFamily
	if t.AddressFamily.WindowDuration <= 0 {
		t.AddressFamily.WindowDuration = 10 * time.Minute
	}
	if t.AddressFamily.FailureThreshold <= 0 {
		t.AddressFamily.FailureThreshold = 5
	}
	if t.AddressFamily.SuspectDuration <= 0 {
		t.AddressFamily.SuspectDuration = 10 * time.Minute
	}
	if t.AddressFamily.ProbeInterval <= 0 {
		t.AddressFamily.ProbeInterval = 30 * time.Second
	}
	// Discovery
	if t.Discovery.RetryAfterFailure <= 0 {
		t.Discovery.RetryAfterFailure = 30 * time.Second
	}
	if t.Discovery.MaxFailures <= 0 {
		t.Discovery.MaxFailures = 3
	}
	if t.Discovery.StrictWait <= 0 {
		t.Discovery.StrictWait = defaultDiscoveryStrictWait
	}
	// QueryBudget
	if t.QueryBudget <= 0 {
		t.QueryBudget = 8 * time.Second
	}
	// Cache TTL bounds. Zero min is the default (no floor), so only max needs
	// filling. A floor above the ceiling is lowered to it: Unbound applies
	// the ceiling last, so max is what wins there too.
	if t.CacheMaxTTL == 0 {
		t.CacheMaxTTL = DefaultCacheMaxTTL
	}
	if t.CacheMinTTL > t.CacheMaxTTL {
		t.CacheMinTTL = t.CacheMaxTTL
	}
	if t.ZoneStateRecheck <= 0 {
		t.ZoneStateRecheck = cache.DefaultZoneStateRecheck
	}
	if t.NSEC3MaxIterations == nil {
		n := uint16(cache.DefaultNSEC3MaxIterations)
		t.NSEC3MaxIterations = &n
	}
}

type LoggingConf struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	File    string `yaml:"file" mapstructure:"file"`
}

type StubConf struct {
	Zone string `validate:"required"`
	// Servers []StubServerConf `validate:"required"`
	Servers []cache.AuthServer `validate:"required"`
}

// ForwardConf declares a forward zone: queries for names at or below Zone
// are sent as recursive queries (RD=1) to the configured upstream resolvers
// instead of being resolved iteratively. "zone: ." forwards everything.
// A configured stub zone that is more specific than the matching forward
// zone takes precedence for names under it.
type ForwardConf struct {
	Zone string `yaml:"zone" mapstructure:"zone" validate:"required"`
	// TrustAD: accept the upstream's AD bit instead of validating the
	// answer locally. For a trusted, validating upstream — and because a
	// spoofed AD bit would be cached as Secure, it REQUIRES every upstream
	// of the zone to be encrypted and verified (dot/doh/doq without
	// insecure); the daemon refuses to start otherwise.
	TrustAD   bool           `yaml:"trust-ad" mapstructure:"trust-ad"`
	Upstreams []UpstreamConf `yaml:"upstreams" mapstructure:"upstreams" validate:"required"`
}

// UpstreamConf is one upstream resolver of a forward zone. Addr is a bare
// IP literal; Port defaults to the transport's standard port (53/853/443);
// Transport is one of do53 (UDP with TCP fallback), tcp, dot, doh, doq and
// defaults to do53.
type UpstreamConf struct {
	Addr      string `yaml:"addr" mapstructure:"addr" validate:"required"`
	Port      uint16 `yaml:"port" mapstructure:"port"`
	Transport string `yaml:"transport" mapstructure:"transport"`
	// TLSServerName is the name the upstream's certificate is verified
	// against (and sent as SNI). Only meaningful for dot/doh/doq; when
	// empty the certificate must carry the Addr IP in a SAN.
	TLSServerName string `yaml:"tls-server-name" mapstructure:"tls-server-name"`
	// Insecure disables certificate verification for this upstream
	// (lab setups with self-signed certificates). Only meaningful for
	// dot/doh/doq.
	Insecure bool `yaml:"insecure" mapstructure:"insecure"`
	// CAFile is the trust anchor this upstream's certificate is verified
	// against, replacing the host's system trust store for this upstream
	// only. Only meaningful for dot/doh/doq.
	//
	// Unset is not "no verification" -- it leaves tls.Config.RootCAs nil,
	// which is the system store. That remains the right answer when the
	// upstream has a publicly-issued certificate; ca-file is for the case
	// the system store cannot cover, a private CA, without making the whole
	// machine trust it. Same spelling as PeerConf.CAFile, deliberately:
	// this is the same question asked of a different kind of peer.
	CAFile string `yaml:"ca-file" mapstructure:"ca-file"`
}

// DefaultClientStatsMax is imrengine.client-stats.max-clients when unset.
const DefaultClientStatsMax = 4096

// imrTestingEqual reports whether two testing blocks ask for the same thing.
func imrTestingEqual(a, b TestingConf) bool {
	sameBool := func(x, y *bool) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	return sameBool(a.Priming, b.Priming) && sameBool(a.RootRefresh, b.RootRefresh) &&
		a.Faketime == b.Faketime && a.FaketimeFile == b.FaketimeFile
}
