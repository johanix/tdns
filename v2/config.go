/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
)

var Conf Config

// confMu protects Conf and Globals during config reload operations.
// Reload paths take the write lock; they replace whole maps/slices
// (e.g. Conf.Internal.DnssecPolicies, Conf.Zones) wholesale. Readers that
// can run concurrently with a reload — notably API handlers — must take
// the read lock around those accesses: a bare read racing a map/slice
// reassignment is a data race, not merely a partial-state read. Reads on
// startup-only paths (no concurrent reload) need not lock.
var confMu sync.RWMutex

// SensitiveString wraps a string that should not appear in logs.
// Use .Value() to get the actual string; String() returns a redacted form.
type SensitiveString string

// Value returns the actual string value.
func (s SensitiveString) Value() string {
	return string(s)
}

// String returns a redacted representation for safe logging.
func (s SensitiveString) String() string {
	if len(s) == 0 {
		return ""
	}
	return "[REDACTED]"
}

type Config struct {
	Service      ServiceConf
	DnsEngine    DnsEngineConf
	Imr          ImrEngineConf `yaml:"imrengine" mapstructure:"imrengine"`
	ApiServer    ApiServerConf
	MultiSigner  map[string]MultiSignerConf `yaml:"multisigner"`
	Catalog      *CatalogConf               `yaml:"catalog" mapstructure:"catalog"`
	DynamicZones DynamicZonesConf           `yaml:"dynamiczones" mapstructure:"dynamiczones"`
	Zones        []ZoneConf                 `yaml:"zones"`
	Templates    []ZoneConf                 `yaml:"templates"`
	// Peers is the top-level peers: block — one declaration per remote
	// server, referenced from upstreams:/notify:/downstreams:/allow-notify:
	// as `- peers: [ id, ... ]` entries (docs/2026-07-21-peers-xfr-auth-design.md).
	Peers map[string]PeerDef `yaml:"peers" mapstructure:"peers"`
	Dnssec       DnssecConf                 `yaml:"dnssec" mapstructure:"dnssec"`
	Keys         KeyConf                    `yaml:"keys" mapstructure:"keys"`
	Db           DbConf
	Registrars   map[string][]string
	Log          LogConf
	Internal     InternalConf
}

// DnssecConf holds DNSSEC-wide settings consumed by the signer and IMR.
type DnssecConf struct {
	// LargeAlgorithms lists the DNSSEC algorithms whose DNSKEY/RRSIG sizes are
	// large for UDP. The IMR may query child DNSKEY over TCP when a parent DS
	// uses one; the signer warns if one signs the bulk of a zone. Each entry is
	// an algorithm NAME (e.g. "RSASHA512", "MLDSA44") or a name prefix with a
	// trailing "*" (e.g. "MLDSA*", "SNOVA*") matching a whole family. Names, not
	// codepoints, because non-standardized PQ codepoints are assigned per
	// deployment at runtime by algorithms.Register — a bare codepoint could mean
	// different algorithms on the IMR and the signer. Matching is
	// case-insensitive and resolves against the algorithm metadata registry, so
	// a name or family this binary recognizes but cannot itself sign with still
	// counts; an entry that matches no known algorithm is a hard config error.
	LargeAlgorithms []string `yaml:"large_algorithms" mapstructure:"large_algorithms"`

	// SplitAlgorithms gates which KSK/ZSK algorithm pairs a policy may use.
	// Keyed by KSK algorithm name; the value lists ZSK algorithm names that
	// algorithm's KSK is permitted to pair with. A policy whose KSK and ZSK
	// algorithms differ is rejected at parse time unless the pair appears
	// here. Same-algorithm policies are always allowed and need no entry.
	SplitAlgorithms map[string][]string `yaml:"split_algorithms" mapstructure:"split_algorithms"`

	// Templates are named, partial DNSSEC policies. A policy may set
	// `template: <name>` to inherit (deep-merge) the gaps in its own definition
	// from the named template here; the policy's own values always win.
	// Templates are not registered as usable policies themselves.
	// YAML: dnssec.templates:.
	Templates map[string]DnssecPolicyConf `yaml:"templates" mapstructure:"templates"`

	// Policies are the named DNSSEC policies a zone references via its
	// dnssec_policy field. YAML: dnssec.policies:.
	Policies map[string]DnssecPolicyConf `yaml:"policies" mapstructure:"policies"`

	// Kasp is the Key and Signing Policy controlling the KeyStateWorker.
	// YAML: dnssec.kasp:.
	Kasp KaspConf `yaml:"kasp" mapstructure:"kasp"`

	// Completeness selects the signer's RFC 4035 §2.2 completeness mode,
	// deployment-wide (NOT per-zone/per-policy — see the algorithm-rollover
	// design doc §4.4). "strict" (default) honors completeness: a ZSK
	// algorithm rollover keeps the old-algorithm key signing through the
	// drain window (maintained double-signature). "relaxed" (alg-split
	// regime) drops the old key at the switch (drain only, no maintained
	// double-signature) — sound because completeness binds the signer, not
	// the validator. The mode also selects the standby-counting discipline
	// for a ZSK roll (role-only vs per-(role,algorithm)). Empty = strict.
	// YAML: dnssec.completeness:.
	Completeness string `yaml:"completeness" mapstructure:"completeness"`
}

// DNSSEC completeness modes (Conf.Internal.Completeness / dnssec.completeness).
const (
	CompletenessStrict  = "strict"
	CompletenessRelaxed = "relaxed"
)

// KaspConf holds Key and Signing Policy parameters for the signer.
// Controls the KeyStateWorker's automatic key state transitions and standby key maintenance.
// YAML key: "dnssec.kasp:"
//
// Example:
//
//	dnssec:
//	    kasp:
//	        propagation_delay: 1h
//	        standby_zsk_count: 1
//	        standby_ksk_count: 0
//	        check_interval: 1m
type KaspConf struct {
	// PropagationDelay is how long to wait for DNSKEY RRsets to propagate
	// through all caches before allowing state transitions.
	// Used for published→standby and retired→removed transitions.
	// Accepts Go duration strings: "1h", "3600s", "90m".
	// Default: "1h".
	PropagationDelay string `yaml:"propagation_delay" mapstructure:"propagation_delay"`

	// StandbyZskCount is the number of standby ZSKs to maintain per zone.
	// When the count drops below this, the KeyStateWorker generates new ZSKs.
	// Default: 1. A value of 0 (or omitted) means use the default.
	StandbyZskCount int `yaml:"standby_zsk_count" mapstructure:"standby_zsk_count"`

	// StandbyKskCount is the number of standby KSKs to maintain per zone.
	// When the count drops below this, the KeyStateWorker generates new KSKs.
	// Default: 0 (no standby KSKs). Set to 1+ to enable standby KSK maintenance.
	StandbyKskCount int `yaml:"standby_ksk_count" mapstructure:"standby_ksk_count"`

	// CheckInterval is how often the KeyStateWorker runs its checks.
	// Accepts Go duration strings: "1m", "60s", "5m".
	// Default: "1m".
	CheckInterval string `yaml:"check_interval" mapstructure:"check_interval"`
}

type AppDetails struct {
	Name             string
	Version          string
	Type             AppType
	Date             string
	ServerBootTime   time.Time
	ServerConfigTime time.Time
}

type LogConf struct {
	File       string            `yaml:"file" validate:"required"`
	Level      string            `yaml:"level"`      // "debug"|"info"|"warn"|"error"; default "info"
	Subsystems map[string]string `yaml:"subsystems"` // per-subsystem level overrides
}

type ServiceConf struct {
	Name       string `validate:"required"`
	Debug      *bool
	Verbose    *bool
	Identities []string      // this is a strawman attempt at deciding on what name to publish the ALPN
	Transport  TransportConf `yaml:"transport"`
}

type TransportConf struct {
	Type   string `yaml:"type" validate:"omitempty,oneof=tsync svcb none"`
	Signal string `yaml:"signal"`
}

type DnsEngineConf struct {
	Addresses   []string              `yaml:"addresses" validate:"required"`
	CertFile    string                `yaml:"certfile,omitempty"`
	KeyFile     string                `yaml:"keyfile,omitempty"`
	Transports  []string              `yaml:"transports" validate:"required,min=1,dive,oneof=do53 dot doh doq"` // "do53", "dot", "doh", "doq"
	OptionsStrs []string              `yaml:"options" mapstructure:"options"`
	Options     map[AuthOption]string `yaml:"-" mapstructure:"-"`
	// NOTE: there is deliberately NO listener-level client-cert policy here.
	// Transfer authentication is per-zone (downstream-auth: + peers
	// tls-identity, enforced at transfer time); dropping non-TLS traffic is
	// transports:. The auth DoT listener always REQUESTS (never requires) a
	// client certificate. See docs/2026-07-21-peers-xfr-auth-design.md D6.
	// OutboundSoaSerial controls the SOA serial advertised on outbound zone
	// transfers and NOTIFYs. One of:
	//   keep     — outbound = inbound serial (default; current behavior).
	//   unixtime — outbound = time.Now().Unix() at parse.
	//   persist  — outbound = previously-saved outbound serial (from the
	//              OutgoingSerials DB table). Every BumpSerial writes the
	//              new value back. On clean restart with no zone change,
	//              the serial stays put — secondaries don't see a regression
	//              and don't trigger an unnecessary AXFR.
	OutboundSoaSerial string `yaml:"outbound_soa_serial,omitempty" mapstructure:"outbound_soa_serial" validate:"omitempty,oneof=keep unixtime persist"`
}

type ImrEngineConf struct {
	Active      *bool                `yaml:"active" mapstructure:"active"`         // If nil or true, IMR is active. Only false explicitly disables it.
	RootHints   string               `yaml:"root-hints" mapstructure:"root-hints"` // Path to root hints file. If empty, uses compiled-in hints.
	Addresses   []string             `yaml:"addresses" mapstructure:"addresses" validate:"required"`
	CertFile    string               `yaml:"certfile" mapstructure:"certfile"`
	KeyFile     string               `yaml:"keyfile" mapstructure:"keyfile"`
	Transports  []string             `yaml:"transports" mapstructure:"transports" validate:"required"` // "do53", "dot", "doh", "doq"
	Stubs       []ImrStubConf        `yaml:"stubs"`
	OptionsStrs []string             `yaml:"options" mapstructure:"options"`
	Options     map[ImrOption]string `yaml:"-" mapstructure:"-"`
	// Trust anchors for recursive validation. Provide either DS or DNSKEY as
	// full RR text (zonefile format). DS is preferred as it is more convenient.
	TrustAnchorDS     string `yaml:"trust_anchor_ds"`
	TrustAnchorDNSKEY string `yaml:"trust_anchor_dnskey"`
	// Unbound-style file with one RR per line (DNSKEY and/or DS). Absolute path.
	TrustAnchorFile string `yaml:"trust-anchor-file"`
	Verbose         bool
	Debug           bool
	Logging         ImrLoggingConf `yaml:"logging" mapstructure:"logging"`
	// RequireDnssecValidation: when true (default), TLSA and other security-sensitive
	// records must have a secure DNSSEC validation state. Set to false to allow
	// indeterminate/insecure records during lab/development when the full DNSSEC
	// chain is not yet established.
	RequireDnssecValidation *bool `yaml:"require_dnssec_validation" mapstructure:"require_dnssec_validation"`
	// Tuning holds runtime-tunable behaviour knobs (backoff, RTT,
	// address-family tracking, discovery state, etc.). All fields
	// are optional in YAML; LoadImrTuningDefaults fills zero values.
	Tuning ImrTuningConf `yaml:"tuning" mapstructure:"tuning"`
}

// ImrTuningConf holds runtime-tunable behaviour knobs for the IMR.
// Fields are exposed as YAML / mapstructure for config files;
// LoadImrTuningDefaults fills zero values with sensible defaults so
// callers can just embed an empty ImrTuningConf and have it work.
type ImrTuningConf struct {
	Backoff       BackoffConf       `yaml:"backoff" mapstructure:"backoff"`
	AddressFamily AddressFamilyConf `yaml:"address_family" mapstructure:"address_family"`
	Discovery     DiscoveryConf     `yaml:"discovery" mapstructure:"discovery"`
	QueryBudget   time.Duration     `yaml:"query_budget" mapstructure:"query_budget"`
	// UpgradeIndirectCacheHits controls whether cache hits with an
	// indirect context (Glue, Referral, Hint) trigger a fresh query
	// to "upgrade" the data quality. nil = legacy behaviour (true).
	// tdns-mp overrides this to false in its default config to cut
	// gossip-driven query volume.
	UpgradeIndirectCacheHits *bool `yaml:"upgrade_indirect_cache_hits" mapstructure:"upgrade_indirect_cache_hits"`
}

// BackoffConf tunes per-(address, transport) backoff behaviour
// after a failed query. Replaces the hardcoded 2 min / 1 h constants
// that lived in cache/authserver.go.
type BackoffConf struct {
	FirstFailure   time.Duration `yaml:"first_failure" mapstructure:"first_failure"`
	MaxFailure     time.Duration `yaml:"max_failure" mapstructure:"max_failure"`
	Multiplier     float64       `yaml:"multiplier" mapstructure:"multiplier"`
	JitterFraction float64       `yaml:"jitter_fraction" mapstructure:"jitter_fraction"`
	RoutingFailure time.Duration `yaml:"routing_failure" mapstructure:"routing_failure"`
	LameDelegation time.Duration `yaml:"lame_delegation" mapstructure:"lame_delegation"`
}

// AddressFamilyConf tunes per-process IPv4/IPv6 reachability
// tracking (deprioritise a family after N distinct failures in a
// sliding window, probe periodically to detect recovery).
type AddressFamilyConf struct {
	WindowDuration   time.Duration `yaml:"window_duration" mapstructure:"window_duration"`
	FailureThreshold int           `yaml:"failure_threshold" mapstructure:"failure_threshold"`
	SuspectDuration  time.Duration `yaml:"suspect_duration" mapstructure:"suspect_duration"`
	ProbeInterval    time.Duration `yaml:"probe_interval" mapstructure:"probe_interval"`
}

// DiscoveryConf tunes the discovery state machine used for
// transport-signal (SVCB / TSYNC) and TLSA lookups, replacing
// the fire-and-forget goroutine pattern.
type DiscoveryConf struct {
	RetryAfterFailure time.Duration `yaml:"retry_after_failure" mapstructure:"retry_after_failure"`
	MaxFailures       int           `yaml:"max_failures" mapstructure:"max_failures"`
}

// LoadImrTuningDefaults fills missing or invalid fields with sensible
// defaults. Any non-positive duration, zero/negative integer count,
// or out-of-range Multiplier / JitterFraction is treated as "unset"
// and replaced. UpgradeIndirectCacheHits is left nil intentionally —
// callers check nil-vs-explicit to distinguish "use legacy
// behaviour" from an explicit toggle. Safe to call repeatedly.
func LoadImrTuningDefaults(t *ImrTuningConf) {
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
		t.Backoff.LameDelegation = 1 * time.Hour
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
	// QueryBudget
	if t.QueryBudget <= 0 {
		t.QueryBudget = 8 * time.Second
	}
}

type ImrLoggingConf struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	File    string `yaml:"file" mapstructure:"file"`
}
type ImrStubConf struct {
	Zone string `validate:"required"`
	// Servers []StubServerConf `validate:"required"`
	Servers []cache.AuthServer `validate:"required"`
}

// type StubServerConf struct {
// 	Name  string   `validate:"required"`
// 	Addrs []string `validate:"required"`
// 	Alpn  []string `validate:"required"`
// }

type ApiServerConf struct {
	Addresses []string        `validate:"required"` // Must be in addr:port format
	ApiKey    SensitiveString `validate:"required"`
	CertFile  string          `validate:"required,file,certkey"`
	KeyFile   string          `validate:"required,file"`
	UseTLS    bool
	Server    ApiServerAppConf
	Agent     ApiServerAppConf
	// MSA       ApiServerAppConf
	Combiner ApiServerAppConf
}

type ApiServerAppConf struct {
	Addresses []string
	ApiKey    SensitiveString
}

type DbConf struct {
	File string // `validate:"required"`
}

// CatalogConf defines configuration for catalog zone support (RFC 9432)
type CatalogConf struct {
	GroupPrefixes GroupPrefixesConf             `yaml:"group_prefixes" mapstructure:"group_prefixes"`
	Policy        CatalogPolicy                 `yaml:"policy" mapstructure:"policy"` // Deprecated, kept for backward compatibility
	ConfigGroups  map[string]*ConfigGroupConfig `yaml:"config_groups" mapstructure:"config_groups"`
	MetaGroups    map[string]*ConfigGroupConfig `yaml:"meta_groups" mapstructure:"meta_groups"` // Deprecated, kept for backward compatibility
	SigningGroups map[string]*SigningGroupInfo  `yaml:"signing_groups" mapstructure:"signing_groups"`
}

// CatalogPolicy defines policy for how catalog zones are processed
type CatalogPolicy struct {
	Zones struct {
		Add    string `yaml:"add" mapstructure:"add" validate:"omitempty,oneof=auto manual"`       // "auto" or "manual"
		Remove string `yaml:"remove" mapstructure:"remove" validate:"omitempty,oneof=auto manual"` // "auto" or "manual"
	} `yaml:"zones" mapstructure:"zones"`
	// Note: conflict_resolution is hardcoded to "manual-priority", not configurable
}

// GroupPrefixesConf defines prefixes that identify special group types in catalog zones
type GroupPrefixesConf struct {
	Config  string `yaml:"config" mapstructure:"config" validate:"required"`   // Prefix for config/transfer groups, or "none" to disable
	Signing string `yaml:"signing" mapstructure:"signing" validate:"required"` // Prefix for signing groups, or "none" to disable
}

// ConfigGroupConfig provides configuration for zone transfers from catalog config groups (RFC 9432 terminology)
type ConfigGroupConfig struct {
	Name     string   `yaml:"-" mapstructure:"-"` // Populated from map key
	Upstream string   `yaml:"upstream" mapstructure:"upstream"`
	TsigKey  string   `yaml:"tsig_key" mapstructure:"tsig_key"`
	Store    string   `yaml:"store" mapstructure:"store"`
	Options  []string `yaml:"options" mapstructure:"options"`
}

// MetaGroupConfig is deprecated, use ConfigGroupConfig instead
type MetaGroupConfig = ConfigGroupConfig

// SigningGroupInfo provides documentation for signing groups (RFC 9432 terminology)
type SigningGroupInfo struct {
	Description string `yaml:"description" mapstructure:"description"`
}

// DynamicZonesConf defines configuration for dynamically created zones (catalog zones, catalog members, etc.)
type DynamicZonesConf struct {
	ConfigFile     string                   `yaml:"configfile" mapstructure:"configfile"`           // Absolute path to dynamic config file
	ZoneDirectory  string                   `yaml:"zonedirectory" mapstructure:"zonedirectory"`     // Absolute path to zone file directory
	CatalogZones   DynamicZoneTypeConf      `yaml:"catalog_zones" mapstructure:"catalog_zones"`     // Configuration for catalog zones
	CatalogMembers DynamicCatalogMemberConf `yaml:"catalog_members" mapstructure:"catalog_members"` // Configuration for catalog member zones
	Dynamic        DynamicZoneTypeConf      `yaml:"dynamic" mapstructure:"dynamic"`                 // Configuration for direct API-created zones (future)
}

// DynamicZoneTypeConf defines configuration for a type of dynamic zone
type DynamicZoneTypeConf struct {
	Allowed bool   `yaml:"allowed" mapstructure:"allowed"`                                              // Whether this type of zone is allowed
	Storage string `yaml:"storage" mapstructure:"storage" validate:"omitempty,oneof=memory persistent"` // "memory" or "persistent"
}

// DynamicCatalogMemberConf defines configuration for catalog member zones (includes add/remove policy)
type DynamicCatalogMemberConf struct {
	Allowed bool   `yaml:"allowed" mapstructure:"allowed"`                                              // Whether catalog member zones are allowed
	Storage string `yaml:"storage" mapstructure:"storage" validate:"omitempty,oneof=memory persistent"` // "memory" or "persistent"
	Add     string `yaml:"add" mapstructure:"add" validate:"omitempty,oneof=auto manual"`               // "auto" or "manual" - Enable auto-configuration from catalog
	Remove  string `yaml:"remove" mapstructure:"remove" validate:"omitempty,oneof=auto manual"`         // "auto" or "manual" - Whether to remove zones when deleted from catalog
}

// InternalDnsConf holds DNS-specific internal state: channels, handlers,
// caches, and engine references. Stays in tdns after repo split.
type InternalDnsConf struct {
	CfgFile             string //
	DebugMode           bool   // if true, may activate dangerous tests
	ZonesCfgFile        string //
	CertData            string // PEM encoded certificate
	KeyData             string // PEM encoded key
	KeyDB               *KeyDB
	AllZones            []string
	DnssecPolicies      map[string]DnssecPolicy
	StopCh              chan struct{}
	APIStopCh           chan struct{}
	StopOnce            sync.Once
	RefreshZoneCh       chan ZoneRefresher
	BumpZoneCh          chan BumperData
	ValidatorCh         chan ValidatorRequest
	RecursorCh          chan ImrRequest
	ScannerQ            chan ScanRequest
	UpdateQ             chan UpdateRequest
	DnsUpdateQ          chan DnsUpdateRequest
	DnsNotifyQ          chan DnsNotifyRequest
	DnsQueryQ           chan DnsQueryRequest           // Optional: if nil, queries use direct call to QueryResponder
	QueryHandlers       map[uint16][]QueryHandlerFunc  // qtype -> list of handlers (registered via RegisterQueryHandler)
	QueryHandlersMutex  sync.RWMutex                   // protects QueryHandlers map
	NotifyHandlers      map[uint16][]NotifyHandlerFunc // qtype -> list of handlers (registered via RegisterNotifyHandler, 0 = all NOTIFYs)
	NotifyHandlersMutex sync.RWMutex                   // protects NotifyHandlers map
	UpdateHandlers      []UpdateHandlerRegistration    // UPDATE handlers (registered via RegisterUpdateHandler)
	UpdateHandlersMutex sync.RWMutex                   // protects UpdateHandlers slice
	DelegationSyncQ     chan DelegationSyncRequest
	NotifyQ             chan NotifyRequest
	AuthQueryQ          chan AuthQueryRequest
	ResignQ             chan *ZoneData     // the names of zones that should be kept re-signed should be sent into this channel
	RRsetCache          *cache.RRsetCacheT // ConcurrentMap of cached RRsets from queries
	ImrEngine           *Imr
	Scanner             *Scanner      // Scanner instance for async job tracking
	TsigKeyStore        *TsigKeyStore // name->secret store for replication TSIG (Improvement 2)
}

// InternalConf holds DNS-internal state (channels, engine references).
// MP state has moved to tdns-mp's own InternalMpConf.
type InternalConf struct {
	InternalDnsConf

	// XfrAliasConflicts records zones/templates whose raw config used two
	// spellings of the same transfer list (e.g. primaries: AND upstreams:).
	// Set by ParseConfig (NormalizeXfrAliases); ParseZones quarantines the
	// named zones. BrokenPeers records invalid peers: definitions (id ->
	// reason); zones referencing one are quarantined at expansion time.
	XfrAliasConflicts map[string]string
	BrokenPeers       map[string]string

	// LargeAlgorithms is the derived lookup set from Dnssec.LargeAlgorithms.
	LargeAlgorithms map[uint8]bool

	// SplitAlgorithms is the derived lookup set from Dnssec.SplitAlgorithms:
	// kskAlg -> set of permitted zskAlgs. nil/empty means no mixed pair is
	// allowed (only same-algorithm KSK/ZSK policies pass).
	SplitAlgorithms map[uint8]map[uint8]bool

	// Completeness is the resolved DNSSEC completeness mode from
	// Dnssec.Completeness ("strict" | "relaxed"), defaulted to "strict".
	// Read by the algorithm-rollover reconcile (step 2) to decide whether a
	// ZSK algorithm roll runs relaxed or is refused under strict.
	Completeness string

	// PostParseZonesHook is called after ParseZones completes during
	// reload (SIGHUP or "config reload-zones"). Set by MP apps to
	// register tdns-mp callbacks on newly added zones.
	PostParseZonesHook func()

	// PostValidateConfigHook is called at the end of ValidateConfig.
	// Set by MP apps (before calling parent MainInit) to run
	// MP-specific config validators alongside the built-in ones.
	PostValidateConfigHook func(conf *Config) error

	// PostParseConfigHook is called at the very end of ParseConfig,
	// after tdns has decoded the YAML, run its own normalization,
	// and executed all tdns-side validation. Downstream packages
	// (tdns-mp, tdns-nm, etc.) can register a hook that decodes
	// their own config-section structs from the same processed
	// configMap, running in parallel with the tdns-side decode.
	//
	// The configMap argument is the post-include, post-default
	// processed map that tdns itself decoded into conf — pass it
	// to mapstructure to decode any downstream sub-tree without
	// re-reading the file from disk.
	PostParseConfigHook func(conf *Config, configMap map[string]interface{}) error
}

// NOTE: MsgQs and its associated message types (KeystateInventoryMsg,
// KeystateSignalMsg, EditsResponseMsg, ConfigResponseMsg,
// AuditResponseMsg, StatusUpdateMsg) live in tdns-mp/v2/config.go.
// They are MP-only and were removed from tdns during the tdns-mp
// extraction.
const defaultKaspPropagationDelay = time.Hour

// validateKaspPropagationDelay rejects invalid kasp.propagation_delay at config load.
func validateKaspPropagationDelay(s string) error {
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("kasp.propagation_delay: invalid duration %q: %w", s, err)
	}
	if d <= 0 {
		return fmt.Errorf("kasp.propagation_delay: must be positive, got %s", d)
	}
	return nil
}

// KaspPropagationDelay returns the configured kasp.propagation_delay, or 1h.
func (conf *Config) KaspPropagationDelay() time.Duration {
	if conf == nil || conf.Dnssec.Kasp.PropagationDelay == "" {
		return defaultKaspPropagationDelay
	}
	d, err := time.ParseDuration(conf.Dnssec.Kasp.PropagationDelay)
	if err != nil || d <= 0 {
		if err != nil {
			lgConfig.Warn("invalid kasp.propagation_delay, using default",
				"value", conf.Dnssec.Kasp.PropagationDelay, "default", defaultKaspPropagationDelay, "err", err)
		} else {
			lgConfig.Warn("kasp.propagation_delay must be positive, using default",
				"value", conf.Dnssec.Kasp.PropagationDelay, "default", defaultKaspPropagationDelay)
		}
		return defaultKaspPropagationDelay
	}
	return d
}

func (conf *Config) ReloadConfig() (string, error) {
	confMu.Lock()
	defer confMu.Unlock()
	err := conf.ParseConfig(true) // true: reload, not initial parsing
	if err != nil {
		lgConfig.Error("error parsing config", "err", err)
	}
	// Rebuild the TSIG store ONLY after a successful parse. With KeyDB, reconcile
	// config keys in place (§6).
	if err == nil {
		if conf.Internal.KeyDB != nil {
			if _, kerr := conf.reconcileAndRefreshTsigKeys(TsigReconcileOptions{}); kerr != nil {
				lgConfig.Error("TSIG keys: config error on reload (affected keys skipped)", "err", kerr)
			}
		} else if kerr := conf.LoadTsigKeys(); kerr != nil {
			lgConfig.Error("TSIG keys: config error on reload (affected keys skipped)", "err", kerr)
		}
	}
	// Publish the new runtime-config snapshot on a successful reload (still under
	// confMu); on a parse error keep the last-good snapshot.
	if err == nil {
		conf.publishRuntimeConfig()
	}
	Globals.App.ServerConfigTime = time.Now()
	return "Config reloaded.", err
}

// ReloadTsigConfig re-reads keys.tsig from the config file and reconciles the DB
// keystore + live cache. opts.Force / opts.Overwrite resolve secret conflicts (§6).
func (conf *Config) ReloadTsigConfig(opts TsigReconcileOptions) (TsigReconcileResult, error) {
	confMu.Lock()
	defer confMu.Unlock()
	if conf.Internal.KeyDB == nil {
		return TsigReconcileResult{}, fmt.Errorf("TSIG keystore reconcile requires KeyDB")
	}
	if err := conf.reloadTsigKeysFromFile(); err != nil {
		return TsigReconcileResult{}, err
	}
	result, err := conf.reconcileAndRefreshTsigKeys(opts)
	Globals.App.ServerConfigTime = time.Now()
	return result, err
}

func (conf *Config) ReloadZoneConfig(ctx context.Context) (string, error) {
	confMu.Lock()
	if ctx == nil {
		ctx = context.Background()
	}

	// Re-read config file to pick up template changes
	if err := conf.reloadTemplatesFromFile(); err != nil {
		lgConfig.Warn("ReloadZoneConfig: failed to reload templates", "err", err)
		// Continue with existing templates rather than failing entirely
	}

	// Re-read and re-parse the dnssec: block from the config file so zones are
	// re-applied against the CURRENT policy definitions — an edited policy is
	// picked up here, no separate `config reload` needed first. A parse error
	// leaves the previous policies in place rather than failing the whole reload.
	if err := conf.reloadDnssecFromFile(); err != nil {
		lgConfig.Error("ReloadZoneConfig: failed to re-parse dnssec config, keeping previous policies", "err", err)
	}

	prezones := Zones.Keys()
	lgConfig.Info("ReloadZones: zones prior to reloading", "zones", prezones)
	// XXX: This is wrong. We must get the zones config file from outside (to enamble things like MUSIC to use a different config file)
	zonelist, brokenlist, err := conf.ParseZones(ctx, true) // true: reload, not initial parsing
	if err != nil {
		confMu.Unlock()
		lgConfig.Error("ReloadZoneConfig: error parsing zones", "err", err)
		return "", fmt.Errorf("ReloadZoneConfig: %w", err)
	}

	for _, zname := range prezones {
		if slices.Contains(zonelist, zname) || slices.Contains(brokenlist, zname) {
			continue
		}
		zd, exists := Zones.Get(zname)
		if !exists {
			lgConfig.Warn("ReloadZoneConfig: zone not in config and also not in zone list", "zone", zname)
			continue
		}
		// Spare any LIVE dynamic/managed zone (catalog zone, catalog member, or
		// API-managed) — these are never in the static config. Guard on the
		// markers directly, NOT ShouldPersistZone: the latter is false for
		// storage: memory, which is a disk-persistence policy, not a liveness
		// signal — a memory-backed dynamic zone is still a valid live zone and
		// must survive a config reload.
		if zd.Options[OptCatalogZone] || zd.Options[OptAutomaticZone] || zd.Options[OptApiManagedZone] {
			lgConfig.Info("ReloadZoneConfig: zone is dynamic/managed, not removing from zone list", "zone", zname)
			continue
		}
		lgConfig.Info("ReloadZoneConfig: zone no longer in config, removing from zone list", "zone", zname)
		stopZonePublisher(zname)
		Zones.Remove(zname)
		// Bump generation so any in-flight refresh on the captured pointer fails
		// the pre-persist guard (B5b) and does not resurrect the removed zone.
		zd.generation.Add(1)
	}

	lgConfig.Info("ReloadZones: zones after reloading", "zones", zonelist, "broken", brokenlist)
	Globals.App.ServerConfigTime = time.Now()

	// Publish the new runtime-config snapshot while still under confMu — the
	// reloaded DnssecPolicies (via reloadDnssecFromFile above) are now final.
	conf.publishRuntimeConfig()

	// Capture hook reference before releasing lock to avoid deadlock
	// if the hook re-enters config paths.
	hook := conf.Internal.PostParseZonesHook
	confMu.Unlock()

	if hook != nil {
		hook()
	}

	return fmt.Sprintf("Zones reloaded. Before: %v, After: %v", prezones, zonelist), err
}
