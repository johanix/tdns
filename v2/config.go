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
// Readers do not need to hold this — the reload window is brief and
// reads during reload may see partial state, which is acceptable.
// Only reload paths acquire the write lock.
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
	Service        ServiceConf
	DnsEngine      DnsEngineConf
	Imr            ImrEngineConf `yaml:"imrengine" mapstructure:"imrengine"`
	ApiServer      ApiServerConf
	DnssecPolicies map[string]DnssecPolicyConf
	MultiSigner    map[string]MultiSignerConf `yaml:"multisigner"`
	MultiProvider  *MultiProviderConf         `yaml:"multi-provider" mapstructure:"multi-provider"`
	Catalog        *CatalogConf               `yaml:"catalog" mapstructure:"catalog"`
	DynamicZones   DynamicZonesConf           `yaml:"dynamiczones" mapstructure:"dynamiczones"`
	Zones          []ZoneConf                 `yaml:"zones"`
	Templates      []ZoneConf                 `yaml:"templates"`
	Kasp           KaspConf                   `yaml:"kasp" mapstructure:"kasp"`
	Keys           KeyConf
	Db             DbConf
	Registrars     map[string][]string
	Log            LogConf
	Internal       InternalConf
}

// KaspConf holds Key and Signing Policy parameters for the signer.
// Controls the KeyStateWorker's automatic key state transitions and standby key maintenance.
// YAML key: "kasp:"
//
// Example:
//
//	kasp:
//	    propagation_delay: 1h
//	    standby_zsk_count: 1
//	    standby_ksk_count: 0
//	    check_interval: 1m
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

// ProviderZoneConf configures a provider-owned zone that the combiner manages.
// Unlike MP zones (hardcoded RRtype whitelist, apex-only), provider zones use
// config-driven RRtype restrictions and allow non-apex record owners.
type ProviderZoneConf struct {
	Zone           string   `yaml:"zone"`
	AllowedRRtypes []string `yaml:"allowed-rrtypes" mapstructure:"allowed-rrtypes"`
}

// MultiProviderConf holds config for multi-provider DNSSEC (RFC 8901).
// Used by all three MP roles: agent, combiner, and signer.
// The Role field determines which role-specific fields are relevant.
// YAML key: "multi-provider:"
type MultiProviderConf struct {
	// === Shared fields (all roles) ===

	// Role: "agent", "combiner", or "signer". Determines which fields are active.
	Role string `yaml:"role"`
	// Active: master switch for multi-provider mode.
	// Must be true AND zone must have options: [multi-provider] for MP behavior.
	Active bool `yaml:"active"`
	// Identity: this node's identity (FQDN) for transport protocol.
	Identity string `yaml:"identity"`
	// LongTermJosePrivKey: path to JOSE private key for secure CHUNK.
	LongTermJosePrivKey string `yaml:"long_term_jose_priv_key"`
	// ChunkMode: "edns0" | "query" for outbound NOTIFY(CHUNK).
	ChunkMode string `yaml:"chunk_mode" mapstructure:"chunk_mode"`
	// ChunkMaxSize: maximum size (bytes) of each data chunk when fragmenting payloads.
	// 0 = default (60000). Useful for testing fragmentation with small values.
	ChunkMaxSize int `yaml:"chunk_max_size" mapstructure:"chunk_max_size"`
	// Agents: the agent peers (address, JOSE public key, optional API URL).
	// Used by signer and combiner roles.
	Agents []*PeerConf `yaml:"agents"`
	// SyncApi: sync API server config for inbound HELLO/BEAT/PING over HTTPS.
	// Used by signer and combiner roles.
	SyncApi struct {
		Addresses struct {
			Listen []string
		}
		CertFile string `yaml:"cert_file" mapstructure:"cert_file"`
		KeyFile  string `yaml:"key_file" mapstructure:"key_file"`
	} `yaml:"sync_api" mapstructure:"sync_api"`

	// === Combiner-specific fields ===

	// CombinerOptions: list of combiner-specific option strings parsed at startup.
	// Known options: "add-signature".
	CombinerOptionsStrs []string                `yaml:"combiner-options" mapstructure:"combiner-options"`
	CombinerOptions     map[CombinerOption]bool `yaml:"-" mapstructure:"-"`

	// ChunkQueryEndpoint: "include" | "none"; required when chunk_mode=query (combiner role).
	ChunkQueryEndpoint string `yaml:"chunk_query_endpoint" mapstructure:"chunk_query_endpoint"`
	// Signature: template string for a TXT record injected into combined zones (demo feature).
	// Supports {identity} and {zone} placeholders.
	Signature    string `yaml:"signature"`
	AddSignature bool   `yaml:"add-signature" mapstructure:"add-signature"` // DEPRECATED: use combiner-options: [add-signature]
	// ProtectedNamespaces: list of domain suffixes that belong to this provider.
	// NS records from remote agents whose targets fall within any of these namespaces
	// are rejected (prevents namespace intrusion).
	ProtectedNamespaces []string `yaml:"protected-namespaces" mapstructure:"protected-namespaces"`
	// ProviderZones: zones owned by the provider where agents may make targeted edits
	// (e.g. _signal KEY records). Unlike MP zones, these use config-driven RRtype
	// restrictions and allow non-apex owners.
	ProviderZones []ProviderZoneConf `yaml:"provider-zones" mapstructure:"provider-zones"`

	// === Signer-specific fields ===

	// SignerOptions: list of signer-specific option strings parsed at startup.
	SignerOptionsStrs []string              `yaml:"signer-options" mapstructure:"signer-options"`
	SignerOptions     map[SignerOption]bool `yaml:"-" mapstructure:"-"`

	// === Agent-specific fields ===

	// AgentOptions: list of agent-specific option strings parsed at startup.
	AgentOptionsStrs []string             `yaml:"agent-options" mapstructure:"agent-options"`
	AgentOptions     map[AgentOption]bool `yaml:"-" mapstructure:"-"`
	// SupportedMechanisms: List of active transport mechanisms (default: ["api", "dns"] if both configured)
	SupportedMechanisms []string `yaml:"supported_mechanisms" mapstructure:"supported_mechanisms"`
	Local               struct {
		Notify      []string
		Nameservers []string `yaml:"nameservers,omitempty"`
	}
	Remote struct {
		LocateInterval int
		BeatInterval   uint32
	}
	Syncengine struct {
		Intervals struct {
			HelloRetry int
		}
	}
	Api LocalAgentApiConf
	Dns LocalAgentDnsConf
	// Combiner peer (agent only): address and combiner's JOSE public key path for secure CHUNK
	Combiner *PeerConf `yaml:"combiner"`
	// Signer peer (agent only): address and JOSE public key path for KEYSTATE signaling
	Signer *PeerConf `yaml:"signer"`
	// AuthorizedPeers: List of agent identities authorized to communicate
	AuthorizedPeers []string `yaml:"authorized_peers"`
	// Peers (DEPRECATED): Old format with embedded addresses/keys - use authorized_peers instead
	Peers map[string]*PeerConf `yaml:"peers"`
	Xfr   struct {
		Outgoing struct {
			Addresses []string `yaml:"addresses,omitempty"`
			Auth      []string `yaml:"auth,omitempty"`
		}
		Incoming struct {
			Addresses []string `yaml:"addresses,omitempty"`
			Auth      []string `yaml:"auth,omitempty"`
		}
	}
}

// FindAgent returns the PeerConf for the agent with the given identity, or nil if not found.
func (c *MultiProviderConf) FindAgent(identity string) *PeerConf {
	for _, a := range c.Agents {
		if a.Identity == identity {
			return a
		}
	}
	return nil
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

// PeerConf holds address and public key path for the other party (agent or combiner).
type PeerConf struct {
	Address            string `yaml:"address"`
	LongTermJosePubKey string `yaml:"long_term_jose_pub_key"`
	ApiBaseUrl         string `yaml:"api_base_url,omitempty"` // Optional: for API transport (e.g. https://combiner:8085/api/v1)
	Identity           string `yaml:"identity"`               // Peer identity (FQDN); required for combiner agents, optional for agent combiner
}

type LocalAgentApiConf struct {
	Addresses struct {
		Publish []string
		Listen  []string
	}
	BaseUrl  string
	Port     uint16
	CertFile string
	KeyFile  string
	CertData string
	KeyData  string
}

type LocalAgentDnsConf struct {
	Addresses struct {
		Publish []string
		Listen  []string
	}
	BaseUrl     string
	Port        uint16
	ControlZone string `yaml:"control_zone" mapstructure:"control_zone"` // Zone used for NOTIFY(CHUNK) QNAMEs in DNS mode (default: agent identity)
	// Chunk config (same key names as combiner for consistency)
	ChunkMode          string `yaml:"chunk_mode" mapstructure:"chunk_mode"`                     // "edns0" | "query"; query = store payload, receiver fetches via CHUNK query (default: edns0)
	ChunkQueryEndpoint string `yaml:"chunk_query_endpoint" mapstructure:"chunk_query_endpoint"` // "include" | "none"; required when chunk_mode=query. include = signal in NOTIFY (EDNS0); none = receiver uses combiner.agents[].address
	// ChunkMaxSize: maximum size (bytes) of each data chunk when fragmenting payloads via PrepareDistributionChunks.
	// 0 = default (60000). Useful for testing fragmentation with small values (e.g. 500).
	ChunkMaxSize int `yaml:"chunk_max_size" mapstructure:"chunk_max_size"`
	// Message retention times for CHUNK distributions (in seconds)
	MessageRetention MessageRetentionConf `yaml:"message_retention" mapstructure:"message_retention"`
}

// MessageRetentionConf defines retention times for different message types in CHUNK distributions.
// Times are in seconds. Beat and ping messages expire quickly to reduce clutter,
// while other message types are kept longer for debugging purposes.
type MessageRetentionConf struct {
	Beat     int `yaml:"beat" mapstructure:"beat"`         // Beat message retention (default: 30s)
	Ping     int `yaml:"ping" mapstructure:"ping"`         // Ping message retention (default: 30s)
	Hello    int `yaml:"hello" mapstructure:"hello"`       // Hello message retention (default: 300s)
	Sync     int `yaml:"sync" mapstructure:"sync"`         // Sync message retention (default: 300s)
	Relocate int `yaml:"relocate" mapstructure:"relocate"` // Relocate message retention (default: 300s)
	Default  int `yaml:"default" mapstructure:"default"`   // Default retention for other types (default: 300s)
}

// GetRetentionForMessageType returns the retention time in seconds for a given message type.
// Returns the configured value if set, otherwise returns the appropriate default.
func (m *MessageRetentionConf) GetRetentionForMessageType(messageType string) int {
	// Apply defaults if values are not set (0 or negative)
	const (
		defaultBeatPing = 30  // 30 seconds for beat and ping
		defaultOther    = 300 // 5 minutes for other message types
	)

	switch messageType {
	case "beat":
		if m.Beat > 0 {
			return m.Beat
		}
		return defaultBeatPing
	case "ping":
		if m.Ping > 0 {
			return m.Ping
		}
		return defaultBeatPing
	case "hello":
		if m.Hello > 0 {
			return m.Hello
		}
		return defaultOther
	case "sync":
		if m.Sync > 0 {
			return m.Sync
		}
		return defaultOther
	case "relocate":
		if m.Relocate > 0 {
			return m.Relocate
		}
		return defaultOther
	default:
		if m.Default > 0 {
			return m.Default
		}
		return defaultOther
	}
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

type InternalConf struct {
	CfgFile               string //
	DebugMode             bool   // if true, may activate dangerous tests
	ZonesCfgFile          string //
	CertData              string // PEM encoded certificate
	KeyData               string // PEM encoded key
	KeyDB                 *KeyDB
	AllZones              []string
	DnssecPolicies        map[string]DnssecPolicy
	StopCh                chan struct{}
	APIStopCh             chan struct{}
	StopOnce              sync.Once
	RefreshZoneCh         chan ZoneRefresher
	BumpZoneCh            chan BumperData
	ValidatorCh           chan ValidatorRequest
	RecursorCh            chan ImrRequest
	ScannerQ              chan ScanRequest
	UpdateQ               chan UpdateRequest
	DeferredUpdateQ       chan DeferredUpdate
	DnsUpdateQ            chan DnsUpdateRequest
	DnsNotifyQ            chan DnsNotifyRequest
	DnsQueryQ             chan DnsQueryRequest           // Optional: if nil, queries use direct call to QueryResponder
	QueryHandlers         map[uint16][]QueryHandlerFunc  // qtype -> list of handlers (registered via RegisterQueryHandler)
	QueryHandlersMutex    sync.RWMutex                   // protects QueryHandlers map
	NotifyHandlers        map[uint16][]NotifyHandlerFunc // qtype -> list of handlers (registered via RegisterNotifyHandler, 0 = all NOTIFYs)
	NotifyHandlersMutex   sync.RWMutex                   // protects NotifyHandlers map
	UpdateHandlers        []UpdateHandlerRegistration    // UPDATE handlers (registered via RegisterUpdateHandler)
	UpdateHandlersMutex   sync.RWMutex                   // protects UpdateHandlers slice
	DelegationSyncQ       chan DelegationSyncRequest
	MusicSyncQ            chan MusicSyncRequest
	NotifyQ               chan NotifyRequest
	AuthQueryQ            chan AuthQueryRequest
	ResignQ               chan *ZoneData // the names of zones that should be kept re-signed should be sent into this channel
	SyncQ                 chan SyncRequest
	MsgQs                 *MsgQs // aggregated channels for agent communication
	SyncStatusQ           chan SyncStatus
	AgentRegistry         *AgentRegistry
	ZoneDataRepo          *ZoneDataRepo
	RRsetCache            *cache.RRsetCacheT // ConcurrentMap of cached RRsets from queries
	ImrEngine             *Imr
	KdcDB                 interface{}            // *kdc.KdcDB - using interface{} to avoid circular import
	KdcConf               interface{}            // *kdc.KdcConf - using interface{} to avoid circular import
	KrsDB                 interface{}            // *krs.KrsDB - using interface{} to avoid circular import
	KrsConf               interface{}            // *krs.KrsConf - using interface{} to avoid circular import
	Scanner               *Scanner               // Scanner instance for async job tracking
	CombinerState         *CombinerState         // Combiner business logic state (error journal, protected namespaces)
	TransportManager      *TransportManager      // Multi-transport (API + DNS) for agent/combiner/signer; nil if transport not initialized
	LeaderElectionManager *LeaderElectionManager // Per-zone leader election for delegation sync; nil if not agent
	ChunkPayloadStore     ChunkPayloadStore      // Optional: for query-mode CHUNK (agent); keyed by qname; set when agent chunk_mode is "query"
	MPZoneNames           []string               // Zone names with OptMultiProvider, collected at parse time for SDE hydration
	DistributionCache     *DistributionCache     // In-memory cache of distributions (agent/combiner)
}

type MsgQs struct {
	Hello chan *AgentMsgReport // incoming /hello from other agents
	Beat  chan *AgentMsgReport // incoming /beat from other agents
	Ping  chan *AgentMsgReport // incoming /ping from other agents
	// Msg               chan *AgentMsgReport    // incoming /msg from other agents
	Msg               chan *AgentMsgPostPlus     // incoming /msg from other agents
	Command           chan *AgentMgmtPostPlus    // local commands TO the agent, usually for passing on to other agents
	DebugCommand      chan *AgentMgmtPostPlus    // local commands TO the agent, usually for passing on to other agents
	SynchedDataUpdate chan *SynchedDataUpdate    // incoming combiner updates
	SynchedDataCmd    chan *SynchedDataCmd       // local commands TO the combiner
	Confirmation      chan *ConfirmationDetail   // combiner confirmation feedback
	KeystateInventory chan *KeystateInventoryMsg // incoming KEYSTATE inventory from signer
	KeystateSignal    chan *KeystateSignalMsg    // incoming KEYSTATE signals (propagated/rejected) from agent to signer
	EditsResponse     chan *EditsResponseMsg     // incoming EDITS response from combiner
	ConfigResponse    chan *ConfigResponseMsg    // incoming CONFIG response from peer agent
	AuditResponse     chan *AuditResponseMsg     // incoming AUDIT response from peer agent
	StatusUpdate      chan *StatusUpdateMsg      // incoming STATUS-UPDATE notifications

	// OnRemoteConfirmationReady is called when this agent (acting as a remote agent)
	// receives a combiner confirmation for a sync that originated from another agent.
	// The callback sends the final confirmation NOTIFY back to the originating agent.
	OnRemoteConfirmationReady func(detail *RemoteConfirmationDetail)
}

// KeystateInventoryMsg carries a complete KEYSTATE inventory from signer to agent.
// Delivered via MsgQs.KeystateInventory channel.
type KeystateInventoryMsg struct {
	SenderID  string
	Zone      string
	Inventory []KeyInventoryItem
}

// KeystateSignalMsg carries a per-key KEYSTATE signal from agent to signer.
// Delivered via MsgQs.KeystateSignal channel.
// Signals: "propagated" (all remote providers confirmed), "rejected" (some provider rejected).
type KeystateSignalMsg struct {
	SenderID string
	Zone     string
	KeyTag   uint16
	Signal   string // "propagated", "rejected", "removed"
	Message  string
}

// EditsResponseMsg carries an agent's contributions from combiner back to the agent.
// Delivered via MsgQs.EditsResponse channel. Modeled on KeystateInventoryMsg.
type EditsResponseMsg struct {
	SenderID     string
	Zone         string
	AgentRecords map[string]map[string][]string // agentID → owner → []RR strings
}

// ConfigResponseMsg carries config data from a peer agent back to the requester.
// Delivered via MsgQs.ConfigResponse channel.
type ConfigResponseMsg struct {
	SenderID   string
	Zone       string
	Subtype    string            // "upstream", "downstream", "sig0key"
	ConfigData map[string]string // Key-value config data
}

// AuditResponseMsg carries audit data from a peer agent back to the requester.
// Delivered via MsgQs.AuditResponse channel.
type AuditResponseMsg struct {
	SenderID  string
	Zone      string
	AuditData interface{} // Zone data repo snapshot (placeholder)
}

// StatusUpdateMsg carries a status-update notification.
// Delivered via MsgQs.StatusUpdate channel.
// Subtypes: "ns-changed", "ksk-changed", "parentsync-done".
type StatusUpdateMsg struct {
	SenderID  string
	Zone      string
	SubType   string
	NSRecords []string
	DSRecords []string
	Result    string
	Msg       string
}

func (conf *Config) ReloadConfig() (string, error) {
	confMu.Lock()
	defer confMu.Unlock()
	err := conf.ParseConfig(true) // true: reload, not initial parsing
	if err != nil {
		lgConfig.Error("error parsing config", "err", err)
	}
	Globals.App.ServerConfigTime = time.Now()
	return "Config reloaded.", err
}

func (conf *Config) ReloadZoneConfig(ctx context.Context) (string, error) {
	confMu.Lock()
	defer confMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}

	// Re-read config file to pick up template changes
	if err := conf.reloadTemplatesFromFile(); err != nil {
		lgConfig.Warn("ReloadZoneConfig: failed to reload templates", "err", err)
		// Continue with existing templates rather than failing entirely
	}

	prezones := Zones.Keys()
	lgConfig.Info("ReloadZones: zones prior to reloading", "zones", prezones)
	// XXX: This is wrong. We must get the zones config file from outside (to enamble things like MUSIC to use a different config file)
	conf.Internal.MPZoneNames = nil             // reset before re-collection by option handler
	zonelist, err := conf.ParseZones(ctx, true) // true: reload, not initial parsing
	if err != nil {
		lgConfig.Error("ReloadZoneConfig: error parsing zones", "err", err)
		return "", fmt.Errorf("ReloadZoneConfig: %w", err)
	}

	for _, zname := range prezones {
		if !slices.Contains(zonelist, zname) {
			zd, exists := Zones.Get(zname)
			if !exists {
				lgConfig.Warn("ReloadZoneConfig: zone not in config and also not in zone list", "zone", zname)
				continue
			}
			if zd.Options[OptAutomaticZone] {
				lgConfig.Info("ReloadZoneConfig: zone is automatic, not removing from zone list", "zone", zname)
				continue
			}
			lgConfig.Info("ReloadZoneConfig: zone no longer in config, removing from zone list", "zone", zname)
			Zones.Remove(zname)
		}
	}

	lgConfig.Info("ReloadZones: zones after reloading", "zones", zonelist)
	Globals.App.ServerConfigTime = time.Now()
	return fmt.Sprintf("Zones reloaded. Before: %v, After: %v", prezones, zonelist), err
}

// LocalIdentity returns the local node's identity string, regardless of role.
// Used by sync API handlers (APIhello, APIbeat, APIsyncPing) so they work on
// agent, combiner, and signer without referencing conf.Agent.Identity directly.
func (conf *Config) LocalIdentity() string {
	if conf.MultiProvider != nil {
		return conf.MultiProvider.Identity
	}
	return ""
}
