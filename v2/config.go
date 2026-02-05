/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
)

var Conf Config

type Config struct {
	Service        ServiceConf
	DnsEngine      DnsEngineConf
	Imr            ImrEngineConf `yaml:"imrengine" mapstructure:"imrengine"`
	ApiServer      ApiServerConf
	DnssecPolicies map[string]DnssecPolicyConf
	MultiSigner    map[string]MultiSignerConf `yaml:"multisigner"`
	Catalog        CatalogConf                `yaml:"catalog" mapstructure:"catalog"`
	DynamicZones   DynamicZonesConf           `yaml:"dynamiczones" mapstructure:"dynamiczones"`
	Zones          []ZoneConf                 `yaml:"zones"`
	Templates      []ZoneConf                 `yaml:"templates"`
	Keys           KeyConf
	Db             DbConf
	Registrars     map[string][]string
	Log            struct {
		File string `validate:"required"`
	}
	Agent *LocalAgentConf `yaml:"agent"`
	// Combiner (combiner only): symmetric to Agent block; our config and peer (agent)
	Combiner *LocalCombinerConf `yaml:"combiner"`
	Internal InternalConf
}

// LocalCombinerConf holds combiner-specific config (symmetric to LocalAgentConf).
type LocalCombinerConf struct {
	// LongTermJosePrivKey: path to our JOSE private key for secure CHUNK
	LongTermJosePrivKey string `yaml:"long_term_jose_priv_key"`
	// Chunk config (same key names as agent.dns for consistency)
	ChunkMode          string `yaml:"chunk_mode" mapstructure:"chunk_mode"`                     // "edns0" | "query" when combiner sends NOTIFY(CHUNK)
	ChunkQueryEndpoint string `yaml:"chunk_query_endpoint" mapstructure:"chunk_query_endpoint"` // "include" | "none"; required when chunk_mode=query
	// Agent (combiner only): the agent we talk to; symmetric to agent.combiner
	Agent *PeerConf `yaml:"agent"`
}

type AppDetails struct {
	Name             string
	Version          string
	Type             AppType
	Date             string
	ServerBootTime   time.Time
	ServerConfigTime time.Time
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
	Addresses []string `validate:"required"` // Must be in addr:port format
	ApiKey    string   `validate:"required"`
	CertFile  string   `validate:"required,file,certkey"`
	KeyFile   string   `validate:"required,file"`
	UseTLS    bool
	Server    ApiServerAppConf
	Agent     ApiServerAppConf
	// MSA       ApiServerAppConf
	Combiner ApiServerAppConf
}

type ApiServerAppConf struct {
	Addresses []string
	ApiKey    string
}

// PeerConf holds address and public key path for the other party (agent or combiner).
type PeerConf struct {
	Address            string `yaml:"address"`
	LongTermJosePubKey string `yaml:"long_term_jose_pub_key"`
	ApiBaseUrl         string `yaml:"api_base_url,omitempty"` // Optional: for API ping (e.g. https://combiner:8085/api/v1)
	Identity           string `yaml:"identity,omitempty"`     // Optional: agent identity (combiner only); NOTIFY(CHUNK) QNAME suffix for correlation ID extraction
}

type LocalAgentConf struct {
	Identity string `validate:"required,hostname"`
	// SupportedMechanisms: List of active transport mechanisms (default: ["api", "dns"] if both configured)
	// Valid values: "api", "dns"
	// Set to ["api"] to disable DNS transport, ["dns"] to disable API transport
	SupportedMechanisms []string `yaml:"supported_mechanisms" mapstructure:"supported_mechanisms"`
	Local               struct {
		Notify      []string // secondaries to notify for an agent autozone
		Nameservers []string `yaml:"nameservers,omitempty"` // authoritative NS hostnames for the agent autozone (FQDN, no glue; must be outside the autozone)
	}
	Remote struct {
		LocateInterval int    // time in seconds
		BeatInterval   uint32 // time between outgoing heartbeats to same destination
	}
	Api LocalAgentApiConf
	Dns LocalAgentDnsConf
	// Combiner peer (agent only): address and combiner's JOSE public key path for secure CHUNK
	Combiner *PeerConf `yaml:"combiner"`
	// AuthorizedPeers: List of agent identities authorized to communicate (identity-only, DNS provides contact info)
	AuthorizedPeers []string `yaml:"authorized_peers"`
	// Peers (DEPRECATED): Old format with embedded addresses/keys - use authorized_peers instead
	Peers map[string]*PeerConf `yaml:"peers"`
	// Our JOSE keypair for secure CHUNK (agent: path to private key; public derived or adjacent .pub)
	LongTermJosePrivKey string `yaml:"long_term_jose_priv_key"`
	Xfr                 struct {
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
	ChunkQueryEndpoint string `yaml:"chunk_query_endpoint" mapstructure:"chunk_query_endpoint"` // "include" | "none"; required when chunk_mode=query. include = signal in NOTIFY (EDNS0); none = receiver uses combiner.agent.address
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
	DeferredUpdateQ     chan DeferredUpdate
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
	MusicSyncQ          chan MusicSyncRequest
	NotifyQ             chan NotifyRequest
	AuthQueryQ          chan AuthQueryRequest
	ResignQ             chan *ZoneData // the names of zones that should be kept re-signed should be sent into this channel
	SyncQ               chan SyncRequest
	AgentQs             *AgentQs // aggregated channels for agent communication
	SyncStatusQ         chan SyncStatus
	AgentRegistry       *AgentRegistry
	ZoneDataRepo        *ZoneDataRepo
	RRsetCache          *cache.RRsetCacheT // ConcurrentMap of cached RRsets from queries
	ImrEngine           *Imr
	KdcDB               interface{}           // *kdc.KdcDB - using interface{} to avoid circular import
	KdcConf             interface{}           // *kdc.KdcConf - using interface{} to avoid circular import
	KrsDB               interface{}           // *krs.KrsDB - using interface{} to avoid circular import
	KrsConf             interface{}           // *krs.KrsConf - using interface{} to avoid circular import
	Scanner             *Scanner              // Scanner instance for async job tracking
	CombinerHandler     *CombinerChunkHandler // CHUNK-based combiner handler
	TransportManager    *TransportManager     // Multi-transport (API + DNS) for agent; nil if not agent or DNS mode disabled
	ChunkPayloadStore   ChunkPayloadStore     // Optional: for query-mode CHUNK (agent); keyed by qname; set when agent chunk_mode is "query"
	DistributionCache   *DistributionCache    // In-memory cache of distributions (agent/combiner)
}

type AgentQs struct {
	Hello chan *AgentMsgReport // incoming /hello from other agents
	Beat  chan *AgentMsgReport // incoming /beat from other agents
	// Msg               chan *AgentMsgReport    // incoming /msg from other agents
	Msg               chan *AgentMsgPostPlus  // incoming /msg from other agents
	Command           chan *AgentMgmtPostPlus // local commands TO the agent, usually for passing on to other agents
	DebugCommand      chan *AgentMgmtPostPlus // local commands TO the agent, usually for passing on to other agents
	SynchedDataUpdate chan *SynchedDataUpdate // incoming combiner updates
	SynchedDataCmd    chan *SynchedDataCmd    // local commands TO the combiner
}

func (conf *Config) ReloadConfig() (string, error) {
	err := conf.ParseConfig(true) // true: reload, not initial parsing
	if err != nil {
		log.Printf("Error parsing config: %v", err)
	}
	Globals.App.ServerConfigTime = time.Now()
	return "Config reloaded.", err
}

func (conf *Config) ReloadZoneConfig(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	prezones := Zones.Keys()
	log.Printf("ReloadZones: zones prior to reloading: %v", prezones)
	// XXX: This is wrong. We must get the zones config file from outside (to enamble things like MUSIC to use a different config file)
	zonelist, err := conf.ParseZones(ctx, true) // true: reload, not initial parsing
	if err != nil {
		log.Printf("ReloadZoneConfig: Error parsing zones: %v", err)
	}

	for _, zname := range prezones {
		if !slices.Contains(zonelist, zname) {
			zd, exists := Zones.Get(zname)
			if !exists {
				log.Printf("ReloadZoneConfig: Zone %s not in config and also not in zone list.", zname)
			}
			if zd.Options[OptAutomaticZone] {
				log.Printf("ReloadZoneConfig: Zone %s is an automatic zone. Not removing from zone list.", zname)
				continue
			}
			log.Printf("ReloadZoneConfig: Zone %s no longer in config. Removing from zone list.", zname)
			Zones.Remove(zname)
		}
	}

	log.Printf("ReloadZones: zones after reloading: %v", zonelist)
	Globals.App.ServerConfigTime = time.Now()
	return fmt.Sprintf("Zones reloaded. Before: %v, After: %v", prezones, zonelist), err
}
