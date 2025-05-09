/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"slices"
	"time"
)

type Config struct {
	// OBE App            AppDetails
	Service        ServiceConf
	DnsEngine      DnsEngineConf
	ImrEngine      ImrEngineConf
	ApiServer      ApiServerConf
	DnssecPolicies map[string]DnssecPolicyConf
	MultiSigner    map[string]MultiSignerConf `yaml:"multisigner"`
	// Zones          map[string]ZoneConf
	Zones      []ZoneConf `yaml:"zones"`
	Templates  []ZoneConf `yaml:"templates"`
	Db         DbConf
	Registrars map[string][]string
	Log        struct {
		File string `validate:"required"`
	}
	Agent    LocalAgentConf
	Internal InternalConf
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
	Identities []string // this is a strawman attempt at deciding on what name to publish the ALPN
}

type DnsEngineConf struct {
	Addresses  []string `yaml:"addresses" validate:"required"`
	CertFile   string   `yaml:"certfile,omitempty"`
	KeyFile    string   `yaml:"keyfile,omitempty"`
	Transports []string `yaml:"transports" validate:"required,min=1,dive,oneof=do53 dot doh doq"` // "do53", "dot", "doh", "doq"
}

type ImrEngineConf struct {
	Addresses  []string `validate:"required"`
	CertFile   string
	KeyFile    string
	Transports []string `validate:"required"` // "do53", "dot", "doh", "doq"
	Verbose    bool
	Debug      bool
}

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

type LocalAgentConf struct {
	Identity string `validate:"required,hostname"`
	Local    struct {
		Notify []string // secondaries to notify for an agent autozone
	}
	Remote struct {
		LocateInterval int    // time in seconds
		BeatInterval   uint32 // time between outgoing heartbeats to same destination
	}
	Api LocalAgentApiConf
	Dns LocalAgentDnsConf
	Xfr struct {
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
	BaseUrl string
	Port    uint16
}

type DbConf struct {
	File string // `validate:"required"`
}

type InternalConf struct {
	CfgFile         string //
	DebugMode       bool   // if true, may activate dangerous tests
	ZonesCfgFile    string //
	KeyDB           *KeyDB
	DnssecPolicies  map[string]DnssecPolicy
	StopCh          chan struct{}
	APIStopCh       chan struct{}
	RefreshZoneCh   chan ZoneRefresher
	BumpZoneCh      chan BumperData
	ValidatorCh     chan ValidatorRequest
	RecursorCh      chan ImrRequest
	ScannerQ        chan ScanRequest
	UpdateQ         chan UpdateRequest
	DeferredUpdateQ chan DeferredUpdate
	DnsUpdateQ      chan DnsUpdateRequest
	DnsNotifyQ      chan DnsNotifyRequest
	DelegationSyncQ chan DelegationSyncRequest
	MusicSyncQ      chan MusicSyncRequest
	NotifyQ         chan NotifyRequest
	AuthQueryQ      chan AuthQueryRequest
	ResignQ         chan *ZoneData // the names of zones that should be kept re-signed should be sent into this channel
	SyncQ           chan SyncRequest
	AgentQs         *AgentQs // aggregated channels for agent communication
	SyncStatusQ     chan SyncStatus
	AgentRegistry   *AgentRegistry
	ZoneDataRepo    *ZoneDataRepo
	RRsetCache      *RRsetCacheT // ConcurrentMap of cached RRsets from queries
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

func (conf *Config) ReloadZoneConfig() (string, error) {
	prezones := Zones.Keys()
	log.Printf("ReloadZones: zones prior to reloading: %v", prezones)
	// XXX: This is wrong. We must get the zones config file from outside (to enamble things like MUSIC to use a different config file)
	zonelist, err := conf.ParseZones(true) // true: reload, not initial parsing
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
