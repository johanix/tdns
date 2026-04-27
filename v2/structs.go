/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"crypto"
	"database/sql"
	"log"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

type ZoneStore uint8

const (
	XfrZone ZoneStore = iota + 1
	MapZone
	SliceZone
)

var ZoneStoreToString = map[ZoneStore]string{
	XfrZone:   "XfrZone",
	MapZone:   "MapZone",
	SliceZone: "SliceZone",
}

type ZoneType uint8

const (
	Primary ZoneType = iota + 1
	Secondary
)

var ZoneTypeToString = map[ZoneType]string{
	Primary:   "primary",
	Secondary: "secondary",
}

const (
	Sig0StateCreated       string = "created"
	Sig0StatePublished     string = "published"
	Sig0StateActive        string = "active"
	Sig0StateRetired       string = "retired"
	DnskeyStateCreated     string = "created"
	DnskeyStatePublished   string = "published"
	DnskeyStateDsPublished string = "ds-published"
	DnskeyStateStandby     string = "standby"
	DnskeyStateActive      string = "active"
	DnskeyStateRetired     string = "retired"
	DnskeyStateRemoved     string = "removed"
)

// MPdata caches multi-provider membership and signing state for a zone.
// nil means the zone is not confirmed as a multi-provider zone (either OptMultiProvider
// is not set, or the zone owner hasn't declared it via HSYNC3+HSYNCPARAM, or we are
// not a listed provider). Populated during zone refresh by populateMPdata().
//
// NOTE: This is an MP type that lives in tdns (not tdns-mp) because it is
// a field of ZoneMPExtension, which is a field of ZoneData.
/*
type MPdata struct {
       WeAreProvider bool                // At least one of our agent identities matches an HSYNC3 Identity
       OurLabel      string              // Our provider label from the matching HSYNC3 record
       WeAreSigner   bool                // Our label appears in HSYNCPARAM signers (or zone is unsigned)
       OtherSigners  int                 // Count of other signers in HSYNCPARAM
       ZoneSigned    bool                // HSYNCPARAM signers= is non-empty (zone uses multi-signer)
       Options       map[ZoneOption]bool // MP-specific options (future: migrate from zd.Options)
}
*/

// ZoneRefreshAnalysis carries analysis results from OnZonePreRefresh
// to OnZonePostRefresh. Set before the hard flip, consumed after.
type ZoneRefreshAnalysis struct {
	DelegationChanged bool
	DelegationStatus  DelegationSyncStatus
	//	HsyncChanged      bool
	//	HsyncStatus       *HsyncStatus
	DnskeyChanged bool
	DnskeyStatus  *DnskeyStatus
}

type ZoneData struct {
	mu         sync.Mutex
	ZoneName   string
	ZoneStore  ZoneStore // 1 = "xfr", 2 = "map", 3 = "slice". An xfr zone only supports xfr related ops
	ZoneType   ZoneType
	Owners     Owners
	OwnerIndex *core.ConcurrentMap[string, int]
	ApexLen    int
	//	RRs            RRArray
	Data *core.ConcurrentMap[string, OwnerData]
	// 20260415 johani: MP    *ZoneMPExtension // Multi-provider state; nil for non-MP zones
	Ready bool // true if zd.Data has been populated (from file or upstream)

	XfrType string // axfr | ixfr
	Logger  *log.Logger
	// ZoneFile           string // TODO: Remove this
	IncomingSerial     uint32 // SOA serial that we got from upstream
	CurrentSerial      uint32 // SOA serial after local bumping
	FirstZoneLoad      bool   // true until first zone data has been loaded
	Verbose            bool
	Debug              bool
	IxfrChain          []Ixfr
	Upstream           string   // primary from where zone is xfrred
	Downstreams        []string // secondaries that we notify
	Zonefile           string
	DelegationSyncQ    chan DelegationSyncRequest
	Parent             string   // name of parentzone (if filled in)
	ParentNS           []string // names of parent nameservers
	ParentServers      []string // addresses of parent nameservers
	Children           map[string]*ChildDelegationData
	DelegationBackend  DelegationBackend // parent-side: backend for storing child delegation data
	Options            map[ZoneOption]bool
	UpdatePolicy       UpdatePolicy
	DnssecPolicy       *DnssecPolicy
	MultiSigner        *MultiSignerConf
	KeyDB              *KeyDB
	AppType            AppType
	Error              bool        // zone is broken and cannot be used
	ErrorType          ErrorType   // "config" | "refresh" | "notify" | "update"
	ErrorMsg           string      // reason for the error (if known)
	LatestError        time.Time   // time of latest error
	RefreshCount       int         // number of times the zone has been sucessfully refreshed (used to determine if we have zonedata)
	LatestRefresh      time.Time   // time of latest successful refresh
	SourceCatalog      string      // if auto-configured, which catalog zone created this zone
	TransportSignal    *core.RRset // transport signal RRset (SVCB or TSYNC)
	AddTransportSignal bool        // whether to attach TransportSignal in responses
	// RemoteDNSKEYs holds DNSKEY RRs from other signers (multi-signer mode 4).
	// These are DNSKEYs found in the incoming zone that do not match keys in our
	// local keystore. They are preserved across resignings and merged into the
	// DNSKEY RRset during PublishDnskeyRRs().
	// RemoteDNSKEYs []dns.RR

	// OnFirstLoad holds one-shot callbacks executed after the zone's first successful load.
	// Apps register these before RefreshEngine starts, and RefreshEngine clears the slice
	// after executing them. Protected by zd.mu.
	OnFirstLoad []func(*ZoneData)

	// OnZonePreRefresh callbacks run BEFORE the hard flip in FetchFromFile/FetchFromUpstream.
	// They receive both old (zd, current, still served) and new (new_zd, incoming, not yet served)
	// zone data. Used for: analysis (compare old vs new for HSYNC/DNSKEY/delegation changes),
	// modification of new_zd (combiner contributions, signature TXT, MP data population),
	// and agent RFIs (RequestAndWaitForKeyInventory). Options map is shared between zd and new_zd.
	OnZonePreRefresh []func(zd, new_zd *ZoneData)

	// OnZonePostRefresh callbacks run AFTER the hard flip (and after RepopulateDynamicRRs).
	// They receive zd which now serves the new data. Used for: queue sends (SyncQ,
	// DelegationSyncQ) that need the live zone pointer, and any post-flip notifications.
	OnZonePostRefresh []func(zd *ZoneData)
}

// Lock and Unlock expose the mutex for code that moves to
// tdns-mp and can no longer access the unexported zd.mu.
func (zd *ZoneData) Lock()   { zd.mu.Lock() }
func (zd *ZoneData) Unlock() { zd.mu.Unlock() }

// ZoneConf represents the external config for a zone; it contains no zone data
type ZoneConf struct {
	Name              string `validate:"required"`
	Zonefile          string
	Type              string `validate:"required"`
	Store             string // xfr | map | slice | reg (defaults to "map" if not specified)
	Primary           string // upstream, for secondary zones
	Notify            []string
	Downstreams       []string
	OptionsStrs       []string     `yaml:"options" mapstructure:"options"`
	Options           []ZoneOption `yaml:"-" mapstructure:"-"` // Ignore during both yaml and mapstructure decoding
	Frozen            bool         // true if zone is frozen; not a config param
	Dirty             bool         // true if zone has been modified; not a config param
	UpdatePolicy      UpdatePolicyConf
	DelegationBackend string    `yaml:"delegation-backend" mapstructure:"delegation-backend"` // named backend for child delegation data
	DnssecPolicy      string    `yaml:"dnssecpolicy" mapstructure:"dnssecpolicy"`
	Template          string    `yaml:"template" mapstructure:"template"`
	MultiSigner       string    `yaml:"multisigner" mapstructure:"multisigner"`
	Error             bool      // zone is broken and cannot be used
	ErrorType         ErrorType // "config" | "refresh" | "agent" | "DNSSEC"
	ErrorMsg          string    // reason for the error (if known)
	RefreshCount      int       // number of times the zone has been sucessfully refreshed (used to determine if we have zonedata)
	SourceCatalog     string    // if auto-configured, which catalog zone created this zone
}

type TemplateConf struct {
	Name         string `validate:"required"`
	Zonefile     string
	Type         string
	Store        string
	Primary      string // upstream, for secondary zones
	Notify       []string
	OptionsStrs  []string `yaml:"options" mapstructure:"options"`
	UpdatePolicy UpdatePolicyConf
	DnssecPolicy string `yaml:"dnssecpolicy" mapstructure:"dnssecpolicy"`
	MultiSigner  string `yaml:"multisigner" mapstructure:"multisigner"`
}

type UpdatePolicyConf struct {
	Child struct {
		Type         string // selfsub | self | sub | none
		RRtypes      []string
		KeyBootstrap []string // manual | dnssec-validated | consistent-lookup
		KeyUpload    string
		TTL          uint32 `yaml:"ttl"`
	}
	Zone struct {
		Type    string // "selfsub" | "self" | "sub" | ...
		RRtypes []string
		TTL     uint32 `yaml:"ttl"`
	}
	Validate bool
}
type UpdatePolicy struct {
	Child    UpdatePolicyDetail
	Zone     UpdatePolicyDetail
	Validate bool
}

type UpdatePolicyDetail struct {
	Type         string // "selfsub" | "self"
	RRtypes      map[uint16]bool
	KeyBootstrap []string
	KeyUpload    string
	TTL          uint32
}

// DnssecPolicyRolloverConf is the YAML `rollover:` subtree (KSK automated rollover; Phase 1+).
type DnssecPolicyRolloverConf struct {
	Method             string `yaml:"method" mapstructure:"method"`
	NumDS              int    `yaml:"num-ds" mapstructure:"num-ds"`
	ParentAgent        string `yaml:"parent-agent" mapstructure:"parent-agent"`
	ConfirmInitialWait string `yaml:"confirm-initial-wait" mapstructure:"confirm-initial-wait"`
	ConfirmPollMax     string `yaml:"confirm-poll-max" mapstructure:"confirm-poll-max"`
	ConfirmTimeout     string `yaml:"confirm-timeout" mapstructure:"confirm-timeout"`
	DsyncRequired      *bool  `yaml:"dsync-required" mapstructure:"dsync-required"`
}

// DnssecPolicyTtlsConf is the YAML `ttls:` subtree under a DNSSEC policy.
type DnssecPolicyTtlsConf struct {
	DNSKEY string `yaml:"dnskey" mapstructure:"dnskey"`
}

// DnssecPolicyClampingConf is the YAML `clamping:` subtree under a DNSSEC policy.
type DnssecPolicyClampingConf struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	Margin  string `yaml:"margin" mapstructure:"margin"`
}

// DnssecPolicyConf should match the configuration
type DnssecPolicyConf struct {
	Name      string
	Algorithm string
	Mode      string `yaml:"mode" mapstructure:"mode"`

	KSK struct {
		Lifetime    string
		SigValidity string
	}
	ZSK struct {
		Lifetime    string
		SigValidity string
	}
	CSK struct {
		Lifetime    string
		SigValidity string
	}

	Rollover DnssecPolicyRolloverConf `yaml:"rollover" mapstructure:"rollover"`
	Ttls     DnssecPolicyTtlsConf     `yaml:"ttls" mapstructure:"ttls"`
	Clamping DnssecPolicyClampingConf `yaml:"clamping" mapstructure:"clamping"`
}

type KeyLifetime struct {
	Lifetime    uint32
	SigValidity uint32
}

// DnssecPolicy is what is actually used; it is created from the corresponding DnssecPolicyConf
type DnssecPolicy struct {
	Name      string
	Algorithm uint8
	Mode      string

	KSK KeyLifetime
	ZSK KeyLifetime
	CSK KeyLifetime

	Rollover RolloverPolicy
	TTLS     DnssecPolicyTTLS
	Clamping ClampingPolicy
}

// DnssecPolicyTTLS holds steady-state TTL hints from policy (seconds). Zero means unset.
type DnssecPolicyTTLS struct {
	DNSKEY uint32
}

type Ixfr struct {
	FromSerial uint32
	ToSerial   uint32
	Removed    []core.RRset
	Added      []core.RRset
}

type Owners []OwnerData

type OwnerData struct {
	Name    string
	RRtypes *RRTypeStore
}

type ChildDelegationData struct {
	DelHasChanged    bool      // When returned from a scanner, this indicates that a change has been detected
	ParentSerial     uint32    // The parent serial that this data was correct for
	Timestamp        time.Time // Time at which this data was fetched
	ChildName        string
	RRsets           map[string]map[uint16]core.RRset // map[ownername]map[rrtype]RRset
	NS_rrs           []dns.RR
	A_glue           []dns.RR
	A_glue_rrsigs    []dns.RR
	AAAA_glue        []dns.RR
	AAAA_glue_rrsigs []dns.RR
	NS_rrset         *core.RRset
	DS_rrset         *core.RRset
	A_rrsets         []*core.RRset
	AAAA_rrsets      []*core.RRset
}

type DelegationSyncStatus struct {
	ZoneName      string
	Parent        string // use zd.Parent instead
	Time          time.Time
	InSync        bool
	Status        string
	Msg           string
	Rcode         uint8
	Adds          []dns.RR `json:"-"`
	Removes       []dns.RR `json:"-"`
	NsAdds        []dns.RR `json:"-"`
	NsRemoves     []dns.RR `json:"-"`
	AAdds         []dns.RR `json:"-"`
	ARemoves      []dns.RR `json:"-"`
	AAAAAdds      []dns.RR `json:"-"`
	AAAARemoves   []dns.RR `json:"-"`
	DNSKEYAdds    []dns.RR `json:"-"`
	DNSKEYRemoves []dns.RR `json:"-"`
	DSAdds        []dns.RR `json:"-"`
	DSRemoves     []dns.RR `json:"-"`
	Error         bool
	ErrorMsg      string
	UpdateResult  UpdateResult // Experimental
	// Complete new delegation data for replace mode
	NewNS   []dns.RR `json:"-"`
	NewA    []dns.RR `json:"-"`
	NewAAAA []dns.RR `json:"-"`
	NewDS   []dns.RR `json:"-"`
	// String representations for JSON serialization (populated by ToStrings())
	NsAddsStr      []string `json:"NsAdds,omitempty"`
	NsRemovesStr   []string `json:"NsRemoves,omitempty"`
	AAddsStr       []string `json:"AAdds,omitempty"`
	ARemovesStr    []string `json:"ARemoves,omitempty"`
	AAAAAddsStr    []string `json:"AAAAAdds,omitempty"`
	AAAARemovesStr []string `json:"AAAARemoves,omitempty"`
	DSAddsStr      []string `json:"DSAdds,omitempty"`
	DSRemovesStr   []string `json:"DSRemoves,omitempty"`
}

func (dss *DelegationSyncStatus) ToStrings() {
	dss.NsAddsStr = rrsToStrings(dss.NsAdds)
	dss.NsRemovesStr = rrsToStrings(dss.NsRemoves)
	dss.AAddsStr = rrsToStrings(dss.AAdds)
	dss.ARemovesStr = rrsToStrings(dss.ARemoves)
	dss.AAAAAddsStr = rrsToStrings(dss.AAAAAdds)
	dss.AAAARemovesStr = rrsToStrings(dss.AAAARemoves)
	dss.DSAddsStr = rrsToStrings(dss.DSAdds)
	dss.DSRemovesStr = rrsToStrings(dss.DSRemoves)
}

func rrsToStrings(rrs []dns.RR) []string {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]string, len(rrs))
	for i, rr := range rrs {
		out[i] = rr.String()
	}
	return out
}

type ZoneRefresher struct {
	Name         string
	ZoneType     ZoneType // primary | secondary
	Primary      string
	Notify       []string
	ZoneStore    ZoneStore // 1=xfr, 2=map, 3=slice
	Zonefile     string
	Options      map[ZoneOption]bool
	Edns0Options *edns0.MsgOptions
	UpdatePolicy UpdatePolicy
	DnssecPolicy string
	MultiSigner  string
	Force        bool // force refresh, ignoring SOA serial
	Wait         bool // wait for refresh to complete before responding
	Response     chan RefresherResponse
}

type RefresherResponse struct {
	Time     time.Time
	Zone     string
	Msg      string
	Error    bool
	ErrorMsg string
}

type ValidatorRequest struct {
	Qname    string
	RRset    *core.RRset
	Response chan ValidatorResponse
}

type ValidatorResponse struct {
	Validated bool
	Msg       string
}

type Sig0StoreT struct {
	Map *core.ConcurrentMap[string, Sig0Key]
}

type Sig0Key struct {
	Name            string
	State           string
	Keyid           uint16
	Algorithm       string
	Creator         string
	Validated       bool   // has this key been validated
	PublishedInDNS  bool   // is this key published in DNS (as a KEY RR)
	DnssecValidated bool   // has this key been DNSSEC validated
	Trusted         bool   // is this key trusted
	Source          string // "dns" | "file" | "keystore" | "child-update"
	PrivateKey      string //
	Key             dns.KEY
	Keystr          string
}

type DnssecKey struct {
	Name                   string
	State                  string
	Keyid                  uint16
	Flags                  uint16
	Algorithm              string
	Creator                string
	PrivateKey             string //
	Key                    dns.DNSKEY
	Keystr                 string
	PropagationConfirmed   bool      // True when all remote providers confirmed this key
	PropagationConfirmedAt time.Time // When propagation was confirmed (zero if not confirmed)
}

type DelegationSyncRequest struct {
	Command      string
	ZoneName     string
	ZoneData     *ZoneData
	SyncStatus   DelegationSyncStatus
	OldDnskeys   *core.RRset
	NewDnskeys   *core.RRset
	MsignerGroup *core.RRset
	Response     chan DelegationSyncStatus // used for API-based requests
}

type BumperData struct {
	Zone   string
	Result chan BumperResponse
}

type BumperResponse struct {
	Time      time.Time
	Zone      string
	Msg       string
	OldSerial uint32
	NewSerial uint32
	Error     bool
	ErrorMsg  string
	Status    bool
}

// A Signer is a struct where we keep track of the signer name and keyid
// for a DNS UPDATE message.
type Sig0UpdateSigner struct {
	Name      string   // from the SIG
	KeyId     uint16   // from the SIG
	Sig0Key   *Sig0Key // a key that matches the signer name and keyid
	Validated bool     // true if this key validated the update
}

// The UpdateStatus is used to track the evolving status of
// a received DNS UPDATE as it passes through the validation
// and approval processes.

type UpdateStatus struct {
	Zone                  string             // zone that the update applies to
	ChildZone             string             // zone that the update applies to
	Type                  string             // auth | child
	Data                  string             // auth | delegation | key
	ValidatorKey          *Sig0Key           // key that validated the update
	Signers               []Sig0UpdateSigner // possible validators
	SignerName            string             // name of the key that signed the update
	SignatureType         string             // by-trusted | by-known | self-signed
	ValidationRcode       uint8              // Rcode from the validation process
	Validated             bool               // true if the update has passed validation
	ValidatedByTrustedKey bool               // true if the update has passed validation by a trusted key
	SafetyChecked         bool               // true if the update has been safety checked
	PolicyChecked         bool               // true if the update has been policy checked
	Approved              bool               // true if the update has been approved
	Msg                   string
	Error                 bool
	ErrorMsg              string
	Status                bool
}

type NotifyStatus struct {
	Zone          string // zone that the update applies to
	ChildZone     string // zone that the update applies to
	Type          uint16 // CDS | CSYNC | DNSKEY | DELEG
	ScanStatus    string // "ok" | "changed" | "failed"
	SafetyChecked bool   // true if the update has been safety checked
	PolicyChecked bool   // true if the update has been policy checked
	Approved      bool   // true if the update has been approved
	Msg           string
	Error         bool
	ErrorMsg      string
	Status        bool
}

// Migrating all DB access to own interface to be able to have local receiver functions.
type PrivateKeyCache struct {
	K          crypto.PrivateKey
	PrivateKey string // This is only used when reading from file with ReadKeyNG()
	CS         crypto.Signer
	RR         dns.RR
	KeyType    uint16
	Algorithm  uint8
	KeyId      uint16
	KeyRR      dns.KEY
	DnskeyRR   dns.DNSKEY
}

type Sig0ActiveKeys struct {
	Keys []*PrivateKeyCache
}

type DnssecKeys struct {
	KSKs []*PrivateKeyCache
	ZSKs []*PrivateKeyCache
}

type KeyDB struct {
	DB *sql.DB
	mu sync.Mutex
	// Sig0Cache   map[string]*Sig0KeyCache
	KeystoreSig0Cache   map[string]*Sig0ActiveKeys
	TruststoreSig0Cache *Sig0StoreT            // was *Sig0StoreT
	KeystoreDnskeyCache map[string]*DnssecKeys // map[zonename]*DnssecActiveKeys
	Ctx                 string
	UpdateQ             chan UpdateRequest
	DeferredUpdateQ     chan DeferredUpdate
	KeyBootstrapperQ    chan KeyBootstrapperRequest
	Options             map[AuthOption]string
	// OutboundSoaSerial is the resolved mode for outbound SOA serials:
	// OutboundSoaSerialKeep / OutboundSoaSerialUnixtime / OutboundSoaSerialPersist.
	// Sourced from DnsEngineConf.OutboundSoaSerial at parse, defaulted to
	// OutboundSoaSerialKeep if unset.
	OutboundSoaSerial string
}

// Lock and Unlock expose the mutex for code that moves to
// tdns-mp and can no longer access the unexported kdb.mu.
func (kdb *KeyDB) Lock()   { kdb.mu.Lock() }
func (kdb *KeyDB) Unlock() { kdb.mu.Unlock() }

type Tx struct {
	*sql.Tx
	KeyDB   *KeyDB
	context string
}

// String-based versions of RRset for JSON marshaling
type RRsetString struct {
	Name   string   `json:"name"`
	RRtype uint16   `json:"rrtype"`
	RRs    []string `json:"rrs"`
	RRSIGs []string `json:"rrsigs,omitempty"`
}

type VerificationInfo struct {
	KeyName        string
	Key            string
	ZoneName       string
	AttemptsLeft   int
	NextCheckTime  time.Time
	ZoneData       *ZoneData
	Keyid          uint16
	FailedAttempts int
}

type KeyBootstrapperRequest struct {
	Cmd          string
	KeyName      string
	ZoneName     string
	ZoneData     *ZoneData
	Key          string
	Verified     bool
	Keyid        uint16
	Algorithm    uint8
	Imr          *Imr
	ResponseChan chan *VerificationInfo
}

type KeyConf struct {
	Tsig []TsigDetails
}
type TsigDetails struct {
	Name      string `validate:"required" yaml:"name"`
	Algorithm string `validate:"required" yaml:"algorithm"`
	Secret    string `validate:"required" yaml:"secret"`
}

type ZoneName string

type AgentId string

func (id AgentId) String() string {
	return string(id)
}

// AgentMgmt{Post,Response} are used in the mgmt API
type AgentMgmtPost struct {
	Command    string   `json:"command"`
	Zone       ZoneName `json:"zone"`
	AgentId    AgentId  `json:"agent_id"`
	RRType     uint16
	RR         string
	RRs        []string
	AddedRRs   []string // for update-local-zonedata
	RemovedRRs []string // for update-local-zonedata
	Upstream   AgentId
	Downstream AgentId
	Data       map[string]interface{} `json:"data,omitempty"` // Generic data field for custom parameters
	Response   chan *AgentMgmtResponse
}

type AgentMgmtResponse struct {
	Identity    AgentId
	Status      string
	Time        time.Time
	AgentConfig MultiProviderConf
	Msg         string
	Error       bool
	ErrorMsg    string
	Data        interface{} `json:"data,omitempty"` // Generic data field for custom responses
}

// DnskeyStatus holds the result of DNSKEY change detection (local keys only).
// 20260415 johani: somewhat unclear if we still need this.
type DnskeyStatus struct {
	Time             time.Time
	ZoneName         string
	LocalAdds        []dns.RR // Local DNSKEYs added since last check
	LocalRemoves     []dns.RR // Local DNSKEYs removed since last check
	CurrentLocalKeys []dns.RR // Complete current set of local DNSKEYs (for replace operations)
}
