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

	core "github.com/johanix/tdns/v0.x/core"
	edns0 "github.com/johanix/tdns/v0.x/edns0"
	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
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
	Sig0StateCreated     string = "created"
	Sig0StatePublished   string = "published"
	Sig0StateActive      string = "active"
	Sig0StateRetired     string = "retired"
	DnskeyStateCreated   string = "created"
	DnskeyStatePublished string = "published"
	DnskeyStateActive    string = "active"
	DnskeyStateRetired   string = "retired"
)

type ZoneData struct {
	mu         sync.Mutex
	ZoneName   string
	ZoneStore  ZoneStore // 1 = "xfr", 2 = "map", 3 = "slice". An xfr zone only supports xfr related ops
	ZoneType   ZoneType
	Owners     Owners
	OwnerIndex cmap.ConcurrentMap[string, int]
	ApexLen    int
	//	RRs            RRArray
	Data         cmap.ConcurrentMap[string, OwnerData]
	CombinerData *cmap.ConcurrentMap[string, OwnerData]
	Ready        bool   // true if zd.Data has been populated (from file or upstream)
	XfrType      string // axfr | ixfr
	Logger       *log.Logger
	// ZoneFile           string // TODO: Remove this
	IncomingSerial     uint32 // SOA serial that we got from upstream
	CurrentSerial      uint32 // SOA serial after local bumping
	Verbose            bool
	Debug              bool
	IxfrChain          []Ixfr
	Upstream           string   // primary from where zone is xfrred
	Downstreams        []string // secondaries that we notify
	Zonefile           string
	DelegationSyncQ    chan DelegationSyncRequest
	MusicSyncQ         chan MusicSyncRequest // Multi-signer (communication between music-sidecars)
	Parent             string                // name of parentzone (if filled in)
	ParentNS           []string              // names of parent nameservers
	ParentServers      []string              // addresses of parent nameservers
	Children           map[string]*ChildDelegationData
	Options            map[ZoneOption]bool
	UpdatePolicy       UpdatePolicy
	DnssecPolicy       *DnssecPolicy
	MultiSigner        *MultiSignerConf
	KeyDB              *KeyDB
	AppType            AppType
	SyncQ              chan SyncRequest
	Error              bool        // zone is broken and cannot be used
	ErrorType          ErrorType   // "config" | "refresh" | "notify" | "update"
	ErrorMsg           string      // reason for the error (if known)
	LatestError        time.Time   // time of latest error
	RefreshCount       int         // number of times the zone has been sucessfully refreshed (used to determine if we have zonedata)
	LatestRefresh      time.Time   // time of latest successful refresh
	SourceCatalog      string      // if auto-configured, which catalog zone created this zone
	TransportSignal    *core.RRset // transport signal RRset (SVCB or TSYNC)
	AddTransportSignal bool        // whether to attach TransportSignal in responses
}

// ZoneConf represents the external config for a zone; it contains no zone data
type ZoneConf struct {
	Name         string `validate:"required"`
	Zonefile     string
	Type         string `validate:"required"`
	Store        string // xfr | map | slice | reg (defaults to "map" if not specified)
	Primary      string // upstream, for secondary zones
	Notify       []string
	Downstreams  []string
	OptionsStrs  []string     `yaml:"options" mapstructure:"options"`
	Options      []ZoneOption `yaml:"-" mapstructure:"-"` // Ignore during both yaml and mapstructure decoding
	Frozen       bool         // true if zone is frozen; not a config param
	Dirty        bool         // true if zone has been modified; not a config param
	UpdatePolicy UpdatePolicyConf
	DnssecPolicy string
	Template     string
	MultiSigner  string
	Error         bool      // zone is broken and cannot be used
	ErrorType     ErrorType // "config" | "refresh" | "agent" | "DNSSEC"
	ErrorMsg      string    // reason for the error (if known)
	RefreshCount  int       // number of times the zone has been sucessfully refreshed (used to determine if we have zonedata)
	SourceCatalog string    // if auto-configured, which catalog zone created this zone
}

type TemplateConf struct {
	Name         string `validate:"required"`
	Zonefile     string
	Type         string
	Store        string
	Primary      string // upstream, for secondary zones
	Notify       []string
	OptionsStrs  []string `yaml:"options"`
	UpdatePolicy UpdatePolicyConf
	DnssecPolicy string
	MultiSigner  string
}

type UpdatePolicyConf struct {
	Child struct {
		Type         string // selfsub | self | sub | none
		RRtypes      []string
		KeyBootstrap []string // manual | dnssec-validated | consistent-lookup
		KeyUpload    string
	}
	Zone struct {
		Type    string // "selfsub" | "self" | "sub" | ...
		RRtypes []string
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
}

// DnssecPolicyConf should match the configuration
type DnssecPolicyConf struct {
	Name      string
	Algorithm string

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
}

type KeyLifetime struct {
	Lifetime    uint32
	SigValidity uint32
}

// DnssecPolicy is what is actually used; it is created from the corresponding DnssecPolicyConf
type DnssecPolicy struct {
	Name      string
	Algorithm uint8

	KSK KeyLifetime
	ZSK KeyLifetime
	CSK KeyLifetime
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

type xxxRRset struct {
	Name   string
	Class  uint16
	RRtype uint16
	RRs    []dns.RR
	RRSIGs []dns.RR
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
	Adds          []dns.RR
	Removes       []dns.RR
	NsAdds        []dns.RR
	NsRemoves     []dns.RR
	AAdds         []dns.RR
	ARemoves      []dns.RR
	AAAAAdds      []dns.RR
	AAAARemoves   []dns.RR
	DNSKEYAdds    []dns.RR
	DNSKEYRemoves []dns.RR
	Error         bool
	ErrorMsg      string
	UpdateResult  UpdateResult // Experimental
	// Complete new delegation data for replace mode
	NewNS   []dns.RR // Complete NS RRset after update
	NewA    []dns.RR // Complete A glue RRs after update
	NewAAAA []dns.RR // Complete AAAA glue RRs after update
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
	Map cmap.ConcurrentMap[string, Sig0Key]
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
	Name       string
	State      string
	Keyid      uint16
	Flags      uint16
	Algorithm  string
	Creator    string
	PrivateKey string //
	Key        dns.DNSKEY
	Keystr     string
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
}

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

type CombinerPost struct {
	Command string              `json:"command"` // add, list, remove
	Zone    string              `json:"zone"`    // zone name
	Data    map[string][]string `json:"data"`    // The RRs as strings, indexed by owner name
}

type CombinerResponse struct {
	Time     time.Time                `json:"time"`
	Error    bool                     `json:"error"`
	ErrorMsg string                   `json:"error_msg,omitempty"`
	Msg      string                   `json:"msg,omitempty"`
	Data     map[string][]RRsetString `json:"data,omitempty"`
}

// type AgentPost struct {
//	Command string `json:"command"`
//	Zone    string `json:"zone"`
//	AgentId string `json:"agent_id"`
// }

// type AgentResponse struct {
//	Identity string
//	Time     time.Time
//	Error    bool
//	ErrorMsg string
//	Msg      string
//	HsyncRRs []string // Keep the HSYNC RRset for reference
//	Agents   []*Agent // The actual agents involved in the zone
// }

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
