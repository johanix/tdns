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
	Data            cmap.ConcurrentMap[string, OwnerData]
	Ready           bool   // true if zd.Data has been populated (from file or upstream)
	XfrType         string // axfr | ixfr
	Logger          *log.Logger
	ZoneFile        string
	IncomingSerial  uint32 // SOA serial that we got from upstream
	CurrentSerial   uint32 // SOA serial after local bumping
	Verbose         bool
	Debug           bool
	IxfrChain       []Ixfr
	Upstream        string   // primary from where zone is xfrred
	Downstreams     []string // secondaries that we notify
	Zonefile        string
	DelegationSyncQ chan DelegationSyncRequest
	Parent          string   // name of parentzone (if filled in)
	ParentNS        []string // names of parent nameservers
	ParentServers   []string // addresses of parent nameservers
	Children        map[string]*ChildDelegationData
	Options         map[ZoneOption]bool
	UpdatePolicy    UpdatePolicy
	DnssecPolicy    *DnssecPolicy
	MultiSigner     *MultiSignerConf
	KeyDB           *KeyDB
}

// ZoneConf represents the external config for a zone; it contains no zone data
type ZoneConf struct {
	Name         string `validate:"required"`
	Zonefile     string
	Type         string `validate:"required"`
	Store        string `validate:"required"` // xfr | map | slice | reg
	Primary      string // upstream, for secondary zones
	Notify       []string
	OptionsStrs  []string     `yaml:"options"`
	Options      []ZoneOption `yaml:"-"` // not used by yaml, but by code
	Frozen       bool         // true if zone is frozen; not a config param
	Dirty        bool         // true if zone has been modified; not a config param
	UpdatePolicy UpdatePolicyConf
	DnssecPolicy string
	Template     string
	MultiSigner  string
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
	Removed    []RRset
	Added      []RRset
}

type Owners []OwnerData

type OwnerData struct {
	Name    string
	RRtypes *RRTypeStore
}

type RRset struct {
	Name   string
	RRtype uint16
	RRs    []dns.RR
	RRSIGs []dns.RR
}

type ChildDelegationData struct {
	DelHasChanged    bool      // When returned from a scanner, this indicates that a change has been detected
	ParentSerial     uint32    // The parent serial that this data was correct for
	Timestamp        time.Time // Time at which this data was fetched
	ChildName        string
	RRsets           map[string]map[uint16]RRset // map[ownername]map[rrtype]RRset
	NS_rrs           []dns.RR
	A_glue           []dns.RR
	A_glue_rrsigs    []dns.RR
	AAAA_glue        []dns.RR
	AAAA_glue_rrsigs []dns.RR
	NS_rrset         *RRset
	DS_rrset         *RRset
	A_rrsets         []*RRset
	AAAA_rrsets      []*RRset
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
}

type ZoneRefresher struct {
	Name         string
	ZoneType     ZoneType // primary | secondary
	Primary      string
	Notify       []string
	ZoneStore    ZoneStore // 1=xfr, 2=map, 3=slice
	Zonefile     string
	Options      map[ZoneOption]bool
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
	RRset    *RRset
	Response chan ValidatorResponse
}

type ValidatorResponse struct {
	Validated bool
	Msg       string
}

// type TAStore map[string]map[uint16]TrustAnchor
type DnskeyCacheT struct {
	Map cmap.ConcurrentMap[string, TrustAnchor]
}

type TrustAnchor struct {
	Name       string
	Keyid      uint16
	Validated  bool
	Trusted    bool
	Dnskey     dns.DNSKEY // just this key
	RRset      *RRset     // complete RRset
	Expiration time.Time
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
	Name      string
	State     string
	Keyid     uint16
	Flags     uint16
	Algorithm string
	Creator   string
	// Validated  bool   // has this key been DNSSEC validated
	// Trusted    bool   // is this key trusted
	PrivateKey string //
	Key        dns.DNSKEY
	Keystr     string
}

type CachedRRset struct {
	Name       string
	RRtype     uint16
	Rcode      uint8
	RRset      *RRset
	Validated  bool
	Expiration time.Time
}

type RRsetCacheT struct {
	Map cmap.ConcurrentMap[string, CachedRRset]
}

type DelegationSyncRequest struct {
	Command    string
	ZoneName   string
	ZoneData   *ZoneData
	SyncStatus DelegationSyncStatus
	OldDnskeys *RRset
	NewDnskeys *RRset
	Response   chan DelegationSyncStatus // used for API-based requests
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
}

type Tx struct {
	*sql.Tx
	KeyDB   *KeyDB
	context string
}

type MultiSignerConf struct {
	Name       string
	Controller MultiSignerController
}

type MultiSignerController struct {
	Name   string
	Notify MSCNotifyConf
	API    MSCAPIConf
}

type MSCNotifyConf struct {
	Addresses []string `validate:"required"` // XXX: must not be in addr:port format
	Port      string   `validate:"required"`
	Targets   []string
}

type MSCAPIConf struct {
	BaseURL    string
	ApiKey     string
	AuthMethod string
	UseTLS     bool
}
