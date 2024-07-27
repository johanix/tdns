/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"log"
	"net/http"
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

type ZoneData struct {
	mu         sync.Mutex
	ZoneName   string
	ZoneStore  ZoneStore // 1 = "xfr", 2 = "map", 3 = "slice". An xfr zone only supports xfr related ops
	ZoneType   ZoneType
	Owners     Owners
	OwnerIndex cmap.ConcurrentMap[string, int]
	ApexLen    int
	//	RRs            RRArray
	Data             cmap.ConcurrentMap[string, OwnerData]
	XfrType          string // axfr | ixfr
	Logger           *log.Logger
	ZoneFile         string
	IncomingSerial   uint32 // SOA serial that we got from upstream
	CurrentSerial    uint32 // SOA serial after local bumping
	Verbose          bool
	Debug            bool
	IxfrChain        []Ixfr
	Upstream         string   // primary from where zone is xfrred
	Downstreams      []string // secondaries that we notify
	Zonefile         string
	DelegationSyncCh chan DelegationSyncRequest
	Parent           string   // name of parentzone (if filled in)
	ParentNS         []string // names of parent nameservers
	ParentServers    []string // addresses of parent nameservers
	Children         map[string]*ChildDelegationData
	Options          map[string]bool
	UpdatePolicy     UpdatePolicy
	KeyDB            *KeyDB
}

// ZoneConf represents the external config for a zone; it contains no zone data
type ZoneConf struct {
	Name         string `validate:"required"`
	Zonefile     string
	Type         string `validate:"required"`
	Store        string `validate:"required"` // xfr | map | slice | reg
	Primary      string // upstream, for secondary zones
	Notify       []string
	Options      []string
	Frozen       bool // true if zone is frozen; not a config param
	Dirty        bool // true if zone has been modified; not a config param
	UpdatePolicy UpdatePolicyConf
	Template     string
}

type TemplateConf struct {
	Name         string `validate:"required"`
	Zonefile     string
	Type         string
	Store        string
	Primary      string // upstream, for secondary zones
	Notify       []string
	Options      []string
	UpdatePolicy UpdatePolicyConf
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

type Ixfr struct {
	FromSerial uint32
	ToSerial   uint32
	Removed    []RRset
	Added      []RRset
}

type Owners []OwnerData

type OwnerData struct {
	Name    string
	RRtypes map[uint16]RRset
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

type KeystorePost struct {
	Command         string // "sig0"
	SubCommand      string // "list" | "add" | "delete" | ...
	Zone            string
	Keyname         string
	Keyid           uint16
	Flags           uint16
	Algorithm       uint8 // RSASHA256 | ED25519 | etc.
	PrivateKey      string
	KeyRR           string
	DnskeyRR        string
	PrivateKeyCache *PrivateKeyCache
	State           string
}

type KeystoreResponse struct {
	Time     time.Time
	Status   string
	Zone     string
	Dnskeys  map[string]DnssecKey // TrustAnchor
	Sig0keys map[string]Sig0Key
	Msg      string
	Error    bool
	ErrorMsg string
}

type TruststorePost struct {
	Command         string // "sig0"
	SubCommand      string // "list-child-keys" | "trust-child-key" | "untrust-child-key"
	Zone            string
	Keyname         string
	Keyid           int
	Validated       bool
	DnssecValidated bool
	Trusted         bool
	Src             string // "dns" | "file"
	KeyRR           string // RR string for key
}

type TruststoreResponse struct {
	Time          time.Time
	Status        string
	Zone          string
	ChildDnskeys  map[string]TrustAnchor
	ChildSig0keys map[string]Sig0Key
	Msg           string
	Error         bool
	ErrorMsg      string
}

type CommandPost struct {
	Command    string
	SubCommand string
	Zone       string
	Force      bool
}

type CommandResponse struct {
	Time     time.Time
	Status   string
	Zone     string
	Names    []string
	Zones    map[string]ZoneConf
	Msg      string
	Error    bool
	ErrorMsg string
}

type DelegationPost struct {
	Command string // status | sync | ...
	Scheme  uint8  // 1=notify | 2=update
	Zone    string
	Force   bool
}

type DelegationResponse struct {
	Time       time.Time
	Zone       string
	SyncStatus DelegationSyncStatus
	Msg        string
	Error      bool
	ErrorMsg   string
}

type DelegationSyncStatus struct {
	ZoneName    string
	Parent      string // use zd.Parent instead
	Time        time.Time
	InSync      bool
	Status      string
	Msg         string
	Rcode       uint8
	Adds        []dns.RR
	Removes     []dns.RR
	NsAdds      []dns.RR
	NsRemoves   []dns.RR
	AAdds       []dns.RR
	ARemoves    []dns.RR
	AAAAAdds    []dns.RR
	AAAARemoves []dns.RR
	Error       bool
	ErrorMsg    string
}

type DebugPost struct {
	Command string
	Zone    string
	Qname   string
	Qtype   uint16
	Verbose bool
}

type DebugResponse struct {
	Time       time.Time
	Status     string
	Zone       string
	OwnerIndex map[string]int
	RRset      RRset
	//	TrustedDnskeys	map[string]dns.DNSKEY
	//	TrustedSig0keys	map[string]dns.KEY
	TrustedDnskeys  []TrustAnchor
	TrustedSig0keys map[string]Sig0Key
	CachedRRsets    []CachedRRset
	Validated       bool
	Msg             string
	Error           bool
	ErrorMsg        string
}

type ApiClient struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	apiKey     string
	AuthMethod string
	UseTLS     bool
	Verbose    bool
	Debug      bool
}

type ZoneRefresher struct {
	Name         string
	ZoneType     ZoneType // primary | secondary
	Primary      string
	Notify       []string
	ZoneStore    ZoneStore // 1=xfr, 2=map, 3=slice
	Zonefile     string
	Options      map[string]bool
	UpdatePolicy UpdatePolicy
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
	Command  string
	ZoneName string
	ZoneData *ZoneData
	// Adds       []dns.RR
	// Removes    []dns.RR
	SyncStatus DelegationSyncStatus
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
