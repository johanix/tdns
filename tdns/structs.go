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
	IxfrChain        []Ixfr
	Upstream         string   // primary from where zone is xfrred
	Downstreams      []string // secondaries that we notify
	Zonefile         string
	DelegationSyncCh chan DelegationSyncRequest
	Parent           string   // name of parentzone (if filled in)
	ParentNS         []string // names of parent nameservers
	ParentServers    []string // addresses of parent nameservers
	Children         map[string]*ChildDelegationData
	Options		 map[string]bool
	// XXX: All of the following should go into a options =  map[string]bool
//	DelegationSync bool // should we (as child) attempt to sync delegation w/ parent?
//	OnlineSigning  bool // should we sign RRSIGs for missing signatures
//	AllowUpdates   bool // should we allow updates to this zone
//	FoldCase       bool // should we fold case for this zone
	Frozen         bool // if frozen no updates are allowed
	Dirty          bool // if true zone has been modified and we need to save the zonefile
}

// ZoneConf represents the external config for a zone; it contains no zone data
type ZoneConf struct {
	Name           string `validate:"required"`
	Type           string `validate:"required"`
	Store          string `validate:"required"` // xfr | map | slice | reg
	Primary        string
	Notify         []string
	Zonefile       string
	Options	       []string
//	DelegationSync bool // should we (as child) attempt to sync delegation w/ parent?
//	OnlineSigning  bool // should we sign RRSIGs for missing signatures
//	AllowUpdates   bool // should we allow updates to this zone
//	FoldCase       bool // should we fold case for this zone
	Frozen         bool // if true no updates are allowed; not a config param
	Dirty          bool // if true zone has been modified; not a config param
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
	RRs    []dns.RR
	RRSIGs []dns.RR
}

type ChildDelegationData struct {
	DelHasChanged bool      // When returned from a scanner, this indicates that a change has been detected
	ParentSerial  uint32    // The parent serial that this data was correct for
	Timestamp     time.Time // Time at which this data was fetched
	Name          string
	RRsets        map[string]map[uint16]RRset // map[ownername]map[rrtype]RRset
	NS_rrs        []dns.RR
	A_glue        []dns.RR
	AAAA_glue     []dns.RR
}

type KeystorePost struct {
	Command    string // "sig0"
	SubCommand string // "list" | "add" | "delete" | ...
	Zone       string
	Keyname    string
	Keyid      uint16
	Flags      uint16
	Algorithm  uint8 // RSASHA256 | ED25519 | etc.
	PrivateKey string
	KeyRR      string
	DnskeyRR   string
	State      string
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
	Command    string // "sig0"
	SubCommand string // "list-child-keys" | "trust-child-key" | "untrust-child-key"
	Zone       string
	Keyname    string
	Keyid      int
	Src        string // "dns" | "file"
	KeyRR      string // RR string for key
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
	Zone        string
	Parent      string
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
	TrustedDnskeys  map[string]TrustAnchor
	TrustedSig0keys map[string]Sig0Key
	Validated       bool
	Msg             string
	Error           bool
	ErrorMsg        string
}

type Api struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	apiKey     string
	Authmethod string
	Verbose    bool
	Debug      bool
}

type ZoneRefresher struct {
	Name           string
	ZoneType       ZoneType // primary | secondary
	Primary        string
	Notify         []string
	ZoneStore      ZoneStore // 1=xfr, 2=map, 3=slice
	Zonefile       string
	Options	       map[string]bool
//	DelegationSync bool
//	OnlineSigning  bool
//	AllowUpdates   bool
//	FoldCase       bool // should we fold case for this zone
	Force          bool // force refresh, ignoring SOA serial
	Response       chan RefresherResponse
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
type TAStoreT struct {
	Map cmap.ConcurrentMap[string, TrustAnchor]
}

type TrustAnchor struct {
	Name      string
	Validated bool
	Trusted   bool
	Dnskey    dns.DNSKEY
}

type Sig0StoreT struct {
	Map cmap.ConcurrentMap[string, Sig0Key]
}

type Sig0Key struct {
	Name       string
	State      string
	Keyid      uint16
	Algorithm  string
	Validated  bool   // has this key been DNSSEC validated
	Trusted    bool   // is this key trusted
	PrivateKey string //
	Key        dns.KEY
	Keystr     string
}

type DnssecKey struct {
	Name      string
	State     string
	Keyid     uint16
	Flags     uint16
	Algorithm string
	// Validated  bool   // has this key been DNSSEC validated
	// Trusted    bool   // is this key trusted
	PrivateKey string //
	Key        dns.DNSKEY
	Keystr     string
}

type DelegationSyncRequest struct {
	Command    string
	ZoneName   string
	ZoneData   *ZoneData
	Adds       []dns.RR
	Removes    []dns.RR
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
