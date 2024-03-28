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
	"github.com/orcaman/concurrent-map/v2"
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
	Data           cmap.ConcurrentMap[string, OwnerData]
	XfrType        string // axfr | ixfr
	Logger         *log.Logger
	ZoneFile       string
	IncomingSerial uint32 // SOA serial that we got from upstream
	CurrentSerial  uint32 // SOA serial after local bumping
	Verbose        bool
	IxfrChain      []Ixfr
	Upstream       string   // primary from where zone is xfrred
	Downstreams    []string // secondaries that we notify
	Zonefile       string
	Parent         string   // name of parentzone (if filled in)
	ParentNS       []string // names of parent nameservers
	ParentServers  []string // addresses of parent nameservers
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

type KeystorePost struct {
	Command    string // "sig0"
	SubCommand string // "list" | "add" | "delete" | ...
	Zone       string
	Keyname    string
	Keyid      uint16
	Algorithm  uint8	// RSASHA256 | ED25519 | etc.
	PrivateKey string
	KeyRR      string
}

type KeystoreResponse struct {
	Time     time.Time
	Status   string
	Zone     string
	Dnskeys  map[string]TrustAnchor
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
	Time        time.Time
	Status      string
	Zone        string
	Parent	    string
	InSync      bool
	NsAdds      []dns.NS
	NsRemoves   []dns.NS
	AAdds       []dns.A
	ARemoves    []dns.A
	AAAAAdds    []dns.AAAA
	AAAARemoves []dns.AAAA
	Msg         string
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
	Name      string
	ZoneType  ZoneType // primary | secondary
	Primary   string
	Notify    []string
	ZoneStore ZoneStore // 1=xfr, 2=map, 3=slice
	Zonefile  string
	Force     bool // force refresh, ignoring SOA serial
	Response  chan RefresherResponse
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
	Keyid      uint16
	Algorithm  string
	Validated  bool   // has this key been DNSSEC validated
	Trusted    bool   // is this key trusted
	PrivateKey string //
	Key        dns.KEY
	Keystr     string
}
