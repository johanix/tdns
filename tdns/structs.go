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
	mu             sync.Mutex
	ZoneName       string
	ZoneStore      ZoneStore // 1 = "xfr", 2 = "map", 3 = "slice". An xfr zone only supports xfr related ops
	ZoneType       ZoneType
	Owners         Owners
	OwnerIndex     cmap.ConcurrentMap[string, int]
	ApexLen        int
//	RRs            RRArray
	Data           cmap.ConcurrentMap[string, OwnerData]
	XfrType        string               // axfr | ixfr
	Logger         *log.Logger
	ZoneFile       string
	IncomingSerial uint32	// SOA serial that we got from upstream
	CurrentSerial  uint32	// SOA serial after local bumping
	Verbose        bool
	IxfrChain      []Ixfr
	Upstream       string   // primary from where zone is xfrred
	Downstreams    []string // secondaries that we notify
	Zonefile       string
}

type Ixfr struct {
	FromSerial uint32
	ToSerial   uint32
	Removed    []RRset
	Added      []RRset
}

type Owners []OwnerData

type OwnerData struct {
	Name	string
	RRtypes map[uint16]RRset
}

type RRset struct {
	Name	string
	RRs	[]dns.RR
	RRSIGs	[]dns.RR
}

type CommandPost struct {
	Command string
	Zone    string
	Force	bool
}

type CommandResponse struct {
	Time     time.Time
	Status   string
	Zone     string
	Msg      string
	Error    bool
	ErrorMsg string
}

type DebugPost struct {
	Command string
	Zone    string
	Qname   string
	Qtype   uint16
	Verbose	bool
}

type DebugResponse struct {
	Time       time.Time
	Status     string
	Zone       string
	OwnerIndex map[string]int
	RRset      RRset
	TrustedDnskeys	TAconfig
	TrustedSig0keys	Sig0config
	Msg        string
	Error      bool
	ErrorMsg   string
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
	Force	  bool		// force refresh, ignoring SOA serial
	Response  chan RefresherResponse
}

type RefresherResponse struct {
     Time 	       time.Time
     Zone	       string
     Msg	       string
     Error	       bool
     ErrorMsg	       string
}

type ValidatorRequest struct {
     Qname	      string
     RRset	      *RRset
     Response	      chan ValidatorResponse
}

type ValidatorResponse struct {
     Validated	       bool
     Msg	       string
}

type TAconfig map[string]TrustAnchor

type TrustAnchor struct {
     Name	 string
     Dnskey	 dns.DNSKEY
}

type Sig0config map[string]Sig0Key

type Sig0Key struct {
     Name	 string
     Key	 dns.KEY
}
