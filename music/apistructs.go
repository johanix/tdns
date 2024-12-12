/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"net/http"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type APIstatus struct {
	Status  int
	Message string
}

type APIresponse struct {
	Status  int
	Message string
	Data    string
}

type ShowPost struct {
	Command string
}

type ShowResponse struct {
	Status   int
	Message  string
	ApiData  []string
	Updaters map[string]bool
}

type ShowAPIresponse struct {
	Status  int
	Message string
	Data    []string
}

type ShowUpdatersResponse struct {
	Status  int
	Message string
	Data    map[string]bool
}

type PingPost struct {
	Message string
	Pings   int
	Fetches int
	Updates int
}

type PingResponse struct {
	Time    time.Time
	Client  string
	Message string
	Pings   int
	Pongs   int
}

type TestPost struct {
	Command string
	Updater string
	Signer  string
	Zone    string
	Qname   string
	RRtype  string
	Count   int
}

type TestResponse struct {
	Time     time.Time
	Client   string
	Msg      string
	Error    bool
	ErrorMsg string
}

type ZonePost struct {
	Command      string
	Zone         Zone
	Owner        string
	RRtype       string
	Signer       string // debug
	FromSigner   string
	ToSigner     string
	SignerGroup  string
	FSM          string
	FSMSigner    string
	FsmNextState string
	Metakey      string
	Metavalue    string
}

type DNSRecords []dns.RR

type ZoneResponse struct {
	Time     time.Time
	Status   int
	Client   string
	Error    bool
	ErrorMsg string
	Msg      string
	Zones    map[string]Zone
	RRsets   map[string][]string // map[signer][]DNSRecords
	RRset    []string            // broken
}

type SignerPost struct {
	Command     string
	Signer      Signer
	SignerGroup string
}

type SignerResponse struct {
	Time     time.Time
	Status   int
	Client   string
	Error    bool
	ErrorMsg string
	Msg      string
	Signers  map[string]Signer
}

type SignerGroupPost struct {
	Command string
	Name    string
}

type SignerGroupResponse struct {
	Time         time.Time
	Status       int
	Client       string
	Error        bool
	ErrorMsg     string
	Msg          string
	SignerGroups map[string]SignerGroup
}

// type Api struct {
// 	Name       string
// 	Client     *http.Client
// 	BaseUrl    string
// 	apiKey     string
// 	Authmethod string
// 	Verbose    bool
// 	Debug      bool

// 	// deSEC stuff
// 	Email    string
// 	Password string
// 	TokViper *viper.Viper
// }

type MusicApi struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	apiKey     string
	Authmethod string
	Verbose    bool
	Debug      bool

	// tdns API client, we're using most of the tdns API client,
	ApiClient *tdns.ApiClient

	// deSEC stuff
	Email    string
	Password string
	TokViper *viper.Viper
}

type ProcessPost struct {
	Command string
	Process string
}

type ProcessResponse struct {
	Time      time.Time
	Status    int
	Client    string
	Error     bool
	ErrorMsg  string
	Msg       string
	Processes []Process
	Graph     string
}

type Process struct {
	Name string
	Desc string
}

type SidecarBeatPost struct {
	Type        string
	Identity    string
	SharedZones []string
}

type SidecarBeatResponse struct {
	Status   string
	Time     time.Time
	Client   string
	Msg      string
	Error    bool
	ErrorMsg string
}
type SidecarHelloPost struct {
	Type      string
	Name      string
	Identity  string
	Addresses []string
	Port      uint16
	TLSA      dns.TLSA
	Zones     []string
}

type SidecarHelloResponse struct {
	Status   string
	Time     time.Time
	Client   string
	Msg      string
	Error    bool
	ErrorMsg string
}
