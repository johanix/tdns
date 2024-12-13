/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"database/sql"
	"time"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type CliConfig struct {
	Debug   bool
	Verbose bool
}

type DBUpdate struct {
	Type          string
	Zone          string
	Key           string
	Value         string
	SignerNsNames map[string][]string // used in INSERT-ZONE-NS
	SignerDNSKEYs map[string][]string // used in INSERT-ZONE-DNSKEYS
}

type EngineCheck struct {
	ZoneName string
}

type Zone struct {
	Name       string
	Exists     bool   // true if zone is present in system
	State      string // state = state in currently ongoing process
	Statestamp time.Time
	NextState  map[string]bool
	StopReason string // possible reason for a state transition not to be possible
	FSMMode    string // "auto" | "manual"
	FSMStatus  string // fsmstatus = "blocked" if next state transition is not possible
	FSM        string
	FSMSigner  string
	SGroup     *SignerGroup
	SGname     string
	MusicDB    *MusicDB
	ZskState   string
	ZoneType   string // "normal", "debug"
	CSYNC      *dns.CSYNC
}

// A process object encapsulates the change that
type ZoneProcess struct {
	Type   string // "add-signer" | "remove-signer"
	Signer string // name of signer
}

type SignerGroup struct {
	Name            string
	Locked          bool
	SignerMap       map[string]*Signer
	CurrentProcess  string
	PendingRemoval  string // name of leaving signer
	PendingAddition string // name of joining signer
	NumZones        int
	NumProcessZones int
	State           string
	DB              *MusicDB
}

func (sg *SignerGroup) Signers() map[string]*Signer {
	return sg.SignerMap
}

type ZoneState string

type Signer struct {
	Name         string
	Exists       bool
	Method       string // "ddns" | "desec" | ...
	UseTcp       bool   // debugging tools, easier to check UDP
	UseTSIG      bool   // debugging tool, not for production
	Address      string
	Port         string
	AuthStr      string // AuthDataTmp // TODO: Issue #28
	Auth         AuthData
	SignerGroup  string   // single signer group for join/leave
	SignerGroups []string // all signer groups signer is member of
	DB           *MusicDB
}

// type AuthDataTmp string // TODO: Issue #28

type AuthData struct {
	TSIGKey    string
	TSIGName   string
	TSIGAlg    string // dns.HmacSHA256, etc
	ApiToken   string
	ApiBaseUrl string `validate:"required" json:"url"`
}

type MusicDB struct {
	db              *sql.DB
	UpdateC         chan DBUpdate
	FSMlist         map[string]FSM
	Tokvip          *viper.Viper
	StopReasonCache map[string]string // key: zonename value: stopreason
}

type SignerOp struct {
	Command  string
	Signer   *Signer
	Zone     string
	Owner    string
	RRtype   uint16
	Inserts  *[][]dns.RR
	Removes  *[][]dns.RR
	Response chan SignerOpResult
}

type SignerOpResult struct {
	Status   int
	Rcode    uint8 // only relevant for DDNS
	RRs      []dns.RR
	Error    error
	Response string
}

type Sidecar struct {
	Identity   string
	Methods    map[string]bool // supported methods: "API" and "DNS"
	Details    map[tdns.MsignerMethod]SidecarDetails
	LastHB     time.Time
	LastFullHB time.Time
	Api        *MusicApi
}

type SidecarDetails struct {
	Addrs       []string
	Port        uint16
	TlsaRR      *dns.TLSA
	UriRR       *dns.URI
	KeyRR       *dns.KEY
	BaseUri     string
	SharedZones []string
	LastHB      time.Time
	BeatCount   int
}

type MusicSyncStatus struct {
	Command  string
	Sidecars map[string]*Sidecar
	Error    bool
	ErrorMsg string
	Response chan MusicSyncStatus // Note: response channel uses same struct
}
