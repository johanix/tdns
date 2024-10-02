/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"net/http"
	"time"
)

type KeystorePost struct {
	Command         string // "sig0"
	SubCommand      string // "list" | "add" | "delete" | ...
	Zone            string
	Keyname         string
	Keyid           uint16
	Flags           uint16
	KeyType         string
	Algorithm       uint8 // RSASHA256 | ED25519 | etc.
	PrivateKey      string
	KeyRR           string
	DnskeyRR        string
	PrivateKeyCache *PrivateKeyCache
	State           string
	Creator         string
}

type KeystoreResponse struct {
	AppName  string
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
	AppName       string
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
	AppName  string
	Time     time.Time
	Status   string
	Zone     string
	Names    []string
	Zones    map[string]ZoneConf
	Msg      string
	Error    bool
	ErrorMsg string
}

type ZonePost struct {
	Command    string
	SubCommand string
	Zone       string
	Force      bool
}

type ZoneResponse struct {
	AppName  string
	Time     time.Time
	Status   string
	Zone     string
	Names    []string
	Zones    map[string]ZoneConf
	Msg      string
	Error    bool
	ErrorMsg string
}
type ZoneDsyncPost struct {
	Command   string // status | bootstrap | ...
	Zone      string
	Algorithm uint8
	Action    string
	OldKeyID  uint16
	NewKeyID  uint16
}

type ZoneDsyncResponse struct {
	AppName      string
	Time         time.Time
	Status       string
	Zone         string
	Functions    map[string]string
	Todo         []string
	Msg          string
	OldKeyID     uint16
	NewKeyID     uint16
	Error        bool
	ErrorMsg     string
	UpdateResult UpdateResult
}
type ConfigPost struct {
	Command string // status | sync | ...
}

type ConfigResponse struct {
	AppName  string
	Time     time.Time
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
	AppName    string
	Time       time.Time
	Zone       string
	SyncStatus DelegationSyncStatus
	Msg        string
	Error      bool
	ErrorMsg   string
}

type DebugPost struct {
	Command string
	Zone    string
	Qname   string
	Qtype   uint16
	Verbose bool
}

type DebugResponse struct {
	AppName    string
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

type MultiSignerPost struct {
	Command string // "fetch-rrset" | "update" | "remove-rrset"
	Zone    string
	Name    string
	Type    uint16
}

type MultiSignerResponse struct {
	AppName  string
	Time     time.Time
	RRset    RRset
	Msg      string
	Error    bool
	ErrorMsg string
}
