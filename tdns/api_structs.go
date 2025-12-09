/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"net/http"
	"time"

	cache "github.com/johanix/tdns/tdns/cache"
	core "github.com/johanix/tdns/tdns/core"
	"github.com/spf13/viper"
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
	ParentState     uint8
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
	ChildDnskeys  map[string]cache.CachedDnskeyRRset
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
	AppName      string
	Time         time.Time
	Status       string
	Zone         string
	Names        []string
	Zones        map[string]ZoneConf
	Msg          string
	ApiEndpoints []string
	Error        bool
	ErrorMsg     string
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
	AppName    string
	Time       time.Time
	DnsEngine  DnsEngineConf
	ApiServer  ApiServerConf
	Identities []string
	Msg        string
	Error      bool
	ErrorMsg   string
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
	RRset      core.RRset
	//	TrustedDnskeys	map[string]dns.DNSKEY
	//	TrustedSig0keys	map[string]dns.KEY
	TrustedDnskeys  []cache.CachedDnskeyRRset
	TrustedSig0keys map[string]Sig0Key
	CachedRRsets    []cache.CachedRRset
	Validated       bool
	Msg             string
	Error           bool
	ErrorMsg        string
}

type ApiClient struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	Addresses  []string // if non-empty, replace the host part of the BaseUrl with each of these
	apiKey     string
	AuthMethod string
	UseTLS     bool
	Verbose    bool
	Debug      bool

	// deSEC stuff (from MUSIC)
	Email    string
	Password string
	TokViper *viper.Viper
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
	RRset    core.RRset
	Msg      string
	Error    bool
	ErrorMsg string
}

// ScanType represents the type of test to perform during scanning
type ScanType uint8

const (
	ScanRRtype ScanType = iota + 1
	ScanCDS
	ScanCSYNC
	ScanDNSKEY
)

var ScanTypeToString = map[ScanType]string{
	ScanRRtype: "rrtype",
	ScanCDS:    "cds",
	ScanCSYNC:  "csync",
	ScanDNSKEY: "dnskey",
}

var StringToScanType = map[string]ScanType{
	"rrtype": ScanRRtype,
	"cds":    ScanCDS,
	"csync":  ScanCSYNC,
	"dnskey": ScanDNSKEY,
}

// ScanCurrentData holds the current data for a scan test
// For ScanRRtype tests, it contains the current RRset for the queried RRtype at the name
// Note: This struct is not JSON-serializable directly. Use ToJSON() to convert to CurrentScanDataJSON.
type CurrentScanData struct {
	RRset  *core.RRset `json:"-"` // Current RRset for ScanRRtype test, nil if no data exists (not JSON serialized)
	CDS    *core.RRset `json:"-"` // Current CDS RRset for ScanCDS test, nil if no data exists (not JSON serialized)
	CSYNC  *core.RRset `json:"-"` // Current CSYNC RRset for ScanCSYNC test, nil if no data exists (not JSON serialized)
	DNSKEY *core.RRset `json:"-"` // Current DNSKEY RRset for ScanDNSKEY test, nil if no data exists (not JSON serialized)
}

// ToJSON converts CurrentScanData to a JSON-serializable format
func (csd *CurrentScanData) ToJSON() CurrentScanDataJSON {
	result := CurrentScanDataJSON{}
	if csd.RRset != nil {
		result.RRset = rrsetToString(csd.RRset)
	}
	if csd.CDS != nil {
		result.CDS = rrsetToString(csd.CDS)
	}
	if csd.CSYNC != nil {
		result.CSYNC = rrsetToString(csd.CSYNC)
	}
	if csd.DNSKEY != nil {
		result.DNSKEY = rrsetToString(csd.DNSKEY)
	}
	return result
}

// CurrentScanDataJSON is the JSON-serializable version of CurrentScanData
type CurrentScanDataJSON struct {
	RRset  *core.RRsetString `json:"rrset,omitempty"`
	CDS    *core.RRsetString `json:"cds,omitempty"`
	CSYNC  *core.RRsetString `json:"csync,omitempty"`
	DNSKEY *core.RRsetString `json:"dnskey,omitempty"`
}

// rrsetToString converts a core.RRset to core.RRsetString
func rrsetToString(rrset *core.RRset) *core.RRsetString {
	if rrset == nil {
		return nil
	}
	rrStrings := make([]string, len(rrset.RRs))
	for i, rr := range rrset.RRs {
		rrStrings[i] = rr.String()
	}
	rrsigStrings := make([]string, len(rrset.RRSIGs))
	for i, rrsig := range rrset.RRSIGs {
		rrsigStrings[i] = rrsig.String()
	}
	return &core.RRsetString{
		Name:   rrset.Name,
		RRtype: rrset.RRtype,
		RRs:    rrStrings,
		RRSIGs: rrsigStrings,
	}
}

type ScanTuple struct {
	Zone string // zone to scan	//
	// Type ScanType	// type of test to perform	// ScanRRtype | ScanCSYNC | ScanDNSKEY
	CurrentData CurrentScanData // current data for the test
	Options     []string        // "all-ns", ...
}

// ScanTupleResponse contains the result of scanning a single ScanTuple
type ScanTupleResponse struct {
	Qname       string              // The qname that was queried
	ScanType    ScanType            // The type of scan performed
	Options     []string            // Options that were used (e.g., "all-ns")
	NewData     CurrentScanDataJSON // The new data retrieved from the scan (JSON-serializable)
	DataChanged bool                // Whether the new data differs from the old data (from ScanTuple.CurrentData)
	AllNSInSync bool                // If "all-ns" option was set, whether all NS were in sync (false if not applicable)
	Error       bool                // Whether an error occurred
	ErrorMsg    string              // Error message if Error is true
}

type ScannerPost struct {
	Command    string      // "scan" | "status"
	ParentZone string      // Legacy field
	ScanZones  []string    // Legacy field
	ScanType   ScanType    // Legacy field: "cds" | "csync" | "dnskey"
	ScanTuples []ScanTuple // New field: list of scan tuples for scan requests
}

type ScannerResponse struct {
	AppName  string
	Time     time.Time
	Status   string
	Msg      string
	Error    bool
	ErrorMsg string
	JobID    string `json:"job_id,omitempty"` // Job ID for async scan requests
}

// ScanJobStatus represents the status of a scan job
type ScanJobStatus struct {
	JobID           string              `json:"job_id"`
	Status          string              `json:"status"` // "queued", "processing", "completed", "failed"
	CreatedAt       time.Time           `json:"created_at"`
	StartedAt       *time.Time          `json:"started_at,omitempty"`
	CompletedAt     *time.Time          `json:"completed_at,omitempty"`
	TotalTuples     int                 `json:"total_tuples"`
	IgnoredTuples   int                 `json:"ignored_tuples"`
	ErrorTuples     int                 `json:"error_tuples"`
	ProcessedTuples int                 `json:"processed_tuples"`
	Responses       []ScanTupleResponse `json:"responses,omitempty"`
	Error           bool                `json:"error,omitempty"`
	ErrorMsg        string              `json:"error_msg,omitempty"`
}
