/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
)

type ScanRequest struct {
	Cmd              string
	ParentZone       string
	ScanZones        []string
	ScanType         ScanType // "cds" | "csync" | "dnskey"
	ScanTuples       []ScanTuple
	ChildZone        string
	CurrentChildData ChildDelegationData // Current parent-side delegation data for child
	ZoneData         *ZoneData
	RRtype           uint16
	Edns0Options     *edns0.MsgOptions
	Response         chan ScanResponse
	JobID            string // Job ID for async processing
}

type ScanResponse struct {
	Time     time.Time
	Zone     string
	RRtype   uint16
	RRset    core.RRset
	Msg      string
	Error    bool
	ErrorMsg string
}

//
// This will wait forever on an external signal, but even better would be
// if we could wait on an external signal OR an internal quit channel. TBD.

type Scanner struct {
	AuthQueryQ     chan AuthQueryRequest
	ImrEngine      *Imr
	Options        []string
	AtApexChecks   int
	AtApexInterval time.Duration
	OnDSChange     func(parentZone string, zd *ZoneData, resp ScanTupleResponse)
	LogFile        string
	LogTemplate    string
	Log            map[string]*log.Logger
	Verbose        bool
	Debug          bool
	Jobs           map[string]*ScanJobStatus
	JobsMutex      sync.RWMutex
}

func (scanner *Scanner) HasOption(name string) bool {
	for _, opt := range scanner.Options {
		if strings.EqualFold(opt, name) {
			return true
		}
	}
	return false
}

func NewScanner(authqueryq chan AuthQueryRequest, verbose, debug bool) *Scanner {
	return &Scanner{
		AuthQueryQ:  authqueryq,
		Log:         map[string]*log.Logger{},
		LogTemplate: "/var/log/tdns/scanner-%s.log",
		Verbose:     verbose,
		Debug:       debug,
		Jobs:        make(map[string]*ScanJobStatus),
	}
}

// GenerateJobID generates a unique job ID using crypto/rand.
func GenerateJobID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("GenerateJobID: crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (scanner *Scanner) AddLogger(rrtype string) error {
	lg := log.New(&lumberjack.Logger{
		Filename:   fmt.Sprintf(scanner.LogTemplate, rrtype),
		MaxSize:    20,
		MaxBackups: 3,
		MaxAge:     7,
	}, fmt.Sprintf("%s scanner: ", rrtype), log.Lshortfile)
	scanner.Log[rrtype] = lg
	scanner.Log[rrtype] = log.Default()
	return nil
}

func ScannerEngine(ctx context.Context, conf *Config) error {
	scannerq := conf.Internal.ScannerQ
	authqueryq := conf.Internal.AuthQueryQ
	interval := viper.GetInt("scanner.interval")
	if interval < 10 {
		interval = 10
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)

	scanner := NewScanner(authqueryq, true, true)
	scanner.Options = viper.GetStringSlice("scanner.options")
	scanner.AtApexChecks = viper.GetInt("scanner.at-apex.checks")
	if scanner.AtApexChecks < 1 {
		scanner.AtApexChecks = 1
	}
	atApexIntervalSec := viper.GetInt("scanner.at-apex.interval")
	if atApexIntervalSec < 1 {
		atApexIntervalSec = 300
	}
	scanner.AtApexInterval = time.Duration(atApexIntervalSec) * time.Second
	scanner.AddLogger("CDS")
	scanner.AddLogger("CSYNC")
	scanner.AddLogger("DNSKEY")
	scanner.AddLogger("GENERIC")

	// Wire callback to apply DS changes via CHILD-UPDATE
	scanner.OnDSChange = func(parentZone string, zd *ZoneData, resp ScanTupleResponse) {
		if zd.KeyDB == nil || zd.KeyDB.UpdateQ == nil {
			lg.Error("ScannerEngine: OnDSChange: no UpdateQ for zone", "zone", parentZone)
			return
		}
		var actions []dns.RR
		for _, rr := range resp.DSAdds {
			rr.Header().Class = dns.ClassINET
			actions = append(actions, rr)
		}
		for _, rr := range resp.DSRemoves {
			rr.Header().Class = dns.ClassNONE
			actions = append(actions, rr)
		}
		lg.Info("ScannerEngine: OnDSChange: enqueuing CHILD-UPDATE", "parent", parentZone, "child", resp.Qname, "adds", len(resp.DSAdds), "removes", len(resp.DSRemoves))
		zd.KeyDB.UpdateQ <- UpdateRequest{
			Cmd:            "CHILD-UPDATE",
			UpdateType:     "CDS",
			ZoneName:       parentZone,
			Actions:        actions,
			Trusted:        true,
			InternalUpdate: true,
			Description:    fmt.Sprintf("CDS scan: DS update for %s", resp.Qname),
		}
	}

	// Store scanner instance in Config for API handler access
	conf.Internal.Scanner = scanner

	lg.Info("ScannerEngine: starting")
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			lg.Info("ScannerEngine: context cancelled")
			return nil
		case <-ticker.C:

		case sr, ok := <-scannerq:
			if !ok {
				lg.Info("ScannerEngine: scannerq closed")
				return nil
			}
			switch sr.Cmd {
			case "SCAN":
				scanner.ImrEngine = conf.Internal.ImrEngine

				// Bridge NOTIFY → ScanTuples: if ScanTuples is empty but
				// ChildZone+RRtype are set (from NOTIFY), synthesize a tuple.
				if len(sr.ScanTuples) == 0 && sr.ChildZone != "" && sr.RRtype != 0 {
					switch sr.RRtype {
					case dns.TypeCDS:
						sr.ScanType = ScanCDS
					case dns.TypeCSYNC:
						sr.ScanType = ScanCSYNC
					case dns.TypeDNSKEY:
						sr.ScanType = ScanDNSKEY
					}

					tuple := ScanTuple{
						Zone: sr.ChildZone,
					}

					// Fetch current DS from delegation backend for comparison
					if sr.ZoneData != nil && sr.ZoneData.DelegationBackend != nil {
						delegData, err := sr.ZoneData.DelegationBackend.GetDelegationData(sr.ZoneData.ZoneName, sr.ChildZone)
						if err != nil {
							lg.Warn("ScannerEngine: error fetching delegation data", "child", sr.ChildZone, "error", err)
						} else if delegData != nil {
							var dsRRs []dns.RR
							for _, rrsByType := range delegData {
								if dsRecords, ok := rrsByType[dns.TypeDS]; ok {
									dsRRs = append(dsRRs, dsRecords...)
								}
							}
							if len(dsRRs) > 0 {
								tuple.CurrentData.DS = &core.RRset{
									Name:   sr.ChildZone,
									RRtype: dns.TypeDS,
									RRs:    dsRRs,
								}
							}
						}
					}

					sr.ScanTuples = []ScanTuple{tuple}
					lg.Info("ScannerEngine: synthesized ScanTuple from NOTIFY", "child", sr.ChildZone, "scanType", ScanTypeToString[sr.ScanType], "hasCurrentDS", tuple.CurrentData.DS != nil)
				}

				lg.Info("ScannerEngine: received SCAN request", "tuples", len(sr.ScanTuples), "jobID", sr.JobID)

				// Create or update job status
				jobID := sr.JobID
				if jobID == "" {
					var err error
					jobID, err = GenerateJobID()
					if err != nil {
						lg.Error("ScannerEngine: failed to generate job ID", "error", err)
						continue
					}
				}

				job := &ScanJobStatus{
					JobID:           jobID,
					Status:          "processing",
					CreatedAt:       time.Now(),
					TotalTuples:     len(sr.ScanTuples),
					IgnoredTuples:   0,
					ErrorTuples:     0,
					ProcessedTuples: 0,
				}
				startedAt := time.Now()
				job.StartedAt = &startedAt

				scanner.JobsMutex.Lock()
				scanner.Jobs[jobID] = job
				scanner.JobsMutex.Unlock()

				// Create response channel for collecting all scan results
				responseCh := make(chan ScanTupleResponse, len(sr.ScanTuples))
				var wg sync.WaitGroup

				for _, tuple := range sr.ScanTuples {
					if tuple.Zone == "" {
						lg.Warn("ScannerEngine: zone unspecified, ignoring")
						job.IgnoredTuples++
						continue
					}

					lg.Debug("ScannerEngine: processing zone", "zone", tuple.Zone, "currentData", fmt.Sprintf("%+v", tuple.CurrentData))
					wg.Add(1)

					switch sr.ScanType {
					/*
						case ScanRRtype:
							log.Printf("ScannerEngine: ScanRRtype not implemented")
							err := conf.Internal.ImrEngine.SendRfc9567ErrorReport(ctx, tuple.Zone, sr.RRtype, edns0.EDECSyncScannerNotImplemented, sr.Edns0Options)
							//if err != nil {
							//	lg.Error("ScannerEngine: SendRfc9567ErrorReport failed", "error", err)
							//}
							go func(t ScanTuple) {
								defer wg.Done()
								newData := CurrentScanData{}
								response := ScanTupleResponse{
									Qname:    t.Zone,
									ScanType: sr.ScanType,
									Options:  t.Options,
									NewData:  newData.ToJSON(),
									Error:    true,
									ErrorMsg: "ScanRRtype not implemented",
								}
								responseCh <- response
							}(tuple)
					*/
					case ScanCDS:
						if sr.ZoneData != nil {
							lg.Debug("ScannerEngine: dispatching ProcessCDSNotify", "child", tuple.Zone)
							go func(t ScanTuple, parentZD *ZoneData) {
								defer wg.Done()
								scanner.ProcessCDSNotify(ctx, t, parentZD, sr.ScanType, sr.Edns0Options, responseCh)
							}(tuple, sr.ZoneData)
						} else {
							lg.Debug("ScannerEngine: dispatching CheckCDS")
							go func(t ScanTuple) {
								defer wg.Done()
								scanner.CheckCDS(ctx, t, sr.ScanType, sr.Edns0Options, responseCh)
							}(tuple)
						}
					case ScanCSYNC:
						go func(t ScanTuple) {
							defer wg.Done()
							scanner.CheckCSYNC_NG(ctx, t, sr.ScanType, sr.Edns0Options, responseCh)
						}(tuple)
					case ScanDNSKEY:
						lg.Debug("ScannerEngine: dispatching CheckDNSKEY")
						go func(t ScanTuple) {
							defer wg.Done()
							scanner.CheckDNSKEY(ctx, t, sr.ScanType, sr.Edns0Options, responseCh)
						}(tuple)
					}
				}

				// Wait for all scans to complete and collect responses
				go func(jobID string, parentZD *ZoneData) {
					wg.Wait()
					close(responseCh)

					// Collect all responses
					var responses []ScanTupleResponse
					for resp := range responseCh {
						responses = append(responses, resp)
					}

					// Update job status
					scanner.JobsMutex.Lock()
					job, exists := scanner.Jobs[jobID]
					if exists {
						job.Responses = responses
						job.ProcessedTuples = len(responses)
						job.Status = "completed"
						completedAt := time.Now()
						job.CompletedAt = &completedAt
					}
					scanner.JobsMutex.Unlock()

					// Notify caller of DS changes
					if scanner.OnDSChange != nil && parentZD != nil {
						for _, resp := range responses {
							if resp.DataChanged && (len(resp.DSAdds) > 0 || len(resp.DSRemoves) > 0) {
								scanner.OnDSChange(parentZD.ZoneName, parentZD, resp)
							}
						}
					}

					lg.Info("ScannerEngine: job completed", "jobID", jobID, "responses", len(responses))
				}(jobID, sr.ZoneData)
			default:
				lg.Warn("ScannerEngine: unknown command, ignoring", "cmd", sr.Cmd)
			}
		}
	}
}

// findEnclosingZoneNS determines the enclosing zone for a given name and returns
// the zone name and its NS RRset. If the name is a zone (has SOA), it returns that zone's NS.
// Otherwise, it finds the parent zone and returns the parent's NS.
// Returns: (zoneName, nsRRset, error)
func (imr *Imr) findEnclosingZoneNS(ctx context.Context, qname string, lg *log.Logger) (string, *core.RRset, error) {
	// Step 1: Determine if the name is a zone by querying for SOA
	soaResp, err := imr.ImrQuery(ctx, qname, dns.TypeSOA, dns.ClassINET, nil)
	if err != nil {
		return "", nil, fmt.Errorf("error querying SOA for %s: %v", qname, err)
	}

	var zoneName string
	var nsRRset *core.RRset

	if soaResp != nil && soaResp.RRset != nil && len(soaResp.RRset.RRs) > 0 {
		// The name is a zone - query for NS RRset
		if lg != nil {
			lg.Printf("findEnclosingZoneNS: %s is a zone (SOA found), querying for NS RRset", qname)
		}
		zoneName = qname
		nsResp, err := imr.ImrQuery(ctx, qname, dns.TypeNS, dns.ClassINET, nil)
		if err != nil {
			return "", nil, fmt.Errorf("error querying NS for zone %s: %v", qname, err)
		}
		if nsResp == nil || nsResp.RRset == nil || len(nsResp.RRset.RRs) == 0 {
			return "", nil, fmt.Errorf("no NS RRset found for zone %s", qname)
		}
		nsRRset = nsResp.RRset
	} else {
		// The name is not a zone - find the parent zone
		if lg != nil {
			lg.Printf("findEnclosingZoneNS: %s is not a zone (no SOA), finding parent zone", qname)
		}
		parentZone, err := imr.ParentZone(qname)
		if err != nil {
			return "", nil, fmt.Errorf("error finding parent zone for %s: %v", qname, err)
		}
		zoneName = parentZone
		if lg != nil {
			lg.Printf("findEnclosingZoneNS: parent zone for %s is %s, querying for NS RRset", qname, parentZone)
		}
		nsResp, err := imr.ImrQuery(ctx, parentZone, dns.TypeNS, dns.ClassINET, nil)
		if err != nil {
			return "", nil, fmt.Errorf("error querying NS for parent zone %s: %v", parentZone, err)
		}
		if nsResp == nil || nsResp.RRset == nil || len(nsResp.RRset.RRs) == 0 {
			return "", nil, fmt.Errorf("no NS RRset found for parent zone %s", parentZone)
		}
		nsRRset = nsResp.RRset
	}

	return zoneName, nsRRset, nil
}

// queryAllNSAndCompare queries all nameservers in an NS RRset for a given qname/qtype,
// compares the responses, and returns a representative RRset and whether all NS were in sync.
// Returns: (responseRRset, allInSync, error)
func (scanner *Scanner) queryAllNSAndCompare(ctx context.Context, qname string, qtype uint16, nsRRset *core.RRset, imr *Imr, lg *log.Logger) (*core.RRset, bool, error) {
	// Extract nameserver names from NS RRset
	var nsNames []string
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames = append(nsNames, ns.Ns)
		}
	}

	if len(nsNames) == 0 {
		return nil, false, fmt.Errorf("no nameservers found in NS RRset")
	}

	if lg != nil {
		lg.Printf("queryAllNSAndCompare: querying %s %s from %d nameservers: %v", qname, dns.TypeToString[qtype], len(nsNames), nsNames)
	}

	// Query from each nameserver and collect responses
	var responseRRsets []*core.RRset
	var queryErrors []error

	for _, nsName := range nsNames {
		// Get A/AAAA records for the nameserver
		var nsAddrs []string
		for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			addrResp, err := imr.ImrQuery(ctx, nsName, rrtype, dns.ClassINET, nil)
			if err != nil {
				if scanner.Verbose && lg != nil {
					lg.Printf("queryAllNSAndCompare: error querying %s for NS %s: %v", dns.TypeToString[rrtype], nsName, err)
				}
				continue
			}
			if addrResp != nil && addrResp.RRset != nil {
				for _, rr := range addrResp.RRset.RRs {
					switch rr := rr.(type) {
					case *dns.A:
						nsAddrs = append(nsAddrs, rr.A.String()+":53")
					case *dns.AAAA:
						nsAddrs = append(nsAddrs, "["+rr.AAAA.String()+"]:53")
					}
				}
			}
		}

		if len(nsAddrs) == 0 {
			if lg != nil {
				lg.Printf("queryAllNSAndCompare: no addresses found for NS %s, skipping", nsName)
			}
			continue
		}

		// Query from the first available address for this nameserver
		// (In a production system, you might want to try all addresses)
		rrset, err := scanner.AuthQueryNG(qname, nsAddrs[0], qtype, "tcp")
		if err != nil {
			if lg != nil {
				lg.Printf("queryAllNSAndCompare: error querying %s %s from %s (%s): %v", qname, dns.TypeToString[qtype], nsName, nsAddrs[0], err)
			}
			_ = append(queryErrors, fmt.Errorf("NS %s: %v", nsName, err))
			continue
		}
		if rrset == nil || len(rrset.RRs) == 0 {
			if lg != nil {
				lg.Printf("queryAllNSAndCompare: no %s RRset found from %s", dns.TypeToString[qtype], nsName)
			}
			continue
		}
		responseRRsets = append(responseRRsets, rrset)
	}

	// Check if we got any responses
	if len(responseRRsets) == 0 {
		return nil, false, fmt.Errorf("no %s RRsets retrieved from any nameserver", dns.TypeToString[qtype])
	}

	// If only one response, we can't compare but return it
	if len(responseRRsets) == 1 {
		if lg != nil {
			lg.Printf("queryAllNSAndCompare: only one %s RRset retrieved (cannot compare)", dns.TypeToString[qtype])
		}
		return responseRRsets[0], true, nil // Consider it "in sync" since there's only one
	}

	// Compare all responses to see if they're in sync
	baseRRset := responseRRsets[0]
	allInSync := true
	for i := 1; i < len(responseRRsets); i++ {
		changed, adds, removes := core.RRsetDiffer(qname, baseRRset.RRs, responseRRsets[i].RRs, qtype, lg, scanner.Verbose, scanner.Debug)
		if changed {
			if lg != nil {
				lg.Printf("queryAllNSAndCompare: %s RRsets differ between nameservers. Adds: %d, Removes: %d", dns.TypeToString[qtype], len(adds), len(removes))
			}
			allInSync = false
		}
	}

	if allInSync && lg != nil {
		lg.Printf("queryAllNSAndCompare: all %d nameservers have identical %s RRsets", len(responseRRsets), dns.TypeToString[qtype])
	}

	return baseRRset, allInSync, nil
}

func (scanner *Scanner) CheckCDS(ctx context.Context, tuple ScanTuple, scanType ScanType, options *edns0.MsgOptions, responseCh chan<- ScanTupleResponse) {
	scanLog := scanner.Log["CDS"]
	if scanLog == nil {
		scanLog = log.Default()
	}

	zone := tuple.Zone
	lg.Debug("ScannerEngine: checking CDS", "zone", zone)

	// Prepare response
	newData := CurrentScanData{}
	response := ScanTupleResponse{
		Qname:    zone,
		ScanType: scanType,
		Options:  tuple.Options,
		NewData:  newData.ToJSON(),
	}

	// Check if "all-ns" option is set
	checkAllNS := false
	for _, opt := range tuple.Options {
		if strings.EqualFold(opt, "all-ns") {
			checkAllNS = true
			break
		}
	}

	if !checkAllNS {
		// Simple case: just query for CDS and compare to CurrentData
		resp, err := scanner.ImrEngine.ImrQuery(ctx, zone, dns.TypeCDS, dns.ClassINET, nil)
		if err != nil {
			scanLog.Printf("CheckCDS: Zone %s: error from ImrQuery: %v", zone, err)
			response.Error = true
			response.ErrorMsg = fmt.Sprintf("error from ImrQuery: %v", err)
			responseCh <- response
			return
		}
		if resp == nil || resp.RRset == nil {
			scanLog.Printf("CheckCDS: Zone %s: no CDS RRset found", zone)
			response.Error = false
			response.DataChanged = false
			responseCh <- response
			return
		}

		newData.CDS = resp.RRset
		response.NewData = newData.ToJSON()
		response.AllNSInSync = false // Not applicable when "all-ns" is not set

		// Compare with CurrentData.CDS if present
		if tuple.CurrentData.CDS != nil {
			changed, adds, removes := core.RRsetDiffer(zone, resp.RRset.RRs, tuple.CurrentData.CDS.RRs, dns.TypeCDS, scanLog, scanner.Verbose, scanner.Debug)
			response.DataChanged = changed
			if changed {
				scanLog.Printf("CheckCDS: Zone %s: CDS RRset changed. Adds: %d, Removes: %d", zone, len(adds), len(removes))
			} else {
				scanLog.Printf("CheckCDS: Zone %s: CDS RRset unchanged", zone)
			}
		} else {
			response.DataChanged = true // New data found where none existed before
			scanLog.Printf("CheckCDS: Zone %s: CDS RRset found (no previous data to compare)", zone)
		}
		responseCh <- response
		return
	}

	// "all-ns" option is set: check all authoritative nameservers
	scanLog.Printf("CheckCDS: Zone %s: checking all authoritative nameservers", zone)

	// Find the enclosing zone and its NS RRset
	_, nsRRset, err := scanner.ImrEngine.findEnclosingZoneNS(ctx, zone, scanLog)
	if err != nil {
		scanLog.Printf("CheckCDS: Zone %s: error finding enclosing zone NS: %v", zone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("error finding enclosing zone NS: %v", err)
		responseCh <- response
		return
	}

	// Query CDS from all nameservers and compare
	cdsRRset, allInSync, err := scanner.queryAllNSAndCompare(ctx, zone, dns.TypeCDS, nsRRset, scanner.ImrEngine, scanLog)
	if err != nil {
		scanLog.Printf("CheckCDS: Zone %s: error querying all NS: %v", zone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("error querying all NS: %v", err)
		responseCh <- response
		return
	}

	newData.CDS = cdsRRset
	response.NewData = newData.ToJSON()
	response.AllNSInSync = allInSync

	if !allInSync {
		scanLog.Printf("CheckCDS: Zone %s: nameservers are not in sync for CDS", zone)
	}

	// Compare with CurrentData.CDS if present
	if tuple.CurrentData.CDS != nil {
		changed, adds, removes := core.RRsetDiffer(zone, cdsRRset.RRs, tuple.CurrentData.CDS.RRs, dns.TypeCDS, scanLog, scanner.Verbose, scanner.Debug)
		response.DataChanged = changed
		if changed {
			scanLog.Printf("CheckCDS: Zone %s: CDS RRset changed compared to CurrentData. Adds: %d, Removes: %d", zone, len(adds), len(removes))
		} else {
			scanLog.Printf("CheckCDS: Zone %s: CDS RRset unchanged compared to CurrentData", zone)
		}
	} else {
		response.DataChanged = true // New data found where none existed before
		scanLog.Printf("CheckCDS: Zone %s: CDS RRset retrieved (no previous data to compare)", zone)
	}

	responseCh <- response
}

func (scanner *Scanner) CheckCSYNC_NG(ctx context.Context, tuple ScanTuple, scanType ScanType, options *edns0.MsgOptions, responseCh chan<- ScanTupleResponse) {
	lg.Info("ScannerEngine: checking CSYNC", "zone", tuple.Zone)
	err := scanner.ImrEngine.SendRfc9567ErrorReport(ctx, tuple.Zone, dns.TypeCSYNC, edns0.EDECSyncScannerNotImplemented, options)
	if err != nil {
		lg.Error("ScannerEngine: SendRfc9567ErrorReport failed", "error", err)
	}

	// Send response indicating not implemented
	newData := CurrentScanData{}
	response := ScanTupleResponse{
		Qname:    tuple.Zone,
		ScanType: scanType,
		Options:  tuple.Options,
		NewData:  newData.ToJSON(),
		Error:    true,
		ErrorMsg: "CSYNC scanner not implemented",
	}
	responseCh <- response
}

func (scanner *Scanner) CheckDNSKEY(ctx context.Context, tuple ScanTuple, scanType ScanType, options *edns0.MsgOptions, responseCh chan<- ScanTupleResponse) {
	lg.Info("ScannerEngine: checking DNSKEY", "zone", tuple.Zone)
	err := scanner.ImrEngine.SendRfc9567ErrorReport(ctx, tuple.Zone, dns.TypeDNSKEY, edns0.EDECSyncScannerNotImplemented, options)
	if err != nil {
		lg.Error("ScannerEngine: SendRfc9567ErrorReport failed", "error", err)
	}

	// Send response indicating not implemented
	newData := CurrentScanData{}
	response := ScanTupleResponse{
		Qname:    tuple.Zone,
		ScanType: scanType,
		Options:  tuple.Options,
		NewData:  newData.ToJSON(),
		Error:    true,
		ErrorMsg: "DNSKEY scanner not implemented",
	}
	responseCh <- response
}

// ProcessCDSNotify handles a CDS NOTIFY by querying CDS from child
// nameservers, converting CDS→DS, and diffing against current DS.
// The scanner is read-only: results (DSAdds/DSRemoves) are returned
// in the ScanTupleResponse for the caller to act on.
func (scanner *Scanner) ProcessCDSNotify(ctx context.Context, tuple ScanTuple, parentZD *ZoneData, scanType ScanType, options *edns0.MsgOptions, responseCh chan<- ScanTupleResponse) {
	scanLog := scanner.Log["CDS"]
	if scanLog == nil {
		scanLog = log.Default()
	}

	childZone := tuple.Zone
	response := ScanTupleResponse{
		Qname:    childZone,
		ScanType: scanType,
		Options:  tuple.Options,
	}

	// 1. Get child NS from parent zone data
	owner, err := parentZD.GetOwner(childZone)
	if err != nil || owner == nil {
		scanLog.Printf("ProcessCDSNotify: %s: cannot get owner from parent zone: %v", childZone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("cannot get owner data for %s: %v", childZone, err)
		responseCh <- response
		return
	}

	nsRRsetVal := owner.RRtypes.GetOnlyRRSet(dns.TypeNS)
	nsRRset := &nsRRsetVal
	if len(nsRRset.RRs) == 0 {
		scanLog.Printf("ProcessCDSNotify: %s: no NS records in parent zone", childZone)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("no NS delegation for %s in parent zone", childZone)
		responseCh <- response
		return
	}

	// 2. Query CDS from all child NS via AuthQueryNG/TCP
	cdsRRset, allInSync, err := scanner.queryAllNSAndCompare(ctx, childZone, dns.TypeCDS, nsRRset, scanner.ImrEngine, scanLog)
	if err != nil {
		scanLog.Printf("ProcessCDSNotify: %s: error querying CDS from child NS: %v", childZone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("error querying CDS: %v", err)
		responseCh <- response
		return
	}
	response.AllNSInSync = allInSync

	if !allInSync {
		scanLog.Printf("ProcessCDSNotify: %s: child nameservers not in sync for CDS, aborting", childZone)
		response.Error = true
		response.ErrorMsg = "child nameservers not in sync for CDS"
		responseCh <- response
		return
	}

	if cdsRRset == nil || len(cdsRRset.RRs) == 0 {
		scanLog.Printf("ProcessCDSNotify: %s: no CDS records found at child", childZone)
		response.DataChanged = false
		responseCh <- response
		return
	}

	// 2b. DNSSEC validation gate (RFC 8078 / RFC 9615)
	bootstrapping := tuple.CurrentData.DS == nil || len(tuple.CurrentData.DS.RRs) == 0
	requireValidation := !scanner.HasOption("no-dnssec-validation")

	if scanner.HasOption("at-ns") {
		// RFC 9615: verify CDS via signaling names under each NS zone
		sigCDS, err := scanner.queryCDSAtSignalingNames(ctx, childZone, nsRRset, cdsRRset, scanLog)
		if err != nil {
			scanLog.Printf("ProcessCDSNotify: %s: RFC 9615 signaling verification failed: %v", childZone, err)
			response.Error = true
			response.ErrorMsg = fmt.Sprintf("RFC 9615 signaling verification failed: %v", err)
			responseCh <- response
			return
		}
		scanLog.Printf("ProcessCDSNotify: %s: RFC 9615 signaling verification passed", childZone)
		// Use signaling-verified CDS
		cdsRRset = sigCDS
	} else if requireValidation {
		if scanner.HasOption("at-apex") && bootstrapping {
			// RFC 8078 opportunistic onboarding: bootstrapping with
			// no existing DS — accept without DNSSEC validation.
			// All NS already verified in sync above.
			// RFC 8078 recommends repeated checks over time before
			// accepting. Config: at-apex.checks and at-apex.interval.
			if scanner.AtApexChecks > 1 {
				scanLog.Printf("ProcessCDSNotify: %s: RFC 8078 bootstrapping: config requires %d checks at %v intervals, but only performing 1 check (time-delay not yet implemented)", childZone, scanner.AtApexChecks, scanner.AtApexInterval)
			}
			scanLog.Printf("ProcessCDSNotify: %s: RFC 8078 bootstrapping (no existing DS), accepting CDS without DNSSEC validation", childZone)
		} else {
			// Direct queries (AuthQueryNG) don't provide DNSSEC
			// validation. To validate: query CDS via IMR instead,
			// which validates using the existing DS trust chain.
			// For now, proceed without validation.
			scanLog.Printf("ProcessCDSNotify: %s: DNSSEC validation of direct CDS query not yet implemented, proceeding without", childZone)
		}
	}

	// 3. Check for CDS removal sentinel (algorithm 0 per RFC 8078)
	isRemoval := false
	for _, rr := range cdsRRset.RRs {
		if cds, ok := rr.(*dns.CDS); ok {
			if cds.Algorithm == 0 {
				isRemoval = true
				break
			}
		}
	}

	if isRemoval {
		if tuple.CurrentData.DS == nil || len(tuple.CurrentData.DS.RRs) == 0 {
			scanLog.Printf("ProcessCDSNotify: %s: CDS removal sentinel but no existing DS", childZone)
			response.DataChanged = false
			responseCh <- response
			return
		}
		scanLog.Printf("ProcessCDSNotify: %s: CDS removal sentinel, removing %d DS records", childZone, len(tuple.CurrentData.DS.RRs))
		response.DataChanged = true
		response.DSRemoves = tuple.CurrentData.DS.RRs
		newData := CurrentScanData{CDS: cdsRRset}
		response.NewData = newData.ToJSON()
		responseCh <- response
		return
	}

	// 4. Convert CDS → DS
	var newDSRRs []dns.RR
	for _, rr := range cdsRRset.RRs {
		if cds, ok := rr.(*dns.CDS); ok {
			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   cds.Hdr.Name,
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    cds.Hdr.Ttl,
				},
				KeyTag:     cds.KeyTag,
				Algorithm:  cds.Algorithm,
				DigestType: cds.DigestType,
				Digest:     cds.Digest,
			}
			newDSRRs = append(newDSRRs, ds)
		}
	}

	// 5. Compare new DS vs current DS from delegation backend
	var currentDSRRs []dns.RR
	if tuple.CurrentData.DS != nil {
		currentDSRRs = tuple.CurrentData.DS.RRs
	}

	changed, adds, removes := core.RRsetDiffer(childZone, newDSRRs, currentDSRRs, dns.TypeDS, scanLog, scanner.Verbose, scanner.Debug)
	response.DataChanged = changed
	if changed {
		response.DSAdds = adds
		response.DSRemoves = removes
		scanLog.Printf("ProcessCDSNotify: %s: DS changed: %d adds, %d removes", childZone, len(adds), len(removes))
	} else {
		scanLog.Printf("ProcessCDSNotify: %s: DS unchanged", childZone)
	}

	newData := CurrentScanData{
		CDS: cdsRRset,
		DS:  &core.RRset{Name: childZone, RRtype: dns.TypeDS, RRs: newDSRRs},
	}
	response.NewData = newData.ToJSON()
	responseCh <- response
}

// queryCDSAtSignalingNames implements RFC 9615 authenticated bootstrap
// via signaling names. For each out-of-bailiwick NS, it queries CDS at
// _dsboot.<child>._signal.<ns> via IMR (DNSSEC-validated) and verifies
// consistency with direct CDS queries to the child NS.
// Returns the CDS RRset if all signaling queries agree, or an error.
func (scanner *Scanner) queryCDSAtSignalingNames(ctx context.Context, childZone string, nsRRset *core.RRset, directCDS *core.RRset, scanLog *log.Logger) (*core.RRset, error) {
	if scanner.ImrEngine == nil {
		return nil, fmt.Errorf("IMR engine required for RFC 9615 signaling queries")
	}

	var signalingResults []*core.RRset
	var queriedNS int

	for _, rr := range nsRRset.RRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		nsName := ns.Ns

		// Skip in-bailiwick NS (under childZone)
		if dns.IsSubDomain(childZone, nsName) {
			scanLog.Printf("queryCDSAtSignalingNames: %s: skipping in-bailiwick NS %s", childZone, nsName)
			continue
		}

		// Build signaling name: _dsboot.<child>._signal.<ns>
		signalingName := "_dsboot." + childZone + "_signal." + nsName
		scanLog.Printf("queryCDSAtSignalingNames: %s: querying CDS at signaling name %s", childZone, signalingName)

		resp, err := scanner.ImrEngine.ImrQuery(ctx, signalingName, dns.TypeCDS, dns.ClassINET, nil)
		if err != nil {
			scanLog.Printf("queryCDSAtSignalingNames: %s: error querying %s: %v", childZone, signalingName, err)
			return nil, fmt.Errorf("signaling query to %s failed: %v", signalingName, err)
		}
		if resp == nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 {
			scanLog.Printf("queryCDSAtSignalingNames: %s: no CDS at signaling name %s", childZone, signalingName)
			return nil, fmt.Errorf("no CDS at signaling name %s", signalingName)
		}

		if !resp.Validated && !scanner.HasOption("no-dnssec-validation") {
			scanLog.Printf("queryCDSAtSignalingNames: %s: CDS at %s not DNSSEC-validated", childZone, signalingName)
			return nil, fmt.Errorf("CDS at signaling name %s not DNSSEC-validated", signalingName)
		}
		signalingResults = append(signalingResults, resp.RRset)
		queriedNS++
	}

	if queriedNS == 0 {
		return nil, fmt.Errorf("no out-of-bailiwick NS found for %s", childZone)
	}

	// Verify all signaling responses agree with each other
	for i := 1; i < len(signalingResults); i++ {
		changed, _, _ := core.RRsetDiffer(childZone, signalingResults[0].RRs, signalingResults[i].RRs, dns.TypeCDS, scanLog, scanner.Verbose, scanner.Debug)
		if changed {
			return nil, fmt.Errorf("signaling CDS responses differ between NS")
		}
	}

	// Verify signaling responses match direct CDS query
	if directCDS != nil && len(directCDS.RRs) > 0 {
		changed, _, _ := core.RRsetDiffer(childZone, signalingResults[0].RRs, directCDS.RRs, dns.TypeCDS, scanLog, scanner.Verbose, scanner.Debug)
		if changed {
			return nil, fmt.Errorf("signaling CDS does not match direct CDS query")
		}
		scanLog.Printf("queryCDSAtSignalingNames: %s: signaling CDS matches direct CDS from %d NS", childZone, queriedNS)
	}

	return signalingResults[0], nil
}
