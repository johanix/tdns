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
	AuthQueryQ         chan AuthQueryRequest
	ImrEngine          *Imr
	Options            []string
	AtApexChecks       int
	AtApexInterval     time.Duration
	OnDelegationChange func(parentZone string, zd *ZoneData, resp ScanTupleResponse)
	LogFile            string
	LogTemplate        string
	Log                map[string]*log.Logger
	Verbose            bool
	Debug              bool
	Jobs               map[string]*ScanJobStatus
	JobsMutex          sync.RWMutex
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

	// Wire callback to apply delegation changes via CHILD-UPDATE.
	// Handles both CDS (DS adds/removes) and CSYNC (NS/glue adds/removes).
	scanner.OnDelegationChange = func(parentZone string, zd *ZoneData, resp ScanTupleResponse) {
		if zd.KeyDB == nil || zd.KeyDB.UpdateQ == nil {
			lg.Error("ScannerEngine: OnDelegationChange: no UpdateQ for zone", "zone", parentZone)
			return
		}
		var actions []dns.RR
		// DS changes (from CDS scan)
		for _, rr := range resp.DSAdds {
			cp := dns.Copy(rr)
			cp.Header().Class = dns.ClassINET
			actions = append(actions, cp)
		}
		for _, rr := range resp.DSRemoves {
			cp := dns.Copy(rr)
			cp.Header().Class = dns.ClassNONE
			actions = append(actions, cp)
		}
		// NS changes (from CSYNC scan)
		for _, rr := range resp.NSAdds {
			cp := dns.Copy(rr)
			cp.Header().Class = dns.ClassINET
			actions = append(actions, cp)
		}
		for _, rr := range resp.NSRemoves {
			cp := dns.Copy(rr)
			cp.Header().Class = dns.ClassNONE
			actions = append(actions, cp)
		}
		// Glue changes (from CSYNC scan)
		for _, rr := range resp.GlueAdds {
			cp := dns.Copy(rr)
			cp.Header().Class = dns.ClassINET
			actions = append(actions, cp)
		}
		for _, rr := range resp.GlueRemoves {
			cp := dns.Copy(rr)
			cp.Header().Class = dns.ClassNONE
			actions = append(actions, cp)
		}

		// Determine update type from which fields are populated
		updateType := "CDS"
		description := fmt.Sprintf("CDS scan: DS update for %s", resp.Qname)
		if len(resp.NSAdds) > 0 || len(resp.NSRemoves) > 0 || len(resp.GlueAdds) > 0 || len(resp.GlueRemoves) > 0 {
			updateType = "CSYNC"
			description = fmt.Sprintf("CSYNC scan: delegation update for %s", resp.Qname)
		}

		lg.Info("ScannerEngine: OnDelegationChange: enqueuing CHILD-UPDATE", "parent", parentZone, "child", resp.Qname, "type", updateType, "actions", len(actions))
		zd.KeyDB.UpdateQ <- UpdateRequest{
			Cmd:            "CHILD-UPDATE",
			UpdateType:     updateType,
			ZoneName:       parentZone,
			Actions:        actions,
			Trusted:        true,
			InternalUpdate: true,
			Description:    description,
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
						if sr.ZoneData != nil {
							lg.Debug("ScannerEngine: dispatching ProcessCSYNCNotify", "child", tuple.Zone)
							go func(t ScanTuple, parentZD *ZoneData) {
								defer wg.Done()
								scanner.ProcessCSYNCNotify(ctx, t, parentZD, sr.ScanType, sr.Edns0Options, responseCh)
							}(tuple, sr.ZoneData)
						} else {
							lg.Warn("ScannerEngine: CSYNC scan without parent zone data not yet supported")
							go func(t ScanTuple) {
								defer wg.Done()
								responseCh <- ScanTupleResponse{
									Qname:    t.Zone,
									ScanType: sr.ScanType,
									Error:    true,
									ErrorMsg: "CSYNC scan without parent zone data not yet supported",
								}
							}(tuple)
						}
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

					// Notify caller of delegation changes (DS from CDS, NS/glue from CSYNC)
					if scanner.OnDelegationChange != nil && parentZD != nil {
						for _, resp := range responses {
							hasDSChanges := len(resp.DSAdds) > 0 || len(resp.DSRemoves) > 0
							hasNSChanges := len(resp.NSAdds) > 0 || len(resp.NSRemoves) > 0
							hasGlueChanges := len(resp.GlueAdds) > 0 || len(resp.GlueRemoves) > 0
							if resp.DataChanged && (hasDSChanges || hasNSChanges || hasGlueChanges) {
								scanner.OnDelegationChange(parentZD.ZoneName, parentZD, resp)
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
	// IMR may be disabled or the generalized-NOTIFY path may have
	// reached the scanner before the IMR singleton was initialized;
	// without this guard the subsequent imr.ImrQuery(...) call
	// dereferences a nil *Imr and panics the tdns-authv2 process
	// from inside a server handler goroutine, killing the daemon on
	// otherwise-accepted NOTIFY(CDS/CSYNC) traffic.
	if imr == nil {
		return nil, false, fmt.Errorf("queryAllNSAndCompare: IMR is not initialized; cannot compare child NS data")
	}
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

// ProcessCSYNCNotify handles a CSYNC NOTIFY by querying CSYNC, NS, and glue
// from child nameservers, diffing against current delegation data, and
// reporting NS/glue adds/removes in the ScanTupleResponse.
// The scanner is read-only: results are returned for the caller to act on.
// Follows RFC 7477 processing algorithm.
func (scanner *Scanner) ProcessCSYNCNotify(ctx context.Context, tuple ScanTuple, parentZD *ZoneData, scanType ScanType, options *edns0.MsgOptions, responseCh chan<- ScanTupleResponse) {
	scanLog := scanner.Log["CSYNC"]
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
		scanLog.Printf("ProcessCSYNCNotify: %s: cannot get owner from parent zone: %v", childZone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("cannot get owner data for %s: %v", childZone, err)
		responseCh <- response
		return
	}

	nsRRsetVal := owner.RRtypes.GetOnlyRRSet(dns.TypeNS)
	nsRRset := &nsRRsetVal
	if len(nsRRset.RRs) == 0 {
		scanLog.Printf("ProcessCSYNCNotify: %s: no NS records in parent zone", childZone)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("no NS delegation for %s in parent zone", childZone)
		responseCh <- response
		return
	}

	// 2. Query SOA from child (start serial) — RFC 7477 step 1
	soaRRset, soaInSync, err := scanner.queryAllNSAndCompare(ctx, childZone, dns.TypeSOA, nsRRset, scanner.ImrEngine, scanLog)
	if err != nil {
		scanLog.Printf("ProcessCSYNCNotify: %s: error querying SOA: %v", childZone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("error querying SOA: %v", err)
		responseCh <- response
		return
	}
	if !soaInSync {
		scanLog.Printf("ProcessCSYNCNotify: %s: child NS not in sync for SOA, aborting", childZone)
		response.Error = true
		response.ErrorMsg = "child nameservers not in sync for SOA"
		responseCh <- response
		return
	}
	var startSerial uint32
	if soaRRset != nil && len(soaRRset.RRs) > 0 {
		if soa, ok := soaRRset.RRs[0].(*dns.SOA); ok {
			startSerial = soa.Serial
		}
	}

	// 3. Query CSYNC from child — RFC 7477 step 2
	csyncRRset, csyncInSync, err := scanner.queryAllNSAndCompare(ctx, childZone, dns.TypeCSYNC, nsRRset, scanner.ImrEngine, scanLog)
	if err != nil {
		scanLog.Printf("ProcessCSYNCNotify: %s: error querying CSYNC: %v", childZone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("error querying CSYNC: %v", err)
		responseCh <- response
		return
	}
	if !csyncInSync {
		scanLog.Printf("ProcessCSYNCNotify: %s: child NS not in sync for CSYNC, aborting", childZone)
		response.Error = true
		response.ErrorMsg = "child nameservers not in sync for CSYNC"
		responseCh <- response
		return
	}
	if csyncRRset == nil || len(csyncRRset.RRs) == 0 {
		scanLog.Printf("ProcessCSYNCNotify: %s: no CSYNC records found", childZone)
		response.DataChanged = false
		responseCh <- response
		return
	}

	// Extract the CSYNC RR
	var csyncrr *dns.CSYNC
	for _, rr := range csyncRRset.RRs {
		if c, ok := rr.(*dns.CSYNC); ok {
			csyncrr = c
			break
		}
	}
	if csyncrr == nil {
		scanLog.Printf("ProcessCSYNCNotify: %s: no CSYNC RR in response", childZone)
		response.Error = true
		response.ErrorMsg = "no CSYNC RR in response"
		responseCh <- response
		return
	}

	// 4. Validate flags — RFC 7477: reject if unknown flags set
	if csyncrr.Flags & ^uint16(0x03) != 0 {
		scanLog.Printf("ProcessCSYNCNotify: %s: unknown CSYNC flags set (0x%04x), aborting", childZone, csyncrr.Flags)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("unknown CSYNC flags: 0x%04x", csyncrr.Flags)
		responseCh <- response
		return
	}

	immediate := (csyncrr.Flags & 0x01) == 1
	usesoamin := (csyncrr.Flags & 0x02) == 2

	if !immediate {
		scanLog.Printf("ProcessCSYNCNotify: %s: CSYNC does not have immediate flag set, only immediate updates are supported", childZone)
		response.Error = true
		response.ErrorMsg = "CSYNC immediate flag not set, only immediate updates supported"
		responseCh <- response
		return
	}

	// 5. Serial dedup — skip if already processed
	if scanner.ZoneCSYNCKnown(childZone, csyncrr) {
		scanLog.Printf("ProcessCSYNCNotify: %s: CSYNC serial %d already processed", childZone, csyncrr.Serial)
		response.DataChanged = false
		responseCh <- response
		return
	}

	// 6. soaminimum check
	if usesoamin && csyncrr.Serial > startSerial {
		scanLog.Printf("ProcessCSYNCNotify: %s: CSYNC serial %d > SOA serial %d, skipping", childZone, csyncrr.Serial, startSerial)
		response.DataChanged = false
		responseCh <- response
		return
	}

	// Get current delegation data from backend
	var delegationData map[string]map[uint16][]dns.RR
	if parentZD.DelegationBackend != nil {
		delegationData, err = parentZD.DelegationBackend.GetDelegationData(parentZD.ZoneName, childZone)
		if err != nil {
			scanLog.Printf("ProcessCSYNCNotify: %s: error fetching delegation data: %v", childZone, err)
			response.Error = true
			response.ErrorMsg = fmt.Sprintf("error fetching delegation data: %v", err)
			responseCh <- response
			return
		}
	}

	// 7. Process each type in bitmap (NS first) — RFC 7477 step 3
	// Ensure NS comes first in processing order
	csynctypes := []uint16{dns.TypeNS}
	for _, t := range csyncrr.TypeBitMap {
		if t == dns.TypeNS {
			continue
		}
		csynctypes = append(csynctypes, t)
	}
	scanLog.Printf("ProcessCSYNCNotify: %s: CSYNC bitmap types: %v, immediate=%v, usesoamin=%v", childZone, csynctypes, immediate, usesoamin)

	// Extract current NS from delegation data
	var currentNSRRs []dns.RR
	if delegationData != nil {
		if childData, ok := delegationData[childZone]; ok {
			if nsRRs, ok := childData[dns.TypeNS]; ok {
				currentNSRRs = nsRRs
			}
		}
	}

	var newNSRRs []dns.RR // Populated after NS processing, used for glue
	var nsAdds, nsRemoves []dns.RR
	var glueAdds, glueRemoves []dns.RR
	dataChanged := false

	for _, t := range csynctypes {
		switch t {
		case dns.TypeNS:
			// Query NS from all child NS
			childNSRRset, nsInSync, err := scanner.queryAllNSAndCompare(ctx, childZone, dns.TypeNS, nsRRset, scanner.ImrEngine, scanLog)
			if err != nil {
				scanLog.Printf("ProcessCSYNCNotify: %s: error querying NS: %v", childZone, err)
				response.Error = true
				response.ErrorMsg = fmt.Sprintf("error querying NS: %v", err)
				responseCh <- response
				return
			}
			if !nsInSync {
				scanLog.Printf("ProcessCSYNCNotify: %s: child NS not in sync for NS RRset, aborting", childZone)
				response.Error = true
				response.ErrorMsg = "child nameservers not in sync for NS"
				responseCh <- response
				return
			}
			if childNSRRset == nil || len(childNSRRset.RRs) == 0 {
				scanLog.Printf("ProcessCSYNCNotify: %s: empty NS RRset from child, rejecting per RFC 7477", childZone)
				response.Error = true
				response.ErrorMsg = "empty NS RRset from child, rejected"
				responseCh <- response
				return
			}

			newNSRRs = childNSRRset.RRs

			// Diff NS
			changed, adds, removes := core.RRsetDiffer(childZone, newNSRRs, currentNSRRs, dns.TypeNS, scanLog, scanner.Verbose, scanner.Debug)
			if changed {
				nsAdds = adds
				nsRemoves = removes
				dataChanged = true
				scanLog.Printf("ProcessCSYNCNotify: %s: NS changed: %d adds, %d removes", childZone, len(adds), len(removes))
			} else {
				scanLog.Printf("ProcessCSYNCNotify: %s: NS unchanged", childZone)
			}

		case dns.TypeA, dns.TypeAAAA:
			// Process glue for in-bailiwick NS
			typeStr := dns.TypeToString[t]

			// Determine which NS names are in-bailiwick in the NEW NS set
			// (if NS wasn't in bitmap, use current NS)
			effectiveNS := newNSRRs
			if len(effectiveNS) == 0 {
				effectiveNS = currentNSRRs
			}

			var newInBailiwickNS []string
			for _, rr := range effectiveNS {
				if ns, ok := rr.(*dns.NS); ok {
					if NSInBailiwick(childZone, ns) {
						newInBailiwickNS = append(newInBailiwickNS, ns.Ns)
					}
				}
			}

			// Old in-bailiwick NS (from current delegation)
			var oldInBailiwickNS []string
			for _, rr := range currentNSRRs {
				if ns, ok := rr.(*dns.NS); ok {
					if NSInBailiwick(childZone, ns) {
						oldInBailiwickNS = append(oldInBailiwickNS, ns.Ns)
					}
				}
			}

			// Build sets for comparison
			newNSSet := make(map[string]bool)
			for _, ns := range newInBailiwickNS {
				newNSSet[dns.CanonicalName(ns)] = true
			}
			oldNSSet := make(map[string]bool)
			for _, ns := range oldInBailiwickNS {
				oldNSSet[dns.CanonicalName(ns)] = true
			}

			// For each new in-bailiwick NS: query glue from child
			for _, nsName := range newInBailiwickNS {
				nsCanon := dns.CanonicalName(nsName)

				glueRRset, glueInSync, err := scanner.queryAllNSAndCompare(ctx, nsName, t, nsRRset, scanner.ImrEngine, scanLog)
				if err != nil {
					scanLog.Printf("ProcessCSYNCNotify: %s: error querying %s for %s: %v", childZone, typeStr, nsName, err)
					continue
				}
				if !glueInSync {
					scanLog.Printf("ProcessCSYNCNotify: %s: child NS not in sync for %s %s, skipping", childZone, nsName, typeStr)
					continue
				}

				var newGlueRRs []dns.RR
				if glueRRset != nil {
					newGlueRRs = glueRRset.RRs
				}

				if oldNSSet[nsCanon] {
					// NS exists in both old and new — diff glue per-owner
					var currentGlue []dns.RR
					if delegationData != nil {
						if ownerData, ok := delegationData[nsName]; ok {
							if glueRRs, ok := ownerData[t]; ok {
								currentGlue = glueRRs
							}
						}
					}
					changed, adds, removes := core.RRsetDiffer(nsName, newGlueRRs, currentGlue, t, scanLog, scanner.Verbose, scanner.Debug)
					if changed {
						glueAdds = append(glueAdds, adds...)
						glueRemoves = append(glueRemoves, removes...)
						dataChanged = true
						scanLog.Printf("ProcessCSYNCNotify: %s: %s glue for %s changed: %d adds, %d removes", childZone, typeStr, nsName, len(adds), len(removes))
					}
				} else {
					// NS only in new set — all glue are adds
					if len(newGlueRRs) > 0 {
						glueAdds = append(glueAdds, newGlueRRs...)
						dataChanged = true
						scanLog.Printf("ProcessCSYNCNotify: %s: new NS %s, adding %d %s glue records", childZone, nsName, len(newGlueRRs), typeStr)
					}
				}
			}

			// NS only in old set — all its glue are removes
			for _, nsName := range oldInBailiwickNS {
				nsCanon := dns.CanonicalName(nsName)
				if newNSSet[nsCanon] {
					continue // Already handled above
				}
				if delegationData != nil {
					if ownerData, ok := delegationData[nsName]; ok {
						if glueRRs, ok := ownerData[t]; ok {
							glueRemoves = append(glueRemoves, glueRRs...)
							dataChanged = true
							scanLog.Printf("ProcessCSYNCNotify: %s: removed NS %s, removing %d %s glue records", childZone, nsName, len(glueRRs), typeStr)
						}
					}
				}
			}

		default:
			scanLog.Printf("ProcessCSYNCNotify: %s: unknown RR type %s in CSYNC bitmap, skipping", childZone, dns.TypeToString[t])
		}
	}

	// 8. Query SOA again (end serial) — RFC 7477 step 4
	endSOARRset, _, err := scanner.queryAllNSAndCompare(ctx, childZone, dns.TypeSOA, nsRRset, scanner.ImrEngine, scanLog)
	if err != nil {
		scanLog.Printf("ProcessCSYNCNotify: %s: error querying end SOA: %v", childZone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("error querying end SOA: %v", err)
		responseCh <- response
		return
	}
	var endSerial uint32
	if endSOARRset != nil && len(endSOARRset.RRs) > 0 {
		if soa, ok := endSOARRset.RRs[0].(*dns.SOA); ok {
			endSerial = soa.Serial
		}
	}
	if startSerial != endSerial {
		scanLog.Printf("ProcessCSYNCNotify: %s: SOA serial changed during analysis (%d → %d), aborting", childZone, startSerial, endSerial)
		response.Error = true
		response.ErrorMsg = "SOA serial changed during CSYNC analysis"
		responseCh <- response
		return
	}
	scanLog.Printf("ProcessCSYNCNotify: %s: SOA serial stable (%d)", childZone, startSerial)

	// 9. Update serial tracking
	KnownCsyncMinSOAs[childZone] = csyncrr.Serial

	// 10. Report results
	response.DataChanged = dataChanged
	response.NSAdds = nsAdds
	response.NSRemoves = nsRemoves
	response.GlueAdds = glueAdds
	response.GlueRemoves = glueRemoves
	response.AllNSInSync = true

	if dataChanged {
		scanLog.Printf("ProcessCSYNCNotify: %s: delegation changes: NS adds=%d removes=%d, glue adds=%d removes=%d",
			childZone, len(nsAdds), len(nsRemoves), len(glueAdds), len(glueRemoves))
	} else {
		scanLog.Printf("ProcessCSYNCNotify: %s: no delegation changes", childZone)
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
		// Use signaling-verified CDS (nil means all NS were in-bailiwick, keep original cdsRRset)
		if sigCDS != nil {
			cdsRRset = sigCDS
		}
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
		// All NS are in-bailiwick -- return nil to let caller fall back to direct/apex path
		scanLog.Printf("queryCDSAtSignalingNames: %s: no out-of-bailiwick NS, falling back", childZone)
		return nil, nil
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
