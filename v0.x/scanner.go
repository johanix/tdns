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

	core "github.com/johanix/tdns/v0.x/core"
	edns0 "github.com/johanix/tdns/v0.x/edns0"
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
	// Conf  *Config
	// LabDB *LabDB
	// RRtype  string
	AuthQueryQ chan AuthQueryRequest
	// IMR         string
	ImrEngine   *Imr
	LogFile     string
	LogTemplate string
	Log         map[string]*log.Logger
	Verbose     bool
	Debug       bool
	// Job storage for async scan requests
	Jobs      map[string]*ScanJobStatus
	JobsMutex sync.RWMutex
}

func NewScanner(authqueryq chan AuthQueryRequest, verbose, debug bool) *Scanner {
	s := &Scanner{
		AuthQueryQ: authqueryq,
		//		Conf:        conf,
		//		LabDB:       conf.Internal.LabDB,
		Log:         map[string]*log.Logger{},
		LogTemplate: "/var/log/tdns/scanner-%s.log",
		Verbose:     verbose,
		Debug:       debug,
		Jobs:        make(map[string]*ScanJobStatus),
	}

	return s
}

// GenerateJobID generates a unique job ID
func GenerateJobID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fall back to time-based ID if crypto/rand fails
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
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

	//scanner := NewScanner(viper.GetBool("services.scanner.verbose"), viper.GetBool("services.scanner.debug"))
	scanner := NewScanner(authqueryq, true, true)
	scanner.AddLogger("CDS")
	scanner.AddLogger("CSYNC")
	scanner.AddLogger("DNSKEY")
	scanner.AddLogger("GENERIC")

	// Store scanner instance in Config for API handler access
	conf.Internal.Scanner = scanner

	log.Printf("*** ScannerEngine: starting ***")
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("ScannerEngine: context cancelled")
			return nil
		case <-ticker.C:

		case sr, ok := <-scannerq:
			if !ok {
				log.Println("ScannerEngine: scannerq closed")
				return nil
			}
			switch sr.Cmd {
			case "SCAN":
				log.Printf("ScannerEngine: Received SCAN request with %d tuples to scan (JobID: %s)", len(sr.ScanTuples), sr.JobID)
				scanner.ImrEngine = conf.Internal.ImrEngine

				// Create or update job status
				jobID := sr.JobID
				if jobID == "" {
					jobID = GenerateJobID()
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
						log.Print("ScannerEngine: Zone unspecified. Ignoring.")
						job.IgnoredTuples++
						continue
					}

					log.Printf("ScannerEngine: Zone %q, Current data:\n%+v", tuple.Zone, tuple.CurrentData)
					wg.Add(1)

					switch sr.ScanType {
					/*
						case ScanRRtype:
							log.Printf("ScannerEngine: ScanRRtype not implemented")
							err := conf.Internal.ImrEngine.SendRfc9567ErrorReport(ctx, tuple.Zone, sr.RRtype, edns0.EDECSyncScannerNotImplemented, sr.Edns0Options)
							//if err != nil {
							//	log.Printf("ScannerEngine: Error from SendRfc9567ErrorReport: %v", err)
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
						log.Printf("go scanner.CheckCDS(sr)")
						go func(t ScanTuple) {
							defer wg.Done()
							scanner.CheckCDS(ctx, t, sr.ScanType, sr.Edns0Options, responseCh)
						}(tuple)
						// err := conf.Internal.ImrEngine.SendRfc9567ErrorReport(ctx, sr.ChildZone, sr.RRtype, edns0.EDECDSScannerNotImplemented, sr.Edns0Options)
						//if err != nil {
						//	log.Printf("ScannerEngine: Error from SendRfc9567ErrorReport: %v", err)
						//}
					case ScanCSYNC:
						go func(t ScanTuple) {
							defer wg.Done()
							scanner.CheckCSYNC_NG(ctx, t, sr.ScanType, sr.Edns0Options, responseCh)
						}(tuple)
					case ScanDNSKEY:
						log.Printf("go scanner.CheckDNSKEY(sr)")
						go func(t ScanTuple) {
							defer wg.Done()
							scanner.CheckDNSKEY(ctx, t, sr.ScanType, sr.Edns0Options, responseCh)
						}(tuple)
					}
				}

				// Wait for all scans to complete and collect responses
				go func(jobID string) {
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

					log.Printf("ScannerEngine: Job %s completed with %d scan responses", jobID, len(responses))
				}(jobID)
			default:
				log.Printf("ScannerEngine: Unknown command: '%s'. Ignoring.", sr.Cmd)
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
	lg := scanner.Log["CDS"]
	if lg == nil {
		lg = log.Default()
	}

	zone := tuple.Zone
	log.Printf("ScannerEngine: Checking CDS for zone %q", zone)

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
			lg.Printf("CheckCDS: Zone %s: error from ImrQuery: %v", zone, err)
			response.Error = true
			response.ErrorMsg = fmt.Sprintf("error from ImrQuery: %v", err)
			responseCh <- response
			return
		}
		if resp == nil || resp.RRset == nil {
			lg.Printf("CheckCDS: Zone %s: no CDS RRset found", zone)
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
			changed, adds, removes := core.RRsetDiffer(zone, resp.RRset.RRs, tuple.CurrentData.CDS.RRs, dns.TypeCDS, lg, scanner.Verbose, scanner.Debug)
			response.DataChanged = changed
			if changed {
				lg.Printf("CheckCDS: Zone %s: CDS RRset changed. Adds: %d, Removes: %d", zone, len(adds), len(removes))
			} else {
				lg.Printf("CheckCDS: Zone %s: CDS RRset unchanged", zone)
			}
		} else {
			response.DataChanged = true // New data found where none existed before
			lg.Printf("CheckCDS: Zone %s: CDS RRset found (no previous data to compare)", zone)
		}
		responseCh <- response
		return
	}

	// "all-ns" option is set: check all authoritative nameservers
	lg.Printf("CheckCDS: Zone %s: checking all authoritative nameservers", zone)

	// Find the enclosing zone and its NS RRset
	_, nsRRset, err := scanner.ImrEngine.findEnclosingZoneNS(ctx, zone, lg)
	if err != nil {
		lg.Printf("CheckCDS: Zone %s: error finding enclosing zone NS: %v", zone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("error finding enclosing zone NS: %v", err)
		responseCh <- response
		return
	}

	// Query CDS from all nameservers and compare
	cdsRRset, allInSync, err := scanner.queryAllNSAndCompare(ctx, zone, dns.TypeCDS, nsRRset, scanner.ImrEngine, lg)
	if err != nil {
		lg.Printf("CheckCDS: Zone %s: error querying all NS: %v", zone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("error querying all NS: %v", err)
		responseCh <- response
		return
	}

	newData.CDS = cdsRRset
	response.NewData = newData.ToJSON()
	response.AllNSInSync = allInSync

	if !allInSync {
		lg.Printf("CheckCDS: Zone %s: nameservers are not in sync for CDS", zone)
	}

	// Compare with CurrentData.CDS if present
	if tuple.CurrentData.CDS != nil {
		changed, adds, removes := core.RRsetDiffer(zone, cdsRRset.RRs, tuple.CurrentData.CDS.RRs, dns.TypeCDS, lg, scanner.Verbose, scanner.Debug)
		response.DataChanged = changed
		if changed {
			lg.Printf("CheckCDS: Zone %s: CDS RRset changed compared to CurrentData. Adds: %d, Removes: %d", zone, len(adds), len(removes))
		} else {
			lg.Printf("CheckCDS: Zone %s: CDS RRset unchanged compared to CurrentData", zone)
		}
	} else {
		response.DataChanged = true // New data found where none existed before
		lg.Printf("CheckCDS: Zone %s: CDS RRset retrieved (no previous data to compare)", zone)
	}

	responseCh <- response
}

func (scanner *Scanner) CheckCSYNC_NG(ctx context.Context, tuple ScanTuple, scanType ScanType, options *edns0.MsgOptions, responseCh chan<- ScanTupleResponse) {
	log.Printf("ScannerEngine: Checking CSYNC for zone %q", tuple.Zone)
	err := scanner.ImrEngine.SendRfc9567ErrorReport(ctx, tuple.Zone, dns.TypeCSYNC, edns0.EDECSyncScannerNotImplemented, options)
	if err != nil {
		log.Printf("ScannerEngine: Error from SendRfc9567ErrorReport: %v", err)
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
	log.Printf("ScannerEngine: Checking DNSKEY for zone %q", tuple.Zone)
	err := scanner.ImrEngine.SendRfc9567ErrorReport(ctx, tuple.Zone, dns.TypeDNSKEY, edns0.EDECSyncScannerNotImplemented, options)
	if err != nil {
		log.Printf("ScannerEngine: Error from SendRfc9567ErrorReport: %v", err)
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
