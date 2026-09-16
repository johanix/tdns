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

	"github.com/johanix/tdns/v2/cache"
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
	AuthQueryQ chan AuthQueryRequest
	// conf is how the IMR is resolved, at the point of use -- see imr(). The
	// Scanner deliberately does not keep an *Imr of its own.
	conf               *Config
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

	childLocks sync.Map         // canonical child name -> *sync.Mutex; see scanChildAndApply
	poll       scannerPollState // scanner_poll.go

	// queryChild and validateRRset stand in, in tests, for the network behind
	// the CDS and CSYNC paths: asking every child nameserver
	// (queryAllNSAndCompare) and the IMR's validator. Nil in production; see
	// askChild and validateChildData.
	queryChild    func(ctx context.Context, qname string, qtype uint16, nsRRset *core.RRset) (*core.RRset, bool, error)
	validateRRset func(ctx context.Context, rrset *core.RRset) (cache.ValidationState, error)
}

// imr resolves the IMR at the point of use.
//
// Not a cached field, and not captured when the Scanner is built, because
// neither works: InitImrEngine publishes the IMR asynchronously and routinely
// finishes AFTER the engines start (see DelegationSyncher's PROXY-SYNC arm for
// the same race), so anything captured at construction would be nil forever.
//
// It used to be latched inside the SCAN arm of the ScannerEngine loop instead,
// which is enqueued only on receipt of a generalized NOTIFY. That made every
// other entry point into the scanner depend on an unrelated NOTIFY having
// arrived first: on a freshly started parent the UPDATE-scheme coherence check
// refused every child update as incoherent, reporting an IMR that was in fact
// initialized and usable, until some unrelated NOTIFY happened to latch the
// pointer (#503). Two schemes specified as independent alternatives were
// hard-coupled, invisibly.
//
// Resolving here removes the class rather than moving the assignment: there is
// no window in which a copy can be stale, and a nil return now means what the
// callers' guards already assume it means -- the IMR is genuinely not usable.
//
// The readiness check is the documented protocol for this pointer: publishImr
// stores the IMR and THEN announces it, so a reader that checks Published()
// first is guaranteed a fully constructed value.
func (scanner *Scanner) imr() *Imr {
	if scanner == nil || scanner.conf == nil {
		return nil
	}
	if !scanner.conf.Internal.ImrReady.Published() {
		return nil
	}
	return scanner.conf.Internal.ImrEngine
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

	// Quiet by default. A poll round scans every child with a DS, and the scan
	// functions narrate every step to scanner.Log, with RRset dumps when Debug is
	// set. What a scan decided is logged once per scan instead
	// (scanChildAndApply). scanner.verbose brings the narration back, and
	// scanner.debug adds the RRset dumps. Read at startup: a change needs a
	// restart.
	debug := viper.GetBool("scanner.debug")
	scanner := NewScanner(authqueryq, debug || viper.GetBool("scanner.verbose"), debug)
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
	scanner.logTrustConfig()
	scanner.AddLogger("CDS")
	scanner.AddLogger("CSYNC")
	scanner.AddLogger("DNSKEY")
	scanner.AddLogger("GENERIC")
	if !scanner.Verbose {
		for rrtype := range scanner.Log {
			scanner.Log[rrtype] = discardLog
		}
	}

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
		// Waits until the change is applied: the caller holds the child's scan
		// lock, and the next scan of the child has to read a delegation that
		// includes it (scanChildAndApply).
		applyScanChildUpdate(ctx, zd.KeyDB.UpdateQ, UpdateRequest{
			Cmd:            "CHILD-UPDATE",
			UpdateType:     updateType,
			ZoneName:       parentZone,
			Actions:        actions,
			Trusted:        true,
			InternalUpdate: true,
			Description:    description,
		})
	}

	// Finish initialising BEFORE publishing. Publication is what other
	// goroutines synchronise on, and this used to publish first: an API
	// request or an UPDATE arriving in that window got a Scanner whose conf
	// was still nil, and scanner.imr() dereferences it.
	scanner.conf = conf
	scanner.poll.interval = time.Duration(interval) * time.Second
	conf.Internal.PublishScanner(scanner)

	lg.Info("ScannerEngine: starting")
	defer ticker.Stop()
	scanner.notePollConf(scanner.pollConf())

	for {
		select {
		case <-ctx.Done():
			lg.Info("ScannerEngine: context cancelled")
			return nil
		case <-ticker.C:
			pc := scanner.pollConf()
			scanner.notePollConf(pc)
			if pc.Enabled {
				if !scanner.startPollRound(ctx, pollParents(Zones.Items()), pc) {
					lg.Debug("ScannerEngine: the previous poll round is still running, skipping this tick")
				}
			}

		case sr, ok := <-scannerq:
			if !ok {
				lg.Info("ScannerEngine: scannerq closed")
				return nil
			}
			switch sr.Cmd {
			case "SCAN":
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

					// The current DS comes from the delegation backend, read by
					// scanChildAndApply under the child's lock. A parent zone
					// that accepts child updates MUST have a DelegationBackend
					// (enforced at config-validation time). Without it the
					// scanner has no way to know the current DS state, so every
					// CDS-NOTIFY would look like a fresh delegation and DS
					// records would accumulate without ever being removed.
					if sr.ZoneData == nil {
						lg.Error("ScannerEngine: no ZoneData on scan request, cannot compute current delegation state", "child", sr.ChildZone)
					} else if sr.ZoneData.DelegationBackend == nil {
						if sr.ZoneData.Options[OptAllowChildUpdates] {
							lg.Error("ScannerEngine: zone allows child updates but has no DelegationBackend; diff against empty current state will produce spurious adds (invariant violation)", "child", sr.ChildZone, "parent", sr.ZoneData.ZoneName)
						} else {
							lg.Warn("ScannerEngine: parent zone has no DelegationBackend, cannot read current DS for diff", "child", sr.ChildZone, "parent", sr.ZoneData.ZoneName)
						}
					}

					sr.ScanTuples = []ScanTuple{tuple}
					lg.Info("ScannerEngine: synthesized ScanTuple from NOTIFY", "child", sr.ChildZone, "scanType", ScanTypeToString[sr.ScanType])
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
							lg.Debug("ScannerEngine: dispatching a CDS scan", "child", tuple.Zone)
							go func(t ScanTuple, parentZD *ZoneData) {
								defer wg.Done()
								responseCh <- scanner.scanChildAndApply(ctx, parentZD, sr.ScanType, t, sr.Edns0Options)
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
							lg.Debug("ScannerEngine: dispatching a CSYNC scan", "child", tuple.Zone)
							go func(t ScanTuple, parentZD *ZoneData) {
								defer wg.Done()
								responseCh <- scanner.scanChildAndApply(ctx, parentZD, sr.ScanType, t, sr.Edns0Options)
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

				// Wait for all scans to complete and collect responses. A change
				// a scan found has already been applied, by scanChildAndApply
				// under the child's lock.
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

					lg.Info("ScannerEngine: job completed", "jobID", jobID, "responses", len(responses))
				}(jobID)
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
		return nil, false, fmt.Errorf("queryAllNSAndCompare: no IMR available yet; cannot compare child NS data")
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

	// Query each nameserver and collect the answers. A nameserver that answers
	// with authority that there is no such RRset (AuthQueryEngine returns an
	// empty RRset) has answered, and is compared like any other: the result is
	// empty only when every nameserver that answered agrees it is. One that
	// cannot be reached, or answers with an error or without authority, is left
	// out, and named in the error when no nameserver answered.
	var answers []*core.RRset
	var queryErrors []string

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
			queryErrors = append(queryErrors, fmt.Sprintf("%s: no addresses", nsName))
			continue
		}

		// Query from the first available address for this nameserver
		// (In a production system, you might want to try all addresses)
		rrset, err := scanner.AuthQueryNG(qname, nsAddrs[0], qtype, "tcp")
		if err != nil {
			if lg != nil {
				lg.Printf("queryAllNSAndCompare: error querying %s %s from %s (%s): %v", qname, dns.TypeToString[qtype], nsName, nsAddrs[0], err)
			}
			queryErrors = append(queryErrors, fmt.Sprintf("%s (%s): %v", nsName, nsAddrs[0], err))
			continue
		}
		if rrset == nil {
			rrset = &core.RRset{Name: qname, Class: dns.ClassINET, RRtype: qtype}
		}
		if len(rrset.RRs) == 0 && lg != nil {
			lg.Printf("queryAllNSAndCompare: %s serves no %s %s", nsName, qname, dns.TypeToString[qtype])
		}
		answers = append(answers, rrset)
	}

	return compareChildAnswers(qname, qtype, answers, queryErrors, lg, scanner.Verbose, scanner.Debug)
}

// compareChildAnswers is the verdict half of queryAllNSAndCompare: the first
// answer, and whether every answer carries the same RRset. An empty answer
// counts, so one nameserver serving an RRset that another says does not exist
// is a disagreement. No answer at all is an error that says why each
// nameserver gave none.
func compareChildAnswers(qname string, qtype uint16, answers []*core.RRset, queryErrors []string, lg *log.Logger, verbose, debug bool) (*core.RRset, bool, error) {
	if lg == nil {
		lg = discardLog
	}
	typeStr := dns.TypeToString[qtype]

	if len(answers) == 0 {
		return nil, false, fmt.Errorf("no %s RRsets retrieved from any nameserver: %s", typeStr, strings.Join(queryErrors, "; "))
	}

	// If only one response, we can't compare but return it
	if len(answers) == 1 {
		lg.Printf("queryAllNSAndCompare: only one %s RRset retrieved (cannot compare)", typeStr)
		return answers[0], true, nil // Consider it "in sync" since there's only one
	}

	base := answers[0]
	allInSync := true
	for _, other := range answers[1:] {
		if changed, adds, removes := core.RRsetDiffer(qname, base.RRs, other.RRs, qtype, lg, verbose, debug); changed {
			lg.Printf("queryAllNSAndCompare: %s RRsets differ between nameservers. Adds: %d, Removes: %d", typeStr, len(adds), len(removes))
			allInSync = false
		}
	}

	if allInSync {
		lg.Printf("queryAllNSAndCompare: all %d nameservers have identical %s RRsets", len(answers), typeStr)
	}

	return base, allInSync, nil
}

// childRRsetFetcher adapts queryAllNSAndCompare -- ask every nameserver in
// nsRRset and require agreement -- to the childRRsetFetcher the RFC 7477 rules
// take (delegation_csync.go). The CSYNC scan and the UPDATE-path coherence
// check both use it, so an asserted change is verified exactly the way a
// scanned one is.
func (scanner *Scanner) childRRsetFetcher(nsRRset *core.RRset, lg *log.Logger) childRRsetFetcher {
	return func(ctx context.Context, name string, qtype uint16) ([]dns.RR, bool, error) {
		rrset, inSync, err := scanner.askChild(ctx, name, qtype, nsRRset, lg)
		if err != nil {
			return nil, false, err
		}
		if rrset == nil {
			return nil, inSync, nil
		}
		return rrset.RRs, inSync, nil
	}
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

	// Both branches below dereference the IMR directly. Resolved and checked
	// once here rather than at each: a nil deref in this function panics a
	// server handler goroutine and takes the daemon down, which is the same
	// hazard queryAllNSAndCompare's guard exists for.
	imr := scanner.imr()
	if imr == nil {
		scanLog.Printf("CheckCDS: Zone %s: no IMR available yet", zone)
		response.Error = true
		response.ErrorMsg = "no IMR available yet; cannot check CDS"
		responseCh <- response
		return
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
		resp, err := imr.ImrQuery(ctx, zone, dns.TypeCDS, dns.ClassINET, nil)
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
	_, nsRRset, err := imr.findEnclosingZoneNS(ctx, zone, scanLog)
	if err != nil {
		scanLog.Printf("CheckCDS: Zone %s: error finding enclosing zone NS: %v", zone, err)
		response.Error = true
		response.ErrorMsg = fmt.Sprintf("error finding enclosing zone NS: %v", err)
		responseCh <- response
		return
	}

	// Query CDS from all nameservers and compare
	cdsRRset, allInSync, err := scanner.queryAllNSAndCompare(ctx, zone, dns.TypeCDS, nsRRset, imr, scanLog)
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
	} else if len(cdsRRset.RRs) == 0 {
		// Every nameserver says there is no CDS, and none was known.
		response.DataChanged = false
		scanLog.Printf("CheckCDS: Zone %s: no CDS RRset served (no previous data to compare)", zone)
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

	// The parent zone's delegation policy decides what the child's data has to
	// show before any of it is copied (#637, scanner_trust.go). Under
	// require-dnssec every RRset below comes through securedChildRRsetFetcher.
	pol := parentZD.boundDelegationPolicy()
	scanner.noteIgnoredOptions(pol, parentZD.ZoneName, childZone)
	fetch := scanner.childRRsetFetcher(nsRRset, scanLog)
	if pol.RequireDnssec {
		fetch = scanner.securedChildRRsetFetcher(pol, nsRRset, scanLog)
	}
	// fail reports err as a refusal when the policy refused the data, and as
	// an error otherwise.
	fail := func(what string, err error) {
		if isScanRefusal(err) {
			scanLog.Printf("ProcessCSYNCNotify: %s: refused: %v", childZone, err)
			refuseScan(&response, err)
		} else {
			scanLog.Printf("ProcessCSYNCNotify: %s: %s: %v", childZone, what, err)
			response.Error = true
			response.ErrorMsg = fmt.Sprintf("%s: %v", what, err)
		}
		responseCh <- response
	}

	// 2. Query SOA from child (start serial) — RFC 7477 step 1
	soaRRs, soaInSync, err := fetch(ctx, childZone, dns.TypeSOA)
	if err != nil {
		fail("error querying SOA", err)
		return
	}
	if !soaInSync {
		scanLog.Printf("ProcessCSYNCNotify: %s: child NS not in sync for SOA, aborting", childZone)
		response.Error = true
		response.ErrorMsg = "child nameservers not in sync for SOA"
		responseCh <- response
		return
	}
	if len(soaRRs) == 0 {
		fail("error querying SOA", fmt.Errorf("the child's nameservers serve no SOA for %s", childZone))
		return
	}
	var startSerial uint32
	if soa, ok := soaRRs[0].(*dns.SOA); ok {
		startSerial = soa.Serial
	}

	// 3. Query CSYNC from child — RFC 7477 step 2. Asked outside the trust
	// gate: a child that publishes no CSYNC asks for nothing, and a no-op needs
	// no authentication (like the CDS removal sentinel for a child without a
	// DS). Through the secured fetcher, a missing CSYNC under require-dnssec
	// was an error, which a poll would log for every such child on every round.
	// A CSYNC that is there is validated before anything is read from it.
	csyncRRset, csyncInSync, err := scanner.askChild(ctx, childZone, dns.TypeCSYNC, nsRRset, scanLog)
	if err != nil {
		fail("error querying CSYNC", err)
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
	if pol.RequireDnssec {
		if err := scanner.requireSecure(ctx, csyncRRset, pol); err != nil {
			fail("", err)
			return
		}
	}
	csyncRRs := csyncRRset.RRs

	// Extract the CSYNC RR
	var csyncrr *dns.CSYNC
	for _, rr := range csyncRRs {
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
	immediate, usesoamin, err := csyncFlags(csyncrr)
	if err != nil {
		scanLog.Printf("ProcessCSYNCNotify: %s: unknown CSYNC flags set (0x%04x), aborting", childZone, csyncrr.Flags)
		response.Error = true
		response.ErrorMsg = err.Error()
		responseCh <- response
		return
	}

	// 4b. Type bitmap — RFC 7477 §2.1.1.2.1: a type this parent does not
	// process means the record is not acted on.
	csynctypes, err := csyncTypes(csyncrr)
	if err != nil {
		scanLog.Printf("ProcessCSYNCNotify: %s: %v", childZone, err)
		response.Error = true
		response.ErrorMsg = err.Error()
		responseCh <- response
		return
	}

	if !immediate {
		scanLog.Printf("ProcessCSYNCNotify: %s: CSYNC does not have immediate flag set, only immediate updates are supported", childZone)
		response.Error = true
		response.ErrorMsg = errCsyncNotImmediate.Error()
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
	if csyncSuppressedBySoaMinimum(usesoamin, csyncrr, startSerial) {
		scanLog.Printf("ProcessCSYNCNotify: %s: CSYNC serial %d > SOA serial %d, skipping", childZone, csyncrr.Serial, startSerial)
		response.DataChanged = false
		responseCh <- response
		return
	}

	// Get current delegation data from backend. A parent zone that
	// accepts child updates MUST have a DelegationBackend (enforced at
	// config-validation time). Without one, NS/glue diffs would be
	// computed against an empty current state and spurious adds would
	// accumulate (the same class of bug as DS accumulation on CDS).
	var delegationData map[string]map[uint16][]dns.RR
	if parentZD.DelegationBackend == nil {
		if parentZD.Options[OptAllowChildUpdates] {
			scanLog.Printf("ProcessCSYNCNotify: %s: parent zone %s allows child updates but has no DelegationBackend; refusing to compute diff against empty current state (invariant violation)", childZone, parentZD.ZoneName)
			response.Error = true
			response.ErrorMsg = "parent zone has no DelegationBackend"
			responseCh <- response
			return
		}
		scanLog.Printf("ProcessCSYNCNotify: %s: parent zone %s has no DelegationBackend, proceeding with empty current state", childZone, parentZD.ZoneName)
	} else {
		delegationData, err = parentZD.DelegationBackend.GetDelegationData(parentZD.ZoneName, childZone)
		if err != nil {
			scanLog.Printf("ProcessCSYNCNotify: %s: error fetching delegation data: %v", childZone, err)
			response.Error = true
			response.ErrorMsg = fmt.Sprintf("error fetching delegation data: %v", err)
			responseCh <- response
			return
		}
	}

	// 7. Process each type in the bitmap (NS first when listed) — RFC 7477
	// step 3. The rules live in delegation_csync.go (computeCsyncDelta), fed by
	// queryAllNSAndCompare for what the child serves and by the delegation
	// backend for what the parent holds.
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
	currentGlue := func(owner string, t uint16) ([]dns.RR, bool) {
		if delegationData == nil {
			return nil, false
		}
		ownerData, ok := delegationData[owner]
		if !ok {
			return nil, false
		}
		glue, ok := ownerData[t]
		return glue, ok
	}
	delta, err := computeCsyncDelta(ctx, childZone, csynctypes, currentNSRRs, currentGlue,
		fetch, scanLog, scanner.Verbose, scanner.Debug)
	if isScanRefusal(err) {
		fail("", err)
		return
	}
	if err != nil {
		response.Error = true
		response.ErrorMsg = err.Error()
		responseCh <- response
		return
	}
	nsAdds, nsRemoves := delta.NSAdds, delta.NSRemoves
	glueAdds, glueRemoves := delta.GlueAdds, delta.GlueRemoves
	dataChanged := delta.Changed

	// 8. Query SOA again (end serial) — RFC 7477 step 4. Through fetch, like
	// the start SOA: RFC 7477 §3 refuses a CSYNC unless all the data from these
	// queries validates, and an end serial nobody authenticated, or one the
	// nameservers disagree on, could hide a change made during the analysis.
	endSOARRs, endInSync, err := fetch(ctx, childZone, dns.TypeSOA)
	if err != nil {
		fail("error querying end SOA", err)
		return
	}
	if !endInSync {
		scanLog.Printf("ProcessCSYNCNotify: %s: child NS not in sync for end SOA, aborting", childZone)
		response.Error = true
		response.ErrorMsg = "child nameservers not in sync for end SOA"
		responseCh <- response
		return
	}
	if len(endSOARRs) == 0 {
		fail("error querying end SOA", fmt.Errorf("the child's nameservers serve no SOA for %s", childZone))
		return
	}
	var endSerial uint32
	if soa, ok := endSOARRs[0].(*dns.SOA); ok {
		endSerial = soa.Serial
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
	recordCsyncProcessed(childZone, csyncrr.Serial)

	// 10. Report results
	response.DataChanged = dataChanged
	response.NSAdds = nsAdds
	response.NSRemoves = nsRemoves
	response.GlueAdds = glueAdds
	response.GlueRemoves = glueRemoves
	response.AllNSInSync = true
	if pol.RequireDnssec {
		response.Validation = ScanValidated
		response.ValidationReason = fmt.Sprintf("the SOA, the CSYNC and the NS and glue copied from the child validated Secure (delegation policy %q)", pol.Name)
	} else {
		response.Validation = ScanUnvalidated
		response.ValidationReason = fmt.Sprintf("delegation policy %q does not require DNSSEC", pol.Name)
	}
	scanLog.Printf("ProcessCSYNCNotify: %s: accepted, %s: %s", childZone, response.Validation, response.ValidationReason)

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
	if imr := scanner.imr(); imr == nil {
		lg.Warn("ScannerEngine: no IMR available yet; not sending the error report", "zone", tuple.Zone)
	} else if err := imr.SendRfc9567ErrorReport(ctx, tuple.Zone, dns.TypeDNSKEY, edns0.EDECSyncScannerNotImplemented, options); err != nil {
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
	cdsRRset, allInSync, err := scanner.askChild(ctx, childZone, dns.TypeCDS, nsRRset, scanLog)
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

	hasDS := tuple.CurrentData.DS != nil && len(tuple.CurrentData.DS.RRs) > 0

	// 2b. The removal sentinel for a child with no DS asks for no change, and a
	// no-op needs no authentication. Settled before the trust gate, so a strict
	// parent does not report refusing it on every NOTIFY.
	if cdsIsRemoval(cdsRRset) && !hasDS {
		scanLog.Printf("ProcessCDSNotify: %s: CDS removal sentinel but no existing DS", childZone)
		response.DataChanged = false
		responseCh <- response
		return
	}

	// 2c. Trust gate: the parent zone's delegation policy decides whether this
	// CDS may change the DS RRset (#637, scanner_trust.go).
	pol := parentZD.boundDelegationPolicy()
	scanner.noteIgnoredOptions(pol, parentZD.ZoneName, childZone)
	cdsRRset, validation, reason, err := scanner.authenticateCDS(ctx, childZone, nsRRset, cdsRRset, hasDS, pol, scanLog)
	if err != nil {
		scanLog.Printf("ProcessCDSNotify: %s: refused: %v", childZone, err)
		refuseScan(&response, err)
		responseCh <- response
		return
	}
	response.Validation, response.ValidationReason = validation, reason
	scanLog.Printf("ProcessCDSNotify: %s: CDS accepted, %s: %s", childZone, validation, reason)

	// 3. CDS removal sentinel (algorithm 0 per RFC 8078). The RFC 9615 path
	// acts on the signaling-name copy, so this is asked again.
	if cdsIsRemoval(cdsRRset) {
		if !hasDS {
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
// Returns the CDS RRset if all signaling queries agree, and whether every one
// of them validated; or an error. requireDnssec is the parent zone's delegation
// policy: with it, an answer that did not validate is an error.
func (scanner *Scanner) queryCDSAtSignalingNames(ctx context.Context, childZone string, nsRRset *core.RRset, directCDS *core.RRset, requireDnssec bool, scanLog *log.Logger) (*core.RRset, bool, error) {
	// Resolved at the first signaling name, not up front: a child whose
	// nameservers are all in bailiwick has no signaling name to ask, and that
	// answer does not depend on the IMR being up.
	var imr *Imr

	var signalingResults []*core.RRset
	var queriedNS int
	allValidated := true

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
		signalingName := signalOwnerName(signalPrefixDsboot, childZone, nsName)
		scanLog.Printf("queryCDSAtSignalingNames: %s: querying CDS at signaling name %s", childZone, signalingName)

		if imr == nil {
			if imr = scanner.imr(); imr == nil {
				return nil, false, fmt.Errorf("IMR engine required for RFC 9615 signaling queries")
			}
		}
		resp, err := imr.ImrQuery(ctx, signalingName, dns.TypeCDS, dns.ClassINET, nil)
		if err != nil {
			scanLog.Printf("queryCDSAtSignalingNames: %s: error querying %s: %v", childZone, signalingName, err)
			return nil, false, fmt.Errorf("signaling query to %s failed: %v", signalingName, err)
		}
		if resp == nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 {
			scanLog.Printf("queryCDSAtSignalingNames: %s: no CDS at signaling name %s", childZone, signalingName)
			return nil, false, fmt.Errorf("no CDS at signaling name %s", signalingName)
		}

		if !resp.Validated {
			if requireDnssec {
				scanLog.Printf("queryCDSAtSignalingNames: %s: CDS at %s not DNSSEC-validated", childZone, signalingName)
				return nil, false, fmt.Errorf("CDS at signaling name %s not DNSSEC-validated", signalingName)
			}
			allValidated = false
		}
		// Re-owned onto the child before it is compared to anything, or
		// returned: everything downstream wants the child's owner, not the
		// signaling one (#688, cdsAtChildOwner).
		signalingResults = append(signalingResults, cdsAtChildOwner(resp.RRset, childZone))
		queriedNS++
	}

	if queriedNS == 0 {
		// All NS are in-bailiwick: there is no signaling name, and the caller
		// decides what the policy leaves.
		scanLog.Printf("queryCDSAtSignalingNames: %s: no out-of-bailiwick NS, no signaling name to ask", childZone)
		return nil, false, nil
	}

	// Verify all signaling responses agree with each other
	for i := 1; i < len(signalingResults); i++ {
		changed, _, _ := core.RRsetDiffer(childZone, signalingResults[0].RRs, signalingResults[i].RRs, dns.TypeCDS, scanLog, scanner.Verbose, scanner.Debug)
		if changed {
			return nil, false, fmt.Errorf("signaling CDS responses differ between NS")
		}
	}

	// Verify signaling responses match direct CDS query
	if directCDS != nil && len(directCDS.RRs) > 0 {
		changed, _, _ := core.RRsetDiffer(childZone, signalingResults[0].RRs, directCDS.RRs, dns.TypeCDS, scanLog, scanner.Verbose, scanner.Debug)
		if changed {
			return nil, false, fmt.Errorf("signaling CDS does not match direct CDS query")
		}
		scanLog.Printf("queryCDSAtSignalingNames: %s: signaling CDS matches direct CDS from %d NS", childZone, queriedNS)
	}

	return signalingResults[0], allValidated, nil
}

// cdsAtChildOwner returns a copy of an RFC 9615 signaling CDS RRset owned by the
// child, instead of by _dsboot.<child>._signal.<ns>.
//
// The signaling copy is the same CDS published somewhere else, and everything
// downstream wants it at the child's owner:
//
//   - the agreement checks compare whole RRs through core.RRsetDiffer, and
//     dns.IsDuplicate compares Class, Rrtype and the OWNER NAME before it looks
//     at the RDATA. Left un-normalised, a signaling CDS never matches the apex
//     CDS however identical the key tag, algorithm and digest, so the check was
//     unsatisfiable and no at-ns bootstrap could complete (#688).
//   - the CDS -> DS conversion copies cds.Hdr.Name into the DS, which would put
//     the child's DS at the signaling name.
//
// Clone() first: the RRset may be held in the IMR cache, so renaming it in place
// would corrupt the cached entry for every other reader.
//
// The RRSIGs are dropped. They cover the signaling owner and cannot cover the
// re-owned records; whether the signaling copy validated has already been
// decided by the caller, from the IMR's answer.
func cdsAtChildOwner(rrset *core.RRset, childZone string) *core.RRset {
	if rrset == nil {
		return nil
	}
	owner := dns.Fqdn(childZone)
	out := rrset.Clone()
	out.Name = owner
	out.RRSIGs = nil
	for _, rr := range out.RRs {
		if rr != nil {
			rr.Header().Name = owner
		}
	}
	return out
}
