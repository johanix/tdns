/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	cache "github.com/johanix/tdns/v0.x/tdns/cache"
	core "github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/miekg/dns"
)

func (kdb *KeyDB) APIkeystore() func(w http.ResponseWriter, r *http.Request) {

	// kdb := conf.Internal.KeyDB

	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var kp KeystorePost
		err := decoder.Decode(&kp)
		if err != nil {
			log.Println("APIkeystore: error decoding command post:", err)
		}

		log.Printf("API: received /keystore request (cmd: %s subcommand: %s) from %s.\n",
			kp.Command, kp.SubCommand, r.RemoteAddr)

		// resp := KeystoreResponse{
		// 	Time: time.Now(),
		// }
		var resp *KeystoreResponse

		tx, err := kdb.Begin("APIkeystore")

		defer func() {
			if tx != nil {
				if err != nil {
					tx.Rollback()
				} else {
					tx.Commit()
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		if err != nil {
			log.Printf("Error from kdb.Begin(): %v", err)
			resp = &KeystoreResponse{
				Error:    true,
				ErrorMsg: err.Error(),
			}
			return
		}

		switch kp.Command {
		case "sig0-mgmt":
			resp, err = kdb.Sig0KeyMgmt(tx, kp)
			if err != nil {
				log.Printf("Error from Sig0Mgmt(): %v", err)
				resp = &KeystoreResponse{
					Error:    true,
					ErrorMsg: err.Error(),
				}
			}

		case "dnssec-mgmt":
			// log.Printf("APIkeystore: received /keystore request (cmd: %s subcommand: %s)\n",
			//	kp.Command, kp.SubCommand)
			resp, err = kdb.DnssecKeyMgmt(tx, kp)
			if err != nil {
				log.Printf("Error from DnssecKeyMgmt(): %v", err)
				resp = &KeystoreResponse{
					Error:    true,
					ErrorMsg: err.Error(),
				}
			}
			// log.Printf("APIkeystore: keystore dnssec-mgmt response: %v", resp)

		default:
			log.Printf("Unknown command: %s", kp.Command)
			resp = &KeystoreResponse{
				Error:    true,
				ErrorMsg: fmt.Sprintf("Unknown command: %s", kp.Command),
			}
		}
	}
}

func (kdb *KeyDB) APItruststore() func(w http.ResponseWriter, r *http.Request) {

	// kdb := conf.Internal.KeyDB

	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var tp TruststorePost
		err := decoder.Decode(&tp)
		if err != nil {
			log.Println("APItruststore: error decoding command post:", err)
		}

		log.Printf("API: received /truststore request (cmd: %s subcommand: %s) from %s.\n",
			tp.Command, tp.SubCommand, r.RemoteAddr)

		// resp := TruststoreResponse{}
		var resp *TruststoreResponse

		tx, err := kdb.Begin("APItruststore")

		defer func() {
			if tx != nil {
				if err != nil {
					tx.Rollback()
				} else {
					tx.Commit()
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		if err != nil {
			log.Printf("Error from kdb.Begin(): %v", err)
			resp = &TruststoreResponse{
				Error:    true,
				ErrorMsg: err.Error(),
			}
			return
		}

		switch tp.Command {
		case "list-dnskey":
			log.Printf("tdnsd truststore list-dnskey inquiry")
			tmp1 := map[string]cache.CachedDnskeyRRset{}
			for _, key := range cache.DnskeyCache.Map.Keys() {
				if val, ok := cache.DnskeyCache.Map.Get(key); ok {
					tmp1[key] = val
				}
			}
			resp = &TruststoreResponse{
				ChildDnskeys: tmp1,
			}

		case "child-sig0-mgmt":
			resp, err = kdb.Sig0TrustMgmt(tx, tp)
			if err != nil {
				log.Printf("Error from Sig0TrustMgmt(): %v", err)
				resp = &TruststoreResponse{
					Error:    true,
					ErrorMsg: err.Error(),
				}
			}

		default:
			log.Printf("Unknown command: %s", tp.Command)
		}
	}
}

// func APIcommand(stopCh chan struct{}) func(w http.ResponseWriter, r *http.Request) {
func APIcommand(conf *Config, rtr *mux.Router) func(w http.ResponseWriter, r *http.Request) {
	if rtr == nil {
		log.Printf("APIcommand: rtr is nil")
		return func(w http.ResponseWriter, r *http.Request) {
			log.Printf("APIcommand: rtr is nil")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		stopCh := conf.Internal.APIStopCh

		decoder := json.NewDecoder(r.Body)
		var cp CommandPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APICommand: error decoding command post:", err)
		}

		log.Printf("API: received /command request (cmd: %s) from %s. AppName: %s\n",
			cp.Command, r.RemoteAddr, Globals.App.Name)

		resp := CommandResponse{
			Time:    time.Now(),
			AppName: Globals.App.Name,
		}

		switch cp.Command {
		case "status":
			log.Printf("Daemon status inquiry\n")
			resp.Status = "ok" // only status we know, so far
			resp.Msg = fmt.Sprintf("%s: I'm happy, but send more cookies", Globals.App.Name)

		case "stop":
			log.Printf("Daemon instructed to stop\n")
			// var done struct{}
			resp.Status = "stopping"
			resp.Msg = fmt.Sprintf("%s: Daemon was happy, but now winding down", Globals.App.Name)

			go func() {
				// Allow the HTTP response to be sent before triggering shutdown
				time.Sleep(200 * time.Millisecond)
				conf.Internal.StopOnce.Do(func() {
					close(stopCh)
				})
			}()

		case "api":
			// XXX: Here we should return the defined API endpoints, as reported by ShowAPI().
			resp.ApiEndpoints, err = ShowAPI(rtr)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				break
			}

		default:
			resp.ErrorMsg = fmt.Sprintf("%s: Unknown command: %s", Globals.App.Name, cp.Command)
			resp.Error = true
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Printf("Error from json encoder: %v", err)
		}
	}
}

func APIconfig(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var cp ConfigPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APIconfig: error decoding config post:", err)
		}

		log.Printf("API: received /config request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := ConfigResponse{
			AppName: Globals.App.Name,
			Time:    time.Now(),
		}

		switch cp.Command {
		case "reload":
			log.Printf("APIconfig: reloading configuration")
			resp.Msg, err = conf.ReloadConfig()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "reload-zones":
			log.Printf("APIconfig: reloading zones")
			resp.Msg, err = conf.ReloadZoneConfig(r.Context())
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "status":
			log.Printf("APIconfig: config status inquiry")
			resp.DnsEngine = conf.DnsEngine
			resp.ApiServer = conf.ApiServer
			resp.Identities = conf.Service.Identities
			resp.Msg = fmt.Sprintf("%s: Configuration is ok, boot time: %s, last config reload: %s",
				Globals.App.Name, Globals.App.ServerBootTime.Format(TimeLayout), Globals.App.ServerConfigTime.Format(TimeLayout))

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown config command: %s", cp.Command)
			resp.Error = true
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func APIdelegation(delsyncq chan DelegationSyncRequest) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var dp DelegationPost
		err := decoder.Decode(&dp)
		if err != nil {
			log.Println("APIdelegation: error decoding delegation post:", err)
		}

		log.Printf("API: received /delegation request (cmd: %s) from %s.\n",
			dp.Command, r.RemoteAddr)

		resp := DelegationResponse{
			Time: time.Now(),
			Zone: dp.Zone,
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		var zd *ZoneData
		var exist bool
		if zd, exist = Zones.Get(dp.Zone); !exist {
			msg := fmt.Sprintf("Zone \"%s\" is unknown.", dp.Zone)
			log.Printf("APIdelegation: %s", msg)
			resp.Error = true
			resp.ErrorMsg = msg
			return
		}
		respch := make(chan DelegationSyncStatus, 1)

		syncreq := DelegationSyncRequest{
			ZoneName: dp.Zone,
			ZoneData: zd,
			Response: respch,
		}
		var syncstate DelegationSyncStatus

		switch dp.Command {
		// Find out whether delegation is in sync or not and report on details
		case "status":
			log.Printf("APIdelegation: zone %s delegation status inquiry", dp.Zone)
			syncreq.Command = "DELEGATION-STATUS"

			delsyncq <- syncreq

			select {
			case syncstate = <-respch:
				resp.SyncStatus = syncstate
			case <-time.After(4 * time.Second):
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		// Find out whether delegation is in sync or not and if not then fix it
		case "sync":
			log.Printf("APIdelegation: zone %s: will check and sync changes to delegation data\n", dp.Zone)
			syncreq.Command = "EXPLICIT-SYNC-DELEGATION"

			delsyncq <- syncreq

			select {
			case syncstate = <-respch:
				resp.SyncStatus = syncstate
				log.Printf("APIdelegation: zone %s: received response from DelegationSyncEngine: %s", dp.Zone, syncstate.Msg)
			case <-time.After(4 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "Timeout waiting for delegation sync response"
			}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown delegation command: %s", dp.Command)
			resp.Error = true
		}
	}
}

func APIdebug(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		resp := DebugResponse{
			Status: "ok", // only status we know, so far
			Msg:    "We're happy, but send more cookies",
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		decoder := json.NewDecoder(r.Body)
		var dp DebugPost
		err := decoder.Decode(&dp)
		if err != nil {
			log.Println("APIdebug: error decoding debug post:", err)
		}

		log.Printf("API: received /debug request (cmd: %s) from %s.\n",
			dp.Command, r.RemoteAddr)

		switch dp.Command {
		case "rrset":
			log.Printf("%s debug rrset inquiry", Globals.App.Name)
			if zd, ok := Zones.Get(dp.Zone); ok {
				//			        idx, _ := zd.OwnerIndex.Get(dp.Qname)
				//				if owner := &zd.Owners[idx]; owner != nil {
				owner, err := zd.GetOwner(dp.Qname)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}

				if rrset, ok := owner.RRtypes.Get(dp.Qtype); ok {
					resp.RRset = rrset
				}
				log.Printf("tdnsd debug rrset: owner: %v", owner)
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is unknown", dp.Zone)
			}

		case "validate-rrset":
			log.Printf("tdnsd debug validate-rrset")
			if zd, ok := Zones.Get(dp.Zone); ok {

				rrset, valid, err := zd.LookupAndValidateRRset(dp.Qname, dp.Qtype, true)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else if rrset == nil {
					resp.Msg = fmt.Sprintf("Found no RRset for %s %s", dp.Qname, dns.TypeToString[dp.Qtype])
				} else {
					resp.Msg = fmt.Sprintf("Found %s %s RRset (validated: %v)", dp.Qname, dns.TypeToString[dp.Qtype], valid)
					for _, rr := range rrset.RRs {
						resp.Msg += fmt.Sprintf("\n%s", rr.String())
					}
				}
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is unknown", dp.Zone)
			}

		case "lav":
			log.Printf("tdnsd debug lookup-and-validate inquiry")
			zd, folded := FindZone(dp.Qname)
			if zd == nil {
				resp.ErrorMsg = fmt.Sprintf("Did not find a known zone for qname %s",
					dp.Qname)
				resp.Error = true
			} else {
				if folded {
					dp.Qname = strings.ToLower(dp.Qname)
				}
				// tmp, err := zd.LookupRRset(dp.Qname, dp.Qtype, dp.Verbose)
				rrset, valid, err := zd.LookupAndValidateRRset(dp.Qname, dp.Qtype, dp.Verbose)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if rrset != nil {
						resp.RRset = *rrset
						resp.Validated = valid
					}
				}
			}

		case "show-ta":
			log.Printf("tdnsd debug show-ta")
			resp.Msg = fmt.Sprintf("TAStore: %v", cache.DnskeyCache.Map.Keys())
			cdrs := []cache.CachedDnskeyRRset{}
			for _, taname := range cache.DnskeyCache.Map.Keys() {
				cdr, ok := cache.DnskeyCache.Map.Get(taname)
				if !ok {
					continue
				}
				cdrs = append(cdrs, cdr)
			}
			resp.TrustedDnskeys = cdrs

		case "show-rrsetcache":
			log.Printf("%s debug show-rrsetcache", Globals.App.Name)
			resp.Msg = fmt.Sprintf("RRsetCache: %v", conf.Internal.RRsetCache.RRsets.Keys())
			rrsets := []cache.CachedRRset{}
			for _, rrsetkey := range conf.Internal.RRsetCache.RRsets.Keys() {
				rrset, ok := conf.Internal.RRsetCache.RRsets.Get(rrsetkey)
				if !ok {
					continue
				}
				rrsets = append(rrsets, rrset)
			}
			resp.CachedRRsets = rrsets

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", dp.Command)
			resp.Error = true
		}
	}
}

func APIscanner(conf *Config, app *AppDetails, scannerq chan ScanRequest, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		resp := ScannerResponse{
			AppName: app.Name,
			Time:    time.Now(),
		}

		decoder := json.NewDecoder(r.Body)
		var sp ScannerPost
		err := decoder.Decode(&sp)
		if err != nil {
			log.Println("APIscanner: error decoding scanner post:", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error decoding scanner post: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		log.Printf("API: received /scanner request (cmd: %s) from %s.\n",
			sp.Command, r.RemoteAddr)

		sp.Command = strings.ToUpper(sp.Command)

		switch sp.Command {
		case "SCAN":
			log.Printf("APIscanner: processing scan request with %d tuples", len(sp.ScanTuples))

			// Generate job ID
			jobID := GenerateJobID()

			// Send request to scanner queue (non-blocking)
			select {
			case scannerq <- ScanRequest{
				Cmd:        sp.Command,
				ParentZone: sp.ParentZone,
				ScanZones:  sp.ScanZones,
				ScanType:   sp.ScanType,
				ScanTuples: sp.ScanTuples,
				JobID:      jobID,
			}:
				// Request queued successfully
				resp.Status = "queued"
				resp.JobID = jobID
				resp.Msg = fmt.Sprintf("Scan request queued with job ID: %s", jobID)
				log.Printf("APIscanner: scan request queued with job ID: %s", jobID)
			default:
				// Queue is full
				resp.Error = true
				resp.ErrorMsg = "Scanner queue is full, please try again later"
			}

		case "status":
			// General status (job status is handled by separate endpoint)
			log.Printf("APIscanner: scanner status inquiry")
			resp.Msg = fmt.Sprintf("%s: Configuration is ok, boot time: %s, last config reload: %s",
				Globals.App.Name, Globals.App.ServerBootTime.Format(TimeLayout), Globals.App.ServerConfigTime.Format(TimeLayout))

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown scanner command: %s", sp.Command)
			resp.Error = true
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// Stolen from labstuff:apihandler_funcs.go
func ShowAPI(rtr *mux.Router) ([]string, error) {
	// resp := []string{fmt.Sprintf("API provided by %s listening on: %s\n",
	//	Globals.App.Name, address)}
	var resp []string

	walker := func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			// Skip routes without path templates (e.g., middleware routes)
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			// Skip routes without methods (e.g., subrouters, middleware)
			return nil
		}
		for _, m := range methods {
			resp = append(resp, fmt.Sprintf("%-6s %s", m, path))
		}
		return nil
	}

	if err := rtr.Walk(walker); err != nil {
		// log.Panicf("Logging err: %s\n", err.Error())
		log.Printf("ShowAPI: Walking error: %v", err)
		return nil, err
	}
	//	response := ApiResponse{
	//		Status: 101,
	//		Data:   resp,
	//	}
	return resp, nil
}

// deepCopyScanJobStatus creates a deep copy of a ScanJobStatus to avoid race conditions
// during JSON encoding. All exported fields are copied, including nested slices and pointers.
func deepCopyScanJobStatus(src *ScanJobStatus) *ScanJobStatus {
	if src == nil {
		return nil
	}

	dst := &ScanJobStatus{
		JobID:           src.JobID,
		Status:          src.Status,
		CreatedAt:       src.CreatedAt,
		TotalTuples:     src.TotalTuples,
		ProcessedTuples: src.ProcessedTuples,
		Error:           src.Error,
		ErrorMsg:        src.ErrorMsg,
	}

	// Deep copy time pointers
	if src.StartedAt != nil {
		startedAtCopy := *src.StartedAt
		dst.StartedAt = &startedAtCopy
	}
	if src.CompletedAt != nil {
		completedAtCopy := *src.CompletedAt
		dst.CompletedAt = &completedAtCopy
	}

	// Deep copy Responses slice
	if src.Responses != nil {
		dst.Responses = make([]ScanTupleResponse, len(src.Responses))
		for i, resp := range src.Responses {
			dst.Responses[i] = deepCopyScanTupleResponse(resp)
		}
	}

	return dst
}

// deepCopyScanTupleResponse creates a deep copy of a ScanTupleResponse
func deepCopyScanTupleResponse(src ScanTupleResponse) ScanTupleResponse {
	dst := ScanTupleResponse{
		Qname:       src.Qname,
		ScanType:    src.ScanType,
		DataChanged: src.DataChanged,
		AllNSInSync: src.AllNSInSync,
		Error:       src.Error,
		ErrorMsg:    src.ErrorMsg,
	}

	// Deep copy Options slice
	if src.Options != nil {
		dst.Options = make([]string, len(src.Options))
		copy(dst.Options, src.Options)
	}

	// Deep copy NewData (CurrentScanDataJSON)
	dst.NewData = deepCopyCurrentScanDataJSON(src.NewData)

	return dst
}

// deepCopyCurrentScanDataJSON creates a deep copy of CurrentScanDataJSON
func deepCopyCurrentScanDataJSON(src CurrentScanDataJSON) CurrentScanDataJSON {
	dst := CurrentScanDataJSON{}

	// Deep copy RRsetString pointers
	if src.RRset != nil {
		dst.RRset = deepCopyRRsetString(src.RRset)
	}
	if src.CDS != nil {
		dst.CDS = deepCopyRRsetString(src.CDS)
	}
	if src.CSYNC != nil {
		dst.CSYNC = deepCopyRRsetString(src.CSYNC)
	}
	if src.DNSKEY != nil {
		dst.DNSKEY = deepCopyRRsetString(src.DNSKEY)
	}

	return dst
}

// deepCopyRRsetString creates a deep copy of RRsetString
func deepCopyRRsetString(src *core.RRsetString) *core.RRsetString {
	if src == nil {
		return nil
	}

	dst := &core.RRsetString{
		Name:   src.Name,
		RRtype: src.RRtype,
	}

	// Deep copy RRs slice
	if src.RRs != nil {
		dst.RRs = make([]string, len(src.RRs))
		copy(dst.RRs, src.RRs)
	}

	// Deep copy RRSIGs slice
	if src.RRSIGs != nil {
		dst.RRSIGs = make([]string, len(src.RRSIGs))
		copy(dst.RRSIGs, src.RRSIGs)
	}

	return dst
}

// APIscannerStatus handles GET requests for scan job status
func APIscannerStatus(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		jobID := r.URL.Query().Get("job_id")

		if conf.Internal.Scanner == nil {
			http.Error(w, "Scanner not initialized", http.StatusServiceUnavailable)
			return
		}

		conf.Internal.Scanner.JobsMutex.RLock()

		if jobID == "" {
			// Return all jobs - create deep copies to avoid race conditions during encoding
			log.Printf("APIscannerStatus: listing all jobs")
			jobs := make([]*ScanJobStatus, 0, len(conf.Internal.Scanner.Jobs))
			for _, job := range conf.Internal.Scanner.Jobs {
				jobs = append(jobs, deepCopyScanJobStatus(job))
			}
			conf.Internal.Scanner.JobsMutex.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jobs)
			return
		}

		// Return specific job - create deep copy to avoid race conditions during encoding
		log.Printf("APIscannerStatus: job status inquiry for job ID: %s", jobID)
		job, exists := conf.Internal.Scanner.Jobs[jobID]

		if !exists {
			http.Error(w, fmt.Sprintf("Job ID not found: %s", jobID), http.StatusNotFound)
			return
		}

		job = deepCopyScanJobStatus(job)
		conf.Internal.Scanner.JobsMutex.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(job)
	}
}

// APIscannerDelete handles DELETE requests for scan job deletion
func APIscannerDelete(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		jobID := r.URL.Query().Get("job_id")
		deleteAll := r.URL.Query().Get("all") == "true"

		if conf.Internal.Scanner == nil {
			http.Error(w, "Scanner not initialized", http.StatusServiceUnavailable)
			return
		}

		conf.Internal.Scanner.JobsMutex.Lock()
		defer conf.Internal.Scanner.JobsMutex.Unlock()

		resp := ScannerResponse{
			AppName: Globals.App.Name,
			Time:    time.Now(),
		}

		if deleteAll {
			// Delete all jobs
			count := len(conf.Internal.Scanner.Jobs)
			conf.Internal.Scanner.Jobs = make(map[string]*ScanJobStatus)
			log.Printf("APIscannerDelete: deleted all %d jobs", count)
			resp.Msg = fmt.Sprintf("Deleted all %d jobs", count)
			resp.Status = "success"
		} else if jobID != "" {
			// Delete specific job
			_, exists := conf.Internal.Scanner.Jobs[jobID]
			if !exists {
				http.Error(w, fmt.Sprintf("Job ID not found: %s", jobID), http.StatusNotFound)
				return
			}
			delete(conf.Internal.Scanner.Jobs, jobID)
			log.Printf("APIscannerDelete: deleted job %s", jobID)
			resp.Msg = fmt.Sprintf("Deleted job %s", jobID)
			resp.Status = "success"
		} else {
			resp.Error = true
			resp.ErrorMsg = "Either job_id or all=true must be specified"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
