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
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	// "github.com/miekg/dns"
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
			tmp1 := map[string]TrustAnchor{}
			for _, key := range DnskeyCache.Map.Keys() {
				val, _ := DnskeyCache.Map.Get(key)
				tmp1[key] = TrustAnchor{
					Name:      val.Name,
					Validated: val.Validated,
					Dnskey:    val.Dnskey,
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
func APIcommand(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		stopCh := conf.Internal.APIStopCh

		decoder := json.NewDecoder(r.Body)
		var cp CommandPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APICommand: error decoding command post:", err)
		}

		log.Printf("API: received /command request (cmd: %s) from %s. AppName: %s\n",
			cp.Command, r.RemoteAddr, Globals.AppName)

		resp := CommandResponse{
			Time:    time.Now(),
			AppName: Globals.AppName,
		}

		switch cp.Command {
		case "status":
			log.Printf("Daemon status inquiry\n")
			resp.Status = "ok" // only status we know, so far
			resp.Msg = "We're happy, but send more cookies"

		case "stop":
			log.Printf("Daemon instructed to stop\n")
			// var done struct{}
			resp.Status = "stopping"
			resp.Msg = "Daemon was happy, but now winding down"

			// w.Header().Set("Content-Type", "application/json")
			// err := json.NewEncoder(w).Encode(resp)
			// if err != nil {
			//		log.Printf("Error from json encoder: %v", err)
			// }
			go func() {
				time.Sleep(5000 * time.Millisecond)
				stopCh <- struct{}{}
			}()

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", cp.Command)
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
			Time: time.Now(),
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
			resp.Msg, err = conf.ReloadZoneConfig()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "status":
			log.Printf("APIconfig: config status inquiry")
			resp.DnsEngine = conf.DnsEngine
			resp.Apiserver = conf.Apiserver
			resp.Msg = fmt.Sprintf("Configuration is ok, server boot time: %s, last config reload: %s",
				conf.ServerBootTime.Format(timelayout), conf.ServerConfigTime.Format(timelayout))

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

func APIdebug() func(w http.ResponseWriter, r *http.Request) {
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
			log.Println("APICdebug: error decoding debug post:", err)
		}

		log.Printf("API: received /debug request (cmd: %s) from %s.\n",
			dp.Command, r.RemoteAddr)

		switch dp.Command {
		case "rrset":
			log.Printf("tdnsd debug rrset inquiry")
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
			resp.Msg = fmt.Sprintf("TAStore: %v", DnskeyCache.Map.Keys())
			tas := []TrustAnchor{}
			for _, taname := range DnskeyCache.Map.Keys() {
				ta, ok := DnskeyCache.Map.Get(taname)
				if !ok {
					continue
				}
				tas = append(tas, ta)
			}
			resp.TrustedDnskeys = tas

		case "show-rrsetcache":
			log.Printf("tdnsd debug show-rrsetcache")
			resp.Msg = fmt.Sprintf("RRsetCache: %v", RRsetCache.Map.Keys())
			rrsets := []CachedRRset{}
			for _, rrsetkey := range RRsetCache.Map.Keys() {
				rrset, ok := RRsetCache.Map.Get(rrsetkey)
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

func WalkRoutes(router *mux.Router, address string) {
	log.Printf("Defined API endpoints for router on: %s\n", address)

	walker := func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		for m := range methods {
			log.Printf("%-6s %s\n", methods[m], path)
		}
		return nil
	}
	if err := router.Walk(walker); err != nil {
		log.Panicf("Logging err: %s\n", err.Error())
	}
	//	return nil
}

func TdnsSetupRouter(conf *Config) *mux.Router {
	kdb := conf.Internal.KeyDB
	r := mux.NewRouter().StrictSlash(true)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", viper.GetString("apiserver.key")).Subrouter()

	sr.HandleFunc("/ping", APIping(conf, conf.AppName, conf.AppVersion, conf.ServerBootTime)).Methods("POST")
	sr.HandleFunc("/keystore", kdb.APIkeystore()).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/zone", APIzone(conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/zone/dsync", APIzoneDsync(conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/delegation", APIdelegation(conf.Internal.DelegationSyncQ)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug()).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	return r
}

// In practice APIdispatcher doesn't need a termination signal, as it will
// just sit inside http.ListenAndServe, but we keep it for symmetry.
func APIdispatcher(conf *Config, done <-chan struct{}) {
	router := TdnsSetupRouter(conf)

	WalkRoutes(router, viper.GetString("apiserver.address"))
	log.Println("")

	address := viper.GetString("apiserver.address")

	go func() {
		log.Println("Starting API dispatcher #1. Listening on", address)
		log.Fatal(http.ListenAndServe(address, router))
	}()

	log.Println("API dispatcher: unclear how to stop the http server nicely.")
}
