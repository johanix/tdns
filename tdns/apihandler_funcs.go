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

func APIcommand(stopCh chan struct{}) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var cp CommandPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APICommand: error decoding command post:", err)
		}

		log.Printf("API: received /command request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := CommandResponse{
			Time: time.Now(),
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

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			time.Sleep(500 * time.Millisecond)
			stopCh <- struct{}{}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", cp.Command)
			resp.Error = true
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func APIzone(refreshq chan ZoneRefresher, kdb *KeyDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var zp ZoneCmdPost
		err := decoder.Decode(&zp)
		if err != nil {
			log.Println("APIzone: error decoding zone command post:", err)
		}

		log.Printf("API: received /zone request (cmd: %s) from %s.\n",
			zp.Command, r.RemoteAddr)

		resp := ZoneCmdResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
			}
		}()

		zd, exist := Zones.Get(zp.Zone)
		if !exist && zp.Command != "list-zones" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", zp.Zone)
			return
		}

		switch zp.Command {
		case "bump":
			// resp.Msg, err = BumpSerial(conf, cp.Zone)

			br, err := zd.BumpSerial()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Msg = fmt.Sprintf("Zone %s: bumped SOA serial from %d to %d", zp.Zone, br.OldSerial, br.NewSerial)

		case "write-zone":
			msg, err := zd.WriteZone(false, zp.Force)
			resp.Msg = msg
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "sign-zone":
			newrrsigs, err := zd.SignZone(kdb, zp.Force)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Msg = fmt.Sprintf("Zone %s: signed with %d new RRSIGs", zd.ZoneName, newrrsigs)

		case "generate-nsec":
			err := zd.GenerateNsecChain(kdb)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "show-nsec-chain":
			resp.Names, err = zd.ShowNsecChain()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "freeze":
			// If a zone has modifications, freezing implies that the updated
			// zone data should be written out to disk.
			if !zd.Options["allow-updates"] && !zd.Options["allow-child-updates"] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("FreezeZone: zone %s does not allow updates. Freeze would be a no-op", zd.ZoneName)
			}

			if zd.Options["frozen"] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("FreezeZone: zone %s is already frozen", zd.ZoneName)
			}

			// zd.mu.Lock()
			zd.SetOption("frozen", true)
			//zd.mu.Unlock()
			if zd.Options["dirty"] {
				tosource := true
				zd.WriteZone(tosource, false)
				resp.Msg = fmt.Sprintf("Zone %s is now frozen, modifications will be written to disk", zd.ZoneName)
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is now frozen", zd.ZoneName)
			}

		case "thaw":
			if !zd.Options["allow-updates"] || !zd.Options["allow-child-updates"] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("ThawZone: zone %s does not allow updates. Thaw would be a no-op", zd.ZoneName)
			}
			if !zd.Options["frozen"] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("ThawZone: zone %s is not frozen", zd.ZoneName)
			}
			zd.Options["frozen"] = false
			resp.Msg = fmt.Sprintf("Zone %s is now thawed", zd.ZoneName)

		case "reload":
			// XXX: Note: if the zone allows updates and is dirty, then reloading should be denied
			log.Printf("ZoneOps: reloading, will check for changes to delegation data\n")
			// resp.Msg, err = ReloadZone(cp.Zone, cp.Force)
			resp.Msg, err = zd.ReloadZone(refreshq, zp.Force)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		// case "foo":
		// XXX: FIXME: not yet sorted
		//			resp, err = ZoneOps(conf, cp, conf.Internal.KeyDB)
		//			if err != nil {
		//				resp.Error = true
		//				resp.ErrorMsg = err.Error()
		//			}

		case "list-zones":
			zones := map[string]ZoneConf{}
			for item := range Zones.IterBuffered() {
				zname := item.Key
				zd := item.Val

				options := []string{}
				for opt, val := range zd.Options {
					if val {
						options = append(options, opt)
					}
				}

				zconf := ZoneConf{
					Name:    zname,
					Dirty:   zd.Options["dirty"],
					Frozen:  zd.Options["frozen"],
					Options: options,
				}
				zones[zname] = zconf
			}
			resp.Zones = zones

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown zone command: %s", zp.Command)
			resp.Error = true
		}
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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

				if rrset, ok := owner.RRtypes[dp.Qtype]; ok {
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

// func SetupRouter(conf *Config) *mux.Router {
//	r := mux.NewRouter().StrictSlash(true)

//	sr := r.PathPrefix("/api/v1").Headers("X-API-Key",
//		viper.GetString("apiserver.key")).Subrouter()
//	sr.HandleFunc("/ping", APIping("tdnsd", conf.ServerBootTime)).Methods("POST")
//	sr.HandleFunc("/keystore", APIkeystore(conf)).Methods("POST")
//	sr.HandleFunc("/truststore", APItruststore(conf)).Methods("POST")
//	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
//	sr.HandleFunc("/delegation", APIdelegation(conf)).Methods("POST")
//	sr.HandleFunc("/debug", APIdebug(conf)).Methods("POST")
//	// sr.HandleFunc("/show/api", APIshowAPI(r)).Methods("GET")

//	return r
//}

func walkRoutes(router *mux.Router, address string) {
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

// In practice APIdispatcher doesn't need a termination signal, as it will
// just sit inside http.ListenAndServe, but we keep it for symmetry.
// func APIdispatcher(conf *Config, done <-chan struct{}) {
//	router := SetupRouter(conf)

//	walkRoutes(router, viper.GetString("apiserver.address"))
//	log.Println("")

//	address := viper.GetString("apiserver.address")

//	go func() {
//		log.Println("Starting API dispatcher #1. Listening on", address)
//		log.Fatal(http.ListenAndServe(address, router))
//	}()

//	log.Println("API dispatcher: unclear how to stop the http server nicely.")
//}
