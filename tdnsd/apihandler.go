/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"github.com/spf13/viper"

	// "github.com/miekg/dns"

	"github.com/johanix/tdns/tdns"
)

func APIkeystore(conf *Config) func(w http.ResponseWriter, r *http.Request) {

	kdb := conf.Internal.KeyDB

	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var kp tdns.KeystorePost
		err := decoder.Decode(&kp)
		if err != nil {
			log.Println("APIkeystore: error decoding command post:", err)
		}

		log.Printf("API: received /keystore request (cmd: %s subcommand: %s) from %s.\n",
			kp.Command, kp.SubCommand, r.RemoteAddr)

		resp := tdns.KeystoreResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		switch kp.Command {
		// 		case "list-dnskey":
		// 			log.Printf("tdnsd keystore list-sig0 inquiry")
		// 			tmp1 := map[string]tdns.TrustAnchor{}
		// 			for _, key := range tdns.TAStore.Map.Keys() {
		// 			    val, _ := tdns.TAStore.Map.Get(key)
		// 			    tmp1[key] = tdns.TrustAnchor{
		// 						Name:		val.Name,
		// 						Validated:	val.Validated,
		// 						Dnskey:		val.Dnskey,
		// 					}
		// 			}
		// 			resp.ChildDnskeys = tmp1

		case "sig0-mgmt":
			resp, err = kdb.Sig0KeyMgmt(kp)
			if err != nil {
				log.Printf("Error from Sig0Mgmt(): %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "dnssec-mgmt":
			resp, err = kdb.DnssecKeyMgmt(kp)
			if err != nil {
				log.Printf("Error from DnssecMgmt(): %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		default:
			log.Printf("Unknown command: %s", kp.Command)
		}
	}
}

func APItruststore(conf *Config) func(w http.ResponseWriter, r *http.Request) {

	kdb := conf.Internal.KeyDB

	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var tp tdns.TruststorePost
		err := decoder.Decode(&tp)
		if err != nil {
			log.Println("APItruststore: error decoding command post:", err)
		}

		log.Printf("API: received /truststore request (cmd: %s subcommand: %s) from %s.\n",
			tp.Command, tp.SubCommand, r.RemoteAddr)

		resp := tdns.TruststoreResponse{}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		switch tp.Command {
		case "list-dnskey":
			log.Printf("tdnsd truststore list-dnskey inquiry")
			tmp1 := map[string]tdns.TrustAnchor{}
			for _, key := range tdns.TAStore.Map.Keys() {
				val, _ := tdns.TAStore.Map.Get(key)
				tmp1[key] = tdns.TrustAnchor{
					Name:      val.Name,
					Validated: val.Validated,
					Dnskey:    val.Dnskey,
				}
			}
			resp.ChildDnskeys = tmp1

		case "child-sig0-mgmt":
			resp, err = kdb.ChildSig0Mgmt(tp)
			if err != nil {
				log.Printf("Error from ChildSig0Mgmt(): %v", err)
			}

		default:
			log.Printf("Unknown command: %s", tp.Command)
		}
	}
}

func APIcommand(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var cp tdns.CommandPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APICommand: error decoding command post:", err)
		}

		log.Printf("API: received /command request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := tdns.CommandResponse{}

		switch cp.Command {
		case "status":
			log.Printf("Daemon status inquiry\n")
			resp = tdns.CommandResponse{
				Status: "ok", // only status we know, so far
				Msg:    "We're happy, but send more cookies"}

		case "bump":
			resp.Msg, err = BumpSerial(conf, cp.Zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "reload":
			log.Printf("APIhandler: reloading, will check for changes to delegation data\n")
			resp.Msg, err = ReloadZone(conf, cp.Zone, cp.Force)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "stop":
			log.Printf("Daemon instructed to stop\n")
			// var done struct{}
			resp = tdns.CommandResponse{
				Status: "stopping",
				Msg:    "Daemon was happy, but now winding down",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			time.Sleep(500 * time.Millisecond)
			conf.Internal.APIStopCh <- struct{}{}

		case "nsec":
			resp, err = tdns.NsecOps(cp)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "list-zones":
			for zname, zconf := range conf.Zones {
				zname = dns.Fqdn(zname)
				log.Printf("APIhandler: finding zone %s (conf: %v) zonedata", zname, zconf)
				zd, ok := tdns.Zones.Get(zname)
				if !ok {
					log.Printf("APIhandler: Error: zone %s should exist but there is no ZoneData", zname)
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", zname)
				} else {
					zconf.Dirty = zd.Dirty
					zconf.Frozen = zd.Frozen
				}
			}
			resp.Zones = conf.Zones

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", cp.Command)
			resp.Error = true
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func APIdelegation(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	delegationsyncQ := conf.Internal.DelegationSyncQ
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var dp tdns.DelegationPost
		err := decoder.Decode(&dp)
		if err != nil {
			log.Println("APIdelegation: error decoding delegation post:", err)
		}

		log.Printf("API: received /delegation request (cmd: %s) from %s.\n",
			dp.Command, r.RemoteAddr)

		resp := tdns.DelegationResponse{
			Time: time.Now(),
			Zone: dp.Zone,
		}

		var zd *tdns.ZoneData
		var exist bool
		if zd, exist = tdns.Zones.Get(dp.Zone); !exist {
			msg := fmt.Sprintf("Zone \"%s\" is unknown.", dp.Zone)
			log.Printf("APIdelegation: %s", msg)
			resp.Error = true
			resp.ErrorMsg = msg
			return
		}
		respch := make(chan tdns.DelegationSyncStatus, 1)

		syncreq := tdns.DelegationSyncRequest{
			ZoneName: dp.Zone,
			ZoneData: zd,
			Response: respch,
		}
		var syncstate tdns.DelegationSyncStatus

		switch dp.Command {
		// Find out whether delegation is in sync or not and report on details
		case "status":
			log.Printf("APIdelegation: zone %s delegation status inquiry", dp.Zone)
			syncreq.Command = "DELEGATION-STATUS"

			delegationsyncQ <- syncreq

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

			delegationsyncQ <- syncreq

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

func APIdebug(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		resp := tdns.DebugResponse{
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
		var dp tdns.DebugPost
		err := decoder.Decode(&dp)
		if err != nil {
			log.Println("APICdebug: error decoding debug post:", err)
		}

		log.Printf("API: received /debug request (cmd: %s) from %s.\n",
			dp.Command, r.RemoteAddr)

		switch dp.Command {
		case "rrset":
			log.Printf("tdnsd debug rrset inquiry")
			if zd, ok := tdns.Zones.Get(dp.Zone); ok {
				//			        idx, _ := zd.OwnerIndex.Get(dp.Qname)
				//				if owner := &zd.Owners[idx]; owner != nil {
				owner, err := zd.GetOwner(dp.Qname)
				if err != nil {
				}

				if rrset, ok := owner.RRtypes[dp.Qtype]; ok {
					resp.RRset = rrset
				}
				log.Printf("tdnsd debug rrset: owner: %v", owner)
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is unknown", dp.Zone)
			}

		case "lav":
			log.Printf("tdnsd debug lookup-and-validate inquiry")
			zd := tdns.FindZone(dp.Qname)
			if zd == nil {
				resp.ErrorMsg = fmt.Sprintf("Did not find a known zone for qname %s",
					dp.Qname)
				resp.Error = true
			} else {
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

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", dp.Command)
			resp.Error = true
		}
	}
}

func SetupRouter(conf *Config) *mux.Router {
	r := mux.NewRouter().StrictSlash(true)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key",
		viper.GetString("apiserver.key")).Subrouter()
	sr.HandleFunc("/ping", tdns.APIping("tdnsd")).Methods("POST")
	sr.HandleFunc("/keystore", APIkeystore(conf)).Methods("POST")
	sr.HandleFunc("/truststore", APItruststore(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
	sr.HandleFunc("/delegation", APIdelegation(conf)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug(conf)).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	return r
}

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
func APIdispatcher(conf *Config, done <-chan struct{}) {
	router := SetupRouter(conf)

	walkRoutes(router, viper.GetString("apiserver.address"))
	log.Println("")

	address := viper.GetString("apiserver.address")

	go func() {
		log.Println("Starting API dispatcher #1. Listening on", address)
		log.Fatal(http.ListenAndServe(address, router))
	}()

	log.Println("API dispatcher: unclear how to stop the http server nicely.")
}

func BumpSerial(conf *Config, zone string) (string, error) {
	var respch = make(chan BumperResponse, 1)
	conf.Internal.BumpZoneCh <- BumperData{
		Zone:   zone,
		Result: respch,
	}

	resp := <-respch

	if resp.Error {
		log.Printf("BumpSerial: Error from RefreshEngine: %s", resp.ErrorMsg)
		msg := fmt.Sprintf("Zone %s: error bumping SOA serial: %s", zone, resp.ErrorMsg)
		return msg, fmt.Errorf(msg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: bumped SOA serial from %d to %d", zone, resp.OldSerial, resp.NewSerial)
	}
	return resp.Msg, nil
}

func ReloadZone(conf *Config, zone string, force bool) (string, error) {
	var respch = make(chan tdns.RefresherResponse, 1)
	conf.Internal.RefreshZoneCh <- tdns.ZoneRefresher{
		Name:     zone,
		Response: respch,
		Force:    force,
	}

	var resp tdns.RefresherResponse

	select {
	case resp = <-respch:
	case <-time.After(2 * time.Second):
		return fmt.Sprintf("Zone %s: timeout waiting for response from RefreshEngine", zone), fmt.Errorf("Zone %s: timeout waiting for response from RefreshEngine", zone)
	}

	if resp.Error {
		log.Printf("ReloadZone: Error from RefreshEngine: %s", resp.ErrorMsg)
		return fmt.Sprintf("Zone %s: Error reloading: %s", zone, resp.ErrorMsg),
			fmt.Errorf("Zone %s: Error reloading: %v", zone, resp.ErrorMsg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: reloaded", zone)
	}
	return resp.Msg, nil
}

type BumperData struct {
	Zone   string
	Result chan BumperResponse
}

type BumperResponse struct {
	Time      time.Time
	Zone      string
	Msg       string
	OldSerial uint32
	NewSerial uint32
	Error     bool
	ErrorMsg  string
	Status    bool
}
