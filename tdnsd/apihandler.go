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
	"github.com/spf13/viper"
	// "github.com/miekg/dns"

	"github.com/johanix/tdns/tdns"
)

func APIkeystore(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var kp tdns.KeystorePost
		err := decoder.Decode(&kp)
		if err != nil {
			log.Println("APIkeystore: error decoding command post:", err)
		}

		log.Printf("API: received /keystore request (cmd: %s) from %s.\n",
			kp.Command, r.RemoteAddr)

		resp := tdns.KeystoreResponse{}

		defer func() {
		      w.Header().Set("Content-Type", "application/json")
		      json.NewEncoder(w).Encode(resp)
		}()

		switch kp.Command {
		case "list-dnskey":
			log.Printf("tdnsd keystore list-sig0 inquiry")
			tmp1 := map[string]tdns.TrustAnchor{}
			for _, key := range tdns.TAStore.Map.Keys() {
			    val, _ := tdns.TAStore.Map.Get(key)
			    tmp1[key] = tdns.TrustAnchor{
						Name:		val.Name,
						Validated:	val.Validated,
						Dnskey:		val.Dnskey,
					}
			}
			resp.ChildDnskeys = tmp1

		case "list-child-sig0":
			log.Printf("tdnsd keystore list-child-sig0 inquiry")
			tmp2 := map[string]tdns.Sig0Key{}
			for _, key := range tdns.Sig0Store.Map.Keys() {
			    val, _ := tdns.Sig0Store.Map.Get(key)
			    tmp2[key] = tdns.Sig0Key{
						Name:		val.Name,
						Validated:	val.Validated,
						Trusted:	val.Trusted,
						Key:		val.Key,
					}
			}
			resp.ChildSig0keys = tmp2

		default:
			log.Printf("Unknown command: %s", kp.Command)
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

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", cp.Command)
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
	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
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
		Name:   zone,
		Response: respch,
		Force:	force,
	}

	resp := <-respch

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
