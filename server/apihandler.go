/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
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

	"github.com/johanix/tdns/tdns"
)

func APIcommand(conf *tdns.Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var cp tdns.CommandPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APICommand: error decoding command post:", err)
		}

		log.Printf("API: received /command request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := tdns.CommandResponse{
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
			conf.Internal.APIStopCh <- struct{}{}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", cp.Command)
			resp.Error = true
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func SetupRouter(conf *tdns.Config) *mux.Router {
	kdb := conf.Internal.KeyDB
	r := mux.NewRouter().StrictSlash(true)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", viper.GetString("apiserver.key")).Subrouter()

	sr.HandleFunc("/ping", tdns.APIping(conf.AppName, conf.AppVersion, conf.ServerBootTime)).Methods("POST")
	sr.HandleFunc("/keystore", kdb.APIkeystore()).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	// The /command endpoint is the only one not in the tdns lib
	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
	sr.HandleFunc("/zone", tdns.APIzone(conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/delegation", tdns.APIdelegation(conf.Internal.DelegationSyncQ)).Methods("POST")
	sr.HandleFunc("/debug", tdns.APIdebug()).Methods("POST")
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
func APIdispatcher(conf *tdns.Config, done <-chan struct{}) {
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
