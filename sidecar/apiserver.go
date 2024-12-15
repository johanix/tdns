/*
 * apiserver.go
 *
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/johanix/tdns/music"
	tdns "github.com/johanix/tdns/tdns"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

// var pongs int = 0

// This is the sidecar mgmt API router.
func SetupRouter(tconf *tdns.Config, mconf *music.Config) *mux.Router {
	kdb := tconf.Internal.KeyDB
	r := mux.NewRouter().StrictSlash(true)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", viper.GetString("apiserver.key")).Subrouter()

	// TDNS stuff
	sr.HandleFunc("/ping", tdns.APIping(tconf, tconf.AppName, tconf.AppVersion, tconf.ServerBootTime)).Methods("POST")
	sr.HandleFunc("/keystore", kdb.APIkeystore()).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	sr.HandleFunc("/zone", tdns.APIzone(tconf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/delegation", tdns.APIdelegation(tconf.Internal.DelegationSyncQ)).Methods("POST")
	sr.HandleFunc("/debug", tdns.APIdebug()).Methods("POST")

	// The /command endpoint is the only one not in the tdns lib
	sr.HandleFunc("/command", tdns.APIcommand(tconf)).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	// MUSIC stuff
	// sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/signer", music.APIsigner(mconf)).Methods("POST")
	sr.HandleFunc("/zone", music.APIzone(mconf)).Methods("POST")
	sr.HandleFunc("/signergroup", music.APIsignergroup(mconf)).Methods("POST")
	sr.HandleFunc("/test", music.APItest(mconf)).Methods("POST")
	sr.HandleFunc("/process", music.APIprocess(mconf)).Methods("POST")
	sr.HandleFunc("/show", music.APIshow(mconf, r)).Methods("POST")

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

// This is the sidecar mgmt API dispatcher.
func APIdispatcher(tconf *tdns.Config, mconf *music.Config, done <-chan struct{}) {
	router := SetupRouter(tconf, mconf)

	walkRoutes(router, viper.GetString("apiserver.address"))
	log.Println("")

	address := viper.GetString("apiserver.address")

	go func() {
		if address != "" {
			log.Println("Starting API dispatcher #1. Listening on", address)
			log.Fatal(http.ListenAndServeTLS(address, viper.GetString("apiserver.certFile"),
				viper.GetString("apiserver.keyFile"), router))
		} else {
			log.Println("API dispatcher #1: address not set, not starting")
		}
	}()

	log.Println("API dispatcher: unclear how to stop the http server nicely.")
}

// This is the sidecar-to-sidecar sync API router.
func MusicSetupRouter(tconf *tdns.Config, mconf *music.Config) *mux.Router {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", music.HomeLink)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", viper.GetString("apiserver.apikey")).Subrouter()

	sr.HandleFunc("/ping", tdns.APIping(tconf, tconf.AppName, tconf.AppVersion, tconf.ServerBootTime)).Methods("POST")
	sr.HandleFunc("/beat", music.APIbeat(mconf)).Methods("POST")
	sr.HandleFunc("/hello", music.APIhello(mconf)).Methods("POST")
	// TODO: send NOTIFY(DNSKEY) here:
	// sr.HandleFunc("/notify", music.APInotify(mconf, r)).Methods("POST")
	return r
}

// This is the sidecar-to-sidecar sync API dispatcher.
func MusicSyncAPIdispatcher(tconf *tdns.Config, mconf *music.Config, done <-chan struct{}) error {
	log.Printf("MusicSyncAPIdispatcher: starting with sidecar ID '%s'", mconf.Sidecar.Api.Identity)

	router := MusicSetupRouter(tconf, mconf)
	addresses := mconf.Sidecar.Api.Addresses.Listen
	port := mconf.Sidecar.Api.Port
	certFile := mconf.Sidecar.Api.Cert
	keyFile := mconf.Sidecar.Api.Key
	if len(addresses) == 0 {
		log.Println("MusicSyncAPIdispatcher: no addresses to listen on. Not starting.")
		return nil
	}
	if certFile == "" || keyFile == "" {
		log.Println("MusicSyncAPIdispatcher: certFile or keyFile not set. Not starting.")
		return nil
	}

	for idx, address := range addresses {
		go func(address string) {
			addr := net.JoinHostPort(address, fmt.Sprintf("%d", port))
			log.Printf("Starting MusicSyncAPI dispatcher #%d. Listening on '%s'\n", idx, addr)
			log.Fatal(http.ListenAndServeTLS(addr, certFile, keyFile, router))
		}(string(address))

		log.Println("MusicSyncAPI dispatcher: unclear how to stop the http server nicely.")
	}
	return nil
}
