/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	// "github.com/miekg/dns"
)

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

func SetupAPIRouter(conf *Config) (*mux.Router, error) {
	kdb := conf.Internal.KeyDB
	r := mux.NewRouter().StrictSlash(true)
	apikey := conf.ApiServer.ApiKey
	if apikey == "" {
		return nil, fmt.Errorf("apiserver.apikey is not set")
	}

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", apikey).Subrouter()

	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/keystore", kdb.APIkeystore()).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/zone", APIzone(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/zone/dsync", APIzoneDsync(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/delegation", APIdelegation(conf.Internal.DelegationSyncQ)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug()).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	return r, nil
}

// SetupCombinerAPIRouter sets up a router for the combiner API. It should
// only support debugging functionality and a single endpoint for replacing
// specific zone data with new data delivered via this API.
func SetupCombinerAPIRouter(conf *Config) (*mux.Router, error) {
	kdb := conf.Internal.KeyDB
	r := mux.NewRouter().StrictSlash(true)
	apikey := conf.ApiServer.ApiKey
	if apikey == "" {
		return nil, fmt.Errorf("apiserver.apikey is not set")
	}

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", apikey).Subrouter()

	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/zone", APIzone(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	// XXX: this is a temporary endpoint that should migrate into the combiner
	// endpoint.
	sr.HandleFunc("/replace", APIzoneReplace(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/combiner", APICombiner(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug()).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	return r, nil
}

func APIdispatcher(conf *Config, router *mux.Router, done <-chan struct{}) error {
	addresses := conf.ApiServer.Addresses
	certFile := conf.ApiServer.CertFile
	keyFile := conf.ApiServer.KeyFile

	if len(addresses) == 0 {
		log.Println("APIdispatcher: no addresses to listen on (key 'apiserver.addresses' not set). Not starting.")
		return fmt.Errorf("no addresses to listen on")
	}

	WalkRoutes(router, addresses[0])
	log.Println("")

	servers := make([]*http.Server, len(addresses))

	for idx, address := range addresses {
		idxCopy := idx
		servers[idx] = &http.Server{
			Addr:    address,
			Handler: router,
		}

		go func(srv *http.Server, idx int) {
			log.Printf("Starting API dispatcher #%d. Listening on '%s'\n", idx, srv.Addr)
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
				log.Fatalf("ListenAndServeTLS(): %v", err)
			}
		}(servers[idx], idxCopy)
	}

	go func() {
		<-done
		log.Println("Shutting down API servers...")
		for _, srv := range servers {
			if err := srv.Shutdown(context.Background()); err != nil {
				log.Printf("API server Shutdown: %v", err)
			}
		}
	}()

	return nil
}
