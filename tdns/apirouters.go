/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

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

	// Common endpoints
	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/zone", APIzone(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug()).Methods("POST")

	if Globals.App.Type == AppTypeServer || Globals.App.Type == AppTypeAgent {
		sr.HandleFunc("/keystore", kdb.APIkeystore()).Methods("POST")
		sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
		sr.HandleFunc("/zone/dsync", APIzoneDsync(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
		sr.HandleFunc("/delegation", APIdelegation(conf.Internal.DelegationSyncQ)).Methods("POST")
	}

	if Globals.App.Type == AppTypeAgent {
		sr.HandleFunc("/agent", conf.APIagent(conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	}
	if Globals.App.Type == AppTypeCombiner {
		sr.HandleFunc("/combiner", APICombiner(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	}

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
	sr.HandleFunc("/combiner", APICombiner(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug()).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	return r, nil
}

func SetupAgentAPIRouter(conf *Config) (*mux.Router, error) {
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
	sr.HandleFunc("/debug", APIdebug()).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	return r, nil
}

// This is the agent-to-agent sync API router.
func SetupAgentSyncRouter(conf *Config) (*mux.Router, error) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Root endpoint is not allowed", http.StatusForbidden)
	})

	// Create base subrouter without auth header requirement
	sr := r.PathPrefix("/api/v1").Subrouter()

	// Special case for /hello endpoint which validates against TLSA in payload
	sr.HandleFunc("/hello", APIhello(conf)).Methods("POST")

	// All other endpoints require valid client cert matching TLSA record
	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("secureRouter: %s", r.URL.Path)
			// Skip validation for /hello endpoint
			if r.URL.Path == "/api/v1/hello" {
				next.ServeHTTP(w, r)
				return
			}

			// Get peer certificate from TLS connection
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "Client certificate required", http.StatusUnauthorized)
				return
			}
			clientCert := r.TLS.PeerCertificates[0]

			// Get TLSA record for the client's identity and verify
			clientId := clientCert.Subject.CommonName
			agent, ok := conf.Internal.Registry.S.Get(clientId)
			if !ok {
				log.Printf("secureRouter: Unknown remote agent identity: %s", clientId)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			tlsaRR := agent.Details["api"].TlsaRR
			if tlsaRR == nil {
				log.Printf("secureRouter: No TLSA record available for client: %s", clientId)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			err := VerifyCertAgainstTlsaRR(tlsaRR, clientCert.Raw)
			if err != nil {
				log.Printf("secureRouter: Certificate verification for client id '%s' failed: %v", clientId, err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	secureRouter.HandleFunc("/ping", APIping(conf)).Methods("POST")
	secureRouter.HandleFunc("/beat", APIbeat(conf)).Methods("POST")

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

// APIdispatcherNG differs from APIdispatcher in that it allows for a different
// set of addresses and certificate files to be used for the API server.
func APIdispatcherNG(conf *Config, router *mux.Router, addrs []string, certFile string, keyFile string, done <-chan struct{}) error {
	addresses := addrs

	if len(addresses) == 0 {
		log.Println("APIdispatcherNG: no addresses to listen on. Not starting.")
		return fmt.Errorf("no addresses to listen on")
	}

	if certFile == "" || keyFile == "" {
		log.Println("APIdispatcherNG: no certificate file or key file provided. Not starting.")
		return fmt.Errorf("no certificate file or key file provided")
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("APIdispatcherNG: certificate file %q does not exist. Not starting.", certFile)
		return fmt.Errorf("certificate file %q does not exist", certFile)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("APIdispatcherNG: key file %q does not exist. Not starting.", keyFile)
		return fmt.Errorf("key file %q does not exist", keyFile)
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
