/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

// apiKeyAuthMiddleware returns a middleware that validates the API key using
// constant-time comparison to prevent timing side-channel attacks.
func apiKeyAuthMiddleware(expectedKey string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			providedKey := r.Header.Get("X-API-Key")
			if subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

var lgApi = Logger("api")

func WalkRoutes(router *mux.Router, address string) {
	lgApi.Info("defined API endpoints", "address", address)

	walker := func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		for m := range methods {
			lgApi.Debug("route", "method", methods[m], "path", path)
		}
		return nil
	}
	if err := router.Walk(walker); err != nil {
		lgApi.Error("walk routes failed", "err", err)
		panic(err)
	}
	//	return nil
}

// The simple API router is sufficient for tdns-imr, tdns-scanner and tdns-reporter.
func (conf *Config) SetupSimpleAPIRouter(ctx context.Context) (*mux.Router, error) {
	rtr := mux.NewRouter().StrictSlash(true)
	apikey := conf.ApiServer.ApiKey.Value()
	if apikey == "" {
		return nil, fmt.Errorf("apiserver.apikey is not set")
	}

	sr := rtr.PathPrefix("/api/v1").Subrouter()
	sr.Use(apiKeyAuthMiddleware(apikey))

	// Common endpoints
	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf, rtr)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug(conf)).Methods("POST")

	return rtr, nil
}

func (conf *Config) SetupAPIRouter(ctx context.Context) (*mux.Router, error) {
	kdb := conf.Internal.KeyDB

	rtr := mux.NewRouter().StrictSlash(true)
	apikey := conf.ApiServer.ApiKey.Value()
	if apikey == "" {
		return nil, fmt.Errorf("apiserver.apikey is not set")
	}

	sr := rtr.PathPrefix("/api/v1").Subrouter()
	sr.Use(apiKeyAuthMiddleware(apikey))

	// Common endpoints
	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf, rtr)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/zone", APIzone(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/catalog", APICatalog(&Globals.App)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug(conf)).Methods("POST")

	if Globals.App.Type == AppTypeAuth || Globals.App.Type == AppTypeAgent {
		sr.HandleFunc("/keystore", kdb.APIkeystore(conf)).Methods("POST")
		sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
		sr.HandleFunc("/zone/dsync", APIzoneDsync(ctx, &Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
		sr.HandleFunc("/delegation", APIdelegation(conf.Internal.DelegationSyncQ)).Methods("POST")
	}

	// Auth peer routes removed — peer management is MP-only.
	// For tdns-mp signer, routes are registered via SetupMPSignerRoutes.

	if Globals.App.Type == AppTypeAgent {
		sr.HandleFunc("/agent", conf.APIagent(conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
		// MP routes (/agent/distrib, /agent/transaction, /agent/debug) now registered by tdns-mp
	}
	if Globals.App.Type == AppTypeScanner {
		sr.HandleFunc("/scanner", APIscanner(conf, &Globals.App, conf.Internal.ScannerQ, kdb)).Methods("POST")
		sr.HandleFunc("/scanner/status", APIscannerStatus(conf)).Methods("GET")
		sr.HandleFunc("/scanner/delete", APIscannerDelete(conf)).Methods("DELETE")
	}
	// Combiner API routes removed — combiner only exists in tdns-mp now.
	// Routes are registered by tdns-mp via SetupMPCombinerRoutes.

	if Globals.App.Type == AppTypeKdc {
		// KDC API routes are set up in kdc.StartKdc() to avoid circular imports
		// They're registered directly on the router there
	}

	if Globals.App.Type == AppTypeKrs {
		// KRS API routes are set up in krs.StartKrs() to avoid circular imports
		// They're registered directly on the router there
	}

	// Call registered API route functions (allows external code to add routes)
	routeFuncs := getRegisteredAPIRoutes()
	for _, routeFunc := range routeFuncs {
		if err := routeFunc(rtr); err != nil {
			lgApi.Error("error registering API route", "err", err)
			// Continue with other routes even if one fails
		}
	}

	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	return rtr, nil
}

// SetupCombinerAPIRouter sets up a router for the combiner API. It should
// only support debugging functionality and a single endpoint for replacing
// specific zone data with new data delivered via this API.
// DEPRECATED: Use SetupAPIRouter instead.
/*
func xxxSetupCombinerAPIRouter(conf *Config) (*mux.Router, error) {
	kdb := conf.Internal.KeyDB
	rtr := mux.NewRouter().StrictSlash(true)
	apikey := conf.ApiServer.ApiKey
	if apikey == "" {
		return nil, fmt.Errorf("apiserver.apikey is not set")
	}

	sr := rtr.PathPrefix("/api/v1").Headers("X-API-Key", apikey).Subrouter()

	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf, rtr)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/zone", APIzone(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/combiner", APICombiner(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug(conf)).Methods("POST")
	// sr.HandleFunc("/show/api", tdns.APIshowAPI(r)).Methods("GET")

	return rtr, nil
}

// DEPRECATED: Use SetupAPIRouter instead.
func xxxSetupAgentAPIRouter(conf *Config) (*mux.Router, error) {
	kdb := conf.Internal.KeyDB
	rtr := mux.NewRouter().StrictSlash(true)
	apikey := conf.ApiServer.ApiKey
	if apikey == "" {
		return nil, fmt.Errorf("apiserver.apikey is not set")
	}

	sr := rtr.PathPrefix("/api/v1").Headers("X-API-Key", apikey).Subrouter()

	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf, rtr)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/zone", APIzone(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug()).Methods("POST")
	// sr.HandleFunc("/show/api", APIshowAPI(r)).Methods("GET")

	return rtr, nil
}
*/

// Sync router setup functions (SetupAgentSyncRouter, SetupCombinerSyncRouter,
// SetupSignerSyncRouter) have moved to tdns-mp/v2/apirouter_sync.go.

func APIdispatcher(conf *Config, router *mux.Router, done <-chan struct{}) error {
	addresses := conf.ApiServer.Addresses
	certFile := conf.ApiServer.CertFile
	keyFile := conf.ApiServer.KeyFile

	lgApi.Debug("dispatcher config", "addresses", addresses, "certFile", certFile, "keyFile", keyFile)

	if len(addresses) == 0 {
		lgApi.Warn("no addresses to listen on (key 'apiserver.addresses' not set), not starting")
		// return fmt.Errorf("no addresses to listen on")
		return nil
	}

	if router == nil {
		lgApi.Warn("API router is nil, not starting")
		return nil
	}

	WalkRoutes(router, addresses[0])

	servers := make([]*http.Server, len(addresses))

	for idx, address := range addresses {
		idxCopy := idx
		servers[idx] = &http.Server{
			Addr:    address,
			Handler: router,
		}

		go func(srv *http.Server, idx int) {
			lgApi.Info("starting API dispatcher", "index", idx, "address", srv.Addr)
			if conf.ApiServer.UseTLS {
				if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
					lgApi.Error("ListenAndServeTLS failed", "err", err)
				}
			} else {
				lgApi.Info("serving HTTP", "address", srv.Addr)
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					lgApi.Error("ListenAndServe failed", "err", err)
				}
			}
		}(servers[idx], idxCopy)
	}

	go func() {
		<-done
		lgApi.Info("shutting down API servers")
		for _, srv := range servers {
			if err := srv.Shutdown(context.Background()); err != nil {
				lgApi.Error("API server shutdown failed", "err", err)
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
		lgApi.Warn("no addresses to listen on, not starting")
		return fmt.Errorf("no addresses to listen on")
	}

	if certFile == "" || keyFile == "" {
		lgApi.Warn("no certificate file or key file provided, not starting")
		return fmt.Errorf("no certificate file or key file provided")
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		lgApi.Error("certificate file does not exist", "certFile", certFile)
		return fmt.Errorf("certificate file %q does not exist", certFile)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		lgApi.Error("key file does not exist", "keyFile", keyFile)
		return fmt.Errorf("key file %q does not exist", keyFile)
	}

	WalkRoutes(router, addresses[0])

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %v", err)
	}

	// Create TLS config that requests but doesn't require client certs
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS13,
		// XXX: this is just for debugging:
		// GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// 	log.Printf("TLS handshake from %s, SNI: %s", hello.Conn.RemoteAddr(), hello.ServerName)
		// 	return nil, nil
		// },
	}

	servers := make([]*http.Server, len(addresses))

	for idx, address := range addresses {
		idxCopy := idx
		servers[idx] = &http.Server{
			Addr:      address,
			Handler:   router,
			TLSConfig: tlsConfig,
		}

		go func(srv *http.Server, idx int) {
			lgApi.Info("starting API dispatcher", "index", idx, "address", srv.Addr)
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
				lgApi.Error("ListenAndServeTLS failed", "err", err)
			}
		}(servers[idx], idxCopy)
	}

	go func() {
		<-done
		lgApi.Info("shutting down API servers")
		for _, srv := range servers {
			if err := srv.Shutdown(context.Background()); err != nil {
				lgApi.Error("API server shutdown failed", "err", err)
			}
		}
	}()

	return nil
}
