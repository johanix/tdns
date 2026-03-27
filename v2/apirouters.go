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
	"time"

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

	// Initialize distribution cache if needed (for agent/combiner)
	if conf.Internal.DistributionCache == nil {
		if Globals.App.Type == AppTypeAgent || Globals.App.Type == AppTypeCombiner || Globals.App.Type == AppTypeMPCombiner {
			conf.Internal.DistributionCache = NewDistributionCache()
			// Start background GC to purge old distributions every minute
			StartDistributionGC(conf.Internal.DistributionCache, 1*time.Minute, conf.Internal.StopCh)
			lgApi.Info("initialized distribution cache with automatic cleanup")
		}
	}

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

	if Globals.App.Type == AppTypeAuth || Globals.App.Type == AppTypeAgent ||
		Globals.App.Type == AppTypeMPSigner || Globals.App.Type == AppTypeMPAgent {
		sr.HandleFunc("/keystore", kdb.APIkeystore(conf)).Methods("POST")
		sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
		sr.HandleFunc("/zone/dsync", APIzoneDsync(ctx, &Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
		sr.HandleFunc("/delegation", APIdelegation(conf.Internal.DelegationSyncQ)).Methods("POST")
	}

	if Globals.App.Type == AppTypeAuth || Globals.App.Type == AppTypeMPSigner {
		sr.HandleFunc("/auth/peer", APIauthPeer(conf)).Methods("POST")
		sr.HandleFunc("/auth/distrib", APIauthDistrib(conf)).Methods("POST")
	}

	if Globals.App.Type == AppTypeAgent {
		sr.HandleFunc("/agent", conf.APIagent(conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
		sr.HandleFunc("/agent/distrib", conf.APIagentDistrib(conf.Internal.DistributionCache)).Methods("POST")
		sr.HandleFunc("/agent/transaction", conf.APIagentTransaction(conf.Internal.DistributionCache)).Methods("POST")
		// XXX: Should be behind a debug requirement, but for now always present
		// if Globals.Debug {
		lgApi.Debug("setting up debug endpoint for agent API")
		sr.HandleFunc("/agent/debug", conf.APIagentDebug()).Methods("POST")
		// }
	}
	if Globals.App.Type == AppTypeScanner {
		sr.HandleFunc("/scanner", APIscanner(conf, &Globals.App, conf.Internal.ScannerQ, kdb)).Methods("POST")
		sr.HandleFunc("/scanner/status", APIscannerStatus(conf)).Methods("GET")
		sr.HandleFunc("/scanner/delete", APIscannerDelete(conf)).Methods("DELETE")
	}
	if Globals.App.Type == AppTypeCombiner || Globals.App.Type == AppTypeMPCombiner {
		sr.HandleFunc("/combiner", APIcombiner(&Globals.App, conf.Internal.RefreshZoneCh, kdb)).Methods("POST")
		sr.HandleFunc("/combiner/distrib", conf.APIcombinerDistrib(conf.Internal.DistributionCache)).Methods("POST")
		sr.HandleFunc("/combiner/transaction", conf.APIcombinerTransaction()).Methods("POST")
		sr.HandleFunc("/combiner/debug", APIcombinerDebug(conf)).Methods("POST")
		sr.HandleFunc("/combiner/edits", APIcombinerEdits(conf)).Methods("POST")
	}

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

// This is the agent-to-agent sync API router.
func (conf *Config) SetupAgentSyncRouter(ctx context.Context) (*mux.Router, error) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "AgentSyncApi: Root endpoint is not allowed", http.StatusForbidden)
	})

	// Create base subrouter without auth header requirement
	sr := r.PathPrefix("/api/v1").Subrouter()

	// Special case for /hello endpoint which validates against TLSA in payload
	sr.HandleFunc("/hello", conf.APIhello()).Methods("POST")

	// All other endpoints require valid client cert matching TLSA record
	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// log.Printf("secureRouter: received %s on URL %s", r.Method, r.URL.Path)
			// Skip validation for /hello endpoint
			if r.URL.Path == "/api/v1/hello" {
				next.ServeHTTP(w, r)
				return
			}

			// Get peer certificate from TLS connection
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "AgentSyncApi: Client certificate required", http.StatusUnauthorized)
				return
			}
			clientCert := r.TLS.PeerCertificates[0]

			// Get TLSA record for the client's identity and verify
			clientId := clientCert.Subject.CommonName
			agent, ok := conf.Internal.AgentRegistry.S.Get(AgentId(clientId))
			if !ok {
				lgApi.Warn("unknown remote agent identity", "clientId", clientId)
				http.Error(w, "AgentSyncApi: Unauthorized", http.StatusUnauthorized)
				return
			}

			// agent.Mu.Lock()
			tlsaRR := agent.ApiDetails.TlsaRR
			// agent.Mu.Unlock()
			if tlsaRR == nil {
				lgApi.Warn("no TLSA record available for client", "clientId", clientId)
				http.Error(w, "AgentSyncApi: Unauthorized", http.StatusUnauthorized)
				return
			}

			err := VerifyCertAgainstTlsaRR(tlsaRR, clientCert.Raw)
			if err != nil {
				lgApi.Warn("certificate verification failed", "clientId", clientId, "err", err)
				http.Error(w, "AgentSyncApi: Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	secureRouter.HandleFunc("/ping", APIping(conf)).Methods("POST")
	secureRouter.HandleFunc("/sync/ping", conf.APIsyncPing()).Methods("POST")
	secureRouter.HandleFunc("/beat", conf.APIbeat()).Methods("POST")
	secureRouter.HandleFunc("/msg", conf.APImsg()).Methods("POST")

	return r, nil
}

// SetupCombinerSyncRouter sets up the HTTPS sync API for the combiner role.
// Agents can send HELLO, BEAT, PING, and MSG to the combiner over this router.
// Runs on a dedicated port (combiner.api.addresses.listen) separate from the
// management API, using mutual TLS with client cert verification against AgentRegistry.
func (conf *Config) SetupCombinerSyncRouter(ctx context.Context) (*mux.Router, error) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "CombinerSyncApi: Root endpoint is not allowed", http.StatusForbidden)
	})

	sr := r.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/hello", conf.APIhello()).Methods("POST")

	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/hello" {
				next.ServeHTTP(w, r)
				return
			}
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "CombinerSyncApi: Client certificate required", http.StatusUnauthorized)
				return
			}
			clientCert := r.TLS.PeerCertificates[0]
			clientId := clientCert.Subject.CommonName
			agent, ok := conf.Internal.AgentRegistry.S.Get(AgentId(clientId))
			if !ok {
				lgApi.Warn("combiner sync api: unknown remote agent identity", "clientId", clientId)
				http.Error(w, "CombinerSyncApi: Unauthorized", http.StatusUnauthorized)
				return
			}
			tlsaRR := agent.ApiDetails.TlsaRR
			if tlsaRR == nil {
				lgApi.Warn("combiner sync api: no TLSA record for client", "clientId", clientId)
				http.Error(w, "CombinerSyncApi: Unauthorized", http.StatusUnauthorized)
				return
			}
			if err := VerifyCertAgainstTlsaRR(tlsaRR, clientCert.Raw); err != nil {
				lgApi.Warn("combiner sync api: certificate verification failed", "clientId", clientId, "err", err)
				http.Error(w, "CombinerSyncApi: Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	secureRouter.HandleFunc("/ping", APIping(conf)).Methods("POST")
	secureRouter.HandleFunc("/sync/ping", conf.APIsyncPing()).Methods("POST")
	secureRouter.HandleFunc("/beat", conf.APIbeat()).Methods("POST")
	secureRouter.HandleFunc("/msg", conf.APImsg()).Methods("POST")

	return r, nil
}

// SetupSignerSyncRouter sets up the HTTPS sync API for the signer (tdns-auth) role.
// Agents can send HELLO, BEAT, PING, and MSG to the signer over this router.
func (conf *Config) SetupSignerSyncRouter(ctx context.Context) (*mux.Router, error) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "SignerSyncApi: Root endpoint is not allowed", http.StatusForbidden)
	})

	sr := r.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/hello", conf.APIhello()).Methods("POST")

	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/hello" {
				next.ServeHTTP(w, r)
				return
			}
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "SignerSyncApi: Client certificate required", http.StatusUnauthorized)
				return
			}
			clientCert := r.TLS.PeerCertificates[0]
			clientId := clientCert.Subject.CommonName
			agent, ok := conf.Internal.AgentRegistry.S.Get(AgentId(clientId))
			if !ok {
				lgApi.Warn("signer sync api: unknown remote agent identity", "clientId", clientId)
				http.Error(w, "SignerSyncApi: Unauthorized", http.StatusUnauthorized)
				return
			}
			tlsaRR := agent.ApiDetails.TlsaRR
			if tlsaRR == nil {
				lgApi.Warn("signer sync api: no TLSA record for client", "clientId", clientId)
				http.Error(w, "SignerSyncApi: Unauthorized", http.StatusUnauthorized)
				return
			}
			if err := VerifyCertAgainstTlsaRR(tlsaRR, clientCert.Raw); err != nil {
				lgApi.Warn("signer sync api: certificate verification failed", "clientId", clientId, "err", err)
				http.Error(w, "SignerSyncApi: Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	secureRouter.HandleFunc("/ping", APIping(conf)).Methods("POST")
	secureRouter.HandleFunc("/sync/ping", conf.APIsyncPing()).Methods("POST")
	secureRouter.HandleFunc("/beat", conf.APIbeat()).Methods("POST")
	secureRouter.HandleFunc("/msg", conf.APImsg()).Methods("POST")

	return r, nil
}

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
