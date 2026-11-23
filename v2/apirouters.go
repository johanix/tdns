/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/gorilla/mux"
)

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

	// The key check goes on the ROOT router, not on this subrouter. A
	// middleware on a subrouter covers only the routes registered on that
	// subrouter, and callers add routes of their own afterwards on a second
	// "/api/v1" subrouter of the router returned here (tdns-mp's
	// Setup*Routes) or on the root router (RegisterAPIRoute callbacks). On
	// the subrouter those routes answered without a key.
	conf.initApiAccess()
	rtr.Use(conf.apiAuthMiddleware(apikey))
	sr := rtr.PathPrefix("/api/v1").Subrouter()

	// Common endpoints
	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf, rtr)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug(conf)).Methods("POST")

	// /imr: only registered on apps that actually host an IMR.
	// SetupSimpleAPIRouter is used by tdns-imr (which does) and by
	// tdns-scanner / tdns-reporter (which don't).
	if Globals.App.Type == AppTypeImr {
		sr.HandleFunc("/imr", conf.APIimr()).Methods("POST")
	}

	return rtr, nil
}

func (conf *Config) SetupAPIRouter(ctx context.Context) (*mux.Router, error) {
	kdb := conf.Internal.KeyDB

	rtr := mux.NewRouter().StrictSlash(true)
	apikey := conf.ApiServer.ApiKey.Value()
	if apikey == "" {
		return nil, fmt.Errorf("apiserver.apikey is not set")
	}

	// The key check goes on the ROOT router, not on this subrouter. A
	// middleware on a subrouter covers only the routes registered on that
	// subrouter, and callers add routes of their own afterwards on a second
	// "/api/v1" subrouter of the router returned here (tdns-mp's
	// Setup*Routes) or on the root router (RegisterAPIRoute callbacks). On
	// the subrouter those routes answered without a key.
	conf.initApiAccess()
	rtr.Use(conf.apiAuthMiddleware(apikey))
	sr := rtr.PathPrefix("/api/v1").Subrouter()

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
		sr.HandleFunc("/zone/parentsync", APIzoneParentSyncWith(ctx, &Globals.App, conf.Internal.RefreshZoneCh, kdb,
			conf.Internal.DelegationSyncQ)).Methods("POST")
		sr.HandleFunc("/zone/childsync", APIzoneChildSync(ctx, &Globals.App)).Methods("POST")
		// Provisioning for the DSYNC API scheme. Deliberately on the
		// management API, behind the operator key: issuing a registrant
		// credential is an operator act. The credentials issued here
		// authenticate somewhere else entirely -- the DSYNC API listener,
		// which is a separate socket with separate auth and a policy that
		// confines every one of them.
		sr.HandleFunc("/dsync-api/credential", kdb.APIdsyncApiCredential()).Methods("POST")
		sr.HandleFunc("/dsync-api/cert-credential", kdb.APIdsyncApiCertCredential()).Methods("POST")
		sr.HandleFunc("/delegation", APIdelegation(conf.Internal.DelegationSyncQ)).Methods("POST")
	}

	// Rollover read + write endpoints (rollover-overhaul phases 9 +
	// 10). Only the auth daemon hosts these — the rollover tick
	// runs there. Mutating handlers acquire the per-zone rollover
	// lock so they serialize against the tick.
	if Globals.App.Type == AppTypeAuth {
		sr.HandleFunc("/rollover/status", APIRolloverStatus(conf)).Methods("GET")
		sr.HandleFunc("/rollover/when", APIRolloverWhen(conf)).Methods("GET")
		sr.HandleFunc("/rollover/asap", APIRolloverAsap(conf)).Methods("POST")
		sr.HandleFunc("/rollover/cancel", APIRolloverCancel(conf)).Methods("POST")
		sr.HandleFunc("/rollover/reset", APIRolloverReset(conf)).Methods("POST")
		sr.HandleFunc("/rollover/unstick", APIRolloverUnstick(conf)).Methods("POST")
		sr.HandleFunc("/config/paths", APIConfigPaths(conf)).Methods("GET")
		// The poll scan of all children: switch it on or off, or read its state.
		sr.HandleFunc("/scanner/poll", APIscannerPoll(conf)).Methods("POST")
	}

	// Auth peer routes removed — peer management is MP-only.
	// For tdns-mp signer, routes are registered via SetupMPSignerRoutes.

	// /imr: in-process IMR inspection and control. Available on every
	// app that hosts an IMR -- tdns-agent, tdns-auth (and, via
	// SetupSimpleAPIRouter, tdns-imr). MP-specific commands keep
	// their own /agent endpoint, registered by tdns-mp.
	if Globals.App.Type == AppTypeAgent || Globals.App.Type == AppTypeAuth {
		sr.HandleFunc("/imr", conf.APIimr()).Methods("POST")
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

// apiServerTLSConfig is the TLS setup of the TCP management API listeners
// (the certificate itself comes from certfile/keyfile). A client certificate
// is asked for, never required: the middleware decides, so key-only clients
// keep working while the API key is accepted. With an access file the
// listener is TLS 1.3 only, as the design says. That is fixed at start; an
// access file a reload adds is held to TLS 1.3 by authenticateApiRequest.
func apiServerTLSConfig(conf *Config) *tls.Config {
	c := &tls.Config{ClientAuth: tls.RequestClientCert}
	if conf.ApiServer.AccessFile != "" {
		c.MinVersion = tls.VersionTLS13
	}
	return c
}

// apiListenerSettings are the apiserver: keys APIdispatcher acts on once, when
// it starts the listeners. A reload cannot change what is listening, so it
// says when they differ (apiListenerReloadNote).
type apiListenerSettings struct {
	Addresses                 []string
	Socket, CertFile, KeyFile string
	UseTLS                    bool
}

// apiListenersStarted is what the running listeners were started with; nil
// before APIdispatcher has run. One per process, as the listeners are.
var apiListenersStarted atomic.Pointer[apiListenerSettings]

func listenerSettingsOf(a ApiServerConf) *apiListenerSettings {
	return &apiListenerSettings{Addresses: slices.Clone(a.Addresses), Socket: a.Socket,
		CertFile: a.CertFile, KeyFile: a.KeyFile, UseTLS: a.UseTLS}
}

// apiListenerReloadNote is the part of a reload's report that names the
// listener settings the reload changed but could not apply: they take effect
// at the next restart. "" when none changed.
func (conf *Config) apiListenerReloadNote() string {
	was := apiListenersStarted.Load()
	if was == nil {
		return ""
	}
	now := listenerSettingsOf(conf.ApiServer)
	var changed []string
	if !slices.Equal(was.Addresses, now.Addresses) {
		changed = append(changed, "apiserver.addresses")
	}
	if was.Socket != now.Socket {
		changed = append(changed, "apiserver.socket")
	}
	if was.UseTLS != now.UseTLS {
		changed = append(changed, "apiserver.usetls")
	}
	if was.CertFile != now.CertFile || was.KeyFile != now.KeyFile {
		changed = append(changed, "apiserver.certfile/keyfile")
	}
	if len(changed) == 0 {
		return ""
	}
	return fmt.Sprintf(" NOT applied: %s changed, and the management API listeners keep what they started with; restart the daemon to apply it.",
		strings.Join(changed, ", "))
}

func APIdispatcher(conf *Config, router *mux.Router, done <-chan struct{}) error {
	addresses := conf.ApiServer.Addresses
	certFile := conf.ApiServer.CertFile
	keyFile := conf.ApiServer.KeyFile

	lgApi.Debug("dispatcher config", "addresses", addresses, "certFile", certFile, "keyFile", keyFile)

	if router == nil {
		lgApi.Warn("API router is nil, not starting")
		return nil
	}
	apiListenersStarted.Store(listenerSettingsOf(conf.ApiServer))

	// Design 3.6 allows an access file with usetls: false (a socket-only
	// daemon with keyauth off, say), but it should not go unnoticed.
	if len(addresses) > 0 && conf.ApiServer.AccessFile != "" && !conf.ApiServer.UseTLS {
		lgApi.Warn("management API: usetls is false, so the access file's certificate clients cannot authenticate on TCP, and the API key, if keyauth allows it, crosses the network in clear",
			"addresses", addresses, "access-file", conf.ApiServer.AccessFile)
	}

	// The local admin socket first, and independently of the TCP listeners:
	// it is the way in that nothing else can take away, so a daemon with no
	// apiserver.addresses still serves it, and a socket that cannot be served
	// is an error the operator sees, not a reason to stop the daemon.
	// A socket that stops serving later is such an error too (apiSocketFailed).
	if sock := conf.ApiServer.Socket; sock != "" {
		// Cleared before the socket starts, not after: a failure the server
		// reports once it runs must not be undone by a late clear here.
		conf.Internal.ServerErrors.clear(ErrCatTransport, ErrSubApiSocket)
		if err := serveApiSocket(sock, router, done, apiSocketFailed(conf, sock)); err != nil {
			lgApi.Error("management API: the local socket is not served", "socket", sock, "err", err)
			conf.Internal.ServerErrors.set(ErrCatTransport, ErrSubApiSocket,
				fmt.Sprintf("local admin socket %s not served: %v", sock, err))
		}
	}

	if len(addresses) == 0 {
		lgApi.Warn("no addresses to listen on (key 'apiserver.addresses' not set), not starting")
		// return fmt.Errorf("no addresses to listen on")
		return nil
	}

	WalkRoutes(router, addresses[0])

	servers := make([]*http.Server, len(addresses))

	for idx, address := range addresses {
		idxCopy := idx
		servers[idx] = &http.Server{
			Addr:      address,
			Handler:   router,
			TLSConfig: apiServerTLSConfig(conf),
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
