/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
// listener is TLS 1.3 only, as the design says: withAccessFile is whether
// the listener starts with one (APIdispatcher reads apiserver.access-file
// once, so that the listener and what it is recorded as started with agree).
//
// MinVersion is fixed when the listener starts, and a reload can add an
// access file later. So every handshake also asks the running policy:
// while an access file is in force, a client that does not offer TLS 1.3 is
// handed a TLS 1.3-only config, and the version negotiation turns it away
// with a protocol_version alert, as a listener started with the access file
// does. (Returning an error instead would send internal_error, which points
// an operator the wrong way.) That config needs no certificate: the
// handshake fails on the version before one is chosen. A client that offers
// TLS 1.3 gets it, as the server picks the highest version both sides have.
func apiServerTLSConfig(conf *Config, withAccessFile bool) *tls.Config {
	c := &tls.Config{ClientAuth: tls.RequestClientCert}
	if withAccessFile {
		c.MinVersion = tls.VersionTLS13
	}
	tls13Only := c.Clone()
	tls13Only.MinVersion = tls.VersionTLS13
	c.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if st := conf.Internal.ApiAccess.load(); st != nil && st.Enabled &&
			!slices.Contains(hello.SupportedVersions, tls.VersionTLS13) {
			// Go's own log line says only "client offered only
			// unsupported versions"; say why here.
			from := "unknown"
			if hello.Conn != nil {
				from = hello.Conn.RemoteAddr().String()
			}
			lgApi.Info("management API: TLS handshake refused: the access file requires TLS 1.3", "client", from)
			return tls13Only, nil
		}
		return nil, nil // the config as it is
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
	// TLS13Only: started with an access file, so MinVersion is TLS 1.3
	// (apiServerTLSConfig), and stays so until a restart.
	TLS13Only bool
}

// apiListenersStarted is what the running listeners were started with; nil
// before APIdispatcher has run. One per process, as the listeners are.
var apiListenersStarted atomic.Pointer[apiListenerSettings]

// apiTCPServer is one TCP management API listener: the server, and the socket
// it serves, which APIdispatcher binds before the server starts.
type apiTCPServer struct {
	srv *http.Server
	ln  net.Listener
}

// apiTCPServers are the TCP management API servers APIdispatcher started and
// whether they speak plaintext; stopped are the addresses of plaintext ones
// closed because an access file came into force. One set per process.
var apiTCPServers struct {
	sync.Mutex
	srvs      []apiTCPServer
	plaintext bool
	stopped   []string
	stoppedBy string // the access file that stopped them, for config status
}

// Test hooks, nil outside tests.
//   - apiDispatchBeforeLockHook runs in APIdispatcher just before it takes
//     apiTCPServers' lock, so a test can put a reload after everything the
//     dispatcher did before the lock.
//   - apiDispatchLockedHook runs inside APIdispatcher's locked region,
//     between the policy check and the registration, so a test can hold
//     start-up there.
//   - apiActivateBeforeLockHook runs in activateApiAccess just before it
//     takes the lock, so a test knows when a reload is about to wait on it.
//   - apiServeHook, if set, is handed each TCP server's serve call (and may
//     hold it, or not run it at all).
//
// APIdispatcher reads its hooks before its goroutines start.
var (
	apiDispatchBeforeLockHook func()
	apiDispatchLockedHook     func()
	apiActivateBeforeLockHook func()
	apiServeHook              func(addr string, serve func())
)

func registerApiTCPServers(srvs []apiTCPServer, plaintext bool) {
	apiTCPServers.Lock()
	defer apiTCPServers.Unlock()
	apiTCPServers.srvs, apiTCPServers.plaintext = srvs, plaintext
}

// activateApiAccess puts an access policy in force (store) after closing the
// plaintext TCP listeners, both under apiTCPServers' lock, and returns the
// addresses it closed. APIdispatcher registers and starts its TCP servers
// under the same lock, and starts no plaintext one once a policy is in force,
// so a reload while the daemon starts can neither miss a plaintext listener
// nor be followed by one.
func activateApiAccess(path string, store func()) []string {
	if apiActivateBeforeLockHook != nil {
		apiActivateBeforeLockHook()
	}
	apiTCPServers.Lock()
	defer apiTCPServers.Unlock()
	addrs := stopPlaintextLocked()
	if len(addrs) > 0 {
		apiTCPServers.stoppedBy = path
	}
	store()
	return addrs
}

// apiAccessInForce says whether an access policy is in force. Read under
// apiTCPServers' lock, it cannot change before the lock is released
// (activateApiAccess).
func apiAccessInForce(conf *Config) bool {
	if conf.Internal.ApiAccess == nil {
		return false
	}
	st := conf.Internal.ApiAccess.load()
	return st != nil && st.Enabled
}

// stopPlaintextApiListeners closes the TCP management API servers, with their
// connections, if they speak plaintext, and returns their addresses (nil when
// there are none, or they speak TLS). An access file requires TLS on TCP, and
// a running plaintext listener cannot take it up: refusing its requests would
// still have clients send their key in clear, so it is closed instead, until
// a restart with TLS. The local admin socket is not touched.
func stopPlaintextApiListeners() []string {
	apiTCPServers.Lock()
	defer apiTCPServers.Unlock()
	return stopPlaintextLocked()
}

// stopPlaintextLocked is stopPlaintextApiListeners for a caller that holds
// apiTCPServers' lock. It closes the socket as well as the server: a server
// whose goroutine has not reached Serve yet has no listener for Close to
// close, and the socket must not accept a connection once this returns.
func stopPlaintextLocked() []string {
	if !apiTCPServers.plaintext || len(apiTCPServers.srvs) == 0 {
		return nil
	}
	var addrs []string
	for _, s := range apiTCPServers.srvs {
		s.srv.Close()
		if s.ln != nil {
			s.ln.Close()
		}
		addrs = append(addrs, s.srv.Addr)
	}
	apiTCPServers.srvs = nil
	apiTCPServers.stopped = append(apiTCPServers.stopped, addrs...)
	return addrs
}

// stoppedPlaintextApiListeners are the addresses stopPlaintextApiListeners
// closed, for `config status` and the reload's reply. They stay closed until
// a restart, also after the access file is removed again.
func stoppedPlaintextApiListeners() []string {
	apiTCPServers.Lock()
	defer apiTCPServers.Unlock()
	return slices.Clone(apiTCPServers.stopped)
}

// apiTCPStoppedBy is the access file that stopped the plaintext TCP
// listeners (stoppedPlaintextApiListeners), or "" if none was stopped.
func apiTCPStoppedBy() string {
	apiTCPServers.Lock()
	defer apiTCPServers.Unlock()
	return apiTCPServers.stoppedBy
}

func listenerSettingsOf(a ApiServerConf) *apiListenerSettings {
	return &apiListenerSettings{Addresses: slices.Clone(a.Addresses), Socket: a.Socket,
		CertFile: a.CertFile, KeyFile: a.KeyFile, UseTLS: a.UseTLS, TLS13Only: a.AccessFile != ""}
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
	// The other way round needs no restart: an access file a reload adds is
	// held to TLS 1.3 at every handshake (apiServerTLSConfig).
	if was.TLS13Only && !now.TLS13Only {
		changed = append(changed, "apiserver.access-file (the listeners stay TLS 1.3 only)")
	}
	if len(changed) == 0 {
		return ""
	}
	return fmt.Sprintf(" NOT applied: %s changed, and the management API listeners keep what they started with; restart the daemon to apply it.",
		strings.Join(changed, ", "))
}

func APIdispatcher(conf *Config, router *mux.Router, done <-chan struct{}) error {
	// Read once: a reload may change conf.ApiServer while the listeners
	// start (over the socket, which is served before them), and a running
	// listener keeps what it started with. The record of that
	// (apiListenersStarted), the access-file guards and the listeners' TLS
	// setup all use this one copy, so they cannot disagree.
	api := conf.ApiServer
	addresses := api.Addresses
	certFile, keyFile := api.CertFile, api.KeyFile
	useTLS := api.UseTLS
	withAccessFile := api.AccessFile != ""
	serveHook := apiServeHook

	lgApi.Debug("dispatcher config", "addresses", addresses, "certFile", certFile, "keyFile", keyFile)

	if router == nil {
		lgApi.Warn("API router is nil, not starting")
		return nil
	}
	apiListenersStarted.Store(listenerSettingsOf(api))

	// An access file requires TLS on TCP (validateAccessSettings refuses
	// the config). A caller that did not validate still gets no plaintext
	// TCP API: the listeners stay off, and the socket below is served.
	if len(addresses) > 0 && withAccessFile && !useTLS {
		lgApi.Error("management API: TCP listeners NOT started: apiserver.access-file requires TLS and usetls is false; the local admin socket is still served",
			"addresses", addresses, "access-file", api.AccessFile)
		addresses = nil
	}

	// No certificate (the default pair could not be written): no TLS
	// listener, which could not start anyway; the socket below is served.
	if len(addresses) > 0 && conf.ApiServer.UseTLS && conf.ApiServer.CertPending {
		cert, _ := ApiCertPaths(conf.Internal.CfgFile)
		lgApi.Error("management API: TCP listeners NOT started: no API certificate (the default pair could not be written); the local admin socket is still served",
			"addresses", addresses, "cert", cert)
		addresses = nil
	}

	// The local admin socket first, and independently of the TCP listeners:
	// it is the way in that nothing else can take away, so a daemon with no
	// apiserver.addresses still serves it, and a socket that cannot be served
	// is an error the operator sees, not a reason to stop the daemon.
	// A socket that stops serving later is such an error too (apiSocketFailed).
	if sock := api.Socket; sock != "" {
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

	serve := func(s apiTCPServer, idx int) {
		lgApi.Info("starting API dispatcher", "index", idx, "address", s.srv.Addr)
		if useTLS {
			if err := s.srv.ServeTLS(s.ln, certFile, keyFile); err != nil && err != http.ErrServerClosed {
				lgApi.Error("ListenAndServeTLS failed", "err", err)
			}
		} else {
			lgApi.Info("serving HTTP", "address", s.srv.Addr)
			if err := s.srv.Serve(s.ln); err != nil && err != http.ErrServerClosed {
				lgApi.Error("ListenAndServe failed", "err", err)
			}
		}
	}
	run := func(s apiTCPServer, idx int) {
		// Serve closes the socket when it returns, but ServeTLS returns
		// before it gets to Serve when the certificate does not load.
		defer s.ln.Close()
		if serveHook != nil {
			serveHook(s.srv.Addr, func() { serve(s, idx) })
			return
		}
		serve(s, idx)
	}

	// Bound, registered and started under the lock a reload holds while it
	// puts an access file in force (activateApiAccess), so that the reload
	// can close them if they are plaintext. A reload that came first has its
	// policy in force already: plaintext servers are then not started at all.
	// One that comes after finds them registered, with their sockets, and
	// closes both: a socket is bound here, before its server starts, so none
	// is bound after the policy is in force (ListenAndServe binds in the
	// goroutine, where a close can come between its check and the bind). A
	// server closed before its goroutine runs returns ErrServerClosed.
	if apiDispatchBeforeLockHook != nil {
		apiDispatchBeforeLockHook()
	}
	apiTCPServers.Lock()
	if !useTLS && apiAccessInForce(conf) {
		apiTCPServers.stopped = append(apiTCPServers.stopped, addresses...)
		apiTCPServers.stoppedBy = conf.Internal.ApiAccess.load().File
		apiTCPServers.Unlock()
		lgApi.Error("management API: plaintext TCP listeners NOT started: an access file came into force while the daemon started, and it requires TLS; restart the daemon with usetls: true to serve TCP (the local admin socket is still served)",
			"addresses", addresses)
		return nil
	}
	if apiDispatchLockedHook != nil {
		apiDispatchLockedHook()
	}
	var servers []apiTCPServer
	for idx, address := range addresses {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			// As when ListenAndServe failed to bind: logged, and the other
			// listeners and the daemon carry on.
			if useTLS {
				lgApi.Error("ListenAndServeTLS failed", "err", err)
			} else {
				lgApi.Error("ListenAndServe failed", "err", err)
			}
			continue
		}
		s := apiTCPServer{ln: ln, srv: &http.Server{
			Addr:      address,
			Handler:   router,
			TLSConfig: apiServerTLSConfig(conf, withAccessFile),
			// Bounds a client that never finishes its headers (slowloris),
			// as on the local socket. Not a read or write timeout: large
			// bodies and slow handlers are legitimate here.
			ReadHeaderTimeout: 10 * time.Second,
		}}
		servers = append(servers, s)
		go run(s, idx)
	}
	apiTCPServers.srvs, apiTCPServers.plaintext = servers, !useTLS
	apiTCPServers.Unlock()

	go func() {
		<-done
		lgApi.Info("shutting down API servers")
		for _, s := range servers {
			if err := s.srv.Shutdown(context.Background()); err != nil {
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
