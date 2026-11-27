/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

	// The access check goes on the ROOT router, not on this subrouter. A
	// middleware on a subrouter covers only the routes registered on that
	// subrouter, and callers add routes of their own afterwards on a second
	// "/api/v1" subrouter of the router returned here (tdns-mp's
	// Setup*Routes) or on the root router (RegisterAPIRoute callbacks). On
	// the subrouter those routes answered unchecked.
	conf.initApiAccess()
	rtr.Use(conf.apiAuthMiddleware())
	sr := rtr.PathPrefix("/api/v1").Subrouter()

	// Common endpoints
	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf, rtr)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/access", APIaccess(conf)).Methods("POST") // admin: the local socket only
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

	// The access check goes on the ROOT router, not on this subrouter. A
	// middleware on a subrouter covers only the routes registered on that
	// subrouter, and callers add routes of their own afterwards on a second
	// "/api/v1" subrouter of the router returned here (tdns-mp's
	// Setup*Routes) or on the root router (RegisterAPIRoute callbacks). On
	// the subrouter those routes answered unchecked.
	conf.initApiAccess()
	rtr.Use(conf.apiAuthMiddleware())
	sr := rtr.PathPrefix("/api/v1").Subrouter()

	// Common endpoints
	sr.HandleFunc("/ping", APIping(conf)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf, rtr)).Methods("POST")
	sr.HandleFunc("/config", APIconfig(conf)).Methods("POST")
	sr.HandleFunc("/access", APIaccess(conf)).Methods("POST") // admin: the local socket only
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

// Sync router setup functions (SetupAgentSyncRouter, SetupCombinerSyncRouter,
// SetupSignerSyncRouter) have moved to tdns-mp/v2/apirouter_sync.go.

// apiServerTLSConfig is the TLS setup of the TCP management API listeners
// (APIdispatcher adds the certificate, loaded once): TLS 1.3 only, and a
// client certificate asked for, not required, so that a client without one
// is told why it is refused (the middleware decides), rather than getting a
// failed handshake.
func apiServerTLSConfig() *tls.Config {
	return &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
}

// apiListenerSettings are the apiserver: keys APIdispatcher acts on once, when
// it starts the listeners. A reload cannot change what is listening, so it
// says when they differ (apiListenerReloadNote).
type apiListenerSettings struct {
	Addresses                 []string
	Socket, CertFile, KeyFile string
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

// apiTCPServers are the TCP management API servers APIdispatcher started.
// One set per process. srvs are the listeners that run: config status
// reports their addresses as listening, so a server that stops is taken out
// of it.
var apiTCPServers struct {
	sync.Mutex
	srvs []apiTCPServer
	// noCert are the addresses APIdispatcher started no listener on because
	// it had no certificate (the default pair could not be written), and
	// noCertFile is that certificate, for config status. Until a restart.
	noCert     []string
	noCertFile string
	// failed are the addresses that could not be bound, or whose server
	// stopped with an error, with the error, for config status. Until a
	// restart.
	failed []ApiTCPFailure
	// pins are the SPKI pins of the certificate the TLS listeners serve,
	// loaded once when APIdispatcher starts them (apiServedPins).
	pins []string
}

// apiServedPins are the SPKI pins of the certificate the TCP API serves, or
// nil when no listener runs.
func apiServedPins() []string {
	apiTCPServers.Lock()
	defer apiTCPServers.Unlock()
	if len(apiTCPServers.srvs) == 0 {
		return nil
	}
	return slices.Clone(apiTCPServers.pins)
}

// apiServeHook, if set (in tests), is handed each TCP server's serve call
// (and may hold it, or not run it at all). APIdispatcher reads it before its
// goroutines start.
var apiServeHook func(addr string, serve func())

// fillApiTCPStatus puts the TCP API listeners' state in a `config status`
// reply, all of it read under one hold of apiTCPServers' lock:
//   - listening: the servers that run (bound, served, not stopped);
//   - not started for want of a certificate, and that certificate; they
//     stay off until a restart, also once the pair is there;
//   - failed: not bound, or stopped serving with an error.
func fillApiTCPStatus(resp *ConfigResponse) {
	apiTCPServers.Lock()
	defer apiTCPServers.Unlock()
	resp.ApiTCPListening = nil
	for _, s := range apiTCPServers.srvs {
		resp.ApiTCPListening = append(resp.ApiTCPListening, s.srv.Addr)
	}
	resp.ApiTCPNotStarted = slices.Clone(apiTCPServers.noCert)
	resp.ApiTCPNoCert = apiTCPServers.noCertFile
	resp.ApiTCPFailed = slices.Clone(apiTCPServers.failed)
}

// apiTCPErrorText is err, short, for config status: a bind failure without
// the "listen tcp <address>:" that the status already says.
func apiTCPErrorText(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

// apiTCPServeFailed records that s stopped serving with err, rather than
// being closed (the shutdown closes it, which is ErrServerClosed). It closes
// the socket first (ServeTLS can return before it gets to Serve), so that
// once s is no longer listed as listening, nothing answers there; then it is
// reported failed, and the shutdown (shutdownApiTCPServers) leaves it alone.
// srvs is replaced, not changed in place, so that a slice read from it under
// the lock stays as it was read.
func apiTCPServeFailed(s apiTCPServer, err error) {
	if s.ln != nil {
		s.ln.Close()
	}
	apiTCPServers.Lock()
	defer apiTCPServers.Unlock()
	apiTCPServers.srvs = slices.DeleteFunc(slices.Clone(apiTCPServers.srvs),
		func(r apiTCPServer) bool { return r.srv == s.srv })
	apiTCPServers.failed = append(apiTCPServers.failed,
		ApiTCPFailure{Address: s.srv.Addr, Error: apiTCPErrorText(err)})
}

func listenerSettingsOf(a ApiServerConf) *apiListenerSettings {
	return &apiListenerSettings{Addresses: slices.Clone(a.Addresses), Socket: a.Socket,
		CertFile: a.CertFile, KeyFile: a.KeyFile}
}

// apiListenerReloadNote is the part of a reload's report that names the
// listener settings the reload changed but could not apply: they take effect
// at the next restart. "" when none changed. (A changed access-file: needs
// no restart: the reload loads the new file.)
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
	// Read once: a reload may change conf.ApiServer while the listeners
	// start (over the socket, which is served before them), and a running
	// listener keeps what it started with. The record of that
	// (apiListenersStarted) and the listeners use this one copy, so they
	// cannot disagree.
	api := conf.ApiServer
	addresses := api.Addresses
	certFile, keyFile := api.CertFile, api.KeyFile
	serveHook := apiServeHook

	lgApi.Debug("dispatcher config", "addresses", addresses, "certFile", certFile, "keyFile", keyFile)

	if router == nil {
		lgApi.Warn("API router is nil, not starting")
		return nil
	}
	apiListenersStarted.Store(listenerSettingsOf(api))
	apiTCPServers.Lock()
	apiTCPServers.pins = nil // until this start serves a certificate
	apiTCPServers.Unlock()

	// No certificate (the default pair could not be written): no TCP
	// listener, which could not start anyway; the socket below is served.
	if len(addresses) > 0 && api.CertPending {
		cert, _ := ApiCertPaths(conf.Internal.CfgFile)
		lgApi.Error("management API: TCP listeners NOT started: no API certificate (the default pair could not be written); the local admin socket is still served",
			"addresses", addresses, "cert", cert)
		apiTCPServers.Lock()
		apiTCPServers.noCert, apiTCPServers.noCertFile = slices.Clone(addresses), cert
		apiTCPServers.Unlock()
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
		lgApi.Info("no TCP management API (apiserver.addresses not set); the local admin socket is the way in")
		return nil
	}

	WalkRoutes(router, addresses[0])

	// The certificate, loaded once for every listener, so that the pin
	// /access reports is of the certificate they serve. One that does not
	// load starts no TCP listener, and each address is reported failed with
	// the error; the socket above is served.
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil && cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	}
	if err != nil {
		lgApi.Error("management API: TCP listeners NOT started: the API certificate does not load; the local admin socket is still served",
			"addresses", addresses, "cert", certFile, "err", err)
		apiTCPServers.Lock()
		for _, a := range addresses {
			apiTCPServers.failed = append(apiTCPServers.failed, ApiTCPFailure{Address: a, Error: apiTCPErrorText(err)})
		}
		apiTCPServers.Unlock()
		return nil
	}
	pin := SPKISHA256(cert.Leaf)

	// A server that returns with an error is taken out of what config
	// status reports as listening, and reported failed.
	serve := func(s apiTCPServer, idx int) {
		lgApi.Info("starting API dispatcher", "index", idx, "address", s.srv.Addr)
		if err := s.srv.ServeTLS(s.ln, "", ""); err != nil && err != http.ErrServerClosed {
			lgApi.Error("ListenAndServeTLS failed", "address", s.srv.Addr, "err", err)
			apiTCPServeFailed(s, err)
		}
	}
	run := func(s apiTCPServer, idx int) {
		// Serve closes the socket when it returns, but ServeTLS may return
		// before it gets to Serve.
		defer s.ln.Close()
		if serveHook != nil {
			serveHook(s.srv.Addr, func() { serve(s, idx) })
			return
		}
		serve(s, idx)
	}

	apiTCPServers.Lock()
	var servers []apiTCPServer
	for idx, address := range addresses {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			// Logged, and the other listeners and the daemon carry on.
			// Recorded too, for config status, which would otherwise list
			// it nowhere.
			lgApi.Error("ListenAndServeTLS failed", "err", err)
			apiTCPServers.failed = append(apiTCPServers.failed,
				ApiTCPFailure{Address: address, Error: apiTCPErrorText(err)})
			continue
		}
		tc := apiServerTLSConfig()
		tc.Certificates = []tls.Certificate{cert}
		s := apiTCPServer{ln: ln, srv: &http.Server{
			Addr:      address,
			Handler:   router,
			TLSConfig: tc,
			// Bounds a client that never finishes its headers (slowloris),
			// as on the local socket. Not a read or write timeout: large
			// bodies and slow handlers are legitimate here.
			ReadHeaderTimeout: 10 * time.Second,
		}}
		servers = append(servers, s)
		go run(s, idx)
	}
	apiTCPServers.srvs = servers
	apiTCPServers.pins = []string{pin}
	apiTCPServers.Unlock()

	go func() {
		<-done
		lgApi.Info("shutting down API servers")
		shutdownApiTCPServers(servers)
	}()

	return nil
}

// shutdownApiTCPServers shuts down those of servers (one dispatcher's TCP
// servers) still listed as listening: one that stopped by itself
// (apiTCPServeFailed) is closed already, and its closing is not a failed
// shutdown, nor is a server's closing meanwhile (ErrServerClosed).
func shutdownApiTCPServers(servers []apiTCPServer) {
	apiTCPServers.Lock()
	var live []apiTCPServer
	for _, s := range servers {
		if slices.ContainsFunc(apiTCPServers.srvs, func(r apiTCPServer) bool { return r.srv == s.srv }) {
			live = append(live, s)
		}
	}
	apiTCPServers.Unlock()
	for _, s := range live {
		if err := s.srv.Shutdown(context.Background()); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lgApi.Error("API server shutdown failed", "address", s.srv.Addr, "err", err)
		}
	}
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
