/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
)

var lgDsyncApi = Logger("dsync-api")

// The DSYNC API listener (docs/2026-08-11-dsync-api-scheme.md §7).
//
// Its own socket, its own router, its own middleware. NOT a subtree of the
// management API and not sharing apiKeyAuthMiddleware, and that separation is
// the design rather than tidiness: a registrant's provisioning script is not a
// trusted operator, and the strongest guarantee that it cannot reach operator
// endpoints is that those endpoints are not on the socket it connects to.
//
// Everything here is confined by the parent zone's updatepolicy.child. Nothing
// here can set PreAuthorized.

// DsyncApiPathPrefix is the path the published URI points at. Changing it
// changes what children discover, so it is a constant rather than a knob.
const DsyncApiPathPrefix = "/dsync/v1"

// DsyncApiRequestTimeout bounds a whole request. Longer than
// UpdateApplyTimeout, so a slow apply reports as an apply timeout with its own
// explanation rather than as the connection simply going away.
const DsyncApiRequestTimeout = 20 * time.Second

// SetupDsyncApiRouter builds the router. Returns nil when the scheme is not
// configured, which is how a deployment that has not opted in ends up with no
// listener at all rather than a listener that refuses everything.
func (conf *Config) SetupDsyncApiRouter(ctx context.Context) *mux.Router {
	dsc := DelegationSyncConfig().Parent
	if !dsyncSchemeConfigured(dsc.Schemes, "api") {
		return nil
	}

	kdb := conf.Internal.KeyDB
	if kdb == nil {
		lgDsyncApi.Error("DSYNC API is configured but there is no KeyDB; not starting")
		return nil
	}

	rtr := mux.NewRouter().StrictSlash(true)
	sr := rtr.PathPrefix(DsyncApiPathPrefix).Subrouter()
	sr.Use(dsyncApiAuthMiddleware(kdb))

	sr.HandleFunc("/delegation/{child}", DsyncApiGetDelegation()).Methods("GET")
	sr.HandleFunc("/delegation/{child}", DsyncApiPostDelegation()).Methods("POST")

	return rtr
}

// StartDsyncApiListener starts the listener, if configured. Always TLS: the
// credential is a bearer token and plaintext hands it to anyone on the path.
func (conf *Config) StartDsyncApiListener(ctx context.Context, router *mux.Router, done <-chan struct{}) error {
	if router == nil {
		return nil
	}
	api := DelegationSyncConfig().Parent.Api.WithDefaults()

	if len(api.Listen) == 0 {
		lgDsyncApi.Warn("DSYNC API scheme is in delegationsync.parent.schemes but" +
			" delegationsync.parent.api.listen is empty; publishing the records but not serving them")
		return nil
	}
	if api.CertFile == "" || api.KeyFile == "" {
		// Refusing to start is the safe failure. Serving this over plaintext
		// would mean every child that used it handed over a working credential
		// to the network, and a conforming child refuses a non-https endpoint
		// anyway -- so a plaintext listener could only ever serve clients that
		// had disabled their own protection.
		return fmt.Errorf("delegationsync.parent.api needs both cert and key:" +
			" this endpoint carries bearer credentials and is not served without TLS")
	}

	servers := make([]*http.Server, 0, len(api.Listen))
	for _, addr := range api.Listen {
		srv := &http.Server{
			Addr:              addr,
			Handler:           router,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       DsyncApiRequestTimeout,
			WriteTimeout:      DsyncApiRequestTimeout,
		}
		servers = append(servers, srv)

		go func(srv *http.Server) {
			lgDsyncApi.Info("starting DSYNC API listener", "address", srv.Addr)
			if err := srv.ListenAndServeTLS(api.CertFile, api.KeyFile); err != nil && err != http.ErrServerClosed {
				lgDsyncApi.Error("DSYNC API ListenAndServeTLS failed", "address", srv.Addr, "err", err)
			}
		}(srv)
	}

	go func() {
		<-done
		lgDsyncApi.Info("shutting down DSYNC API listeners")
		for _, srv := range servers {
			if err := srv.Shutdown(context.Background()); err != nil {
				lgDsyncApi.Error("DSYNC API shutdown failed", "err", err)
			}
		}
	}()

	return nil
}

// dsyncApiPrincipalKey is the request-context key carrying the authenticated
// credential from the middleware to the handler.
type dsyncApiPrincipalKey struct{}

// dsyncApiAuthMiddleware authenticates HTTP Basic against the credential store.
//
// The parent zone has to be resolved before the credential can be looked up --
// credentials are scoped to one parent -- so the order is: find the zone,
// then authenticate, then (in the handler) authorize. Zone existence is
// therefore visible to an unauthenticated caller, which is fine: it is visible
// in the DNS too.
func dsyncApiAuthMiddleware(kdb *KeyDB) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			child := dns.Fqdn(strings.TrimSpace(mux.Vars(r)["child"]))
			if child == "." {
				dsyncApiError(w, http.StatusBadRequest, "no child name in the request path")
				return
			}

			zd, err := dsyncApiParentZone(child)
			if err != nil {
				dsyncApiError(w, http.StatusNotFound, "%v", err)
				return
			}

			user, key, ok := r.BasicAuth()
			if !ok {
				// The challenge names the realm as the parent zone, which is
				// the scope the credential actually has.
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf("Basic realm=%q, charset=\"UTF-8\"", zd.ZoneName))
				dsyncApiError(w, http.StatusUnauthorized, "")
				return
			}

			cred, err := kdb.VerifyDsyncApiCredential(zd.ZoneName, user, key)
			if err != nil {
				// Logged with the username, answered without one. The store
				// returns the same error for unknown/wrong/disabled/expired,
				// and that must not leak into the response.
				lgDsyncApi.Warn("DSYNC API authentication failed",
					"zone", zd.ZoneName, "child", child, "user", user, "from", r.RemoteAddr)
				dsyncApiError(w, http.StatusUnauthorized, "")
				return
			}

			lgDsyncApi.Debug("DSYNC API request authenticated",
				"zone", zd.ZoneName, "child", child, "user", cred.Username,
				"principal", cred.Principal, "from", r.RemoteAddr)

			ctx := context.WithValue(r.Context(), dsyncApiPrincipalKey{}, cred)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// dsyncApiCredentialFrom retrieves the authenticated credential. Absent means
// the handler was reached without the middleware, which is a wiring bug rather
// than a request the caller can fix.
func dsyncApiCredentialFrom(r *http.Request) *DsyncApiCredential {
	cred, _ := r.Context().Value(dsyncApiPrincipalKey{}).(*DsyncApiCredential)
	return cred
}

// dsyncApiParentZone resolves the hosted parent zone for a child name.
//
// Strictly an ancestor: a zone is never its own parent. Asking to change the
// delegation of example. when example. is the hosted zone is a request to
// rewrite that zone's own apex through a channel meant for its children, so
// the search starts one label up.
//
// The nearest hosted ancestor wins. One listener can front many parents, and
// the child name is what says which.
func dsyncApiParentZone(child string) (*ZoneData, error) {
	child = strings.ToLower(dns.Fqdn(strings.TrimSpace(child)))

	labels := dns.SplitDomainName(child)
	// i starts at 1: labels[0:] would be the child itself.
	for i := 1; i <= len(labels); i++ {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))
		zd, ok := Zones.Get(candidate)
		if !ok {
			continue
		}

		zd.mu.Lock()
		offersScheme := zd.Options[OptDelSyncParent]
		allowsChildUpdates := zd.Options[OptAllowChildUpdates]
		zd.mu.Unlock()

		// A hosted ancestor that does not offer the facility is the answer,
		// not a reason to keep climbing: its grandparent is not authoritative
		// for this delegation and must not be asked to change it.
		if !offersScheme {
			return nil, fmt.Errorf("zone %s does not offer delegation sync", candidate)
		}
		if !allowsChildUpdates {
			return nil, fmt.Errorf("zone %s does not accept child updates", candidate)
		}
		return zd, nil
	}
	return nil, fmt.Errorf("no hosted parent zone for %s", child)
}
