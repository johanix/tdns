/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Who is calling the management API, and may they? Design:
 * docs/2026-11-20-api-pinning-mtls-roles-design.md sections 3.3 to 3.5.
 */
package tdns

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/gorilla/mux"
)

// ApiIdentity is who a management API request was authenticated as.
type ApiIdentity struct {
	Name string  // the access-file client, "apikey", or "local"
	Role ApiRole // what it may do
	Via  string  // "local socket", "certificate" or "api key"
}

// Describe is the sentence `ping` answers with.
func (id ApiIdentity) Describe() string {
	if id.Via == "local socket" {
		return fmt.Sprintf("on the local socket (%s)", id.Role)
	}
	return fmt.Sprintf("authenticated as %s (%s) by %s", id.Name, id.Role, id.Via)
}

type apiIdentityKey struct{}

// ApiIdentityFrom returns the identity the auth middleware put on the request.
func ApiIdentityFrom(ctx context.Context) (ApiIdentity, bool) {
	id, ok := ctx.Value(apiIdentityKey{}).(ApiIdentity)
	return id, ok
}

// accessState is the network API's access policy as running: published whole
// (a new pointer) and read whole, so a request sees one policy, never half of
// a reload.
type accessState struct {
	// Enabled: apiserver.access-file is set. Not enabled is the network API
	// as before the access file existed: the API key, as admin.
	Enabled bool
	File    string
	// Err is why the file could not be used when there was no previous policy
	// to keep (start-up). Until a reload succeeds the TCP API answers 503.
	Err     error
	KeyAuth bool
	byPin   map[string]AccessClient
	Clients []AccessClient
}

// apiAccessHolder holds the running policy. A pointer in InternalConf, so a
// Config may be copied without copying the atomic.
type apiAccessHolder struct{ p atomic.Pointer[accessState] }

func (h *apiAccessHolder) load() *accessState {
	if h == nil {
		return nil
	}
	return h.p.Load()
}

// newAccessState builds the running policy from a validated file.
func newAccessState(path string, af *AccessFile) *accessState {
	st := &accessState{Enabled: true, File: path, KeyAuth: af.KeyAuthOn(),
		byPin: map[string]AccessClient{}, Clients: append([]AccessClient(nil), af.Clients...)}
	for _, c := range af.Clients {
		st.byPin[c.Pin] = c
	}
	return st
}

// maxPeekBody caps how much of a request body the middleware reads to find its
// Command. A body longer than this is still passed on whole; its command is
// then unknown, which needs admin.
const maxPeekBody = 1 << 20

// peekCommand returns the request body's Command field and puts the body back
// for the handler. It decodes with encoding/json into a field named Command,
// as every handler does, so both read the same value (the same case-insensitive
// key match, the same last-one-wins on a repeated key).
func peekCommand(r *http.Request) string {
	if r.Body == nil || r.Body == http.NoBody {
		return ""
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, maxPeekBody+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
	if err != nil || len(buf) > maxPeekBody {
		return "\x00unknown" // matches nothing: needs admin
	}
	var c struct{ Command string }
	if json.Unmarshal(buf, &c) != nil {
		return ""
	}
	return c.Command
}

// authenticate decides who r is. A non-zero status means refuse it.
func (conf *Config) authenticateApiRequest(r *http.Request, apikey string) (ApiIdentity, int, string) {
	if FromLocalSocket(r.Context()) {
		return ApiIdentity{Name: "local", Role: RoleAdmin, Via: "local socket"}, 0, ""
	}
	keyOK := func() bool {
		k := r.Header.Get("X-API-Key")
		return apikey != "" && subtle.ConstantTimeCompare([]byte(k), []byte(apikey)) == 1
	}

	st := conf.Internal.ApiAccess.load()
	if st == nil || !st.Enabled {
		// No access file: the key, as admin, exactly as before.
		if keyOK() {
			return ApiIdentity{Name: "apikey", Role: RoleAdmin, Via: "api key"}, 0, ""
		}
		return ApiIdentity{}, http.StatusForbidden, "Forbidden"
	}
	if st.Err != nil {
		return ApiIdentity{}, http.StatusServiceUnavailable,
			"management API disabled by a configuration error; see the daemon log, or use the local socket"
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		pin := SPKISHA256(r.TLS.PeerCertificates[0])
		if c, ok := st.byPin[pin]; ok && !c.Disabled {
			role, _ := parseNetworkRole(c.Role) // validated when loaded
			return ApiIdentity{Name: c.Name, Role: role, Via: "certificate"}, 0, ""
		}
		// An unknown or disabled certificate does not fall through to the key:
		// a client that presents a certificate is that certificate.
		return ApiIdentity{}, http.StatusForbidden, "Forbidden"
	}
	if st.KeyAuth && keyOK() {
		return ApiIdentity{Name: "apikey", Role: RoleReadWrite, Via: "api key"}, 0, ""
	}
	return ApiIdentity{}, http.StatusForbidden, "Forbidden"
}

// apiAuthMiddleware authenticates every request on the router it is installed
// on (the ROOT router, so routes added later are covered too), checks the role
// the route and command need, logs the decision and hands the identity to the
// handler.
func (conf *Config) apiAuthMiddleware(apikey string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, status, msg := conf.authenticateApiRequest(r, apikey)
			if status != 0 {
				lgApi.Info("api request refused", "from", r.RemoteAddr, "path", r.URL.Path, "status", status)
				http.Error(w, msg, status)
				return
			}
			route := r.URL.Path
			if cr := mux.CurrentRoute(r); cr != nil {
				if tpl, err := cr.GetPathTemplate(); err == nil {
					route = tpl
				}
			}
			cmd := peekCommand(r)
			need := RequiredApiRole(route, cmd)
			if id.Role < need {
				lgApi.Info("api request denied", "client", id.Name, "role", id.Role, "route", route, "command", cmd, "needs", need)
				if need == RoleAdmin {
					http.Error(w, fmt.Sprintf("%s %s needs admin, which is available only on the daemon's local admin socket", route, cmd), http.StatusForbidden)
				} else {
					http.Error(w, fmt.Sprintf("%s %s needs %s; %s is %s", route, cmd, need, id.Name, id.Role), http.StatusForbidden)
				}
				return
			}
			if need >= RoleReadWrite {
				lgApi.Info("api request", "client", id.Name, "role", id.Role, "via", id.Via, "route", route, "command", strings.TrimSpace(cmd))
			} else {
				lgApi.Debug("api request", "client", id.Name, "role", id.Role, "via", id.Via, "route", route, "command", strings.TrimSpace(cmd))
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), apiIdentityKey{}, id)))
		})
	}
}

// initApiAccess loads the access file into the running policy. The router
// builders call it, once, at start-up.
//
// A file that cannot be used closes the TCP API (503) rather than falling back
// to the API key: that fallback would be a security downgrade at exactly the
// moment something has gone wrong. DNS and the local socket are unaffected,
// and a reload over the socket brings the TCP API back once the file is fixed.
func (conf *Config) initApiAccess() {
	if conf.Internal.ApiAccess == nil {
		conf.Internal.ApiAccess = &apiAccessHolder{}
	}
	path := conf.ApiServer.AccessFile
	if path == "" {
		conf.Internal.ApiAccess.p.Store(&accessState{})
		return
	}
	af, err := LoadAccessFile(path)
	if err != nil {
		lgApi.Error("management API: the access file cannot be used; the TCP API answers 503 until a reload succeeds (the local socket still works)",
			"file", path, "err", err)
		conf.Internal.ServerErrors.set(ErrCatConfig, ErrSubApiAccess, fmt.Sprintf("access file %s: %v", path, err))
		conf.Internal.ApiAccess.p.Store(&accessState{Enabled: true, File: path, Err: err})
		return
	}
	conf.Internal.ServerErrors.clear(ErrCatConfig, ErrSubApiAccess)
	conf.Internal.ApiAccess.p.Store(newAccessState(path, af))
	lgApi.Info("management API: access file loaded", "file", path, "clients", len(af.Clients), "keyauth", af.KeyAuthOn())
}

// reloadApiAccess re-reads the access file after a successful config reload
// and returns a line for the reload's reply. A file that does not load leaves
// the running policy as it was (still closed, after a failed start) and says
// so; like a refused forward table it does not fail the rest of the reload.
func (conf *Config) reloadApiAccess() string {
	h := conf.Internal.ApiAccess
	if h == nil {
		return "" // this daemon built no management API router
	}
	path := conf.ApiServer.AccessFile
	if path == "" {
		if st := h.load(); st != nil && st.Enabled {
			h.p.Store(&accessState{})
			conf.Internal.ServerErrors.clear(ErrCatConfig, ErrSubApiAccess)
			return " The access file is no longer configured: the API key is admin on the TCP API again."
		}
		return ""
	}
	af, err := LoadAccessFile(path)
	if err != nil {
		lgApi.Error("management API: access file NOT reloaded; the running policy is unchanged", "file", path, "err", err)
		conf.Internal.ServerErrors.set(ErrCatConfig, ErrSubApiAccess, fmt.Sprintf("access file %s: %v", path, err))
		return fmt.Sprintf(" Access file NOT reloaded (the running policy is unchanged): %v", err)
	}
	conf.Internal.ServerErrors.clear(ErrCatConfig, ErrSubApiAccess)
	h.p.Store(newAccessState(path, af))
	keyauth := "on"
	if !af.KeyAuthOn() {
		keyauth = "off"
	}
	return fmt.Sprintf(" Access file reloaded: %d client(s), keyauth %s.", len(af.Clients), keyauth)
}

// ApiAccessStatus is the running access policy as `config status` reports it.
// Pins are public (a hash of a public key); there is no secret in here.
type ApiAccessStatus struct {
	File    string
	Error   string `json:",omitempty"` // set when the file could not be used at start-up: the TCP API answers 503
	KeyAuth bool
	Clients []ApiAccessStatusClient
}

// ApiAccessStatusClient is one client of the running policy.
type ApiAccessStatusClient struct {
	Name     string
	Pin      string
	Role     string
	Disabled bool `json:",omitempty"`
}

// apiAccessStatus is the running policy for `config status`, or nil when no
// access file is configured.
func (conf *Config) apiAccessStatus() *ApiAccessStatus {
	st := conf.Internal.ApiAccess.load()
	if st == nil || !st.Enabled {
		return nil
	}
	out := &ApiAccessStatus{File: st.File, KeyAuth: st.KeyAuth}
	if st.Err != nil {
		out.Error = st.Err.Error()
	}
	for _, c := range st.Clients {
		out.Clients = append(out.Clients, ApiAccessStatusClient{Name: c.Name, Pin: c.Pin, Role: c.Role, Disabled: c.Disabled})
	}
	return out
}
