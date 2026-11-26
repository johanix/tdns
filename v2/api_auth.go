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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
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
// Command: far more than any management request needs. A longer body is
// refused to a network client with 413, since its command cannot be checked.
// The local socket is admin, which needs no check, so its body is passed on
// whole. A var so that tests can lower it.
var maxPeekBody = 64 << 20

// unknownCommand matches no entry in the role table, so it needs admin.
const unknownCommand = "\x00unknown"

// peekCommand returns the request body's Command field and puts the body back
// for the handler. It decodes with encoding/json into a field named Command,
// as every handler does, so both read the same value (the same case-insensitive
// key match, the same last-one-wins on a repeated key). tooLarge says the body
// is over maxPeekBody; the command is then unknownCommand.
func peekCommand(r *http.Request) (cmd string, tooLarge bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return "", false
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, int64(maxPeekBody)+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
	switch {
	case len(buf) > maxPeekBody:
		return unknownCommand, true
	case err != nil:
		return unknownCommand, false
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		return "", false
	}
	// A body that does not decode as one JSON value is not a commandless
	// request: a handler's Decoder reads the first value and ignores the
	// rest, so `{"command":"off"}{}` would run "off" with only the role a
	// commandless request needs. It needs admin instead.
	var c struct{ Command string }
	if json.Unmarshal(buf, &c) != nil {
		return unknownCommand, false
	}
	return c.Command, false
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
	// An access file means TLS 1.3 on TCP. What a listener speaks is fixed
	// when it starts, and a reload can put an access file in force on a
	// listener started without one: plaintext (usetls: false then), or a TLS
	// minimum below 1.3. Refuse such requests here, whatever the listener let
	// through. (The local socket returned above.)
	if r.TLS == nil {
		return ApiIdentity{}, http.StatusForbidden, "the access file requires TLS on the management API; this listener is plaintext (restart the daemon with usetls: true, or use the local admin socket)"
	}
	if r.TLS.Version < tls.VersionTLS13 {
		return ApiIdentity{}, http.StatusForbidden, "the access file requires TLS 1.3 on the management API"
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
			// A client that names the config it means (tdns-ncli on the local
			// socket it found through that config) is refused here, before
			// the request does anything, when this daemon runs another: the
			// socket path may be held by a daemon other than the one the
			// client checked earlier.
			if want := r.Header.Get(ExpectConfigFileHeader); want != "" && !sameConfigFile(want, conf.Internal.CfgFile) {
				lgApi.Info("api request refused: for another daemon's config", "from", r.RemoteAddr, "path", r.URL.Path, "wanted", want)
				http.Error(w, fmt.Sprintf("this daemon runs %s, not %s", absConfigFile(conf.Internal.CfgFile), want), http.StatusPreconditionFailed)
				return
			}
			route := r.URL.Path
			if cr := mux.CurrentRoute(r); cr != nil {
				if tpl, err := cr.GetPathTemplate(); err == nil {
					route = tpl
				}
			}
			cmd, tooLarge := peekCommand(r)
			need := RequiredApiRole(route, cmd)
			if tooLarge && id.Role < RoleAdmin {
				lgApi.Info("api request refused: body too large", "client", id.Name, "role", id.Role, "route", route, "limit", maxPeekBody)
				http.Error(w, fmt.Sprintf("%s: request body is over %d bytes, the most the management API reads to check a request; the daemon's local admin socket has no such limit",
					route, maxPeekBody), http.StatusRequestEntityTooLarge)
				return
			}
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

// AccessFileNotReloaded begins the part of a reload's reply that says the
// access file did not load and the running policy is unchanged. The reload as
// a whole still succeeds, so this is how its reply says so.
const AccessFileNotReloaded = "Access file NOT reloaded"

// reloadApiAccess re-reads the access file after a successful config reload
// and returns a line for the reload's reply. A file that does not load leaves
// the running policy as it was (still closed, after a failed start) and says
// so; like a refused forward table it does not fail the rest of the reload.
func (conf *Config) reloadApiAccess() string {
	accessMu.Lock() // not while /access writes the file and loads it
	defer accessMu.Unlock()
	h := conf.Internal.ApiAccess
	if h == nil {
		return "" // this daemon built no management API router
	}
	path := conf.ApiServer.AccessFile
	if path == "" {
		if st := h.load(); st != nil && st.Enabled {
			h.p.Store(&accessState{})
			conf.Internal.ServerErrors.clear(ErrCatConfig, ErrSubApiAccess)
			msg := " The access file is no longer configured: the API key is admin on the TCP API again."
			// Removing the file does not reopen what it closed: a closed
			// listener is not started again until a restart.
			if addrs := stoppedPlaintextApiListeners(); len(addrs) > 0 {
				lgApi.Info("management API: the access file is no longer configured; the API key is admin on the TCP API again, but the plaintext TCP listeners an access file STOPPED stay stopped until a restart (the local admin socket is still served)",
					"addresses", addrs)
				return msg + fmt.Sprintf(" The plaintext TCP listeners %v that an access file STOPPED stay stopped until the daemon restarts (the local admin socket is still served).", addrs)
			}
			lgApi.Info("management API: the access file is no longer configured; the API key is admin on the TCP API again")
			return msg
		}
		return ""
	}
	af, addrs, err := conf.loadAccessPolicy(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// The first enrolment: the access-file: line is new and the file
		// is not there yet. Lines of at most 72, after the path.
		return fmt.Sprintf("\nAccess file not there yet (the running policy is unchanged):\n   %s\nThe first client add (or config add) creates it.", path)
	case err != nil:
		return fmt.Sprintf("\n%s (the running policy is unchanged):\n   %v", AccessFileNotReloaded, err)
	}
	stopped := ""
	if len(addrs) > 0 {
		stopped = fmt.Sprintf(" The plaintext TCP listeners %v are STOPPED: the access file requires TLS; restart the daemon with usetls: true to serve TCP again (the local admin socket is still served).", addrs)
	}
	return fmt.Sprintf(" Access file reloaded: %d client(s), keyauth %s.%s", len(af.Clients), onOff(af.KeyAuthOn()), stopped)
}

// loadAccessPolicy loads the access file at path and puts it in force: a
// reload's way, and /access's after it writes the file. A file that does not
// load leaves the running policy as it was. Before the policy goes in force,
// the plaintext TCP listeners close (a listener started without an access
// file cannot take up TLS, and while it listens, clients send their API key
// to it in clear), until a restart: closed and the policy stored under one
// lock, which APIdispatcher also holds while it registers and starts its
// servers (activateApiAccess). stopped are the listeners it closed.
func (conf *Config) loadAccessPolicy(path string) (af *AccessFile, stopped []string, err error) {
	af, err = LoadAccessFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// The first enrolment: the access-file: line is new and the file
		// is not there yet; /access add creates it. Nothing is wrong, so
		// no server error is recorded (config status would show one).
		lgApi.Info("management API: the access file is not there yet; the running policy is unchanged, and the first client add creates it", "file", path)
		return nil, nil, err
	case err != nil:
		lgApi.Error("management API: access file NOT loaded; the running policy is unchanged", "file", path, "err", err)
		conf.Internal.ServerErrors.set(ErrCatConfig, ErrSubApiAccess, fmt.Sprintf("access file %s: %v", path, err))
		return nil, nil, err
	}
	conf.Internal.ServerErrors.clear(ErrCatConfig, ErrSubApiAccess)
	h := conf.Internal.ApiAccess
	stopped = activateApiAccess(path, func() { h.p.Store(newAccessState(path, af)) })
	if len(stopped) > 0 {
		lgApi.Error("management API: plaintext TCP listeners STOPPED: the access file requires TLS; restart the daemon with usetls: true to serve TCP again (the local admin socket is still served)",
			"addresses", stopped, "file", path)
	}
	// Logged as well as returned: after a SIGHUP nobody reads the message.
	lgApi.Info("management API: access file loaded", "file", path, "clients", len(af.Clients), "keyauth", onOff(af.KeyAuthOn()))
	return af, stopped, nil
}

// ApiAccessStatus is the running access policy as `config status` reports it.
// Pins are public (a hash of a public key); there is no secret in here.
type ApiAccessStatus struct {
	File    string
	Error   string `json:",omitempty"` // set when the file could not be used at start-up: the TCP API answers 503
	KeyAuth bool
	Clients []ApiAccessStatusClient
	// The plaintext TCP listeners an access file closed are not here but in
	// ConfigResponse.ApiTCPStopped: they stay closed after the access file
	// is removed, when there is no policy to report.
}

// ApiAccessStatusClient is one client of the running policy.
type ApiAccessStatusClient struct {
	Name     string
	Pin      string
	Role     string
	Disabled bool   `json:",omitempty"`
	Comment  string `json:",omitempty"`
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
		out.Clients = append(out.Clients, ApiAccessStatusClient{Name: c.Name, Pin: c.Pin, Role: c.Role, Disabled: c.Disabled, Comment: c.Comment})
	}
	return out
}

// withoutComments is st without the clients' comments. config status
// answers read-only callers too, and a comment is the operator's note;
// the admin /access list keeps them.
func (st *ApiAccessStatus) withoutComments() *ApiAccessStatus {
	if st != nil {
		for i := range st.Clients {
			st.Clients[i].Comment = ""
		}
	}
	return st
}

// absConfigFile is cfg made absolute from this daemon's working directory.
func absConfigFile(cfg string) string {
	if abs, err := filepath.Abs(cfg); err == nil {
		return abs
	}
	return cfg
}

// sameConfigFile says whether want, the config file a client means, is
// cfg, this daemon's: as given, cleaned, or with symlinks resolved.
func sameConfigFile(want, cfg string) bool {
	if cfg == "" {
		return false
	}
	a, b := filepath.Clean(want), absConfigFile(cfg)
	if a == b {
		return true
	}
	ra, erra := filepath.EvalSymlinks(a)
	rb, errb := filepath.EvalSymlinks(b)
	return erra == nil && errb == nil && ra == rb
}
