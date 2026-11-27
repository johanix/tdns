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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/gorilla/mux"
)

// ApiIdentity is who a management API request was authenticated as.
type ApiIdentity struct {
	Name string  // the access-file client, or "local"
	Role ApiRole // what it may do
	Via  string  // "local socket" or "certificate"
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
	// File is the access file, whether it is there or not.
	File string
	// Missing: the file is not there, so there are no TLS clients. A
	// normal state, not an error: the operator creates the file (touch) to
	// take them.
	Missing bool
	// Err is why the file could not be used when there was no policy to
	// keep (start-up, or no file before). Until a load succeeds the TCP API
	// answers 503.
	Err     error
	byPin   map[string]AccessClient
	Clients []AccessClient
}

// apiAccessHolder holds the running policy. A pointer in InternalConf, so a
// Config may be copied without copying the atomic. stamp is what the access
// file looked like at the last load (refreshApiAccess).
type apiAccessHolder struct {
	p     atomic.Pointer[accessState]
	stamp atomic.Pointer[accessStamp]
}

// accessStamp is the access file as the last load found it: its path, and
// its file info, nil when it was not there.
type accessStamp struct {
	path string
	fi   os.FileInfo
}

// unchanged says whether fi (err from the stat) is still the file of s: not
// there then and now, or the same file with the same size, time and mode.
func (s *accessStamp) unchanged(fi os.FileInfo, err error) bool {
	switch {
	case s.fi == nil:
		return err != nil
	case err != nil:
		return false
	}
	return os.SameFile(s.fi, fi) && s.fi.Size() == fi.Size() && s.fi.ModTime().Equal(fi.ModTime()) && s.fi.Mode() == fi.Mode()
}

// refreshApiAccess loads the access file again when it changed since the
// last load: created, edited, chmodded or removed. Every TCP request calls
// it, so what the file says is in force at the next request, with no
// reload; it costs a stat when nothing changed.
func (conf *Config) refreshApiAccess() {
	h := conf.Internal.ApiAccess
	if h == nil {
		return
	}
	s := h.stamp.Load()
	if s == nil {
		return // never loaded: no policy from a file to keep current
	}
	if fi, err := os.Stat(s.path); s.unchanged(fi, err) {
		return
	}
	accessMu.Lock()
	defer accessMu.Unlock()
	if h.stamp.Load() != s {
		return // loaded meanwhile, by another request, /access or a reload
	}
	conf.loadAccessPolicy(s.path)
}

func (h *apiAccessHolder) load() *accessState {
	if h == nil {
		return nil
	}
	return h.p.Load()
}

// newAccessState builds the running policy from a validated file.
func newAccessState(path string, af *AccessFile) *accessState {
	st := &accessState{File: path, byPin: map[string]AccessClient{}, Clients: append([]AccessClient(nil), af.Clients...)}
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

// authenticateApiRequest decides who r is. A non-zero status means refuse
// it. The local socket is admin. Over TCP the only credential is a client
// certificate whose pin is an enabled client in the access file; with no
// access file there are no TLS clients.
func (conf *Config) authenticateApiRequest(r *http.Request) (ApiIdentity, int, string) {
	if FromLocalSocket(r.Context()) {
		return ApiIdentity{Name: "local", Role: RoleAdmin, Via: "local socket"}, 0, ""
	}
	conf.refreshApiAccess()
	st := conf.Internal.ApiAccess.load()
	switch {
	case st == nil:
		return ApiIdentity{}, http.StatusForbidden, "Forbidden"
	case st.Err != nil:
		return ApiIdentity{}, http.StatusServiceUnavailable,
			fmt.Sprintf("the access file %s does not load, so the TCP API is closed\n(the daemon log says why); the local admin socket still works", st.File)
	case st.Missing:
		return ApiIdentity{}, http.StatusForbidden, accessFileMissing(st.File)
	}
	// The listeners speak TLS 1.3 only (apiServerTLSConfig); this is the
	// guard for a router served some other way.
	if r.TLS == nil {
		return ApiIdentity{}, http.StatusForbidden, "the management API takes TLS only"
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return ApiIdentity{}, http.StatusForbidden,
			"no client certificate: the management API takes a client\ncertificate whose pin is in the daemon's access file"
	}
	pin := SPKISHA256(r.TLS.PeerCertificates[0])
	if c, ok := st.byPin[pin]; ok && !c.Disabled {
		role, _ := parseNetworkRole(c.Role) // validated when loaded
		return ApiIdentity{Name: c.Name, Role: role, Via: "certificate"}, 0, ""
	}
	return ApiIdentity{}, http.StatusForbidden,
		fmt.Sprintf("Forbidden: the client certificate's pin %s is not an\nenabled client in the daemon's access file", pin)
}

// accessFileMissing says that the access file path is not there, and how to
// create it. Lines of at most 72 after the path; a client adds the command
// to run again.
func accessFileMissing(path string) string {
	name := Globals.App.Name
	if name == "" {
		name = "the daemon"
	}
	return fmt.Sprintf("access file %s is missing, so\n%s takes no TLS clients. Create it (empty is fine):\n   touch %s",
		path, name, shellWord(path))
}

// apiAuthMiddleware authenticates every request on the router it is installed
// on (the ROOT router, so routes added later are covered too), checks the role
// the route and command need, logs the decision and hands the identity to the
// handler.
func (conf *Config) apiAuthMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, status, msg := conf.authenticateApiRequest(r)
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
// No file is no TLS clients, logged at INFO: a normal state. A file that
// cannot be used closes the TCP API (503). DNS and the local socket are
// unaffected either way, and a reload, or a client add over the socket,
// loads the file once it is there and right.
func (conf *Config) initApiAccess() {
	if conf.Internal.ApiAccess == nil {
		conf.Internal.ApiAccess = &apiAccessHolder{}
	}
	conf.loadAccessPolicy(conf.ApiServer.AccessFile)
}

// AccessFileNotReloaded begins the part of a reload's reply that says the
// access file did not load and the running policy is unchanged. The reload as
// a whole still succeeds, so this is how its reply says so.
const AccessFileNotReloaded = "Access file NOT reloaded"

// reloadApiAccess re-reads the access file after a successful config reload
// and returns a line for the reload's reply. A file that does not load leaves
// a running policy as it was and says so; like a refused forward table it
// does not fail the rest of the reload.
func (conf *Config) reloadApiAccess() string {
	accessMu.Lock() // not while /access writes the file and loads it
	defer accessMu.Unlock()
	if conf.Internal.ApiAccess == nil {
		return "" // this daemon built no management API router
	}
	path := conf.ApiServer.AccessFile
	af, err := conf.loadAccessPolicy(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Sprintf("\nNo access file, so no TLS clients. To take them:\n   touch %s", shellWord(path))
	case err != nil:
		return fmt.Sprintf("\n%s (the running policy is unchanged):\n   %v", AccessFileNotReloaded, err)
	}
	return fmt.Sprintf(" Access file reloaded: %d client(s).", len(af.Clients))
}

// loadAccessPolicy loads the access file at path and puts it in force: at
// start-up, at a reload, and in /access. A file that is not there is no
// TLS clients, which is put in force too: removing the file takes TLS
// access away. A file that is there but does not load leaves a policy
// loaded from a file as it was; with none (start-up, or no file before),
// the TCP API answers 503 until a load succeeds.
func (conf *Config) loadAccessPolicy(path string) (*AccessFile, error) {
	h := conf.Internal.ApiAccess
	// The stamp first: a change after it, even during the read, makes the
	// next request load again (refreshApiAccess).
	fi, serr := os.Stat(path)
	if serr != nil {
		fi = nil
	}
	h.stamp.Store(&accessStamp{path: path, fi: fi})
	af, err := LoadAccessFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if st := h.load(); st == nil || !st.Missing || st.File != path {
			lgApi.Info("management API: no access file, so no TLS clients (the local socket works); create it to take them",
				"file", path)
		}
		conf.Internal.ServerErrors.clear(ErrCatConfig, ErrSubApiAccess)
		h.p.Store(&accessState{File: path, Missing: true})
		return nil, err
	case err != nil:
		st := h.load()
		if st == nil || st.Missing || st.Err != nil {
			lgApi.Error("management API: the access file cannot be used; the TCP API answers 503 until it loads (the local socket still works)",
				"file", path, "err", err)
			h.p.Store(&accessState{File: path, Err: err})
		} else {
			lgApi.Error("management API: access file NOT loaded; the running policy is unchanged", "file", path, "err", err)
		}
		conf.Internal.ServerErrors.set(ErrCatConfig, ErrSubApiAccess, fmt.Sprintf("access file %s: %v", path, err))
		return nil, err
	}
	conf.Internal.ServerErrors.clear(ErrCatConfig, ErrSubApiAccess)
	h.p.Store(newAccessState(path, af))
	// Logged as well as returned: after a SIGHUP nobody reads the message.
	lgApi.Info("management API: access file loaded", "file", path, "clients", len(af.Clients))
	if af.KeyAuth != nil {
		lgApi.Warn("management API: keyauth: in the access file is obsolete (there is no API key); it is ignored, and the daemon's next write of the file drops it",
			"file", path)
	}
	return af, nil
}

// ApiAccessStatus is the running access policy as `config status` reports it.
// Pins are public (a hash of a public key); there is no secret in here.
type ApiAccessStatus struct {
	File string
	// Missing: there is no access file, so no TLS clients.
	Missing bool   `json:",omitempty"`
	Error   string `json:",omitempty"` // the file does not load, and no policy from one runs: the TCP API answers 503
	Clients []ApiAccessStatusClient
}

// ApiAccessStatusClient is one client of the running policy.
type ApiAccessStatusClient struct {
	Name     string
	Pin      string
	Role     string
	Disabled bool   `json:",omitempty"`
	Comment  string `json:",omitempty"`
}

// apiAccessStatus is the running policy for `config status`, or nil when
// this daemon built no management API router.
func (conf *Config) apiAccessStatus() *ApiAccessStatus {
	st := conf.Internal.ApiAccess.load()
	if st == nil {
		return nil
	}
	out := &ApiAccessStatus{File: st.File, Missing: st.Missing}
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
