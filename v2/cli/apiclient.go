/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * API client configuration, role → clientKey registry, and the
 * shared InitApiClients helper used by each CLI binary's root.go.
 */
package cli

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// ApiDetails is one entry in the apiservers list of a CLI config file.
type ApiDetails struct {
	Name       string `validate:"required" yaml:"name"`
	BaseURL    string `validate:"required" yaml:"baseurl"`
	ApiKey     string `validate:"required" yaml:"apikey"`
	AuthMethod string `validate:"required" yaml:"authmethod"`
	RootCA     string `yaml:"rootca"`
	Command    string `yaml:"command,omitempty"`
	// Role names the command tree this entry is reachable through, for a
	// SECOND (third, ...) instance of a daemon this CLI already knows how to
	// drive. `role: auth` on an entry named "sectdns" builds the whole auth
	// command tree a second time, targeting this entry, reachable as
	// `tdns-ncli sectdns ...`. (tdns-cli ignores the field entirely; only
	// tdns-ncli wires instance trees.)
	//
	// Empty is the normal case and means "this entry is the canonical target
	// for whichever role RegisterRole maps to its Name" -- i.e. every config
	// written before this field existed keeps working unchanged.
	//
	// mapstructure as well as yaml, for the same reason ConfigFile below
	// carries one: the CLI roots decode with viper.Unmarshal, which never
	// consults yaml tags.
	Role string `yaml:"role,omitempty" mapstructure:"role"`
	// mapstructure as well as yaml: the CLI roots decode this file with
	// viper.Unmarshal, which never consults yaml tags. "config-file" does not
	// match the field name, so without this tag it decodes to "" in silence.
	ConfigFile string `yaml:"config-file,omitempty" mapstructure:"config-file"`
	// TLSAuth says how the CLI verifies the daemon over TLS: "pin" (Pins),
	// "pkix" (RootCA, or the system roots), or "" for the old behaviour
	// (RootCA if set, else no verification). tdns-ncli refuses an https entry
	// that verifies nothing unless it says rootca: insecure.
	TLSAuth string `yaml:"tlsauth,omitempty" mapstructure:"tlsauth"`
	// Pins are the daemon's SPKI SHA-256 pins for tlsauth: pin: its current
	// key, and the next one during a key change.
	Pins []string `yaml:"pins,omitempty" mapstructure:"pins"`
}

// CliConf is the parsed CLI config. Each CLI binary's root.go populates
// one of these (currently via viper + Unmarshal) and hands it to
// InitApiClients.
type CliConf struct {
	ApiServers []ApiDetails
	Keys       tdns.KeyConf
	// Client names the operator's own certificate, presented by entries with
	// authmethod: certificate. Unset, the default location is used
	// (DefaultClientCertPaths).
	Client CliClientConf
}

// CliClientConf is the CLI config's client: block.
type CliClientConf struct {
	Cert string `yaml:"cert" mapstructure:"cert"`
	Key  string `yaml:"key" mapstructure:"key"`
}

// RequireServerVerification makes an https entry that verifies nothing about
// the daemon an error rather than an unverified connection. tdns-ncli sets it
// in its init(); tdns-cli leaves it false and keeps its long-standing
// default (no rootca: no verification).
var RequireServerVerification bool

// apiClientErrors records why an entry has no client; GetApiClient reports it
// when that entry is used, so one bad entry does not stop the others.
var apiClientErrors = map[string]error{}

// apiClientWarnings are said once, when the entry is first used.
var apiClientWarnings = map[string]string{}

// socketPending holds the entries whose daemon's local admin socket is checked
// when the entry is first used (GetApiClient), not when the CLI starts. The
// check asks the daemon which config it runs, and a command uses one entry:
// asking every daemon in the CLI config first cost a round trip each, and a
// daemon that hangs would hold up commands for the others.
var socketPending = map[string]pendingClient{}

type pendingClient struct {
	e  ApiDetails
	cc CliClientConf
}

// roleToClientKey maps Cobra-tree role names (e.g. "agent", "signer")
// to the clientKey used to look up the ApiClient in
// tdns.Globals.ApiClients (e.g. "tdns-agent", "tdns-mpsigner").
//
// Each CLI package owns the roles for the daemons it interacts with
// and registers them via RegisterRole in its own init(). Downstream
// packages (e.g. tdns-mp/v2/cli) can override entries set by upstream
// packages; the per-binary effective map is the union of whichever
// cli packages the binary imports.
var roleToClientKey = map[string]string{}

// RegisterRole associates role with clientKey. Later calls for the
// same role override earlier ones — this is how tdns-mp overrides the
// "agent" → "tdns-agent" default with "agent" → "tdns-mpagent".
//
// The map is not concurrency-safe, so this must be called before any
// goroutine can read it. Two callers qualify: package init() (init ordering
// inside a package is deterministic, and across imported packages topological,
// which is what makes downstream overrides work), and WireInstanceTrees during
// Execute, before cobra dispatches anything. Do not call it from a running
// command.
func RegisterRole(role, clientKey string) {
	roleToClientKey[role] = clientKey
}

func init() {
	// tdns-owned roles. Downstream cli packages register their own
	// daemons' roles (signer/combiner/agent→mpagent in tdns-mp,
	// scanner in tdns-apps, kdc/krs in tdns-nm, …).
	RegisterRole("auth", "tdns-auth")
	RegisterRole("imr", "tdns-imr")
	RegisterRole("agent", "tdns-agent")
}

// apiConfig is the most recent CliConf passed to InitApiClients. Used
// by getApiDetailsByClientKey to look up per-server config (command
// path for "daemon start", config-file for "keys generate", etc.)
// without reaching back into viper.
var apiConfig *CliConf

// InitApiClients creates a tdns.ApiClient for every entry in
// c.ApiServers and stashes them in tdns.Globals.ApiClients. Also
// parses TSIG keys from c.Keys and records c for later config
// lookups.
//
// Unlike the previous per-binary implementations, this does *not*
// require a client named "tdns-auth". Callers resolve their ApiClient
// via GetApiClient(role, …) and get a use-time failure if the role
// they need isn't configured.
func InitApiClients(c *CliConf) error {
	if c == nil {
		return fmt.Errorf("InitApiClients: nil CliConf")
	}

	// Only the instance entries the wiring gave a command tree get a client
	// (see clientEntries); the wiring has already warned about the others.
	servers := clientEntries(c.ApiServers)

	if tdns.Globals.Debug {
		fmt.Printf("InitApiClients: setting up API clients for:")
	}
	for _, val := range servers {
		delete(socketPending, val.Name)
		if socketCandidate(val) {
			// Its socket is checked on first use (resolvePending). Until
			// then, the TCP client, for code that reads the client table
			// without GetApiClient (the tdns.Globals.Api shim below).
			socketPending[val.Name] = pendingClient{e: val, cc: c.Client}
			delete(apiClientErrors, val.Name)
			delete(apiClientWarnings, val.Name)
			delete(tdns.Globals.ApiClients, val.Name)
			if val.BaseURL != "" {
				if ac, _, err := buildApiClient(val, c.Client, "", ""); err == nil {
					tdns.Globals.ApiClients[val.Name] = ac
				}
			}
			continue
		}
		ac, warn, err := newApiClientFor(val, c.Client)
		if err != nil {
			apiClientErrors[val.Name] = err
			delete(tdns.Globals.ApiClients, val.Name)
			continue
		}
		delete(apiClientErrors, val.Name)
		if warn != "" {
			apiClientWarnings[val.Name] = warn
		}
		tdns.Globals.ApiClients[val.Name] = ac
		if tdns.Globals.Debug {
			fmt.Printf(" %s", val.Name)
		}
	}
	if tdns.Globals.Debug {
		fmt.Printf("\n")
	}

	// Shim: tdns.Globals.Api is still used by external packages
	// (tdns-es, tdns-nm, tdns/music). Point it at the tdns-auth client
	// when available so those keep working. Nothing inside tdns/v2/cli
	// reads it any more; the shim can go away once the external
	// consumers migrate to GetApiClient(role, …).
	if authClient, ok := tdns.Globals.ApiClients["tdns-auth"]; ok {
		tdns.Globals.Api = authClient
	}

	// The config lookups by client name (config-file:, the daemon command)
	// must find the entry whose client was built, not a left-out instance
	// that happens to come first.
	cc := *c
	cc.ApiServers = servers
	apiConfig = &cc

	numtsigs, _ := tdns.ParseTsigKeys(&c.Keys)
	if tdns.Globals.Debug {
		fmt.Printf("Parsed %d TSIG keys\n", numtsigs)
	}

	return nil
}

// GetApiClient returns the configured ApiClient for the given role.
// The role is resolved to a clientKey via the RegisterRole registry
// and looked up in tdns.Globals.ApiClients. dieOnError controls
// whether unknown/missing roles terminate the process.
func GetApiClient(role string, dieOnError bool) (*tdns.ApiClient, error) {
	clientKey := getClientKeyFromParent(role)
	if clientKey == "" {
		if dieOnError {
			fatalf("unknown role: %s", role)
		}
		return nil, fmt.Errorf("unknown role: %s", role)
	}

	resolvePending(clientKey)
	client := tdns.Globals.ApiClients[clientKey]
	if client == nil {
		if err := apiClientErrors[clientKey]; err != nil {
			if dieOnError {
				dieOn(err)
			}
			return nil, err
		}
		if dieOnError {
			keys := make([]string, 0, len(tdns.Globals.ApiClients))
			for k := range tdns.Globals.ApiClients {
				keys = append(keys, k)
			}
			fatalf("no API client found for %s (have clients for: %v)", clientKey, keys)
		}
		return nil, fmt.Errorf("no API client found for %s", clientKey)
	}

	if w := apiClientWarnings[clientKey]; w != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
		delete(apiClientWarnings, clientKey)
	}
	if tdns.Globals.Debug {
		fmt.Printf("Using API client for %q:\nBaseUrl: %s\n", clientKey, client.BaseUrl)
	}
	return client, nil
}

// resolvePending builds the client of an entry whose socket check
// InitApiClients left for first use: over the daemon's local admin socket when
// it answers and is that daemon, else over TCP. Once per entry.
func resolvePending(name string) {
	p, ok := socketPending[name]
	if !ok {
		return
	}
	delete(socketPending, name)
	delete(apiClientWarnings, name)
	ac, warn, err := newApiClientFor(p.e, p.cc)
	if err != nil {
		apiClientErrors[name] = err
		delete(tdns.Globals.ApiClients, name)
		return
	}
	delete(apiClientErrors, name)
	if warn != "" {
		apiClientWarnings[name] = warn
	}
	tdns.Globals.ApiClients[name] = ac
	if name == "tdns-auth" {
		tdns.Globals.Api = ac
	}
}

// ApiClientByName is the client of the apiservers entry called name, its
// daemon's local admin socket checked as GetApiClient does, or nil: for tools
// that pick an entry by name, not by role (tdns-debug --target).
func ApiClientByName(name string) *tdns.ApiClient {
	resolvePending(name)
	return tdns.Globals.ApiClients[name]
}

// isUnixURL says whether baseurl is a local socket URL, its scheme in any case.
func isUnixURL(baseurl string) bool {
	return len(baseurl) >= 7 && strings.EqualFold(baseurl[:7], "unix://")
}

// socketCandidate says whether e may reach its daemon over the daemon's local
// admin socket: it names the daemon's config, it is not a socket entry, and
// --tcp was not given.
func socketCandidate(e ApiDetails) bool {
	return !ForceTCP && e.ConfigFile != "" && !isUnixURL(e.BaseURL)
}

// loopbackURL says whether rawURL's host is localhost or a loopback address.
func loopbackURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// clientRefusal is an entry tdns-ncli will not connect through: why, and the
// command that fixes it. GetApiClient prints it as a refusal, on lines of its
// own; Error() is the one-line form, for config list.
type clientRefusal struct {
	entry, why, fix string
}

func (r clientRefusal) Error() string {
	return fmt.Sprintf("not connecting to %s: %s; fix: %s", r.entry, r.why, r.fix)
}

// pinRefusal refuses entry e for want of a pin. Pinning is how tdns-ncli
// verifies a daemon, and config add is how an entry gets its pin, a known
// one included.
func pinRefusal(e ApiDetails, why string) clientRefusal {
	daemon := "<the daemon's config file>"
	if e.ConfigFile != "" {
		daemon = shellQuote(e.ConfigFile)
	}
	return clientRefusal{entry: e.Name, why: why, fix: "tdns-ncli config add " + daemon}
}

// dieOn ends the process on err, which GetApiClient could not get past. A
// refusal says so plainly, with its fix on a line of its own; anything else
// is an error. Neither goes through the log: it is the answer to the
// command, not a log line.
func dieOn(err error) {
	var r clientRefusal
	if errors.As(err, &r) {
		fmt.Fprintf(os.Stderr, "Error: not connecting to %s:\n  %s.\n  Fix: %s\n", r.entry, r.why, r.fix)
		os.Exit(1)
	}
	fatalf("%v", err)
}

// ForceTCP makes every entry use its TCP address, never its daemon's local
// admin socket (tdns-ncli --tcp): to see what a remote operator sees, roles
// and all, from the daemon's own host.
var ForceTCP bool

// usableDaemonSocket is the local admin socket of the daemon e's config-file:
// names, when it answers and is that daemon, or "". Not for an entry that is
// already a socket entry, nor with ForceTCP. Answering takes root (the socket
// is 0600 in a 0700 directory) and a running daemon; anything less leaves the
// TCP address.
//
// Only when the entry's TCP address is one that daemon config lists, or the
// entry has none: the same config-file: path exists on every host
// (/etc/tdns/tdns-auth.yaml), so an entry for a daemon on another host would
// otherwise reach the daemon on this one. And only when the daemon that
// answers on the socket says it runs that config file: the path comes from
// the config, but another daemon may hold it (one whose socket: names it),
// and a command for one daemon must not run, as admin, on another. note says
// why a socket that answered was not used.
func usableDaemonSocket(e ApiDetails) (sock, note string) {
	if !socketCandidate(e) {
		return "", ""
	}
	sock, addrs := daemonSocket(e.ConfigFile)
	if sock == "" {
		return "", ""
	}
	if e.BaseURL != "" && !slices.Contains(addrs, hostPort(e.BaseURL)) {
		return "", ""
	}
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return "", ""
	}
	c.Close()
	probe := tdns.NewClientWithOptions(e.Name, "unix://"+sock, tdns.ClientOptions{AuthMethod: "none"})
	probe.Client.Timeout = 5 * time.Second
	resp, err := askIdentity(probe)
	switch {
	case err != nil:
		return "", fmt.Sprintf("%s: the local admin socket %s did not say which daemon it is (%v); not using it", e.Name, sock, err)
	case resp.ConfigFile == "":
		return "", fmt.Sprintf("%s: the daemon on %s does not say which config it runs; not using its socket", e.Name, sock)
	case resolvedPath(resp.ConfigFile) != resolvedPath(e.ConfigFile):
		return "", fmt.Sprintf("%s: the daemon on %s runs %s, not %s; not using its socket", e.Name, sock, resp.ConfigFile, e.ConfigFile)
	}
	return sock, ""
}

// askIdentity asks the daemon on probe which config it runs. Quietly: it is
// how tdns-ncli picks its route, not the command the operator gave, so -v does
// not print its status (SendConfigCommand would).
func askIdentity(probe *tdns.ApiClient) (tdns.ConfigResponse, error) {
	var cr tdns.ConfigResponse
	body, err := json.Marshal(tdns.ConfigPost{Command: "identity"})
	if err != nil {
		return cr, err
	}
	status, buf, err := probe.Post("/config", body)
	if err != nil {
		return cr, err
	}
	if err := json.Unmarshal(buf, &cr); err != nil {
		return cr, fmt.Errorf("status %d, and a reply that is not JSON: %v", status, err)
	}
	if cr.Error {
		return cr, errors.New(cr.ErrorMsg)
	}
	return cr, nil
}

// newApiClientFor builds the client for one apiservers entry: how it verifies
// the daemon (pins, roots, or, said out loud, nothing) and how it
// authenticates itself (key, certificate, or nothing on the local socket).
// The warning, if any, is for the operator when the entry is used.
func newApiClientFor(e ApiDetails, cc CliClientConf) (*tdns.ApiClient, string, error) {
	// The client recognises the socket scheme only as "unix://"; spelled
	// any other way it would be taken for TCP (and its rootca read, or the
	// process ended on it). The scheme is case-insensitive, the path is not.
	if isUnixURL(e.BaseURL) {
		e.BaseURL = "unix://" + e.BaseURL[7:]
	}
	// The daemon's local admin socket, when the entry names the daemon's
	// config and the socket answers: admin, no key, no TLS. Its path is in the
	// daemon config (tdns.ApiSocketPath), not in the CLI config, so the two
	// cannot disagree. Otherwise the entry's TCP address.
	sock, sockNote := usableDaemonSocket(e)
	return buildApiClient(e, cc, sock, sockNote)
}

// buildApiClient builds e's client, over sock when that is set (the daemon's
// local admin socket, checked by usableDaemonSocket), else over e's own
// baseurl. sockNote says why a socket that answered was not used.
func buildApiClient(e ApiDetails, cc CliClientConf, sock, sockNote string) (*tdns.ApiClient, string, error) {
	if isUnixURL(e.BaseURL) {
		e.BaseURL = "unix://" + e.BaseURL[7:]
	}
	if sock != "" {
		if tdns.Globals.Debug {
			fmt.Printf("%s: using the daemon's local admin socket %s\n", e.Name, sock)
		}
		e.BaseURL, e.ApiKey, e.AuthMethod = "unix://"+sock, "", "none"
	}
	switch {
	case e.BaseURL == "" && sockNote != "":
		return nil, "", errors.New(sockNote)
	case e.BaseURL == "":
		return nil, "", fmt.Errorf("entry %q has no baseurl, and the local admin socket of its daemon (config-file: %s) cannot be used: only root can open it, and the daemon must be running", e.Name, e.ConfigFile)
	case ForceTCP && strings.HasPrefix(e.BaseURL, "unix://"):
		// An entry written as a socket entry has no TCP address to use.
		return nil, "", fmt.Errorf("entry %q is a local socket entry (baseurl %s), so it has no TCP address for --tcp", e.Name, e.BaseURL)
	}
	o := tdns.ClientOptions{ApiKey: e.ApiKey, AuthMethod: e.AuthMethod, RootCA: e.RootCA}
	if sock != "" {
		// Checked above, and on every request too: the daemon refuses one
		// meant for another config, so a daemon that took the socket after
		// the check cannot run the command.
		o.ExpectConfigFile = e.ConfigFile
	}
	warn := ""
	if strings.HasPrefix(strings.ToLower(e.BaseURL), "https://") {
		switch strings.ToLower(e.TLSAuth) {
		case "pin":
			if len(e.Pins) == 0 {
				return nil, "", pinRefusal(e, "its entry has tlsauth: pin but no pins:")
			}
			o.Pins = e.Pins
		case "pkix":
			if o.RootCA == "" {
				o.RootCA = "system"
			}
		case "":
			if o.RootCA == "" {
				if RequireServerVerification {
					return nil, "", pinRefusal(e, "its entry has no pin of the daemon's certificate, so the daemon cannot be verified")
				}
				o.RootCA = "insecure" // tdns-cli's long-standing default
			}
		default:
			return nil, "", fmt.Errorf("entry %q: unknown tlsauth %q (pin or pkix)", e.Name, e.TLSAuth)
		}
		if o.RootCA == "insecure" && len(o.Pins) == 0 && RequireServerVerification {
			warn = fmt.Sprintf("%s: the daemon's TLS certificate is not verified (rootca: insecure)", e.Name)
		}
	} else {
		if o.RootCA == "" {
			o.RootCA = "insecure" // plain http or the local socket: there is no certificate
		}
		// Plain http verifies nothing and sends the key in clear. On
		// loopback neither leaves the host; elsewhere, say so.
		if RequireServerVerification && strings.HasPrefix(strings.ToLower(e.BaseURL), "http://") && !loopbackURL(e.BaseURL) {
			warn = fmt.Sprintf("%s: plain http to %s: the daemon is not verified, and an API key goes in clear; use https with pins: (tdns-ncli config add writes them)",
				e.Name, e.BaseURL)
		}
	}
	// The local socket has no TLS, and the client sends no credentials on
	// it (NewClientWithOptions): a leftover rootca: or authmethod:
	// certificate must not stop the entry before it is built.
	socket := strings.HasPrefix(e.BaseURL, "unix://")
	switch {
	case socket:
	case len(o.Pins) > 0:
		// tlsauth: pin. The pins replace the roots, and the client ignores
		// rootca, so a rootca: line left over from before must not be read
		// (a file that is gone would fail an entry that verifies fine).
	case o.RootCA == "", o.RootCA == "insecure", o.RootCA == "tlsa", o.RootCA == "system":
	default:
		// NewClientWithOptions exits the process on a CA file it cannot read
		// -- and a directory passes a stat -- which would take every other
		// entry down with this one (config list --check stops printing).
		// Read and parse it here, return the error instead, and hand the
		// client the parsed roots so it does not read the file a second time.
		data, err := os.ReadFile(o.RootCA)
		if err != nil {
			return nil, "", fmt.Errorf("entry %q: rootca: %w", e.Name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, "", fmt.Errorf("entry %q: rootca: %s holds no PEM certificate", e.Name, o.RootCA)
		}
		o.RootCAs = pool
	}
	if e.AuthMethod == "certificate" && !socket {
		cert, err := loadClientCert(cc)
		if err != nil {
			return nil, "", fmt.Errorf("entry %q has authmethod: certificate, but %w (tdns-ncli client init makes one)", e.Name, err)
		}
		o.ClientCert = cert
	}
	// A socket that answered for another daemon: said, after any warning
	// about the route taken instead.
	if sockNote != "" {
		if warn != "" {
			warn += "; "
		}
		warn += sockNote
	}
	return tdns.NewClientWithOptions(e.Name, e.BaseURL, o), warn, nil
}

func getClientKeyFromParent(role string) string {
	return roleToClientKey[role]
}

// GetClientKeyFromParent is the exported form of getClientKeyFromParent
// for cross-package CLI consumers (e.g. tdns-mp/v2/cli's JOSE keys
// commands) that need to resolve a role name to its clientKey.
func GetClientKeyFromParent(role string) string {
	return getClientKeyFromParent(role)
}

// getApiDetailsByClientKey returns the ApiDetails entry whose Name
// matches clientKey, or nil if no such entry exists. Data comes from
// the CliConf handed to InitApiClients — no viper reach-through.
func getApiDetailsByClientKey(clientKey string) *ApiDetails {
	if apiConfig == nil {
		return nil
	}
	for i := range apiConfig.ApiServers {
		if apiConfig.ApiServers[i].Name == clientKey {
			return &apiConfig.ApiServers[i]
		}
	}
	return nil
}

// GetApiDetailsByClientKey is the exported form of
// getApiDetailsByClientKey for cross-package CLI consumers.
func GetApiDetailsByClientKey(clientKey string) *ApiDetails {
	return getApiDetailsByClientKey(clientKey)
}

// refusalError is a daemon's plain-text refusal (tdns.ApiRefusal: the access
// check's 403, or an application client refused something it may not do),
// for the senders to return. printDaemonError finds the ApiRefusal in it;
// its text is worded for a caller that prints it after its own "Error from
// <daemon>: " (ApiRefusal.Report). ok is false for any other error, which
// the caller reports as before.
func refusalError(err error) (error, bool) {
	var ref *tdns.ApiRefusal
	if !errors.As(err, &ref) {
		return err, false
	}
	return refusal{ref}, true
}

type refusal struct{ ref *tdns.ApiRefusal }

func (r refusal) Error() string { return r.ref.Report() }
func (r refusal) Unwrap() error { return r.ref }

// daemonError is the error message a daemon's JSON reply carried (Error
// set, ErrorMsg), as a sender returns it. Error() is lead and the message,
// worded as the sender always worded it; printDaemonError prints msg.
type daemonError struct {
	lead, msg string
}

func (e *daemonError) Error() string { return e.lead + e.msg }

// printDaemonError prints a command's failed exchange with the daemon called
// daemon (the API client's name), once, verdict first, as every command
// that an application client can be refused on prints it
// (daemonErrorText). The caller exits as it did before.
func printDaemonError(daemon string, err error) {
	fmt.Println(daemonErrorText(daemon, err))
}

// printDaemonErrorMsg is printDaemonError for a reply's ErrorMsg.
func printDaemonErrorMsg(daemon, msg string) {
	printDaemonError(daemon, &daemonError{msg: msg})
}

// daemonErrorText is err as printDaemonError prints it: the verdict, which
// names the daemon, on a line of its own, then the daemon's words, indented
// two spaces and wrapped within 72 characters, each of its own lines kept
// (tdns.ErrorReport):
//
//	Refused by tdns-auth (HTTP 403):     a plain-text refusal (ApiRefusal)
//	Error from tdns-auth (HTTP 500):     another plain-text error
//	Error from tdns-auth:                a JSON reply's ErrorMsg (daemonError)
//	Error talking to tdns-auth:          anything else: no reply, or not one
//	                                     this CLI could read
func daemonErrorText(daemon string, err error) string {
	if daemon == "" {
		daemon = "the daemon"
	}
	var ref *tdns.ApiRefusal
	if errors.As(err, &ref) {
		return ref.ReportFrom(daemon)
	}
	var de *daemonError
	if errors.As(err, &de) {
		msg := de.msg
		if strings.TrimSpace(msg) == "" {
			msg = "(no message)"
		}
		return tdns.ErrorReport("Error from "+daemon+":", msg)
	}
	return tdns.ErrorReport("Error talking to "+daemon+":", err.Error())
}
