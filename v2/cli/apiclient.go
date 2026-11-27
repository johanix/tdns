/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * API client configuration, role → clientKey registry, and the
 * shared InitApiClients helper used by each CLI binary's root.go.
 */
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// ApiDetails is one entry in the apiservers list of a CLI config file.
type ApiDetails struct {
	// Name is the entry's name, and the command word that reaches it: the
	// first daemon of a role is named after the role (auth, imr, agent),
	// any further one after its config file or --name (auth2).
	Name string `validate:"required" yaml:"name"`
	// BaseURL is the daemon's TCP API (https://host:port/api/v1), or "" for
	// an entry that reaches its daemon only through the local admin socket
	// its config-file: names.
	BaseURL string `yaml:"baseurl"`
	Command string `yaml:"command,omitempty"`
	// Role is the daemon type: auth, agent, imr. An entry named after its
	// role is that role's entry, reached through the role's command tree
	// (tdns-ncli auth ...). Any other name with a role: gets a command tree
	// of its own (tdns-ncli auth2 ...). An entry named after its role may
	// leave role: out.
	//
	// mapstructure as well as yaml, for the same reason ConfigFile below
	// carries one: the CLI roots decode with viper.Unmarshal, which never
	// consults yaml tags.
	Role string `yaml:"role,omitempty" mapstructure:"role"`
	// mapstructure as well as yaml: the CLI roots decode this file with
	// viper.Unmarshal, which never consults yaml tags. "config-file" does not
	// match the field name, so without this tag it decodes to "" in silence.
	ConfigFile string `yaml:"config-file,omitempty" mapstructure:"config-file"`
	// Pins are the SPKI SHA-256 pins of the daemon's API certificate: its
	// current one, and the next one during a change. Over TCP the CLI
	// verifies the daemon by them and nothing else, and presents the client
	// certificate (CliConf.Client).
	Pins []string `yaml:"pins,omitempty" mapstructure:"pins"`
}

// CliConf is the parsed CLI config. Each CLI binary's root.go populates
// one of these (currently via viper + Unmarshal) and hands it to
// InitApiClients.
type CliConf struct {
	ApiServers []ApiDetails
	Keys       tdns.KeyConf
	// Client names the operator's own certificate, presented on every TCP
	// connection. Unset, the default location is used
	// (DefaultClientCertPaths).
	Client CliClientConf
	// File is the CLI config this run read, named in the commands a
	// refusal advises. Set by the root, never from the config itself.
	File string `mapstructure:"-"`
}

// CliClientConf is the CLI config's client: block.
type CliClientConf struct {
	Cert string `yaml:"cert" mapstructure:"cert"`
	Key  string `yaml:"key" mapstructure:"key"`
}

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

// roleToClientKey maps Cobra-tree role names (e.g. "auth", "signer") to
// the clientKey used to look up the ApiClient in tdns.Globals.ApiClients:
// the name of the role's entry, which is the role itself (auth -> auth).
//
// Each CLI package owns the roles for the daemons it interacts with
// and registers them via RegisterRole in its own init(). Downstream
// packages (e.g. tdns-mp/v2/cli) can override entries set by upstream
// packages; the per-binary effective map is the union of whichever
// cli packages the binary imports.
var roleToClientKey = map[string]string{}

// RegisterRole associates role with clientKey. Later calls for the
// same role override earlier ones — this is how a downstream package
// points a role at its own daemon's entry.
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
	// An entry's name is its command word (design 2026-11-26, change 3).
	RegisterRole("auth", "auth")
	RegisterRole("imr", "imr")
	RegisterRole("agent", "agent")
	RegisterOldEntryName("tdns-auth", "auth")
	RegisterOldEntryName("tdns-imr", "imr")
	RegisterOldEntryName("tdns-agent", "agent")
}

// oldEntryNames maps an entry name of the past (the program's name, before
// an entry's name was its command word) to the name it has now. An entry
// with an old name is not used: every command that would need it says to
// rename it (config update <old> --rename <new>), and config check fails on
// it. There is no compatibility.
var oldEntryNames = map[string]string{}

// RegisterOldEntryName records that entries once named old are now named
// new. As RegisterRole, only from init() or before Execute.
func RegisterOldEntryName(old, new string) {
	oldEntryNames[old] = new
}

// renamedTo is the name entry e must have now, when its name is an old one
// (oldEntryNames), else "".
func renamedTo(e ApiDetails) string {
	n := oldEntryNames[e.Name]
	if n == "" || e.Role == "" {
		return n
	}
	// An explicit role decides: tdns-auth with role: agent is the agent's
	// entry under an old name, so it becomes agent (which checkRename takes).
	if key := roleToClientKey[e.Role]; key != "" {
		return key
	}
	return n
}

// apiConfig is the most recent CliConf passed to InitApiClients, with the
// entries that got a client. Used by getApiDetailsByClientKey to look up
// per-server config (command path for "daemon start", config-file for
// "keys generate", etc.) without reaching back into viper. allEntries are
// all of its entries, for the refusal that names an entry with an old name.
var apiConfig *CliConf
var allEntries []ApiDetails

// InitApiClients creates a tdns.ApiClient for every entry in
// c.ApiServers and stashes them in tdns.Globals.ApiClients. Also
// parses TSIG keys from c.Keys and records c for later config
// lookups.
//
// Unlike the previous per-binary implementations, this does *not*
// require a client for any one role. Callers resolve their ApiClient
// via GetApiClient(role, …) and get a use-time failure if the role
// they need isn't configured.
func InitApiClients(c *CliConf) error {
	if c == nil {
		return fmt.Errorf("InitApiClients: nil CliConf")
	}

	// Only the instance entries the wiring gave a command tree get a client
	// (see clientEntries); the wiring has already warned about the others.
	servers := clientEntries(c.ApiServers)

	// The config lookups by client name (config-file:, the daemon command)
	// must find the entry whose client was built, not a left-out instance
	// that happens to come first. Set before the clients are built: a
	// refusal made while building one names this run's CLI config.
	cc := *c
	cc.ApiServers = servers
	apiConfig = &cc
	allEntries = append([]ApiDetails(nil), c.ApiServers...)

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
	// (tdns-es, tdns-nm, tdns/music). Point it at the auth client
	// when available so those keep working. Nothing inside tdns/v2/cli
	// reads it any more; the shim can go away once the external
	// consumers migrate to GetApiClient(role, …).
	if authClient, ok := tdns.Globals.ApiClients[roleToClientKey["auth"]]; ok {
		tdns.Globals.Api = authClient
	}

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
		err := missingEntry(role, clientKey)
		if dieOnError {
			dieOn(err)
		}
		return nil, err
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
	if name == roleToClientKey["auth"] {
		tdns.Globals.Api = ac
	}
}

// missingEntry is the refusal for a role whose entry (clientKey) the CLI
// config does not have: an entry with the old name says to rename it, else
// config add names the role's default daemon config.
func missingEntry(role, clientKey string) error {
	cfg := DefaultCliConfigFile
	if apiConfig != nil && apiConfig.File != "" {
		cfg = apiConfig.File
	}
	for _, e := range allEntries {
		if renamedTo(e) == clientKey {
			return clientRefusal{entry: clientKey,
				why: fmt.Sprintf("the CLI config %s names it %q, the old\nname; an entry's name is now its command word", cfg, e.Name),
				fix: ncliFor(cfg) + " config update " + shellQuote(e.Name) + " --rename " + shellQuote(clientKey)}
		}
	}
	return clientRefusal{entry: clientKey,
		why: fmt.Sprintf("the CLI config %s has no entry\nnamed %q", cfg, clientKey),
		fix: ncliFor(cfg) + " config add " + shellQuote(defaultDaemonConfig(role))}
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

// tcpRefusal is r, unless e's TCP address is what keeps it off this host's
// admin socket (usableDaemonSocket uses the socket only for an address its
// daemon config lists): then that is why, and config update --cert is the
// fix. It takes the daemon's own address and pins, and makes the client
// certificate if there is none.
func tcpRefusal(e ApiDetails, r clientRefusal) clientRefusal {
	if !socketCandidate(e) || e.BaseURL == "" {
		return r
	}
	sock, addrs := daemonSocket(e.ConfigFile)
	hp := hostPort(e.BaseURL)
	if sock == "" || len(addrs) == 0 || hp == "" || slices.Contains(addrs, hp) {
		return r
	}
	return clientRefusal{entry: e.Name,
		why: fmt.Sprintf("its address %s is not one %s listens on (%s), so this host's admin socket is not used for it",
			hp, e.ConfigFile, strings.Join(addrs, ", ")),
		fix: updateFix(e, "--cert")}
}

// clientRefusal is an entry tdns-ncli will not connect through: why, and the
// command that fixes it. GetApiClient prints it as a refusal, the command on
// a line of its own; Error() is the one-line form, for config list.
type clientRefusal struct {
	entry, why, fix string
}

func (r clientRefusal) Error() string {
	return fmt.Sprintf("not connecting to %s: %s; fix: %s", r.entry, strings.ReplaceAll(r.why, "\n", " "), r.fix)
}

// ncliForThisRun is the tdns-ncli command for the CLI config this run read,
// whichever tool is running: a tdns-cli or tdns-debug run gets tdns-ncli
// with --config <its file>, which tdns-ncli edits as well (#1205).
func ncliForThisRun() string {
	cfg := ""
	if apiConfig != nil {
		cfg = apiConfig.File
	}
	return ncliFor(cfg)
}

// updateFix is the config update command that fixes entry e, in the CLI
// config this run read: flag is --cert (your certificate enrolled, the
// daemon's address and pins taken) or --repin (its new pins taken). An entry
// without config-file: needs the daemon config named: the one it most
// likely is (likelyDaemonConfig), so that the command runs as printed.
func updateFix(e ApiDetails, flag string) string {
	fix := ncliForThisRun() + " config update " + shellQuote(e.Name) + " " + flag
	if e.ConfigFile == "" {
		fix += " --daemon-config " + shellQuote(likelyDaemonConfig(e))
	}
	return fix
}

// likelyDaemonConfig is the daemon config of an entry that names none, as a
// command printed for the operator guesses it: a role's entry's default
// (/etc/tdns/tdns-auth.yaml), else one named after the entry, as config add
// names an instance after its file (auth2: /etc/tdns/tdns-auth2.yaml).
func likelyDaemonConfig(e ApiDetails) string {
	if role := roleEntryOf(e, builtinRoles()); role != "" {
		return defaultDaemonConfig(role)
	}
	if n := renamedTo(e); n != "" {
		return defaultDaemonConfig(entryRole(e))
	}
	return filepath.Join(filepath.Dir(tdns.DefaultAuthCfgFile), "tdns-"+e.Name+".yaml")
}

// pinRefusal refuses entry e for want of a pin: config update --cert gives
// it the pins of the certificate its daemon serves, with the client
// certificate enrolled.
func pinRefusal(e ApiDetails, why string) clientRefusal {
	return clientRefusal{entry: e.Name, why: why, fix: updateFix(e, "--cert")}
}

// dieOn ends the process on err, which GetApiClient could not get past. A
// refusal says so plainly, with the command that fixes it on a line of its
// own; anything else is an error. Neither goes through the log: it is the
// answer to the command, not a log line.
func dieOn(err error) {
	var r clientRefusal
	if errors.As(err, &r) {
		lead := "Error: not connecting to " + r.entry + ": " + strings.ReplaceAll(r.why, "\n", " ") + "."
		fmt.Fprintf(os.Stderr, "%s\nFix:\n%s\n", strings.Join(wrapText(lead, 72), "\n"), commandLines(r.fix, 3))
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
	probe := tdns.NewClientWithOptions(e.Name, "unix://"+sock, tdns.ClientOptions{})
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

// newApiClientFor builds the client for one apiservers entry: over the
// daemon's local admin socket when the entry names the daemon's config and
// the socket answers (admin, no TLS), else over TCP with the daemon's pins
// and the client certificate. The warning, if any, is for the operator when
// the entry is used.
func newApiClientFor(e ApiDetails, cc CliClientConf) (*tdns.ApiClient, string, error) {
	// The client recognises the socket scheme only as "unix://"; spelled
	// any other way it would be taken for TCP. The scheme is
	// case-insensitive, the path is not.
	if isUnixURL(e.BaseURL) {
		e.BaseURL = "unix://" + e.BaseURL[7:]
	}
	// The daemon's local admin socket path is in the daemon config
	// (tdns.ApiSocketPath), not in the CLI config, so the two cannot
	// disagree.
	sock, sockNote := usableDaemonSocket(e)
	return buildApiClient(e, cc, sock, sockNote)
}

// buildApiClient builds e's client, over sock when that is set (the daemon's
// local admin socket, checked by usableDaemonSocket), else over e's own
// baseurl: https, with the entry's pins and the client certificate. sockNote
// says why a socket that answered was not used.
func buildApiClient(e ApiDetails, cc CliClientConf, sock, sockNote string) (*tdns.ApiClient, string, error) {
	if isUnixURL(e.BaseURL) {
		e.BaseURL = "unix://" + e.BaseURL[7:]
	}
	if sock != "" {
		if tdns.Globals.Debug {
			fmt.Printf("%s: using the daemon's local admin socket %s\n", e.Name, sock)
		}
		e.BaseURL = "unix://" + sock
	}
	switch {
	case e.BaseURL == "" && sockNote != "":
		return nil, "", errors.New(sockNote)
	case e.BaseURL == "":
		return nil, "", fmt.Errorf("entry %q has no baseurl, and the local admin socket of its daemon\n(config-file: %s) cannot be used: only root can open it, and\nthe daemon must be running", e.Name, e.ConfigFile)
	case ForceTCP && strings.HasPrefix(e.BaseURL, "unix://"):
		// An entry written as a socket entry has no TCP address to use.
		return nil, "", fmt.Errorf("entry %q is a local socket entry (baseurl %s), so it has no TCP address for --tcp", e.Name, e.BaseURL)
	}
	var o tdns.ClientOptions
	switch lower := strings.ToLower(e.BaseURL); {
	case strings.HasPrefix(lower, "unix://"):
		// Checked above, and on every request too: the daemon refuses one
		// meant for another config, so a daemon that took the socket after
		// the check cannot run the command.
		if sock != "" {
			o.ExpectConfigFile = e.ConfigFile
		}
	case strings.HasPrefix(lower, "https://"):
		if len(e.Pins) == 0 {
			return nil, "", tcpRefusal(e, pinRefusal(e, "its entry has no pin of the daemon's certificate,\nso the daemon cannot be verified"))
		}
		o.Pins = e.Pins
		o.PinFix = updateFix(e, "--repin")
		cert, err := loadClientCert(cc)
		if err != nil {
			return nil, "", tcpRefusal(e, clientRefusal{entry: e.Name, why: err.Error(), fix: ncliForThisRun() + " client init"})
		}
		o.ClientCert = cert
	case strings.HasPrefix(lower, "http://"):
		return nil, "", tcpRefusal(e, clientRefusal{entry: e.Name,
			why: fmt.Sprintf("its baseurl %s is plain http, and the\nmanagement API is TLS only", e.BaseURL),
			fix: updateFix(e, "--cert")})
	default:
		return nil, "", fmt.Errorf("entry %q: baseurl %s is neither https:// nor unix://", e.Name, e.BaseURL)
	}
	return tdns.NewClientWithOptions(e.Name, e.BaseURL, o), sockNote, nil
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
