/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * API client configuration, role → clientKey registry, and the
 * shared InitApiClients helper used by each CLI binary's root.go.
 */
package cli

import (
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

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

	// An instance entry named like another client is left out: building it
	// would replace that client (see clientEntries). The wiring has already
	// warned about it, and refused it its command tree.
	servers := clientEntries(c.ApiServers, builtinRoles())

	if tdns.Globals.Debug {
		fmt.Printf("InitApiClients: setting up API clients for:")
	}
	for _, val := range servers {
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
			log.Fatalf("Unknown role: %s", role)
		}
		return nil, fmt.Errorf("unknown role: %s", role)
	}

	client := tdns.Globals.ApiClients[clientKey]
	if client == nil {
		if err := apiClientErrors[clientKey]; err != nil {
			if dieOnError {
				log.Fatalf("%v", err)
			}
			return nil, err
		}
		if dieOnError {
			keys := make([]string, 0, len(tdns.Globals.ApiClients))
			for k := range tdns.Globals.ApiClients {
				keys = append(keys, k)
			}
			log.Fatalf("No API client found for %s (have clients for: %v)", clientKey, keys)
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

// newApiClientFor builds the client for one apiservers entry: how it verifies
// the daemon (pins, roots, or, said out loud, nothing) and how it
// authenticates itself (key, certificate, or nothing on the local socket).
// The warning, if any, is for the operator when the entry is used.
func newApiClientFor(e ApiDetails, cc CliClientConf) (*tdns.ApiClient, string, error) {
	o := tdns.ClientOptions{ApiKey: e.ApiKey, AuthMethod: e.AuthMethod, RootCA: e.RootCA}
	warn := ""
	if strings.HasPrefix(strings.ToLower(e.BaseURL), "https://") {
		switch strings.ToLower(e.TLSAuth) {
		case "pin":
			if len(e.Pins) == 0 {
				return nil, "", fmt.Errorf("entry %q has tlsauth: pin but no pins:", e.Name)
			}
			o.Pins = e.Pins
		case "pkix":
			if o.RootCA == "" {
				o.RootCA = "system"
			}
		case "":
			if o.RootCA == "" {
				if RequireServerVerification {
					return nil, "", fmt.Errorf("entry %q (%s) does not verify the daemon: give it tlsauth: pin and the daemon's pins: (tdns-ncli config add writes them), or a rootca:, or say rootca: insecure",
						e.Name, e.BaseURL)
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
	switch o.RootCA {
	case "", "insecure", "tlsa", "system":
		// "" only with pins, which replace the roots.
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
	if e.AuthMethod == "certificate" {
		cert, err := loadClientCert(cc)
		if err != nil {
			return nil, "", fmt.Errorf("entry %q has authmethod: certificate, but %w (tdns-ncli client init makes one)", e.Name, err)
		}
		o.ClientCert = cert
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
