/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * API client configuration, role → clientKey registry, and the
 * shared InitApiClients helper used by each CLI binary's root.go.
 */
package cli

import (
	"fmt"
	"log"

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
	ConfigFile string `yaml:"config_file,omitempty"`
}

// CliConf is the parsed CLI config. Each CLI binary's root.go populates
// one of these (currently via viper + Unmarshal) and hands it to
// InitApiClients.
type CliConf struct {
	ApiServers []ApiDetails
	Keys       tdns.KeyConf
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
// Safe only from init() (map is not concurrency-safe; init ordering
// inside a package is deterministic, across imported packages it is
// topological and thus deterministic for override purposes).
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
// path for "daemon start", config_file for "keys generate", etc.)
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

	if tdns.Globals.Debug {
		fmt.Printf("InitApiClients: setting up API clients for:")
	}
	for _, val := range c.ApiServers {
		rootCA := val.RootCA
		if rootCA == "" {
			rootCA = "insecure" // default: skip TLS verification
		}
		ac := tdns.NewClient(val.Name, val.BaseURL, val.ApiKey, val.AuthMethod, rootCA)
		if ac == nil {
			return fmt.Errorf("InitApiClients: failed to setup API client for %q (baseurl: %s, rootca: %s)",
				val.Name, val.BaseURL, rootCA)
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

	apiConfig = c

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
		if dieOnError {
			keys := make([]string, 0, len(tdns.Globals.ApiClients))
			for k := range tdns.Globals.ApiClients {
				keys = append(keys, k)
			}
			log.Fatalf("No API client found for %s (have clients for: %v)", clientKey, keys)
		}
		return nil, fmt.Errorf("no API client found for %s", clientKey)
	}

	if tdns.Globals.Debug {
		fmt.Printf("Using API client for %q:\nBaseUrl: %s\n", clientKey, client.BaseUrl)
	}
	return client, nil
}

func getClientKeyFromParent(role string) string {
	return roleToClientKey[role]
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
