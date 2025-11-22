/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package core

import (
	"fmt"
	"net"
	"net/url"
)

type GlobalStuff struct {
	IMR         string
	Verbose     bool
	Debug       bool
	Zonename    string
	// AgentId     AgentId
	ParentZone  string
	//Sig0Keyfile string
	//Api         *ApiClient
	//ApiClients  map[string]*ApiClient // tdns-cli has multiple clients
	//PingCount   int
	Slurp       bool
	Algorithm   string
	Rrtype      string
	ShowHeaders bool // -H in various CLI commands
	BaseUri     string
	Port        uint16
	Address     string
	// App         AppDetails
	// ServerSVCB  *dns.SVCB // ALPN for DoH/DoQ
	// TsigKeys    map[string]*TsigDetails
}

var Globals = GlobalStuff{
	//	IMR:     "8.8.8.8:53",
	Verbose:    false,
	Debug:      false,
	// ApiClients: map[string]*ApiClient{},
}

func (gs *GlobalStuff) Validate() error {
	if gs.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", gs.Port)
	}
	if gs.Address != "" {
		if net.ParseIP(gs.Address) == nil {
			return fmt.Errorf("invalid address format: %s", gs.Address)
		}
	}
	if gs.BaseUri != "" {
		if _, err := url.Parse(gs.BaseUri); err != nil {
			return fmt.Errorf("invalid base URI: %s", gs.BaseUri)
		}
	}
	return nil
}
