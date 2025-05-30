/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"net"
	"net/url"

	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
)

type GlobalStuff struct {
	IMR         string
	Verbose     bool
	Debug       bool
	Zonename    string
	ParentZone  string
	Sig0Keyfile string
	Api         *ApiClient
	ApiClients  map[string]*ApiClient // tdns-cli has multiple clients
	PingCount   int
	Slurp       bool
	Algorithm   string
	Rrtype      string
	ShowHeaders bool // -H in various CLI commands
	BaseUri     string
	Port        uint16
	Address     string
	App         AppDetails
	ServerALPN  *dns.SVCB // ALPN for DoH/DoQ
}

var Globals = GlobalStuff{
	//	IMR:     "8.8.8.8:53",
	Verbose:    false,
	Debug:      false,
	ApiClients: map[string]*ApiClient{},
}

var Zones = cmap.New[*ZoneData]()

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
