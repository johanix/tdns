/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	core "github.com/johanix/tdns/v1.0/tdns/core"
	"github.com/miekg/dns"
)

type MusicSyncRequest struct {
	Command         string
	ZoneName        string
	ZoneData        *ZoneData
	OldDnskeys      *core.RRset
	NewDnskeys      *core.RRset
	MusicSyncStatus *MusicSyncStatus
	Response        chan MusicSyncStatus // used for API-based requests
}

type MusicSyncStatus struct {
	ZoneName       string
	MsignerAdds    []dns.RR
	MsignerRemoves []dns.RR
	DnskeyAdds     []dns.RR
	DnskeyRemoves  []dns.RR
	Msg            string
	Error          bool
	ErrorMsg       string
	Status         bool
	// Sidecars       map[string]*Sidecar
}

type MultiSignerConf struct {
	Name       string
	Controller MultiSignerController
}

type MultiSignerController struct {
	Name   string
	Notify MSCNotifyConf
	API    MSCAPIConf
}

type MSCNotifyConf struct {
	Addresses []string `validate:"required"` // XXX: must not be in addr:port format
	Port      string   `validate:"required"`
	Targets   []string
}

type MSCAPIConf struct {
	BaseURL    string `validate:"required,url"`
	ApiKey     string `validate:"required_if=AuthMethod apikey"`
	AuthMethod string `validate:"required,oneof=none apikey"`
	UseTLS     bool   `validate:"required"`
}
