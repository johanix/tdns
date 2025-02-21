/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"slices"
	"time"
)

type Config struct {
	App            AppDetails
	Service        ServiceConf
	DnsEngine      DnsEngineConf
	ApiServer      ApiServerConf
	DnssecPolicies map[string]DnssecPolicyConf
	MultiSigner    map[string]MultiSignerConf `yaml:"multisigner"`
	// Zones          map[string]ZoneConf
	Zones      []ZoneConf          `yaml:"zones"`
	Templates  map[string]ZoneConf // Templates are reusable zone configurations
	Db         DbConf
	Registrars map[string][]string
	Log        struct {
		File string `validate:"required"`
	}
	Internal InternalConf
}

type AppDetails struct {
	Name             string
	Version          string
	Mode             string
	Date             string
	ServerBootTime   time.Time
	ServerConfigTime time.Time
}

type ServiceConf struct {
	Name    string `validate:"required"`
	Debug   *bool
	Verbose *bool
}

type DnsEngineConf struct {
	Addresses []string `validate:"required"`
}

type ApiServerConf struct {
	Addresses []string `validate:"required"`
	ApiKey    string   `validate:"required"`
	CertFile  string   `validate:"required,file,certkey"`
	KeyFile   string   `validate:"required,file"`
	UseTLS    bool
	Server    ApiServerAppConf
	Agent     ApiServerAppConf
	MSA       ApiServerAppConf
	Combiner  ApiServerAppConf
}

type ApiServerAppConf struct {
	Addresses []string
	ApiKey    string
}

type DbConf struct {
	File string // `validate:"required"`
}

type InternalConf struct {
	CfgFile         string //
	ZonesCfgFile    string //
	KeyDB           *KeyDB
	DnssecPolicies  map[string]DnssecPolicy
	StopCh          chan struct{}
	APIStopCh       chan struct{}
	RefreshZoneCh   chan ZoneRefresher
	BumpZoneCh      chan BumperData
	ValidatorCh     chan ValidatorRequest
	ScannerQ        chan ScanRequest
	UpdateQ         chan UpdateRequest
	DeferredUpdateQ chan DeferredUpdate
	DnsUpdateQ      chan DnsUpdateRequest
	DnsNotifyQ      chan DnsNotifyRequest
	DelegationSyncQ chan DelegationSyncRequest
	MusicSyncQ      chan MusicSyncRequest
	NotifyQ         chan NotifyRequest
	AuthQueryQ      chan AuthQueryRequest
	ResignQ         chan *ZoneData // the names of zones that should be kept re-signed should be sent into this channel
}

func (conf *Config) ReloadConfig() (string, error) {
	err := conf.ParseConfig(true) // true: reload, not initial parsing
	if err != nil {
		log.Printf("Error parsing config: %v", err)
	}
	conf.App.ServerConfigTime = time.Now()
	return "Config reloaded.", err
}

func (conf *Config) ReloadZoneConfig() (string, error) {
	prezones := Zones.Keys()
	log.Printf("ReloadZones: zones prior to reloading: %v", prezones)
	// XXX: This is wrong. We must get the zones config file from outside (to enamble things like MUSIC to use a different config file)
	zonelist, err := conf.ParseZones(true) // true: reload, not initial parsing
	if err != nil {
		log.Printf("ReloadZoneConfig: Error parsing zones: %v", err)
	}

	for _, zname := range prezones {
		if !slices.Contains(zonelist, zname) {
			zd, exists := Zones.Get(zname)
			if !exists {
				log.Printf("ReloadZoneConfig: Zone %s not in config and also not in zone list.", zname)
			}
			if zd.Options[OptAutomaticZone] {
				log.Printf("ReloadZoneConfig: Zone %s is an automatic zone. Not removing from zone list.", zname)
				continue
			}
			log.Printf("ReloadZoneConfig: Zone %s no longer in config. Removing from zone list.", zname)
			Zones.Remove(zname)
		}
	}

	log.Printf("ReloadZones: zones after reloading: %v", zonelist)
	conf.App.ServerConfigTime = time.Now()
	return fmt.Sprintf("Zones reloaded. Before: %v, After: %v", prezones, zonelist), err
}
