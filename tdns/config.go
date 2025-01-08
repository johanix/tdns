/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	App            AppDetails
	Service        ServiceConf
	DnsEngine      DnsEngineConf
	Apiserver      ApiserverConf
	DnssecPolicies map[string]DnssecPolicyConf
	MultiSigner    map[string]MultiSignerConf `yaml:"multisigner"`
	Zones          map[string]ZoneConf
	Db             DbConf
	Registrars     map[string][]string
	Log            struct {
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

type ApiserverConf struct {
	Addresses []string `validate:"required"`
	ApiKey    string   `validate:"required"`
	CertFile  string   `validate:"required,file"`
	KeyFile   string   `validate:"required,file"`
	UseTLS    bool
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
	// ResignQ         chan ZoneRefresher // the names of zones that should be kept re-signed should be sent into this channel
	ResignQ chan *ZoneData // the names of zones that should be kept re-signed should be sent into this channel
}

func ValidateConfig(v *viper.Viper, cfgfile string) error {
	var config Config

	if v == nil {
		if err := viper.Unmarshal(&config); err != nil {
			log.Fatalf("ValidateConfig: Unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&config); err != nil {
			log.Fatalf("ValidateConfig: Unmarshal error: %v", err)
		}
	}

	var configsections = make(map[string]interface{}, 5)

	configsections["log"] = config.Log
	configsections["service"] = config.Service
	configsections["db"] = config.Db
	configsections["apiserver"] = config.Apiserver
	configsections["dnsengine"] = config.DnsEngine

	if err := ValidateBySection(&config, configsections, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateZones(c *Config, cfgfile string) error {
	config := c

	var zones = make(map[string]interface{}, 5)

	// Cannot validate a map[string]foobar, must validate the individual foobars:
	for zname, val := range config.Zones {
		zones["zone:"+zname] = val
	}

	if err := ValidateBySection(config, zones, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateBySection(config *Config, configsections map[string]interface{}, cfgfile string) error {
	validate := validator.New()

	for k, data := range configsections {
		log.Printf("%s: Validating config for %s section\n", strings.ToUpper(config.App.Name), k)
		if err := validate.Struct(data); err != nil {
			log.Fatalf("%s: Config %s, section %s: missing required attributes:\n%v\n",
				strings.ToUpper(config.App.Name), cfgfile, k, err)
		}
	}
	return nil
}

func (conf *Config) ReloadConfig() (string, error) {
	err := ParseConfig(conf, true) // true: reload, not initial parsing
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
	zonelist, err := ParseZones(conf, conf.Internal.RefreshZoneCh, true) // true: reload, not initial parsing
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
