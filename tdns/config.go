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
	AppName          string
	AppVersion       string
	AppMode          string
	AppDate          string
	ServerBootTime   time.Time
	ServerConfigTime time.Time
	Service          ServiceConf
	DnsEngine        DnsEngineConf
	Apiserver        ApiserverConf
	DnssecPolicies   map[string]DnssecPolicyConf
	MultiSigner      map[string]MultiSignerConf `yaml:"multisigner"`
	Zones            map[string]ZoneConf
	Db               DbConf
	Registrars       map[string][]string
	Log              struct {
		File string `validate:"required"`
	}
	Internal InternalConf
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
	Address string `validate:"required"`
	Key     string `validate:"required"`
}

type DbConf struct {
	File string // `validate:"required"`
}

type InternalConf struct {
	KeyDB           *KeyDB
	DnssecPolicies  map[string]DnssecPolicy
	APIStopCh       chan struct{}
	RefreshZoneCh   chan ZoneRefresher
	BumpZoneCh      chan BumperData
	ValidatorCh     chan ValidatorRequest
	ScannerQ        chan ScanRequest
	UpdateQ         chan UpdateRequest
	UpdateTrustQ    chan UpdateTrustRequest
	DnsUpdateQ      chan DnsUpdateRequest
	DnsNotifyQ      chan DnsNotifyRequest
	DelegationSyncQ chan DelegationSyncRequest
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
		log.Printf("%s: Validating config for %s section\n", strings.ToUpper(config.AppName), k)
		if err := validate.Struct(data); err != nil {
			log.Fatalf("%s: Config %s, section %s: missing required attributes:\n%v\n",
				strings.ToUpper(config.AppName), cfgfile, k, err)
		}
	}
	return nil
}

func (conf *Config) ReloadConfig() (string, error) {
	err := ParseConfig(conf, true) // true: reload, not initial parsing
	if err != nil {
		log.Printf("Error parsing config: %v", err)
	}
	conf.ServerConfigTime = time.Now()
	return "Config reloaded.", err
}

func (conf *Config) ReloadZoneConfig() (string, error) {
	prezones := Zones.Keys()
	log.Printf("ReloadZones: zones prior to reloading: %v", prezones)
	zonelist, err := ParseZones(conf, conf.Internal.RefreshZoneCh, true) // true: reload, not initial parsing
	if err != nil {
		log.Printf("ReloadZoneConfig: Error parsing zones: %v", err)
	}

	for _, zname := range prezones {
		if !slices.Contains(zonelist, zname) {
			log.Printf("ReloadZoneConfig: Zone %s no longer in config. Removing from zone list.", zname)
			Zones.Remove(zname)
		}
	}

	log.Printf("ReloadZones: zones after reloading: %v", zonelist)
	conf.ServerConfigTime = time.Now()
	return fmt.Sprintf("Zones reloaded. Before: %v, After: %v", prezones, zonelist), err
}
