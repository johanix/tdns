/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"log"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	AppName        string
	AppVersion     string
	AppMode        string
	ServerBootTime time.Time
	Service        ServiceConf
	DnsEngine      DnsEngineConf
	Apiserver      ApiserverConf
	DnssecPolicies map[string]DnssecPolicyConf
	Zones          map[string]ZoneConf
	Db             DbConf
	Registrars     map[string][]string
	Log            struct {
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

	var configsections = make(map[string]interface{}, 5)

	// Cannot validate a map[string]foobar, must validate the individual foobars:
	for zname, val := range config.Zones {
		configsections["zone:"+zname] = val
	}

	if err := ValidateBySection(config, configsections, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateBySection(config *Config, configsections map[string]interface{}, cfgfile string) error {
	validate := validator.New()

	for k, data := range configsections {
		log.Printf("%s: Validating config for %s section\n", config.Service.Name, k)
		if err := validate.Struct(data); err != nil {
			log.Fatalf("Config %s, section %s: missing required attributes:\n%v\n",
				cfgfile, k, err)
		}
	}
	return nil
}
