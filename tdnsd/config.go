/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"time"

	// "github.com/orcaman/concurrent-map/v2"
	"github.com/go-playground/validator/v10"
	"github.com/johanix/tdns/tdns"
	"github.com/spf13/viper"
)

type Config struct {
	ServerBootTime time.Time
	Service        ServiceConf
	DnsEngine      DnsEngineConf
	Apiserver      ApiserverConf
	Zones          map[string]tdns.ZoneConf
	Db             DbConf
	Ddns           struct {
		KeyDirectory string `validate:"dir,required"`
		Update_NS    *bool  `validate:"required"`
		Update_A     *bool  `validate:"required"`
		Update_AAAA  *bool  `validate:"required"`
		Policy       struct {
			Type      string   `validate:"required"`
			RRtypes   []string `validate:"required"`
			KeyUpload string   `validate:"required"`
		}
	}

	Log struct {
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
	File string `validate:"required"`
}

type InternalConf struct {
	KeyDB           *tdns.KeyDB
	APIStopCh       chan struct{}
	RefreshZoneCh   chan tdns.ZoneRefresher
	BumpZoneCh      chan tdns.BumperData
	ValidatorCh     chan tdns.ValidatorRequest
	ScannerQ        chan tdns.ScanRequest
	UpdateQ         chan tdns.UpdateRequest
	DnsUpdateQ      chan tdns.DnsHandlerRequest
	DnsNotifyQ      chan tdns.DnsHandlerRequest
	DelegationSyncQ chan tdns.DelegationSyncRequest
	NotifyQ         chan tdns.NotifyRequest
	AuthQueryQ      chan tdns.AuthQueryRequest
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
