/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/viper"
)

type Config struct {
	Verbose *bool    `validate:"required"`
	Zones   []string `validate:"required"`
}

func ValidateConfig(v *viper.Viper, cfgfile string) error {
	fmt.Println("ValidateConfig")
	var tconf tdns.Config

	if v == nil {
		if err := viper.Unmarshal(&tconf); err != nil {
			log.Fatalf("ValidateConfig: Unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&tconf); err != nil {
			log.Fatalf("ValidateConfig: unmarshal error: %v", err)
		}
	}

	var configsections = make(map[string]interface{}, 5)
	configsections["log"] = tconf.Log
	configsections["service"] = tconf.Service
	configsections["db"] = tconf.Db
	configsections["apiserver"] = tconf.ApiServer
	configsections["dnsengine"] = tconf.DnsEngine

	if err := ValidateBySection(&tconf, configsections, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateZoneConfig(v *viper.Viper, cfgfile string) error {
	var tconf tdns.Config

	if v == nil {
		if err := viper.Unmarshal(&tconf); err != nil {
			log.Fatalf("ValidateConfig: Unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&tconf); err != nil {
			log.Fatalf("ValidateConfig: unmarshal error: %v", err)
		}
	}

	var configsections = make(map[string]interface{}, 5)

	//	configsections["checks"] = config.Checks
	//	configsections["params"] = config.Params

	if err := ValidateBySection(&tconf, configsections, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateBySection(tconf *tdns.Config, configsections map[string]interface{}, cfgfile string) error {
	// validate := validator.New()
	validate, err := tdns.NewCustomValidator()
	if err != nil {
		return fmt.Errorf("ValidateBySection: error creating custom validator: %v", err)
	}

	for k, data := range configsections {
		if tdns.Globals.Verbose {
			log.Printf("%s: Validating config for %s section", tconf.App.Name, k)
		}
		if err := validate.Struct(data); err != nil {
			log.Fatalf("%s: Config %s, section %s: missing required attributes:\n%v",
				tconf.App.Name, cfgfile, k, err)
		}
	}
	return nil
}
