/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"log"

	"github.com/go-playground/validator/v10"
	"github.com/johanix/tdns/v0.x"
	"github.com/spf13/viper"
)

type Config struct {
	Verbose *bool    `validate:"required"`
	Zones   []string `validate:"required"`
}

func ValidateConfig(v *viper.Viper, cfgfile string) error {
	var config Config

	if v == nil {
		if err := viper.Unmarshal(&config); err != nil {
			log.Fatalf("ValidateConfig: Unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&config); err != nil {
			log.Fatalf("ValidateConfig: unmarshal error: %v", err)
		}
	}

	var configsections = make(map[string]interface{}, 5)

	if err := ValidateBySection(&config, configsections, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateZoneConfig(v *viper.Viper, cfgfile string) error {
	var config Config

	if v == nil {
		if err := viper.Unmarshal(&config); err != nil {
			log.Fatalf("ValidateConfig: Unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&config); err != nil {
			log.Fatalf("ValidateConfig: unmarshal error: %v", err)
		}
	}

	var configsections = make(map[string]interface{}, 5)

	//	configsections["checks"] = config.Checks
	//	configsections["params"] = config.Params

	if err := ValidateBySection(&config, configsections, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateBySection(config *Config, configsections map[string]interface{}, cfgfile string) error {
	validate := validator.New()

	for k, data := range configsections {
		if tdns.Globals.Verbose {
			log.Printf("Validating config for %s section", k)
		}
		if err := validate.Struct(data); err != nil {
			log.Fatalf("Config %s, section %s: missing required attributes:\n%v\n",
				cfgfile, k, err)
		}
	}
	return nil
}
