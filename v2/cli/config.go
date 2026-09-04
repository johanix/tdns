/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"log"

	"github.com/go-playground/validator/v10"
	"github.com/johanix/tdns/v2"
	"github.com/spf13/viper"
)

type Config struct {
	Verbose *bool    `validate:"required"`
	Zones   []string `validate:"required"`
}

// unmarshalCLIConfig decodes tdns-cli's own config, and says something useful
// when what it was handed is a SERVER config instead.
//
// That mistake is easy to make -- both files are called tdns-*.yaml and both
// have a zones: key -- and it used to surface as
//
//	ValidateConfig: Unmarshal error: 9 error(s) decoding:
//	  * 'Zones[0]' expected type 'string', got unconvertible type 'map[string]interface {}'
//
// which names a Go type and a struct field, and leaves the operator to work
// out that --config takes tdns-cli's config, not the server's. The shapes are
// distinguishable: the CLI's zones: is a list of NAMES, a server's is a list
// of objects, so the wrong file can be recognised and named as such.
func unmarshalCLIConfig(v *viper.Viper, cfgfile string) Config {
	var config Config
	if v == nil {
		v = viper.GetViper()
	}
	if err := v.Unmarshal(&config); err != nil {
		if looksLikeServerConfig(v) {
			log.Fatalf("Config %q looks like a tdns SERVER config: its zones: entries are objects, while tdns-cli's are names.\n"+
				"--config is tdns-cli's own config. Pass a server config as the argument to `config check`, or via --serverconfig.\n"+
				"(underlying error: %v)", cfgfile, err)
		}
		log.Fatalf("ValidateConfig: Unmarshal error: %v", err)
	}
	return config
}

// looksLikeServerConfig reports whether the config has a top-level zones:
// list whose entries are objects — the shape a server config has and a CLI
// config cannot.
func looksLikeServerConfig(v *viper.Viper) bool {
	list, ok := v.Get("zones").([]interface{})
	if !ok || len(list) == 0 {
		return false
	}
	_, isMap := list[0].(map[string]interface{})
	return isMap
}

func ValidateConfig(v *viper.Viper, cfgfile string) error {
	config := unmarshalCLIConfig(v, cfgfile)

	var configsections = make(map[string]interface{}, 5)

	if err := ValidateBySection(&config, configsections, cfgfile); err != nil {
		log.Fatalf("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateZoneConfig(v *viper.Viper, cfgfile string) error {
	config := unmarshalCLIConfig(v, cfgfile)

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
