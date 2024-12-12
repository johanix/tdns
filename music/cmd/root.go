/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package mcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	tdns "github.com/johanix/tdns/tdns"

	"github.com/spf13/viper"

	"github.com/go-playground/validator/v10"
)

// initConfig reads in config file and ENV variables if set.
func InitConfig() {
	var conf tdns.Config
	var mconf music.Config

	viper.SetConfigFile(music.DefaultSidecarTdnsCfgFile)
	if err := viper.ReadInConfig(); err == nil {
		if tdns.Globals.Verbose {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}
		err = viper.Unmarshal(&conf)
		if err != nil {
			log.Fatalf("Error unmarshalling TDNS config %s: %v", music.DefaultSidecarTdnsCfgFile, err)
		}
	} else {
		log.Fatalf("Error parsing TDNS config %s: %v", music.DefaultSidecarTdnsCfgFile, err)
	}

	// Load MUSIC config; note that this must be after the TDNS config has been parsed and use viper.MergeConfig()
	if err := music.LoadMusicConfig(&mconf, "sidecar-cli", false); err == nil {
		if tdns.Globals.Verbose {
			fmt.Println("Using MUSIC config file:", music.DefaultSidecarCfgFile)
		}
		err = viper.Unmarshal(&mconf)
		if err != nil {
			log.Fatalf("Error unmarshalling MUSIC config: %v", err)
		}
	} else {
		log.Fatalf("Error loading MUSIC config: %v", err)
	}

	music.Validate = validator.New()
	if err := music.Validate.Struct(&mconf); err != nil {
		log.Fatalf("Config '%s' is missing required attributes:\n%v\n", music.DefaultSidecarCfgFile, err)
	}
}

func InitApi() {

	baseurl := viper.GetString("cli.sidecar.baseurl")
	apikey := viper.GetString("cli.sidecar.apikey")
	authmethod := viper.GetString("cli.sidecar.authmethod")
	//rootcafile := viper.GetString("cli.sidecar.cacert")

	//	api = music.NewClient("musicd", baseurl, apikey, authmethod, rootcafile,
	//		tdns.Globals.Verbose, cliconf.Debug)

	tdns.Globals.Api = tdns.NewClient("sidecar-cli", baseurl, apikey, authmethod, "insecure", tdns.Globals.Verbose, tdns.Globals.Debug)

	if tdns.Globals.Debug {
		tmpapi := tdns.ApiClient{
			Name:       tdns.Globals.Api.Name,
			BaseUrl:    tdns.Globals.Api.BaseUrl,
			AuthMethod: tdns.Globals.Api.AuthMethod,
			Client:     nil,
			Verbose:    tdns.Globals.Verbose,
			Debug:      tdns.Globals.Debug,
			UseTLS:     tdns.Globals.Api.UseTLS,
		}
		bytebuf := new(bytes.Buffer)
		err := json.NewEncoder(bytebuf).Encode(tmpapi)
		if err != nil {
			log.Fatalf("Error from json.NewEncoder: %v", err)
		}
		var prettyJSON bytes.Buffer
		err = json.Indent(&prettyJSON, bytebuf.Bytes(), "", "  ")
		if err != nil {
			log.Println("JSON parse error: ", err)
		}
		fmt.Printf("initApi: api connection to %s initialized (%s)\n:\napi: %s\n", baseurl, apikey, prettyJSON.String())
	}
}
