/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/tdns"
	cli "github.com/johanix/tdns/tdns/cli"
)

var cfgFile, cfgFileUsed string
var StopCh chan struct{}
var LocalConfig string

var daemonflag bool

var conf tdns.Config

// var api *tdns.ApiClient

var rootCmd = &cobra.Command{
	Use:   "tdns-cli",
	Short: "Interactive DNS lookup tool",
	Long:  `A DNS lookup tool with both command-line and interactive interfaces`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			if !daemonflag {
				startInteractiveMode() // old go-prompt version
				// startReadlineMode() // new readline version
				return
			} else {
				fmt.Printf("tdns-cli: Starting in daemon mode, no CLI\n")
				done := make(chan struct{}, 1)
				<-done
			}
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig, initRecursor)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", tdns.DefaultImrCfgFile))
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "zone name")
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.ParentZone, "pzone", "Z", "", "parent zone name")

	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d",
		false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&daemonflag, "daemon", "", false, "daemon mode (no CLI)")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v",
		false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.ShowHeaders, "headers", "H",
		false, "show headers")

	SetRootCommand(rootCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	cfgFile = conf.Internal.CfgFile // this gets populated from MainInit()
	if cfgFile != "" {
		fmt.Printf("tdns-lookup: config file is '%s'\n", cfgFile)
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(tdns.DefaultImrCfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		if tdns.Globals.Verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		log.Fatalf("Could not load config %s: Error: %v", viper.ConfigFileUsed(), err)
	}

	LocalConfig = viper.GetString("cli.localconfig")
	if LocalConfig != "" {
		_, err := os.Stat(LocalConfig)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Fatalf("Error stat(%s): %v", LocalConfig, err)
			}
		} else {
			viper.SetConfigFile(LocalConfig)
			if err := viper.MergeInConfig(); err != nil {
				log.Fatalf("Error merging in local config from '%s'", LocalConfig)
			} else {
				if tdns.Globals.Verbose {
					fmt.Printf("Merging in local config from '%s'\n", LocalConfig)
				}
			}
		}
		viper.SetConfigFile(LocalConfig)
	}

	cli.ValidateConfig(nil, cfgFileUsed) // will terminate on error
	err := viper.Unmarshal(&conf)
	if err != nil {
		log.Printf("Error from viper.UnMarshal(cfg): %v", err)
	}
}

type ApiDetails struct {
	Name       string `validate:"required" yaml:"name"`
	BaseURL    string `validate:"required" yaml:"baseurl"`
	ApiKey     string `validate:"required" yaml:"apikey"`
	AuthMethod string `validate:"required" yaml:"authmethod"`
}

// func initApi() {
//	for _, val := range cconf.ApiServers {
//		// XXX: here we should validate the conf for this apiserver
//		tmp := tdns.NewClient("tdns-cli", val.BaseURL, val.ApiKey, val.AuthMethod, "insecure")
//		if tmp == nil {
//			log.Fatalf("initApi: Failed to setup API client for %q. Exiting.", val.Name)
//		}
//		tdns.Globals.ApiClients[val.Name] = tmp
//		if tdns.Globals.Debug {
//			fmt.Printf("API client for %q set up (baseurl: %q).\n", val.Name, tmp.BaseUrl)
//		}
//	}

// for convenience we store the API client for "server" in the old place also
//	tdns.Globals.Api = tdns.Globals.ApiClients["tdns-server"]
//}

func initRecursor() {
	log.Printf("initRecursor: Calling conf.MainInit(%q)", tdns.DefaultImrCfgFile)
	// Conf.Internal.RecursorCh = make(chan tdns.RecursorRequest, 10)
	err := conf.MainInit(tdns.DefaultImrCfgFile)
	log.Printf("initRecursor: Back from conf.MainInit()")
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error initializing tdns-imr: %v", err))
	}

	// conf.Internal.RecursorCh = make(chan tdns.ImrRequest, 10)
	// stopCh := make(chan struct{}, 10)
	// go tdns.RecursorEngine(&conf, stopCh)

	err = tdns.MainStartThreads(&conf, nil)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error starting threads: %v", err))
	}
}
