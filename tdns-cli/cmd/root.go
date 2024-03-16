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

	"github.com/johanix/tdns/tdns"
)

var cfgFile, cfgFileUsed string
var debug, verbose bool

// var GlobalReportCh, ResultCh chan tdns.CheckReport
var StopCh chan struct{}
var LocalConfig string

var api *tdns.Api

var rootCmd = &cobra.Command{
	Use:   "tdns-cli",
	Short: "tdns-cli is a tool used to interact with the tdnsd nameserver via API",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig, initApi)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", tdns.DefaultCfgFile))
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "zone name")
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.ParentZone, "pzone", "Z", "", "parent zone name")

	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(tdns.DefaultCfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		log.Fatalf("Could not load config %s: Error: %v", tdns.DefaultCfgFile, err)
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
				if verbose {
					fmt.Printf("Merging in local config from '%s'\n", LocalConfig)
				}
			}
		}
		viper.SetConfigFile(LocalConfig)
	}

	ValidateConfig(nil, cfgFileUsed) // will terminate on error

	err := tdns.RegisterNotifyRR()
	if err != nil {
		fmt.Printf("Error registering NOTIFY RR type: %v\n", err)
	}
	err = tdns.RegisterDsyncRR()
	if err != nil {
		fmt.Printf("Error registering DSYNC RR type: %v\n", err)
	}
}

func initApi() {
	baseurl := viper.GetString("cli.tdnsd.baseurl")
	apikey := viper.GetString("cli.tdnsd.apikey")
	authmethod := viper.GetString("cli.tdnsd.authmethod")

	api = tdns.NewClient("tdnsd", baseurl, apikey, authmethod, "insecure", verbose, debug)
}
