/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
	cli "github.com/johanix/tdns/v2/cli"
	_ "github.com/johanix/tdns/v2/core" // Import for RR type registration (CHUNK, etc.)
)

var cfgFile, cfgFileUsed string
var LocalConfig string

var rootCmd = &cobra.Command{
	Use:   "tdns-cli",
	Short: "tdns-cli is a tool used to interact with the tdnsd nameserver via API",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		tdns.SetupCliLogging()
		// keys generate (root-level) does not need config or API
		if isRootKeysCommand(cmd) {
			return
		}
		initConfig()
		initApi()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

// ExecuteContext adds all child commands to the root command and sets flags appropriately.
// This is called by main.main() with a context for signal handling.
func ExecuteContext(ctx context.Context) {
	cobra.CheckErr(rootCmd.ExecuteContext(ctx))
}

// isRootKeysCommand returns true if cmd is the root-level "keys" (e.g. keys generate).
// Those commands do not require config or API. Root has Use "tdns-cli".
func isRootKeysCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() == "keys" {
			p := c.Parent()
			return p != nil && p.Name() == "tdns-cli"
		}
	}
	return false
}

func init() {
	// Config/API init moved to rootCmd.PersistentPreRun (skipped for root-level "keys")

	// Register catalog zone management commands
	rootCmd.AddCommand(cli.CatalogCmd)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", tdns.DefaultCliCfgFile))
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "zone name")
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.ParentZone, "pzone", "Z", "", "parent zone name")

	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d",
		false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v",
		false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.ShowHeaders, "headers", "H",
		false, "show headers")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(tdns.DefaultCliCfgFile)
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
			// File doesn't exist - do not set config file or merge
		} else {
			// File exists - set config file and merge it
			viper.SetConfigFile(LocalConfig)
			if err := viper.MergeInConfig(); err != nil {
				log.Fatalf("Error merging in local config from '%s'", LocalConfig)
			} else {
				if tdns.Globals.Verbose {
					fmt.Printf("Merging in local config from '%s'\n", LocalConfig)
				}
			}
		}
	}

	cli.ValidateConfig(nil, cfgFileUsed) // will terminate on error
	if err := viper.Unmarshal(&cconf); err != nil {
		log.Fatalf("FATAL: viper.Unmarshal failed to parse config: %v", err)
	}
}

var cconf cli.CliConf

func initApi() {
	if err := cli.InitApiClients(&cconf); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
}
