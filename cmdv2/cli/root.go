/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
	cli "github.com/johanix/tdns/v2/cli"
	_ "github.com/johanix/tdns/v2/core" // Import for RR type registration (CHUNK, etc.)
)

var cfgFile, cfgFileUsed string
var LocalConfig string
var showVersion bool // --version : print version + supported algorithms, then exit

var rootCmd = &cobra.Command{
	Use:   "tdns-cli",
	Short: "tdns-cli is a tool used to interact with the TDNS applications via a mgmt API",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// --version is answered before any config/API setup: it reports what
		// this binary knows, in-process, and exits.
		if showVersion {
			tdns.PrintVersionAndExit()
		}
		tdns.SetupCliLogging()
		// keys generate (root-level) and gen-docs (offline doc generator) do
		// not need config or API.
		if isRootKeysCommand(cmd) || cmd.Name() == "gen-docs" {
			return
		}
		initConfig()
		initApi()
	},
	// tdns-cli has no default action; with no subcommand it prints help.
	// (--version is handled in PersistentPreRun above, which Cobra runs
	// before this Run even for the bare root command, so there is no need
	// to re-check showVersion here.)
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
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

// isRootKeysCommand returns true if cmd is the no-config "keys" subtree
// (e.g. keys generate). Those commands do not require config or API.
// Two accepted ancestries:
//   - legacy: tdns-cli keys ...
//   - current: tdns-cli util keys ...   (moved under 'util' in the
//     CLI restructure; same no-config semantics).
func isRootKeysCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() != "keys" {
			continue
		}
		p := c.Parent()
		if p == nil {
			return false
		}
		if p.Name() == "tdns-cli" {
			return true
		}
		gp := p.Parent()
		return p.Name() == "util" && gp != nil && gp.Name() == "tdns-cli"
	}
	return false
}

func init() {
	// Config/API init moved to rootCmd.PersistentPreRun (skipped for root-level "keys")

	// Catalog zone management lives under 'auth' — catalog zones are an
	// auth-daemon concern (RFC 9432 catalog zones served by tdns-auth).
	cli.AuthCmd.AddCommand(cli.CatalogCmd)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", tdns.DefaultCliCfgFile))
	rootCmd.PersistentFlags().BoolVar(&showVersion, "version", false, "print version and supported algorithms, then exit")
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

	// Expand any top-level "include:" directives. viper has no native
	// include support, so we merge each listed file in turn. This is a
	// single-level (non-recursive) shim: an included file's own
	// "include:" is not processed. Relative paths resolve against the
	// main config file's directory. Used e.g. to pull algorithm
	// enrichment data in from a shareable /etc/tdns/algorithms.yaml,
	// keeping it out of this host-local, secret-bearing config.
	for _, inc := range viper.GetStringSlice("include") {
		incPath := inc
		if !filepath.IsAbs(incPath) {
			incPath = filepath.Join(filepath.Dir(cfgFileUsed), incPath)
		}
		// A missing included file is not fatal — it is treated as an
		// optional overlay (mirrors the LocalConfig handling below), so
		// e.g. an as-yet-uninstalled /etc/tdns/algorithms.yaml just
		// leaves the CLI without that enrichment. A present-but-broken
		// include is still a hard error.
		if _, err := os.Stat(incPath); err != nil {
			if os.IsNotExist(err) {
				if tdns.Globals.Verbose {
					fmt.Fprintln(os.Stderr, "Skipping missing included config:", incPath)
				}
				continue
			}
			log.Fatalf("Error stat(%s): %v", incPath, err)
		}
		viper.SetConfigFile(incPath)
		if err := viper.MergeInConfig(); err != nil {
			log.Fatalf("Could not merge included config %s: Error: %v", incPath, err)
		}
		if tdns.Globals.Verbose {
			fmt.Fprintln(os.Stderr, "Merged included config:", incPath)
		}
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
