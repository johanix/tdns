/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
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
	_ "github.com/johanix/tdns/v2/core" // RR type registration
	"github.com/johanix/tdns/v2/debug"
)

// tdns-debug reads the SAME config as tdns-cli (design doc §4): no new
// config format. initConfig mirrors cmdv2/cli/root.go's, including the
// single-level include: expansion and the cli.localconfig overlay.

var cfgFile, cfgFileUsed string
var statePath string
var cconf cli.CliConf

var rootCmd = &cobra.Command{
	Use:   "tdns-debug",
	Short: "tdns-debug drives a running DNS server with churn and verifies invariants",
	Long: `tdns-debug is the tdns project's live test/debug instrument: it drives a
running server (tdns-auth or any standards-compliant implementation) with
configurable barrages of operations while concurrently observing behavior,
and verifies that every observation is consistent with a correct server.
Design: docs/2026-07-13-tdns-debug-test-tool.md.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		tdns.SetupCliLogging()
		initConfig()
		initApi()
	},
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

func ExecuteContext(ctx context.Context) {
	cobra.CheckErr(rootCmd.ExecuteContext(ctx))
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s — shared with tdns-cli)", tdns.DefaultCliCfgFile))
	rootCmd.PersistentFlags().StringVar(&statePath, "state", debug.DefaultStatePath,
		"tdns-debug state file (test identities)")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "verbose output")

	rootCmd.AddCommand(testCmd, probeCmd, listTestsCmd, cleanupCmd)
}

// initConfig mirrors cmdv2/cli/root.go: main file, single-level include:
// expansion (relative paths resolve against the main file's directory,
// missing includes are optional overlays), then the cli.localconfig overlay.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(tdns.DefaultCliCfgFile)
	}
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if tdns.Globals.Verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		log.Fatalf("Could not load config %s: Error: %v", viper.ConfigFileUsed(), err)
	}

	for _, inc := range viper.GetStringSlice("include") {
		incPath := inc
		if !filepath.IsAbs(incPath) {
			incPath = filepath.Join(filepath.Dir(cfgFileUsed), incPath)
		}
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
	}

	if lc := viper.GetString("cli.localconfig"); lc != "" {
		if _, err := os.Stat(lc); err == nil {
			viper.SetConfigFile(lc)
			if err := viper.MergeInConfig(); err != nil {
				log.Fatalf("Error merging in local config from '%s'", lc)
			}
		} else if !os.IsNotExist(err) {
			log.Fatalf("Error stat(%s): %v", lc, err)
		}
	}

	cli.ValidateConfig(nil, cfgFileUsed) // terminates on error
	if err := viper.Unmarshal(&cconf); err != nil {
		log.Fatalf("FATAL: viper.Unmarshal failed to parse config: %v", err)
	}
}

func initApi() {
	if err := cli.InitApiClients(&cconf); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
}

// apiClientFor looks up an apiservers: entry by name. Unlike tdns-cli's
// role-based GetApiClient, tdns-debug targets are named explicitly
// (--target), because a testbed run may aim at any instance.
func apiClientFor(name string) *tdns.ApiClient {
	if name == "" {
		return nil
	}
	return tdns.Globals.ApiClients[name]
}
