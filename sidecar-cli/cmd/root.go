/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cmd

import (
	"fmt"

	mcmd "github.com/johanix/tdns/music/cmd"
	tdns "github.com/johanix/tdns/tdns"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sidecar-cli",
	Short: "CLI tool to manage music-sidecar",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(mcmd.InitConfig, mcmd.InitApi)

	rootCmd.PersistentFlags().StringVar(&mcmd.CfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", mcmd.DefaultCfgFile))

	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "Debugging output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.ShowHeaders, "headers", "H", false, "Show column headers on output")
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "name of zone")
	rootCmd.PersistentFlags().StringVarP(&mcmd.Signername, "signer", "s", "", "name of signer")
	rootCmd.PersistentFlags().StringVarP(&mcmd.Sgroupname, "group", "g", "", "name of signer group")
}
