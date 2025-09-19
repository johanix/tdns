/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
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

var cliflag bool

var rootCmd = &cobra.Command{
	Use:   "tdns-imr",
	Short: "Interactive DNS lookup tool",
	Long:  `A DNS lookup tool with both command-line and interactive interfaces`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			if cliflag {
				cli.StartInteractiveMode() // old go-prompt version
				// StartInteractiveMode() // old go-prompt version
				// startReadlineMode() // new readline version
				return
			} else {
				fmt.Printf("tdns-imr: Starting in daemon mode, no CLI\n")
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
	cobra.OnInitialize(initConfig, initImr)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", tdns.DefaultImrCfgFile))
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "zone name")
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.ParentZone, "pzone", "Z", "", "parent zone name")

	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d",
		false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&cliflag, "cli", "", false, "CLI mode")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v",
		false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.ShowHeaders, "headers", "H",
		false, "show headers")

	// Add exit and quit commands for interactive mode
	// rootCmd.AddCommand(exitCmd)

	cli.SetRootCommand(rootCmd)
	// SetRootCommand(rootCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	cfgFile = cli.Conf.Internal.CfgFile // this gets populated from MainInit()
	if cfgFile != "" {
		fmt.Printf("tdns-imr: config file is '%s'\n", cfgFile)
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

	LocalConfig = viper.GetString("imr.localconfig")
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
	err := viper.Unmarshal(&cli.Conf)
	if err != nil {
		log.Printf("Error from viper.UnMarshal(cfg): %v", err)
	}
}

func initImr() {
	// conf := cli.Conf

	if tdns.Globals.Debug {
		fmt.Printf("initImr: Calling conf.MainInit(%q)\n", tdns.DefaultImrCfgFile)
	}

	err := cli.Conf.MainInit(tdns.DefaultImrCfgFile)
	if err != nil {
		tdns.Shutdowner(&cli.Conf, fmt.Sprintf("Error initializing tdns-imr: %v", err))
	}

	if tdns.Globals.Debug {
		fmt.Printf("initImr: Calling tdns.MainStartThreads()\n")
	}
	err = tdns.MainStartThreads(&cli.Conf, nil)
	if err != nil {
		tdns.Shutdowner(&cli.Conf, fmt.Sprintf("Error starting threads: %v", err))
	}
}
