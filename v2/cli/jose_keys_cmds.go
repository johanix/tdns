/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-cli agent keys / tdns-cli combiner keys: generate JOSE keypair or show public key.
 * Uses server config file (agent or combiner) for long_term_jose_priv_key path.
 */

package cli

import (
	"fmt"
	"log"
	"os"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

var keysServerConfig string

var KeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "JOSE keypair for secure CHUNK (generate, show)",
	Long:  `Generate a JOSE keypair or display the public key. Uses the server config file (agent or combiner) to get long_term_jose_priv_key path, or --server-config.`,
}

var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate JOSE keypair and write to config path or -output",
	Run: func(cmd *cobra.Command, args []string) {
		runKeysCommand(cmd, "generate", args)
	},
}

var keysShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print public key (JWK) from configured long_term_jose_priv_key",
	Run: func(cmd *cobra.Command, args []string) {
		runKeysCommand(cmd, "show", args)
	},
}

func init() {
	KeysCmd.PersistentFlags().StringVar(&keysServerConfig, "server-config", "",
		"path to agent/combiner config file (overrides apiservers.*.config_file)")
	KeysCmd.AddCommand(keysGenerateCmd, keysShowCmd)
	keysGenerateCmd.Flags().StringP("output", "o", "", "path for generated private key (overrides config)")
}

func runKeysCommand(cmd *cobra.Command, subcommand string, args []string) {
	parent, _ := getCommandContext("keys")
	if parent != "agent" && parent != "combiner" {
		log.Fatalf("keys must be run under agent or combiner (e.g. tdns-cli agent keys %s)", subcommand)
	}

	serverConfigPath := keysServerConfig
	if serverConfigPath == "" {
		clientKey := getClientKeyFromParent(parent)
		details := getApiDetailsByClientKey(clientKey)
		if details != nil {
			if cf, ok := details["config_file"].(string); ok && cf != "" {
				serverConfigPath = cf
			}
		}
	}
	if serverConfigPath == "" {
		log.Fatalf("No server config: set apiservers.*.config_file in tdns-cli config for %s, or use --server-config",
			getClientKeyFromParent(parent))
	}

	conf, err := tdns.LoadConfigForKeys(serverConfigPath)
	if err != nil {
		log.Fatalf("Load config %s: %v", serverConfigPath, err)
	}

	appType := tdns.AppTypeAgent
	if parent == "combiner" {
		appType = tdns.AppTypeCombiner
	}

	runArgs := []string{subcommand}
	if subcommand == "generate" {
		output, _ := cmd.Flags().GetString("output")
		if output != "" {
			runArgs = append(runArgs, "-output", output)
		}
	}

	if err := tdns.RunKeysCmd(conf, appType, runArgs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
