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

// NewKeysCmd returns a fresh "keys" command tree bound to the given role.
// Role must be "agent" or "combiner" — the tree is only meaningful under
// those two API clients (their configs point to the long_term_jose_priv_key).
func NewKeysCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "keys",
		Short: "JOSE keypair for secure CHUNK (generate, show)",
		Long:  `Generate a JOSE keypair or display the public key. Uses the server config file (agent or combiner) to get long_term_jose_priv_key path, or --server-config.`,
	}
	c.PersistentFlags().StringVar(&keysServerConfig, "server-config", "",
		"path to agent/combiner config file (overrides apiservers.*.config_file)")

	generate := &cobra.Command{
		Use:   "generate",
		Short: "Generate JOSE keypair and write to config path or -output",
		Run: func(cmd *cobra.Command, args []string) {
			runKeysCommand(role, cmd, "generate", args)
		},
	}
	generate.Flags().StringP("output", "o", "", "path for generated private key (overrides config)")

	show := &cobra.Command{
		Use:   "show",
		Short: "Print public key (JWK) from configured long_term_jose_priv_key",
		Run: func(cmd *cobra.Command, args []string) {
			runKeysCommand(role, cmd, "show", args)
		},
	}

	c.AddCommand(generate, show)
	return c
}

func runKeysCommand(role string, cmd *cobra.Command, subcommand string, args []string) {
	if role != "agent" && role != "combiner" {
		log.Fatalf("keys must be run under agent or combiner (e.g. tdns-cli agent keys %s)", subcommand)
	}

	serverConfigPath := keysServerConfig
	if serverConfigPath == "" {
		clientKey := getClientKeyFromParent(role)
		if ad := getApiDetailsByClientKey(clientKey); ad != nil && ad.ConfigFile != "" {
			serverConfigPath = ad.ConfigFile
		}
	}
	if serverConfigPath == "" {
		log.Fatalf("No server config: set apiservers.*.config_file in tdns-cli config for %s, or use --server-config",
			getClientKeyFromParent(role))
	}

	conf, err := tdns.LoadConfigForKeys(serverConfigPath)
	if err != nil {
		log.Fatalf("Load config %s: %v", serverConfigPath, err)
	}

	appType := tdns.AppTypeAgent
	if role == "combiner" {
		appType = tdns.AppTypeMPCombiner
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
