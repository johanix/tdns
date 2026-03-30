/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package main

import (
	cli "github.com/johanix/tdns/v2/cli"
)

func init() {
	// From ../tdns/cli/db_cmds.go:
	rootCmd.AddCommand(cli.DbCmd)

	// From ../tdns/cli/start_cmds.go:
	rootCmd.AddCommand(cli.PingCmd)

	// From ../tdns/cli/report.go:
	rootCmd.AddCommand(cli.ReportCmd)

	rootCmd.AddCommand(cli.DaemonCmd)
	cli.AgentCmd.AddCommand(cli.DaemonCmd)
	cli.CombinerCmd.AddCommand(cli.DaemonCmd)

	// From ../tdns/cli/ddns_cmds.go:
	rootCmd.AddCommand(cli.DdnsCmd, cli.DelCmd)

	// From ../tdns/cli/debug_cmds.go:
	rootCmd.AddCommand(cli.DebugCmd)
	cli.AgentCmd.AddCommand(cli.DebugCmd)
	cli.CombinerCmd.AddCommand(cli.DebugCmd)

	// Keystore and truststore are under AuthCmd and AgentCmd
	// (wired in cli/auth_cmds.go init). Agent also gets them:
	cli.AgentCmd.AddCommand(cli.KeystoreCmd)
	cli.AgentCmd.AddCommand(cli.TruststoreCmd)

	// From ../tdns/cli/dsync_cmds.go:
	rootCmd.AddCommand(cli.DsyncDiscoveryCmd)

	// From ../tdns/cli/config_cmds.go:
	rootCmd.AddCommand(cli.ConfigCmd)
	cli.CombinerCmd.AddCommand(cli.ConfigCmd)
	cli.AgentCmd.AddCommand(cli.ConfigCmd)

	// From ../tdns/cli/generate_cmds.go:
	rootCmd.AddCommand(cli.GenerateCmd)

	// From ../tdns/cli/notify_cmds.go:
	rootCmd.AddCommand(cli.NotifyCmd)

	// From ../tdns/cli/commands.go:
	rootCmd.AddCommand(cli.StopCmd)

	// From ../tdns/cli/combiner_cmds.go:
	rootCmd.AddCommand(cli.CombinerCmd)

	// From ../tdns/cli/agent_cmds.go:
	rootCmd.AddCommand(cli.AgentCmd)

	// Root-level keys (generate JOSE for agent/combiner; no config required)
	rootCmd.AddCommand(cli.RootKeysCmd)

	// From ../tdns/cli/jose_keys_cmds.go: agent/combiner keys (generate, show) — under agent/combiner, uses config
	cli.AgentCmd.AddCommand(cli.KeysCmd)
	cli.CombinerCmd.AddCommand(cli.KeysCmd)

	// ZoneCmd is now under AuthCmd (wired in cli/auth_cmds.go init).
	// Agent uses AgentZoneCmd (wired in cli/agent_zone_cmds.go).
	// Combiner uses combinerZoneCmd (wired in cli/legacy_combiner_edits_cmds.go).

	// From ../tdns/cli/base32_cmds.go
	rootCmd.AddCommand(cli.Base32Cmd)

	// From ../tdns/cli/scanner_cmds.go:
	rootCmd.AddCommand(cli.ScannerCmd)

	// From ../tdns/cli/imr_cmds.go:
	rootCmd.AddCommand(cli.ImrCmd)

	// From ../tdns/cli/auth_cmds.go:
	rootCmd.AddCommand(cli.AuthCmd)

	// From ../tdns/cli/jwt_cmds.go:
	rootCmd.AddCommand(cli.JwtCmd)

	// From ../tdns/cli/distrib_cmds.go:
	cli.AgentCmd.AddCommand(cli.AgentDistribCmd)
	cli.CombinerCmd.AddCommand(cli.CombinerDistribCmd)

	// From ../tdns/cli/transaction_cmds.go:
	cli.AgentCmd.AddCommand(cli.AgentTransactionCmd)
	cli.CombinerCmd.AddCommand(cli.CombinerTransactionCmd)

	rootCmd.AddCommand(cli.VersionCmd)
}
