/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	cli "github.com/johanix/tdns/tdns/cli"
)

func init() {
	// From ../tdns/cli/db_cmds.go:
	rootCmd.AddCommand(cli.DbCmd)

	// From ../tdns/cli/start_cmds.go:
	rootCmd.AddCommand(cli.PingCmd)

	rootCmd.AddCommand(cli.ReportCmd)
	rootCmd.AddCommand(cli.RawReportCmd)

	rootCmd.AddCommand(cli.DaemonCmd)
	cli.AgentCmd.AddCommand(cli.DaemonCmd)
	cli.CombinerCmd.AddCommand(cli.DaemonCmd)

	// From ../tdns/cli/ddns_cmds.go:
	rootCmd.AddCommand(cli.DdnsCmd, cli.DelCmd)

	// From ../tdns/cli/debug_cmds.go:
	rootCmd.AddCommand(cli.DebugCmd)
	cli.AgentCmd.AddCommand(cli.DebugCmd)
	cli.CombinerCmd.AddCommand(cli.DebugCmd)

	// From ../tdns/cli/keystore_cmds.go:
	rootCmd.AddCommand(cli.KeystoreCmd)
	cli.AgentCmd.AddCommand(cli.KeystoreCmd)

	// From ../tdns/cli/truststore_cmds.go:
	rootCmd.AddCommand(cli.TruststoreCmd)
	cli.AgentCmd.AddCommand(cli.TruststoreCmd)

	// From ../tdns/cli/dsync_cmds.go:
	rootCmd.AddCommand(cli.DsyncDiscoveryCmd)

	// From ../tdns/cli/config_cmds.go:
	rootCmd.AddCommand(cli.ConfigCmd)
	cli.CombinerCmd.AddCommand(cli.ConfigCmd)
	cli.AgentCmd.AddCommand(cli.ConfigCmd)

	// From ../tdns/cli/rfc3597.go:
	rootCmd.AddCommand(cli.ToRFC3597Cmd)

	// From ../tdns/cli/notify_cmds.go:
	rootCmd.AddCommand(cli.NotifyCmd)

	// From ../tdns/cli/commands.go:
	rootCmd.AddCommand(cli.StopCmd)

	// From ../tdns/cli/combiner_cmds.go:
	rootCmd.AddCommand(cli.CombinerCmd)

	// From ../tdns/cli/agent_cmds.go:
	rootCmd.AddCommand(cli.AgentCmd)

	// From ../tdns/cli/zone_cmds.go:
	rootCmd.AddCommand(cli.ZoneCmd)
	cli.CombinerCmd.AddCommand(cli.ZoneCmd)
	cli.AgentCmd.AddCommand(cli.ZoneCmd)

	// From ../tdns/cli/base32_cmds.go
	rootCmd.AddCommand(cli.Base32Cmd)

	rootCmd.AddCommand(cli.VersionCmd)
}
