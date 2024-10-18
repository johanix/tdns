/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	cli "github.com/johanix/tdns/libcli"
)

func init() {
	// From ../libcli/start_cmds.go:
	rootCmd.AddCommand(cli.PingCmd)
	rootCmd.AddCommand(cli.DaemonCmd)

	// From ../libcli/zone_cmds.go:
	rootCmd.AddCommand(cli.ZoneCmd)

	// From ../libcli/ddns_cmds.go:
	rootCmd.AddCommand(cli.DdnsCmd, cli.DelCmd)

	// From ../libcli/debug_cmds.go:
	rootCmd.AddCommand(cli.DebugCmd)

	// From ../libcli/keystore_cmds.go:
	rootCmd.AddCommand(cli.KeystoreCmd)

	// From ../libcli/truststore_cmds.go:
	rootCmd.AddCommand(cli.TruststoreCmd)

	// From ../libcli/dsync_cmds.go:
	rootCmd.AddCommand(cli.DsyncDiscoveryCmd)

	// From ../libcli/config_cmds.go:
	rootCmd.AddCommand(cli.ConfigCmd)

	// From ../libcli/rfc3597.go:
	rootCmd.AddCommand(cli.ToRFC3597Cmd)

	// From ../libcli/notify_cmds.go:
	rootCmd.AddCommand(cli.NotifyCmd)

	// From ../libcli/commands.go:
	rootCmd.AddCommand(cli.StopCmd)
}
