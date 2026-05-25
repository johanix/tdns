/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package main

import (
	cli "github.com/johanix/tdns/v2/cli"
)

func init() {
	// From ../tdns/cli/db_cmds.go: per-daemon factory; both auth and agent
	// have their own SQLite DB so each gets its own 'db init' command.
	cli.AuthCmd.AddCommand(cli.NewDbCmd("auth"))
	cli.AgentCmd.AddCommand(cli.NewDbCmd("agent"))

	// Note: 'auth ping' is already wired in v2/cli/auth_cmds.go init().

	// From ../tdns/cli/report.go: 'auth report' — reports are an
	// auth-daemon concern (CDS/CSYNC/error reports about a zone).
	cli.AuthCmd.AddCommand(cli.ReportCmd)

	// Note: 'auth daemon' is already wired in v2/cli/auth_cmds.go init().
	cli.AgentCmd.AddCommand(cli.NewDaemonCmd("agent"))

	// From ../tdns/cli/ddns_cmds.go: 'auth ddns' and 'auth del' —
	// DDNS update protocol + delegation-sync are auth-daemon concerns.
	cli.AuthCmd.AddCommand(cli.DdnsCmd, cli.DelCmd)

	// From ../tdns/cli/debug_cmds.go:
	cli.AuthCmd.AddCommand(cli.NewDebugCmd("auth"))
	cli.AgentCmd.AddCommand(cli.NewDebugCmd("agent"))

	// Keystore and truststore are wired here (not in v2/cli's
	// auth_cmds.go init) so the algorithm list embedded in their
	// --help text reflects the PQ algorithms this binary registered
	// in its own init() above.
	cli.AuthCmd.AddCommand(cli.NewKeystoreCmd("auth"))
	cli.AuthCmd.AddCommand(cli.NewTruststoreCmd("auth"))
	cli.AgentCmd.AddCommand(cli.NewKeystoreCmd("agent"))
	cli.AgentCmd.AddCommand(cli.NewTruststoreCmd("agent"))

	// From ../tdns/cli/dsync_cmds.go: 'imr dsync-query' — DSYNC discovery
	// resolves via the IMR resolver, so it sits under the imr daemon parent.
	cli.ImrCmd.AddCommand(cli.DsyncDiscoveryCmd)

	// From ../tdns/cli/config_cmds.go:
	cli.AuthCmd.AddCommand(cli.NewConfigCmd("auth"))
	cli.AgentCmd.AddCommand(cli.NewConfigCmd("agent"))

	// From ../tdns/cli/generate_cmds.go: daemon-agnostic record syntax helpers
	cli.UtilCmd.AddCommand(cli.GenerateCmd)

	// From ../tdns/cli/notify_cmds.go: 'auth notify' — sends NOTIFY
	// (CDS/CSYNC/DNSKEY) toward the parent or signer, an auth-daemon op.
	cli.AuthCmd.AddCommand(cli.NotifyCmd)

	// From ../tdns/cli/commands.go: 'auth stop' (matches 'agent stop' via NewDaemonCmd).
	cli.AuthCmd.AddCommand(cli.NewStopCmd("auth"))

	// From ../tdns/cli/combiner_cmds.go:
	//	rootCmd.AddCommand(cli.CombinerCmd)

	// From ../tdns/cli/agent_cmds.go:
	rootCmd.AddCommand(cli.AgentCmd)

	// JOSE/JWT keys CLI moved to tdns-mp/v2/cli and tdns-mp/cmd/mpcli;
	// plain tdns-cli no longer carries those commands. See tdns-mp PR #27.

	// ZoneCmd is now under AuthCmd (wired in cli/auth_cmds.go init).
	// Agent uses AgentZoneCmd (wired in cli/agent_zone_cmds.go).
	// Combiner uses combinerZoneCmd (wired in cli/legacy_combiner_edits_cmds.go).

	// From ../tdns/cli/base32_cmds.go: daemon-agnostic encode/decode helper
	cli.UtilCmd.AddCommand(cli.Base32Cmd)

	// From ../tdns/cli/scanner_cmds.go:
	rootCmd.AddCommand(cli.ScannerCmd)

	// From ../tdns/cli/imr_cmds.go:
	rootCmd.AddCommand(cli.ImrCmd)

	// From ../tdns/cli/auth_cmds.go:
	rootCmd.AddCommand(cli.AuthCmd)

	// Synthetic 'util' parent itself (must be added once, after children).
	rootCmd.AddCommand(cli.UtilCmd)

	// distrib_cmds.go and transaction_cmds.go live in tdns-mp/v2/cli;
	// their endpoints are only served by mp daemons, so they are wired
	// in from mpcli, not here.

	rootCmd.AddCommand(cli.VersionCmd)
}
