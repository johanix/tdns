/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"github.com/spf13/cobra"
)

// AuthCmd is the parent command for all auth-related commands
var AuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Interact with tdns-auth (authoritative) via API",
}

func init() {
	// Add ping and daemon commands to AuthCmd (NewPingCmd/DaemonCmd are defined elsewhere)
	AuthCmd.AddCommand(NewPingCmd("auth"))
	AuthCmd.AddCommand(NewDaemonCmd("auth"))
	AuthCmd.AddCommand(NewZoneCmd("auth"))

	// Keystore and truststore are wired by the binary's own init()
	// after the binary has registered its DNSSEC algorithms — the
	// keystore commands' --help text embeds the supported-algorithm
	// list at command-construction time, so deferring lets PQ
	// algorithms appear in --help. See cmdv2/cliv2/shared_cmds.go.
}
