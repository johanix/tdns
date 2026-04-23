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
	AuthCmd.AddCommand(NewKeystoreCmd("auth"))
	AuthCmd.AddCommand(NewTruststoreCmd("auth"))
}
