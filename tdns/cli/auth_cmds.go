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
	// Add ping and daemon commands to AuthCmd (PingCmd and DaemonCmd are defined elsewhere)
	AuthCmd.AddCommand(PingCmd)
	AuthCmd.AddCommand(DaemonCmd)
}
