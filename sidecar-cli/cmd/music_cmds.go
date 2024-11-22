/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package cmd

import (
	"github.com/spf13/cobra"
	mcmd "github.com/johanix/tdns/music/cmd"
)

func init() {
	var MusicCmd = &cobra.Command{
		Use:	"music",
		Short:	"prefix cmd to reach all MUSIC sub-commands",
	}

	rootCmd.AddCommand(MusicCmd)

	// from ../music/cmd/status.go:	
	MusicCmd.AddCommand(mcmd.StatusCmd)

	// from ../music/cmd/deseclogin.go:	
	MusicCmd.AddCommand(mcmd.DesecCmd)

	// from ../music/cmd/process.go:
	MusicCmd.AddCommand(mcmd.ProcessCmd)

	// from ../music/cmd/show.go:
	MusicCmd.AddCommand(mcmd.ShowCmd)

	// from ../music/cmd/signer.go:
	MusicCmd.AddCommand(mcmd.SignerCmd)

	// from ../music/cmd/signergroup.go:
	MusicCmd.AddCommand(mcmd.SignerGroupCmd)

	// from ../music/cmd/test.go:
	MusicCmd.AddCommand(mcmd.TestCmd)

	// from ../music/cmd/zone.go:	
	MusicCmd.AddCommand(mcmd.ZoneCmd)
}
