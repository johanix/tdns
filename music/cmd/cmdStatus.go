/*
 * Copyright (c) 2022 Rog Murray, roger.murray@internetstiftelsen.se
 */

package mcmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
//	rootCmd.AddCommand(statusCmd)
	StatusCmd.AddCommand(statusZonesCmd)
	StatusCmd.AddCommand(statusSignerCmd)
	StatusCmd.AddCommand(statusSignerGroupCmd)
	StatusCmd.AddCommand(statusAllCmd)
}

var StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current status of MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var statusZonesCmd = &cobra.Command{
	Use:   "zone",
	Short: "Show current status of all zones in MuSiC",
	Run: func(cmd *cobra.Command, arg []string) {
		ZoneStatus()
	},
}

var statusSignerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Show current status of all signers in MuSiC",
	Run: func(cmd *cobra.Command, arg []string) {
		SignerStatus()
	},
}

var statusSignerGroupCmd = &cobra.Command{
	Use:   "signergroup",
	Short: "Show current status of all signergroups in MuSiC",
	Run: func(cmd *cobra.Command, arg []string) {
		SignerGroupStatus()
	},
}

var statusAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Show current status of MuSiC",
	Run: func(cmd *cobra.Command, arg []string) {
		fmt.Println("-------------------   -------------------")
		ZoneStatus()
		fmt.Println("-------------------   -------------------")
		SignerStatus()
		fmt.Println("-------------------   -------------------")
		SignerGroupStatus()
		fmt.Println("-------------------   -------------------")
	},
}
