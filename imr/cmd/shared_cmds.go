/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cmd

import (
	cli "github.com/johanix/tdns/tdns/cli"
)

func init() {
	rootCmd.AddCommand(cli.ImrDumpCmd)
	//	rootCmd.AddCommand(ImrDumpCmd)

	rootCmd.AddCommand(cli.ImrQueryCmd)
	//	rootCmd.AddCommand(ImrQueryCmd)

	rootCmd.AddCommand(cli.ImrStatsCmd)
	//	rootCmd.AddCommand(ImrStatsCmd)

	rootCmd.AddCommand(cli.ImrShowCmd)
	rootCmd.AddCommand(cli.ImrFlushCmd)

	rootCmd.AddCommand(cli.ImrZoneCmd)
	//	rootCmd.AddCommand(ImrZoneCmd)

	//	rootCmd.AddCommand(imrServerCmd)

	rootCmd.AddCommand(cli.ExitCmd)
	rootCmd.AddCommand(cli.QuitCmd)
}
