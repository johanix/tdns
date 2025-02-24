/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"github.com/spf13/cobra"
)

var AgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "TDNS Agent commands",
}

func init() {
	//	CombinerCmd.AddCommand(combinerAddDataCmd)
	//	CombinerCmd.AddCommand(combinerListDataCmd)
}
