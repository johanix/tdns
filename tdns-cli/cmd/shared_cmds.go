/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"github.com/johanix/tdns/tdns"
)

func init() {
	rootCmd.AddCommand(tdns.DsyncQueryCmd)
}

