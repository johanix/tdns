/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"github.com/spf13/cobra"
)

// UtilCmd is a synthetic parent for daemon-agnostic helper commands
// (base32 encoding, JWT inspection, record-syntax generators, root-level
// JOSE key generation). Putting these under a single 'util' parent keeps
// the top-level uncluttered and reserves it for daemon parents
// (auth, agent, imr, scanner) plus 'version'.
var UtilCmd = &cobra.Command{
	Use:   "util",
	Short: "Daemon-agnostic utility commands (base32, jwt, generate, keys)",
}
