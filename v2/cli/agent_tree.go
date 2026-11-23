/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * A complete tdns-agent command tree, built for one named daemon instance.
 */
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewAgentTree builds a tdns-agent command tree targeting one instance:
// `use` is the word typed on the command line, `role` the key that
// GetApiClient resolves to an ApiClient.
//
// Same idea as NewAuthTree: nothing here is a copy of the tree wired up in the
// init()s that build AgentCmd. Every subcommand comes from the same
// role-parameterised factory those call; this calls each one again with a
// different role. The canonical tree is: ping, imr and the hidden legacy
// parentsync (v2/cli), zone (agent_zone_cmds.go), and db, daemon, debug,
// keystore, truststore and config (the binaries' shared_cmds.go). Every one of
// those is here, and TestInstanceTreeMatchesCanonicalAgentTree (cmdv2/ncli)
// fails if the canonical tree grows one that this does not.
//
// The agent's `zone` group is a factory (NewAgentZoneCmd) for the same reason
// it had to become one: its commands used to carry the literal role "agent",
// which in a second tree would silently drive the canonical tdns-agent.
func NewAgentTree(use, role string) *cobra.Command {
	c := &cobra.Command{
		Use:   use,
		Short: fmt.Sprintf("Interact with the %q tdns-agent instance via its API", role),
		Long: fmt.Sprintf(`Interact with the %q tdns-agent instance via its management API.

This is the same command set as "agent", targeting a different daemon. The
target is the apiservers entry named %q in the CLI config.`, role, role),
	}
	TagRole(c, role)

	c.AddCommand(
		NewPingCmd(role),
		NewDaemonCmd(role),
		NewAgentZoneCmd(role),
		newLegacyAgentParentSync(role),
		NewDbCmd(role),
		NewDebugCmd(role),
		NewConfigCmdFor(role, "agent"),
		NewImrSubtree(role),
	)

	// Keystore and truststore last, for the reason NewAuthTree gives: their
	// --help text embeds the supported-algorithm list at construction time.
	c.AddCommand(
		NewKeystoreCmd(role),
		NewTruststoreCmd(role),
	)

	return c
}
