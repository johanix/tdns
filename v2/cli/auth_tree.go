/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * A complete tdns-auth command tree, built for one named daemon instance.
 */
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewAuthTree builds a tdns-auth command tree targeting one instance:
// `use` is the word typed on the command line, `role` the key that
// GetApiClient resolves to an ApiClient.
//
// Nothing here is a copy of the tree wired up in auth_cmds.go's init(). Every
// subcommand comes from the same role-parameterised factory that init() calls;
// this simply calls each one again with a different role. A *cobra.Command has
// exactly one parent, so a second tree has to be a second instantiation -- but
// it is not a second DEFINITION, which is the property that matters.
//
// DELIBERATELY ABSENT (not an oversight): report and notify. Neither contains
// a GetApiClient call -- they are wire-protocol tools (send a NOTIFY, build a
// report about a zone), not management-API clients. They are not
// instance-scoped, and offering them per-instance would imply a targeting
// relationship that does not exist.
//
// Everything else the canonical tree offers is here. catalog, ddns/del and imr
// were package-level command vars until phase 2 converted them to factories;
// see NewCatalogCmd for why a var could only ever hang off one tree.
func NewAuthTree(use, role string) *cobra.Command {
	c := &cobra.Command{
		Use:   use,
		Short: fmt.Sprintf("Interact with the %q tdns-auth instance via its API", role),
		Long: fmt.Sprintf(`Interact with the %q tdns-auth instance via its management API.

This is the same command set as "auth", targeting a different daemon. The
target is the apiservers entry named %q in the tdns-cli config.`, role, role),
	}
	TagRole(c, role)

	c.AddCommand(
		NewPingCmd(role),
		NewDaemonCmd(role),
		NewZoneCmd(role),
		NewDsyncApiCmd(role),
		NewDbCmd(role),
		NewDebugCmd(role),
		NewConfigCmd(role),
		NewStopCmd(role),
		NewCatalogCmd(role),
		NewDdnsCmd(role),
		NewDelCmd(role),
		NewImrSubtree(role),
	)

	// Keystore and truststore last, and by the same rule they follow in
	// cmdv2/cli/shared_cmds.go: their --help text embeds the supported-
	// algorithm list at CONSTRUCTION time, so they must not be built until the
	// binary's own init() has registered its algorithms. Callers build the
	// whole tree from Execute(), which is after every init() has run.
	c.AddCommand(
		NewKeystoreCmd(role),
		NewTruststoreCmd(role),
	)

	return c
}
