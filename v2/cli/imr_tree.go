/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * A tdns-imr command tree, built for one named daemon instance.
 */
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// The imr role is registered here, next to its factory, rather than in the map
// literal in instances.go: a role is one new file this way, and the roles'
// pull requests do not all edit the same three lines.
func init() {
	knownInstanceRoles["imr"] = NewImrTree
}

// imrInstanceStats are the `imr stats` subcommands that ask the daemon over
// its API and so belong on an instance. The one left out is large-ksk, which
// reports the metrics of the process it runs in.
//
// An allowlist rather than "everything but large-ksk": a new stats command
// should be a decision. If it reads local state it must stay off the instance
// tree, and a denylist would put it there until someone noticed.
var imrInstanceStats = map[string]bool{
	"auth-transports":   true,
	"client-transports": true,
	"transport-stats":   true,
}

// NewImrTree builds a tdns-imr command tree targeting one instance: `use` is
// the word typed on the command line, `role` the key that GetApiClient
// resolves to an ApiClient.
//
// It differs from NewAuthTree and NewAgentTree in two ways, both because of
// where the imr commands live. First, they are package-level values shared
// with the tdns-imr daemon's own shell, so the query, flush and stats commands
// are copied from the canonical ones (cloneCmdTree) rather than rebuilt:
// there is still one definition of each. Second, a standalone resolver offers
// the CLI less than an authoritative server does. Only what talks to the
// daemon's API is on the tree:
//
//	ping, daemon, config (check, mwe, status), query, flush (common, all),
//	forward, stub, stats (auth-transports, client-transports, transport-stats)
//
// DELIBERATELY ABSENT (not an oversight), each for the same reason, that it has
// no management-API target and would only describe the CLI's own process, or
// nothing at all:
//
//   - show (config, options) and set (linewidth, server transport) read and
//     change the state of the process they run in, which for tdns-ncli is not
//     the resolver. They exist for `tdns-imr --cli`.
//   - stats large-ksk is the same: in-process metrics.
//   - zone (list, check) are placeholders that print a line and do nothing.
//   - dsync-query starts its own resolver inside the CLI process and queries
//     with that; no daemon, so no instance.
//
// TestInstanceTreeMatchesCanonicalImrTree (cmdv2/ncli) fails if the canonical
// tree grows a command that is neither on this tree nor in that list.
func NewImrTree(use, role string) *cobra.Command {
	c := &cobra.Command{
		Use:   use,
		Short: fmt.Sprintf("Interact with the %q tdns-imr instance via its API", role),
		Long: fmt.Sprintf(`Interact with the %q tdns-imr instance via its management API.

This is the same command set as "imr" for everything that talks to the daemon,
targeting a different resolver. The target is the apiservers entry named %q in
the CLI config.`, role, role),
	}
	TagRole(c, role)

	// The stats parent is a copy of the canonical one without its Run, which
	// reports in-process metrics; bare, it just lists its subcommands.
	stats := cloneCmdOnly(ImrStatsCmd, func(name string) bool { return imrInstanceStats[name] })
	stats.Run, stats.RunE = nil, nil
	// The canonical text is about the large-KSK telemetry the instance does
	// not have.
	stats.Long = "Show the transport statistics the daemon reports."

	c.AddCommand(
		NewPingCmd(role),
		NewDaemonCmd(role),
		NewImrConfigCmdFor(role),
		newImrForwardCmd(role),
		newImrStubCmd(role),
		cloneCmdTree(ImrQueryCmd),
		cloneCmdTree(ImrFlushCmd),
		stats,
	)
	// The daemon's access file, managed from its host (tdns-ncli only: the
	// factories are only used for tdns-ncli's instance trees).
	c.AddCommand(NewClientCmd(role))
	return c
}
