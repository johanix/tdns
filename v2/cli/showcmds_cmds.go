/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
)

// ShowCmdsName is the name of the command-tree lister. Exported so the
// binaries' PersistentPreRun can recognize it and skip config/API setup:
// show-cmds only inspects the in-memory cobra tree, so it must work with
// no daemon running and no tdns-cli.yaml present.
const ShowCmdsName = "show-cmds"

// showCmdsEntry is one line of output: the full invocation path plus the
// command's own Short text (only printed with --desc).
type showCmdsEntry struct {
	path  string
	short string
}

// NewShowCmdsCmd returns a fresh "show-cmds" command. Each attachment site
// needs its own instance -- cobra stores the parent pointer in the command
// itself, so a single shared instance cannot hang off several parents.
//
// The command needs no role argument: it reports on whatever subtree it was
// attached to, found at run time via cmd.Parent(). "tdns-cli auth show-cmds"
// lists the auth subtree, "tdns-cli show-cmds" lists everything.
func NewShowCmdsCmd() *cobra.Command {
	var withDesc, showAll bool
	var maxDepth int

	cmd := &cobra.Command{
		Use:   ShowCmdsName,
		Short: "List the whole command tree below this command, one line per command",
		Long: `List every command below this point in the tree, one per line, as a
full invocation path.

Unlike -h, which only shows the immediate children of one command, this
walks the entire subtree, so the output is greppable and every line can be
copied and run as-is.

show-cmds exists on every command that has subcommands, but is only listed
in -h at the top level and under each application prefix; deeper down it is
hidden to keep the help screens clean. It still works there, e.g.
"tdns-cli auth keystore dnssec show-cmds".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// 0 is the documented sentinel for "no limit". A negative value
			// would quietly mean the same thing, turning a typo into a full
			// 300-line dump instead of an error.
			if maxDepth < 0 {
				return fmt.Errorf("--depth must be 0 or greater, got %d", maxDepth)
			}

			// The subtree to report on is our parent, not us. A show-cmds
			// with no parent (never wired up) degenerates to itself, which
			// is empty but not a crash.
			root := cmd.Parent()
			if root == nil {
				root = cmd
			}

			entries := collectShowCmds(root, 1, maxDepth, showAll)
			fmt.Printf("%s has the following command structure:\n\n", root.CommandPath())

			width := 0
			if withDesc {
				for _, e := range entries {
					if len(e.path) > width {
						width = len(e.path)
					}
				}
			}
			for _, e := range entries {
				if withDesc && e.short != "" {
					fmt.Printf("%-*s   %s\n", width, e.path, e.short)
					continue
				}
				fmt.Printf("%s\n", e.path)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&withDesc, "desc", false,
		"append each command's short description, column-aligned")
	cmd.Flags().BoolVar(&showAll, "all", false,
		"also list hidden and deprecated commands")
	cmd.Flags().IntVar(&maxDepth, "depth", 0,
		"only descend N levels below this command (0 = no limit)")

	return cmd
}

// collectShowCmds walks cmd's children depth-first, in name order, returning
// one entry per command. depth is the level of cmd's children relative to the
// subtree root (1 for the root's own children); maxDepth of 0 means no limit.
func collectShowCmds(cmd *cobra.Command, depth, maxDepth int, showAll bool) []showCmdsEntry {
	if maxDepth > 0 && depth > maxDepth {
		return nil
	}

	kids := append([]*cobra.Command(nil), cmd.Commands()...)
	sort.Slice(kids, func(i, j int) bool { return kids[i].Name() < kids[j].Name() })

	var entries []showCmdsEntry
	for _, c := range kids {
		if skipInShowCmds(c, showAll) {
			continue
		}
		entries = append(entries, showCmdsEntry{path: c.CommandPath(), short: c.Short})
		entries = append(entries, collectShowCmds(c, depth+1, maxDepth, showAll)...)
	}
	return entries
}

// skipInShowCmds reports whether c should be left out of the listing.
func skipInShowCmds(c *cobra.Command, showAll bool) bool {
	// Never list show-cmds itself: it is the command being run, it exists on
	// every parent, and listing ~60 copies of it would drown out the tree.
	if c.Name() == ShowCmdsName {
		return true
	}
	// cobra's own scaffolding, not part of the tdns command surface.
	if c.Name() == "help" || c.Name() == "completion" {
		return true
	}
	if showAll {
		return false
	}
	return c.Hidden || c.Deprecated != ""
}

// AttachShowCmds hangs a show-cmds on root and on every descendant that has
// subcommands. Call it once, after all AddCommand wiring is done (i.e. from
// the binary's Execute path, not from an init(), where file ordering would
// decide whether the tree is complete yet).
//
// Only the copies at the top level and directly under an application prefix
// ("tdns-cli show-cmds", "tdns-cli auth show-cmds") are listed in -h. Deeper
// copies are marked Hidden so that ~60 help screens don't each grow a line
// for it; they remain fully usable, and are documented in the Long text above.
//
// Calling this more than once on the same tree is safe: cobra's AddCommand
// does not deduplicate, so without a guard a second call would give every
// parent a second show-cmds child.
func AttachShowCmds(root *cobra.Command) {
	attachShowCmds(root, 0)
}

func attachShowCmds(cmd *cobra.Command, depth int) {
	if !cmd.HasSubCommands() {
		return
	}

	// Snapshot the children before adding, so we recurse over the original
	// set and not into the show-cmds we are about to add.
	kids := append([]*cobra.Command(nil), cmd.Commands()...)

	if !hasShowCmdsChild(kids) {
		sc := NewShowCmdsCmd()
		sc.Hidden = depth >= 2
		cmd.AddCommand(sc)
	}

	for _, c := range kids {
		switch c.Name() {
		case ShowCmdsName, "help", "completion":
			continue
		}
		attachShowCmds(c, depth+1)
	}
}

// hasShowCmdsChild reports whether a show-cmds is already among these
// commands, i.e. whether this parent has been attached to before.
func hasShowCmdsChild(kids []*cobra.Command) bool {
	for _, c := range kids {
		if c.Name() == ShowCmdsName {
			return true
		}
	}
	return false
}
