/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Discovering extra daemon instances from the CLI config, early enough for
 * cobra to route to them.
 */
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
)

// knownInstanceRoles are the roles an apiservers entry may ask to be wired as.
// Only "auth" for now: it is the only tree with a NewXxxTree factory. Adding
// agent or imr is a matter of writing the equivalent factory.
var knownInstanceRoles = map[string]func(use, role string) *cobra.Command{
	"auth": NewAuthTree,
}

// ConfigPathFromArgs finds the config file the user asked for, WITHOUT running
// cobra's flag parsing.
//
// It has to work this early because instance names are command words: cobra
// resolves the command path in Find(), which runs before PersistentPreRun --
// where the config is normally read. A tree that does not exist by then cannot
// be routed to, so the apiservers list has to be read ahead of Execute().
//
// Deliberately forgiving: an argument shape it does not understand just falls
// back to the default path. The authoritative parse still happens later in the
// normal config load, which reports errors properly; getting this wrong costs
// the instance subcommands, not correctness of anything else.
func ConfigPathFromArgs(args []string) string {
	for i, a := range args {
		if strings.HasPrefix(a, "--config=") {
			return strings.TrimPrefix(a, "--config=")
		}
		if a == "--config" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return tdns.DefaultCliCfgFile
}

// EarlyApiServers reads just the apiservers: block from the CLI config.
//
// Best-effort by design: every failure returns nil rather than terminating.
// Commands that need no config at all (util keys generate, gen-docs, the cert
// subtree) must keep working with no config file present, and this runs before
// we know which command was typed. Real config errors are still reported, by
// the full load in PersistentPreRun.
//
// Goes through viper + MergeViperIncludes rather than a plain yaml read so
// that an apiservers: block living in an include: file is found here exactly
// as it is by the real loader.
func EarlyApiServers(cfgFile string) []ApiDetails {
	v := viper.New()
	v.SetConfigFile(cfgFile)
	if err := v.ReadInConfig(); err != nil {
		return nil
	}
	if err := tdns.MergeViperIncludes(v, cfgFile); err != nil {
		return nil
	}
	// cli.localconfig, merged the same way the full load does (initConfig in
	// each binary's root.go). Skipping it here would mean an apiservers entry
	// that lives ONLY in the local config never becomes a command word: the
	// full load would find it, but far too late -- cobra has already failed to
	// resolve the command path by then, so the operator gets
	// `unknown command "sectdns"` from a config that plainly defines it.
	//
	// Still best-effort: a local config that is named but absent is normal
	// (that is what makes it local), and any error leaves the entries we
	// already have rather than discarding them.
	if local := v.GetString("cli.localconfig"); local != "" {
		if _, err := os.Stat(local); err == nil {
			v.SetConfigFile(local)
			_ = v.MergeInConfig()
		}
	}
	var entries []ApiDetails
	if err := v.UnmarshalKey("apiservers", &entries); err != nil {
		return nil
	}
	return entries
}

// WireInstanceTrees adds one command tree per apiservers entry carrying a
// role:, and registers each entry's name as its own clientKey.
//
// Returns the problems it declined to act on, for the caller to print. They
// are warnings rather than fatal errors on purpose: a typo in one apiservers
// entry should cost that entry's subcommand, not the whole CLI.
func WireInstanceTrees(root *cobra.Command, entries []ApiDetails) []string {
	var warnings []string

	for _, e := range entries {
		if e.Role == "" {
			continue // canonical entry; reached through its built-in tree
		}
		newTree, known := knownInstanceRoles[e.Role]
		if !known {
			warnings = append(warnings, fmt.Sprintf(
				"apiservers entry %q: role %q has no command tree (known: %s) -- entry ignored",
				e.Name, e.Role, knownRoleList()))
			continue
		}
		if e.Name == "" {
			warnings = append(warnings, "apiservers entry with role but no name -- entry ignored")
			continue
		}
		// A name that shadows a built-in role would silently retarget the
		// canonical tree, which is the exact failure this feature exists to
		// prevent. Refuse it.
		if _, taken := roleToClientKey[e.Name]; taken {
			warnings = append(warnings, fmt.Sprintf(
				"apiservers entry %q: name collides with a built-in role -- entry ignored (choose another name)",
				e.Name))
			continue
		}
		if existing := findChild(root, e.Name); existing != nil {
			warnings = append(warnings, fmt.Sprintf(
				"apiservers entry %q: name collides with the existing %q command -- entry ignored (choose another name)",
				e.Name, existing.Name()))
			continue
		}
		// show-cmds is attached AFTER instance wiring -- it walks the tree and
		// gives every node with children its own copy, so it has to see the
		// instance trees. That means findChild above cannot see it, and an
		// instance called "show-cmds" would collide with a command that does
		// not exist yet. Reserve the name explicitly.
		//
		// The caller is responsible for the same problem with cobra's lazily
		// added "help" and "completion": it must call InitDefaultHelpCmd and
		// InitDefaultCompletionCmd before this, so findChild can see them.
		if e.Name == ShowCmdsName {
			warnings = append(warnings, fmt.Sprintf(
				"apiservers entry %q: name is reserved -- entry ignored (choose another name)",
				e.Name))
			continue
		}

		// The instance is addressed by its own name at both levels: the command
		// word IS the role IS the clientKey. One name for the operator to know.
		RegisterRole(e.Name, e.Name)
		root.AddCommand(newTree(e.Name, e.Name))
	}

	return warnings
}

// findChild reports whether root already has a subcommand answering to name,
// as its name or as one of its aliases.
func findChild(root *cobra.Command, name string) *cobra.Command {
	for _, c := range root.Commands() {
		if c.Name() == name || c.HasAlias(name) {
			return c
		}
	}
	return nil
}

func knownRoleList() string {
	names := make([]string, 0, len(knownInstanceRoles))
	for r := range knownInstanceRoles {
		names = append(names, r)
	}
	return strings.Join(names, ", ")
}
