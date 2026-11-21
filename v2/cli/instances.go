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

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
)

// DefaultCliConfigFile is the CLI config read when --config is not given.
//
// A variable rather than the tdns.DefaultCliCfgFile constant because two
// binaries share this package and read two different files: tdns-cli reads
// /etc/tdns/tdns-cli.yaml (this initial value, so it behaves exactly as it
// always did) and tdns-ncli sets it to its own /etc/tdns/tdns-ncli.yaml in its
// own init(), before anything here reads it.
var DefaultCliConfigFile = tdns.DefaultCliCfgFile

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
	return DefaultCliConfigFile
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
	entries, _ := ReadApiServers(cfgFile)
	return entries
}

// ReadApiServers is EarlyApiServers with the errors kept, for the commands
// (config list, config add) whose whole job is to report on the config and so
// must not paper over a broken one.
//
// It reads the effective list, the way the real loader does: the main file,
// then its include: files, then cli.localconfig merged on top. Viper merges
// maps and REPLACES lists, so an apiservers: block in cli.localconfig hides
// the one in the main file entirely, and this returns the one that wins.
//
// A failure merging cli.localconfig returns the entries already read together
// with the error, which is what EarlyApiServers has always done: a broken
// local overlay costs the overlay, not the entries beneath it.
func ReadApiServers(cfgFile string) ([]ApiDetails, error) {
	return readApiServers(cfgFile, nil)
}

// readApiServers is ReadApiServers reading through fs; nil is the real file
// system. `config add --dry-run` passes the real file system with the edited
// file laid over it, so the preview loads exactly what the add would write.
func readApiServers(cfgFile string, fs afero.Fs) ([]ApiDetails, error) {
	v := viper.New()
	if fs != nil {
		v.SetFs(fs)
	}
	// As initConfig does, so a setting the CLI takes from the environment
	// (cli.localconfig among them) is taken from it here too.
	v.AutomaticEnv()
	v.SetConfigFile(cfgFile)
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	if err := tdns.MergeViperIncludes(v, cfgFile); err != nil {
		return nil, err
	}
	// cli.localconfig, merged the same way the full load does (initConfig in
	// each binary's root.go). Skipping it here would mean an apiservers entry
	// that lives ONLY in the local config never becomes a command word: the
	// full load would find it, but far too late -- cobra has already failed to
	// resolve the command path by then, so the operator gets
	// `unknown command "sectdns"` from a config that plainly defines it.
	//
	// A local config that is named but absent is normal (that is what makes it
	// local). One that is there but cannot be read or checked -- a directory
	// on the way that the operator may not enter, say -- stops the full load,
	// so it is an error here too. Either error leaves the entries we already
	// have rather than discarding them.
	var localErr error
	if local := v.GetString("cli.localconfig"); local != "" {
		if _, err := os.Stat(local); err == nil {
			v.SetConfigFile(local)
			if err := v.MergeInConfig(); err != nil {
				localErr = fmt.Errorf("cli.localconfig %s: %w", local, err)
			}
		} else if !os.IsNotExist(err) {
			localErr = fmt.Errorf("cli.localconfig %s: %w", local, err)
		}
	}
	var entries []ApiDetails
	if err := v.UnmarshalKey("apiservers", &entries); err != nil {
		return nil, fmt.Errorf("%s: apiservers: %w", cfgFile, err)
	}
	return entries, localErr
}

// instanceVerdict is the outcome of checking one apiservers entry for wiring.
type instanceVerdict struct {
	Entry ApiDetails
	// Canonical: the entry has no role:, so it is the canonical target of a
	// built-in tree (or of no tree at all) and is not an instance.
	Canonical bool
	// Wire: an instance tree would be wired for this entry.
	Wire bool
	// Why is the warning text for an instance entry that will not be wired.
	Why string
}

// checkInstanceEntries decides, without changing anything, which entries
// become instance trees and why the others do not. WireInstanceTrees acts on
// the answer; `config list` shows it. One function for both, so what the list
// reports is what the wiring does.
//
// registry is the role -> clientKey map to judge names against: the live one
// (roleToClientKey) at wiring time, or builtinRoles() when `config list`
// looks back at the situation before any instance was wired.
func checkInstanceEntries(root *cobra.Command, entries []ApiDetails, registry map[string]string) []instanceVerdict {
	// The API-client names that are already spoken for: the built-in roles'
	// clients (tdns-auth, tdns-imr, ...) and every canonical entry. An
	// instance sharing one of these would be the SAME client as that entry:
	// InitApiClients keys tdns.Globals.ApiClients by entry name, so the later
	// of the two silently replaces the earlier and a command meant for one
	// daemon reaches the other. The role-name check below does not see this,
	// because it compares against role names (auth), not client names
	// (tdns-auth).
	clientNames := map[string]bool{}
	for _, ck := range registry {
		clientNames[ck] = true
	}
	canonical := map[string]bool{}
	for _, e := range entries {
		if e.Role == "" {
			canonical[e.Name] = true
		}
	}

	// Instance names accepted by THIS call, so a duplicate can be reported as
	// the duplicate it is rather than as a built-in-role collision.
	claimed := map[string]bool{}

	out := make([]instanceVerdict, 0, len(entries))
	for _, e := range entries {
		v := instanceVerdict{Entry: e}
		if e.Role == "" {
			v.Canonical = true // reached through its built-in tree
			out = append(out, v)
			continue
		}
		v.Why = instanceRefusal(root, e, registry, clientNames, canonical, claimed)
		if v.Why == "" {
			v.Wire = true
			claimed[e.Name] = true
		}
		out = append(out, v)
	}
	return out
}

// instanceRefusal returns why an instance entry cannot be wired, or "" if it
// can.
func instanceRefusal(root *cobra.Command, e ApiDetails, registry map[string]string, clientNames, canonical, claimed map[string]bool) string {
	if _, known := knownInstanceRoles[e.Role]; !known {
		return fmt.Sprintf(
			"apiservers entry %q: role %q has no command tree (known: %s) -- entry ignored",
			e.Name, e.Role, knownRoleList())
	}
	if e.Name == "" {
		return "apiservers entry with role but no name -- entry ignored"
	}
	// A name that shadows a built-in role would silently retarget the
	// canonical tree, which is the exact failure this feature exists to
	// prevent. Refuse it.
	if _, taken := registry[e.Name]; taken || claimed[e.Name] {
		// Two different collisions land here and the operator needs to be
		// told which: a built-in role (auth/agent/imr), or an earlier
		// apiservers entry that already claimed this name. Reporting the
		// second as "a built-in role" sends them looking for a conflict
		// that is not there.
		what := "a built-in role"
		if claimed[e.Name] {
			what = "an earlier apiservers entry with the same name"
		}
		return fmt.Sprintf(
			"apiservers entry %q: name collides with %s -- entry ignored (choose another name)",
			e.Name, what)
	}
	if clientNames[e.Name] || canonical[e.Name] {
		what := "another apiservers entry"
		if clientNames[e.Name] {
			what = "the API client of a built-in role"
		}
		return fmt.Sprintf(
			"apiservers entry %q: name is the API-client name of %s, so the two would share one client -- entry ignored (choose another name)",
			e.Name, what)
	}
	// root is nil when the question is only which entry owns a name
	// (clientEntries): a command collision refuses every entry of that name
	// alike, so it cannot change the owner.
	if existing := findChildOrNil(root, e.Name); existing != nil {
		return fmt.Sprintf(
			"apiservers entry %q: name collides with the existing %q command -- entry ignored (choose another name)",
			e.Name, existing.Name())
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
		return fmt.Sprintf(
			"apiservers entry %q: name is reserved -- entry ignored (choose another name)",
			e.Name)
	}
	return ""
}

// WireInstanceTrees adds one command tree per apiservers entry carrying a
// role:, and registers each entry's name as its own clientKey.
//
// Returns the problems it declined to act on, for the caller to print. They
// are warnings rather than fatal errors on purpose: a typo in one apiservers
// entry should cost that entry's subcommand, not the whole CLI.
func WireInstanceTrees(root *cobra.Command, entries []ApiDetails) []string {
	var warnings []string
	for _, v := range checkInstanceEntries(root, entries, roleToClientKey) {
		if v.Canonical {
			continue // reached through its built-in tree
		}
		if !v.Wire {
			warnings = append(warnings, v.Why)
			continue
		}
		// The instance is addressed by its own name at both levels: the command
		// word IS the role IS the clientKey. One name for the operator to know.
		e := v.Entry
		RegisterRole(e.Name, e.Name)
		root.AddCommand(knownInstanceRoles[e.Role](e.Name, e.Name))
	}
	return warnings
}

// clientEntries returns the entries to build API clients for: every canonical
// entry, and every instance entry the wiring accepts (checkInstanceEntries,
// the same rules and the same order).
//
// tdns.Globals.ApiClients is keyed by entry name, so a client built for an
// instance the wiring refused can replace the one the name already stands
// for (`tdns-ncli auth ...` then reaching the instance's daemon), or stand in
// for the entry the wiring did accept under that name: with two auth2 entries
// where the wiring refuses the first and wires the second, the client must be
// the second's, or the auth2 tree drives the first one's daemon. Asking
// checkInstanceEntries, not a copy of its rules, keeps the two from
// disagreeing.
//
// registry is the built-in role -> clientKey map, builtinRoles(): the
// instances wired so far are registered as name -> name and are not built-in
// clients.
func clientEntries(entries []ApiDetails, registry map[string]string) []ApiDetails {
	out := make([]ApiDetails, 0, len(entries))
	for _, v := range checkInstanceEntries(nil, entries, registry) {
		if v.Canonical || v.Wire {
			out = append(out, v.Entry)
		}
	}
	return out
}

// findChildOrNil is findChild, with no root meaning no command.
func findChildOrNil(root *cobra.Command, name string) *cobra.Command {
	if root == nil {
		return nil
	}
	return findChild(root, name)
}

// builtinRoles returns the role -> clientKey registrations that are not
// instances. WireInstanceTrees registers each instance as RegisterRole(n, n),
// the one shape no built-in role has (auth -> tdns-auth), which is how the two
// are told apart.
func builtinRoles() map[string]string {
	out := make(map[string]string, len(roleToClientKey))
	for role, key := range roleToClientKey {
		if role != key {
			out[role] = key
		}
	}
	return out
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
