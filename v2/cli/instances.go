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
	"reflect"
	"slices"
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

// knownInstanceRoles are the roles an apiservers entry may ask to be wired as:
// the ones with a NewXxxTree factory (auth and agent here; imr registers itself
// from imr_tree.go).
var knownInstanceRoles = map[string]func(use, role string) *cobra.Command{
	"auth":  NewAuthTree,
	"agent": NewAgentTree,
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

// ReadCliClientConf reads the CLI config's client: block from the same merged
// view the CLI itself loads (the main file, its include: files,
// cli.localconfig), or returns the zero value when there is none or it cannot
// be read (the defaults then apply). A client.cert set only in an include or
// the local config is the one the CLI uses, so it is the one checked.
func ReadCliClientConf(cfgFile string) CliClientConf {
	cc, _ := readCliClientConf(cfgFile, nil)
	return cc
}

// readCliClientConf is ReadCliClientConf reading through fs; nil is the real
// file system. It decodes the whole config, as the CLI's own load does
// (viper.Unmarshal in initConfig), not the client: key alone: only that
// applies the environment's leaf overrides (CLIENT.CERT, CLIENT.KEY). A
// config that does not load, a cli.localconfig that does not merge, or a
// client: block that does not decode is an error, with the zero value; a
// config with no client: block is the zero value (the defaults).
func readCliClientConf(cfgFile string, fs afero.Fs) (CliClientConf, error) {
	v, localErr, err := loadCliViper(cfgFile, fs)
	switch {
	case err != nil:
		return CliClientConf{}, err
	case localErr != nil:
		return CliClientConf{}, localErr
	}
	var c struct {
		Client CliClientConf `mapstructure:"client"`
	}
	if err := v.Unmarshal(&c); err != nil {
		return CliClientConf{}, fmt.Errorf("%s: client: %w", cfgFile, err)
	}
	return c.Client, nil
}

// readApiServers is ReadApiServers reading through fs; nil is the real file
// system. `config add --dry-run` passes the real file system with the edited
// file laid over it, so the preview loads exactly what the add would write.
func readApiServers(cfgFile string, fs afero.Fs) ([]ApiDetails, error) {
	v, localErr, err := loadCliViper(cfgFile, fs)
	if err != nil {
		return nil, err
	}
	var entries []ApiDetails
	if err := v.UnmarshalKey("apiservers", &entries); err != nil {
		return nil, fmt.Errorf("%s: apiservers: %w", cfgFile, err)
	}
	return entries, localErr
}

// loadCliViper loads the CLI config the way the full load does (initConfig in
// each binary's root.go): the environment, the main file, its include: files,
// then cli.localconfig merged on top. localErr is a cli.localconfig that is
// there but could not be merged; the view without it is still returned.
func loadCliViper(cfgFile string, fs afero.Fs) (v *viper.Viper, localErr error, err error) {
	v = viper.New()
	if fs != nil {
		v.SetFs(fs)
	}
	// As initConfig does, so a setting the CLI takes from the environment
	// (cli.localconfig among them) is taken from it here too.
	v.AutomaticEnv()
	v.SetConfigFile(cfgFile)
	if err := v.ReadInConfig(); err != nil {
		return nil, nil, err
	}
	if err := tdns.MergeViperIncludes(v, cfgFile); err != nil {
		return nil, nil, err
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
	return v, localErr, nil
}

// instanceVerdict is the outcome of checking one apiservers entry for wiring.
type instanceVerdict struct {
	Entry ApiDetails
	// Canonical: the entry is not an instance. Either it is a role's entry
	// (RoleEntry), reached through the role's built-in tree, or it has no
	// role: and no tree reaches it.
	Canonical bool
	// RoleEntry is the role whose entry this is (its name is the role's
	// entry name), or "".
	RoleEntry string
	// Rename is the name an entry with an old name must have now; such an
	// entry is not used.
	Rename string
	// Wire: an instance tree would be wired for this entry.
	Wire bool
	// Why is the warning text for an entry that will not be used.
	Why string
}

// roleEntryOf is the role whose entry e is, judged against registry (role ->
// clientKey): e's name is that role's clientKey, and e's role: is that role
// or left out. "" when e is no role's entry.
func roleEntryOf(e ApiDetails, registry map[string]string) string {
	for role, key := range registry {
		if key == e.Name && (e.Role == "" || e.Role == role) {
			return role
		}
	}
	return ""
}

// checkInstanceEntries decides, without changing anything, which entries
// become instance trees and why the others do not. WireInstanceTrees acts on
// the answer; `config list` shows it. One function for both, so what the list
// reports is what the wiring does.
//
// registry is the role -> clientKey map to judge names against: the built-in
// roles (builtinRoles), without the instances the wiring registers.
func checkInstanceEntries(root *cobra.Command, entries []ApiDetails, registry map[string]string) []instanceVerdict {
	// The API-client names that are already spoken for: the built-in roles'
	// entries (auth, imr, ...) and every role-less entry. An instance
	// sharing one of these would be the SAME client as that entry:
	// InitApiClients keys tdns.Globals.ApiClients by entry name, so the later
	// of the two silently replaces the earlier and a command meant for one
	// daemon reaches the other.
	clientNames := map[string]bool{}
	for _, ck := range registry {
		clientNames[ck] = true
	}
	canonical := map[string]bool{}
	for _, e := range entries {
		if e.Role == "" && renamedTo(e) == "" {
			canonical[e.Name] = true
		}
	}

	// Instance names accepted by THIS call, so a duplicate can be reported as
	// the duplicate it is rather than as a built-in-role collision.
	claimed := map[string]bool{}
	// Names of the entries that are not instances, as met: a later entry
	// with one of them would be the same client, so the first one wins.
	seen := map[string]bool{}

	out := make([]instanceVerdict, 0, len(entries))
	for _, e := range entries {
		v := instanceVerdict{Entry: e}
		notInstance := e.Role == "" || roleEntryOf(e, registry) != ""
		switch {
		case renamedTo(e) != "":
			v.Rename = renamedTo(e)
			v.Why = fmt.Sprintf("apiservers entry %q: the old name of the %s entry -- entry ignored (rename it to %s)",
				e.Name, v.Rename, v.Rename)
		case notInstance && seen[e.Name]:
			v.Why = fmt.Sprintf("apiservers entry %q: an earlier apiservers entry has the same name -- entry ignored (choose another name)", e.Name)
		case roleEntryOf(e, registry) != "":
			v.Canonical, v.RoleEntry = true, roleEntryOf(e, registry)
			seen[e.Name] = true
		case e.Role == "":
			v.Canonical = true // no role: and no tree's entry
			seen[e.Name] = true
		default:
			v.Why = instanceRefusal(root, e, registry, clientNames, canonical, claimed)
			if v.Why == "" {
				v.Wire = true
				claimed[e.Name] = true
			}
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
	// A name that shadows a built-in role would silently retarget that
	// role's tree, which is the exact failure this feature exists to
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
	if existing := findChild(root, e.Name); existing != nil {
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
// role: and a name of its own, and registers each entry's name as its own
// clientKey.
//
// Returns the problems it declined to act on, for the caller to print. They
// are warnings rather than fatal errors on purpose: a typo in one apiservers
// entry should cost that entry's subcommand, not the whole CLI.
func WireInstanceTrees(root *cobra.Command, entries []ApiDetails) []string {
	var warnings []string
	for _, v := range checkInstanceEntries(root, entries, builtinRoles()) {
		if v.Canonical {
			continue // reached through its built-in tree, or no tree
		}
		if v.Rename != "" {
			// The command, for the CLI config this run reads (its root
			// read --config the same way, to wire the trees at all).
			warnings = append(warnings, fmt.Sprintf("apiservers entry %q is the old name of the %s\nentry, and is ignored. Rename it:\n%s",
				v.Entry.Name, v.Rename, commandLines(ncliFor(ConfigPathFromArgs(os.Args[1:]))+" config update "+shellQuote(v.Entry.Name)+" --rename "+shellQuote(v.Rename), 3)))
			continue
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
		wiredInstances[e.Name] = e
	}
	return warnings
}

// wiredInstances holds the instance entries WireInstanceTrees gave a command
// tree, by name. They and the entries that are not instances are the only
// entries InitApiClients builds clients for.
var wiredInstances = map[string]ApiDetails{}

// clientEntries returns the entries to build API clients for: every entry
// that is not an instance (a role's entry, or one with no role:), and each
// instance entry the wiring gave a command tree, once. An entry with an old
// name gets none: commands that need it say to rename it.
//
// tdns.Globals.ApiClients is keyed by entry name, so a client built for an
// instance the wiring refused can replace the one the name already stands
// for (`tdns-ncli auth ...` then reaching the instance's daemon), or stand in
// for the entry the wiring did accept under that name (two auth2 entries,
// the first refused and the second wired). Only the wiring knows all of its
// decisions (a command collision needs the command tree), so this takes them
// from it rather than deciding again. A binary that wires no instance trees
// (tdns-cli) gets clients for the other entries only: nothing in it reaches
// an instance.
func clientEntries(entries []ApiDetails) []ApiDetails {
	out := make([]ApiDetails, 0, len(entries))
	taken := map[string]bool{}
	builtin := builtinRoles()
	for _, e := range entries {
		switch {
		case renamedTo(e) != "":
			continue
		case e.Role == "" || roleEntryOf(e, builtin) != "":
			// The first entry of a name wins, as in the wiring.
			if !taken[e.Name] {
				taken[e.Name] = true
				out = append(out, e)
			}
			continue
		}
		if w, ok := wiredInstances[e.Name]; ok && !taken[e.Name] && reflect.DeepEqual(w, e) {
			taken[e.Name] = true
			out = append(out, e)
		}
	}
	return out
}

// builtinRoles returns the role -> clientKey registrations that are not
// instances: those WireInstanceTrees did not make.
func builtinRoles() map[string]string {
	out := make(map[string]string, len(roleToClientKey))
	for role, key := range roleToClientKey {
		if _, inst := wiredInstances[role]; !inst {
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
	slices.Sort(names)
	return strings.Join(names, ", ")
}
