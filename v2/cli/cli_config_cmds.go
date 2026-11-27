/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * `tdns-ncli config add|update|list`: maintaining the CLI's own list of daemons
 * (apiservers:) from the daemons' config files.
 */
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ryanuber/columnize"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

// cliConfigAnnotation marks the root-level `config` command. The binary's
// PersistentPreRun asks IsCliConfigCmd whether to skip loading the CLI config
// and building API clients: these commands read and edit that file themselves,
// and `config add` has to work when it does not exist yet.
const cliConfigAnnotation = "tdns.cli-config"

// IsCliConfigCmd reports whether cmd is, or sits under, the CLI-config
// command created by NewCliConfigCmd.
func IsCliConfigCmd(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Annotations[cliConfigAnnotation] == "1" {
			return true
		}
	}
	return false
}

// NoCliConfigNeeded says whether cmd can run without the CLI config at
// cliConfig, which the binary's PersistentPreRun otherwise loads (and stops
// without): when it was given --daemon-config (the client commands, config
// reload), which names the daemon itself, and the file does not exist. That
// is how root reaches a daemon on a host where it has no CLI config yet.
// With the file there, it is loaded as always. An empty --daemon-config (an
// unset shell variable) names no daemon: it is as if not given.
func NoCliConfigNeeded(cmd *cobra.Command, cliConfig string) bool {
	f := cmd.Flags().Lookup("daemon-config")
	if f == nil || !f.Changed || f.Value.String() == "" {
		return false
	}
	_, err := os.Stat(cliConfig)
	return errors.Is(err, os.ErrNotExist)
}

// NewCliConfigCmd builds `config`, with `add`, `update`, `list` and `check`.
//
// Not to be confused with `<daemon> config check`, which checks a DAEMON's
// config. This is about the CLI's own: which daemons it addresses.
func NewCliConfigCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Maintain the CLI's own list of daemons and instances",
		Long: `Maintain the CLI's own config: the apiservers: list that says which daemons
(and which instances of a daemon) this CLI addresses.

This is not "<daemon> config check", which checks a daemon's config.`,
		Annotations: map[string]string{cliConfigAnnotation: "1"},
	}
	c.AddCommand(newConfigAddCmd(), newConfigUpdateCmd(), newConfigListCmd(), newConfigCheckCliCmd())
	return c
}

// cliConfigPath is the CLI config the user asked for with --config, or the
// binary's default.
func cliConfigPath(cmd *cobra.Command) string {
	if f := cmd.Flags().Lookup("config"); f != nil && f.Value.String() != "" {
		return f.Value.String()
	}
	return DefaultCliConfigFile
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}

// ---------------------------------------------------------------- config add

func newConfigAddCmd() *cobra.Command {
	var o AddOptions
	c := &cobra.Command{
		Use:   "add <daemon-config.yaml>",
		Short: "Add the daemon described by a daemon config file to the CLI config",
		Long: `Reads a daemon's own config (tdns-auth, tdns-agent or tdns-imr) and adds
one apiservers: entry for that daemon to the CLI config. Run it as root on
the daemon's host: it asks the daemon over its local admin socket.

  tdns-ncli config add /etc/tdns/tdns-auth2.yaml

The daemon type comes from service.name (or, for tdns-imr, from having an
imrengine: block and no service: block), and failing that from the file
name; --role overrides it. An entry's name is the command word that
reaches it. The first daemon of a type is named after the type ("auth",
"agent", "imr": tdns-ncli auth ...). Any further one is named after the
file (tdns-auth2.yaml -> auth2) unless --name says otherwise, reached as
"tdns-ncli auth2 ...".

A running daemon takes remote clients once its access file is there:
<config dir>/<config name>-access.yaml, or apiserver.access-file. The
daemon never creates it; if it is missing, config add says how (touch).
Your client certificate is made if you have none (as client init does),
the daemon adds its pin to its access file as --client-name (read-write),
and one request over TCP checks it. Only then is the entry written: the
TCP address, the pins of the daemon's certificate and config-file:.

A stopped daemon, or one with no TCP address, gets an entry with
config-file: only, through which root reaches its local admin socket.
Once a stopped daemon is up, "config update <entry> --cert" gives the
entry its address and your certificate.

An entry for the daemon that is already there is left alone; "config
update" changes it. The CLI config is created, mode 0600, if it does not
exist.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			o.Ctx = cmd.Context()
			o.DaemonConfig = args[0]
			o.CliConfig = cliConfigPath(cmd)
			root := cmd.Root()
			o.CommandWordTaken = func(n string) bool { return findChild(root, n) != nil }

			res, err := AddDaemonConfig(o)
			if err != nil {
				fatalf("%v", err)
			}
			printAddResult(os.Stdout, res, o.DryRun, o.CliConfig)
		},
	}
	c.Flags().StringVar(&o.Role, "role", "", "daemon type: auth, agent or imr (default: detect from the daemon config)")
	c.Flags().StringVar(&o.Name, "name", "", "name (and command word) for the entry (default: from the file name)")
	c.Flags().StringVar(&o.ClientName, "client-name", "", "your name in the daemon's access file (default: user-host, as client init)")
	c.Flags().StringVar(&o.TargetFile, "file", "", "file to add the entry to, if the apiservers: list is not in the CLI config itself (an include or cli.localconfig)")
	c.Flags().BoolVar(&o.DryRun, "dry-run", false, "show what would be done; enrol nothing, change nothing")
	return c
}

// AddOptions is the input to AddDaemonConfig.
type AddOptions struct {
	// Ctx ends the wait for another add's lock (Ctrl-C). Nil means no end.
	Ctx context.Context
	// CliConfig is the CLI config to add to.
	CliConfig string
	// TargetFile is the file to edit when the apiservers: list lives in a file
	// other than CliConfig itself. Empty means CliConfig.
	TargetFile string
	// DaemonConfig is the daemon config file to read.
	DaemonConfig string
	// Role overrides the daemon-type detection.
	Role string
	// Name overrides the derived entry name.
	Name string
	// ClientName is the operator's name in the daemon's access file; empty
	// means defaultClientName.
	ClientName string
	// DryRun asks the daemon what it runs, and enrols and writes nothing.
	DryRun bool
	// CommandWordTaken reports whether a name is already a command of the CLI.
	// Optional; without it only the names in the config and the registry count.
	CommandWordTaken func(name string) bool
}

// AddResult describes what AddDaemonConfig did.
type AddResult struct {
	// Entry is the entry added (or that would be).
	Entry ApiDetails
	// Canonical: Entry is a built-in role's entry (named after the role),
	// not an instance.
	Canonical bool
	// AlreadyKnown is the name of the existing entry for this daemon; when set
	// nothing was added.
	AlreadyKnown string
	// Update is the config update command to run: for the entry AlreadyKnown
	// names, or for a stopped daemon's entry once the daemon is up. "" when
	// there is none.
	Update string
	// Running: the daemon answered on its local admin socket.
	Running bool
	// Steps say what was done to set up the client certificate (with
	// DryRun, what would be).
	Steps []string
	// File is the file the entry was (or would be) added to.
	File string
	// Created: File did not exist and was created.
	Created bool
	// Wrote: the file was changed.
	Wrote bool
	// Notes are things the operator should know.
	Notes []string
	// AccessMissing is the access file of a stopped daemon that is not
	// there: config update --cert needs it.
	AccessMissing string
}

var addableRoles = map[string]bool{"auth": true, "agent": true, "imr": true}

const newCliConfigHeader = "# tdns-ncli configuration.\n# apiservers: lists the daemons (and instances of a daemon) tdns-ncli addresses;\n# `tdns-ncli config add <daemon-config.yaml>` adds to it. An entry's name is\n# the command word that reaches it.\n\n"

// AddDaemonConfig adds one apiservers: entry for the daemon whose config is
// o.DaemonConfig to the CLI config (design 2026-11-25 section 4). A running
// daemon gets a certificate entry: the operator's pin enrolled over the
// local admin socket and checked over TCP before anything is written. A
// stopped one, or one with no TCP address, gets the config-file:-only
// entry. An entry already there for the daemon is left alone.
//
// Each step leaves a state that is valid on its own, so nothing is undone:
// the one leftover is an enrolled pin with no entry, which the next run
// reuses. Only the CLI config is locked, and only for its own edit.
func AddDaemonConfig(o AddOptions) (*AddResult, error) {
	if o.Role != "" && !addableRoles[o.Role] {
		return nil, fmt.Errorf("--role must be one of auth, agent, imr (got %q)", o.Role)
	}
	info, err := ReadDaemonApi(o.DaemonConfig, o.Role)
	if err != nil {
		return nil, err
	}
	if err := needSocket(info, "config add"); err != nil {
		return nil, err
	}
	res := &AddResult{Notes: append([]string(nil), info.Warnings...)}
	tcpURL, notes, err := daemonTCP(info)
	if err != nil {
		return nil, err
	}
	res.Notes = append(res.Notes, notes...)
	target := o.TargetFile
	if target == "" {
		target = o.CliConfig
	}
	if err := danglingSymlink(target); err != nil {
		return nil, err
	}

	// The entry for this daemon, if there is one, and the new one's name,
	// from what is in the CLI config: before the daemon is asked anything,
	// and again under the lock before the write.
	entry := ApiDetails{ConfigFile: info.ConfigFile}
	nNotes := len(res.Notes)
	plan := func() (existing []ApiDetails, known bool, err error) {
		existing, missing, err := cliEntries(o.CliConfig)
		if err != nil {
			return nil, false, err
		}
		res.Notes, res.Canonical, entry.Name, entry.Role = res.Notes[:nNotes], false, "", ""
		if known, err = knownEntry(o, res, existing, info, tcpURL); err != nil || known {
			return nil, known, err
		}
		// Compared resolved, as the locks are: --config and --file may name
		// the one (missing) CLI config through two aliases of its directory.
		res.Created = missing && resolvedPath(target) == resolvedPath(o.CliConfig)
		return existing, false, chooseEntryName(&entry, res, info.Role, existing, o)
	}
	existing, known, err := plan()
	if err != nil || known {
		return res, err
	}

	// Running? Its socket answers /access list, naming its config.
	// Stopped: the config-file:-only entry.
	sock, list, running, err := askAccess(info, "config add")
	if err != nil {
		return nil, err
	}
	res.Running = running
	cert := res.Running && tcpURL != ""
	if cert {
		if err := daemonReady(info, list, tcpURL, true, retryAdd(o, o.ClientName)); err != nil {
			return nil, err
		}
		entry.BaseURL, entry.Pins = tcpURL, list.ServerPins
	}
	if !res.Running && tcpURL != "" {
		if _, err := os.Stat(info.AccessFile); errors.Is(err, fs.ErrNotExist) {
			res.AccessMissing = info.AccessFile
		}
	}
	// The pair is the one the CLI config will name once written: a
	// cli.localconfig with its own client: block counts, also when the
	// CLI config is not there yet (prospectiveClientConf).
	var cc CliClientConf
	if cert {
		out, err := renderAdd(o, target, existing, entry, res.Created)
		if err != nil {
			return nil, err // refused before the enrolment: a hidden list, a flow style
		}
		if cc, err = prospectiveClientConf(o.CliConfig, target, out); err != nil {
			return nil, err
		}
	}
	client := o.ClientName
	if client == "" {
		client = defaultClientName()
	}
	// After the enrolment every failure says the pin stays enrolled: each
	// step leaves a valid state, and the next run reuses the pin.
	enrolled := false
	keep := func(err error) error {
		if enrolled && err != nil {
			return fmt.Errorf("%v.\nThe pin stays enrolled; the next config add reuses it", err)
		}
		return err
	}
	switch {
	case o.DryRun && cert:
		res.Steps = enrolPlan(cc, client, tcpURL)
	case cert:
		if err := enrol(sock, cc, client, "config add", retryAdd(o, client), &entry, &res.Steps); err != nil {
			return nil, err
		}
		enrolled = true
	}
	if !o.DryRun {
		unlock, err := lockEdit(o.Ctx, o.CliConfig, target)
		if err != nil {
			return nil, keep(err)
		}
		defer unlock()
		existing, known, err = plan()
		switch {
		case err != nil:
			return nil, keep(err)
		case known && enrolled:
			res.Notes = append(res.Notes, fmt.Sprintf(
				"your pin was enrolled as %s just now; the entry that\nappeared meanwhile was left alone", client))
			return res, nil
		case known:
			return res, nil
		}
	}
	out, err := renderAdd(o, target, existing, entry, res.Created)
	if err != nil {
		return nil, keep(err)
	}
	// The pin enrolled is this pair's; the entry is used with whatever pair
	// the config written names: checked on that config, under the lock.
	if enrolled {
		if err := samePair(o.CliConfig, target, out, cc, client, "config add", retryAdd(o, client)); err != nil {
			return nil, err
		}
	}
	res.Entry, res.File = entry, target
	if !res.Running && tcpURL != "" {
		res.Update = fmt.Sprintf("%s config update %s --cert", ncliFor(o.CliConfig), shellQuote(entry.Name))
	}
	if o.DryRun {
		return res, nil
	}
	if err := writeFileAtomic(target, out); err != nil {
		return nil, keep(err)
	}
	res.Wrote = true
	return res, nil
}

// chooseEntryName fills in entry.Name and entry.Role. The first daemon of
// a role is named after the role (its clientKey: auth); any further one
// after its config file, or --name.
func chooseEntryName(entry *ApiDetails, res *AddResult, role string, existing []ApiDetails, o AddOptions) error {
	roleName := roleToClientKey[role] // auth, agent, imr
	if roleName == "" {
		roleName = role
	}
	used := map[string]bool{}
	oldHolder := "" // an entry with the old name of this role's entry
	for _, e := range existing {
		used[e.Name] = true
		if renamedTo(e) == roleName {
			oldHolder = e.Name
		}
	}
	taken := func(n string) bool {
		if used[n] || n == ShowCmdsName || n == "help" || n == "completion" {
			return true
		}
		if _, ok := roleToClientKey[n]; ok {
			return true
		}
		for _, ck := range roleToClientKey {
			if ck == n {
				return true
			}
		}
		if _, old := oldEntryNames[n]; old {
			return true
		}
		return o.CommandWordTaken != nil && o.CommandWordTaken(n)
	}

	// An entry with the old name holds this role's entry until it is
	// renamed: a second one for it would be one daemon too many.
	oldNameRefusal := func() error {
		return fmt.Errorf("the CLI config has an entry with the old name %q:\nrename it first, then run this again:\n%s",
			oldHolder, commandLines(ncliFor(o.CliConfig)+" config update "+shellQuote(oldHolder)+" --rename "+shellQuote(roleName), 3))
	}
	asRoleEntry := func() {
		entry.Name, entry.Role = roleName, role
		res.Canonical = true
	}
	asInstance := func(name string) error {
		if _, ok := knownInstanceRoles[role]; !ok {
			return fmt.Errorf("a %s entry already exists, and tdns-ncli has no command tree for a second %s instance yet (it has one for: %s)",
				roleName, role, knownRoleList())
		}
		entry.Name, entry.Role = name, role
		return nil
	}

	switch {
	case (o.Name == "" || o.Name == roleName) && !used[roleName] && oldHolder != "":
		return oldNameRefusal()
	case o.Name == "" && !used[roleName]:
		asRoleEntry()
	case o.Name == "":
		base := deriveInstanceName(o.DaemonConfig)
		if base == "" || base == roleName {
			base = role
		}
		name := freeName(base, taken)
		// freeName can push a derived name past what a command word may be
		// (a 32-character name that is taken gets a digit appended). --name is
		// checked below; the derived name must be held to the same rule.
		if !validInstanceName(name) {
			return fmt.Errorf("the name derived from the file name, %q, is not usable (lower-case letters, digits and hyphens, starting with a letter, at most 32 characters); choose one with --name", name)
		}
		if name != base {
			res.Notes = append(res.Notes, fmt.Sprintf("the name %q is taken; using %q (--name chooses another)", base, name))
		}
		return asInstance(name)
	default:
		if !validInstanceName(o.Name) {
			return fmt.Errorf("--name %q is not usable: lower-case letters, digits and hyphens, starting with a letter, at most 32 characters", o.Name)
		}
		if o.Name == roleName && !used[roleName] {
			asRoleEntry()
			return nil
		}
		if taken(o.Name) {
			return fmt.Errorf("--name %q is already in use (by an apiservers entry, a built-in role or a command)", o.Name)
		}
		return asInstance(o.Name)
	}
	return nil
}

func sameEntries(a, b []ApiDetails) bool {
	return reflect.DeepEqual(a, b)
}

// cliEntries is the CLI config's apiservers: list, and whether the file is
// not there yet. One that exists but does not load cleanly is not one to
// edit.
func cliEntries(cfg string) (existing []ApiDetails, missing bool, err error) {
	if _, err := os.Stat(cfg); err != nil {
		if !os.IsNotExist(err) {
			return nil, false, err
		}
		return nil, true, nil
	}
	if existing, err = ReadApiServers(cfg); err != nil {
		return nil, false, fmt.Errorf("cannot read the CLI config %s: %w", cfg, err)
	}
	return existing, false, nil
}

// knownEntry looks in existing for an entry for the daemon of info: by its
// config file (resolved, so a symlink to it is the same daemon), or by its
// TCP address. When there is one it is left alone: res names it and the
// config update command that would change it, if any. Two daemons that
// such an entry would confuse are an error.
func knownEntry(o AddOptions, res *AddResult, existing []ApiDetails, info *DaemonApi, tcpURL string) (bool, error) {
	// Every address the daemon listens on identifies it, not only the
	// first, which a new entry uses.
	addrs := map[string]bool{}
	for _, a := range info.Addresses {
		if u, err := apiBaseURL(a); err == nil {
			addrs[hostPort(u)] = true
		}
	}
	for _, e := range existing {
		sameFile := e.ConfigFile != "" && resolvedPath(e.ConfigFile) == resolvedPath(info.ConfigFile)
		// No TCP address: the entry reaches the daemon over its socket,
		// through config-file: (or, written before that, a unix:// baseurl).
		noTCP := e.BaseURL == "" || isUnixURL(e.BaseURL)
		hp := hostPort(e.BaseURL)
		sameAddr := hp != "" && addrs[hp]
		switch {
		case sameFile && (sameAddr || noTCP):
		case sameFile:
			return false, fmt.Errorf("entry %q already points at %s but with a different API address (%s, the config says %q); edit or remove that entry by hand",
				e.Name, info.ConfigFile, e.BaseURL, tcpURL)
		case e.ConfigFile == "" && (sameAddr || entryIsDaemonSocket(e, info)):
			// Typically the canonical entry written before config-file:
			// existed, by its TCP address or its unix:// socket.
		case sameAddr:
			return false, fmt.Errorf("entry %q (config-file %s) already uses the API address %s, which %s also names; two daemons cannot listen on one address",
				e.Name, e.ConfigFile, e.BaseURL, info.ConfigFile)
		default:
			continue
		}
		res.AlreadyKnown = e.Name
		flag := "--cert" // no pins, or no address yet
		switch {
		case noTCP && tcpURL == "" && renamedTo(e) == "":
			return true, nil // the socket is all there is
		case noTCP && tcpURL == "":
			flag = ""
		case usesCert(e):
			flag = "--repin"
		}
		if n := renamedTo(e); n != "" {
			flag = strings.TrimSpace("--rename " + shellQuote(n) + " " + flag)
		}
		if e.ConfigFile == "" && flag != "" && !strings.HasPrefix(flag, "--rename") {
			flag += " --daemon-config " + shellQuote(info.ConfigFile)
		}
		res.Update = fmt.Sprintf("%s config update %s %s", ncliFor(o.CliConfig), shellQuote(e.Name), flag)
		return true, nil
	}
	return false, nil
}

// needSocket refuses a daemon that serves no local admin socket: cmd
// (config add, config update) sets up certificates through it.
func needSocket(info *DaemonApi, cmd string) error {
	if info.Socket == "" {
		why := "socket: none"
		if info.SocketError != "" {
			why = info.SocketError
		}
		return fmt.Errorf("%s serves no local admin socket:\n%s.\n%s needs it, run as root on the daemon's host:\ncertificate setup goes through the socket", info.ConfigFile, why, cmd)
	}
	return nil
}

// daemonTCP is the base URL of the daemon's TCP API, its first address, or
// "" when it has none; notes say when it lists more than one.
func daemonTCP(info *DaemonApi) (tcpURL string, notes []string, err error) {
	if len(info.Addresses) == 0 {
		return "", nil, nil
	}
	if tcpURL, err = apiBaseURL(info.Addresses[0]); err != nil {
		return "", nil, fmt.Errorf("%s: %w", info.ConfigFile, err)
	}
	if len(info.Addresses) > 1 {
		notes = append(notes, fmt.Sprintf(
			"apiserver.addresses lists %d addresses (%s); using the first",
			len(info.Addresses), strings.Join(info.Addresses, ", ")))
	}
	return tcpURL, notes, nil
}

// askAccess asks the daemon of info what is in force (/access list) over
// its local admin socket, which names its config. running is false, and err
// nil, when no daemon answers there. cmd names the command in a refusal.
func askAccess(info *DaemonApi, cmd string) (sock *tdns.ApiClient, list tdns.AccessResponse, running bool, err error) {
	if sock, err = socketClientOf(info); err != nil {
		return nil, list, false, err
	}
	list, err = accessOver(sock, tdns.AccessPost{Command: "list"})
	errno := socketErrno(err)
	stopped, lerr := refusedSocketStopped(errno, info.Socket)
	switch {
	case lerr != nil:
		return nil, list, false, fmt.Errorf("cannot look at the daemon's local admin socket\n   %s\n(%v). %s needs it: run it as root on the\ndaemon's host", info.Socket, pathCause(lerr), cmd)
	case errno == syscall.ENOTSOCK || errno == syscall.ECONNREFUSED && !stopped:
		// A file that is not a socket: the BSDs say ENOTSOCK, Linux
		// ECONNREFUSED. No daemon can serve its socket there, so this is
		// not a stopped daemon.
		return nil, list, false, fmt.Errorf("the daemon's local admin socket path is there but is\nnot a socket:\n   %s\nThe daemon cannot serve its socket there. Remove that\nfile, start the daemon, and run %s again", info.Socket, cmd)
	case errno == syscall.ENOENT || errno == syscall.ECONNREFUSED:
		return sock, list, false, nil
	case errno != 0:
		return nil, list, false, fmt.Errorf("cannot open the daemon's local admin socket %s\n(%v). %s needs it: run it as root on the\ndaemon's host", info.Socket, errno, cmd)
	case err != nil:
		return nil, list, false, err
	case list.Error:
		return nil, list, false, errors.New(list.ErrorMsg)
	}
	return sock, list, true, nil
}

// daemonReady refuses a running daemon whose pins there is no taking: no
// TCP API, or no certificate served on it. For a certificate (cert) also
// one with no access file: the refusal names the file, how to create it,
// and retry, the command to run again then.
func daemonReady(info *DaemonApi, list tdns.AccessResponse, tcpURL string, cert bool, retry string) error {
	switch {
	case tcpURL == "":
		return fmt.Errorf("%s lists no apiserver.addresses: the\ndaemon has no TCP API to reach with pins", info.ConfigFile)
	case cert && list.Missing:
		path := list.File
		if path == "" {
			path = info.AccessFile
		}
		return accessFileMissing(path, "tdns-"+info.Role, retry)
	case len(list.ServerPins) == 0:
		return fmt.Errorf("the daemon serves no certificate on its TCP API (is it\nlistening on %s?), so there is nothing to pin", info.Addresses[0])
	}
	return nil
}

// accessFileMissing is the refusal for a daemon without its access file:
// the file, how to create it, and retry, the command to run again then.
func accessFileMissing(path, daemon, retry string) error {
	return fmt.Errorf("access file %s is missing, so\n%s takes no remote clients. Create it (empty is fine):\n%s\nthen run this again:\n%s",
		path, daemon, commandLines("touch "+shellQuote(path), 3), commandLines(retry, 3))
}

// commandLines is cmd as printed for the operator to run, indented by
// indent: on one line when it fits in 72 columns, indent included; else
// broken between flags, with a trailing backslash, so that it still runs as
// pasted.
func commandLines(cmd string, indent int) string {
	pad := strings.Repeat(" ", indent)
	if indent+len(cmd) <= 72 {
		return pad + cmd
	}
	parts := strings.Split(cmd, " --")
	// The first flag stays with the program: a line of the program's name
	// alone says nothing.
	if len(parts) > 1 {
		parts = append([]string{parts[0] + " --" + parts[1]}, parts[2:]...)
	}
	lines := []string{pad + parts[0]}
	cont := pad + "   "
	for _, p := range parts[1:] {
		w := "--" + p
		last := &lines[len(lines)-1]
		if len(*last)+1+len(w)+2 <= 72 {
			*last += " " + w
			continue
		}
		*last += " \\"
		lines = append(lines, cont+w)
	}
	return strings.Join(lines, "\n")
}

// usesCert says whether e reaches its daemon over https with pins: config
// update --repin changes those.
func usesCert(e ApiDetails) bool {
	return len(e.Pins) > 0 && strings.HasPrefix(strings.ToLower(e.BaseURL), "https://")
}

// enrolPlan is what enrol would do, for a dry run.
func enrolPlan(cc CliClientConf, client, url string) []string {
	certPath, _ := clientCertPaths(cc)
	verb := "use"
	if _, err := os.Stat(certPath); err != nil {
		verb = "make"
	}
	return []string{verb + " your client certificate " + certPath,
		"have the daemon add its pin as " + client + " (read-write)",
		"check one request over TCP to " + url}
}

// retryAdd is o's config add, enrolling as client (if set), as the command
// line to run it again: a refusal gives it to copy.
func retryAdd(o AddOptions, client string) string {
	c := ncliFor(o.CliConfig) + " config add"
	if o.Role != "" {
		c += " --role " + shellQuote(o.Role)
	}
	if o.Name != "" {
		c += " --name " + shellQuote(o.Name)
	}
	if o.TargetFile != "" {
		c += " --file " + shellQuote(o.TargetFile)
	}
	if client != "" {
		c += " --client-name " + shellQuote(client)
	}
	return c + " " + shellQuote(o.DaemonConfig)
}

// enrol is steps 1 to 3 of a running daemon's certificate entry: the
// operator's client pair, made if there is none; its pin added by the
// daemon over its local admin socket sock; one request over TCP with it and
// the server pins. A refusal or a failed request stops cmd before anything
// is written. The pin stays enrolled after a failed request; the next run
// reuses it ("already there").
func enrol(sock *tdns.ApiClient, cc CliClientConf, client, cmd, retry string, entry *ApiDetails, steps *[]string) error {
	certPath, keyPath := clientCertPaths(cc)
	pin, made, err := ensureClientCert(certPath, keyPath, client)
	if err != nil {
		return err
	}
	if made {
		*steps = append(*steps, "Made your client certificate "+certPath)
	}
	ans, err := accessOver(sock, tdns.AccessPost{Command: "add", Name: client, Pin: pin,
		Role: "read-write", Comment: "tdns-ncli " + cmd})
	switch {
	case err != nil:
		// The daemon may have added it and lost the answer.
		return fmt.Errorf("%v\nNo answer that the daemon added your pin; nothing was\nwritten. Run it again, which reuses a pin added:\n%s", err, commandLines(retry, 3))
	case ans.Error:
		// A refusal, or a pin written to the access file but not loaded.
		return fmt.Errorf("the daemon refused or did not load your pin; nothing was written:\n%s\nIf it says the file was written, fix that and run this again,\nwhich reuses the pin:\n%s", ans.ErrorMsg, commandLines(retry, 3))
	}
	said := "The daemon: " + strings.ReplaceAll(ans.Msg, "\n", "\n   ")
	*steps = append(*steps, said)
	if len(ans.ServerPins) > 0 {
		entry.Pins = ans.ServerPins
	}
	ok, err := tcpCheck(*entry, cc)
	if err != nil {
		// What the daemon said stays: a pin there already but disabled is
		// refused over TCP, and only its answer says to enable it.
		return fmt.Errorf("%s\nbut a request over TCP to\n%s failed: %v\nNothing was written. The pin stays enrolled: once that is\nfixed, run this again, which reuses it:\n%s", said, entry.BaseURL, err, commandLines(retry, 3))
	}
	*steps = append(*steps, ok)
	return nil
}

// samePair refuses the write when the CLI config cfg, as it will be once
// target holds out, names another client pair than cc did when its pin was
// enrolled as client: the entry is used with that pair, which the daemon
// does not know. The daemon refuses a second pin under one name, so a rerun
// needs the old pair or a new name.
func samePair(cfg, target string, out []byte, cc CliClientConf, client, cmd, retry string) error {
	was, wasKey := clientCertPaths(cc)
	pc, err := prospectiveClientConf(cfg, target, out)
	if err != nil {
		// Not a pair that changed: say what failed.
		return fmt.Errorf("cannot read the client pair of the config to be\nwritten (%v); nothing was written. The pin of %s\nstays enrolled as %s; run this again, which reuses it:\n%s", err, was, client, commandLines(retry, 3))
	}
	if now, key := clientCertPaths(pc); now != was || key != wasKey {
		return fmt.Errorf("the client pair in %s changed while %s\nran (now %s); nothing was written. The pin of\n%s stays enrolled as %s: put that pair back and run\n%s\nor run that with another --client-name", cfg, cmd, now, was, client, commandLines(retry, 3))
	}
	return nil
}

// tcpCheck makes one request (ping) over TCP to e's baseurl, as e says: its
// pins, and the client certificate. It says how, as ping does.
func tcpCheck(e ApiDetails, cc CliClientConf) (string, error) {
	api, _, err := buildApiClient(e, cc, "", "")
	if err != nil {
		return "", err
	}
	api.Client.Timeout = 10 * time.Second
	pr, err := api.SendPing(1, false)
	if err != nil {
		return "", err
	}
	return "TCP check: ok (" + pingHow(api, pr) + ")", nil
}

// lockEdit takes the lock of the CLI config cfg, and of target, the file
// edited, when they differ: two edits of two files that feed one effective
// list would otherwise both read the old list. A nil ctx never ends the
// wait.
func lockEdit(ctx context.Context, cfg, target string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	unlock, err := lockCliConfigs(ctx, cfg, target)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		unlock()
		return nil, err // cancelled while the lock was being taken
	}
	return unlock, nil
}

// pathCause is err without the operation and path a *fs.PathError adds: the
// path is named on its own line where this is used.
func pathCause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// refusedSocketStopped says whether a dial to the socket path that failed
// with errno is a stopped daemon's: for ECONNREFUSED, nothing at the path or
// a stale socket is (true), a file that is not a socket is not (false), and
// an error that keeps the path from being looked at (EACCES) is the error,
// not a stopped daemon. Any other errno is left to the caller (true, nil).
func refusedSocketStopped(errno syscall.Errno, path string) (bool, error) {
	if errno != syscall.ECONNREFUSED {
		return true, nil
	}
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, err
	}
	return fi.Mode()&fs.ModeSocket != 0, nil
}

// prospectiveClientConf is the client: block the CLI will load from cfg
// once target holds out: the whole merged view (include: files,
// cli.localconfig) with the edited file laid over the real one. A config
// that does not load, or a client: block that does not decode, is an error:
// the default pair would be enrolled in its place.
func prospectiveClientConf(cfg, target string, out []byte) (CliClientConf, error) {
	ofs, err := overlayFs(target, out)
	if err != nil {
		return CliClientConf{}, err
	}
	return readCliClientConf(cfg, ofs)
}

// renderAdd is target with entry added, checked to load, the way the CLI
// will read it, as exactly the old list plus the new entry. Nothing is
// written: the edited file is laid over the real one (overlayFs). The case
// this exists for: apiservers: is ALSO defined in an include or in
// cli.localconfig, which hides this one (lists are replaced, not merged).
// created: target is the CLI config, and it is not there yet.
func renderAdd(o AddOptions, target string, existing []ApiDetails, entry ApiDetails, created bool) ([]byte, error) {
	var src []byte
	if !created {
		var err error
		if src, err = os.ReadFile(target); err != nil {
			return nil, err
		}
	}
	out, _, err := spliceApiserver(src, entry)
	if errors.Is(err, errFlowApiservers) && len(entry.Pins) > 0 {
		// Checked before the enrolment: an entry pasted now would hold a
		// pin the daemon does not know.
		return nil, fmt.Errorf("%s: %w; nothing was written.\nMake the list block style (or name its file with --file),\nthen run config add again", target, err)
	}
	if errors.Is(err, errFlowApiservers) {
		return nil, fmt.Errorf("%s: %w; nothing was written. Make the list block style (or name its file with --file), or add this entry by hand:\n\n%s",
			target, err, renderEntry(entry, itemLayout{indent: defItemIndent, gap: defDashGap, valueCol: defValueCol}))
	}
	if err != nil {
		return nil, err
	}
	if created {
		out = append([]byte(newCliConfigHeader), out...)
	}
	want := append(append([]ApiDetails(nil), existing...), entry)
	if err := loadsAs(o.CliConfig, target, out, want); err != nil {
		return nil, fmt.Errorf("after adding the entry to %s the CLI config would not load as the old list plus the new entry (%v). Is apiservers: also defined in an include: file or in cli.localconfig, which hides it? Use --file to name the file that holds the list. Nothing was written.",
			target, err)
	}
	return out, nil
}

// loadsAs checks that the CLI config cfg, with target's text replaced by
// out, loads the way the CLI will read it as exactly want. Nothing is
// written: the edited file is laid over the real one (overlayFs).
func loadsAs(cfg, target string, out []byte, want []ApiDetails) error {
	fs, err := overlayFs(target, out)
	if err != nil {
		return err
	}
	got, err := readApiServers(cfg, fs)
	if err == nil && !sameEntries(got, want) {
		err = errors.New("it would read as another list")
	}
	return err
}

// hostPort returns the host:port of a base URL, lower-cased, or "". A URL
// without a port gets its scheme's (443 for https, 80 for http), so
// https://127.0.0.1/api/v1 and a daemon on 127.0.0.1:443 compare equal.
func hostPort(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			return strings.ToLower(net.JoinHostPort(u.Hostname(), "443"))
		case "http":
			return strings.ToLower(net.JoinHostPort(u.Hostname(), "80"))
		}
	}
	return strings.ToLower(u.Host)
}

// overlayFs is the real file system, read-only, with the file at path reading
// as data: what the file system would look like after the add, without the
// write.
//
// "The file at path" however the config names it: as given, relative, through
// a symlink at path (writeFileAtomic writes where it points), or through a
// symlink to it named in cli.localconfig. Names are compared resolved
// (resolvedPath), which is what the add's rename replaces. Not by file
// identity: a hard link to the file is another name, which the rename leaves
// reading the old file, so the add would fail there and the preview must too.
func overlayFs(path string, data []byte) (afero.Fs, error) {
	o := &fileOverlay{Fs: afero.NewReadOnlyFs(afero.NewOsFs()), mem: afero.NewMemMapFs(), target: resolvedPath(path)}
	if err := afero.WriteFile(o.mem, "/overlay", data, 0o600); err != nil {
		return nil, err
	}
	return o, nil
}

// fileOverlay is an afero.Fs that opens one file's replacement instead of the
// file. viper reads a config through Open only (afero.ReadFile).
type fileOverlay struct {
	afero.Fs
	mem    afero.Fs
	target string // resolvedPath of the replaced file
}

func (o *fileOverlay) replaces(name string) bool {
	return resolvedPath(name) == o.target
}

func (o *fileOverlay) Open(name string) (afero.File, error) {
	if o.replaces(name) {
		return o.mem.Open("/overlay")
	}
	return o.Fs.Open(name)
}

func (o *fileOverlay) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if o.replaces(name) {
		return o.mem.OpenFile("/overlay", flag, perm)
	}
	return o.Fs.OpenFile(name, flag, perm)
}

// MissingCliConfig is the refusal for cmd, which needs the CLI config cfg,
// when cfg is not there: the config add that creates it, for the daemon cmd
// is for (the role of its top-level command; auth when it names none).
func MissingCliConfig(cmd *cobra.Command, cfg string) string {
	role := "auth"
	for c := cmd; c != nil && c.HasParent(); c = c.Parent() {
		if !c.Parent().HasParent() {
			if _, ok := builtinRoles()[c.Name()]; ok {
				role = c.Name()
			}
		}
	}
	return fmt.Sprintf("no CLI config %s. Create it with:\n%s", cfg,
		commandLines(ConfigAddHint(cfg)+" "+shellQuote(defaultDaemonConfig(role)), 3))
}

// ConfigAddHint is the `config add` command line that writes cfg, the CLI
// config the caller found missing: with --config when cfg is not the default,
// so that following the advice creates the file that was missing.
func ConfigAddHint(cfg string) string {
	return ncliFor(cfg) + " config add"
}

// ncliFor is "tdns-ncli", with --config cfg when cfg is not the file
// tdns-ncli reads without it: the start of any command line printed as
// advice, so that it reads the CLI config the command that printed it read.
// The tool running may be another (tdns-cli, tdns-debug), whose own default
// tdns-ncli does not read (#1205); "" is the running tool's default.
func ncliFor(cfg string) string {
	if cfg == "" {
		cfg = DefaultCliConfigFile
	}
	if cfg == tdns.DefaultNcliCfgFile {
		return "tdns-ncli"
	}
	return "tdns-ncli --config " + shellQuote(cfg)
}

// reShellSafe matches a word a POSIX shell takes as it stands: no expansion,
// no splitting, no operator.
var reShellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// shellQuote returns s as one shell word: as it stands when that is safe,
// single-quoted otherwise, so advice pasted into a shell runs as printed.
func shellQuote(s string) string {
	if reShellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// printAddResult says what config add did, verdict first: the entry added
// and the command that tries it, in a line or two. The entry and the steps
// taken are printed with -v, and with --dry-run, which is for seeing them.
// What the operator must know stays: a certificate made, the notes, and
// what a stopped daemon still needs.
func printAddResult(w io.Writer, r *AddResult, dryRun bool, cfg string) {
	verify := ncliFor(cfg) + " " + commandWord(r.Entry) + " ping"
	switch {
	case r.AlreadyKnown != "":
		fmt.Fprintf(w, "Already known as %q; nothing written.\n", r.AlreadyKnown)
	case dryRun && r.Created:
		fmt.Fprintf(w, "Would create %s with the new entry %q:\n\n", r.File, r.Entry.Name)
	case dryRun:
		fmt.Fprintf(w, "Would add the new entry %q to %s:\n\n", r.Entry.Name, r.File)
	default:
		lead := fmt.Sprintf("Added the new entry %q to %s.", r.Entry.Name, r.File)
		if r.Created {
			lead = fmt.Sprintf("Created %s with the new entry %q.", r.File, r.Entry.Name)
		}
		if r.Running && r.Update == "" {
			if line := lead + " Verify with:  " + verify; len(line) <= 72 {
				lead = line
			} else {
				lead += "\nVerify with:  " + verify
			}
		}
		fmt.Fprintln(w, lead)
	}
	steps := r.Steps
	if r.AlreadyKnown == "" && (dryRun || tdns.Globals.Verbose) {
		if !dryRun {
			fmt.Fprintln(w)
		}
		// Unaligned, so that a line of pins fits.
		fmt.Fprint(w, renderEntry(r.Entry, itemLayout{indent: 3, gap: 1}))
	} else {
		// Without -v only a certificate made, which is a new key file.
		steps = nil
		for _, st := range r.Steps {
			if strings.HasPrefix(st, "Made your client certificate") {
				steps = append(steps, st)
			}
		}
	}
	printStepsNotes(w, steps, r.Notes, dryRun)
	switch {
	case r.AlreadyKnown != "" && r.Update != "":
		fmt.Fprintf(w, "To change it:\n%s\n", commandLines(r.Update, 3))
	case r.Update != "":
		if r.AccessMissing != "" {
			fmt.Fprintf(w, "\nThe daemon's access file is missing, so it takes no remote\nclients. Create it (empty is fine):\n%s\n", commandLines("touch "+shellQuote(r.AccessMissing), 3))
		}
		fmt.Fprintf(w, "\nThe daemon is not running. Once it is up, this gives the\nentry its address and your client certificate:\n%s\n", commandLines(r.Update, 3))
	}
}

// printStepsNotes prints what was done (with dryRun, what would be), and
// the notes, wrapped.
func printStepsNotes(w io.Writer, steps, notes []string, dryRun bool) {
	if len(steps) > 0 {
		if dryRun {
			fmt.Fprint(w, "\nFirst it would:\n")
		} else if tdns.Globals.Verbose {
			fmt.Fprintln(w)
		}
		for _, s := range steps {
			fmt.Fprintf(w, " - %s\n", s)
		}
	}
	if len(notes) > 0 {
		fmt.Fprintln(w)
	}
	for _, n := range notes {
		fmt.Fprintf(w, "Note: %s\n", strings.Join(wrapText(n, 66), "\n      "))
	}
}

// commandWord is the word that reaches entry e: the role of a built-in
// role's entry (whose name is that role, unless a downstream package
// registered another), else its name.
func commandWord(e ApiDetails) string {
	if role := roleEntryOf(e, builtinRoles()); role != "" {
		return role
	}
	return e.Name
}

// entryRole is the daemon type of entry e: its role:, the role whose entry
// it is, or for an entry with an old name, the role of the entry it must
// become. "" when none says.
func entryRole(e ApiDetails) string {
	if e.Role != "" {
		return e.Role
	}
	builtin := builtinRoles()
	if role := roleEntryOf(e, builtin); role != "" {
		return role
	}
	if n := renamedTo(e); n != "" {
		return roleEntryOf(ApiDetails{Name: n}, builtin)
	}
	return ""
}

// --------------------------------------------------------------- config list

func newConfigListCmd() *cobra.Command {
	var check bool
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "list",
		Short: "List the daemons and instances in the CLI config",
		Long: `Lists every apiservers: entry of the CLI config: its name, the command word
that reaches it, what kind of entry it is, its API address, the daemon config it
refers to, and whether tdns-ncli can use it. An entry that is ignored says why.

With --check each API is also pinged, and the exit status is non-zero if any
of them does not answer.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cliConfigPath(cmd)
			entries, err := ReadApiServers(cfg)
			if errors.Is(err, os.ErrNotExist) {
				fatalf("no CLI config %s yet; create it from a daemon's config with: %s <daemon-config.yaml>", cfg, ConfigAddHint(cfg))
			}
			if err != nil {
				fatalf("%v", err)
			}
			rows := BuildListRows(cmd.Root(), entries)
			failed := false
			if check {
				results := CheckEntries(entries, ReadCliClientConf(cfg), timeout)
				for i := range rows {
					rows[i].Check = results[i]
					// An API that was not checked is not one that answered:
					// --check succeeds only when every one of them did.
					if strings.HasPrefix(results[i], "FAIL") || strings.HasPrefix(results[i], "not checked") {
						failed = true
					}
				}
			}
			fmt.Printf("CLI config: %s\n\n", cfg)
			printListRows(os.Stdout, rows, check, cfg)
			for _, w := range duplicatePins(entries) {
				fmt.Printf("\nWarning: %s\n", w)
			}
			if failed {
				os.Exit(1)
			}
		},
	}
	c.Flags().BoolVar(&check, "check", false, "ping each entry's API and report whether it answers")
	c.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "with --check: how long to wait for each answer")
	return c
}

// ListRow is one apiservers entry as `config list` shows it.
type ListRow struct {
	Name       string
	Command    string // the command word that reaches it, or "-"
	Kind       string
	BaseURL    string
	ConfigFile string
	Status     string
	Check      string // with --check
}

// BuildListRows describes every entry, judging instance entries by the same
// rules WireInstanceTrees applies, against the CLI as it was before any
// instance was wired (root has instance trees on it by now).
func BuildListRows(root *cobra.Command, entries []ApiDetails) []ListRow {
	builtin := builtinRoles()
	verdicts := checkInstanceEntries(commandsWithoutInstances(root), entries, builtin)

	rows := make([]ListRow, 0, len(entries))
	for i, e := range entries {
		v := verdicts[i]
		r := ListRow{Name: e.Name, BaseURL: e.BaseURL, ConfigFile: e.ConfigFile, Command: "-"}
		if r.BaseURL == "" {
			r.BaseURL = "(local socket only)" // found through config-file:
		}
		switch {
		case v.Rename != "":
			r.Kind, r.Status = "old name", "ignored: rename it to "+v.Rename
			if r.ConfigFile == "" {
				r.ConfigFile = "-"
			}
		case v.RoleEntry != "":
			r.Command, r.Kind, r.Status = v.RoleEntry, v.RoleEntry, "ok"
			if r.ConfigFile == "" {
				r.ConfigFile = defaultDaemonConfig(v.RoleEntry) + " (default)"
			}
		case v.Canonical:
			r.Kind, r.Status = "other", "no command tree in this CLI"
		default:
			r.Kind = "instance of " + e.Role
			if e.Role == "" || roleEntryOf(e, builtin) != "" {
				r.Kind = "duplicate"
			}
			if v.Wire {
				r.Command, r.Status = e.Name, "ok"
			} else {
				r.Status = "ignored: " + trimEntryPrefix(v.Why)
			}
			if r.ConfigFile == "" {
				r.ConfigFile = "-"
			}
		}
		rows = append(rows, r)
	}
	return rows
}

// commandsWithoutInstances returns a stand-in for root that has root's
// commands except the instance trees, which are the ones named by entries and
// would otherwise look like collisions with themselves.
func commandsWithoutInstances(root *cobra.Command) *cobra.Command {
	s := &cobra.Command{Use: root.Name()}
	for _, c := range root.Commands() {
		if _, inst := wiredInstances[c.Name()]; inst {
			continue // an instance tree
		}
		s.AddCommand(&cobra.Command{Use: c.Name(), Aliases: c.Aliases})
	}
	return s
}

func defaultDaemonConfig(role string) string {
	switch role {
	case "agent":
		return tdns.DefaultAgentCfgFile
	case "imr":
		return tdns.DefaultImrCfgFile
	}
	return tdns.DefaultAuthCfgFile
}

// trimEntryPrefix drops the `apiservers entry "x": ` lead from a refusal, which
// the table row already says.
func trimEntryPrefix(why string) string {
	if i := strings.Index(why, `": `); i >= 0 {
		return why[i+3:]
	}
	return why
}

func printListRows(w io.Writer, rows []ListRow, check bool, cfg string) {
	head := "NAME|COMMAND|KIND|API|DAEMON CONFIG|STATUS"
	if check {
		head += "|CHECK"
	}
	lines := []string{head}
	for _, r := range rows {
		l := strings.Join([]string{r.Name, r.Command, r.Kind, r.BaseURL, r.ConfigFile, r.Status}, "|")
		if check {
			l += "|" + r.Check
		}
		lines = append(lines, l)
	}
	if len(rows) == 0 {
		fmt.Fprintf(w, "No apiservers entries. Add one with: %s <daemon-config.yaml>\n", ConfigAddHint(cfg))
		return
	}
	fmt.Fprintln(w, columnize.SimpleFormat(lines))
}

// CheckEntries pings each entry's API, concurrently, and returns one result
// string per entry, in order: "ok ..." or "FAIL: ...".
func CheckEntries(entries []ApiDetails, cc CliClientConf, timeout time.Duration) []string {
	out := make([]string, len(entries))
	var wg sync.WaitGroup
	for i := range entries {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i] = pingEntry(entries[i], cc, timeout)
		}(i)
	}
	wg.Wait()
	return out
}

// pingEntry pings one entry with the client every other command would use
// (its pins, roots and credentials), so a pass here means the entry works.
func pingEntry(e ApiDetails, cc CliClientConf, timeout time.Duration) string {
	api, warn, err := newApiClientFor(e, cc)
	if err != nil {
		return "FAIL: " + err.Error()
	}
	// What every other command would say when it uses this entry: the check
	// says it too, after its verdict, so the leading ok/FAIL that sets the
	// exit status stays first.
	suffix := ""
	if warn != "" {
		suffix = " (warning: " + warn + ")"
	}

	done := make(chan string, 1)
	go func() {
		pr, err := api.SendPing(1, false)
		if err != nil {
			msg := strings.ReplaceAll(err.Error(), "\n", " ")
			if strings.Contains(msg, "connection refused") {
				msg = "connection refused (daemon not running?)"
			}
			done <- "FAIL: " + msg
			return
		}
		// How it was reached and as whom, as ping says it.
		s := "ok (" + pingHow(api, pr) + ")"
		if !pr.BootTime.IsZero() {
			s += ", up " + shortDuration(time.Since(pr.BootTime))
		}
		if pr.Version != "" {
			s += ", " + pr.Version
		}
		done <- s
	}()
	select {
	case s := <-done:
		return s + suffix
	case <-time.After(timeout):
		return fmt.Sprintf("FAIL: no answer within %s", timeout) + suffix
	}
}

func shortDuration(d time.Duration) string {
	d = d.Truncate(time.Second)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd%dh", d/(24*time.Hour), d%(24*time.Hour)/time.Hour)
	case d >= time.Hour:
		return fmt.Sprintf("%dh%dm", d/time.Hour, d%time.Hour/time.Minute)
	}
	return fmt.Sprintf("%dm%ds", d/time.Minute, d%time.Minute/time.Second)
}

// duplicatePins reports entries of different daemons that have the same
// certificate pin. The CLI cannot tell such daemons apart, so a command
// meant for one is accepted by the other. Where both entries name their
// daemon config, the warning names the certificate and how to give the
// second daemon its own (its default pair, which it writes at its start).
func duplicatePins(entries []ApiDetails) []string {
	by := map[string][]ApiDetails{}
	// Entries of one daemon (the same baseurl) have its pin as a matter of
	// course; only distinct daemons sharing one are worth a warning.
	// daemons[pin] holds the daemons seen.
	daemons := map[string]map[string]bool{}
	var order []string
	for _, e := range entries {
		d := pinDaemon(e)
		for _, p := range e.Pins {
			if _, seen := by[p]; !seen {
				order = append(order, p)
				daemons[p] = map[string]bool{}
			}
			if daemons[p][d] {
				continue
			}
			daemons[p][d] = true
			by[p] = append(by[p], e)
		}
	}
	var out []string
	for _, p := range order {
		es := by[p]
		if len(es) < 2 {
			continue
		}
		names := make([]string, len(es))
		for i, e := range es {
			names[i] = e.Name
		}
		out = append(out, samePinWarning(names, es, p))
	}
	return out
}

// samePinWarning is duplicatePins' warning for the entries es, of names,
// which all have pin. With the daemon configs of the first two, and the
// second naming its certificate under apiserver:, it says which file and
// what to change; else it names the pin.
func samePinWarning(names []string, es []ApiDetails, pin string) string {
	who := strings.Join(names, " and ")
	generic := fmt.Sprintf("%s have the same certificate pin (%s): the CLI cannot tell them apart, so a command meant for one is accepted by the other. Each daemon should have a certificate of its own.",
		who, pin)
	if len(es) != 2 || es[0].ConfigFile == "" || es[1].ConfigFile == "" {
		return warningText(generic)
	}
	cert, other := daemonCertFile(es[0].ConfigFile), daemonCertFile(es[1].ConfigFile)
	if cert == "" || cert != other {
		return warningText(generic)
	}
	second := es[1]
	own, _ := tdns.ApiCertPaths(second.ConfigFile)
	msg := fmt.Sprintf("%s use the same API certificate (%s): the CLI cannot tell them apart, so a command meant for one is accepted by the other. To give %s its own, remove certfile: and keyfile: under apiserver: in %s and restart it (at start it writes %s). Then run:",
		who, cert, second.Name, second.ConfigFile, own)
	return warningText(msg) + "\n" + commandLines(ncliForThisRun()+" config update "+shellQuote(second.Name)+" --repin", 3)
}

// warningText is msg wrapped in lines of at most 72, the first of them with
// room for the "Warning: " its printer puts before it.
func warningText(msg string) string {
	const lead = "Warning: "
	lines := wrapText(lead+msg, 72)
	lines[0] = strings.TrimPrefix(lines[0], lead)
	return strings.Join(lines, "\n")
}

// daemonCertFile is the API certificate the daemon config cfg names under
// apiserver:, or "" when it names none (the default pair) or cannot be
// read.
func daemonCertFile(cfg string) string {
	v, err := readDaemonViper(cfg)
	if err != nil {
		return ""
	}
	return v.GetString("apiserver.certfile")
}

// pinDaemon says which daemon an entry reaches, for duplicatePins: the
// baseurl's host:port, lower-cased, so that two entries of one daemon
// count once. An entry whose baseurl has no host (unparseable, empty, a
// unix socket) stands for itself.
func pinDaemon(e ApiDetails) string {
	u, err := url.Parse(e.BaseURL)
	if err != nil || u.Host == "" {
		return "entry " + e.Name
	}
	return "host " + strings.ToLower(u.Host)
}
