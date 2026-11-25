/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * `tdns-ncli config add|list`: maintaining the CLI's own list of daemons
 * (apiservers:) from the daemons' config files.
 */
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// NewCliConfigCmd builds `config`, with `add` and `list`.
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
	c.AddCommand(newConfigAddCmd(), newConfigListCmd())
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
name; --role overrides it. The first daemon of a type is added under its
canonical name (tdns-auth, tdns-agent, tdns-imr) and is reached as "auth",
"agent", "imr". Any further one becomes an instance with role: set, named
after the file (tdns-auth2.yaml -> auth2) unless --name says otherwise,
reached as "tdns-ncli auth2 ...".

A running daemon: your client certificate is made if you have none (as
client init does), the daemon adds its pin to its access file as
--client-name (read-write), and one request over TCP checks it. Only then
is the entry written: the TCP address, the pins of the daemon's
certificate, authmethod: certificate and config-file:. No API key.

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
	// Canonical: Entry is the canonical entry of a built-in role, not an
	// instance.
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
}

var addableRoles = map[string]bool{"auth": true, "agent": true, "imr": true}

const newCliConfigHeader = "# tdns-ncli configuration.\n# apiservers: lists the daemons (and instances of a daemon) tdns-ncli addresses;\n# `tdns-ncli config add <daemon-config.yaml>` adds to it. It holds API keys.\n\n"

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
	entry := ApiDetails{AuthMethod: "none", ConfigFile: info.ConfigFile}
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
		if err := daemonReady(info, list, tcpURL, true); err != nil {
			return nil, err
		}
		entry.BaseURL, entry.AuthMethod, entry.TLSAuth, entry.Pins = tcpURL, "certificate", "pin", list.ServerPins
	}
	cc := ReadCliClientConf(o.CliConfig)
	client := o.ClientName
	if client == "" {
		client = defaultClientName()
	}
	switch {
	case o.DryRun && cert:
		res.Steps = enrolPlan(cc, client, tcpURL)
	case cert:
		// Refused before the enrolment, not after: a hidden list, a flow
		// style.
		if _, err := renderAdd(o, target, existing, entry, res.Created); err != nil {
			return nil, err
		}
		if err := enrol(sock, cc, client, "config add", &entry, &res.Steps); err != nil {
			return nil, err
		}
	}
	if !o.DryRun {
		unlock, err := lockEdit(o.Ctx, o.CliConfig, target)
		if err != nil {
			return nil, err
		}
		defer unlock()
		if existing, known, err = plan(); err != nil || known {
			return res, err
		}
	}
	out, err := renderAdd(o, target, existing, entry, res.Created)
	if err != nil {
		return nil, err
	}
	res.Entry, res.File = entry, target
	if !res.Running && tcpURL != "" {
		res.Update = fmt.Sprintf("%s config update %s --cert", ncliFor(o.CliConfig), entry.Name)
	}
	if o.DryRun {
		return res, nil
	}
	if err := writeFileAtomic(target, out); err != nil {
		if cert {
			return nil, fmt.Errorf("%v.\nThe pin stays enrolled; the next config add reuses it", err)
		}
		return nil, err
	}
	res.Wrote = true
	return res, nil
}

// chooseEntryName fills in entry.Name (and Role for an instance).
func chooseEntryName(entry *ApiDetails, res *AddResult, role string, existing []ApiDetails, o AddOptions) error {
	canonical := roleToClientKey[role] // tdns-auth, tdns-agent, tdns-imr
	// Only a role-less row is the canonical entry. A row named tdns-auth
	// that carries a role: is an instance using a reserved name, which the
	// CLI ignores (checkInstanceEntries): counting it would file the first
	// real auth daemon as an extra instance, and leave `tdns-ncli auth` with
	// no client.
	hasCanonical, badRole := false, ""
	used := map[string]bool{}
	for _, e := range existing {
		used[e.Name] = true
		if e.Name == canonical {
			if e.Role == "" {
				hasCanonical = true
			} else {
				badRole = e.Role
			}
		}
	}
	// That row also holds the name this daemon would take as the canonical
	// one: say so, rather than write an entry the CLI would ignore too.
	badCanonical := func() error {
		return fmt.Errorf("the CLI config has an entry named %q with role: %s, which the CLI ignores: %q is the canonical %s's name. Remove its role: line to make it the canonical %s, or rename it, then add again",
			canonical, badRole, canonical, role, role)
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
		return o.CommandWordTaken != nil && o.CommandWordTaken(n)
	}

	asCanonical := func() {
		entry.Name = canonical
		res.Canonical = true
		res.Notes = append(res.Notes, fmt.Sprintf(
			"there was no %s entry yet, so this daemon is the canonical one (tdns-ncli %s ...); --name adds it as an extra instance instead",
			canonical, role))
	}
	asInstance := func(name string) error {
		if _, ok := knownInstanceRoles[role]; !ok {
			return fmt.Errorf("a %s entry already exists, and tdns-ncli has no command tree for a second %s instance yet (it has one for: %s)",
				canonical, role, knownRoleList())
		}
		entry.Name, entry.Role = name, role
		return nil
	}

	switch {
	case o.Name == "" && !hasCanonical && badRole != "":
		return badCanonical()
	case o.Name == "" && !hasCanonical:
		asCanonical()
	case o.Name == "":
		base := deriveInstanceName(o.DaemonConfig)
		if base == "" {
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
		if o.Name == canonical && !hasCanonical {
			if badRole != "" {
				return badCanonical()
			}
			asCanonical()
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
	for _, e := range existing {
		sameFile := e.ConfigFile != "" && resolvedPath(e.ConfigFile) == resolvedPath(info.ConfigFile)
		// No TCP address: the entry reaches the daemon over its socket,
		// through config-file: (or, written before that, a unix:// baseurl).
		noTCP := e.BaseURL == "" || isUnixURL(e.BaseURL)
		sameAddr := tcpURL != "" && hostPort(e.BaseURL) == hostPort(tcpURL)
		switch {
		case sameFile && (sameAddr || noTCP):
		case sameFile:
			return false, fmt.Errorf("entry %q already points at %s but with a different API address (%s, the config says %q); edit or remove that entry by hand",
				e.Name, info.ConfigFile, e.BaseURL, tcpURL)
		case sameAddr && e.ConfigFile == "":
			// Typically the canonical entry written before config-file: existed.
		case sameAddr:
			return false, fmt.Errorf("entry %q (config-file %s) already uses the API address %s, which %s also names; two daemons cannot listen on one address",
				e.Name, e.ConfigFile, e.BaseURL, info.ConfigFile)
		default:
			continue
		}
		res.AlreadyKnown = e.Name
		flag := "--cert" // from the key, or no address yet
		switch {
		case noTCP && tcpURL == "":
			return true, nil // the socket is all there is
		case usesCert(e):
			flag = "--repin"
		}
		if e.ConfigFile == "" {
			flag += " --daemon-config " + shellQuote(info.ConfigFile)
		}
		res.Update = fmt.Sprintf("%s config update %s %s", ncliFor(o.CliConfig), e.Name, flag)
		return true, nil
	}
	return false, nil
}

// needSocket refuses a daemon that serves no local admin socket: cmd
// (config add, config update) sets up certificates through it.
func needSocket(info *DaemonApi, cmd string) error {
	if info.Socket == "" {
		return fmt.Errorf("%s serves no local admin socket\n(socket: none). %s needs it, run as root on the\ndaemon's host: certificate setup goes through the socket", info.ConfigFile, cmd)
	}
	return nil
}

// daemonTCP is the base URL of the daemon's TCP API, its first address, or
// "" when it has none; notes say when it lists more than one.
func daemonTCP(info *DaemonApi) (tcpURL string, notes []string, err error) {
	if len(info.Addresses) == 0 {
		return "", nil, nil
	}
	if tcpURL, err = apiBaseURL(info.Addresses[0], info.UseTLS); err != nil {
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
	switch errno := socketErrno(err); {
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
// one with no access file (the daemon's advice) or no TLS.
func daemonReady(info *DaemonApi, list tdns.AccessResponse, tcpURL string, cert bool) error {
	switch {
	case cert && list.File == "":
		return errors.New(list.Msg) // the daemon's advice: no access file
	case tcpURL == "":
		return fmt.Errorf("%s lists no apiserver.addresses: the\ndaemon has no TCP API to reach with pins", info.ConfigFile)
	case cert && !info.UseTLS:
		return fmt.Errorf("%s: apiserver.usetls is false, but a client\ncertificate needs TLS on the TCP API; set usetls: true", info.ConfigFile)
	case len(list.ServerPins) == 0:
		return fmt.Errorf("the daemon serves no certificate on its TCP API (is it\nlistening on %s?), so there is nothing to pin", info.Addresses[0])
	}
	return nil
}

// usesCert says whether e reaches its daemon over https with the client
// certificate: config update --repin changes it, --cert has done its work.
func usesCert(e ApiDetails) bool {
	return e.AuthMethod == "certificate" && strings.HasPrefix(strings.ToLower(e.BaseURL), "https://")
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

// enrol is steps 1 to 3 of a running daemon's certificate entry: the
// operator's client pair, made if there is none; its pin added by the
// daemon over its local admin socket sock; one request over TCP with it and
// the server pins. A refusal or a failed request stops cmd before anything
// is written. The pin stays enrolled after a failed request; the next run
// reuses it ("already there").
func enrol(sock *tdns.ApiClient, cc CliClientConf, client, cmd string, entry *ApiDetails, steps *[]string) error {
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
		return err
	case ans.Error:
		return fmt.Errorf("the daemon did not add your pin; nothing was written:\n%s", ans.ErrorMsg)
	}
	*steps = append(*steps, "The daemon: "+strings.ReplaceAll(ans.Msg, "\n", "\n   "))
	if len(ans.ServerPins) > 0 {
		entry.Pins = ans.ServerPins
	}
	ok, err := tcpCheck(*entry, cc)
	if err != nil {
		return fmt.Errorf("the daemon added your pin, but a request over TCP to\n%s failed: %v\nNothing was written. The pin stays enrolled: once that is\nfixed, run %s again, which reuses it", entry.BaseURL, err, cmd)
	}
	*steps = append(*steps, ok)
	return nil
}

// tcpCheck makes one request (ping) over TCP to e's baseurl, as e says: its
// pins, and its key or certificate. It says how, as ping does.
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

// ConfigAddHint is the `config add` command line that writes cfg, the CLI
// config the caller found missing: with --config when cfg is not the default,
// so that following the advice creates the file that was missing.
func ConfigAddHint(cfg string) string {
	return ncliFor(cfg) + " config add"
}

// ncliFor is "tdns-ncli", with --config cfg when cfg is not the default: the
// start of any command line printed as advice, so that it reads the CLI
// config the command that printed it read.
func ncliFor(cfg string) string {
	if cfg == "" || cfg == DefaultCliConfigFile {
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

// printAddResult says what config add did, verdict first, in lines of at
// most 72 where it can (a path is as long as it is).
func printAddResult(w io.Writer, r *AddResult, dryRun bool, cfg string) {
	if r.AlreadyKnown != "" {
		fmt.Fprintf(w, "Already known as %q; nothing written.\n", r.AlreadyKnown)
	} else {
		kind := "instance of " + r.Entry.Role
		if r.Canonical {
			kind = "canonical"
		}
		switch {
		case dryRun && r.Created:
			fmt.Fprintf(w, "Would create %s with %q (%s):\n\n", r.File, r.Entry.Name, kind)
		case dryRun:
			fmt.Fprintf(w, "Would add %q (%s) to %s:\n\n", r.Entry.Name, kind, r.File)
		case r.Created:
			fmt.Fprintf(w, "Created %s with %q (%s):\n\n", r.File, r.Entry.Name, kind)
		default:
			fmt.Fprintf(w, "Added %q (%s) to %s:\n\n", r.Entry.Name, kind, r.File)
		}
		// Unaligned, so that a line of pins fits.
		fmt.Fprint(w, renderEntry(r.Entry, itemLayout{indent: 3, gap: 1}))
	}
	printStepsNotes(w, r.Steps, r.Notes, dryRun)
	switch {
	case r.AlreadyKnown != "" && r.Update != "":
		fmt.Fprintf(w, "\nconfig add writes new entries only. To change this one:\n\n   %s\n", r.Update)
	case r.Update != "":
		fmt.Fprintf(w, "\nThe daemon is not running. Once it is up, this gives the\nentry its address and your client certificate:\n\n   %s\n", r.Update)
	case r.Running && !dryRun && r.AlreadyKnown == "":
		// The CLI config the add read, not the --file it edited: --file
		// only names where in that config the list lives.
		fmt.Fprintf(w, "\nTry it:  %s %s ping\n", ncliFor(cfg), commandWord(r.Entry))
	}
}

// printStepsNotes prints what was done (with dryRun, what would be), and
// the notes, wrapped.
func printStepsNotes(w io.Writer, steps, notes []string, dryRun bool) {
	if len(steps) > 0 {
		if dryRun {
			fmt.Fprint(w, "\nFirst it would:\n")
		} else {
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
// role's canonical entry (auth for tdns-auth), else its name.
func commandWord(e ApiDetails) string {
	if e.Role == "" {
		for role, key := range builtinRoles() {
			if key == e.Name {
				return role
			}
		}
	}
	return e.Name
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
of them does not answer, or could not be checked (rootca: tlsa).`,
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
	roleOfClient := map[string]string{}
	for role, key := range builtin {
		roleOfClient[key] = role
	}
	verdicts := checkInstanceEntries(commandsWithoutInstances(root), entries, builtin)

	rows := make([]ListRow, 0, len(entries))
	for i, e := range entries {
		v := verdicts[i]
		r := ListRow{Name: e.Name, BaseURL: e.BaseURL, ConfigFile: e.ConfigFile, Command: "-"}
		if r.BaseURL == "" {
			r.BaseURL = "(local socket only)" // found through config-file:
		}
		if v.Canonical {
			if role, ok := roleOfClient[e.Name]; ok {
				r.Command, r.Kind, r.Status = role, "built-in "+role, "ok"
				if r.ConfigFile == "" {
					r.ConfigFile = defaultDaemonConfig(role) + " (default)"
				}
			} else {
				r.Kind, r.Status = "other", "no command tree in this CLI"
			}
		} else {
			r.Kind = "instance of " + e.Role
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
		if roleToClientKey[c.Name()] == c.Name() {
			continue // an instance tree: WireInstanceTrees registers those as n -> n
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
	// Only when TLSA is what verifies the daemon: with pins (tlsauth: pin),
	// a leftover rootca: tlsa is ignored and the entry can be checked.
	if e.RootCA == "tlsa" && !(strings.EqualFold(e.TLSAuth, "pin") && len(e.Pins) > 0) {
		return "not checked (rootca: tlsa)"
	}
	// What every other command would say when it uses this entry (no
	// verification, a key in clear): the check says it too, after its
	// verdict, so the leading ok/FAIL that sets the exit status stays first.
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

// duplicatePins reports entries that pin the same key. Two daemons with one
// key cannot be told apart by their pins, so a command meant for one is
// accepted by the other: the same hazard as a shared API key.
func duplicatePins(entries []ApiDetails) []string {
	by := map[string][]string{}
	// Entries of one daemon (a key entry and a certificate entry with the
	// same baseurl) pin its key as a matter of course; only distinct daemons
	// sharing a key are worth a warning. daemons[pin] holds the daemons seen.
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
			by[p] = append(by[p], e.Name)
		}
	}
	var out []string
	for _, p := range order {
		if names := by[p]; len(names) > 1 {
			out = append(out, fmt.Sprintf("%s pin the same key (%s): each daemon should have a key of its own, or a command meant for one is accepted by the other",
				strings.Join(names, " and "), p))
		}
	}
	return out
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
