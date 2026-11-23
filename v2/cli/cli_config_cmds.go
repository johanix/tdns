/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * `tdns-ncli config add|list`: maintaining the CLI's own list of daemons
 * (apiservers:) from the daemons' config files.
 */
package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
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
		Long: `Reads a daemon's own config (tdns-auth, tdns-agent or tdns-imr), takes its
apiserver: block, and adds an apiservers: entry for it to the CLI config.

  tdns-ncli config add /etc/tdns/tdns-auth2.yaml

The daemon type comes from service.name (or, for tdns-imr, from having an
imrengine: block and no service: block), and failing that from the file name;
--role overrides it. The first daemon of a type is added under its canonical
name (tdns-auth, tdns-agent, tdns-imr) and is reached as "auth", "agent",
"imr". Any further one becomes an instance with role: set, named after the
file (tdns-auth2.yaml -> auth2) unless --name says otherwise, reached as
"tdns-ncli auth2 ...".

The entry is the daemon's TCP address, the pin of its certificate, and
authmethod: certificate: it authenticates with your client certificate (the
CLI config's client: block, else the default pair; created, as by
"tdns-ncli client init", if there is none). It also records the daemon
config's path as config-file:, so "tdns-ncli auth2 config check" checks the
right daemon, and so that tdns-ncli, run as root, reaches the daemon over its
local admin socket instead (admin, no credentials), which it finds in the
daemon config. tdns-ncli --tcp uses the TCP address even then. A daemon with
no TCP address gets an entry with config-file: only, which only root can use.

The certificate works only once the daemon's access file lists its pin. When
config add can write the daemon's files (root on its host, in practice), it
enrolls the pin there (read-write), as "<daemon> client add" does; creates the
access file and adds access-file: to the daemon config's apiserver: block if
it names none (with an access file the API key over TCP is read-write, not
admin, TCP clients need TLS 1.3, and admin is the local socket's alone); and
reloads the daemon over its local socket. A daemon that is not running reads
the files when it next starts. When the certificate cannot be set up from
here, a new entry is refused with the lines that fix it (to run on the
daemon's host), and no entry is written with the API key.

The CLI config is created, mode 0600, if it does not exist. Adding a daemon
that is already there keeps its entry, brought up to date: an https entry
that does not pin the daemon's current certificate is given that pin
(tlsauth: pin), and an entry that uses the API key is switched to the
certificate (authmethod: certificate, its apikey: line removed) once the
daemon accepts it. If it cannot be set up, the entry keeps the key, and
config add says what the certificate still needs.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			o.Ctx = cmd.Context()
			o.DaemonConfig = args[0]
			o.CliConfig = cliConfigPath(cmd)
			root := cmd.Root()
			o.CommandWordTaken = func(n string) bool { return findChild(root, n) != nil }

			res, err := AddDaemonConfig(o)
			var r addRefusal
			switch {
			case errors.As(err, &r):
				printRefusal(os.Stderr, r)
				os.Exit(1)
			case err != nil:
				fatalf("%v", err)
			}
			printAddResult(os.Stdout, res, o.DryRun, o.CliConfig)
		},
	}
	c.Flags().StringVar(&o.Role, "role", "", "daemon type: auth, agent or imr (default: detect from the daemon config)")
	c.Flags().StringVar(&o.Name, "name", "", "name (and command word) for the entry (default: from the file name)")
	c.Flags().StringVar(&o.RootCA, "rootca", "", "rootca for the entry (default: none, which the CLI treats as insecure)")
	c.Flags().StringVar(&o.TargetFile, "file", "", "file to add the entry to, if the apiservers: list is not in the CLI config itself (an include or cli.localconfig)")
	c.Flags().BoolVar(&o.DryRun, "dry-run", false, "show what would be added; change nothing")
	return c
}

// runningAsRoot reports whether this process can open a root-only admin
// socket. A variable so the tests, which do not run as root, can say yes.
var runningAsRoot = func() bool { return os.Geteuid() == 0 }

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
	// RootCA is recorded as the entry's rootca, if non-empty.
	RootCA string
	// DryRun computes everything and writes nothing.
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
	// Pinned: the entry AlreadyKnown names did not pin the daemon's current
	// certificate, so it was (or, with DryRun, would be) given tlsauth: pin
	// and that pin. Entry is the entry as rewritten.
	Pinned bool
	// Cert is what config add found, and did, about the operator's client
	// certificate on the daemon's side; nil for an entry with no TCP address.
	Cert *CertSetup
	// Switched: the entry AlreadyKnown names used the API key, and now uses
	// the client certificate (authmethod: certificate, no apikey: line).
	Switched bool
	// KeyKept: the entry AlreadyKnown names keeps the API key, because the
	// certificate could not be made to work (Cert says why, and what would).
	KeyKept bool
	// ApiCertCreated is the daemon's default API certificate, which config
	// add made (the daemon had not started yet, so there was none to pin);
	// ApiCertWould the one a dry run would make. ApiCertKey is its key.
	ApiCertCreated, ApiCertWould, ApiCertKey string
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

// AddDaemonConfig adds an apiservers: entry for the daemon whose config is
// o.DaemonConfig to the CLI config.
//
// It refuses anything it is not sure of rather than guessing: an unknown
// daemon type, a name that collides with something, a second daemon whose
// API address another entry already uses. And it checks its own work: after
// writing, the CLI config is loaded again the way the CLI loads it, and if the
// effective list is not the old list plus the new entry the change is undone.
func AddDaemonConfig(o AddOptions) (*AddResult, error) {
	if o.Role != "" && !addableRoles[o.Role] {
		return nil, fmt.Errorf("--role must be one of auth, agent, imr (got %q)", o.Role)
	}
	info, err := ReadDaemonApi(o.DaemonConfig, o.Role)
	if err != nil {
		return nil, err
	}
	res := &AddResult{Notes: append([]string(nil), info.Warnings...)}

	// The daemon's TCP address, if it has one.
	tcpURL := ""
	if len(info.Addresses) > 0 {
		if tcpURL, err = apiBaseURL(info.Addresses[0], info.UseTLS); err != nil {
			return nil, fmt.Errorf("%s: %w", info.ConfigFile, err)
		}
	}
	// The local admin socket is not written into the entry: tdns-ncli finds it
	// in the daemon config the entry's config-file: names (usableDaemonSocket),
	// so the two cannot disagree. socketURL is only for recognising an entry
	// written as a socket entry before that.
	socketURL := ""
	if info.Socket != "" {
		socketURL = "unix://" + info.Socket
	}
	switch {
	case tcpURL == "" && !runningAsRoot():
		return nil, fmt.Errorf("%s has only a local admin socket (%s), which only root can open; run config add as root", info.ConfigFile, info.Socket)
	case tcpURL != "" && info.ApiKey == "":
		// ReadDaemonApi lets an empty key through when there is a socket.
		// The entry sends no key (it is a certificate entry), but the daemon
		// requires apiserver.apikey with a TCP API.
		return nil, fmt.Errorf("%s: apiserver.apikey is not set, which the daemon requires; set it", info.ConfigFile)
	case info.Socket != "" && tcpURL != "":
		res.Notes = append(res.Notes, fmt.Sprintf(
			"as root, tdns-ncli uses this daemon's local admin socket\n%s (admin, no key);\ntdns-ncli --tcp uses the TCP address", info.Socket))
	}
	baseURL := tcpURL
	if len(info.Addresses) > 1 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"apiserver.addresses lists %d addresses (%s); using the first",
			len(info.Addresses), strings.Join(info.Addresses, ", ")))
	}

	target := o.TargetFile
	if target == "" {
		target = o.CliConfig
	}
	if err := danglingSymlink(target); err != nil {
		return nil, err
	}
	// From before the read of what is there to after the last write: an add
	// that ran in between would otherwise be overwritten (lockCliConfig). The
	// CLI config is locked as well as the file edited, when they differ: two
	// adds editing two files that feed one effective list (the main file and
	// cli.localconfig, say) would otherwise both read the old list and both
	// succeed, the one list then hiding the other's entry. A dry run writes
	// nothing and takes no lock.
	if !o.DryRun {
		ctx := o.Ctx
		if ctx == nil {
			ctx = context.Background()
		}
		unlock, err := lockCliConfigs(ctx, o.CliConfig, target)
		if err != nil {
			return nil, err
		}
		defer unlock()
		// Cancelled while the lock was being taken: edit nothing.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	// What is there now. A CLI config that exists but does not load cleanly is
	// not one to edit.
	var existing []ApiDetails
	created := false
	if _, err := os.Stat(o.CliConfig); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		created = true
	} else if existing, err = ReadApiServers(o.CliConfig); err != nil {
		return nil, fmt.Errorf("cannot read the CLI config %s: %w", o.CliConfig, err)
	}

	// Already there? By config file or by API address, where an address is
	// either of the daemon's: its TCP address or its socket.
	sameDaemonAddr := func(u string) bool {
		if hp := hostPort(u); hp != "" && tcpURL != "" && hp == hostPort(tcpURL) {
			return true
		}
		return socketURL != "" && u == socketURL
	}
	for _, e := range existing {
		// Resolved, so the same daemon config reached through a symlink is
		// the same daemon, not a second one on the same address. The stored
		// path stays as written.
		sameFile := e.ConfigFile != "" && resolvedPath(e.ConfigFile) == resolvedPath(info.ConfigFile)
		// A daemon with no TCP address has an entry with no baseurl: the
		// same address, when it is the same file.
		sameAddr := sameDaemonAddr(e.BaseURL) || (sameFile && e.BaseURL == "" && tcpURL == "")
		// What the daemon config says an entry of e's kind should hold: a
		// socket entry sends no key, a TCP entry the apikey over its TCP
		// address. Compared against baseURL instead, a socket entry would
		// read as a changed key and scheme whenever this add chose TCP.
		wantKey, wantURL := info.ApiKey, tcpURL
		switch {
		case strings.HasPrefix(e.BaseURL, "unix://"):
			wantKey, wantURL = "", socketURL
		case e.BaseURL == "" && sameAddr:
			wantKey = "" // a socket-only entry: no key
		case strings.EqualFold(e.AuthMethod, "certificate"):
			wantKey = e.ApiKey // it sends no key, so the daemon's is not its concern
		}
		switch {
		case sameFile && sameAddr:
			// The same daemon, but it may have changed since: a new key, or
			// usetls turned on or off on the same port. "Already known" would
			// then leave the CLI with an entry that no longer works.
			if diff := changedSettings(e, wantKey, wantURL); diff != "" {
				return nil, fmt.Errorf("entry %q is this daemon, but its %s no longer match %s; edit that entry by hand (config add changes only an existing entry's pins)",
					e.Name, diff, info.ConfigFile)
			}
			res.AlreadyKnown = e.Name
			return repinKnownEntry(o, res, e, existing, target, info)
		case sameFile:
			return nil, fmt.Errorf("entry %q already points at %s but with a different API address (%s, the config says %s); edit or remove that entry by hand",
				e.Name, info.ConfigFile, e.BaseURL, baseURL)
		case sameAddr && e.ConfigFile == "":
			// Typically the canonical entry written before config-file: existed.
			res.AlreadyKnown = e.Name
			res.Notes = append(res.Notes, fmt.Sprintf(
				"entry %q already uses %s; it has no config-file: -- add \"config-file: %s\" to it if it is this daemon",
				e.Name, e.BaseURL, info.ConfigFile))
			if diff := changedSettings(e, wantKey, wantURL); diff != "" {
				res.Notes = append(res.Notes, fmt.Sprintf(
					"entry %q: its %s do not match %s; if it is this daemon, edit them by hand",
					e.Name, diff, info.ConfigFile))
				return res, nil
			}
			// Its key and scheme are this daemon's, on this daemon's address:
			// pin it as the daemon's own entry would be.
			return repinKnownEntry(o, res, e, existing, target, info)
		case sameAddr:
			return nil, fmt.Errorf("entry %q (config-file %s) already uses the API address %s, which %s also names; two daemons cannot listen on one address",
				e.Name, e.ConfigFile, e.BaseURL, info.ConfigFile)
		}
	}

	entry := ApiDetails{
		BaseURL:    baseURL,
		ApiKey:     info.ApiKey,
		AuthMethod: "X-API-Key", // spelled exactly so: the client matches it case-sensitively
		RootCA:     o.RootCA,
		ConfigFile: info.ConfigFile,
	}
	if tcpURL == "" {
		// Only the socket, found through config-file:. No key and no TLS: the
		// daemon authenticates the socket by file permissions.
		entry.ApiKey, entry.AuthMethod, entry.RootCA = "", "none", ""
	}
	if err := chooseEntryName(&entry, res, info.Role, existing, o); err != nil {
		return nil, err
	}
	if strings.HasPrefix(entry.BaseURL, "https://") && entry.RootCA == "" {
		// The daemon's own certificate, pinned: no CA, no name check, and
		// nothing for the operator to do. A new entry that cannot be pinned
		// is not written: tdns-ncli would refuse it (the owner's ruling,
		// 2026-11-23). A daemon on its default API pair that has not
		// started yet has none: config add makes it, as the daemon would.
		pin, err := defaultApiCert(o, res, info)
		if err != nil {
			return nil, err
		}
		if pin == "" && res.ApiCertWould == "" {
			if pin, err = daemonCertPin(info); err != nil {
				return nil, unpinnableRefusal(info, err)
			}
		}
		if pin != "" {
			entry.TLSAuth, entry.Pins = "pin", []string{pin}
		}
	}

	// A new TCP entry authenticates with the operator's client certificate,
	// never with the API key: the daemon must accept the certificate, or
	// config add must be able to make it (planCert; done below, once the
	// entry is known to fit in the CLI config).
	var cert *CertSetup
	if tcpURL != "" {
		cert = planCert(o, info, commandWord(entry, info.Role))
		res.Cert = cert
		if !cert.usable() {
			return nil, cert.refusal(fmt.Sprintf("not adding %s: a new entry uses your client certificate, and %s",
				info.ConfigFile, cert.whyNot()))
		}
		entry.ApiKey, entry.AuthMethod = "", "certificate"
	}

	// Compared resolved, as the locks are: --config and --file may name the
	// one (missing) CLI config through two aliases of its directory.
	res.Entry, res.File, res.Created = entry, target, created && resolvedPath(target) == resolvedPath(o.CliConfig)

	var src []byte
	if !res.Created {
		if src, err = os.ReadFile(target); err != nil {
			return nil, err
		}
	}
	out, _, err := spliceApiserver(src, entry)
	if errors.Is(err, errFlowApiservers) {
		return nil, fmt.Errorf("%s: %w; add this entry by hand:\n\n%s", target, err, renderEntry(maskKey(entry), itemLayout{indent: defItemIndent, gap: defDashGap, valueCol: defValueCol}))
	}
	if err != nil {
		return nil, err
	}
	if res.Created {
		out = append([]byte(newCliConfigHeader), out...)
	}

	// The result must load, the way the CLI will read it, as exactly the old
	// list plus the new entry. The case this exists for: apiservers: is ALSO
	// defined in an include or in cli.localconfig, which hides this one (lists
	// are replaced, not merged).
	want := append(append([]ApiDetails(nil), existing...), entry)
	hidden := func(gerr error, verb string) string {
		msg := fmt.Sprintf("after adding the entry to %s the CLI config %s as the old list plus the new entry", target, verb)
		if gerr != nil {
			msg += fmt.Sprintf(" (%v)", gerr)
		}
		return msg + ". Is apiservers: also defined in an include: file or in cli.localconfig, which hides it? Use --file to name the file that holds the list."
	}

	// Load it with the edited file laid over the real one, before anything is
	// written, so the add is refused where it would fail and the preview
	// (--dry-run) says the same. Only checking after the write meant undoing
	// it, and an undo cannot always put back what the write changed: with
	// --file a hard link to the file the CLI reads, the rename detaches the
	// two names, and writing the old bytes back does not join them again.
	fs, err := overlayFs(target, out)
	if err != nil {
		return nil, err
	}
	if got, gerr := readApiServers(o.CliConfig, fs); gerr != nil || !sameEntries(got, want) {
		return nil, fmt.Errorf("%s Nothing was written.", hidden(gerr, "would not load"))
	}
	if o.DryRun {
		return res, nil
	}

	// The daemon's side first: an entry that names a certificate the
	// daemon does not accept would only be refused.
	if cert != nil && cert.changesDaemon() {
		if err := cert.apply(o.Ctx); err != nil {
			return nil, cert.refusal(fmt.Sprintf("not adding %s: setting up your client certificate on the daemon failed: %v",
				info.ConfigFile, err))
		}
	}

	// What the daemon's side got for an entry that is not written after
	// all is put back as well.
	daemonBack := func() string {
		if cert == nil || !cert.changesDaemon() {
			return ""
		}
		return " On the daemon's side, " + cert.rollback() + "."
	}
	if err := writeFileAtomic(target, out); err != nil {
		return nil, fmt.Errorf("%v.%s", err, daemonBack())
	}
	res.Wrote = true

	// Check the written result, and undo the change if it is not right.
	got, gerr := ReadApiServers(o.CliConfig)
	if gerr != nil || !sameEntries(got, want) {
		var uerr error
		if res.Created {
			uerr = os.Remove(target)
		} else {
			uerr = writeFileAtomic(target, src)
		}
		msg := hidden(gerr, "does not load")
		if uerr != nil {
			return nil, fmt.Errorf("%s The change could NOT be undone (%v): restore %s by hand.%s", msg, uerr, target, daemonBack())
		}
		return nil, fmt.Errorf("%s The change was undone.%s", msg, daemonBack())
	}
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
			"there was no %s entry yet, so this is the canonical one (tdns-ncli %s ...); --name adds an extra instance instead",
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

// certFilePin is the SPKI pin of the first certificate in the PEM file path.
// Only an absolute path: the daemon opens a relative certfile from its own
// working directory, which is not knowable from here, and pinning some other
// file of the same name would make an entry that never connects.
func certFilePin(path string) (string, error) {
	if path == "" {
		return "", errors.New("the daemon config has no apiserver.certfile")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("apiserver.certfile %q is a relative path, which the daemon resolves from its working directory, so it is not known which file it serves", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return "", fmt.Errorf("%s holds no certificate", path)
		}
		if b.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return "", fmt.Errorf("%s: %w", path, err)
			}
			return tdns.SPKISHA256(c), nil
		}
	}
}

// defaultApiCert makes the default API pair of a daemon that names no
// certfile or keyfile and has not started yet (neither file is there), as
// the daemon does at its first start (tdns.EnsureDefaultApiCert), and
// returns its pin; with o.DryRun it says it would (res.ApiCertWould) and
// makes nothing. "" and no error when there is nothing to make. Half a pair,
// or a pair config add cannot write (not root), is a refusal.
func defaultApiCert(o AddOptions, res *AddResult, info *DaemonApi) (string, error) {
	if !info.CertDefault {
		return "", nil
	}
	cert, key := tdns.ApiCertPaths(info.ConfigFile)
	_, cerr := os.Stat(cert)
	_, kerr := os.Stat(key)
	switch {
	case cerr == nil && kerr == nil:
		return "", nil // there: pinned as any certificate is
	case cerr == nil || kerr == nil:
		// Refused from what is there, never through EnsureDefaultApiCert:
		// if the remaining file went meanwhile, it would write a pair (a dry
		// run included) and leave no refusal to give.
		return "", refuseAdd(info, tdns.HalfApiCertPairError(cert, key, cerr == nil).Error(),
			"put back the missing file, or remove the other (the daemon then makes a new pair, which config add pins), then run config add again")
	case !errors.Is(cerr, os.ErrNotExist) || !errors.Is(kerr, os.ErrNotExist):
		return "", refuseAdd(info, fmt.Sprintf("the daemon's API certificate %s cannot be looked for (%v)", cert, errors.Join(cerr, kerr)),
			"run config add as root on the daemon's host")
	case o.DryRun:
		res.ApiCertWould, res.ApiCertKey = cert, key
		return "", nil
	}
	pin, created, err := tdns.EnsureDefaultApiCert(info.ConfigFile, info.Addresses)
	if err != nil {
		return "", refuseAdd(info, fmt.Sprintf("the daemon's API certificate cannot be created at %s (%v)", cert, err),
			"run config add as root on the daemon's host")
	}
	if created {
		res.ApiCertCreated, res.ApiCertKey = cert, key
	}
	return pin, nil // "" if another made it meanwhile: pinned as usual
}

// refuseAdd is config add's refusal of daemon config info: why, and the fix,
// printed as the other refusals are (printRefusal).
func refuseAdd(info *DaemonApi, why, fix string) addRefusal {
	return addRefusal{why: fmt.Sprintf("not adding %s: %s", info.ConfigFile, why), fix: []string{fix + "."}}
}

// unpinnableRefusal is the refusal of a new https entry whose daemon
// certificate config add cannot pin (err, from daemonCertPin): why, and a
// Fix line that fits. Most often it is the default API pair of a daemon that
// has not started yet, which writes it at its first start.
func unpinnableRefusal(info *DaemonApi, err error) addRefusal {
	why := fmt.Sprintf("the daemon's certificate cannot be pinned (%v)", err)
	var fix string
	_, serr := os.Stat(info.CertFile)
	switch {
	case info.CertDefault && errors.Is(serr, os.ErrNotExist):
		why = fmt.Sprintf("%s is not there yet: the daemon writes its API certificate there when it first starts", info.CertFile)
		fix = "start the daemon (it writes its API certificate at first start), then run config add again"
	case info.CertFile == "":
		fix = "set apiserver.certfile to the certificate the daemon serves, then run config add again"
	case !filepath.IsAbs(info.CertFile):
		fix = "give apiserver.certfile as an absolute path, then run config add again"
	case errors.Is(serr, os.ErrNotExist):
		fix = fmt.Sprintf("put the daemon's certificate at %s, or correct apiserver.certfile, then run config add again", info.CertFile)
	default:
		fix = fmt.Sprintf("make %s a readable PEM certificate here (run config add as root on the daemon's host), then run config add again", info.CertFile)
	}
	return refuseAdd(info, why, fix)
}

// repinKnownEntry brings e, the existing entry for this daemon, up to date.
//
// The pin: an https entry with no pin of the daemon's certificate is broken
// (tdns-ncli refuses it), and so is one whose pins are all of an earlier
// certificate (every connection fails). It gets the pin of the certificate the
// daemon serves, as a new entry does. tlsauth: becomes pin, and a rootca: line
// goes (with pins the client does not read it). An entry that already
// verified by pin keeps its old pins next to the new one, so a certificate
// replaced on disk but not yet served still connects.
//
// The client certificate: an entry that uses the API key is switched to it
// (authmethod: certificate, its apikey: line gone) when the daemon accepts the
// certificate, or config add can make it (planCert). Otherwise it keeps the
// key, which works at both ends (changedSettings checked that the key is the
// daemon's), and the result says what the certificate still needs. An entry
// that already uses the certificate is kept working the same way.
//
// The entry keeps its other lines. The edit is made and checked before the
// daemon's side is touched, so an entry config add cannot rewrite leaves the
// daemon as it was.
//
// The caller holds the CLI config's lock (unless o.DryRun).
func repinKnownEntry(o AddOptions, res *AddResult, e ApiDetails, existing []ApiDetails, target string, info *DaemonApi) (*AddResult, error) {
	res.Entry = e
	lower := strings.ToLower(e.BaseURL)
	https := strings.HasPrefix(lower, "https://")
	if !https && !strings.HasPrefix(lower, "http://") {
		return res, nil // the local socket: no certificate to pin, and none to present
	}
	up, repin := e, false
	if https {
		up, repin = pinnedEntry(res, e, info)
	}

	c := planCert(o, info, commandWord(e, info.Role))
	res.Cert = c
	isCert := strings.EqualFold(e.AuthMethod, "certificate")
	toCert := !isCert && c.usable()

	write, err := knownEdit(o, res, e, up, existing, target, entryEdit{repin: repin, toCert: toCert})
	if err != nil && toCert && c.state != certWorks {
		// The entry cannot be rewritten to use the certificate: it keeps
		// the key, and the daemon's side is left as it is.
		res.Notes = append(res.Notes, fmt.Sprintf("entry %q cannot be switched to your certificate in %s (%v); it keeps the API key", e.Name, target, err))
		toCert, res.Cert = false, nil
		write, err = knownEdit(o, res, e, up, existing, target, entryEdit{repin: repin})
	}
	if err != nil {
		return nil, err
	}

	if !o.DryRun && res.Cert != nil && c.changesDaemon() && (isCert || toCert) {
		if aerr := c.apply(o.Ctx); aerr != nil && toCert {
			// The key, then.
			toCert = false
			if write, err = knownEdit(o, res, e, up, existing, target, entryEdit{repin: repin}); err != nil {
				return nil, err
			}
		}
	}
	// It keeps the key. Whether the daemon takes it does not hold back the
	// pin, which the entry needs either way: an entry whose key the daemon
	// refuses is refused below, after its pin is written.
	keepsKey := !isCert && !toCert
	if keepsKey {
		res.KeyKept = true
		if c.keyUnknown != "" && !c.keyOff {
			res.Notes = append(res.Notes, fmt.Sprintf("whether the daemon takes that key could not be told: %s", c.keyUnknown))
		}
	}
	if repin {
		res.Pinned = true
	}
	if toCert {
		up.AuthMethod, up.ApiKey = "certificate", ""
		res.Switched = true
	}
	if repin || toCert {
		res.Entry, res.File, res.Canonical = up, target, up.Role == ""
	}
	if write != nil && !o.DryRun {
		if err := write(); err != nil {
			// The daemon's side changed for an entry that was not
			// written: put it back too.
			if res.Cert != nil && (res.Cert.didReload || len(res.Cert.undo) > 0) {
				return nil, fmt.Errorf("%v; on the daemon's side, %s", err, res.Cert.rollback())
			}
			return nil, err
		}
	}
	if keepsKey && c.keyOff {
		return nil, keyRefusal(e, c, repin, o.DryRun)
	}
	return res, nil
}

// pinnedEntry is e verifying the daemon by the pin of the certificate in
// certFile, and whether that changes e. When the certificate cannot be read,
// e stays as it is and a note says what that means for it.
func pinnedEntry(res *AddResult, e ApiDetails, info *DaemonApi) (ApiDetails, bool) {
	byPin := strings.EqualFold(e.TLSAuth, "pin") && len(e.Pins) > 0
	pin, err := daemonCertPin(info)
	if err != nil {
		switch {
		case byPin:
			res.Notes = append(res.Notes, fmt.Sprintf(
				"the daemon's certificate could not be read (%v), so entry %q's pins were not checked", err, e.Name))
		case e.TLSAuth == "" && e.RootCA == "":
			// The entry tdns-ncli refuses (it verifies nothing).
			// Over TCP, that is: root may reach the daemon over its local
			// admin socket, which needs no pin, whatever the entry says --
			// when the daemon serves one (config add writes config-file:,
			// so the CLI can find it) and --tcp is not given.
			res.Notes = append(res.Notes, fmt.Sprintf(
				"entry %q has no pin, so tdns-ncli refuses it over TCP (root may still reach the daemon over its local admin socket, while the daemon serves one and --tcp is not given), and the daemon's certificate could not be pinned (%v); add tlsauth: pin and its pins: to the entry by hand (tdns-cli cert pin <apiserver.certfile>)", e.Name, err))
		default:
			// pkix, a rootca: file or rootca: insecure: it connects as it
			// did, and stays as it is.
			res.Notes = append(res.Notes, fmt.Sprintf(
				"entry %q does not pin the daemon's certificate, and config add could not pin it (%v); the entry's verification is unchanged", e.Name, err))
		}
		return e, false
	}
	if byPin && slices.Contains(e.Pins, pin) {
		return e, false
	}
	up := e
	up.TLSAuth, up.RootCA, up.Pins = "pin", "", []string{pin}
	if byPin {
		up.Pins = append(append([]string(nil), e.Pins...), pin)
		res.Notes = append(res.Notes, fmt.Sprintf(
			"entry %q pinned an earlier certificate; its old pins stay until the daemon serves the new one -- remove them then", e.Name))
	}
	if e.RootCA != "" {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"entry %q: its rootca: %s is removed; the pin replaces it", e.Name, e.RootCA))
	}
	return up, true
}

// keyRefusal refuses known entry e, which keeps the API key because the
// certificate does not work, when the daemon does not take that key either:
// the entry cannot authenticate. Its pin, which config add has written
// (repinned) all the same, is said first.
func keyRefusal(e ApiDetails, c *CertSetup, repinned, dryRun bool) addRefusal {
	lead := fmt.Sprintf("entry %q cannot authenticate", e.Name)
	switch {
	case repinned && dryRun:
		lead = fmt.Sprintf("entry %q would be re-pinned, but it cannot authenticate", e.Name)
	case repinned:
		lead = fmt.Sprintf("entry %q is re-pinned, but it cannot authenticate", e.Name)
	}
	return c.refusal(fmt.Sprintf("%s: the daemon does not take its API key (%s), and your certificate does not work here (%s)",
		lead, c.keyWhy, c.whyNot()))
}

// knownEdit prepares the rewrite of e, the entry for this daemon, as up with
// what ed says changed (with ed.toCert: authmethod: certificate, no key). The
// edit is made, and the CLI config loaded with it laid over the file, before
// anything is written: it must load as the old list with that one entry
// changed. It returns the write, which checks again after writing and undoes
// a change that does not load as intended; nil when ed changes nothing.
func knownEdit(o AddOptions, res *AddResult, e, up ApiDetails, existing []ApiDetails, target string, ed entryEdit) (func() error, error) {
	if !ed.repin && !ed.toCert {
		return nil, nil
	}
	if ed.toCert {
		up.AuthMethod, up.ApiKey = "certificate", ""
	}
	byHand := func(why error) error {
		var lines []string
		if ed.toCert {
			lines = append(lines, "   authmethod: certificate")
		}
		if ed.repin {
			lines = append(lines, "   tlsauth: pin", "   pins:    "+pinsFlow(up.Pins))
		}
		if ed.toCert {
			lines = append(lines, "and take out its apikey: line.")
		}
		return fmt.Errorf("entry %q needs changing, and config add cannot rewrite it in %s (%v), so nothing was changed. Use --file to name the file that holds it, or give it these lines by hand:\n\n%s\n",
			e.Name, target, why, strings.Join(lines, "\n"))
	}
	src, err := os.ReadFile(target)
	if err != nil {
		return nil, byHand(err)
	}
	out, err := editEntryText(src, e.Name, up, ed)
	if err != nil {
		return nil, byHand(err)
	}

	want := append([]ApiDetails(nil), existing...)
	for i := range want {
		if reflect.DeepEqual(want[i], e) {
			want[i] = up
			break
		}
	}
	fs, err := overlayFs(target, out)
	if err != nil {
		return nil, err
	}
	if got, gerr := readApiServers(o.CliConfig, fs); gerr != nil || !sameEntries(got, want) {
		if gerr == nil {
			gerr = errors.New("the edited file does not load as that entry changed")
		}
		return nil, byHand(gerr)
	}
	return func() error {
		if err := writeFileAtomic(target, out); err != nil {
			return err
		}
		res.Wrote = true
		if got, gerr := ReadApiServers(o.CliConfig); gerr != nil || !sameEntries(got, want) {
			if uerr := writeFileAtomic(target, src); uerr != nil {
				return fmt.Errorf("changing entry %q in %s left a CLI config that does not load as intended, and the change could NOT be undone (%v): restore %s by hand", e.Name, target, uerr, target)
			}
			return fmt.Errorf("changing entry %q in %s left a CLI config that does not load as intended; the change was undone", e.Name, target)
		}
		return nil
	}, nil
}

// commandWord is the word that reaches entry e of a role daemon: the role
// for the canonical entry, the entry's name for an instance.
func commandWord(e ApiDetails, role string) string {
	if e.Role == "" {
		return role
	}
	return e.Name
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

// changedSettings names the settings in which entry e no longer matches the
// daemon config it points at -- the API key, and the URL scheme that
// apiserver.usetls decides -- or returns "". Neither key is printed.
func changedSettings(e ApiDetails, apiKey, baseURL string) string {
	var what []string
	if e.ApiKey != apiKey {
		what = append(what, "apikey")
	}
	if a, b := urlScheme(e.BaseURL), urlScheme(baseURL); a != b {
		what = append(what, fmt.Sprintf("baseurl scheme (%s; apiserver.usetls now means %s)", a, b))
	}
	if len(what) == 0 {
		return ""
	}
	return strings.Join(what, " and ") + " settings"
}

func urlScheme(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
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

// maskKey returns e with the API key hidden, for anything printed. The key is
// the one secret in the entry and has no business in terminal scrollback. An
// entry without one (a certificate entry) shows no apikey: line at all.
func maskKey(e ApiDetails) ApiDetails {
	if e.ApiKey != "" {
		e.ApiKey = "********"
	}
	return e
}

// printAddResult says what config add did: the verdict first, then the entry
// as written, what was done about the client certificate, and the notes.
// Lines are wrapped to textWidth, notes with their continuation lines
// indented, and a "\n" in a note begins a line of its own.
func printAddResult(w io.Writer, r *AddResult, dryRun bool, cfg string) {
	usesCert := strings.EqualFold(r.Entry.AuthMethod, "certificate")
	notes := func() {
		if len(r.Notes) > 0 {
			fmt.Fprintln(w)
		}
		for _, n := range r.Notes {
			writeWrapped(w, "Note: ", "  ", strings.Split(n, "\n")...)
		}
	}
	if r.AlreadyKnown != "" && !r.Pinned && !r.Switched {
		daemonSide := r.Cert != nil && r.Cert.changesDaemon() && r.Cert.failed == nil && usesCert
		trouble := r.KeyKept && r.Cert != nil && (r.Cert.failed != nil || !r.Cert.usable())
		switch {
		case trouble:
			// The verdict and why, said once.
			r.Cert.writeTrouble(w, fmt.Sprintf("Already known as %q; it keeps the API key: your certificate does not work here", r.AlreadyKnown), true)
		case r.KeyKept:
			fmt.Fprintf(w, "Already known as %q; it keeps the API key.\n", r.AlreadyKnown)
		case daemonSide:
			fmt.Fprintf(w, "Already known as %q; the entry is unchanged.\n", r.AlreadyKnown)
		default:
			fmt.Fprintf(w, "Already known as %q; nothing changed.\n", r.AlreadyKnown)
		}
		printCert(w, r.Cert, usesCert, r.KeyKept, dryRun, trouble)
		notes()
		return
	}
	kind := "instance of " + r.Entry.Role
	if r.Canonical {
		kind = "canonical"
	}
	what := "pinned the daemon's certificate"
	switch {
	case r.Switched && r.Pinned:
		what = "switched it to your client certificate, and pinned the daemon's,"
	case r.Switched:
		what = "switched it to your client certificate"
	}
	var verdict string
	switch {
	case dryRun && r.Switched:
		verdict = fmt.Sprintf("Already known as %q (%s); would have %s in %s:", r.AlreadyKnown, kind, what, r.File)
	case r.Switched:
		verdict = fmt.Sprintf("Already known as %q (%s); %s in %s:", r.AlreadyKnown, kind, what, r.File)
	case dryRun && r.Pinned:
		verdict = fmt.Sprintf("Already known as %q (%s); would pin the daemon's certificate in %s:", r.AlreadyKnown, kind, r.File)
	case r.Pinned:
		verdict = fmt.Sprintf("Already known as %q (%s); pinned the daemon's certificate in %s:", r.AlreadyKnown, kind, r.File)
	case dryRun && r.Created:
		verdict = fmt.Sprintf("Would create %s with %q (%s):", r.File, r.Entry.Name, kind)
	case dryRun:
		verdict = fmt.Sprintf("Would add %q (%s) to %s:", r.Entry.Name, kind, r.File)
	case r.Created:
		verdict = fmt.Sprintf("Created %s with %q (%s):", r.File, r.Entry.Name, kind)
	default:
		verdict = fmt.Sprintf("Added %q (%s) to %s:", r.Entry.Name, kind, r.File)
	}
	writeWrapped(w, "", "", verdict)
	fmt.Fprintln(w)
	fmt.Fprint(w, renderEntry(maskKey(r.Entry), itemLayout{indent: 3, gap: 1, valueCol: defValueCol}))
	switch {
	case r.ApiCertCreated != "":
		fmt.Fprintln(w)
		writeWrapped(w, "", "", "Created the daemon's API certificate "+r.ApiCertCreated, "(key "+r.ApiCertKey+", mode 0600); the daemon uses it when it starts.")
	case r.ApiCertWould != "":
		fmt.Fprintln(w)
		writeWrapped(w, "", "", "Would create the daemon's API certificate "+r.ApiCertWould, "(key "+r.ApiCertKey+", mode 0600) and pin it; the daemon uses it when it starts.")
	}
	printCert(w, r.Cert, usesCert, r.KeyKept, dryRun, false)
	notes()
	if dryRun {
		return
	}
	word := r.Entry.Name
	if r.Canonical {
		for role, key := range builtinRoles() {
			if key == r.Entry.Name {
				word = role
			}
		}
	}
	// The CLI config the add read, not the --file it edited: --file only
	// names where in that config the list lives.
	fmt.Fprintf(w, "\nTry it:  %s %s ping\n", ncliFor(cfg), word)
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
