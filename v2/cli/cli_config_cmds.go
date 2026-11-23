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

The entry is the daemon's TCP address, its API key, and the pin of its
certificate. It also records the daemon config's path as config-file:, so
"tdns-ncli auth2 config check" checks the right daemon, and so that tdns-ncli,
run as root, reaches the daemon over its local admin socket instead (admin, no
key), which it finds in the daemon config: the CLI config does not repeat the
socket's path. tdns-ncli --tcp uses the TCP address even then. A daemon with no
TCP address gets an entry with config-file: only, which only root can use.

The CLI config is
created, mode 0600, if it does not exist. Adding a daemon that is already
there changes nothing, except that an https entry that does not pin the
daemon's current certificate is given that pin (tlsauth: pin): an entry
without one is refused, so this is how an old entry is fixed.`,
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
		// A TCP entry without one would fail every request.
		return nil, fmt.Errorf("%s: apiserver.apikey is not set, so the entry would have no key to send over TCP; set it", info.ConfigFile)
	case info.Socket != "" && tcpURL != "":
		res.Notes = append(res.Notes, fmt.Sprintf(
			"run as root, tdns-ncli reaches this daemon over its local admin socket %s (admin, no key), found through config-file:; tdns-ncli --tcp uses the TCP address", info.Socket))
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
			return repinKnownEntry(o, res, e, existing, target, info.CertFile)
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
			return repinKnownEntry(o, res, e, existing, target, info.CertFile)
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
	} else if strings.HasPrefix(entry.BaseURL, "https://") && entry.RootCA == "" {
		// The daemon's own certificate, pinned: no CA, no name check, and
		// nothing for the operator to do.
		if pin, err := certFilePin(info.CertFile); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"could not pin the daemon's certificate (%v); add tlsauth: pin and its pins: to the entry by hand (tdns-cli cert pin <apiserver.certfile>), or tdns-ncli will refuse to connect", err))
		} else {
			entry.TLSAuth, entry.Pins = "pin", []string{pin}
		}
	}
	if err := chooseEntryName(&entry, res, info.Role, existing, o); err != nil {
		return nil, err
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

	if err := writeFileAtomic(target, out); err != nil {
		return nil, err
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
			return nil, fmt.Errorf("%s The change could NOT be undone (%v): restore %s by hand.", msg, uerr, target)
		}
		return nil, fmt.Errorf("%s The change was undone.", msg)
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

// repinKnownEntry gives e, the existing entry for this daemon, the pin of the
// daemon's certificate when it does not have it. An https entry with no pin is
// broken: tdns-ncli refuses it. So is one whose pins are all of an earlier
// certificate: every connection fails. Running config add again is how either
// is fixed, the same way a new entry gets its pin.
//
// The entry keeps its other lines. tlsauth: becomes pin, and a rootca: line
// goes (with pins the client does not read it). An entry that already
// verified by pin keeps its old pins next to the new one, so a certificate
// replaced on disk but not yet served still connects.
//
// The caller holds the CLI config's lock (unless o.DryRun).
func repinKnownEntry(o AddOptions, res *AddResult, e ApiDetails, existing []ApiDetails, target, certFile string) (*AddResult, error) {
	if !strings.HasPrefix(strings.ToLower(e.BaseURL), "https://") {
		return res, nil // the socket, or plain http: no certificate to pin
	}
	byPin := strings.EqualFold(e.TLSAuth, "pin") && len(e.Pins) > 0
	pin, err := certFilePin(certFile)
	if err != nil {
		if byPin {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"the daemon's certificate could not be read (%v), so entry %q's pins were not checked", err, e.Name))
		} else {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"entry %q has no pin, so tdns-ncli refuses it, and the daemon's certificate could not be pinned (%v); add tlsauth: pin and its pins: to the entry by hand (tdns-cli cert pin <apiserver.certfile>)", e.Name, err))
		}
		return res, nil
	}
	if byPin && slices.Contains(e.Pins, pin) {
		return res, nil
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
	res.Pinned, res.Entry, res.File, res.Canonical = true, up, target, up.Role == ""

	byHand := func(why error) error {
		return fmt.Errorf("entry %q does not pin the daemon's certificate, and config add cannot rewrite it in %s (%v). Use --file to name the file that holds it, or give it these lines by hand:\n\n   tlsauth: pin\n   pins:    %s\n",
			e.Name, target, why, pinsFlow(up.Pins))
	}
	src, err := os.ReadFile(target)
	if err != nil {
		return nil, byHand(err)
	}
	out, err := repinEntryText(src, e.Name, up)
	if err != nil {
		return nil, byHand(err)
	}

	// The result must load as exactly the old list with this one entry
	// changed: checked before anything is written, and again after.
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
			gerr = errors.New("the edited file does not load as that entry pinned")
		}
		return nil, byHand(gerr)
	}
	if o.DryRun {
		return res, nil
	}
	if err := writeFileAtomic(target, out); err != nil {
		return nil, err
	}
	res.Wrote = true
	if got, gerr := ReadApiServers(o.CliConfig); gerr != nil || !sameEntries(got, want) {
		if uerr := writeFileAtomic(target, src); uerr != nil {
			return nil, fmt.Errorf("pinning entry %q in %s left a CLI config that does not load as intended, and the change could NOT be undone (%v): restore %s by hand", e.Name, target, uerr, target)
		}
		return nil, fmt.Errorf("pinning entry %q in %s left a CLI config that does not load as intended; the change was undone", e.Name, target)
	}
	return res, nil
}

// hostPort returns the host:port of a base URL, lower-cased, or "".
func hostPort(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
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
// the one secret in the entry and has no business in terminal scrollback.
func maskKey(e ApiDetails) ApiDetails {
	e.ApiKey = "********"
	return e
}

func printAddResult(w io.Writer, r *AddResult, dryRun bool, cfg string) {
	for _, n := range r.Notes {
		fmt.Fprintf(w, "Note: %s\n", n)
	}
	if r.AlreadyKnown != "" && !r.Pinned {
		fmt.Fprintf(w, "Already known as %q; nothing changed.\n", r.AlreadyKnown)
		return
	}
	kind := "instance of " + r.Entry.Role
	if r.Canonical {
		kind = "canonical"
	}
	switch {
	case dryRun && r.Pinned:
		fmt.Fprintf(w, "Already known as %q (%s); would pin the daemon's certificate in %s:\n\n", r.AlreadyKnown, kind, r.File)
	case r.Pinned:
		fmt.Fprintf(w, "Already known as %q (%s); pinned the daemon's certificate in %s:\n\n", r.AlreadyKnown, kind, r.File)
	case dryRun && r.Created:
		fmt.Fprintf(w, "Would create %s with %q (%s):\n\n", r.File, r.Entry.Name, kind)
	case dryRun:
		fmt.Fprintf(w, "Would add %q (%s) to %s:\n\n", r.Entry.Name, kind, r.File)
	case r.Created:
		fmt.Fprintf(w, "Created %s with %q (%s):\n\n", r.File, r.Entry.Name, kind)
	default:
		fmt.Fprintf(w, "Added %q (%s) to %s:\n\n", r.Entry.Name, kind, r.File)
	}
	fmt.Fprint(w, renderEntry(maskKey(r.Entry), itemLayout{indent: 3, gap: 1, valueCol: defValueCol}))
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
		s := "ok"
		if !pr.BootTime.IsZero() {
			s += ", up " + shortDuration(time.Since(pr.BootTime))
		}
		if pr.Version != "" {
			s += ", " + pr.Version
		}
		if pr.Auth != "" {
			s += "; " + pr.Auth
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
