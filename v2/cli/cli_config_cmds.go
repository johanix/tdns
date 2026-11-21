/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * `tdns-ncli config add|list`: maintaining the CLI's own list of daemons
 * (apiservers:) from the daemons' config files.
 */
package cli

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
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

The new entry records the daemon config's path as config-file:, so
"tdns-ncli auth2 config check" checks the right daemon. The CLI config is
created, mode 0600, if it does not exist. Adding a daemon that is already
there changes nothing.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			o.DaemonConfig = args[0]
			o.CliConfig = cliConfigPath(cmd)
			root := cmd.Root()
			o.CommandWordTaken = func(n string) bool { return findChild(root, n) != nil }

			res, err := AddDaemonConfig(o)
			if err != nil {
				fatalf("%v", err)
			}
			printAddResult(os.Stdout, res, o.DryRun)
		},
	}
	c.Flags().StringVar(&o.Role, "role", "", "daemon type: auth, agent or imr (default: detect from the daemon config)")
	c.Flags().StringVar(&o.Name, "name", "", "name (and command word) for the entry (default: from the file name)")
	c.Flags().StringVar(&o.RootCA, "rootca", "", "rootca for the entry (default: none, which the CLI treats as insecure)")
	c.Flags().StringVar(&o.TargetFile, "file", "", "file to add the entry to, if the apiservers: list is not in the CLI config itself (an include or cli.localconfig)")
	c.Flags().BoolVar(&o.DryRun, "dry-run", false, "show what would be added; change nothing")
	return c
}

// AddOptions is the input to AddDaemonConfig.
type AddOptions struct {
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

	baseURL, err := apiBaseURL(info.Addresses[0], info.UseTLS)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", info.ConfigFile, err)
	}
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
	// that ran in between would otherwise be overwritten (lockCliConfig). A
	// dry run writes nothing and takes no lock.
	if !o.DryRun {
		unlock, err := lockCliConfig(target)
		if err != nil {
			return nil, err
		}
		defer unlock()
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

	// Already there? By config file or by API address.
	for _, e := range existing {
		sameFile := e.ConfigFile != "" && filepath.Clean(e.ConfigFile) == info.ConfigFile
		sameAddr := hostPort(e.BaseURL) != "" && hostPort(e.BaseURL) == hostPort(baseURL)
		switch {
		case sameFile && sameAddr:
			// The same daemon, but it may have changed since: a new key, or
			// usetls turned on or off on the same port. "Already known" would
			// then leave the CLI with an entry that no longer works.
			if diff := changedSettings(e, info.ApiKey, baseURL); diff != "" {
				return nil, fmt.Errorf("entry %q is this daemon, but its %s no longer match %s; edit that entry by hand (config add does not change an existing entry)",
					e.Name, diff, info.ConfigFile)
			}
			res.AlreadyKnown = e.Name
			return res, nil
		case sameFile:
			return nil, fmt.Errorf("entry %q already points at %s but with a different API address (%s, the config says %s); edit or remove that entry by hand",
				e.Name, info.ConfigFile, e.BaseURL, baseURL)
		case sameAddr && e.ConfigFile == "":
			// Typically the canonical entry written before config-file: existed.
			res.AlreadyKnown = e.Name
			res.Notes = append(res.Notes, fmt.Sprintf(
				"entry %q already uses %s; it has no config-file: -- add \"config-file: %s\" to it if it is this daemon",
				e.Name, e.BaseURL, info.ConfigFile))
			if diff := changedSettings(e, info.ApiKey, baseURL); diff != "" {
				res.Notes = append(res.Notes, fmt.Sprintf(
					"entry %q: its %s do not match %s; if it is this daemon, edit them by hand",
					e.Name, diff, info.ConfigFile))
			}
			return res, nil
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
	if err := chooseEntryName(&entry, res, info.Role, existing, o); err != nil {
		return nil, err
	}

	res.Entry, res.File, res.Created = entry, target, created && target == o.CliConfig

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

	if o.DryRun {
		// Load it with the edited file laid over the real one, so the
		// preview fails where the add would fail.
		fs, err := overlayFs(target, out)
		if err != nil {
			return nil, err
		}
		if got, gerr := readApiServers(o.CliConfig, fs); gerr != nil || !sameEntries(got, want) {
			return nil, fmt.Errorf("%s Nothing was written.", hidden(gerr, "would not load"))
		}
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
	hasCanonical := false
	used := map[string]bool{}
	for _, e := range existing {
		used[e.Name] = true
		if e.Name == canonical {
			hasCanonical = true
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
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

// overlayFs is the real file system, read-only, with path reading as data:
// what the file system would look like after the add, without the write. The
// path is laid over both as given and made absolute, since the config may
// name the file either way.
func overlayFs(path string, data []byte) (afero.Fs, error) {
	mem := afero.NewMemMapFs()
	paths := []string{filepath.Clean(path)}
	if abs, err := filepath.Abs(path); err == nil && abs != paths[0] {
		paths = append(paths, abs)
	}
	for _, p := range paths {
		if err := afero.WriteFile(mem, p, data, 0o600); err != nil {
			return nil, err
		}
	}
	return afero.NewCopyOnWriteFs(afero.NewReadOnlyFs(afero.NewOsFs()), mem), nil
}

// ConfigAddHint is the `config add` command line that writes cfg, the CLI
// config the caller found missing: with --config when cfg is not the default,
// so that following the advice creates the file that was missing.
func ConfigAddHint(cfg string) string {
	if cfg == "" || cfg == DefaultCliConfigFile {
		return "tdns-ncli config add"
	}
	if strings.ContainsAny(cfg, " \t'\"$\\`") {
		cfg = "'" + strings.ReplaceAll(cfg, "'", `'\''`) + "'"
	}
	return "tdns-ncli --config " + cfg + " config add"
}

// maskKey returns e with the API key hidden, for anything printed. The key is
// the one secret in the entry and has no business in terminal scrollback.
func maskKey(e ApiDetails) ApiDetails {
	e.ApiKey = "********"
	return e
}

func printAddResult(w io.Writer, r *AddResult, dryRun bool) {
	for _, n := range r.Notes {
		fmt.Fprintf(w, "Note: %s\n", n)
	}
	if r.AlreadyKnown != "" {
		fmt.Fprintf(w, "Already known as %q; nothing changed.\n", r.AlreadyKnown)
		return
	}
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
	fmt.Fprintf(w, "\nTry it:  tdns-ncli %s ping\n", word)
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
				results := CheckEntries(entries, timeout)
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
			printListRows(os.Stdout, rows, check)
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

func printListRows(w io.Writer, rows []ListRow, check bool) {
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
		fmt.Fprintln(w, "No apiservers entries. Add one with: tdns-ncli config add <daemon-config.yaml>")
		return
	}
	fmt.Fprintln(w, columnize.SimpleFormat(lines))
}

// CheckEntries pings each entry's API, concurrently, and returns one result
// string per entry, in order: "ok ..." or "FAIL: ...".
func CheckEntries(entries []ApiDetails, timeout time.Duration) []string {
	out := make([]string, len(entries))
	var wg sync.WaitGroup
	for i := range entries {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i] = pingEntry(entries[i], timeout)
		}(i)
	}
	wg.Wait()
	return out
}

func pingEntry(e ApiDetails, timeout time.Duration) string {
	rootCA := e.RootCA
	if rootCA == "" {
		rootCA = "insecure" // the CLI's own default for an entry with no rootca
	}
	switch rootCA {
	case "insecure":
	case "tlsa":
		return "not checked (rootca: tlsa)"
	default:
		// NewClient exits the process on a CA file it cannot read -- and a
		// directory passes a stat -- which would end the whole list. Read it
		// here and report this entry instead.
		pem, err := os.ReadFile(rootCA)
		if err != nil {
			return "FAIL: rootca: " + err.Error()
		}
		if !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return "FAIL: rootca: " + rootCA + " holds no PEM certificate"
		}
	}

	done := make(chan string, 1)
	go func() {
		api := tdns.NewClient(e.Name, e.BaseURL, e.ApiKey, e.AuthMethod, rootCA)
		if api == nil {
			done <- "FAIL: could not set up an API client"
			return
		}
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
		done <- s
	}()
	select {
	case s := <-done:
		return s
	case <-time.After(timeout):
		return fmt.Sprintf("FAIL: no answer within %s", timeout)
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
