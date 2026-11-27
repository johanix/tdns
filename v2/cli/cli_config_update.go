/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * `tdns-ncli config update <entry> --cert|--repin`: changing one existing
 * apiservers: entry, with the help of its running daemon.
 */
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

func newConfigUpdateCmd() *cobra.Command {
	var o UpdateOptions
	c := &cobra.Command{
		Use:   "update <entry> (--cert | --repin | --rename <name>)",
		Short: "Enrol your client certificate for an entry, take its daemon's new pins, or rename it",
		Long: `Changes one apiservers: entry, named by its name:. For --cert and
--repin run it as root on the daemon's host, with the daemon running: it
asks it over its local admin socket. The daemon is the entry's
config-file:, or --daemon-config <file> for an entry without one (the
line is then written).

  tdns-ncli config update auth --cert
  tdns-ncli config update auth2 --repin
  tdns-ncli config update tdns-auth --rename auth

--cert: as config add: your certificate (made if you have none), its pin
added by the daemon to its access file as --client-name, one request over
TCP. Then the entry gets the daemon's address if it had none, and the
daemon's pins.

--repin: the pins of the certificate the daemon serves now. One request
over TCP with them, then they replace the entry's pins.

--rename: the entry's new name, which is its command word. An entry with
an old name (tdns-auth, tdns-imr, tdns-agent) is renamed to its role
(auth, imr, agent). Needs no daemon; it goes with --cert or --repin too.

Every edit drops the entry's lines of the API key era (apikey:,
authmethod:, tlsauth:, rootca:). If anything before the write fails, the
entry is left as it was. Every other line of the file, comments
included, stays as it is.`,
		// Checked in UpdateEntry, with the entries listed: cobra's own
		// message would name neither the entries nor a command to run.
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			o.Ctx, o.CliConfig = cmd.Context(), cliConfigPath(cmd)
			root := cmd.Root()
			o.CommandWordTaken = func(n string) bool { return findChild(root, n) != nil }
			o.Args = args
			if len(args) == 1 {
				o.Entry = args[0]
			}
			res, err := UpdateEntry(o)
			if err != nil {
				fatalf("%v", err)
			}
			printUpdateResult(os.Stdout, res, o)
		},
	}
	c.Flags().BoolVar(&o.Cert, "cert", false, "enrol your client certificate and take the daemon's address and pins")
	c.Flags().BoolVar(&o.Repin, "repin", false, "replace the entry's pins with the ones the daemon serves now")
	c.Flags().StringVar(&o.Rename, "rename", "", "the entry's new name (and command word)")
	c.Flags().StringVar(&o.DaemonConfig, "daemon-config", "", "the entry's daemon config, for an entry without config-file:")
	c.Flags().StringVar(&o.ClientName, "client-name", "", "with --cert: your name in the daemon's access file (default: user-host, as client init)")
	c.Flags().StringVar(&o.TargetFile, "file", "", "file that holds the entry, if the apiservers: list is not in the CLI config itself")
	c.Flags().BoolVar(&o.DryRun, "dry-run", false, "show the entry as it would become; enrol nothing, change nothing")
	return c
}

// UpdateOptions is the input to UpdateEntry.
type UpdateOptions struct {
	// Ctx ends the wait for another edit's lock. Nil means no end.
	Ctx context.Context
	// CliConfig is the CLI config; TargetFile the file that holds its
	// apiservers: list, when that is another one.
	CliConfig, TargetFile string
	// Entry is the name: of the entry to change.
	Entry string
	// Args are the command's arguments, when it is the command line's: more
	// or fewer than one is refused, with the entries listed.
	Args []string
	// Cert enrols the client certificate and takes the daemon's address and
	// pins; Repin takes the daemon's current pins. At most one.
	Cert, Repin bool
	// Rename is the entry's new name, alone or with Cert or Repin.
	Rename string
	// DaemonConfig is the entry's daemon config, for an entry without
	// config-file: (which is then written). With one, the same file.
	DaemonConfig string
	// ClientName is the operator's name in the access file (--cert).
	ClientName string
	// DryRun asks the daemon what it serves, and enrols and writes nothing.
	DryRun bool
	// CommandWordTaken reports whether a name is already a command of the
	// CLI (as for config add): --rename refuses one, which wiring would.
	CommandWordTaken func(name string) bool
}

// UpdateResult describes what UpdateEntry did.
type UpdateResult struct {
	// Entry is the entry as it is (or would be) now; Was its name before.
	Entry ApiDetails
	Was   string
	// File is the file that holds it.
	File         string
	Steps, Notes []string
	// Current: --repin found the daemon's pins in the entry already.
	Current bool
	// Wrote: the file was changed.
	Wrote bool
}

// UpdateEntry changes the entry named o.Entry (design 2026-11-25 section
// 5, and 2026-11-26): --cert enrols the client certificate, through steps 1
// to 3 of config add; --repin replaces its pins with the ones its daemon
// serves, after one request over TCP with them; --rename gives it a new
// name. --cert and --repin need the daemon running. Every argument is
// checked before the daemon is asked anything. If anything before the
// write fails, nothing is written. Only the CLI config is locked, and only
// for its own edit.
func UpdateEntry(o UpdateOptions) (*UpdateResult, error) {
	const cmd = "config update"
	target := o.TargetFile
	if target == "" {
		target = o.CliConfig
	}
	// The entry, as the CLI reads it: before the daemon is asked anything,
	// and again under the lock before the write.
	find := func() ([]ApiDetails, int, error) {
		existing, missing, err := cliEntries(o.CliConfig)
		switch {
		case err != nil:
			return nil, 0, err
		case missing:
			return nil, 0, fmt.Errorf("no CLI config %s. This writes one:\n%s",
				o.CliConfig, commandLines(ConfigAddHint(o.CliConfig)+" "+defaultDaemonConfig("auth"), 3))
		}
		for i, e := range existing {
			if e.Name == o.Entry {
				return existing, i, nil
			}
		}
		return existing, -1, nil
	}
	existing, i, err := find()
	if err != nil {
		return nil, err
	}
	switch {
	case o.Args != nil && len(o.Args) != 1, !o.Cert && !o.Repin && o.Rename == "":
		return nil, updateUsage(o.CliConfig, existing, "config update needs an entry and --cert, --repin or\n--rename.")
	case o.Cert && o.Repin:
		return nil, updateUsage(o.CliConfig, existing, "config update takes --cert or --repin, not both.")
	case i < 0:
		return nil, updateUsage(o.CliConfig, existing, fmt.Sprintf("no entry named %q in %s; nothing was\nwritten.", o.Entry, o.CliConfig))
	}
	e := existing[i]
	up := e
	if o.Rename != "" {
		if err := checkRename(o, existing, e); err != nil {
			return nil, err
		}
		up.Name, up.Role = o.Rename, entryRole(e)
	}
	res := &UpdateResult{Was: e.Name, File: target}
	if !o.Cert && !o.Repin {
		res.Entry = up
		return res, writeUpdate(o, target, find, e, up, res, nil, "")
	}

	https := strings.HasPrefix(strings.ToLower(e.BaseURL), "https://")
	daemonCfg := e.ConfigFile
	switch {
	case o.Repin && !https:
		return nil, fmt.Errorf("entry %q has no https address, so no pins to take.\nThis gives it the daemon's address and your certificate:\n%s",
			e.Name, commandLines(retryUpdate(UpdateOptions{CliConfig: o.CliConfig, Entry: o.Entry, Cert: true, Rename: o.Rename,
				DaemonConfig: o.DaemonConfig, TargetFile: o.TargetFile}, ""), 3))
	case daemonCfg == "" && o.DaemonConfig == "":
		with := o
		with.DaemonConfig = defaultDaemonConfig(entryRole(e))
		return nil, fmt.Errorf("entry %q names no daemon config (config-file:), and the\ndaemon is never guessed from the address. If it runs %s:\n%s\nconfig update then writes the config-file: line",
			e.Name, with.DaemonConfig, commandLines(retryUpdate(with, o.ClientName), 3))
	case daemonCfg == "":
		daemonCfg = o.DaemonConfig
	case o.DaemonConfig != "" && resolvedPath(o.DaemonConfig) != resolvedPath(daemonCfg):
		return nil, fmt.Errorf("entry %q names the daemon config %s,\nnot %s (--daemon-config); nothing was written", e.Name, daemonCfg, o.DaemonConfig)
	}

	info, err := ReadDaemonApi(daemonCfg, entryRole(e))
	if err != nil {
		return nil, err
	}
	if err := needSocket(info, cmd); err != nil {
		return nil, err
	}
	res.Notes = append(res.Notes, info.Warnings...)
	tcpURL, notes, err := daemonTCP(info)
	if err != nil {
		return nil, err
	}
	res.Notes = append(res.Notes, notes...)
	sock, list, running, err := askAccess(info, cmd)
	switch {
	case err != nil:
		return nil, err
	case !running:
		return nil, fmt.Errorf("the daemon of %s is not running: its\nlocal admin socket %s does not answer.\nconfig update needs it running; nothing was written", info.ConfigFile, info.Socket)
	}
	if err := daemonReady(info, list, tcpURL, o.Cert, retryUpdate(o, o.ClientName)); err != nil {
		return nil, err
	}

	up.Pins = list.ServerPins
	if e.ConfigFile == "" {
		up.ConfigFile = info.ConfigFile
	}
	if o.Cert && !https {
		up.BaseURL = tcpURL
	}
	if o.Repin && samePins(e.Pins, up.Pins) && up.Name == e.Name {
		if up.ConfigFile == e.ConfigFile {
			res.Entry, res.Current = e, true
			return res, nil
		}
		res.Notes = append(res.Notes, "the pins were current; config-file: is the change")
	}
	// Refused before anything is enrolled: an entry the editor cannot change.
	out, err := renderUpdate(o.CliConfig, target, existing, i, up)
	if err != nil {
		return nil, err
	}
	// The pair the CLI config will name once written (see config add).
	cc, err := prospectiveClientConf(o.CliConfig, target, out)
	if err != nil {
		return nil, err
	}
	client := o.ClientName
	if client == "" {
		client = defaultClientName()
	}
	switch {
	case o.DryRun && o.Cert:
		res.Steps = enrolPlan(cc, client, up.BaseURL, list.Clients)
	case o.DryRun:
		res.Steps = []string{"check one request over TCP to " + up.BaseURL + " with these pins"}
	case o.Cert:
		if err := enrol(sock, o.CliConfig, cc, client, cmd, retryUpdate(o, client), &up, &res.Steps, list, info); err != nil {
			return nil, err
		}
	default:
		ok, err := tcpCheck(up, cc)
		if err != nil {
			return nil, fmt.Errorf("a request over TCP to %s with the daemon's\npins failed: %v\nNothing was written", up.BaseURL, err)
		}
		res.Steps = append(res.Steps, ok)
	}
	res.Entry = up
	if o.DryRun {
		return res, nil
	}
	return res, writeUpdate(o, target, find, e, up, res, &cc, client)
}

// writeUpdate writes up in place of e, the entry the update read, under the
// CLI config's lock: refused when the entry changed meanwhile. With cc (a
// --cert update), the write is also refused when the client pair the CLI
// config names changed since the pin was enrolled as client.
func writeUpdate(o UpdateOptions, target string, find func() ([]ApiDetails, int, error), e, up ApiDetails, res *UpdateResult, cc *CliClientConf, client string) error {
	const cmd = "config update"
	if o.DryRun {
		return nil
	}
	after := func(err error) error {
		if o.Cert {
			return fmt.Errorf("%v.\nThe pin stays enrolled; the next config update reuses it", err)
		}
		return err
	}
	unlock, err := lockEdit(o.Ctx, o.CliConfig, target)
	if err != nil {
		return after(err)
	}
	defer unlock()
	existing, i, err := find()
	switch {
	case err == nil && (i < 0 || !reflect.DeepEqual(existing[i], e)):
		err = fmt.Errorf("entry %q changed while config update ran; nothing was\nwritten", e.Name)
	case err == nil && up.Name != e.Name && slices.ContainsFunc(existing, func(x ApiDetails) bool { return x.Name == up.Name }):
		err = fmt.Errorf("an entry named %q appeared while config update ran;\nnothing was written", up.Name)
	}
	var out []byte
	if err == nil {
		out, err = renderUpdate(o.CliConfig, target, existing, i, up)
	}
	if err == nil && cc != nil && o.Cert {
		if err := samePair(o.CliConfig, target, out, *cc, client, cmd, retryUpdate(o, client)); err != nil {
			return err // says what stays enrolled
		}
	}
	if err == nil {
		err = writeFileAtomic(target, out)
	}
	if err != nil {
		return after(err)
	}
	res.Wrote = true
	return nil
}

// checkRename refuses o.Rename for entry e of existing when it is no usable
// name, is taken, or would make the entry another role's entry.
func checkRename(o UpdateOptions, existing []ApiDetails, e ApiDetails) error {
	n := o.Rename
	role := entryRole(e)
	switch {
	case !validInstanceName(n):
		return fmt.Errorf("--rename %q is not usable: lower-case letters, digits and\nhyphens, starting with a letter, at most 32 characters", n)
	case n == e.Name:
		return fmt.Errorf("entry %q has that name already; nothing was written", n)
	case slices.ContainsFunc(existing, func(x ApiDetails) bool { return x.Name == n }):
		return fmt.Errorf("--rename %q: an entry has that name already; nothing\nwas written", n)
	case oldEntryNames[n] != "":
		return fmt.Errorf("--rename %q: that is an old name, which the CLI does not use;\nnothing was written", n)
	}
	// A role's entry is named after its command tree; any other command word
	// is refused, as config add and wiring refuse it.
	isRoleName := roleEntryOf(ApiDetails{Name: n}, builtinRoles()) != ""
	if !isRoleName && (n == ShowCmdsName || n == "help" || n == "completion" ||
		(o.CommandWordTaken != nil && o.CommandWordTaken(n))) {
		return fmt.Errorf("--rename %q: that is a command of the CLI already; nothing\nwas written", n)
	}
	if other := roleEntryOf(ApiDetails{Name: n}, builtinRoles()); other != "" && other != role {
		return fmt.Errorf("--rename %q: that is the %s entry's name, and this entry is\n%s; nothing was written", n, other, roleOrUnknown(role))
	}
	if role == "" && roleEntryOf(ApiDetails{Name: n}, builtinRoles()) == "" {
		return fmt.Errorf("entry %q has no role:, so it cannot become an instance;\nadd role: to it first; nothing was written", e.Name)
	}
	return nil
}

func roleOrUnknown(role string) string {
	if role == "" {
		return "of no role"
	}
	return "of role " + role
}

// updateUsage is the refusal of a config update that cannot go ahead as
// given: lead says why, and one line per entry of cfg gives the command
// that fixes it (entryFix), so that the first refusal is the only one.
func updateUsage(cfg string, entries []ApiDetails, lead string) error {
	if len(entries) == 0 {
		return fmt.Errorf("%s\nThe CLI config %s has no entries. This adds one:\n%s",
			lead, cfg, commandLines(ConfigAddHint(cfg)+" "+defaultDaemonConfig("auth"), 3))
	}
	type row struct{ name, state, fix string }
	rows := make([]row, len(entries))
	wn, ws := 0, 0
	for i, e := range entries {
		state, fix := entryFix(cfg, e)
		rows[i] = row{e.Name, state, fix}
		wn, ws = max(wn, len(e.Name)), max(ws, len(state))
	}
	fits := true
	for _, r := range rows {
		if 3+wn+2+ws+2+len(r.fix) > 72 {
			fits = false
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nYour entries in %s:\n", lead, cfg)
	for _, r := range rows {
		if fits {
			fmt.Fprintf(&b, "   %-*s  %-*s  %s\n", wn, r.name, ws, r.state, r.fix)
		} else {
			fmt.Fprintf(&b, "   %s (%s):\n%s\n", r.name, r.state, commandLines(r.fix, 6))
		}
	}
	return errors.New(strings.TrimRight(b.String(), "\n"))
}

// entryFix says what state entry e of the CLI config cfg is in, and the
// config update command for it: --rename for an old name, --repin for an
// entry with pins, else --cert.
func entryFix(cfg string, e ApiDetails) (state, fix string) {
	cmd := ncliFor(cfg) + " config update " + shellQuote(e.Name)
	rename := ""
	if n := renamedTo(e); n != "" {
		rename = " --rename " + shellQuote(n)
	}
	daemon := ""
	if e.ConfigFile == "" {
		daemon = " --daemon-config " + shellQuote(likelyDaemonConfig(e))
	}
	switch {
	case usesCert(e) && rename != "":
		return "old name", cmd + rename
	case usesCert(e):
		return "pinned", cmd + " --repin" + daemon
	case e.BaseURL == "" && rename != "":
		return "old name", cmd + rename
	case e.BaseURL == "":
		return "socket only", cmd + " --cert" + daemon
	case rename != "":
		return "old name", cmd + rename + " --cert" + daemon
	}
	return "no pins", cmd + " --cert" + daemon
}

// retryUpdate is o's config update, enrolling as client (--cert, when
// set), as the command line to run it again: a refusal gives it.
func retryUpdate(o UpdateOptions, client string) string {
	c := ncliFor(o.CliConfig) + " config update " + shellQuote(o.Entry)
	if o.Rename != "" {
		c += " --rename " + shellQuote(o.Rename)
	}
	switch {
	case o.Cert && client != "":
		c += " --cert --client-name " + shellQuote(client)
	case o.Cert:
		c += " --cert"
	case o.Repin:
		c += " --repin"
	}
	if o.DaemonConfig != "" {
		c += " --daemon-config " + shellQuote(o.DaemonConfig)
	}
	if o.TargetFile != "" {
		c += " --file " + shellQuote(o.TargetFile)
	}
	if o.DryRun {
		// A dry run's retry stays a dry run: it must not enrol or write.
		c += " --dry-run"
	}
	return c
}

// renderUpdate is target with entry i of existing rewritten as up, checked
// to load, the way the CLI will read it, as existing with only that entry
// changed. Nothing is written.
func renderUpdate(cfg, target string, existing []ApiDetails, i int, up ApiDetails) ([]byte, error) {
	src, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	set, drop := entryEdits(existing[i], up)
	out, err := editEntryText(src, existing[i].Name, set, drop)
	if err != nil {
		return nil, fmt.Errorf("cannot edit entry %q in %s: %v.\nNothing was written. --file names the file that holds it", existing[i].Name, target, err)
	}
	want := slices.Clone(existing)
	want[i] = up
	if err := loadsAs(cfg, target, out, want); err != nil {
		return nil, fmt.Errorf("with entry %q edited, the CLI config %s would not load\nas before with only that entry changed (%v).\nIs apiservers: also in an include: file or in cli.localconfig?\n--file names the file that holds it. Nothing was written", up.Name, cfg, err)
	}
	return out, nil
}

// samePins says whether a and b hold the same pins, in any order.
func samePins(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// printUpdateResult says what config update did, verdict first, and the
// command that tries the entry. The entry and the steps taken are printed
// with -v, and with --dry-run, which is for seeing them.
func printUpdateResult(w io.Writer, r *UpdateResult, o UpdateOptions) {
	renamed := ""
	if r.Was != r.Entry.Name {
		renamed = fmt.Sprintf(" (was %q)", r.Was)
	}
	var lead string
	switch {
	case r.Current:
		fmt.Fprintf(w, "The pins of %q are already current; nothing written.\n", r.Entry.Name)
		return
	case o.DryRun:
		fmt.Fprintf(w, "Would change %q in %s to:\n\n", r.Was, r.File)
	case o.Cert:
		lead = fmt.Sprintf("%q%s now uses your client certificate, in %s.", r.Entry.Name, renamed, r.File)
	case o.Repin:
		lead = fmt.Sprintf("Re-pinned %q%s in %s.", r.Entry.Name, renamed, r.File)
	default:
		lead = fmt.Sprintf("Renamed %q to %q in %s.", r.Was, r.Entry.Name, r.File)
	}
	if lead != "" {
		if r.Wrote {
			verify := ncliFor(o.CliConfig) + " " + commandWord(r.Entry) + " ping"
			if line := lead + " Verify with:  " + verify; len(line) <= 72 {
				lead = line
			} else {
				lead += "\nVerify with:  " + verify
			}
		}
		fmt.Fprintln(w, lead)
	}
	steps := r.Steps
	if o.DryRun || tdns.Globals.Verbose {
		if !o.DryRun {
			fmt.Fprintln(w)
		}
		fmt.Fprint(w, renderEntry(r.Entry, itemLayout{indent: 3, gap: 1}))
	} else {
		steps = nil
		for _, st := range r.Steps {
			if strings.HasPrefix(st, "Made your client certificate") {
				steps = append(steps, st)
			}
		}
	}
	printStepsNotes(w, steps, r.Notes, o.DryRun)
}
