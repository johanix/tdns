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
)

func newConfigUpdateCmd() *cobra.Command {
	var o UpdateOptions
	c := &cobra.Command{
		Use:   "update <entry> (--cert | --repin)",
		Short: "Switch an entry to your client certificate, or take the daemon's new pins",
		Long: `Changes one apiservers: entry, named by its name:. Run it as root on the
daemon's host, with the daemon running: it asks it over its local admin
socket. The daemon is the entry's config-file:, or --daemon-config <file>
for an entry without one (the line is then written).

  tdns-ncli config update tdns-auth --cert
  tdns-ncli config update auth2 --repin

--cert: from the API key to your client certificate, or a config-file:-only
entry completed. As config add: your certificate (made if you have none),
its pin added by the daemon as --client-name, one request over TCP. Then
the entry gets the daemon's address if it had none, authmethod: certificate
and the daemon's pins; its apikey: and rootca: go.

--repin: the pins of the certificate the daemon serves now. One request
over TCP with them, then they replace the entry's pins.

If anything before the write fails, the entry is left as it was. Every
other line of the file, comments included, stays as it is.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			o.Ctx, o.Entry, o.CliConfig = cmd.Context(), args[0], cliConfigPath(cmd)
			res, err := UpdateEntry(o)
			if err != nil {
				fatalf("%v", err)
			}
			printUpdateResult(os.Stdout, res, o)
		},
	}
	c.Flags().BoolVar(&o.Cert, "cert", false, "switch the entry to your client certificate")
	c.Flags().BoolVar(&o.Repin, "repin", false, "replace the entry's pins with the ones the daemon serves now")
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
	// Cert switches the entry to the client certificate; Repin takes the
	// daemon's current pins. Exactly one.
	Cert, Repin bool
	// DaemonConfig is the entry's daemon config, for an entry without
	// config-file: (which is then written). With one, the same file.
	DaemonConfig string
	// ClientName is the operator's name in the access file (--cert).
	ClientName string
	// DryRun asks the daemon what it serves, and enrols and writes nothing.
	DryRun bool
}

// UpdateResult describes what UpdateEntry did.
type UpdateResult struct {
	// Entry is the entry as it is (or would be) now.
	Entry ApiDetails
	// File is the file that holds it.
	File         string
	Steps, Notes []string
	// Current: --repin found the daemon's pins in the entry already.
	Current bool
	// Wrote: the file was changed.
	Wrote bool
}

// UpdateEntry changes the entry named o.Entry (design 2026-11-25 section
// 5): --cert switches it to the client certificate, through steps 1 to 3 of
// config add; --repin replaces its pins with the ones its daemon serves,
// after one request over TCP with them. The daemon must be running. If
// anything before the write fails, nothing is written. Only the CLI config
// is locked, and only for its own edit.
func UpdateEntry(o UpdateOptions) (*UpdateResult, error) {
	if o.Cert == o.Repin {
		return nil, errors.New("give one of --cert (to your client certificate) and\n--repin (the daemon's current pins)")
	}
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
			return nil, 0, fmt.Errorf("no CLI config %s; %s <daemon-config.yaml>\nwrites one", o.CliConfig, ConfigAddHint(o.CliConfig))
		}
		for i, e := range existing {
			if e.Name == o.Entry {
				return existing, i, nil
			}
		}
		return nil, 0, fmt.Errorf("no entry named %q in %s\n(config list shows them); nothing was written", o.Entry, o.CliConfig)
	}
	existing, i, err := find()
	if err != nil {
		return nil, err
	}
	e := existing[i]
	https := strings.HasPrefix(strings.ToLower(e.BaseURL), "https://")
	daemonCfg := e.ConfigFile
	switch {
	case o.Cert && usesCert(e):
		return nil, fmt.Errorf("entry %q already uses a certificate; --repin takes\nnew pins", e.Name)
	case o.Repin && !https:
		return nil, fmt.Errorf("entry %q has no https address, so no pins to take;\n--cert gives it the daemon's address and your certificate", e.Name)
	case daemonCfg == "" && o.DaemonConfig == "":
		return nil, fmt.Errorf("entry %q names no daemon config (config-file:).\nName it with --daemon-config <file>, and config update\nwrites the line; the daemon is never guessed from the address", e.Name)
	case daemonCfg == "":
		daemonCfg = o.DaemonConfig
	case o.DaemonConfig != "" && resolvedPath(o.DaemonConfig) != resolvedPath(daemonCfg):
		return nil, fmt.Errorf("entry %q names the daemon config %s,\nnot %s (--daemon-config); nothing was written", e.Name, daemonCfg, o.DaemonConfig)
	}

	role := e.Role
	if role == "" && commandWord(e) != e.Name {
		role = commandWord(e) // the canonical entry of a built-in role
	}
	info, err := ReadDaemonApi(daemonCfg, role)
	if err != nil {
		return nil, err
	}
	if err := needSocket(info, cmd); err != nil {
		return nil, err
	}
	res := &UpdateResult{Notes: append([]string(nil), info.Warnings...)}
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
	if err := daemonReady(info, list, tcpURL, o.Cert); err != nil {
		return nil, err
	}

	up := e
	up.TLSAuth, up.Pins, up.RootCA = "pin", list.ServerPins, "" // pins replace roots
	if e.ConfigFile == "" {
		up.ConfigFile = info.ConfigFile
	}
	if o.Cert {
		if !https {
			up.BaseURL = tcpURL
		}
		up.AuthMethod, up.ApiKey = "certificate", ""
	}
	if o.Repin && strings.EqualFold(e.TLSAuth, "pin") && samePins(e.Pins, up.Pins) {
		res.Entry, res.File, res.Current = e, target, true
		return res, nil
	}
	// Refused before anything is enrolled: an entry the editor cannot change.
	out, err := renderUpdate(o.CliConfig, target, existing, i, up)
	if err != nil {
		return nil, err
	}
	cc := ReadCliClientConf(o.CliConfig)
	client := o.ClientName
	if client == "" {
		client = defaultClientName()
	}
	switch {
	case o.DryRun && o.Cert:
		res.Steps = enrolPlan(cc, client, up.BaseURL)
	case o.DryRun:
		res.Steps = []string{"check one request over TCP to " + up.BaseURL + " with these pins"}
	case o.Cert:
		if err := enrol(sock, cc, client, cmd, &up, &res.Steps); err != nil {
			return nil, err
		}
	default:
		ok, err := tcpCheck(up, cc)
		if err != nil {
			return nil, fmt.Errorf("a request over TCP to %s with the daemon's\npins failed: %v\nNothing was written", up.BaseURL, err)
		}
		res.Steps = append(res.Steps, ok)
	}
	res.Entry, res.File = up, target
	if o.DryRun {
		return res, nil
	}

	after := func(err error) error {
		if o.Cert {
			return fmt.Errorf("%v.\nThe pin stays enrolled; the next config update reuses it", err)
		}
		return err
	}
	unlock, err := lockEdit(o.Ctx, o.CliConfig, target)
	if err != nil {
		return nil, after(err)
	}
	defer unlock()
	if existing, i, err = find(); err == nil && !reflect.DeepEqual(existing[i], e) {
		err = fmt.Errorf("entry %q changed while config update ran; nothing was\nwritten", e.Name)
	}
	if err == nil && o.Cert {
		if err := samePair(o.CliConfig, cc, cmd); err != nil {
			return nil, err // says what stays enrolled
		}
	}
	if err == nil {
		out, err = renderUpdate(o.CliConfig, target, existing, i, up)
	}
	if err == nil {
		err = writeFileAtomic(target, out)
	}
	if err != nil {
		return nil, after(err)
	}
	res.Wrote = true
	return res, nil
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
	out, err := editEntryText(src, up.Name, set, drop)
	if err != nil {
		return nil, fmt.Errorf("cannot edit entry %q in %s: %v.\nNothing was written. --file names the file that holds it", up.Name, target, err)
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

// printUpdateResult says what config update did, verdict first, in lines of
// at most 72 where it can.
func printUpdateResult(w io.Writer, r *UpdateResult, o UpdateOptions) {
	switch {
	case r.Current:
		fmt.Fprintf(w, "The pins of %q are already current; nothing written.\n", r.Entry.Name)
		return
	case o.DryRun:
		fmt.Fprintf(w, "Would change %q in %s to:\n\n", r.Entry.Name, r.File)
	case o.Cert:
		fmt.Fprintf(w, "Switched %q to your client certificate in %s:\n\n", r.Entry.Name, r.File)
	default:
		fmt.Fprintf(w, "Re-pinned %q in %s:\n\n", r.Entry.Name, r.File)
	}
	fmt.Fprint(w, renderEntry(r.Entry, itemLayout{indent: 3, gap: 1}))
	printStepsNotes(w, r.Steps, r.Notes, o.DryRun)
	if r.Wrote {
		fmt.Fprintf(w, "\nTry it:  %s %s ping\n", ncliFor(o.CliConfig), commandWord(r.Entry))
	}
}
