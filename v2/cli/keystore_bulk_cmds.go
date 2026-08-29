/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * bulk-export / bulk-import for the three keystore classes.
 *
 * The keystore lives in a SQLite file, which is a bad home for material that
 * has to outlive the machine: it cannot be reviewed, diffed or committed, and
 * losing it loses every key for every zone the server signs. These two commands
 * move a selected subset out to a reviewable directory and back again — see
 * v2/keystore_manifest.go for the on-disk shape and v2/keystore_bulk.go for the
 * import's create-if-absent rule.
 */

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

// bulkFlags holds one command tree's flag targets. addBulkCommands runs once
// per class in the same process, so package-level targets would be shared by
// all three registrations: correct today only because every registration writes
// the same zero default and one command runs per invocation, and silently
// wrong the moment any class wants a different default. The surrounding
// commands in keystore_cmds.go already scope their targets this way.
type bulkFlags struct {
	dest      string
	format    string
	src       string
	dir       string
	state     string
	noBackup  bool
	force     bool
	selExact  []string
	selSubtre []string
}

// addBulkCommands hangs bulk-export/bulk-import off a class's command tree.
// class is "dnssec", "sig0" or "tsig"; the flag names differ for tsig because
// its keys are named, not zone-scoped.
func addBulkCommands(parent *cobra.Command, role, class string) {
	f := &bulkFlags{}
	exactHelp, subtreeHelp := "Zone to include (repeatable)",
		"Include this zone and everything below it (repeatable)"
	exactFlag, subtreeFlag := "zone", "zones"
	// Shadow the inherited -z/--zone with our repeatable form, shorthand and
	// all: leaving the shorthand behind makes `-z x` an error on exactly the
	// commands where it reads most naturally.
	exactShorthand := "z"
	if class == "tsig" {
		exactHelp, subtreeHelp = "TSIG key name to include (repeatable)",
			"Include this name and everything below it (repeatable)"
		exactFlag, subtreeFlag = "key", "keys"
		exactShorthand = "" // TSIG keys are named, not zone-scoped; -z would be a lie
	}

	bulkExport := &cobra.Command{
		Use:   "bulk-export",
		Short: fmt.Sprintf("Export %s keys from the keystore to a directory", classLabel(class)),
		Long: fmt.Sprintf(`Export %s keys to --dest as BIND-convention key files plus a manifest
that carries what those files cannot (key state, rollover timestamps).

Selection is additive: --%s takes one exact name, --%s takes a name and
everything below it, and both may be repeated. Subtree matching is on label
boundaries, so --%s pq.dnslab does not match notpq.dnslab. With no selector at
all, the whole class is exported.

Re-exporting into a directory MERGES: entries for keys not covered by this
run are left in place, so several exports can populate one directory.`,
			classLabel(class), exactFlag, subtreeFlag, subtreeFlag),
		Run: func(cmd *cobra.Command, args []string) {
			bulkExportRun(role, class, f)
		},
	}
	bulkExport.Flags().StringVar(&f.dest, "dest", "", "Directory to write keys and manifest to")
	// Not for TSIG: a TSIG secret is not a private key and has no bind
	// private-key file, so the flag would be accepted and then ignored.
	if class != "tsig" {
		bulkExport.Flags().StringVar(&f.format, "format", tdns.KeyFormatPEM, keyFormatHelp)
	}
	bulkExport.Flags().StringArrayVarP(&f.selExact, exactFlag, exactShorthand, nil, exactHelp)
	bulkExport.Flags().StringArrayVar(&f.selSubtre, subtreeFlag, nil, subtreeHelp)
	bulkExport.MarkFlagRequired("dest")

	bulkImport := &cobra.Command{
		Use:   "bulk-import",
		Short: fmt.Sprintf("Import %s keys from a directory into the keystore", classLabel(class)),
		Long: fmt.Sprintf(`Import every %s key described by --src/manifest.yaml.

A key that is not in the keystore is inserted. A key that is already there
with identical content is left alone. A key that is already there with
DIFFERENT content is reported and SKIPPED: the running keystore outranks a
file that may be arbitrarily stale, and silently overwriting it is how a stale
export un-rolls a rolled key.

--force flips that last case to overwrite, which is what you want when
recovering a keystore you know to be wrong.`, classLabel(class)),
		Run: func(cmd *cobra.Command, args []string) {
			bulkImportRun(role, class, f)
		},
	}
	bulkImport.Flags().StringVar(&f.src, "src", "", "Directory to read keys and manifest from")
	bulkImport.Flags().BoolVar(&f.force, "force", false,
		"Overwrite keystore entries that differ (default: report and skip them)")
	bulkImport.MarkFlagRequired("src")

	parent.AddCommand(bulkExport, bulkImport)

	// TSIG keys have no key files -- the secret travels in the manifest -- so
	// there is nothing for a file converter to do.
	if class == "tsig" {
		return
	}

	bulkConvert := &cobra.Command{
		Use:   "bulk-convert",
		Short: fmt.Sprintf("Convert a directory of bind9 %s keys into one tdns can pre-load", classLabel(class)),
		Long: fmt.Sprintf(`Convert bind9-generated %s keys in --dir into the form keystore.preload reads.

Two things stand between dnssec-keygen output and a pre-loadable directory: the
private half is in bind's own format rather than PKCS#8 PEM, and there is no
manifest, without which pre-load refuses the directory outright.

This rewrites each .private in place as PEM, keeping the original alongside as
.private.orig, and writes the manifest. The .key files are NOT touched: they
already hold the public RR in exactly the form tdns exports.

Key state comes from bind's .state file (9.16+, dnssec-policy zones), mapped
onto tdns's states. A key with no .state file has no state to read, and it is
not guessed -- pass --state to say which one applies. Guessing wrong is how a
retired key gets published again.

Runs entirely locally: no daemon, no API, no keystore. That is the point --
these directories are built and committed before the server that serves them
exists. Re-running is safe; already-converted keys are left alone.`, classLabel(class)),
		Run: func(cmd *cobra.Command, args []string) {
			bulkConvertRun(class, f)
		},
	}
	bulkConvert.Flags().StringVar(&f.dir, "dir", "", "Directory of bind9 key files to convert in place")
	bulkConvert.Flags().StringVar(&f.state, "state", "",
		"Key state for keys with no .state file (required only for those)")
	bulkConvert.Flags().BoolVar(&f.noBackup, "no-backup", false,
		"Do not keep the original bind-format key as .private.orig")
	bulkConvert.MarkFlagRequired("dir")

	parent.AddCommand(bulkConvert)
}

func bulkConvertRun(class string, f *bulkFlags) {
	// The destination holds private keys and is about to hold more of them in a
	// second form. Same check the export path makes, and for the same reason:
	// MkdirAll's mode is not involved here at all, so an existing 0755 course
	// directory would otherwise go unremarked.
	if mode, leaks, err := tdns.DirLeaksBeyondOwner(f.dir); err != nil {
		fmt.Printf("Error: cannot check permissions on %s: %v\n", f.dir, err)
		os.Exit(1)
	} else if leaks {
		fmt.Printf("WARNING: %s is mode %04o, i.e. readable beyond its owner, and holds\n"+
			"         private key material. Run 'chmod 700 %s'\n"+
			"         unless that exposure is intended.\n", f.dir, mode, f.dir)
	}

	ds, err := tdns.ConvertBindKeyDir(f.dir, tdns.BindConvertOptions{
		Class:        class,
		DefaultState: f.state,
		Backup:       !f.noBackup,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		// Only claim the directory is untouched when it actually is. Validation
		// failures happen before anything is written, and saying so tells the
		// operator to fix the cause and re-run. But a phase-2 failure means
		// earlier keys were already rewritten, and reporting THAT as "unchanged"
		// would be a confident lie about the one state that cannot be diagnosed
		// by looking at the directory.
		var partial *tdns.PartialConvertError
		if errors.As(err, &partial) {
			// MAY have changed, not HAS. The failure happened after writing
			// began, but which keys got as far as being rewritten depends on
			// where in the loop it stopped, and claiming more than that is how
			// the previous version of this message came to be wrong in the
			// other direction.
			fmt.Printf("\nThe failure happened after writing began, so this directory MAY be\n" +
				"partially converted: some keys may now hold PEM while others are\n" +
				"still in bind format.\n")
			if len(ds) > 0 {
				fmt.Printf("Keys this run planned to convert:\n")
				printConvertDispositions(ds)
			}
			fmt.Printf("Check the .private files against any .private.orig beside them before\n" +
				"re-running. Re-running is safe in itself: an already-converted key is\n" +
				"left alone, and an existing .private.orig is never overwritten.\n")
		} else {
			fmt.Printf("Nothing was converted; the directory is unchanged.\n")
		}
		os.Exit(1)
	}

	converted, skipped := printConvertDispositions(ds)
	fmt.Printf("Converted %d %s key(s) in %s; %d left alone.\n",
		converted, classLabel(class), f.dir, skipped)
	if converted > 0 {
		if f.noBackup {
			fmt.Printf("The bind-format originals were NOT kept (--no-backup).\n")
		} else {
			fmt.Printf("The bind-format originals are kept as *.private.orig -- still private keys.\n")
		}
		fmt.Printf("Point keystore.preload.%s at this directory to load them at startup.\n", class)
	}
}

func classLabel(class string) string {
	switch class {
	case "dnssec":
		return "DNSSEC"
	case "sig0":
		return "SIG(0)"
	case "tsig":
		return "TSIG"
	}
	return class
}

func classCommand(class string) string {
	switch class {
	case "dnssec":
		return "dnssec-mgmt"
	case "sig0":
		return "sig0-mgmt"
	case "tsig":
		return "tsig-mgmt"
	}
	return class
}

// --- export ------------------------------------------------------------

func bulkExportRun(role, class string, f *bulkFlags) {
	// Before anything is contacted, selected or printed: a typo here would
	// otherwise surface after the "exporting every key" notice, reading as if
	// the export had already begun.
	if err := tdns.ValidateKeyFormat(f.format); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	// A blank value is refused rather than ignored. Ignoring it would leave the
	// selector empty, and empty means "everything" — so `--zones "$SUBTREE"`
	// with an unset variable would dump every private key in the keystore.
	// (The server refuses it too; this is just the better error.)
	for _, v := range append(append([]string{}, f.selExact...), f.selSubtre...) {
		if strings.TrimSpace(v) == "" {
			fmt.Printf("Error: empty selector value. To export everything, pass no selector at all.\n")
			os.Exit(1)
		}
	}

	if len(f.selExact) == 0 && len(f.selSubtre) == 0 {
		fmt.Printf("No selector given: exporting every %s key in the keystore.\n", classLabel(class))
	}

	tr, err := SendKeystoreCmd(api, tdns.KeystorePost{
		Command:       classCommand(class),
		SubCommand:    "bulk-export",
		KeyFormat:     f.format,
		SelectExact:   f.selExact,
		SelectSubtree: f.selSubtre,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if tr.Error {
		fmt.Printf("Error from the daemon: %s\n", tr.ErrorMsg)
		os.Exit(1)
	}

	// 0700: this directory is about to hold private keys.
	if err := os.MkdirAll(f.dest, 0700); err != nil {
		fmt.Printf("Error creating %s: %v\n", f.dest, err)
		os.Exit(1)
	}
	// MkdirAll applies that 0700 only when it CREATES the directory. Exporting
	// into one that already exists — a checked-out labconfig repo, a shared
	// scratch dir, anything at the usual 0755 — leaves the mode untouched and
	// drops .private files (and, for TSIG, a manifest full of secrets) into a
	// world-listable path with nothing said about it.
	//
	// Checked here, BEFORE the first key is written, so the warning arrives
	// while the operator can still stop and fix the mode rather than after the
	// material is already on disk. Warning rather than refusal, matching the
	// pre-load side: a lab where these keys are public on purpose is a real
	// case, and this is the operator's own explicitly-named destination.
	if mode, leaks, err := tdns.DirLeaksBeyondOwner(f.dest); err != nil {
		fmt.Printf("Error: cannot check permissions on %s: %v\n", f.dest, err)
		os.Exit(1)
	} else if leaks {
		fmt.Printf("WARNING: %s is mode %04o, i.e. readable beyond its owner, and is about\n"+
			"         to receive private key material. Run 'chmod 700 %s'\n"+
			"         unless that exposure is intended.\n", f.dest, mode, f.dest)
	}
	manifest, err := tdns.LoadOrNewKeystoreManifest(f.dest)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var written int
	switch class {
	case "dnssec":
		if len(tr.BulkDnssecKeys) == 0 {
			fmt.Printf("No DNSSEC keys matched.\n")
			return
		}
		for _, k := range tr.BulkDnssecKeys {
			base, err := bulkKeyBasename(k.Zone, k.Algorithm, k.Keyid)
			if err != nil {
				fmt.Printf("Error: %s keyid %d: %v\n", k.Zone, k.Keyid, err)
				os.Exit(1)
			}
			if err := writeKeyPair(f.dest, base, k.PrivateKey, k.KeyRR); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			// A bind export without a .state file is only half a round trip:
			// bulk-convert reads the state from there, and with none present
			// it refuses the key or falls back to --state. The text is pure
			// state and timestamps, so the CLI can render it -- unlike the
			// private key, which needs the algorithm registry.
			if f.format == tdns.KeyFormatBind {
				st, err := tdns.BindKeyStateText(k.State, k.Flags&0x0001 != 0,
					k.PublishedAt, k.ActiveAt, k.RetiredAt)
				if err != nil {
					fmt.Printf("Error: %s keyid %d: %v\n", k.Zone, k.Keyid, err)
					os.Exit(1)
				}
				if err := writeOrVerifyFile(filepath.Join(f.dest, base+".state"), st, 0600); err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(1)
				}
			}
			manifest.UpsertDnssec(tdns.ManifestEntryForDnssec(k, base))
			written++
		}

	case "sig0":
		if len(tr.BulkSig0Keys) == 0 {
			fmt.Printf("No SIG(0) keys matched.\n")
			return
		}
		for _, k := range tr.BulkSig0Keys {
			base, err := bulkKeyBasename(k.Zone, k.Algorithm, k.Keyid)
			if err != nil {
				fmt.Printf("Error: %s keyid %d: %v\n", k.Zone, k.Keyid, err)
				os.Exit(1)
			}
			if err := writeKeyPair(f.dest, base, k.PrivateKey, k.KeyRR); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			manifest.UpsertSig0(tdns.ManifestEntryForSig0(k, base))
			written++
		}

	case "tsig":
		if len(tr.BulkTsigKeys) == 0 {
			fmt.Printf("No TSIG keys matched.\n")
			return
		}
		// TSIG has no key files: the secret is the key, and it travels in the
		// manifest.
		for _, k := range tr.BulkTsigKeys {
			manifest.UpsertTsig(tdns.ManifestEntryForTsig(k))
			written++
		}
	}

	if err := manifest.Save(f.dest); err != nil {
		fmt.Printf("Error writing manifest: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Exported %d %s key(s) to %s\n", written, classLabel(class), f.dest)
	fmt.Printf("These files contain private key material. Keep the directory at mode 0700.\n")
}

// bulkKeyBasename derives the BIND-convention basename for a key. The manifest
// records the resulting file names, so this derivation happens only here, on
// the way out — the import side never has to redo it, and therefore never needs
// to resolve an algorithm name it may not link.
func bulkKeyBasename(owner, algorithm string, keyid uint16) (string, error) {
	algNum, ok := AlgorithmNumber(strings.ToUpper(algorithm))
	if !ok {
		return "", fmt.Errorf("unknown algorithm %q", algorithm)
	}
	return tdns.KeyFileBasename(owner, algNum, keyid), nil
}

// writeKeyPair writes the .private/.key pair, tolerating a re-export of a key
// that is already there: identical content is a no-op, different content is an
// error rather than a silent overwrite (the manifest and the files must agree,
// and the operator should know which one moved).
func writeKeyPair(dir, base, privPEM, keyRR string) error {
	if !strings.HasSuffix(keyRR, "\n") {
		keyRR += "\n"
	}
	if err := writeOrVerifyFile(filepath.Join(dir, base+".private"), privPEM, 0600); err != nil {
		return err
	}
	return writeOrVerifyFile(filepath.Join(dir, base+".key"), keyRR, 0644)
}

func writeOrVerifyFile(path, content string, perm os.FileMode) error {
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if string(existing) == content {
			return nil // already exported, unchanged
		}
		return fmt.Errorf("%s already exists with different content; move it aside if you mean to replace it", path)
	case !os.IsNotExist(err):
		return fmt.Errorf("reading %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		return fmt.Errorf("writing %s: %v", path, err)
	}
	return nil
}

// --- import ------------------------------------------------------------

func bulkImportRun(role, class string, f *bulkFlags) {
	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	manifest, err := tdns.LoadKeystoreManifest(f.src)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	data := tdns.KeystorePost{
		Command:    classCommand(class),
		SubCommand: "bulk-import",
		Force:      f.force,
	}
	var offered int

	switch class {
	case "dnssec":
		keys, err := manifest.LoadDnssecKeys(f.src)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		data.BulkDnssecKeys, offered = keys, len(keys)

	case "sig0":
		keys, err := manifest.LoadSig0Keys(f.src)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		data.BulkSig0Keys, offered = keys, len(keys)

	case "tsig":
		keys := manifest.TsigKeys()
		data.BulkTsigKeys, offered = keys, len(keys)
	}

	if offered == 0 {
		fmt.Printf("Manifest in %s lists no %s keys; nothing to do.\n", f.src, classLabel(class))
		return
	}

	tr, err := SendKeystoreCmd(api, data)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if tr.Error {
		fmt.Printf("Error from the daemon: %s\n", tr.ErrorMsg)
		os.Exit(1)
	}

	printBulkDispositions(tr.BulkDispositions)
	if tr.Msg != "" {
		fmt.Printf("%s\n", tr.Msg)
	}
	// A conflict means the operator's file is not what the server is running.
	// That is worth a non-zero exit: it is the case a script must not treat as
	// a successful restore.
	for _, d := range tr.BulkDispositions {
		if d.Status == tdns.BulkStatusConflict {
			os.Exit(2)
		}
	}
}

func printBulkDispositions(ds []tdns.BulkKeyDisposition) {
	var lines []string
	for _, d := range ds {
		// Unchanged keys are the boring majority of any re-import; listing
		// them buries the two lines that matter.
		if d.Status == tdns.BulkStatusUnchanged {
			continue
		}
		name := d.Name
		if d.Keyid != 0 {
			name = fmt.Sprintf("%s keyid %d", d.Name, d.Keyid)
		}
		line := fmt.Sprintf("  %-9s %s", d.Status, name)
		if d.Detail != "" {
			line += fmt.Sprintf("  (differs: %s)", d.Detail)
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return
	}
	sort.Strings(lines)
	fmt.Printf("%s\n", strings.Join(lines, "\n"))
}

// printConvertDispositions renders one line per key and returns the converted
// and left-alone counts.
func printConvertDispositions(ds []tdns.BindConvertDisposition) (converted, skipped int) {
	var lines []string
	for _, d := range ds {
		switch d.Status {
		case tdns.BindConvertConverted:
			converted++
			lines = append(lines, fmt.Sprintf("  %-11s %s keyid %d (%s)",
				d.Status, d.Zone, d.Keyid, d.Detail))
		default:
			skipped++
			lines = append(lines, fmt.Sprintf("  %-11s %s  (%s)", d.Status, d.Basename, d.Detail))
		}
	}
	sort.Strings(lines)
	if len(lines) > 0 {
		fmt.Printf("%s\n", strings.Join(lines, "\n"))
	}
	return converted, skipped
}
