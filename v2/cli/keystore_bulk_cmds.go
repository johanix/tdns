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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

var (
	bulkDest      string
	bulkSrc       string
	bulkForce     bool
	bulkSelExact  []string
	bulkSelSubtre []string
)

// addBulkCommands hangs bulk-export/bulk-import off a class's command tree.
// class is "dnssec", "sig0" or "tsig"; the flag names differ for tsig because
// its keys are named, not zone-scoped.
func addBulkCommands(parent *cobra.Command, role, class string) {
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
			bulkExportRun(role, class)
		},
	}
	bulkExport.Flags().StringVar(&bulkDest, "dest", "", "Directory to write keys and manifest to")
	bulkExport.Flags().StringArrayVarP(&bulkSelExact, exactFlag, exactShorthand, nil, exactHelp)
	bulkExport.Flags().StringArrayVar(&bulkSelSubtre, subtreeFlag, nil, subtreeHelp)
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
			bulkImportRun(role, class)
		},
	}
	bulkImport.Flags().StringVar(&bulkSrc, "src", "", "Directory to read keys and manifest from")
	bulkImport.Flags().BoolVar(&bulkForce, "force", false,
		"Overwrite keystore entries that differ (default: report and skip them)")
	bulkImport.MarkFlagRequired("src")

	parent.AddCommand(bulkExport, bulkImport)
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

func bulkExportRun(role, class string) {
	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	// A blank value is refused rather than ignored. Ignoring it would leave the
	// selector empty, and empty means "everything" — so `--zones "$SUBTREE"`
	// with an unset variable would dump every private key in the keystore.
	// (The server refuses it too; this is just the better error.)
	for _, v := range append(append([]string{}, bulkSelExact...), bulkSelSubtre...) {
		if strings.TrimSpace(v) == "" {
			fmt.Printf("Error: empty selector value. To export everything, pass no selector at all.\n")
			os.Exit(1)
		}
	}

	if len(bulkSelExact) == 0 && len(bulkSelSubtre) == 0 {
		fmt.Printf("No selector given: exporting every %s key in the keystore.\n", classLabel(class))
	}

	tr, err := SendKeystoreCmd(api, tdns.KeystorePost{
		Command:       classCommand(class),
		SubCommand:    "bulk-export",
		SelectExact:   bulkSelExact,
		SelectSubtree: bulkSelSubtre,
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
	if err := os.MkdirAll(bulkDest, 0700); err != nil {
		fmt.Printf("Error creating %s: %v\n", bulkDest, err)
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
	if mode, leaks, err := tdns.DirLeaksBeyondOwner(bulkDest); err != nil {
		fmt.Printf("Error: cannot check permissions on %s: %v\n", bulkDest, err)
		os.Exit(1)
	} else if leaks {
		fmt.Printf("WARNING: %s is mode %04o, i.e. readable beyond its owner, and is about\n"+
			"         to receive private key material. Run 'chmod 700 %s'\n"+
			"         unless that exposure is intended.\n", bulkDest, mode, bulkDest)
	}
	manifest, err := tdns.LoadOrNewKeystoreManifest(bulkDest)
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
			if err := writeKeyPair(bulkDest, base, k.PrivateKey, k.KeyRR); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
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
			if err := writeKeyPair(bulkDest, base, k.PrivateKey, k.KeyRR); err != nil {
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

	if err := manifest.Save(bulkDest); err != nil {
		fmt.Printf("Error writing manifest: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Exported %d %s key(s) to %s\n", written, classLabel(class), bulkDest)
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

func bulkImportRun(role, class string) {
	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	manifest, err := tdns.LoadKeystoreManifest(bulkSrc)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	data := tdns.KeystorePost{
		Command:    classCommand(class),
		SubCommand: "bulk-import",
		Force:      bulkForce,
	}
	var offered int

	switch class {
	case "dnssec":
		keys, err := manifest.LoadDnssecKeys(bulkSrc)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		data.BulkDnssecKeys, offered = keys, len(keys)

	case "sig0":
		keys, err := manifest.LoadSig0Keys(bulkSrc)
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
		fmt.Printf("Manifest in %s lists no %s keys; nothing to do.\n", bulkSrc, classLabel(class))
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
