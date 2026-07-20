/*
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

// var filename string
var keyid int
var NewState, filename, keytype, outdir string

// NewKeystoreCmd returns a fresh "keystore" command tree bound to the
// given role. The subtree (sig0 + dnssec branches with their children
// and flags) is built inline so every attachment point gets unique
// *cobra.Command instances.
func NewKeystoreCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "keystore",
		Short: "Prefix command to access different features of the keystore",
		Long: `The keystore holds SIG(0), DNSSEC, and global TSIG keys.
The CLI contains functions for listing, adding, deleting, and
changing the state of keys.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("keystore called. This is likely a mistake, sub command needed")
		},
	}

	c.AddCommand(newKeystoreSig0Cmd(role), newKeystoreDnssecCmd(role), newKeystoreTsigCmd(role))
	return c
}

func newKeystoreTsigCmd(role string) *cobra.Command {
	var tsigName, tsigAlgo, tsigSecret, tsigSecretFile, tsigOwner, tsigImportFile, tsigImportFormat string
	var tsigForce, tsigYes, tsigInteractive, tsigVerbose, tsigExportBind, tsigExportNsd bool

	c := &cobra.Command{
		Use:   "tsig",
		Short: "Manage global TSIG keys in the keystore",
		Long: `Global TSIG keystore (no --zone). Keys are DB-backed with origin=api
for keys created here; config keys are managed via keys.tsig.`,
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List TSIG keys (no secrets)",
		Run: func(cmd *cobra.Command, args []string) {
			tsigKeyMgmt(role, "list", tsigName, tsigAlgo, tsigSecret, tsigOwner, tsigForce)
		},
	}

	add := &cobra.Command{
		Use:   "add",
		Short: "Add a TSIG key with a known secret",
		Run: func(cmd *cobra.Command, args []string) {
			secret, err := resolveTsigSecret(tsigSecret, tsigSecretFile)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			if secret == "" {
				fmt.Println("Error: set exactly one of --secret or --secret-file")
				os.Exit(1)
			}
			tsigKeyMgmt(role, "add", tsigName, tsigAlgo, secret, tsigOwner, tsigForce)
		},
	}
	add.Flags().StringVar(&tsigName, "name", "", "TSIG key name")
	add.Flags().StringVar(&tsigAlgo, "algorithm", "hmac-sha256", "HMAC algorithm")
	add.Flags().StringVar(&tsigSecretFile, "secret-file", "", "File containing the base64 TSIG secret; preferred over --secret")
	add.Flags().StringVar(&tsigSecret, "secret", "", "Inline TSIG secret (base64). WARNING: visible in shell history / process list; prefer --secret-file")
	add.Flags().StringVar(&tsigOwner, "owner", "api", "Owner label (default api)")
	add.Flags().BoolVar(&tsigForce, "force", false, "Overwrite on secret/algorithm conflict")
	add.MarkFlagRequired("name")

	generate := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new TSIG key and add it to the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			tsigKeyMgmt(role, "generate", tsigName, tsigAlgo, tsigSecret, tsigOwner, tsigForce)
		},
	}
	generate.Flags().StringVar(&tsigName, "name", "", "TSIG key name")
	generate.Flags().StringVar(&tsigAlgo, "algorithm", "hmac-sha256", "HMAC algorithm")
	generate.Flags().StringVar(&tsigOwner, "owner", "api", "Owner label (default api)")
	generate.MarkFlagRequired("name")

	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import TSIG keys from a BIND or NSD config snippet",
		Long: `Scan a config file for TSIG key blocks (not a full config parser).
Default: import new keys and skip conflicts. --force overwrites all conflicts;
--interactive prompts per conflict (two-phase round-trip).`,
		Run: func(cmd *cobra.Command, args []string) {
			tsigKeyImport(role, tsigImportFile, tsigImportFormat, tsigOwner, tsigForce, tsigInteractive, tsigVerbose)
		},
	}
	importCmd.Flags().StringVarP(&tsigImportFile, "file", "f", "", "File containing TSIG key declarations")
	importCmd.Flags().StringVar(&tsigImportFormat, "format", "bind", "Key syntax: bind or nsd")
	importCmd.Flags().StringVar(&tsigOwner, "owner", "api", "Owner label for imported keys")
	importCmd.Flags().BoolVar(&tsigForce, "force", false, "Overwrite all secret/algorithm conflicts")
	importCmd.Flags().BoolVar(&tsigInteractive, "interactive", false, "Prompt per conflict before overwriting")
	importCmd.Flags().BoolVarP(&tsigVerbose, "verbose", "v", false, "List per-key disposition")
	importCmd.MarkFlagRequired("file")

	purgeCmd := &cobra.Command{
		Use:   "purge",
		Short: "Delete unreferenced api-origin TSIG keys owned by api",
		Long: `Dry-run by default: lists purge candidates (origin=api, owner=api,
zero zone references) and deletes nothing. Pass --force to delete all
candidates, or --interactive to prompt per key.`,
		Run: func(cmd *cobra.Command, args []string) {
			tsigKeyPurge(role, tsigForce, tsigInteractive, tsigYes)
		},
	}
	purgeCmd.Flags().BoolVar(&tsigForce, "force", false, "Actually delete; otherwise dry-run")
	purgeCmd.Flags().BoolVar(&tsigInteractive, "interactive", false, "Prompt per purge candidate")
	purgeCmd.Flags().BoolVarP(&tsigYes, "yes", "y", false, "Skip confirmation when used with --force")

	setowner := &cobra.Command{
		Use:   "setowner",
		Short: "Change owner on an api-origin TSIG key",
		Run: func(cmd *cobra.Command, args []string) {
			tsigKeyMgmt(role, "setowner", tsigName, tsigAlgo, tsigSecret, tsigOwner, tsigForce)
		},
	}
	setowner.Flags().StringVar(&tsigName, "name", "", "TSIG key name")
	setowner.Flags().StringVar(&tsigOwner, "owner", "", "New owner label")
	setowner.MarkFlagRequired("name")
	setowner.MarkFlagRequired("owner")

	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete an api-origin TSIG key",
		Run: func(cmd *cobra.Command, args []string) {
			if !tsigYes {
				fmt.Printf("Delete TSIG key %q? [y/N] ", tsigName)
				var ans string
				fmt.Scanln(&ans)
				if ans != "y" && ans != "Y" && ans != "yes" {
					fmt.Println("Aborted.")
					return
				}
			}
			tsigKeyMgmt(role, "delete", tsigName, tsigAlgo, tsigSecret, tsigOwner, tsigForce)
		},
	}
	deleteCmd.Flags().StringVar(&tsigName, "name", "", "TSIG key name")
	deleteCmd.Flags().BoolVarP(&tsigYes, "yes", "y", false, "Skip confirmation prompt")
	deleteCmd.MarkFlagRequired("name")

	exportCmd := &cobra.Command{
		Use:   "export <keyname>",
		Short: "Print a TSIG key's secret (default) or a full BIND/NSD key block, to stdout",
		Long: "Print a TSIG key's base64 secret to stdout with NO trailing newline and\n" +
			"nothing else, so it can be captured inline in another command (e.g. via\n" +
			"shell backticks or $(...)) to TSIG-sign a dog query or transfer:\n" +
			"\n" +
			"    dog @srv -y name.:$(tdns-cli auth keystore tsig export name) zone. axfr\n" +
			"\n" +
			"With --bind or --nsd, print a complete BIND9 or NSD key block instead\n" +
			"(still on stdout). Errors go to stderr so stdout stays clean for capture.",
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tsigKeyExport(role, args[0], tsigExportBind, tsigExportNsd)
		},
	}
	exportCmd.Flags().BoolVar(&tsigExportBind, "bind", false, "Output a complete BIND9 key { ... } block")
	exportCmd.Flags().BoolVar(&tsigExportNsd, "nsd", false, "Output a complete NSD key: block")

	c.AddCommand(list, add, generate, importCmd, exportCmd, setowner, deleteCmd, purgeCmd)
	return c
}

func tsigKeyMgmt(role, subcmd, name, algo, secret, owner string, force bool) {
	data := tdns.KeystorePost{
		Command:       "tsig-mgmt",
		SubCommand:    subcmd,
		TsigKeyname:   name,
		TsigAlgorithm: algo,
		TsigSecret:    secret,
		Owner:         owner,
		Force:         force,
		Creator:       "tdns-cli",
	}

	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	tr, err := SendKeystoreCmd(api, data)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if tr.Error {
		fmt.Printf("Error from server: %s\n", tr.ErrorMsg)
		os.Exit(1)
	}

	switch subcmd {
	case "list":
		var out, rows []string
		if tdns.Globals.ShowHeaders {
			out = append(out, "Name|Algorithm|Origin|Owner|Refs|Created")
		}
		for _, k := range tr.TsigKeys {
			rows = append(rows, fmt.Sprintf("%s|%s|%s|%s|%d|%s",
				k.Name, k.Algorithm, k.Origin, k.Owner, k.RefCount, k.Created))
		}
		sort.Strings(rows)
		out = append(out, rows...)
		fmt.Println(columnize.SimpleFormat(out))

	default:
		if tr.Msg != "" {
			fmt.Println(tr.Msg)
		}
	}
}

// tsigKeyExport prints a TSIG key to stdout for use inline in other commands.
// Default: the base64 secret only, with NO trailing newline and nothing else, so
// it can be captured in `backticks` / $() to TSIG-sign a dog query or transfer.
// --bind / --nsd print a full BIND9 / NSD key block instead. All diagnostics go
// to stderr, so stdout carries only the intended payload.
func tsigKeyExport(role, name string, asBind, asNsd bool) {
	if asBind && asNsd {
		fmt.Fprintln(os.Stderr, "Error: --bind and --nsd are mutually exclusive")
		os.Exit(1)
	}
	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating API client: %v\n", err)
		os.Exit(1)
	}
	tr, err := SendKeystoreCmd(api, tdns.KeystorePost{
		Command:     "tsig-mgmt",
		SubCommand:  "export",
		TsigKeyname: name,
		Creator:     "tdns-cli",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if tr.Error {
		fmt.Fprintf(os.Stderr, "Error from server: %s\n", tr.ErrorMsg)
		os.Exit(1)
	}
	if tr.TsigExport == nil {
		fmt.Fprintf(os.Stderr, "Error: server returned no key for %q\n", name)
		os.Exit(1)
	}
	ex := tr.TsigExport
	kn := strings.TrimSuffix(ex.Name, ".")
	algo := strings.TrimSuffix(ex.Algorithm, ".")
	switch {
	case asBind:
		fmt.Printf("key \"%s\" {\n\talgorithm %s;\n\tsecret \"%s\";\n};\n", kn, algo, ex.Secret)
	case asNsd:
		fmt.Printf("key:\n\tname: \"%s\"\n\talgorithm: %s\n\tsecret: \"%s\"\n", kn, algo, ex.Secret)
	default:
		fmt.Print(ex.Secret) // bare secret, no newline, nothing else
	}
}

func tsigKeyImport(role, file, format, owner string, force, interactive, verbose bool) {
	if tsigForceInteractiveConflict(force, interactive) {
		fmt.Println("Error: --force and --interactive are mutually exclusive")
		os.Exit(1)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", file, err)
		os.Exit(1)
	}
	post := tdns.KeystorePost{
		Command:          "tsig-mgmt",
		SubCommand:       "import",
		TsigImportData:   string(data),
		TsigImportFormat: format,
		Owner:            owner,
		Force:            force,
		TsigVerbose:      verbose,
		Creator:          "tdns-cli",
	}
	if interactive {
		requireInteractiveTTY()
		probe, err := tsigKeystorePost(role, post)
		if err == nil {
			printTsigImportResult(probe, verbose)
			return
		}
		if tsigImportConflictCount(probe.TsigImport) == 0 {
			if probe.ErrorMsg != "" {
				fmt.Printf("Error: %s\n", probe.ErrorMsg)
			} else {
				fmt.Printf("Error: %v\n", err)
			}
			os.Exit(1)
		}
		var overwrite []string
		for _, d := range probe.TsigImport {
			if d.Status != "conflict" {
				continue
			}
			fmt.Printf("Overwrite TSIG key %q? [y/N] ", d.Name)
			var ans string
			fmt.Scanln(&ans)
			if ans == "y" || ans == "Y" || ans == "yes" {
				overwrite = append(overwrite, d.Name)
			}
		}
		if len(overwrite) == 0 {
			fmt.Println("No keys overwritten.")
			os.Exit(1)
		}
		post.TsigOverwrite = overwrite
	}
	tr, err := tsigKeystorePost(role, post)
	if err != nil {
		if tr.Error || len(tr.TsigImport) > 0 || tr.Msg != "" {
			printTsigImportResult(tr, verbose)
		}
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	printTsigImportResult(tr, verbose)
}

func tsigImportConflictCount(dispositions []tdns.TsigKeyDisposition) int {
	n := 0
	for _, d := range dispositions {
		if d.Status == "conflict" {
			n++
		}
	}
	return n
}

func tsigForceInteractiveConflict(force, interactive bool) bool {
	return force && interactive
}

func printTsigImportResult(tr tdns.KeystoreResponse, verbose bool) {
	if tr.Error {
		fmt.Printf("Error from server: %s\n", tr.ErrorMsg)
	}
	if verbose {
		for _, d := range tr.TsigImport {
			fmt.Printf("%s: %s\n", d.Name, d.Status)
		}
	}
	if tr.Msg != "" {
		fmt.Println(tr.Msg)
	}
	if tr.Error {
		os.Exit(1)
	}
}

func tsigKeyPurge(role string, force, interactive, yes bool) {
	if tsigForceInteractiveConflict(force, interactive) {
		fmt.Println("Error: --force and --interactive are mutually exclusive")
		os.Exit(1)
	}
	if yes && !force && !interactive {
		fmt.Println("Error: purge -y requires --force (default is dry-run)")
		os.Exit(1)
	}
	post := tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "purge", Force: force, Creator: "tdns-cli"}
	if interactive {
		requireInteractiveTTY()
		probe, err := tsigKeystorePost(role, post)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if len(probe.TsigKeys) == 0 {
			fmt.Println(probe.Msg)
			return
		}
		var overwrite []string
		for _, k := range probe.TsigKeys {
			fmt.Printf("Purge TSIG key %q (api, 0 refs)? [y/N] ", k.Name)
			var ans string
			fmt.Scanln(&ans)
			if ans == "y" || ans == "Y" || ans == "yes" {
				overwrite = append(overwrite, k.Name)
			}
		}
		if len(overwrite) == 0 {
			fmt.Println("No keys purged.")
			return
		}
		post.TsigOverwrite = overwrite
		post.Force = false
	} else if force && !yes {
		requireTTYOrYes(false, "purge --force")
		fmt.Print("Purge all matching TSIG keys? [y/N] ")
		var ans string
		fmt.Scanln(&ans)
		if ans != "y" && ans != "Y" && ans != "yes" {
			fmt.Println("Aborted.")
			return
		}
	}
	tr, err := tsigKeystorePost(role, post)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if tr.Error {
		fmt.Printf("Error from server: %s\n", tr.ErrorMsg)
		os.Exit(1)
	}
	if len(tr.TsigKeys) > 0 && !force && len(post.TsigOverwrite) == 0 {
		var out, rows []string
		if tdns.Globals.ShowHeaders {
			out = append(out, "Name|Algorithm|Origin|Owner|Created")
		}
		for _, k := range tr.TsigKeys {
			rows = append(rows, fmt.Sprintf("%s|%s|%s|%s|%s", k.Name, k.Algorithm, k.Origin, k.Owner, k.Created))
		}
		sort.Strings(rows)
		out = append(out, rows...)
		fmt.Println(columnize.SimpleFormat(out))
	}
	if tr.Msg != "" {
		fmt.Println(tr.Msg)
	}
}

func tsigKeystorePost(role string, post tdns.KeystorePost) (tdns.KeystoreResponse, error) {
	api, err := GetApiClient(role, true)
	if err != nil {
		return tdns.KeystoreResponse{}, err
	}
	return SendKeystoreCmd(api, post)
}

func newKeystoreSig0Cmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "sig0",
		Short: "Prefix command, only usable via sub-commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("keystore sig0 called (but NYI)")
		},
	}

	add := &cobra.Command{
		Use:   "add",
		Short: "Add a new SIG(0) key pair to the keystore",
		Long: `Add a new SIG(0) key pair to the keystore. Required arguments are the name of the file
containing either the private or the public SIG(0) key and the name of the zone.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("filename", "childzone")
			sig0KeyMgmt(role, "add")
		},
	}
	add.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	add.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to add SIG(0) key for")
	add.MarkFlagRequired("file")
	add.MarkFlagRequired("zone")

	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Add a new SIG(0) key pair to the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("filename", "childzone")
			sig0KeyMgmt(role, "import")
		},
	}
	importCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	importCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to import SIG(0) key for")
	importCmd.MarkFlagRequired("file")
	importCmd.MarkFlagRequired("zone")

	generate := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new SIG(0) key pair and add it to the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename", "state")
			sig0KeyMgmt(role, "generate")
		},
	}
	generate.Flags().StringVarP(&NewState, "state", "", "", "Inital key state (created|published|active|retired)")
	generate.Flags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "",
		sig0AlgorithmsHelp("Algorithm to use for SIG(0) key generation"))
	generate.MarkFlagRequired("state")

	algorithms := &cobra.Command{
		Use:   "algorithms",
		Short: "List the SIG(0) algorithms the server supports",
		Run: func(cmd *cobra.Command, args []string) {
			if err := printServerAlgorithms(role, useSIG0); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List all SIG(0) key pairs in the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			sig0KeyMgmt(role, "list")
		},
	}

	export := &cobra.Command{
		Use:   "export",
		Short: "Export a SIG(0) key pair from the keystore as BIND-style .private/.key files",
		Long: `Write the SIG(0) key pair for (zone, keyid) to two files in BIND filename
convention: K<zone>+<alg-num>+<keyid>.private (PKCS#8 PEM) and .key (zone-file
KEY RR). The resulting pair is directly consumable by commands accepting
--key <basename.private>.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename", "keyid")
			sig0KeyMgmt(role, "export")
		},
	}
	export.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone the key belongs to")
	export.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to export")
	export.Flags().StringVarP(&outdir, "outdir", "o", ".", "Directory to write .private and .key files to")
	export.MarkFlagRequired("zone")
	export.MarkFlagRequired("keyid")

	delete := &cobra.Command{
		Use:   "delete",
		Short: "Delete SIG(0) key pair from the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("keyid", "childzone")
			sig0KeyMgmt(role, "delete")
		},
	}
	delete.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")

	setstate := &cobra.Command{
		Use:   "setstate",
		Short: "Set the state of and existing SIG(0) key pair in the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("keyid", "zonename", "state")
			sig0KeyMgmt(role, "setstate")
		},
	}
	setstate.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	setstate.Flags().StringVarP(&NewState, "state", "", "", "New state of key (created|published|active|retired)")

	c.AddCommand(add, importCmd, generate, algorithms, list, export, delete, setstate)
	return c
}

func newKeystoreDnssecCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "dnssec",
		Short: "Prefix command, only usable via sub-commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("keystore dnssec called (this is an empty prefix command)")
		},
	}

	add := &cobra.Command{
		Use:   "add",
		Short: "Add a new DNSSEC key pair to the keystore",
		Long: `Add a new SIG(0) key pair to the keystore. Required arguments are the name of the file
containing either the private or the public SIG(0) key and the name of the zone.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("filename", "zonename")
			dnssecKeyMgmt(role, "add")
		},
	}
	add.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	add.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to add DNSSEC key for")
	add.MarkFlagRequired("file")
	add.MarkFlagRequired("zone")

	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Add a new DNSSEC key pair to the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("filename", "zonename")
			dnssecKeyMgmt(role, "import")
		},
	}
	importCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	importCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to import DNSSEC key for")
	importCmd.MarkFlagRequired("file")
	importCmd.MarkFlagRequired("zone")

	generate := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new DNSSEC key pair and add it to the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename", "keytype", "state")
			dnssecKeyMgmt(role, "generate")
		},
	}
	generate.Flags().StringVarP(&keytype, "keytype", "", "", "Key type to generate (KSK|ZSK|CSK)")
	generate.Flags().StringVarP(&NewState, "state", "", "", "Inital key state (created|published|active|retired)")
	generate.Flags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "",
		dnssecAlgorithmsHelp("Algorithm to use for DNSSEC key generation"))
	generate.MarkFlagRequired("keytype")
	generate.MarkFlagRequired("state")

	algorithms := &cobra.Command{
		Use:   "algorithms",
		Short: "List the DNSSEC algorithms the server supports",
		Run: func(cmd *cobra.Command, args []string) {
			if err := printServerAlgorithms(role, useDNSSEC); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	policies := &cobra.Command{
		Use:   "policies",
		Short: "List the DNSSEC policies the server loaded (including any in error)",
		Run: func(cmd *cobra.Command, args []string) {
			if err := printServerPolicies(role); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List all DNSSEC key pairs in the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			dnssecKeyMgmt(role, "list")
		},
	}

	export := &cobra.Command{
		Use:   "export",
		Short: "Export a DNSSEC key pair from the keystore as BIND-style .private/.key files",
		Long: `Write the DNSSEC key pair for (zone, keyid) to two files in BIND filename
convention: K<zone>+<alg-num>+<keyid>.private (PKCS#8 PEM) and .key (zone-file
DNSKEY RR). The resulting pair is directly consumable by 'keystore dnssec import'.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename", "keyid")
			dnssecKeyMgmt(role, "export")
		},
	}
	export.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone the key belongs to")
	export.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to export")
	export.Flags().StringVarP(&outdir, "outdir", "o", ".", "Directory to write .private and .key files to")
	export.MarkFlagRequired("zone")
	export.MarkFlagRequired("keyid")

	delete := &cobra.Command{
		Use:   "delete",
		Short: "Delete DNSSEC key pair from the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("keyid", "zonename")
			dnssecKeyMgmt(role, "delete")
		},
	}
	delete.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")

	setstate := &cobra.Command{
		Use:   "setstate",
		Short: "Set the state of and existing DNSSEC key pair in the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("keyid", "zonename", "state")
			dnssecKeyMgmt(role, "setstate")
		},
	}
	setstate.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	setstate.Flags().StringVarP(&NewState, "state", "", "", "New statei of key")

	genDS := &cobra.Command{
		Use:   "gen-ds",
		Short: "Generate DS records for a zone's KSK(s) from the keystore",
		Long:  `Generate DS (Delegation Signer) records for a zone's KSK (Key Signing Key) DNSKEY records stored in the keystore. The command queries the keystore for DNSKEY records for the specified zone, filters for KSKs (keys with the SEP bit set), and generates DS records using SHA-256 and SHA-384 digest algorithms. If --keyid is not specified, DS records are generated for all KSKs in the zone.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			if keyid < 0 || keyid > 65535 {
				fmt.Printf("Error: keyid must be between 0 and 65535, got %d\n", keyid)
				os.Exit(1)
			}
			dnssecGenDS(role)
		},
	}
	genDS.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to generate DS records for")
	genDS.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of specific KSK to generate DS for (optional, if not specified, generates for all KSKs)")
	genDS.MarkFlagRequired("zone")

	rollover := &cobra.Command{
		Use:   "rollover",
		Short: "Perform a manual DNSSEC key rollover (standby→active, active→retired)",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			dnssecKeyMgmt(role, "rollover")
		},
	}
	rollover.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to perform rollover for")
	rollover.Flags().StringVarP(&keytype, "keytype", "", "ZSK", "Key type to roll over (ZSK|KSK)")
	rollover.MarkFlagRequired("zone")

	clear := &cobra.Command{
		Use:   "clear",
		Short: "Permanently delete all DNSSEC keys for a zone (KeyStateWorker will regenerate as needed)",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			zone := tdns.Globals.Zonename
			force, _ := cmd.Flags().GetBool("force")

			if !force {
				fmt.Printf("This will immediately permanently delete all DNSSEC keys for zone %s. Proceed? [y/N]: ", zone)
				var response string
				fmt.Scanln(&response)
				response = strings.ToLower(strings.TrimSpace(response))
				if response != "y" && response != "yes" {
					fmt.Println("Cancelled.")
					return
				}
			}

			dnssecKeyMgmt(role, "clear")
		},
	}
	clear.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to clear all DNSSEC keys for")
	clear.Flags().Bool("force", false, "Skip confirmation prompt")
	clear.MarkFlagRequired("zone")

	policyCleanup := &cobra.Command{
		Use:   "policy-cleanup",
		Short: "Remove a zone's retired keys (and their RRSIGs) now, keeping active keys",
		Long: `After a DNSSEC policy change, the old keys are retired but kept (with their
signatures) so the zone stays validatable while the new keys take over —
leaving the zone briefly double-signed. policy-cleanup collapses that window
early: it removes the retired keys and strips their RRSIGs immediately,
keeping the active keys. Unlike 'clear' (which deletes ALL keys and
regenerates), this only touches retired keys.

Accelerating removal means a resolver still caching only an old (now-removed)
DNSKEY briefly cannot validate until it re-queries; the active keys already
serve. Normally you can just wait for the KeyStateWorker to age the retired
keys out after propagation_delay.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			zone := tdns.Globals.Zonename
			force, _ := cmd.Flags().GetBool("force")
			if !force {
				fmt.Printf("This will immediately remove retired DNSSEC keys (and their signatures) for zone %s. Proceed? [y/N]: ", zone)
				var response string
				fmt.Scanln(&response)
				response = strings.ToLower(strings.TrimSpace(response))
				if response != "y" && response != "yes" {
					fmt.Println("Cancelled.")
					return
				}
			}
			dnssecKeyMgmt(role, "policy-cleanup")
		},
	}
	policyCleanup.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to clean up retired keys for")
	policyCleanup.Flags().Bool("force", false, "Skip confirmation prompt")
	policyCleanup.MarkFlagRequired("zone")

	purge := &cobra.Command{
		Use:   "purge",
		Short: "Delete keys in 'removed' state, keeping the 3 most recent per zone",
		Long: `Delete keys in 'removed' state from the keystore, keeping the 3
most recent per zone (by insert order). Use --zone all to apply to
every zone with removed keys at once.

Dry-run by default: prints the keys that would be deleted and exits
without modifying anything. Pass --force to actually delete.`,
		Run: func(cmd *cobra.Command, args []string) {
			dnssecKeyPurgeCmd(role, cmd)
		},
	}
	purge.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to purge ('all' for every zone)")
	purge.Flags().Bool("force", false, "Actually delete; otherwise dry-run")
	purge.MarkFlagRequired("zone")

	// auto-rollover moved to `zone dnssec auto-rollover` (auth only; agents never
	// sign, so it was vestigial under `agent keystore dnssec`).
	c.AddCommand(add, importCmd, generate, algorithms, policies, list, export, delete, setstate, genDS, rollover, clear, policyCleanup, purge, newKeystoreDnssecPolicyCmd(role), newKeystoreDnssecDsPushCmd(role), newKeystoreDnssecQueryParentCmd(role))
	return c
}

func sig0KeyMgmt(role, cmd string) {
	data := tdns.KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: cmd,
	}

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error creating API client: %v", err)
	}
	switch cmd {
	case "list":
		// no action

	case "add", "import":
		pkc, err := tdns.ReadPrivateKey(filename)
		if err != nil {
			log.Fatalf("Error reading key '%s': %v", filename, err)
		}
		if pkc == nil {
			log.Fatalf("Error: no SIG(0) key found in keyfile '%s'", filename)
		}

		fmt.Printf("KeyRR: %s\n", pkc.KeyRR.String())

		if pkc.KeyType == dns.TypeKEY {
			if pkc.KeyRR.Header().Name != tdns.Globals.Zonename {
				log.Fatalf("Error: name of zone (%s) and name of key (%s) do not match",
					pkc.KeyRR.Header().Name, tdns.Globals.Zonename)
			}

			// Do not log pkc.PrivateKey or pkc.K — they are raw private
			// key material. Log only non-sensitive metadata.
			log.Printf("[tdns-cli] SIG(0) key loaded: name=%s keyid=%d alg=%d",
				pkc.KeyRR.Header().Name, pkc.KeyRR.KeyTag(), pkc.KeyRR.Algorithm)

			data = tdns.KeystorePost{
				Command:         "sig0-mgmt",
				SubCommand:      "add",
				Zone:            tdns.Globals.Zonename,
				PrivateKeyCache: pkc,
				State:           "created",
			}
		}

	case "generate":
		data.Zone = tdns.Globals.Zonename
		data.Keyname = tdns.Globals.Zonename // It should be possible to generate SIG(0) keys for other names than zone names.
		// Bare "-a" lists the server's SIG(0) algorithms and exits;
		// otherwise resolve the name to a codepoint via the server.
		data.Algorithm = ResolveAlgorithm(role, useSIG0)
		data.State = NewState

	case "delete", "setstate", "export":
		data.Keyid = uint16(keyid)
		data.Zone = tdns.Globals.Zonename
		data.Keyname = tdns.Globals.Zonename

	default:
		fmt.Printf("Unknown keystore command: \"%s\"\n", cmd)
		os.Exit(1)
	}

	if cmd == "setstate" {
		data.State = NewState
	}

	if tdns.Globals.Debug {
		log.Printf("sig0KeyMgmt: calling SendKeystoreCmd with data=%v", data)
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

	switch cmd {
	case "list":
		var out, tmplist []string
		if tdns.Globals.ShowHeaders {
			out = append(out, "Signer|State|KeyID|Algorithm|KEY Record")
		}
		if len(tr.Sig0keys) > 0 {
			for k, v := range tr.Sig0keys {
				tmp := strings.Split(k, "::")
				tmplist = append(tmplist, fmt.Sprintf("%s|%s|%s|%v|%.50s...\n",
					tmp[0], v.State, tmp[1], v.Algorithm, v.Keystr))
			}
			sort.Strings(tmplist)
			out = append(out, tmplist...)
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		} else {
			fmt.Printf("No SIG(0) key pairs found\n")
		}

	case "add", "import", "delete", "setstate", "generate":
		if tr.Msg != "" {
			fmt.Printf("%s\n", tr.Msg)
		}

	case "export":
		if len(tr.Sig0keys) == 0 {
			fmt.Printf("No key returned for zone %s keyid %d\n",
				tdns.Globals.Zonename, keyid)
			os.Exit(1)
		}
		for _, v := range tr.Sig0keys {
			if err := writeSig0ExportFiles(v, outdir); err != nil {
				fmt.Printf("Error writing key files: %v\n", err)
				os.Exit(1)
			}
		}
		if tr.Msg != "" {
			fmt.Printf("%s\n", tr.Msg)
		}
	}
}

// writeSig0ExportFiles writes a SIG(0) key pair to two BIND-style files
// in outdir: K<zone>+<alg>+<keyid>.private (PKCS#8 PEM as stored in the
// keystore) and .key (zone-file KEY RR text). The resulting basename is
// directly consumable by tdns.ReadPrivateKey.
// writeNewFile writes data to path, failing if path already exists.
// The O_CREATE|O_EXCL open makes the "don't overwrite" guarantee atomic
// at the OS level (no check-then-write race), which matters because the
// .private file holds an unredacted private key.
func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("refusing to overwrite existing file %s (move or delete it first)", path)
		}
		return fmt.Errorf("open %s: %v", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %v", path, err)
	}
	fmt.Printf("Wrote %s\n", path)
	return nil
}

func writeSig0ExportFiles(sk tdns.Sig0Key, outdir string) error {
	algNum, ok := AlgorithmNumber(strings.ToUpper(sk.Algorithm))
	if !ok {
		return fmt.Errorf("unknown algorithm %q in exported key", sk.Algorithm)
	}
	base := fmt.Sprintf("K%s+%03d+%05d", sk.Name, algNum, sk.Keyid)
	if err := writeNewFile(filepath.Join(outdir, base+".private"), []byte(sk.PrivateKey), 0600); err != nil {
		return err
	}
	keyRR := sk.Keystr
	if !strings.HasSuffix(keyRR, "\n") {
		keyRR += "\n"
	}
	return writeNewFile(filepath.Join(outdir, base+".key"), []byte(keyRR), 0644)
}

func writeDnssecExportFiles(dk tdns.DnssecKey, outdir string) error {
	algNum, ok := AlgorithmNumber(strings.ToUpper(dk.Algorithm))
	if !ok {
		return fmt.Errorf("unknown algorithm %q in exported key", dk.Algorithm)
	}
	base := fmt.Sprintf("K%s+%03d+%05d", dk.Name, algNum, dk.Keyid)
	if err := writeNewFile(filepath.Join(outdir, base+".private"), []byte(dk.PrivateKey), 0600); err != nil {
		return err
	}
	keyRR := dk.Keystr
	if !strings.HasSuffix(keyRR, "\n") {
		keyRR += "\n"
	}
	return writeNewFile(filepath.Join(outdir, base+".key"), []byte(keyRR), 0644)
}

func dnssecKeyMgmt(role, cmd string) {
	data := tdns.KeystorePost{
		Command:    "dnssec-mgmt",
		SubCommand: cmd,
	}

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error creating API client: %v", err)
	}

	switch cmd {
	case "list":
		// no action

	case "add", "import":
		fmt.Printf("Adding DNSSEC key pair to keystore\n")
		pkc, err := tdns.ReadPrivateKey(filename)
		if err != nil {
			log.Fatalf("Error reading key '%s': %v", filename, err)
		}

		if pkc == nil {
			log.Fatalf("Error: no DNSKEY found in keyfile '%s'", filename)
		}

		fmt.Printf("DNSKEY RR: %s\n", pkc.DnskeyRR.String())

		if pkc.KeyType == dns.TypeDNSKEY {
			if pkc.DnskeyRR.Header().Name != tdns.Globals.Zonename {
				log.Fatalf("Error: name of zone (%s) and name of key (%s) do not match",
					tdns.Globals.Zonename, pkc.DnskeyRR.Header().Name)
			}

			data = tdns.KeystorePost{
				Command:         "dnssec-mgmt",
				SubCommand:      "add",
				Zone:            tdns.Globals.Zonename,
				PrivateKeyCache: pkc,
				State:           "created",
			}
		}

	case "generate":
		data.Zone = tdns.Globals.Zonename
		// Bare "-a" lists the server's DNSSEC algorithms and exits;
		// otherwise resolve the name to a codepoint via the server.
		data.Algorithm = ResolveAlgorithm(role, useDNSSEC)
		data.KeyType = keytype // "KSK|ZSK|CSK"
		data.State = NewState

	case "rollover":
		data.Zone = tdns.Globals.Zonename
		data.KeyType = keytype

	case "delete", "setstate", "export":
		data.Keyid = uint16(keyid)
		data.Zone = tdns.Globals.Zonename
		data.Keyname = tdns.Globals.Zonename

	case "clear", "policy-cleanup":
		data.Zone = tdns.Globals.Zonename

	default:
		fmt.Printf("Unknown keystore command: \"%s\"\n", cmd)
		os.Exit(1)
	}

	if cmd == "setstate" {
		data.State = NewState
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

	switch cmd {
	case "list":
		type dnssecListEntry struct {
			zone     string
			state    string // display form, may be "[foreign]"
			rawState string // raw state value used for sorting
			keyid    string
			flags    uint16
			alg      string
			keystr   string
		}
		var entries []dnssecListEntry
		if len(tr.Dnskeys) > 0 {
			fmt.Printf("Known DNSSEC key pairs:\n")
			for k, v := range tr.Dnskeys {
				tmp := strings.Split(k, "::")
				state := v.State
				if state == "foreign" {
					state = "[foreign]"
				}
				entries = append(entries, dnssecListEntry{
					zone: tmp[0], state: state, rawState: v.State, keyid: tmp[1],
					flags: v.Flags, alg: v.Algorithm, keystr: v.Keystr,
				})
			}
			// Sort by zone, then by raw state (so the "[foreign]"
			// display bracket doesn't perturb order — "[" sorts
			// before lowercase letters), then by keyid.
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].zone != entries[j].zone {
					return entries[i].zone < entries[j].zone
				}
				if entries[i].rawState != entries[j].rawState {
					return entries[i].rawState < entries[j].rawState
				}
				return entries[i].keyid < entries[j].keyid
			})
			var out []string
			for _, e := range entries {
				out = append(out, fmt.Sprintf("%s|%s|%s|%d|%s|%.50s...\n",
					e.zone, e.state, e.keyid, e.flags, e.alg, e.keystr))
			}
			if tdns.Globals.ShowHeaders {
				out = append([]string{"Signer|State|KeyID|Flags|Algorithm|DNSKEY Record"}, out...)
			}

			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		} else {
			fmt.Printf("No DNSSEC key pairs found\n")
		}

	case "export":
		if len(tr.Dnskeys) == 0 {
			fmt.Printf("No key returned for zone %s keyid %d\n",
				tdns.Globals.Zonename, keyid)
			os.Exit(1)
		}
		for _, v := range tr.Dnskeys {
			if err := writeDnssecExportFiles(v, outdir); err != nil {
				fmt.Printf("Error writing key files: %v\n", err)
				os.Exit(1)
			}
		}
		if tr.Msg != "" {
			fmt.Printf("%s\n", tr.Msg)
		}

	case "add", "import", "generate", "delete", "setstate", "rollover", "clear", "policy-cleanup":
		if tr.Msg != "" {
			fmt.Printf("%s\n", tr.Msg)
		}
	}

}

// dnssecKeyPurgeCmd handles "keystore dnssec purge". The zone "all"
// passes through verbatim (no Fqdn); anything else is normalized. The
// server returns the set of keys it deleted (or would delete in
// dry-run mode); we print them in the same column format as 'list'.
func dnssecKeyPurgeCmd(role string, cmd *cobra.Command) {
	zoneArg := strings.TrimSpace(tdns.Globals.Zonename)
	if zoneArg == "" {
		fmt.Println("Error: --zone is required (use 'all' to purge every zone)")
		os.Exit(1)
	}
	if strings.EqualFold(zoneArg, "all") {
		zoneArg = "all"
	} else {
		zoneArg = dns.Fqdn(zoneArg)
	}
	force, _ := cmd.Flags().GetBool("force")

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error creating API client: %v", err)
	}

	tr, err := SendKeystoreCmd(api, tdns.KeystorePost{
		Command:    "dnssec-mgmt",
		SubCommand: "purge",
		Zone:       zoneArg,
		Force:      force,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if tr.Error {
		fmt.Printf("Error from the daemon: %s\n", tr.ErrorMsg)
		os.Exit(1)
	}

	if len(tr.Dnskeys) > 0 {
		if force {
			fmt.Println("Purged DNSSEC key pairs:")
		} else {
			fmt.Println("DNSSEC key pairs that would be purged:")
		}
		type entry struct {
			zone, keyid, alg, keystr string
			flags                    uint16
		}
		var entries []entry
		for k, v := range tr.Dnskeys {
			tmp := strings.SplitN(k, "::", 2)
			if len(tmp) != 2 {
				continue
			}
			entries = append(entries, entry{
				zone:   tmp[0],
				keyid:  tmp[1],
				flags:  v.Flags,
				alg:    v.Algorithm,
				keystr: v.Keystr,
			})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].zone != entries[j].zone {
				return entries[i].zone < entries[j].zone
			}
			return entries[i].keyid < entries[j].keyid
		})
		var out []string
		for _, e := range entries {
			out = append(out, fmt.Sprintf("%s|%s|%d|%s|%.50s...\n",
				e.zone, e.keyid, e.flags, e.alg, e.keystr))
		}
		if tdns.Globals.ShowHeaders {
			out = append([]string{"Signer|KeyID|Flags|Algorithm|DNSKEY Record"}, out...)
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	}
	if tr.Msg != "" {
		fmt.Println(tr.Msg)
	}
}

func dnssecGenDS(role string) {
	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error: failed to get API client: %v", err)
	}

	// First, list all DNSSEC keys to find the ones for our zone
	data := tdns.KeystorePost{
		Command:    "dnssec-mgmt",
		SubCommand: "list",
	}

	tr, err := SendKeystoreCmd(api, data)
	if err != nil {
		log.Fatalf("Error listing DNSSEC keys: %v", err)
	}

	if tr.Error {
		log.Fatalf("Error from keystore: %s", tr.ErrorMsg)
	}

	if len(tr.Dnskeys) == 0 {
		fmt.Printf("No DNSSEC keys found in keystore\n")
		return
	}

	zone := dns.Fqdn(tdns.Globals.Zonename)
	trimmed := strings.TrimSuffix(zone, ".")
	if trimmed == "" {
		log.Fatalf("Error: cannot generate DS for root zone")
	}

	// Filter keys for the specified zone and optionally keyid
	ksks := make([]tdns.DnssecKey, 0, len(tr.Dnskeys))
	for k, v := range tr.Dnskeys {
		parts := strings.Split(k, "::")
		if len(parts) != 2 {
			continue
		}
		keyZone := dns.Fqdn(parts[0])
		if keyZone != zone {
			continue
		}

		// Parse keyid from the map key
		keyidStr := parts[1]
		parsedKeyid, err := strconv.ParseUint(keyidStr, 10, 16)
		if err != nil {
			if tdns.Globals.Verbose {
				fmt.Printf("Warning: skipping key with invalid keyid %s: %v\n", keyidStr, err)
			}
			continue
		}
		v.Keyid = uint16(parsedKeyid)

		// If --keyid was specified, filter by it
		if keyid != 0 && uint16(parsedKeyid) != uint16(keyid) {
			continue
		}

		// Filter for KSKs (keys with SEP flag bit 0 set, flags & 0x0001 != 0)
		// Note: SEP flag is bit 0 (0x0001), ZONE flag is bit 8 (0x0100)
		// ZSK = 256 (0x0100) = only ZONE flag, KSK = 257 (0x0101) = ZONE + SEP flags
		// For DS generation, we want KSKs (SEP bit 0 set)
		if v.Flags&0x0001 == 0 {
			continue
		}

		ksks = append(ksks, v)
	}

	// Sort KSKs by Keyid after collecting all of them
	sort.Slice(ksks, func(i, j int) bool {
		return ksks[i].Keyid < ksks[j].Keyid
	})

	if len(ksks) == 0 {
		if keyid != 0 {
			fmt.Printf("No KSK with keyid %d found for zone %s\n", keyid, zone)
		} else {
			fmt.Printf("No KSK (Key Signing Key) found for zone %s\n", zone)
			fmt.Println("KSKs are identified by having the SEP (Secure Entry Point) bit set (flags & 0x0001 != 0)")
		}
		return
	}

	fmt.Printf("Found %d KSK(s) for zone %s\n\n", len(ksks), zone)
	fmt.Println("DS records (for parent zone):")
	fmt.Println()

	// Generate DS records for each KSK using SHA-256 and SHA-384
	for i, ksk := range ksks {
		// Parse the DNSKEY record from Keystr (the Key field may not be populated)
		rr, err := dns.NewRR(ksk.Keystr)
		if err != nil {
			fmt.Printf("Error parsing DNSKEY record for keyid %d: %v\n", ksk.Keyid, err)
			continue
		}
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			fmt.Printf("Error: keyid %d is not a DNSKEY record\n", ksk.Keyid)
			continue
		}

		keytag := dnskey.KeyTag()
		algorithm := dnskey.Algorithm
		alg := dns.AlgorithmToString[algorithm]

		// Generate DS with SHA-256 (digest type 2)
		ds256 := dnskey.ToDS(dns.SHA256)
		if ds256 != nil {
			fmt.Printf("%s. IN DS %d %d %d %s ; %s (SHA-256)\n", trimmed, keytag, algorithm, dns.SHA256, ds256.Digest, alg)
		}

		// Generate DS with SHA-384 (digest type 4)
		ds384 := dnskey.ToDS(dns.SHA384)
		if ds384 != nil {
			fmt.Printf("%s. IN DS %d %d %d %s ; %s (SHA-384)\n", trimmed, keytag, algorithm, dns.SHA384, ds384.Digest, alg)
		}

		if i < len(ksks)-1 {
			fmt.Println()
		}
	}

}

func SendKeystoreCmd(api *tdns.ApiClient, data tdns.KeystorePost) (tdns.KeystoreResponse, error) {

	// fmt.Printf("Sending keystore command: %v\n", data)

	var kr tdns.KeystoreResponse

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/keystore", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return kr, fmt.Errorf("error from api post: %v", err)
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &kr)
	if err != nil {
		return kr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if kr.Error {
		return kr, fmt.Errorf("%s", kr.ErrorMsg)
	}

	return kr, nil
}
