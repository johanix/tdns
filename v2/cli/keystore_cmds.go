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
		Long: `The keystore holds SIG(0) and DNSSEC key pairs.
The CLI contains functions for listing, adding, deleting, and
changing the state of keys.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("keystore called. This is likely a mistake, sub command needed")
		},
	}

	c.AddCommand(newKeystoreSig0Cmd(role), newKeystoreDnssecCmd(role))
	return c
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
			PrepArgs("zonename", "algorithm", "state")
			sig0KeyMgmt(role, "generate")
		},
	}
	generate.Flags().StringVarP(&NewState, "state", "", "", "Inital key state (created|published|active|retired)")
	generate.Flags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519",
		sig0AlgorithmsHelp("Algorithm to use for SIG(0) key generation"))
	generate.MarkFlagRequired("state")

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
		Short: "Delete SIG(0) key pair from TDNSD keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("keyid", "childzone")
			sig0KeyMgmt(role, "delete")
		},
	}
	delete.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")

	setstate := &cobra.Command{
		Use:   "setstate",
		Short: "Set the state of and existing SIG(0) key pair in the TDNSD keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("keyid", "zonename", "state")
			sig0KeyMgmt(role, "setstate")
		},
	}
	setstate.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	setstate.Flags().StringVarP(&NewState, "state", "", "", "New state of key (created|published|active|retired)")

	c.AddCommand(add, importCmd, generate, list, export, delete, setstate)
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
			PrepArgs("zonename", "algorithm", "keytype", "state")
			dnssecKeyMgmt(role, "generate")
		},
	}
	generate.Flags().StringVarP(&keytype, "keytype", "", "", "Key type to generate (KSK|ZSK|CSK)")
	generate.Flags().StringVarP(&NewState, "state", "", "", "Inital key state (created|published|active|retired)")
	generate.Flags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519",
		dnssecAlgorithmsHelp("Algorithm to use for DNSSEC key generation"))
	generate.MarkFlagRequired("keytype")
	generate.MarkFlagRequired("state")
	// generate.MarkFlagRequired("algorithm") // XXX: marking it as required defeats the default value

	list := &cobra.Command{
		Use:   "list",
		Short: "List all DNSSEC key pairs in the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			dnssecKeyMgmt(role, "list")
		},
	}

	delete := &cobra.Command{
		Use:   "delete",
		Short: "Delete DNSSEC key pair from TDNSD keystore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("keyid", "zonename")
			dnssecKeyMgmt(role, "delete")
		},
	}
	delete.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")

	setstate := &cobra.Command{
		Use:   "setstate",
		Short: "Set the state of and existing DNSSEC key pair in the TDNSD keystore",
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

	c.AddCommand(add, importCmd, generate, list, delete, setstate, genDS, rollover, clear, newKeystoreDnssecPolicyCmd(role), newKeystoreDnssecDsPushCmd(role))
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
		data.Algorithm = dns.StringToAlgorithm[tdns.Globals.Algorithm]
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
		fmt.Printf("Error from TDNSD: %s\n", tr.ErrorMsg)
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
func writeSig0ExportFiles(sk tdns.Sig0Key, outdir string) error {
	algNum, ok := dns.StringToAlgorithm[strings.ToUpper(sk.Algorithm)]
	if !ok {
		return fmt.Errorf("unknown algorithm %q in exported key", sk.Algorithm)
	}
	base := fmt.Sprintf("K%s+%03d+%05d", sk.Name, algNum, sk.Keyid)
	privPath := filepath.Join(outdir, base+".private")
	keyPath := filepath.Join(outdir, base+".key")
	for _, p := range []string{privPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("refusing to overwrite existing file %s (move or delete it first)", p)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %v", p, err)
		}
	}
	if err := os.WriteFile(privPath, []byte(sk.PrivateKey), 0600); err != nil {
		return fmt.Errorf("write %s: %v", privPath, err)
	}
	keyRR := sk.Keystr
	if !strings.HasSuffix(keyRR, "\n") {
		keyRR += "\n"
	}
	if err := os.WriteFile(keyPath, []byte(keyRR), 0644); err != nil {
		return fmt.Errorf("write %s: %v", keyPath, err)
	}
	fmt.Printf("Wrote %s\n", privPath)
	fmt.Printf("Wrote %s\n", keyPath)
	return nil
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
		data.Algorithm = dns.StringToAlgorithm[tdns.Globals.Algorithm]
		data.KeyType = keytype // "KSK|ZSK|CSK"
		data.State = NewState

	case "rollover":
		data.Zone = tdns.Globals.Zonename
		data.KeyType = keytype

	case "delete", "setstate":
		data.Keyid = uint16(keyid)
		data.Zone = tdns.Globals.Zonename
		data.Keyname = tdns.Globals.Zonename

	case "clear":
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
		fmt.Printf("Error from TDNSD: %s\n", tr.ErrorMsg)
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

	case "add", "import", "generate", "delete", "setstate", "rollover", "clear":
		if tr.Msg != "" {
			fmt.Printf("%s\n", tr.Msg)
		}
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
