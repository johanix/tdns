/*
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
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
var NewState, filename, keytype string

var KeystoreCmd = &cobra.Command{
	Use:   "keystore",
	Short: "Prefix command to access different features of tdns-auth truststore",
	Long: `The TDNS-AUTH keystore is where SIG(0) key pairs for zones are kept.
The CLI contains functions for listing SIG(0) key pairs, adding and
deleting keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("keystore called. This is likely a mistake, sub command needed")
	},
}

var keystoreSig0Cmd = &cobra.Command{
	Use:   "sig0",
	Short: "Prefix command, only usable via sub-commands",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("keystore sig0 called (but NYI)")
	},
}

var keystoreSig0AddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new SIG(0) key pair to the keystore",
	Long: `Add a new SIG(0) key pair to the keystore. Required arguments are the name of the file
containing either the private or the public SIG(0) key and the name of the zone.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("filename", "childzone")
		parent, _ := GetCommandContext("keystore")
		err := Sig0KeyMgmt(parent, "add")
		if err != nil {
			fmt.Printf("Error from Sig0KeyMgmt(): %v\n", err)
		}
	},
}

var keystoreSig0ImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Add a new SIG(0) key pair to the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("filename", "childzone")
		parent, _ := GetCommandContext("keystore")
		err := Sig0KeyMgmt(parent, "import")
		if err != nil {
			fmt.Printf("Error from Sig0KeyMgmt(): %v\n", err)
		}
	},
}

var keystoreSig0GenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new SIG(0) key pair and add it to the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "algorithm", "state")
		parent, _ := GetCommandContext("keystore")
		err := Sig0KeyMgmt(parent, "generate")
		if err != nil {
			fmt.Printf("Error from Sig0KeyMgmt(): %v\n", err)
		}
	},
}

var keystoreSig0ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all SIG(0) key pairs in the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := GetCommandContext("keystore")
		err := Sig0KeyMgmt(parent, "list")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

var keystoreSig0DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete SIG(0) key pair from TDNSD keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("keyid", "childzone")

		parent, _ := GetCommandContext("keystore")
		err := Sig0KeyMgmt(parent, "delete")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

var keystoreSig0SetStateCmd = &cobra.Command{
	Use:   "setstate",
	Short: "Set the state of and existing SIG(0) key pair in the TDNSD keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("keyid", "zonename", "state")

		parent, _ := GetCommandContext("keystore")
		err := Sig0KeyMgmt(parent, "setstate")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

var keystoreDnssecCmd = &cobra.Command{
	Use:   "dnssec",
	Short: "Prefix command, only usable via sub-commands",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("keystore dnssec called (this is an empty prefix command)")
	},
}

var keystoreDnssecAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new DNSSEC key pair to the keystore",
	Long: `Add a new SIG(0) key pair to the keystore. Required arguments are the name of the file
containing either the private or the public SIG(0) key and the name of the zone.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("filename", "zonename")
		parent, _ := GetCommandContext("keystore")
		err := DnssecKeyMgmt(parent, "add")
		if err != nil {
			fmt.Printf("Error from DnssecKeyMgmt(): %v\n", err)
		}
	},
}

var keystoreDnssecImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Add a new DNSSEC key pair to the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("filename", "zonename")
		parent, _ := GetCommandContext("keystore")
		err := DnssecKeyMgmt(parent, "import")
		if err != nil {
			fmt.Printf("Error from DnssecKeyMgmt(): %v\n", err)
		}
	},
}

var keystoreDnssecGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new DNSSEC key pair and add it to the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "algorithm", "keytype", "state")
		parent, _ := GetCommandContext("keystore")
		err := DnssecKeyMgmt(parent, "generate")
		if err != nil {
			fmt.Printf("Error from DnssecKeyMgmt(): %v\n", err)
		}
	},
}

var keystoreDnssecListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all DNSSEC key pairs in the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := GetCommandContext("keystore")
		err := DnssecKeyMgmt(parent, "list")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

var keystoreDnssecDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete DNSSEC key pair from TDNSD keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("keyid", "zonename")

		parent, _ := GetCommandContext("keystore")
		err := DnssecKeyMgmt(parent, "delete")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

var keystoreDnssecSetStateCmd = &cobra.Command{
	Use:   "setstate",
	Short: "Set the state of and existing DNSSEC key pair in the TDNSD keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("keyid", "zonename", "state")

		parent, _ := GetCommandContext("keystore")
		err := DnssecKeyMgmt(parent, "setstate")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

var keystoreDnssecGenDSCmd = &cobra.Command{
	Use:   "gen-ds",
	Short: "Generate DS records for a zone's KSK(s) from the keystore",
	Long:  `Generate DS (Delegation Signer) records for a zone's KSK (Key Signing Key) DNSKEY records stored in the keystore. The command queries the keystore for DNSKEY records for the specified zone, filters for KSKs (keys with the SEP bit set), and generates DS records using SHA-256 and SHA-384 digest algorithms. If --keyid is not specified, DS records are generated for all KSKs in the zone.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		if keyid < 0 || keyid > 65535 {
			fmt.Printf("Error: keyid must be between 0 and 65535, got %d\n", keyid)
			os.Exit(1)
		}
		parent, _ := GetCommandContext("keystore")
		err := DnssecGenDS(parent)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var keystoreDnssecRolloverCmd = &cobra.Command{
	Use:   "rollover",
	Short: "Perform a manual DNSSEC key rollover (standby→active, active→retired)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		parent, _ := GetCommandContext("keystore")
		err := DnssecKeyMgmt(parent, "rollover")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var keystoreDnssecClearCmd = &cobra.Command{
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

		parent, _ := GetCommandContext("keystore")
		err := DnssecKeyMgmt(parent, "clear")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	// rootCmd.AddCommand(KeystoreCmd)
	KeystoreCmd.AddCommand(keystoreSig0Cmd, keystoreDnssecCmd)

	keystoreSig0Cmd.AddCommand(keystoreSig0AddCmd, keystoreSig0ImportCmd, keystoreSig0GenerateCmd)
	keystoreSig0Cmd.AddCommand(keystoreSig0ListCmd, keystoreSig0DeleteCmd, keystoreSig0SetStateCmd)

	keystoreDnssecCmd.AddCommand(keystoreDnssecAddCmd, keystoreDnssecImportCmd, keystoreDnssecGenerateCmd)
	keystoreDnssecCmd.AddCommand(keystoreDnssecListCmd, keystoreDnssecDeleteCmd, keystoreDnssecSetStateCmd, keystoreDnssecGenDSCmd, keystoreDnssecRolloverCmd, keystoreDnssecClearCmd)

	keystoreSig0AddCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	keystoreSig0AddCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to add SIG(0) key for")
	keystoreSig0ImportCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	keystoreSig0ImportCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to import SIG(0) key for")
	keystoreSig0ImportCmd.MarkFlagRequired("file")
	keystoreSig0AddCmd.MarkFlagRequired("file")
	keystoreSig0AddCmd.MarkFlagRequired("zone")
	keystoreSig0ImportCmd.MarkFlagRequired("zone")
	keystoreSig0DeleteCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	keystoreSig0SetStateCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	keystoreSig0SetStateCmd.Flags().StringVarP(&NewState, "state", "", "", "New state of key (created|published|active|retired)")
	keystoreSig0GenerateCmd.Flags().StringVarP(&NewState, "state", "", "", "Inital key state (created|published|active|retired)")
	keystoreSig0GenerateCmd.Flags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519", "Algorithm to use for key generation (default: ED25519)")
	keystoreSig0GenerateCmd.MarkFlagRequired("state")

	keystoreDnssecAddCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	keystoreDnssecAddCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to add DNSSEC key for")
	keystoreDnssecImportCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	keystoreDnssecImportCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to import DNSSEC key for")
	keystoreDnssecImportCmd.MarkFlagRequired("file")
	keystoreDnssecAddCmd.MarkFlagRequired("file")
	keystoreDnssecAddCmd.MarkFlagRequired("zone")
	keystoreDnssecImportCmd.MarkFlagRequired("zone")
	keystoreDnssecDeleteCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	keystoreDnssecSetStateCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	keystoreDnssecSetStateCmd.Flags().StringVarP(&NewState, "state", "", "", "New statei of key")
	keystoreDnssecGenerateCmd.Flags().StringVarP(&keytype, "keytype", "", "", "Key type to generate (KSK|ZSK|CSK)")
	keystoreDnssecGenerateCmd.Flags().StringVarP(&NewState, "state", "", "", "Inital key state (created|published|active|retired)")
	keystoreDnssecGenerateCmd.Flags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519", "Algorithm to use for key generation (default: ED25519)")
	keystoreDnssecGenerateCmd.MarkFlagRequired("keytype")
	keystoreDnssecGenerateCmd.MarkFlagRequired("state")
	// keystoreDnssecGenerateCmd.MarkFlagRequired("algorithm") // XXX: marking it as required defeats the default value

	keystoreDnssecGenDSCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to generate DS records for")
	keystoreDnssecGenDSCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of specific KSK to generate DS for (optional, if not specified, generates for all KSKs)")
	keystoreDnssecGenDSCmd.MarkFlagRequired("zone")

	keystoreDnssecRolloverCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to perform rollover for")
	keystoreDnssecRolloverCmd.Flags().StringVarP(&keytype, "keytype", "", "ZSK", "Key type to roll over (ZSK|KSK)")
	keystoreDnssecRolloverCmd.MarkFlagRequired("zone")

	keystoreDnssecClearCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to clear all DNSSEC keys for")
	keystoreDnssecClearCmd.Flags().Bool("force", false, "Skip confirmation prompt")
	keystoreDnssecClearCmd.MarkFlagRequired("zone")
}

func Sig0KeyMgmt(parent, cmd string) error {
	data := tdns.KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: cmd,
	}

	api, _ := GetApiClient(parent, true)
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

			log.Printf("[tdns-cli]pkc.K: %s, pkc.PrivateKey: %s", pkc.K, pkc.PrivateKey)

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

	case "delete", "setstate":
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
		log.Printf("Sig0KeyMgmt: calling SendKeystoreCmd with data=%v", data)
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
	}

	return nil
}

func DnssecKeyMgmt(parent, cmd string) error {
	data := tdns.KeystorePost{
		Command:    "dnssec-mgmt",
		SubCommand: cmd,
	}

	api, _ := GetApiClient(parent, true)

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
			zone   string
			state  string
			keyid  string
			flags  uint16
			alg    string
			keystr string
		}
		var entries []dnssecListEntry
		if len(tr.Dnskeys) > 0 {
			fmt.Printf("Known DNSSEC key pairs:\n")
			for k, v := range tr.Dnskeys {
				tmp := strings.Split(k, "::")
				entries = append(entries, dnssecListEntry{
					zone: tmp[0], state: v.State, keyid: tmp[1],
					flags: v.Flags, alg: v.Algorithm, keystr: v.Keystr,
				})
			}
			// Sort: by zone, then foreign keys last, then by state, then by keyid
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].zone != entries[j].zone {
					return entries[i].zone < entries[j].zone
				}
				iForeign := entries[i].state == "foreign"
				jForeign := entries[j].state == "foreign"
				if iForeign != jForeign {
					return jForeign // foreign sorts last
				}
				if entries[i].state != entries[j].state {
					return entries[i].state < entries[j].state
				}
				return entries[i].keyid < entries[j].keyid
			})
			var out []string
			for _, e := range entries {
				displayState := e.state
				if displayState == "foreign" {
					displayState = "[foreign]"
				}
				out = append(out, fmt.Sprintf("%s|%s|%s|%d|%s|%.50s...\n",
					e.zone, displayState, e.keyid, e.flags, e.alg, e.keystr))
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

	return nil
}

func DnssecGenDS(parent string) error {
	api, err := GetApiClient(parent, true)
	if err != nil {
		return fmt.Errorf("failed to get API client: %w", err)
	}

	// First, list all DNSSEC keys to find the ones for our zone
	data := tdns.KeystorePost{
		Command:    "dnssec-mgmt",
		SubCommand: "list",
	}

	tr, err := SendKeystoreCmd(api, data)
	if err != nil {
		return fmt.Errorf("error listing DNSSEC keys: %v", err)
	}

	if tr.Error {
		return fmt.Errorf("error from keystore: %s", tr.ErrorMsg)
	}

	if len(tr.Dnskeys) == 0 {
		fmt.Printf("No DNSSEC keys found in keystore\n")
		return nil
	}

	zone := dns.Fqdn(tdns.Globals.Zonename)
	trimmed := strings.TrimSuffix(zone, ".")
	if trimmed == "" {
		return fmt.Errorf("cannot generate DS for root zone")
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
		return nil
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

	return nil
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
