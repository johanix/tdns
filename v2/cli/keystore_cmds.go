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
		err := Sig0KeyMgmt("add")
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
		err := Sig0KeyMgmt("import")
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
		err := Sig0KeyMgmt("generate")
		if err != nil {
			fmt.Printf("Error from Sig0KeyMgmt(): %v\n", err)
		}
	},
}

var keystoreSig0ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all SIG(0) key pairs in the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		err := Sig0KeyMgmt("list")
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

		err := Sig0KeyMgmt("delete")
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

		err := Sig0KeyMgmt("setstate")
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
		err := DnssecKeyMgmt("add")
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
		err := DnssecKeyMgmt("import")
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
		err := DnssecKeyMgmt("generate")
		if err != nil {
			fmt.Printf("Error from DnssecKeyMgmt(): %v\n", err)
		}
	},
}

var keystoreDnssecListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all DNSSEC key pairs in the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		err := DnssecKeyMgmt("list")
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

		err := DnssecKeyMgmt("delete")
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

		err := DnssecKeyMgmt("setstate")
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
		err := DnssecGenDS()
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
	keystoreDnssecCmd.AddCommand(keystoreDnssecListCmd, keystoreDnssecDeleteCmd, keystoreDnssecSetStateCmd, keystoreDnssecGenDSCmd)

	keystoreSig0AddCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	keystoreSig0ImportCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
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
	keystoreDnssecImportCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
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

	keystoreDnssecGenDSCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of specific KSK to generate DS for (optional, if not specified, generates for all KSKs)")
	keystoreDnssecGenDSCmd.MarkFlagRequired("zone")
}

func Sig0KeyMgmt(cmd string) error {
	data := tdns.KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: cmd,
	}

	prefixcmd, _ := getCommandContext("keystore")
	api, _ := getApiClient(prefixcmd, true)
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
			out = append(out, "Signer|State|KeyID|Algorithm|PrivKey|KEY Record")
		}
		if len(tr.Sig0keys) > 0 {
			// fmt.Printf("Known SIG(0) key pairs:\n")
			for k, v := range tr.Sig0keys {
				tmp := strings.Split(k, "::")
				tmplist = append(tmplist, fmt.Sprintf("%s|%s|%s|%v|%v|%.50s...\n",
					tmp[0], v.State, tmp[1], v.Algorithm, v.PrivateKey, v.Keystr))
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

func DnssecKeyMgmt(cmd string) error {
	data := tdns.KeystorePost{
		Command:    "dnssec-mgmt",
		SubCommand: cmd,
	}

	prefixcmd, _ := getCommandContext("keystore")
	api, _ := getApiClient(prefixcmd, true)

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
		var out []string
		if len(tr.Dnskeys) > 0 {
			fmt.Printf("Known DNSSEC key pairs:\n")
			for k, v := range tr.Dnskeys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("%s|%s|%s|%d|%s|%s|%.50s...\n",
					tmp[0], v.State, tmp[1], v.Flags, v.Algorithm, v.PrivateKey, v.Keystr))
			}
			sort.Strings(out)
			if tdns.Globals.ShowHeaders {
				out = append([]string{"Signer|State|KeyID|Flags|Algorithm|PrivKey|DNSKEY Record"}, out...)
			}

			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		} else {
			fmt.Printf("No DNSSEC key pairs found\n")
		}

	case "add", "import", "generate", "delete", "setstate":
		if tr.Msg != "" {
			fmt.Printf("%s\n", tr.Msg)
		}
	}

	return nil
}

func DnssecGenDS() error {
	prefixcmd, _ := getCommandContext("keystore")
	api, _ := getApiClient(prefixcmd, true)

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
	ksks := []tdns.DnssecKey{}
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
			continue
		}

		// If --keyid was specified, filter by it
		if keyid != 0 && uint16(parsedKeyid) != uint16(keyid) {
			continue
		}

		// Filter for KSKs (keys with KSK flag bit 0 set, flags & 0x0001 != 0)
		// Note: KSK flag is bit 0 (0x0001), SEP bit is bit 8 (0x0100)
		// For DS generation, we want KSKs (bit 0 set)
		if v.Flags&0x0001 == 0 {
			continue
		}

		ksks = append(ksks, v)
	}

	if len(ksks) == 0 {
		if keyid != 0 {
			fmt.Printf("No KSK with keyid %d found for zone %s\n", keyid, zone)
		} else {
			fmt.Printf("No KSK (Key Signing Key) found for zone %s\n", zone)
			fmt.Println("KSKs are identified by having the SEP (Secure Entry Point) bit set (flags & 0x100 != 0)")
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
