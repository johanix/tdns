/*
 */
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gookit/goutil/dump"
	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	// "gopkg.in/yaml.v3"
)

// var filename string
var keyid int
var NewState, filename string

var keystoreCmd = &cobra.Command{
	Use:   "keystore",
	Short: "A brief description of your command",
	Long: `The TDNSD keystore is where SIG(0) key pairs for zones are kept.
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
		fmt.Println("keystore dnssec called (but NYI)")
	},
}

var keystoreDnssecAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new DNSSEC key pair to the keystore",
	Long: `Add a new SIG(0) key pair to the keystore. Required arguments are the name of the file
containing either the private or the public SIG(0) key and the name of the zone.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("filename", "childzone")
		err := DnssecKeyMgmt("add")
		if err != nil {
			fmt.Printf("Error from KeystoreImportKey(): %v\n", err)
		}
	},
}

var keystoreDnssecImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Add a new DNSSEC key pair to the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("filename", "childzone")
		err := DnssecKeyMgmt("import")
		if err != nil {
			fmt.Printf("Error from KeystoreImportKey(): %v\n", err)
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
		PrepArgs("keyid", "childzone")

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

func init() {
	rootCmd.AddCommand(keystoreCmd)
	keystoreCmd.AddCommand(keystoreSig0Cmd, keystoreDnssecCmd)

	keystoreSig0Cmd.AddCommand(keystoreSig0AddCmd, keystoreSig0ImportCmd)
	keystoreSig0Cmd.AddCommand(keystoreSig0ListCmd, keystoreSig0DeleteCmd, keystoreSig0SetStateCmd)

	keystoreDnssecCmd.AddCommand(keystoreDnssecAddCmd, keystoreDnssecImportCmd)
	keystoreDnssecCmd.AddCommand(keystoreDnssecListCmd, keystoreDnssecDeleteCmd, keystoreDnssecSetStateCmd)

	keystoreSig0AddCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	keystoreSig0ImportCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	keystoreSig0ImportCmd.MarkFlagRequired("file")
	keystoreSig0AddCmd.MarkFlagRequired("file")
	keystoreSig0AddCmd.MarkFlagRequired("zone")
	keystoreSig0ImportCmd.MarkFlagRequired("zone")
	keystoreSig0DeleteCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	keystoreSig0SetStateCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	keystoreSig0SetStateCmd.Flags().StringVarP(&NewState, "state", "", "", "New statei of key")

	keystoreDnssecAddCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	keystoreDnssecImportCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv SIG(0) data")
	keystoreDnssecImportCmd.MarkFlagRequired("file")
	keystoreDnssecAddCmd.MarkFlagRequired("file")
	keystoreDnssecAddCmd.MarkFlagRequired("zone")
	keystoreDnssecImportCmd.MarkFlagRequired("zone")
	keystoreDnssecDeleteCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	keystoreDnssecSetStateCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
	keystoreDnssecSetStateCmd.Flags().StringVarP(&NewState, "state", "", "", "New statei of key")
}

func Sig0KeyMgmt(cmd string) error {
	data := tdns.KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: cmd,
	}

	switch cmd {
	case "list":
		// no action

	case "add", "import":
		pkc, err := tdns.ReadPrivateKey(filename)
		if err != nil {
			log.Fatalf("Error reading key '%s': %v", filename, err)
		}

		dump.P(pkc)

		fmt.Printf("KeyRR: %s\n", pkc.KeyRR.String())

		if pkc != nil && pkc.KeyType == dns.TypeKEY {
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
		var out = []string{"Signer|State|KeyID|Algorithm|PrivKey|KEY Record"}
		if len(tr.Sig0keys) > 0 {
			fmt.Printf("Known SIG(0) key pairs:\n")
			for k, v := range tr.Sig0keys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("%s|%s|%s|%v|%v|%.50s...\n",
					tmp[0], v.State, tmp[1], v.Algorithm, v.PrivateKey, v.Keystr))
			}
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		} else {
			fmt.Printf("No SIG(0) key pairs found\n")
		}

	case "add", "import", "delete", "setstate":
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

	switch cmd {
	case "list":
		// no action

	case "add", "import":
		fmt.Printf("Adding DNSSEC key pair to keystore\n")
		pkc, err := tdns.ReadPrivateKey(filename)
		if err != nil {
			log.Fatalf("Error reading key '%s': %v", filename, err)
		}

		fmt.Printf("DNSKEY RR: %s\n", pkc.DnskeyRR.String())

		if pkc != nil && pkc.KeyType == dns.TypeDNSKEY {
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
		var out = []string{"Signer|State|KeyID|Flags|Algorithm|PrivKey|DNSKEY Record"}
		if len(tr.Dnskeys) > 0 {
			fmt.Printf("Known DNSSEC key pairs:\n")
			for k, v := range tr.Dnskeys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("%s|%s|%s|%d|%s|%s|%.50s...\n",
					tmp[0], v.State, tmp[1], v.Flags, v.Algorithm, v.PrivateKey, v.Keystr))
			}
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		} else {
			fmt.Printf("No DNSSEC key pairs found\n")
		}

	case "add", "import", "delete", "setstate":
		if tr.Msg != "" {
			fmt.Printf("%s\n", tr.Msg)
		}
	}

	return nil
}

func SendKeystoreCmd(api *tdns.Api, data tdns.KeystorePost) (tdns.KeystoreResponse, error) {

	// fmt.Printf("Sending keystore command: %v\n", data)

	var kr tdns.KeystoreResponse

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/keystore", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return kr, fmt.Errorf("error from api post: %v", err)
	}
	if verbose {
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
