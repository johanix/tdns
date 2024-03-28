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

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	// "gopkg.in/yaml.v3"
)

// var filename string
var keyid int

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

type BindPrivateKey struct {
	Private_Key_Format string `yaml:"Private-key-format"`
	Algorithm          string `yaml:"Algorithm"`
	PrivateKey         string `yaml:"PrivateKey"`
}

var keystoreSig0AddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new SIG(0) key pair to the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("filename", "childzone")
		err := KeystoreImportKey(filename)
		if err != nil {
			fmt.Printf("Error from KeystoreImportKey(): %v\n", err)
		}
	},
}

var keystoreSig0ImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Add a new SIG(0) key pair to the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("filename", "childzone")
		err := KeystoreImportKey(filename)
		if err != nil {
			fmt.Printf("Error from KeystoreImportKey(): %v\n", err)
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

func init() {
	rootCmd.AddCommand(keystoreCmd)
	keystoreCmd.AddCommand(keystoreSig0Cmd)

	keystoreSig0Cmd.AddCommand(keystoreSig0AddCmd, keystoreSig0ImportCmd)
	keystoreSig0Cmd.AddCommand(keystoreSig0ListCmd, keystoreSig0DeleteCmd)

	keystoreSig0AddCmd.Flags().StringVarP(&filename, "file", "f", "", "Name of file containing either pub or priv data")
	keystoreSig0DeleteCmd.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")
}

func KeystoreImportKey(filename string) error {
	_, _, rr, _, privkey, alg, err := tdns.ReadKey(filename)
	if err != nil {
		log.Fatalf("Error reading key '%s': %v", filename, err)
	}

	if krr, ok := rr.(*dns.KEY); ok {
		if rr.Header().Name != tdns.Globals.Zonename {
			log.Fatalf("Error: name of zone (%s) and name of key (%s) do not match",
				rr.Header().Name, tdns.Globals.Zonename)
		}

		data := tdns.KeystorePost{
			Command:    "sig0-mgmt",
			SubCommand: "add",
			Zone:       tdns.Globals.Zonename,
			Keyname:    rr.Header().Name,
			Keyid:      krr.KeyTag(),
			Algorithm:  alg,
			PrivateKey: privkey,
			KeyRR:      rr.String(),
		}
		kr, err := SendKeystore(api, data)
		if err != nil {
			fmt.Printf("Error from SendKeystore: %v", err)
			os.Exit(1)
		}
		if kr.Error {
			fmt.Printf("%s\n", kr.ErrorMsg)
			os.Exit(1)
		}
		if len(kr.Msg) != 0 {
			fmt.Printf("%s\n", kr.Msg)
		}
	}
	return nil
}

func Sig0KeyMgmt(cmd string) error {
	data := tdns.KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: cmd,
	}

	if cmd == "delete" {
		data.Keyid = uint16(keyid)
		data.Zone = tdns.Globals.Zonename
		data.Keyname = tdns.Globals.Zonename
	}

	tr, err := SendKeystore(api, data)
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
		var out = []string{"Signer|KeyID|Algorithm|PrivKey|KEY Record"}
		if len(tr.Sig0keys) > 0 {
			fmt.Printf("Known SIG(0) key pairs:\n")
			for k, v := range tr.Sig0keys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("%s|%s|%v|%v|%.50s...\n",
					tmp[0], tmp[1], v.Algorithm, v.PrivateKey, v.Keystr))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))

	case "delete":
		fmt.Printf("%s\n", tr.Msg)

	default:
		fmt.Printf("Unknown keystore command: \"%s\"\n", cmd)
	}

	return nil
}

func SendKeystore(api *tdns.Api, data tdns.KeystorePost) (tdns.KeystoreResponse, error) {

	var kr tdns.KeystoreResponse

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/keystore", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return kr, fmt.Errorf("Error from api post: %v", err)
	}
	if verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &kr)
	if err != nil {
		return kr, fmt.Errorf("Error from unmarshal: %v\n", err)
	}

	if kr.Error {
		return kr, fmt.Errorf("%s", kr.ErrorMsg)
	}

	return kr, nil
}
