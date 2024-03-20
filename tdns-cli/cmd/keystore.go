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
)

var childSig0Name string
var childSig0Keyid int

var keystoreCmd = &cobra.Command{
	Use:   "keystore",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("keystore called")
	},
}

var keystoreAddSig0Cmd = &cobra.Command{
	Use:   "addsig0",
	Short: "Add a new SIG(0) key to the keystore (both private and public)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("keystore called")
	},
}

var keystoreChildSig0Cmd = &cobra.Command{
	Use:   "childsig0",
	Short: "Prefix command, only usable via sub-commands",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("childsig0 called")
	},
}

var keystoreChildSig0ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all child SIG(0) public key in the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		err := Sig0TrustMgmt("list")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

var keystoreChildSig0TrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Declare a child SIG(0) public key in the keystore as trusted",
	Run: func(cmd *cobra.Command, args []string) {
		err := Sig0TrustMgmt("trust")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}
var keystoreChildSig0UntrustCmd = &cobra.Command{
	Use:   "untrust",
	Short: "Declare a child SIG(0) public key in the keystore as untrusted",
	Run: func(cmd *cobra.Command, args []string) {
		err := Sig0TrustMgmt("untrust")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(keystoreCmd)
	keystoreCmd.AddCommand(keystoreChildSig0Cmd, keystoreAddSig0Cmd)

	keystoreChildSig0Cmd.AddCommand(keystoreChildSig0ListCmd)
	keystoreChildSig0Cmd.AddCommand(keystoreChildSig0TrustCmd)
	keystoreChildSig0Cmd.AddCommand(keystoreChildSig0UntrustCmd)

	keystoreChildSig0Cmd.PersistentFlags().IntVarP(&childSig0Keyid, "keyid", "", 0, "Keyid of child SIG(0) key to change trust for")
	keystoreChildSig0Cmd.PersistentFlags().StringVarP(&childSig0Name, "child", "c", "", "Name of child SIG(0) key to change trust for")
}

func Sig0TrustMgmt(trustval string) error {
	kr, err := SendKeystore(api, tdns.KeystorePost{
		Command:    "child-sig0-mgmt",
		SubCommand: "list",
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if trustval == "list" {
		var out = []string{"Signer|KeyID|Validated|Trusted|Record"}
		if len(kr.ChildSig0keys) > 0 {
			fmt.Printf("Known SIG(0) keys:\n")
			for k, v := range kr.ChildSig0keys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("%s|%s|%v|%v|%.70s...\n",
					tmp[0], tmp[1], v.Validated, v.Trusted, v.Keystr))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))

		return nil
	}

	if childSig0Name == "" {
		fmt.Printf("Error: name of SIG(0) key not specified (with --child)\n")
		os.Exit(1)
	}
	childSig0Name = dns.Fqdn(childSig0Name)
	if childSig0Keyid == 0 {
		fmt.Printf("Error: keyid of SIG(0) key not specified (with --keyid)\n")
		os.Exit(1)
	}

	mapkey := fmt.Sprintf("%s::%d", childSig0Name, childSig0Keyid)
	if _, ok := kr.ChildSig0keys[mapkey]; !ok {
		fmt.Printf("Error: no key with name %s and keyid %d is known.\n",
			childSig0Name, childSig0Keyid)
		os.Exit(1)
	}

	kr, err = SendKeystore(api, tdns.KeystorePost{
		Command:    "child-sig0-mgmt",
		SubCommand: trustval,
		Keyname:    childSig0Name,
		Keyid:      childSig0Keyid,
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if kr.Error {
		fmt.Printf("Error: %s\n", kr.ErrorMsg)
	} else {
		fmt.Printf("%s\n", kr.Msg)
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
		return kr, fmt.Errorf("Error from tdnsd: %s\n", kr.ErrorMsg)
	}

	return kr, nil
}
