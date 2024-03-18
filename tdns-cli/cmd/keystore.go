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

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"github.com/johanix/tdns/tdns"
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
		fmt.Println("list called")

		kr, err := SendKeystore(api, tdns.KeystorePost{
			Command: "list-child-sig0",
		})

		if err != nil {
		   fmt.Printf("Error: %v\n", err)
		   os.Exit(1)
		}

		var out = []string{"Type|Signer|KeyID|Trusted|Validated|Record"}
		if len(kr.ChildSig0keys) > 0 {
			fmt.Printf("Known SIG(0) keys:\n")
			for k, v := range kr.ChildSig0keys {
				tmp := strings.Split(k, "::")
				out = append(out, fmt.Sprintf("%s|%s|%v|%v|%.70s...\n",
					tmp[0], tmp[1], v.Trusted, v.Validated, v.Key.String()))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var keystoreChildSig0TrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Declare a child SIG(0) public key in the keystore as trusted",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("trust called")
	},
}
var keystoreChildSig0UntrustCmd = &cobra.Command{
	Use:   "untrust",
	Short: "Declare a child SIG(0) public key in the keystore as untrusted",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("untrust called")
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

