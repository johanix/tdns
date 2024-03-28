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

var truststoreCmd = &cobra.Command{
	Use:   "truststore",
	Short: "Prefix command to access different features of tdnsd truststore",
	Long:  `The TDNSD truststore is where SIG(0) public keys for child zones are kept.
The CLI contains functions for listing trusted SIG(0) keys, adding and
deleting child keys and alsowell as changing the trust state of individual keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("truststore called. This is likely a mistake, sub command needed")
	},
}

var truststoreSig0Cmd = &cobra.Command{
	Use:   "sig0",
	Short: "Prefix command, only usable via sub-commands",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("childsig0 called")
	},
}

var truststoreSig0AddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new SIG(0) public key to the truststore",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("truststore sig0 add called (but NYI)")
	},
}

var truststoreSig0ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all child SIG(0) public key in the keystore",
	Run: func(cmd *cobra.Command, args []string) {
		err := Sig0TrustMgmt("list")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

var truststoreSig0TrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Declare a child SIG(0) public key in the keystore as trusted",
	Run: func(cmd *cobra.Command, args []string) {
		err := Sig0TrustMgmt("trust")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}
var truststoreSig0UntrustCmd = &cobra.Command{
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
	rootCmd.AddCommand(truststoreCmd)
	truststoreCmd.AddCommand(truststoreSig0Cmd)

	truststoreSig0Cmd.AddCommand(truststoreSig0AddCmd)
	truststoreSig0Cmd.AddCommand(truststoreSig0ListCmd)
	truststoreSig0Cmd.AddCommand(truststoreSig0TrustCmd)
	truststoreSig0Cmd.AddCommand(truststoreSig0UntrustCmd)

	truststoreSig0Cmd.PersistentFlags().IntVarP(&childSig0Keyid, "keyid", "", 0, "Keyid of child SIG(0) key to change trust for")
	truststoreSig0Cmd.PersistentFlags().StringVarP(&childSig0Name, "child", "c", "", "Name of child SIG(0) key to change trust for")
}

func Sig0TrustMgmt(trustval string) error {
	tr, err := SendTruststore(api, tdns.TruststorePost{
		Command:    "child-sig0-mgmt",
		SubCommand: "list",
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if trustval == "list" {
		var out = []string{"Signer|KeyID|Validated|Trusted|Record"}
		if len(tr.ChildSig0keys) > 0 {
			fmt.Printf("Known child SIG(0) keys:\n")
			for k, v := range tr.ChildSig0keys {
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
	if _, ok := tr.ChildSig0keys[mapkey]; !ok {
		fmt.Printf("Error: no key with name %s and keyid %d is known.\n",
			childSig0Name, childSig0Keyid)
		os.Exit(1)
	}

	tr, err = SendTruststore(api, tdns.TruststorePost{
		Command:    "child-sig0-mgmt",
		SubCommand: trustval,
		Keyname:    childSig0Name,
		Keyid:      childSig0Keyid,
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if tr.Error {
		fmt.Printf("Error: %s\n", tr.ErrorMsg)
	} else {
		fmt.Printf("%s\n", tr.Msg)
	}
	return nil
}

func SendTruststore(api *tdns.Api, data tdns.TruststorePost) (tdns.TruststoreResponse, error) {

	var tr tdns.TruststoreResponse

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/truststore", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return tr, fmt.Errorf("Error from api post: %v", err)
	}
	if verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &tr)
	if err != nil {
		return tr, fmt.Errorf("Error from unmarshal: %v\n", err)
	}

	if tr.Error {
		return tr, fmt.Errorf("Error from tdnsd: %s\n", tr.ErrorMsg)
	}

	return tr, nil
}
