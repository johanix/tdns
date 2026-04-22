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

var childSig0Src string

// NewTruststoreCmd returns a fresh "truststore" command tree bound to
// the given role. The nested sig0 subtree and its children/flags are
// built inline so every attachment point gets unique *cobra.Command
// instances.
func NewTruststoreCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "truststore",
		Short: "Prefix command to access different features of the truststore",
		Long: `The truststore is where SIG(0) public keys for child zones are kept.
The CLI contains functions for listing trusted SIG(0) keys, adding and
deleting child keys as well as changing the trust state of individual keys.`,
	}
	c.AddCommand(newTruststoreSig0Cmd(role))
	return c
}

func newTruststoreSig0Cmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "sig0",
		Short: "Prefix command, only usable via sub-commands",
	}
	c.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "child", "c", "", "Name of child SIG(0) key")

	add := &cobra.Command{
		Use:   "add",
		Short: "Add a new SIG(0) public key to the truststore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("src", "child")
			sig0TrustMgmt(role, "add")
		},
	}
	add.PersistentFlags().StringVarP(&childSig0Src, "src", "s", "", "Source for SIG(0) public key, a file name or 'dns'")

	del := &cobra.Command{
		Use:   "delete",
		Short: "Delete a SIG(0) public key from the truststore",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("child")
			sig0TrustMgmt(role, "delete")
		},
	}
	del.Flags().IntVarP(&keyid, "keyid", "", 0, "Key ID of key to delete")

	list := &cobra.Command{
		Use:   "list",
		Short: "List all child SIG(0) public key in the keystore",
		Run: func(cmd *cobra.Command, args []string) {
			sig0TrustMgmt(role, "list")
		},
	}

	trust := &cobra.Command{
		Use:   "trust",
		Short: "Declare a child SIG(0) public key in the keystore as trusted",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("keyid", "child")
			sig0TrustMgmt(role, "trust")
		},
	}
	trust.PersistentFlags().IntVarP(&keyid, "keyid", "", 0, "Keyid of child SIG(0) key to change trust for")

	untrust := &cobra.Command{
		Use:   "untrust",
		Short: "Declare a child SIG(0) public key in the keystore as untrusted",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("keyid", "child")
			sig0TrustMgmt(role, "untrust")
		},
	}
	untrust.PersistentFlags().IntVarP(&keyid, "keyid", "", 0, "Keyid of child SIG(0) key to change trust for")

	c.AddCommand(add, del, list, trust, untrust)
	return c
}

func sig0TrustMgmt(role, subcommand string) {
	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	tr, err := SendTruststore(api, tdns.TruststorePost{
		Command:    "child-sig0-mgmt",
		SubCommand: "list",
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	tsp := tdns.TruststorePost{
		Command:    "child-sig0-mgmt",
		SubCommand: subcommand,
		Keyname:    tdns.Globals.Zonename,
		Keyid:      keyid,
	}
	if subcommand == "list" {
		var out, tmplist []string
		if tdns.Globals.ShowHeaders {
			out = append(out, "Signer|KeyID|Validated|Trusted|Source|Record")
		}
		if len(tr.ChildSig0keys) > 0 {
			// fmt.Printf("Known child SIG(0) keys:\n")
			for k, v := range tr.ChildSig0keys {
				tmp := strings.Split(k, "::")
				keyid, _ := strconv.Atoi(tmp[1])
				tmplist = append(tmplist, fmt.Sprintf("%s|%d|%v|%v|%s|%.55s...\n",
					tmp[0], keyid, v.Validated, v.Trusted, v.Source, v.Keystr))
			}
			sort.Strings(tmplist)
			out = append(out, tmplist...)
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		}

		return
	}

	if subcommand == "add" {
		mapkey := fmt.Sprintf("%s::%d", tdns.Globals.Zonename, keyid)
		if _, ok := tr.ChildSig0keys[mapkey]; ok {
			fmt.Printf("Error: key with name %s and keyid %d is already known.\n", tdns.Globals.Zonename, keyid)
			os.Exit(1)
		}
		if strings.ToLower(childSig0Src) != "dns" {
			keyrr, ktype, _, err := tdns.ReadPubKey(childSig0Src)
			if err != nil {
				fmt.Printf("Error reading SIG(0) public keyfile %s: %v\n", childSig0Src, err)
				os.Exit(1)
			}
			if ktype != dns.TypeKEY {
				fmt.Printf("Error: keyfile %s is not a KEY RR\n", childSig0Src)
				os.Exit(1)
			}
			if keyrr.Header().Name != tdns.Globals.Zonename {
				fmt.Printf("Error: key %s does not match zone name %s\n", keyrr.Header().Name, tdns.Globals.Zonename)
				os.Exit(1)
			}
			tsp.Keyname = keyrr.Header().Name
			tsp.Keyid = int(keyrr.(*dns.KEY).KeyTag())
			tsp.KeyRR = keyrr.String()
			tsp.Src = "file"
		} else {
			tsp.Src = "dns"
		}
	}

	if subcommand == "delete" {
		tsp.Keyid = keyid
		tsp.Keyname = tdns.Globals.Zonename
	}

	if subcommand == "trust" || subcommand == "untrust" {
		mapkey := fmt.Sprintf("%s::%d", tdns.Globals.Zonename, keyid)
		if _, ok := tr.ChildSig0keys[mapkey]; !ok {
			fmt.Printf("Error: no key with name %s and keyid %d is known.\n", tdns.Globals.Zonename, keyid)
			os.Exit(1)
		}
	}

	tr, err = SendTruststore(api, tsp)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if tr.Error {
		fmt.Printf("Error: %s\n", tr.ErrorMsg)
	} else {
		fmt.Printf("%s\n", tr.Msg)
	}
}

func SendTruststore(api *tdns.ApiClient, data tdns.TruststorePost) (tdns.TruststoreResponse, error) {

	var tr tdns.TruststoreResponse

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/truststore", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return tr, fmt.Errorf("error from api post: %v", err)
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &tr)
	if err != nil {
		return tr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if tr.Error {
		return tr, fmt.Errorf("error from %s: %s", tr.AppName, tr.ErrorMsg)
	}

	return tr, nil
}
