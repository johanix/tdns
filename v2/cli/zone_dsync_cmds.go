/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var rollaction string

// newZoneDsyncCmd returns a fresh "dsync" subtree bound to the given
// role. Each Run closure resolves its ApiClient via GetApiClient(role).
func newZoneDsyncCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "dsync",
		Short: "Prefix command, not useable by itself",
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Send dsync status command",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")

			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
				Command: "status",
				Zone:    dns.Fqdn(tdns.Globals.Zonename),
			})

			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}

			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
			out := []string{}
			for key, s := range resp.Functions {
				out = append(out, fmt.Sprintf("%s|%s", key, s))
			}

			sort.Strings(out)
			if tdns.Globals.ShowHeaders {
				out = append([]string{"Function|Status"}, out...)
			}

			fmt.Printf("%s\n", columnize.SimpleFormat(out))
			if len(resp.Todo) > 0 {
				fmt.Printf("\nTODO:\n")
				for _, todo := range resp.Todo {
					fmt.Printf("--> %s\n", todo)
				}
			}
		},
	}

	bootstrap := &cobra.Command{
		Use:   "bootstrap-sig0-key",
		Short: "Send dsync bootstrap command",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename", "algorithm")

			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
				Command:   "bootstrap-sig0-key",
				Zone:      dns.Fqdn(tdns.Globals.Zonename),
				Algorithm: dns.StringToAlgorithm[tdns.Globals.Algorithm],
			})
			PrintUpdateResult(resp.UpdateResult)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}
			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
	bootstrap.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519",
		sig0AlgorithmsHelp("Algorithm for the new SIG(0) key"))

	rollKey := &cobra.Command{
		Use:   "roll-sig0-key",
		Short: "Send dsync rollover command",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename", "algorithm", "rollaction")

			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
				Command:   "roll-sig0-key",
				Zone:      dns.Fqdn(tdns.Globals.Zonename),
				Algorithm: dns.StringToAlgorithm[tdns.Globals.Algorithm],
				Action:    rollaction,
			})
			PrintUpdateResult(resp.UpdateResult)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}
			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
	rollKey.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519",
		sig0AlgorithmsHelp("Algorithm for the new SIG(0) key"))
	rollKey.PersistentFlags().StringVarP(&rollaction, "rollaction", "r", "complete", "[debug] Phase of the rollover to perform: complete, add, remove, update-local")
	rollKey.PersistentFlags().MarkHidden("rollaction")

	publish := &cobra.Command{
		Use:   "publish",
		Short: "Send dsync publish-dsync-rrset command",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")

			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
				Command: "publish-dsync-rrset",
				Zone:    dns.Fqdn(tdns.Globals.Zonename),
			})
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}
			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}

	unpublish := &cobra.Command{
		Use:   "unpublish",
		Short: "Send dsync unpublish-dsync-rrset command",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")

			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
				Command: "unpublish-dsync-rrset",
				Zone:    dns.Fqdn(tdns.Globals.Zonename),
			})
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}
			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}

	c.AddCommand(status, bootstrap, rollKey, publish, unpublish)
	return c
}

func SendDsyncCommand(api *tdns.ApiClient, data tdns.ZoneDsyncPost) (tdns.ZoneDsyncResponse, error) {
	var cr tdns.ZoneDsyncResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/zone/dsync", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return cr, fmt.Errorf("error from api post: %v", err)
	}
	// Only print status if it's not 200 (success) - useful for debugging errors
	if status != 200 && tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if cr.Error {
		return cr, fmt.Errorf("error from server: %s", cr.ErrorMsg)
	}

	return cr, nil
}

func PrintUpdateResult(ur tdns.UpdateResult) {
	if len(ur.TargetStatus) > 0 {
		fmt.Printf("Update result:\n")
		var out = []string{"Sender|Rcode|EDE code|Message"}
		for _, tes := range ur.TargetStatus {
			if tes.Error {
				out = append(out, fmt.Sprintf("%s|%s|%s|%s", tes.Sender, "ERROR", "---", tes.ErrorMsg))
			} else {
				out = append(out, fmt.Sprintf("%s|%s|%d|%s", tes.Sender, dns.RcodeToString[tes.Rcode],
					tes.EDECode, tes.EDEMessage))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	}
}
