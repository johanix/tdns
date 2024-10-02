/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var zoneDsyncCmd = &cobra.Command{
	Use:   "dsync",
	Short: "Prefix command, not useable by itself",
}

var zoneDsyncStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Send dsync status command to tdns-server",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		resp, err := SendDsyncCommand(tdns.Globals.Api, tdns.ZoneDsyncPost{
			Command: "status",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-server: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}

		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
		out := []string{}
		for key, status := range resp.Functions {
			out = append(out, fmt.Sprintf("%s|%s", key, status))
		}
		sort.Strings(out)
		if showhdr {
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

var zoneDsyncBootstrapCmd = &cobra.Command{
	Use:   "bootstrap-sig0-key",
	Short: "Send dsync bootstrap command to tdns-server",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "algorithm")

		resp, err := SendDsyncCommand(tdns.Globals.Api, tdns.ZoneDsyncPost{
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
			fmt.Printf("Error from tdns-server: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var rollaction string

var zoneDsyncRollKeyCmd = &cobra.Command{
	Use:   "roll-sig0-key",
	Short: "Send dsync rollover command to tdns-server",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "algorithm", "rollaction")

		resp, err := SendDsyncCommand(tdns.Globals.Api, tdns.ZoneDsyncPost{
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
			fmt.Printf("Error from tdns-server: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var zoneDsyncPublishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Send dsync publish-dsync-rrset command to tdns-server",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		resp, err := SendDsyncCommand(tdns.Globals.Api, tdns.ZoneDsyncPost{
			Command: "publish-dsync-rrset",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-server: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var zoneDsyncUnpublishCmd = &cobra.Command{
	Use:   "unpublish",
	Short: "Send dsync unpublish-dsync-rrset command to tdns-server",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		resp, err := SendDsyncCommand(tdns.Globals.Api, tdns.ZoneDsyncPost{
			Command: "unpublish-dsync-rrset",
			Zone:    dns.Fqdn(tdns.Globals.Zonename),
		})
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-server: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

func init() {
	zoneCmd.AddCommand(zoneDsyncCmd)
	zoneDsyncCmd.AddCommand(zoneDsyncStatusCmd, zoneDsyncBootstrapCmd, zoneDsyncRollKeyCmd, zoneDsyncPublishCmd, zoneDsyncUnpublishCmd)

	zoneDsyncCmd.PersistentFlags().BoolVarP(&showhdr, "showhdr", "H", false, "Show headers")
	zoneDsyncRollKeyCmd.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519", "Algorithm to use for the new SIG(0) key")
	zoneDsyncBootstrapCmd.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "ED25519", "Algorithm to use for the new SIG(0) key")
	zoneDsyncRollKeyCmd.PersistentFlags().StringVarP(&rollaction, "rollaction", "r", "complete", "[debug] Phase of the rollover to perform: complete, add, remove, update-local")
	zoneDsyncRollKeyCmd.PersistentFlags().MarkHidden("rollaction")
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
	if verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if cr.Error {
		return cr, fmt.Errorf("error from tdns-server: %s", cr.ErrorMsg)
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
