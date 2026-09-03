/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
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
			PrepArgs("zonename")
			alg := ResolveAlgorithm(role, useSIG0)

			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
				Command:   "bootstrap-sig0-key",
				Zone:      dns.Fqdn(tdns.Globals.Zonename),
				Algorithm: alg,
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
	bootstrap.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "",
		sig0AlgorithmsHelp("Algorithm for the new SIG(0) key"))

	rollKey := &cobra.Command{
		Use:   "roll-sig0-key",
		Short: "Send dsync rollover command",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename", "rollaction")
			alg := ResolveAlgorithm(role, useSIG0)

			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendDsyncCommand(api, tdns.ZoneDsyncPost{
				Command:   "roll-sig0-key",
				Zone:      dns.Fqdn(tdns.Globals.Zonename),
				Algorithm: alg,
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
	rollKey.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "",
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

// parentSideCommands are dsync commands that operate on the parent (childsync) side.
var parentSideCommands = map[string]bool{
	"publish-dsync-rrset":   true,
	"unpublish-dsync-rrset": true,
}

// SendDsyncCommand is a hidden-alias helper: child-side commands post to
// /zone/parentsync; parent-side commands post to /zone/childsync.
func SendDsyncCommand(api *tdns.ApiClient, data tdns.ZoneDsyncPost) (tdns.ZoneDsyncResponse, error) {
	if parentSideCommands[data.Command] {
		// Map to childsync
		csReq := tdns.ZoneChildSyncPost{
			Command: map[string]string{
				"publish-dsync-rrset":   "publish",
				"unpublish-dsync-rrset": "unpublish",
			}[data.Command],
			Zone: data.Zone,
		}
		csResp, err := SendChildSyncCommand(api, csReq)
		return tdns.ZoneDsyncResponse{
			AppName:  csResp.AppName,
			Time:     csResp.Time,
			Msg:      csResp.Msg,
			Error:    csResp.Error,
			ErrorMsg: csResp.ErrorMsg,
		}, err
	}

	// Child-side: map to parentsync
	psCmd := data.Command
	switch psCmd {
	case "bootstrap-sig0-key":
		psCmd = "bootstrap"
	case "roll-sig0-key":
		psCmd = "roll-key"
	}
	psReq := tdns.ZoneParentSyncPost{
		Command:   psCmd,
		Zone:      data.Zone,
		Algorithm: data.Algorithm,
		Action:    data.Action,
		OldKeyID:  data.OldKeyID,
		NewKeyID:  data.NewKeyID,
		Scheme:    "update",
	}
	psResp, err := SendParentSyncCommand(api, psReq)
	return tdns.ZoneDsyncResponse{
		AppName:      psResp.AppName,
		Time:         psResp.Time,
		Status:       psResp.Status,
		Zone:         psResp.Zone,
		Functions:    psResp.Functions,
		Todo:         psResp.Todo,
		Msg:          psResp.Msg,
		OldKeyID:     psResp.OldKeyID,
		NewKeyID:     psResp.NewKeyID,
		Error:        psResp.Error,
		ErrorMsg:     psResp.ErrorMsg,
		UpdateResult: psResp.UpdateResult,
	}, err
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
