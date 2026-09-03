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

// newZoneParentSyncCmd returns a fresh "parentsync" subtree for the child role.
func newZoneParentSyncCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "parentsync",
		Short: "Child-side parent delegation sync commands",
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show parentsync status for the zone",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
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

	var bootstrapScheme string
	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap the SIG(0) key with the parent",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
				Command: "bootstrap",
				Zone:    dns.Fqdn(tdns.Globals.Zonename),
				Scheme:  bootstrapScheme,
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
	bootstrap.Flags().StringVar(&bootstrapScheme, "scheme", "", "Bootstrap scheme: update | notify | api (required)")
	bootstrap.MarkFlagRequired("scheme")

	rollKey := &cobra.Command{
		Use:   "roll-key",
		Short: "Roll the SIG(0) key with the parent",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename", "rollaction")
			alg := ResolveAlgorithm(role, useSIG0)
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
				Command:   "roll-key",
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

	inquire := &cobra.Command{
		Use:   "inquire",
		Short: "Inquire the parent about the current SIG(0) key state",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
				Command: "inquire",
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
			fmt.Printf("KeyState Inquiry for %s\n", dns.Fqdn(tdns.Globals.Zonename))
			fmt.Printf("  KeyID:        %d\n", resp.KeyID)
			fmt.Printf("  Parent says:  %s (code %d)\n", resp.StateName, resp.KeyState)
			fmt.Printf("  Authenticated: %v\n", resp.Authenticated)
		},
	}

	delta := &cobra.Command{
		Use:   "delta",
		Short: "Compute delta between parent delegation data and child zone data",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}
			dr, err := SendDelegationCmd(api, tdns.DelegationPost{
				Command: "status",
				Zone:    tdns.Globals.Zonename,
			})
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			if dr.Error {
				fmt.Printf("Error: %s\n", dr.ErrorMsg)
				os.Exit(1)
			}
			fmt.Printf("%s\n", dr.Msg)
			if dr.SyncStatus.InSync {
				fmt.Printf("Delegation information in parent %s is in sync with child %s. No action needed.\n",
					dr.SyncStatus.Parent, dr.SyncStatus.ZoneName)
				os.Exit(0)
			}
			fmt.Printf("Delegation information in parent %q is NOT in sync with child %q. Changes needed:\n",
				dr.SyncStatus.Parent, dr.SyncStatus.ZoneName)
			out := []string{"Change|RR"}
			for _, rr := range dr.SyncStatus.NsAddsStr {
				out = append(out, fmt.Sprintf("ADD NS|%s", rr))
			}
			for _, rr := range dr.SyncStatus.NsRemovesStr {
				out = append(out, fmt.Sprintf("DEL NS|%s", rr))
			}
			for _, rr := range dr.SyncStatus.AAddsStr {
				out = append(out, fmt.Sprintf("ADD IPv4 GLUE|%s", rr))
			}
			for _, rr := range dr.SyncStatus.ARemovesStr {
				out = append(out, fmt.Sprintf("DEL IPv4 GLUE|%s", rr))
			}
			for _, rr := range dr.SyncStatus.AAAAAddsStr {
				out = append(out, fmt.Sprintf("ADD IPv6 GLUE|%s", rr))
			}
			for _, rr := range dr.SyncStatus.AAAARemovesStr {
				out = append(out, fmt.Sprintf("DEL IPv6 GLUE|%s", rr))
			}
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		},
	}

	sync := &cobra.Command{
		Use:   "sync",
		Short: "Sync delegation data in parent zone via DDNS UPDATE",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}
			dr, err := SendDelegationCmd(api, tdns.DelegationPost{
				Command: "sync",
				Zone:    tdns.Globals.Zonename,
			})
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			if dr.Error {
				fmt.Printf("Error: %s\n", dr.ErrorMsg)
				os.Exit(1)
			}
			fmt.Printf("%s\n", dr.Msg)
		},
	}

	c.AddCommand(status, bootstrap, rollKey, inquire, delta, sync)
	return c
}

// SendParentSyncCommand POSTs a ZoneParentSyncPost to /zone/parentsync.
func SendParentSyncCommand(api *tdns.ApiClient, data tdns.ZoneParentSyncPost) (tdns.ZoneParentSyncResponse, error) {
	var cr tdns.ZoneParentSyncResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/zone/parentsync", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return cr, fmt.Errorf("error from api post: %v", err)
	}
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
