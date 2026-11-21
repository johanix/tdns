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
		Short: "Show whether a delegation change can reach the parent, and by which scheme",
		Long: `For a zone with parentsync (a zone syncing its own delegation) or
parentsync-proxy (a tdns-agent secondary syncing on behalf of its primary),
report whether a delegation change can reach the parent right now, by which
scheme, and if not, why not:

  - the parent, and whether its DSYNC RRset validated;
  - every scheme in parentsync.schemes, in preference order: usable (with
    its target) or skipped (with the reason);
  - detail for the configured schemes: for UPDATE on a parentsync-proxy zone
    the KEY-bootstrap state and the records to publish at the primary (what
    "zone proxy-key" used to print), for UPDATE on a parentsync zone its
    SIG(0) key and what the parent holds for it, for NOTIFY whether the zone
    publishes CDS and CSYNC, for API whether a credential is configured;
  - whether the parent's delegation is in sync with the zone, as
    "parentsync delta" computes it, and the zone's delegation-sync-warning.

Nothing on the zone is changed, with one exception: on a parentsync-proxy zone
waiting for its KEY to be published, the agent's SIG(0) keypair is generated
if it has none -- as the agent's next sync would -- so that there are records
to print.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			showParentSyncStatus(api, "error from server")
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
			if err != nil {
				fmt.Printf("error: %s\n", err.Error())
				os.Exit(1)
			}
			if tdns.Globals.Verbose {
				PrintUpdateResult(resp.UpdateResult)
			}
			if !printBootstrapResult(os.Stdout, resp.KeyID, resp.UpdateResult, resp.Error, resp.ErrorMsg) {
				os.Exit(1)
			}
		},
	}
	// Only "update" is implemented; it negotiates the actual method with the
	// parent from the advertised and willing lists. Defaulted rather than
	// required, so the working case needs no flag at all.
	bootstrap.Flags().StringVar(&bootstrapScheme, "scheme", "update", "Bootstrap scheme (only \"update\" is implemented)")

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
			if err != nil {
				fmt.Printf("error: %s\n", err.Error())
				os.Exit(1)
			}
			if tdns.Globals.Verbose {
				PrintUpdateResult(resp.UpdateResult)
			}
			if !printRollResult(os.Stdout, resp.OldKeyID, resp.NewKeyID, resp.UpdateResult,
				resp.Error, resp.ErrorMsg, resp.Msg) {
				os.Exit(1)
			}
		},
	}
	rollKey.PersistentFlags().StringVarP(&tdns.Globals.Algorithm, "algorithm", "a", "",
		sig0AlgorithmsHelp("Algorithm for the new SIG(0) key"))
	rollKey.PersistentFlags().StringVarP(&rollaction, "rollaction", "r", "complete", "[debug] Phase of the rollover to perform: complete, add, remove, update-local")
	rollKey.PersistentFlags().MarkHidden("rollaction")

	inquireRun := func(cmd *cobra.Command, args []string) {
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
			fmt.Printf("error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("error from server: %s\n", resp.ErrorMsg)
			os.Exit(1)
		}
		printInquireResult(os.Stdout, resp.KeyID, resp.StateName, resp.Authenticated)
	}

	inquire := &cobra.Command{
		Use:   "inquire",
		Short: "Inquire the parent about the current SIG(0) key state",
		Run:   inquireRun,
	}
	// The retired agent subtree spelled this "inquire update", with "inquire"
	// as a bare prefix. Kept as a hidden child so that spelling still runs,
	// rather than failing with "unknown command" for anyone who has it in a
	// script.
	inquire.AddCommand(&cobra.Command{
		Use:    "update",
		Short:  "Deprecated spelling of \"parentsync inquire\"",
		Hidden: true,
		Run:    inquireRun,
	})

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
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
			if dr.SyncStatus.Error {
				fmt.Printf("error: %s\n", dr.SyncStatus.ErrorMsg)
				os.Exit(1)
			}
			printDelegationDelta(os.Stdout, dr.SyncStatus)
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
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
			// The outcome is in SyncStatus; Msg is not set for "sync", so
			// this used to print one empty line whatever happened.
			if !printSyncResult(os.Stdout, dr.SyncStatus) {
				os.Exit(1)
			}
		},
	}

	c.AddCommand(status, bootstrap, rollKey, inquire, delta, sync)
	return c
}

// showParentSyncStatus asks the daemon for the parentsync status of
// tdns.Globals.Zonename and prints it. Shared by "zone parentsync status" and
// the hidden "zone dsync status" aliases, so the old spellings print the same
// report rather than the table the report replaced. errPrefix names who
// answered, as each caller always has.
func showParentSyncStatus(api *tdns.ApiClient, errPrefix string) {
	resp, err := SendParentSyncCommand(api, tdns.ZoneParentSyncPost{
		Command: "status",
		Zone:    dns.Fqdn(tdns.Globals.Zonename),
	})
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		os.Exit(1)
	}
	if resp.Error {
		fmt.Printf("%s: %s\n", errPrefix, resp.ErrorMsg)
		os.Exit(1)
	}
	if resp.Report == nil {
		// A daemon from before the report: its Functions table.
		printParentSyncStatus(resp)
		return
	}
	printParentSyncReport(os.Stdout, resp.Zone, resp.Report, resp.Todo, tdns.Globals.Verbose)
}

// printParentSyncStatus renders the Msg, Functions, and Todo from a
// /zone/parentsync status response from a daemon that predates the report.
func printParentSyncStatus(resp tdns.ZoneParentSyncResponse) {
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
	// cr.Error is NOT turned into a Go error: the callers render it
	// themselves ("Error from server: ..."), and wrapping it here made that
	// branch unreachable and doubled the prefix on the path that did run.
	// A non-nil error from this function means the exchange failed.
	return cr, nil
}
