/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var delegationChild string

var (
	syncLogSince string
	syncLogLimit int
	syncLogJSON  bool
)

// AttachZoneDelegationCmds adds the "zone delegation" subtree.
//
// The read half of "zone update". A client that has just written a delegation
// otherwise has no way to confirm what the server holds except by querying the
// public DNS -- a different channel, with different authentication and
// caching, and blind to anything the server has accepted but not yet
// published.
func AttachZoneDelegationCmds(c *cobra.Command, role string) {
	delegation := &cobra.Command{
		Use:   "delegation",
		Short: "Inspect the delegation data a parent zone holds for its children",
	}

	get := &cobra.Command{
		Use:   "get",
		Short: "Show what this parent publishes for a child (or list its children)",
		Long: `Report the delegation records the parent currently holds for a child zone,
grouped by owner name and type.

With no --child, list the children this parent has delegation data for -- the
question that comes first when reconciling an external store against the
server.

The answer comes from the zone's delegation backend, so it is what the SERVER
considers current. For a backend that records delegations somewhere other than
the served zone those differ deliberately, and reading the zone instead would
quietly give the wrong answer.`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { runZoneDelegationGet(role) },
	}
	get.Flags().StringVar(&delegationChild, "child", "",
		"Child zone to report on; omit to list the parent's children")

	syncLogCmd := &cobra.Command{
		Use:   "sync-log",
		Short: "Show what this parent received from its children, and what it did with it",
		Long: `Show the delegation-sync log: one line per UPDATE from a child, per scan a
NOTIFY started, per scan a poll started that found something or could not
process the child, per NOTIFY refused before any scan, and per DSYNC API write.
Newest first.

"applied" means the parent's delegation data changed. A change a scan decided
on is "queued" or "apply failed" until it has landed.

With -z, only that parent; with --child, only that child. The log is kept in
memory: it starts empty when the server starts, and holds the most recent
childsync.sync-log events (default 10000).`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { runZoneDelegationSyncLog(role) },
	}
	syncLogCmd.Flags().StringVar(&delegationChild, "child", "", "Only this child zone")
	syncLogCmd.Flags().StringVar(&syncLogSince, "since", "", "Only events since: a duration back from now (10m) or an RFC 3339 time")
	syncLogCmd.Flags().IntVar(&syncLogLimit, "limit", 50, "At most this many events; 0 for all")
	syncLogCmd.Flags().BoolVar(&syncLogJSON, "json", false, "Print the report as JSON")

	delegation.AddCommand(get, syncLogCmd)
	c.AddCommand(delegation)
}

func runZoneDelegationSyncLog(role string) {
	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}
	dr, err := SendDelegationCmd(api, tdns.DelegationPost{
		Command: "sync-log",
		Zone:    tdns.Globals.Zonename,
		Child:   delegationChild,
		Since:   syncLogSince,
		Limit:   syncLogLimit,
	})
	if err != nil {
		fmt.Printf("Error from %s: %s\n", role, err.Error())
		os.Exit(1)
	}
	if dr.SyncLog == nil {
		fmt.Printf("Error: %s returned no delegation-sync log\n", role)
		os.Exit(1)
	}
	if syncLogJSON {
		out, _ := json.MarshalIndent(dr.SyncLog, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Print(formatSyncLog(dr.SyncLog))
}

// formatSyncLog renders a delegation-sync log report as a table.
func formatSyncLog(rep *tdns.SyncLogReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Delegation-sync log since %s: %d events shown, %d kept at most, %d dropped\n\n",
		rep.Since.Format("2006-01-02 15:04:05"), len(rep.Events), rep.Size, rep.Dropped)
	if len(rep.Events) == 0 {
		b.WriteString("(no events)\n")
		return b.String()
	}
	tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tPARENT\tCHILD\tMECHANISM\tOUTCOME\tDETAILS")
	for _, ev := range rep.Events {
		var details []string
		for _, s := range []string{ev.Changes, ev.Rcode, ev.EDE, ev.Reason} {
			if s != "" {
				details = append(details, s)
			}
		}
		parent := ev.Parent
		if parent == "" {
			parent = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", ev.Time.Format("01-02 15:04:05"),
			parent, ev.Child, ev.Mechanism, ev.Outcome, strings.Join(details, "; "))
	}
	tw.Flush()
	return b.String()
}

func runZoneDelegationGet(role string) {
	PrepArgs("zonename")

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command:   "get-delegation",
		Zone:      dns.Fqdn(tdns.Globals.Zonename),
		ChildZone: delegationChild,
	})
	if err != nil {
		fmt.Printf("Error from %s: %s\n", role, err.Error())
		os.Exit(1)
	}
	if cr.Error {
		fmt.Printf("Error: %s\n", cr.ErrorMsg)
		os.Exit(1)
	}
	if cr.Delegation == nil {
		fmt.Printf("%s: no delegation information returned\n", tdns.Globals.Zonename)
		os.Exit(1)
	}
	printDelegation(cr.Delegation)
}

func printDelegation(d *tdns.ChildDelegationReport) {
	owners := make([]string, 0, len(d.RRsets))
	for o := range d.RRsets {
		owners = append(owners, o)
	}
	sort.Strings(owners)

	if d.Child == "" {
		fmt.Printf("%s: %d child zone(s) with delegation data (backend: %s)\n",
			d.Parent, len(owners), d.Backend)
		for _, o := range owners {
			fmt.Printf("   %s\n", o)
		}
		return
	}

	fmt.Printf("%s: delegation of %s (backend: %s)\n", d.Parent, d.Child, d.Backend)
	if len(owners) == 0 {
		fmt.Printf("   (the parent holds no delegation data for this child)\n")
		return
	}
	for _, o := range owners {
		types := make([]string, 0, len(d.RRsets[o]))
		for t := range d.RRsets[o] {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			for _, rr := range d.RRsets[o][t] {
				fmt.Printf("   %s\n", rr)
			}
		}
	}
}
