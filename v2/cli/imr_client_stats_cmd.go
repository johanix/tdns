/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

var (
	clientStatsClients []string
	clientStatsReset   bool
	clientStatsSort    string
	clientStatsJSON    bool
	clientStatsPct     bool
	clientStatsPrivacy bool
)

// imrStatsClientStatsCmd shows the per-client transport counters of a running
// tdns-imr: for each client, how many queries arrived over which transport,
// since startup or the last reset. Like transport-stats it works in-process
// (the tdns-imr REPL) and remotely (tdns-cli, over the /imr API).
var imrStatsClientStatsCmd = &cobra.Command{
	Use:     "client-transports",
	Aliases: []string{"client-stats"},
	Short:   "Show which transports clients use to reach this resolver",
	Long: `Show, per client address, how many queries arrived over each transport
(Do53 over UDP and TCP, DoT, DoQ, DoH) and when each was last used, since the
resolver started or the counters were last reset.

--pct shows each transport's share of the row's queries instead of a count.
--privacy shows one row per PRIVACY level a client's queries carried: "none"
(also without the option), "opp." (opportunistic) and "strict". A client that
never asks for privacy stays one row. Privacy asked for over a cleartext hop to
the resolver (strict over Do53) shows as such.

-c selects clients by address or prefix, and may be given more than once; with
none, all clients are shown. --reset clears the counters after showing them --
ALL of them, every client and the evicted totals, whatever -c selected -- so
the next run covers a new period.

The counters must be switched on in the resolver's configuration
(imrengine.client-stats.enabled), which takes effect at restart. They record
client addresses, never query names.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runClientStats(cmd.Context())
	},
}

func runClientStats(ctx context.Context) {
	var rep tdns.ImrClientStatsReport
	if imr := tdns.Globals.ImrEngine; imr != nil && imr.ClientStats != nil {
		// In-process: the REPL has no reason to call its own API.
		filter, err := tdns.ParseClientFilter(clientStatsClients)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		rep = imr.ClientStats.Snapshot(filter, clientStatsReset)
	} else {
		data := map[string]interface{}{"reset": clientStatsReset}
		if len(clientStatsClients) > 0 {
			data["clients"] = clientStatsClients
		}
		amr, err := SendImrMgmtCmd(ctx, "imr", &tdns.ImrMgmtPost{Command: "imr-client-stats", Data: data})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if amr.Error {
			fmt.Printf("Error: %s\n", amr.ErrorMsg)
			os.Exit(1)
		}
		raw, err := json.Marshal(amr.Data)
		if err != nil {
			log.Fatalf("failed to read response: %v", err)
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			log.Fatalf("failed to parse response: %v", err)
		}
	}
	if clientStatsJSON {
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Print(formatClientStats(rep, clientStatsSort, clientStatsPct, clientStatsPrivacy))
}

// formatClientStats renders a report as a table, sorted by address, total or
// last seen. With pct the transport columns are shares of each row's TOTAL;
// with privacy each client has a row per PRIVACY level it used.
func formatClientStats(rep tdns.ImrClientStatsReport, sortBy string, pct, privacy bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Client transport counters since %s: %d clients held, %d shown, %d evicted\n\n",
		rep.Since.Format("2006-01-02 15:04:05"), rep.Clients, len(rep.Rows), rep.EvictedClients)

	rows := append([]tdns.ImrClientStatsRow(nil), rep.Rows...)
	switch sortBy {
	case "total":
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Total > rows[j].Total })
	case "last":
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].LastAny.After(rows[j].LastAny) })
	}

	tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	header := []string{"CLIENT"}
	if privacy {
		header = append(header, "PRIVACY")
	}
	for _, t := range tdns.ImrClientTransports {
		header = append(header, strings.ToUpper(t))
	}
	header = append(header, "TOTAL", "LAST SEEN")
	fmt.Fprintln(tw, strings.Join(header, "\t"))

	totals := newLevelTotals()
	unsplit := false
	group := func(label string, counts map[string]uint64, total uint64, byPrivacy map[string]map[string]uint64, last string) {
		if privacy && total > 0 && byPrivacy == nil {
			unsplit = true
		}
		for i, cr := range countRows(counts, total, byPrivacy, privacy) {
			totals.add(cr)
			cols := []string{""}
			if i == 0 {
				cols[0] = label
			}
			if privacy {
				cols = append(cols, privacyLabel(cr.level))
			}
			cols = append(cols, transportCells(cr.counts, cr.total, pct)...)
			cols = append(cols, fmt.Sprint(cr.total))
			if i == 0 {
				cols = append(cols, last)
			}
			fmt.Fprintln(tw, joinCells(cols, len(header)))
		}
	}
	for _, r := range rows {
		group(r.Client, r.Counts, r.Total, r.ByPrivacy, lastSeen(r))
	}
	if rep.EvictedClients > 0 {
		var n uint64
		for _, c := range rep.EvictedCounts {
			n += c
		}
		group(fmt.Sprintf("(%d evicted)", rep.EvictedClients), rep.EvictedCounts, n, rep.EvictedByPrivacy, "")
	}
	for i, cr := range totals.rows() {
		cols := []string{""}
		if i == 0 {
			cols[0] = "TOTAL"
		}
		if privacy {
			cols = append(cols, privacyLabel(cr.level))
		}
		cols = append(cols, transportCells(cr.counts, cr.total, pct)...)
		cols = append(cols, fmt.Sprint(cr.total))
		fmt.Fprintln(tw, joinCells(cols, len(header)))
	}
	tw.Flush()
	table := trimLineEnds(b.String())
	b.Reset()
	b.WriteString(table)

	if unsplit {
		b.WriteString("\nThe resolver does not count queries by privacy level (it predates --privacy): its rows are not split.\n")
	}
	if rep.Reset {
		b.WriteString("\nThe counters were reset after this snapshot: a new period starts now.\n")
	}
	return b.String()
}

// lastSeen is when the client was last seen, and over which transport.
func lastSeen(r tdns.ImrClientStatsRow) string {
	return lastOver(r.LastSeen)
}

// lastOver is the latest of a per-transport set of times, and its transport.
func lastOver(last map[string]time.Time) string {
	var latest time.Time
	var via string
	for _, t := range tdns.ImrClientTransports {
		if ts, ok := last[t]; ok && ts.After(latest) {
			latest, via = ts, t
		}
	}
	if latest.IsZero() {
		return ""
	}
	return fmt.Sprintf("%s (%s)", latest.Format("15:04:05"), via)
}

func init() {
	imrStatsClientStatsCmd.Flags().StringSliceVarP(&clientStatsClients, "client", "c", nil, "Client address or prefix; may be repeated")
	imrStatsClientStatsCmd.Flags().BoolVar(&clientStatsReset, "reset", false, "Clear ALL counters after showing them")
	imrStatsClientStatsCmd.Flags().StringVar(&clientStatsSort, "sort", "addr", "Sort by addr, total or last")
	imrStatsClientStatsCmd.Flags().BoolVar(&clientStatsJSON, "json", false, "Print the report as JSON")
	imrStatsClientStatsCmd.Flags().BoolVar(&clientStatsPct, "pct", false, "Show each transport's share of the row's queries instead of counts")
	imrStatsClientStatsCmd.Flags().BoolVar(&clientStatsPrivacy, "privacy", false, "One row per PRIVACY level a client's queries carried (none, opp., strict)")
	ImrStatsCmd.AddCommand(imrStatsClientStatsCmd)
}
