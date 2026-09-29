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

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

var (
	authServersServers []string
	authServersReset   bool
	authServersSort    string
	authServersJSON    bool
	authServersPct     bool
)

// imrStatsAuthServersCmd shows, per auth server, which transports a running
// tdns-imr's own queries went over, next to the transport signal the server
// gave. Like client-stats it works in-process (the tdns-imr REPL) and remotely
// (tdns-cli, over the /imr API).
var imrStatsAuthServersCmd = &cobra.Command{
	Use:   "auth-servers",
	Short: "Show which transports this resolver uses to reach each auth server",
	Long: `Show, per authoritative server, how many of the resolver's queries were
answered over each transport (Do53 over UDP and TCP, DoT, DoQ, DoH), how many
attempts failed (FAIL), how many Do53/UDP answers were truncated and retried
over TCP (TC), and when the server last answered -- next to the transport
signal the server gave (OOTS), so that the two can be compared. "none" means
the server gave no signal.

Selection gives each encrypted transport its signalled weight as a percentage
of the queries, and Do53 the rest. --pct shows each transport's share of the
server's answers instead of a count, which compares directly with the signal.
A client that asks for privacy moves queries off Do53 whatever the signal says.

Each server is one row, however many zones it serves (ZONES); the per-zone
listing of the same counters is "auth-transports". A stub zone's server is
counted apart from the same name found by resolution, and is marked (stub).

-s selects servers by name, and may be given more than once: a name selects
that server and every server below it. With none, all servers are shown.
--reset clears the counters after showing them -- ALL of them, every server,
whatever -s selected, including those auth-transports shows -- so the next run
covers a new period.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runAuthServers(cmd.Context())
	},
}

func runAuthServers(ctx context.Context) {
	switch authServersSort {
	case "name", "total", "last":
	default:
		// Refused before anything is fetched: a typo must not cost a --reset.
		fmt.Printf("Error: --sort %q: use name, total or last\n", authServersSort)
		return
	}
	var rep tdns.ImrAuthServersReport
	if imr := tdns.Globals.ImrEngine; imr != nil && imr.Cache != nil {
		// In-process: the REPL has no reason to call its own API.
		filter, err := tdns.ParseServerFilter(authServersServers)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		rep = tdns.ImrAuthServersSnapshot(imr.Cache, filter, authServersReset)
	} else {
		data := map[string]interface{}{"reset": authServersReset}
		if len(authServersServers) > 0 {
			data["servers"] = authServersServers
		}
		amr, err := SendImrMgmtCmd(ctx, "imr", &tdns.ImrMgmtPost{Command: "imr-auth-servers", Data: data})
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
	if authServersJSON {
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Print(formatAuthServers(rep, authServersSort, authServersPct))
}

// formatAuthServers renders a report as a table, sorted by name, total or last
// used; with pct, the transport columns are shares of each row's TOTAL.
func formatAuthServers(rep tdns.ImrAuthServersReport, sortBy string, pct bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Auth server transport counters since %s: %d servers held, %d shown\n\n",
		rep.Since.Format("2006-01-02 15:04:05"), rep.Servers, len(rep.Rows))

	rows := append([]tdns.ImrAuthServerRow(nil), rep.Rows...)
	switch sortBy {
	case "total":
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Total > rows[j].Total })
	case "last":
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].LastAny.After(rows[j].LastAny) })
	}

	tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	header := []string{"AUTH SERVER", "ZONES"}
	for _, t := range tdns.ImrClientTransports {
		header = append(header, strings.ToUpper(t))
	}
	header = append(header, "TOTAL", "FAIL", "TC", "LAST USED", "OOTS")
	fmt.Fprintln(tw, strings.Join(header, "\t"))

	totals := map[string]uint64{}
	var total, failed, truncated uint64
	for _, r := range rows {
		cols := []string{authServerLabel(r), fmt.Sprint(len(r.Zones))}
		for _, t := range tdns.ImrClientTransports {
			cols = append(cols, countOrShare(r.Counts[t], r.Total, pct))
			totals[t] += r.Counts[t]
		}
		total += r.Total
		failed += r.FailedTotal
		truncated += r.Truncated
		cols = append(cols, fmt.Sprint(r.Total), fmt.Sprint(r.FailedTotal), fmt.Sprint(r.Truncated),
			lastOver(r.LastUsed), formatOOTSSignal(r.Signal))
		fmt.Fprintln(tw, strings.Join(cols, "\t"))
	}
	cols := []string{"TOTAL", ""}
	for _, t := range tdns.ImrClientTransports {
		cols = append(cols, countOrShare(totals[t], total, pct))
	}
	cols = append(cols, fmt.Sprint(total), fmt.Sprint(failed), fmt.Sprint(truncated))
	fmt.Fprintln(tw, strings.Join(cols, "\t"))
	tw.Flush()

	if rep.Reset {
		b.WriteString("\nThe counters were reset after this snapshot: a new period starts now.\n")
	}
	return b.String()
}

// authServerLabel is the server's name, marked when the row is a stub zone's
// private instance rather than the one resolution shares.
func authServerLabel(r tdns.ImrAuthServerRow) string {
	if r.Shared {
		return r.Server
	}
	src := r.Src
	if src == "" {
		src = "private"
	}
	return fmt.Sprintf("%s (%s)", r.Server, src)
}

// countOrShare is n, or with pct n's share of total. A share that rounds to 0
// or 100 without being either says so, so that a few queries are not hidden.
func countOrShare(n, total uint64, pct bool) string {
	if !pct {
		return fmt.Sprint(n)
	}
	if total == 0 {
		return "-"
	}
	p := (n*100 + total/2) / total
	switch {
	case n > 0 && p == 0:
		return "<1%"
	case n < total && p == 100:
		return ">99%"
	}
	return fmt.Sprintf("%d%%", p)
}

// formatOOTSSignal renders a server's transport signal in the order of the
// table's columns, zero weights included: a zero is what the server said.
// "none" when it gave no signal, which the per-zone listing shows as do53=100.
func formatOOTSSignal(signal map[string]uint8) string {
	if len(signal) == 0 {
		return "none"
	}
	order := []string{"do53", "dot", "doq", "doh"}
	known := map[string]bool{}
	var parts []string
	for _, t := range order {
		known[t] = true
		if w, ok := signal[t]; ok {
			parts = append(parts, fmt.Sprintf("%s:%d", t, w))
		}
	}
	var rest []string
	for t := range signal {
		if !known[t] {
			rest = append(rest, t)
		}
	}
	sort.Strings(rest)
	for _, t := range rest {
		parts = append(parts, fmt.Sprintf("%s:%d", t, signal[t]))
	}
	return strings.Join(parts, " ")
}

func init() {
	imrStatsAuthServersCmd.Flags().StringSliceVarP(&authServersServers, "server", "s", nil, "Server name, selecting it and every server below it; may be repeated")
	imrStatsAuthServersCmd.Flags().BoolVar(&authServersReset, "reset", false, "Clear ALL auth-server counters after showing them")
	imrStatsAuthServersCmd.Flags().StringVar(&authServersSort, "sort", "name", "Sort by name, total or last")
	imrStatsAuthServersCmd.Flags().BoolVar(&authServersJSON, "json", false, "Print the report as JSON")
	imrStatsAuthServersCmd.Flags().BoolVar(&authServersPct, "pct", false, "Show each transport's share of the server's answers instead of counts")
	ImrStatsCmd.AddCommand(imrStatsAuthServersCmd)
}
