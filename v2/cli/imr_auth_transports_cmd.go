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
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var (
	authTransportsServers []string
	authTransportsReset   bool
	authTransportsSort    string
	authTransportsJSON    bool
	authTransportsPct     bool
	authTransportsPrivacy bool
)

// imrStatsAuthTransportsCmd shows, per auth server, which transports a running
// tdns-imr's own queries went over, next to the transport signal the server
// gave. Like client-transports it works in-process (the tdns-imr REPL) and
// remotely (tdns-cli, over the /imr API).
var imrStatsAuthTransportsCmd = &cobra.Command{
	Use:     "auth-transports [zone]",
	Aliases: []string{"auth-servers"},
	Short:   "Show which transports this resolver uses to reach each auth server",
	Long: `Show, per authoritative server, how many of the resolver's queries were
answered over each transport (Do53 over UDP and TCP, DoT, DoQ, DoH), how many
attempts failed (FAIL), how many Do53/UDP answers were truncated and retried
over TCP (TC), and when the server last answered -- next to the transport
signal the server gave (OOTS), so that the two can be compared.

OOTS is the signal as the server gave it: only the transports it named, with
their weights. "none" means it gave none. "alpn:" is an SVCB with an ALPN list
and no weights (each counts as 100), and "set:" an operator's override (imr set
server transport). A stub's row shows its configured signal. Cleartext is udp
and tcp, apart; an older signal's do53:N is shown as what it means, udp:N
tcp:N, and an explicit udp or tcp wins over it. A weight of 1 is marked
(ignored): selection uses only weights above 1. Nor are the udp and tcp
weights shares: Do53 gets what the encrypted weights leave of 100, and tcp
only caps the TCP the resolver would choose on its own, which is none (TCP
after truncation, or forced, ignores it). A port the signal assigns follows
that transport (dot:30 port:1234), udp and tcp included. A record's port
applies to every transport the record names; an older signal's do53 never
takes one. The retry over TCP after truncation goes to the address and port
that truncated, and forced TCP to the tcp port, or 53 when there is none.

--pct shows each transport's share of the row's answers instead of a count,
and adds EXPECTED: the shares selection gives a query without PRIVACY (with
--privacy, at the row's level). Without PRIVACY, each encrypted transport gets
its weight as a percentage and Do53 the rest; with PRIVACY (opportunistic or
strict) only the encrypted transports are drawn, in proportion to their
weights. A server's shares still differ from EXPECTED when:
  - its zone has several nameservers. Each server's pick for a query competes
    with the others' on round-trip time, so a pick of a slower transport tends
    to lose the query to another server: the shares lean to the faster ones;
  - few names are asked for. A name always gets the same pick at a server;
  - queries fail and fall back, and when answers come from the cache (they
    send no query).

--privacy shows one row per class of query under each server: "none", "opp."
and "strict" for a client's PRIVACY level, and "internal" for the resolver's
own lookups (DNSKEY and DS for validation, nameserver addresses, transport
signals, priming, and lookups by the scanner, the DSYNC code and the in-process
"imr query"). "tdns-cli imr query", sent over the API, counts as a client's
query without PRIVACY: "none". FAIL and TC are the server's, on its first row.

Each server is one row, however many zones it serves (ZONES); [zone] shows only
the servers of that zone. The per-zone listing of the same counters, attempted
and failed per transport included, is "transport-stats". A stub zone's server
is counted apart from the same name found by resolution, and is marked (stub).

-s selects servers by name, and may be given more than once: a name selects
that server and every server below it. With none, all servers are shown.
--reset clears the counters after showing them -- ALL of them, every server,
whatever [zone] and -s selected, including those transport-stats shows -- so
the next run covers a new period.

--sort orders the rows (the TOTAL row is always last):
  label   by the server's DNS labels from the right, TLD first, so that all
          *.root-servers.net. rows are together, and so are all
          *.gtld-servers.net. rows (the default)
  oots    the servers that gave an OOTS signal (anything but "none" in the
          OOTS column) first, then the rest; label order within each group
  name    by name, plain alphabetical
  total   the busiest server first (ties by name)
  last    the most recently used server first (ties by name)
--sort orders the table only; --json prints the rows as the resolver sends them.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var zone string
		if len(args) == 1 {
			zone = dns.Fqdn(args[0])
		}
		runAuthTransports(cmd.Context(), imrRoleFor(cmd), zone)
	},
}

// runAuthTransports fetches the report -- from the live cache in the tdns-imr
// shell, over the /imr API from tdns-cli -- and prints it as the flags say.
// role names the daemon the API call goes to.
func runAuthTransports(ctx context.Context, role, zone string) {
	if err := checkAuthTransportsSort(authTransportsSort); err != nil {
		// Refused before anything is fetched: a typo must not cost a --reset.
		fmt.Printf("Error: %v\n", err)
		return
	}
	var rep tdns.ImrAuthTransportsReport
	if imr := tdns.Globals.ImrEngine; imr != nil && imr.Cache != nil {
		// In-process: the REPL has no reason to call its own API.
		filter, err := tdns.ParseServerFilter(authTransportsServers)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		rep = imr.AuthTransportsSnapshot(filter, zone, authTransportsReset)
	} else {
		data := map[string]interface{}{"reset": authTransportsReset}
		if len(authTransportsServers) > 0 {
			data["servers"] = authTransportsServers
		}
		if zone != "" {
			data["zone"] = zone
		}
		amr, err := SendImrMgmtCmd(ctx, role, &tdns.ImrMgmtPost{Command: "imr-auth-transports", Data: data})
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
	if authTransportsJSON {
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Print(formatAuthTransports(rep, authTransportsSort, authTransportsPct, authTransportsPrivacy))
}

// authTransportsSortModes are the values of --sort, the default first.
var authTransportsSortModes = []string{"label", "oots", "name", "total", "last"}

// checkAuthTransportsSort is nil for a --sort value, and otherwise an error
// that names the values there are.
func checkAuthTransportsSort(mode string) error {
	for _, m := range authTransportsSortModes {
		if m == mode {
			return nil
		}
	}
	last := len(authTransportsSortModes) - 1
	return fmt.Errorf("--sort %q: use %s or %s", mode,
		strings.Join(authTransportsSortModes[:last], ", "), authTransportsSortModes[last])
}

// advertisesOOTS reports whether the server gave a transport signal: anything
// but "none" in the OOTS column. A signal that named no transport ("empty")
// and a stub's configured or an operator's set one count.
func advertisesOOTS(r tdns.ImrAuthTransportsRow) bool {
	return len(r.Signal) > 0 || r.SignalSource != ""
}

// lessByLabel orders rows by server name from the right-hand label (TLD first),
// as the "dump" listings do, so that every server of a parent domain is
// together. Rows of one name: the shared instance, then the others in the order
// they came.
func lessByLabel(a, b tdns.ImrAuthTransportsRow) bool {
	if lessByReverseLabels(a.Server, b.Server) {
		return true
	}
	if lessByReverseLabels(b.Server, a.Server) {
		return false
	}
	return a.Shared && !b.Shared
}

// lessByName orders rows by plain name, as the resolver lists them: the shared
// instance of a name first.
func lessByName(a, b tdns.ImrAuthTransportsRow) bool {
	if a.Server != b.Server {
		return a.Server < b.Server
	}
	return a.Shared && !b.Shared
}

// sortAuthTransportRows orders rows in place as --sort sortBy says (see
// checkAuthTransportsSort); an unknown mode leaves them as they are.
func sortAuthTransportRows(rows []tdns.ImrAuthTransportsRow, sortBy string) {
	switch sortBy {
	case "label":
		sort.SliceStable(rows, func(i, j int) bool { return lessByLabel(rows[i], rows[j]) })
	case "oots":
		sort.SliceStable(rows, func(i, j int) bool {
			if si, sj := advertisesOOTS(rows[i]), advertisesOOTS(rows[j]); si != sj {
				return si
			}
			return lessByLabel(rows[i], rows[j])
		})
	case "name":
		sort.SliceStable(rows, func(i, j int) bool { return lessByName(rows[i], rows[j]) })
	case "total":
		sortAuthTransportRows(rows, "name")
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Total > rows[j].Total })
	case "last":
		sortAuthTransportRows(rows, "name")
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].LastAny.After(rows[j].LastAny) })
	}
}

// formatAuthTransports renders a report as a table, sorted as sortBy says (by
// label, oots signal, name, total or last used). With pct the transport columns
// are shares of each row's TOTAL, and EXPECTED shows what selection would give;
// with privacy each server has a row per class of query.
func formatAuthTransports(rep tdns.ImrAuthTransportsReport, sortBy string, pct, privacy bool) string {
	var b strings.Builder
	var of string
	if rep.Zone != "" {
		of = " for zone " + rep.Zone
	}
	fmt.Fprintf(&b, "Auth server transport counters%s since %s: %d servers held, %d shown\n\n",
		of, rep.Since.Format("2006-01-02 15:04:05"), rep.Servers, len(rep.Rows))

	rows := append([]tdns.ImrAuthTransportsRow(nil), rep.Rows...)
	sortAuthTransportRows(rows, sortBy)

	tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	header := []string{"AUTH SERVER", "ZONES"}
	if privacy {
		header = append(header, "PRIVACY")
	}
	for _, t := range tdns.ImrClientTransports {
		header = append(header, strings.ToUpper(t))
	}
	header = append(header, "TOTAL", "FAIL", "TC", "LAST USED")
	if pct {
		header = append(header, "EXPECTED")
	}
	header = append(header, "OOTS")
	fmt.Fprintln(tw, strings.Join(header, "\t"))

	totals := newLevelTotals()
	var failed, truncated uint64
	unsplit := false
	for _, r := range rows {
		if privacy && r.Total > 0 && r.ByPrivacy == nil {
			unsplit = true
		}
		failed += r.FailedTotal
		truncated += r.Truncated
		for i, cr := range countRows(r.Counts, r.Total, r.ByPrivacy, privacy) {
			totals.add(cr)
			first := i == 0
			cols := []string{"", ""}
			if first {
				cols = []string{authServerLabel(r), fmt.Sprint(len(r.Zones))}
			}
			if privacy {
				cols = append(cols, privacyLabel(cr.level))
			}
			cols = append(cols, transportCells(cr.counts, cr.total, pct)...)
			cols = append(cols, fmt.Sprint(cr.total))
			if first {
				cols = append(cols, fmt.Sprint(r.FailedTotal), fmt.Sprint(r.Truncated), lastOver(r.LastUsed))
			} else {
				cols = append(cols, "", "", "")
			}
			if pct {
				cols = append(cols, formatExpected(r.Expected, cr.level))
			}
			if first {
				cols = append(cols, formatOOTSSignal(r.Signal, r.SignalPorts, r.SignalSource))
			}
			fmt.Fprintln(tw, joinCells(cols, len(header)))
		}
	}
	for i, cr := range totals.rows() {
		cols := []string{"", ""}
		if i == 0 {
			cols[0] = "TOTAL"
		}
		if privacy {
			cols = append(cols, privacyLabel(cr.level))
		}
		cols = append(cols, transportCells(cr.counts, cr.total, pct)...)
		cols = append(cols, fmt.Sprint(cr.total))
		if i == 0 {
			cols = append(cols, fmt.Sprint(failed), fmt.Sprint(truncated))
		}
		fmt.Fprintln(tw, joinCells(cols, len(header)))
	}
	tw.Flush()
	table := trimLineEnds(b.String())
	b.Reset()
	b.WriteString(table)

	if unsplit {
		b.WriteString("\nThe resolver does not count answers by privacy level (it predates --privacy): its rows are not split.\n")
	}
	if rep.Reset {
		b.WriteString("\nThe counters were reset after this snapshot: a new period starts now.\n")
	}
	return b.String()
}

// authServerLabel is the server's name, marked when the row is a stub zone's
// private instance or a redirect target's (Src "target") rather than the one
// resolution shares.
func authServerLabel(r tdns.ImrAuthTransportsRow) string {
	if r.Shared {
		return r.Server
	}
	src := r.Src
	if src == "" {
		src = "private"
	}
	return fmt.Sprintf("%s (%s)", r.Server, src)
}

// formatOOTSSignal renders a server's transport signal as it was given, in the
// order of the table's columns: only the transports it named, an explicit zero
// included. An encrypted transport's weight of 1 is marked: selection uses only
// weights above 1. "none" when there was no signal, and "empty" when there was
// one that named no transport (an oots SvcParam without entries).
func formatOOTSSignal(signal map[string]uint8, ports map[string]uint16, source string) string {
	if len(signal) == 0 {
		if source != "" {
			return "empty"
		}
		return "none"
	}
	if source == "alpn" {
		var parts []string
		for _, t := range orderedTransports(signal) {
			if ports[t] != 0 {
				t += fmt.Sprintf(" port:%d", ports[t])
			}
			parts = append(parts, t)
		}
		return "alpn:" + strings.Join(parts, ",")
	}
	var parts []string
	for _, t := range orderedTransports(signal) {
		w := signal[t]
		part := fmt.Sprintf("%s:%d", t, w)
		if ports[t] != 0 {
			part += fmt.Sprintf(" port:%d", ports[t])
		}
		if w == 1 && !cleartextToken(t) {
			part += " (ignored)"
		}
		parts = append(parts, part)
	}
	out := strings.Join(parts, " ")
	if source == "operator" {
		out = "set: " + out
	}
	return out
}

// formatExpected renders the shares selection gives a query at level (the
// row's; "none" without --privacy), leaving out the transports that get none.
// "-" when the server cannot carry such a query; empty for the resolver's own
// lookups, which follow no one client's level, and for a resolver that
// predates EXPECTED.
// cleartextToken reports whether t names cleartext DNS: udp, tcp, or the do53
// transport. Their weights are not shares, so a weight of 1 is not marked
// (ignored).
func cleartextToken(t string) bool {
	return t == "udp" || t == "tcp" || t == "do53"
}

func formatExpected(expected map[string]map[string]uint8, level string) string {
	if len(expected) == 0 || level == "internal" {
		return ""
	}
	if level == "" || level == "-" {
		level = "none"
	}
	shares, ok := expected[level]
	if !ok {
		return "-"
	}
	var parts []string
	for _, t := range orderedTransports(shares) {
		if shares[t] > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", t, shares[t]))
		}
	}
	return strings.Join(parts, " ")
}

func init() {
	imrStatsAuthTransportsCmd.Flags().StringSliceVarP(&authTransportsServers, "server", "s", nil, "Server name, selecting it and every server below it; may be repeated")
	imrStatsAuthTransportsCmd.Flags().BoolVar(&authTransportsReset, "reset", false, "Clear ALL auth-server counters after showing them")
	imrStatsAuthTransportsCmd.Flags().StringVar(&authTransportsSort, "sort", "label", "Sort the rows by label (DNS labels from the TLD down), oots (servers with an OOTS signal first), name, total or last")
	imrStatsAuthTransportsCmd.Flags().BoolVar(&authTransportsJSON, "json", false, "Print the report as JSON")
	imrStatsAuthTransportsCmd.Flags().BoolVar(&authTransportsPct, "pct", false, "Show each transport's share of the row's answers instead of counts, and what selection would give (EXPECTED)")
	imrStatsAuthTransportsCmd.Flags().BoolVar(&authTransportsPrivacy, "privacy", false, "One row per class of query: a client's PRIVACY level (none, opp., strict) or internal")
	ImrStatsCmd.AddCommand(imrStatsAuthTransportsCmd)
}
