/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// transportStatsFilter selects which zones' transport stats to show. At most
// one of zone (exact match) / suffix (zone-name suffix, à la `dump suffix`) is
// set; both empty means "all zones". It is applied identically on the in-process
// and remote paths so the filtering behaves the same in the REPL and via
// tdns-cli.
type transportStatsFilter struct {
	zone   string // exact zone (fqdn), or ""
	suffix string // zone-name suffix (fqdn), or ""
}

// matches reports whether a zone (ServerMap key, an fqdn) passes the filter.
// Delegates to the shared, DNS-label-aware predicate so the in-process and API
// paths cannot diverge.
func (f transportStatsFilter) matches(zone string) bool {
	return tdns.ZoneMatchesSelector(zone, f.zone, f.suffix)
}

// data renders the filter into the API request payload for the remote path.
func (f transportStatsFilter) data() map[string]interface{} {
	data := map[string]interface{}{}
	if f.zone != "" {
		data["zone"] = f.zone
	}
	if f.suffix != "" {
		data["suffix"] = f.suffix
	}
	return data
}

// noneMsg is the "nothing matched" message, scoped to the active filter.
func (f transportStatsFilter) noneMsg() string {
	switch {
	case f.zone != "":
		return fmt.Sprintf("No auth servers recorded for %s", f.zone)
	case f.suffix != "":
		return fmt.Sprintf("No auth servers recorded with suffix %s", f.suffix)
	default:
		return "No auth servers recorded"
	}
}

// imrStatsTransportStatsCmd shows per-server transport-usage stats (attempted /
// used / failed incl. do53-tcp, plus TC=1 truncations) for a running tdns-imr.
// It works both in-process (the `tdns-imr --cli` REPL, straight from the live
// cache) and remotely (the tdns-cli binary, over the /imr API), rendering an
// identical matrix either way. An optional [zone] positional narrows to a single
// zone; the `suffix` subcommand narrows to a zone-name suffix.
var imrStatsTransportStatsCmd = &cobra.Command{
	Use:   "transport-stats [zone]",
	Short: "Show per-server transport-usage stats for a running tdns-imr",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var f transportStatsFilter
		if len(args) == 1 {
			f.zone = dns.Fqdn(args[0])
		}
		runTransportStats(f)
	},
}

// imrStatsTransportStatsSuffixCmd is the suffix-filtered counterpart, mirroring
// `dump suffix {suffix}`: it shows only zones whose name ends in {suffix}. A
// missing suffix arg means "all zones" (same as the bare command).
var imrStatsTransportStatsSuffixCmd = &cobra.Command{
	Use:   "suffix [suffix]",
	Short: "Show transport-usage stats for zones whose name ends in suffix",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var f transportStatsFilter
		if len(args) == 1 {
			f.suffix = dns.Fqdn(args[0])
		}
		runTransportStats(f)
	},
}

// runTransportStats dispatches to the in-process renderer when the live RRset
// cache is present (the imr REPL) and to the remote API renderer otherwise (the
// standalone tdns-cli binary). There is no reason for the imr to open an API
// client to talk to itself — and doing so previously KILLED the REPL:
// SendImrMgmtCmd found no self-client and the error path called
// log.Fatalf/os.Exit, terminating the process (a #297 regression).
func runTransportStats(f transportStatsFilter) {
	if Conf.Internal.RRsetCache != nil {
		renderTransportStatsLocal(f)
		return
	}
	renderTransportStatsRemote(f)
}

// renderTransportStatsLocal renders per-server transport-usage stats straight
// from the in-process RRset cache (used by the interactive imr REPL). It mirrors
// the layout of the remote path so `stats transport-stats` looks identical
// whether run inside the imr or via tdns-cli. The caller guarantees the cache
// is non-nil.
func renderTransportStatsLocal(f transportStatsFilter) {
	rc := Conf.Internal.RRsetCache
	type row struct {
		zone, server string
		srv          *cache.AuthServer
	}
	var rows []row
	for item := range rc.ServerMap.IterBuffered() {
		if !f.matches(item.Key) {
			continue
		}
		for name, server := range item.Val {
			rows = append(rows, row{zone: item.Key, server: name, srv: server})
		}
	}
	if len(rows) == 0 {
		fmt.Println(f.noneMsg())
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].zone != rows[j].zone {
			return rows[i].zone < rows[j].zone
		}
		return rows[i].server < rows[j].server
	})
	var lastZone string
	for _, r := range rows {
		if r.zone != lastZone {
			fmt.Printf("\nZone: %s\n", r.zone)
			lastZone = r.zone
		}
		fmt.Printf("  Server: %s\n", r.server)
		fmt.Printf("    signal: %s\n", renderSignal(r.srv))
		fmt.Printf("    %s\n", formatTransportCounters(r.srv))
	}
}

// renderTransportStatsRemote fetches per-server transport-usage stats from a
// running tdns-imr over the /imr API and renders the full matrix using the SAME
// formatter as the local/interactive path, so the two cannot drift. Used only
// by the standalone tdns-cli binary (no in-process cache); log.Fatalf/os.Exit
// on error is acceptable here because that is a short-lived one-shot process.
func renderTransportStatsRemote(f transportStatsFilter) {
	amr, err := SendImrMgmtCmd("imr", &tdns.ImrMgmtPost{
		Command: "imr-transport-stats",
		Data:    f.data(),
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if amr.Error {
		fmt.Fprintf(os.Stderr, "Error: %s\n", amr.ErrorMsg)
		os.Exit(1)
	}
	fmt.Println(amr.Msg)

	// resp.Data is generic JSON; re-marshal into the typed record slice.
	raw, err := json.Marshal(amr.Data)
	if err != nil {
		log.Fatalf("failed to read response: %v", err)
	}
	var records []tdns.ImrServerTransportStats
	if err := json.Unmarshal(raw, &records); err != nil {
		log.Fatalf("failed to parse response: %v", err)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Zone != records[j].Zone {
			return records[i].Zone < records[j].Zone
		}
		return records[i].Server < records[j].Server
	})
	var lastZone string
	for _, rec := range records {
		if rec.Zone != lastZone {
			fmt.Printf("\nZone: %s\n", rec.Zone)
			lastZone = rec.Zone
		}
		fmt.Printf("  Server: %s\n", rec.Server)
		fmt.Printf("    signal: %s\n", renderSignalFromWeights(weightsStringToTransport(rec.Weights)))
		fmt.Printf("    %s\n", formatTransportStats(imrServerStatsToTransportStats(rec)))
	}
}

// imrServerStatsToTransportStats converts the name-keyed API record into the
// transport-keyed cache.TransportStats the shared formatter consumes.
func imrServerStatsToTransportStats(s tdns.ImrServerTransportStats) cache.TransportStats {
	conv := func(m map[string]uint64) map[core.Transport]uint64 {
		if len(m) == 0 {
			return nil
		}
		out := make(map[core.Transport]uint64, len(m))
		for k, v := range m {
			t, err := core.StringToTransport(k)
			if err != nil {
				// Don't silently drop: an unrecognized transport name (imr newer
				// than this cli) would otherwise undercount the totals.
				fmt.Fprintf(os.Stderr, "warning: unrecognized transport %q (count %d) omitted — imr/cli version skew?\n", k, v)
				continue
			}
			out[t] = v
		}
		return out
	}
	return cache.TransportStats{
		Attempted: conv(s.Attempted),
		Used:      conv(s.Used),
		Failed:    conv(s.Failed),
		Truncated: s.Truncated,
	}
}

// weightsStringToTransport converts a name-keyed weight map (from the API) into
// a transport-keyed one for the shared signal renderer.
func weightsStringToTransport(m map[string]uint8) map[core.Transport]uint8 {
	if len(m) == 0 {
		return nil
	}
	out := make(map[core.Transport]uint8, len(m))
	for k, v := range m {
		if t, err := core.StringToTransport(k); err == nil {
			out[t] = v
		}
	}
	return out
}

func init() {
	ImrStatsCmd.AddCommand(imrStatsTransportStatsCmd)
	imrStatsTransportStatsCmd.AddCommand(imrStatsTransportStatsSuffixCmd)
}
