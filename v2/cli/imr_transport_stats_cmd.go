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

// imrStatsTransportStatsCmd is the REMOTE counterpart of the in-process
// auth-transports view: it fetches per-server transport-usage stats from a
// running tdns-imr over the /imr API and renders the full matrix (attempted /
// used / failed incl. do53-tcp, plus TC=1 truncations) using the SAME formatter
// as the interactive dump, so the two cannot drift.
var imrStatsTransportStatsCmd = &cobra.Command{
	Use:   "transport-stats [zone]",
	Short: "Show per-server transport-usage stats for a running tdns-imr",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// When invoked inside the imr itself (the `tdns-imr --cli` interactive
		// REPL) the live RRset cache is present in this process, so render the
		// stats directly from it. There is no reason for the imr to open an API
		// client to talk to itself — and doing so previously KILLED the REPL:
		// SendImrMgmtCmd found no self-client and the error path called
		// log.Fatalf/os.Exit, terminating the process (a #297 regression).
		// Only the standalone tdns-cli binary (which has no local cache) uses
		// the remote API path.
		if Conf.Internal.RRsetCache != nil {
			renderTransportStatsLocal(args)
			return
		}
		renderTransportStatsRemote(args)
	},
}

// renderTransportStatsLocal renders per-server transport-usage stats straight
// from the in-process RRset cache (used by the interactive imr REPL). It mirrors
// the layout of the remote path so `stats transport-stats` looks identical
// whether run inside the imr or via tdns-cli. The caller guarantees the cache
// is non-nil.
func renderTransportStatsLocal(args []string) {
	rc := Conf.Internal.RRsetCache
	var zoneFilter string
	if len(args) == 1 {
		zoneFilter = dns.Fqdn(args[0])
	}
	type row struct {
		zone, server string
		srv          *cache.AuthServer
	}
	var rows []row
	for item := range rc.ServerMap.IterBuffered() {
		if zoneFilter != "" && item.Key != zoneFilter {
			continue
		}
		for name, server := range item.Val {
			rows = append(rows, row{zone: item.Key, server: name, srv: server})
		}
	}
	if len(rows) == 0 {
		if zoneFilter != "" {
			fmt.Printf("No auth servers recorded for %s\n", zoneFilter)
		} else {
			fmt.Println("No auth servers recorded")
		}
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
func renderTransportStatsRemote(args []string) {
	data := map[string]interface{}{}
	if len(args) == 1 {
		data["zone"] = dns.Fqdn(args[0])
	}
	amr, err := SendImrMgmtCmd("imr", &tdns.ImrMgmtPost{
		Command: "imr-transport-stats",
		Data:    data,
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
}
