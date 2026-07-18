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
	Short: "Show per-server transport-usage stats from a running tdns-imr (via API)",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		data := map[string]interface{}{}
		if len(args) == 1 {
			data["zone"] = dns.Fqdn(args[0])
		}
		amr, err := SendImrMgmtCmd("imr", &tdns.AgentMgmtPost{
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
			if rec.Signal != "" {
				fmt.Printf("    signal: %s\n", rec.Signal)
			}
			fmt.Printf("    %s\n", formatTransportStats(imrServerStatsToTransportStats(rec)))
		}
	},
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
			if t, err := core.StringToTransport(k); err == nil {
				out[t] = v
			}
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

func init() {
	ImrStatsCmd.AddCommand(imrStatsTransportStatsCmd)
}
