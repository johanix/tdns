package cli

import (
	"fmt"
	"log"
	"sort"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// ImrSetCmd is defined in imr_cmds.go, we just add subcommands here

var imrSetServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Set server parameters",
}

var (
	setServerName   string
	setTransportSig string
	setReset        bool
)

var imrSetServerTransportCmd = &cobra.Command{
	Use:   "transport",
	Short: "Override transport signal for a server (debug)",
	Long: `Manually override the transport signal for an authoritative server.
This is a debug command useful for testing different transport distributions.

Examples:
  # Force 100% DoT
  imr set server transport --server ns1.example.com. --signal "dot:100"
  
  # Test mixed distribution
  imr set server transport --server ns1.example.com. --signal "doq:20,dot:100,do53:3"
  
  # Reset to original signal
  imr set server transport --server ns1.example.com. --reset`,
	Run: func(cmd *cobra.Command, args []string) {
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("Error: RRsetCache is nil")
			return
		}

		if setServerName == "" {
			fmt.Println("Error: --server is required")
			return
		}

		// Ensure server name is FQDN (has trailing dot)
		setServerName = dns.Fqdn(setServerName)

		// Find the server in the global AuthServerMap
		server := Conf.Internal.RRsetCache.GetOrCreateAuthServer(setServerName)
		if server == nil {
			fmt.Printf("Error: Unable to get server %s\n", setServerName)
			return
		}

		// Check if server actually exists (has been seen before)
		if len(server.GetAddrs()) == 0 && server.GetSrc() == "unknown" {
			fmt.Printf("Error: Server %s not found in cache (never seen)\n", setServerName)
			return
		}

		if setReset {
			// Reset to defaults - clear all weights
			server.SetTransportWeights(nil) // Clear by setting to nil
			server.SetTransports([]core.Transport{core.TransportDo53})
			server.SetAlpn([]string{"do53"})
			fmt.Printf("Transport signal reset for server %s\n", setServerName)
			fmt.Printf("  Transports: [do53:100]\n")
			fmt.Printf("  Connection mode: %s\n", server.ConnectionMode().String())
			return
		}

		if setTransportSig == "" {
			fmt.Println("Error: --signal is required (or use --reset)")
			return
		}

		// Parse the transport signal
		kvMap, err := core.ParseTransportString(setTransportSig)
		if err != nil {
			fmt.Printf("Error: Invalid transport string %q: %v\n", setTransportSig, err)
			return
		}

		// Build sorted transport list by weight (descending)
		type pair struct {
			k string
			w uint8
		}
		var pairs []pair
		weights := map[core.Transport]uint8{}
		for k, v := range kvMap {
			t, err := core.StringToTransport(k)
			if err != nil {
				log.Printf("Warning: Unknown transport %q, skipping", k)
				continue
			}
			pairs = append(pairs, pair{k: k, w: v})
			weights[t] = v
		}

		sort.SliceStable(pairs, func(i, j int) bool {
			return pairs[i].w > pairs[j].w || (pairs[i].w == pairs[j].w && pairs[i].k < pairs[j].k)
		})

		var transports []core.Transport
		var alpnOrder []string
		for _, p := range pairs {
			t, err := core.StringToTransport(p.k)
			if err != nil {
				continue
			}
			transports = append(transports, t)
			alpnOrder = append(alpnOrder, p.k)
		}

		// Apply to server (complete replacement, not merge)
		server.SetTransports(transports)
		if len(transports) > 0 {
			server.SetPrefTransport(transports[0])
		}
		server.SetAlpn(alpnOrder)
		server.SetTransportWeights(weights) // Use SetTransportWeights to replace, not merge
		server.PromoteConnMode(cache.ConnModeOpportunistic)

		// Display result
		fmt.Printf("Transport signal set for server %s\n", setServerName)
		fmt.Printf("  Signal: %s\n", setTransportSig)
		fmt.Printf("  Transports: %s\n", formatTransportWeights(server))
		fmt.Printf("  Connection mode: %s\n", server.ConnectionMode().String())
		fmt.Printf("\nNote: This is a runtime override. It will be lost on IMR restart.\n")
	},
}

func init() {
	ImrSetCmd.AddCommand(imrSetServerCmd)
	imrSetServerCmd.AddCommand(imrSetServerTransportCmd)

	imrSetServerTransportCmd.Flags().StringVarP(&setServerName, "server", "s", "", "Server name (e.g., ns1.example.com.)")
	imrSetServerTransportCmd.Flags().StringVarP(&setTransportSig, "signal", "t", "", "Transport signal (e.g., \"doq:20,dot:100,do53:3\")")
	imrSetServerTransportCmd.Flags().BoolVarP(&setReset, "reset", "r", false, "Reset to default (do53 only)")
	imrSetServerTransportCmd.MarkFlagRequired("server")
}
