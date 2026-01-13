package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v0.x"
	cache "github.com/johanix/tdns/v0.x/cache"
	core "github.com/johanix/tdns/v0.x/core"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var Conf tdns.Config

// ImrCmd is the parent command for all IMR-related commands
var ImrCmd = &cobra.Command{
	Use:   "imr",
	Short: "Interact with tdns-imr via API",
}

// Query command - takes name and type
var ImrQueryCmd = &cobra.Command{
	Use:   "query [name] [type]",
	Short: "Query DNS records",
	Long:  `Query DNS records for a given name and type`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 {
			fmt.Println("Error: both name and type are required.")
			_ = cmd.Usage()
			return
		}
		fmt.Printf("Querying %s for %s records (verbose mode: %t)\n", args[0], args[1], tdns.Globals.Verbose)

		qname := dns.Fqdn(args[0])
		if _, ok := dns.IsDomainName(qname); !ok {
			fmt.Printf("Not a valid domain name: '%s'\n", qname)
			return
		}

		qtype, exist := dns.StringToType[strings.ToUpper(args[1])]
		if !exist {
			fmt.Printf("Not a valid DNS RR type: '%s'\n", args[1])
			return
		}

		if Conf.Internal.RecursorCh == nil {
			fmt.Printf("No active channel to RecursorEngine. Terminating.\n")
			return
		}

		resp := make(chan tdns.ImrResponse, 1)
		Conf.Internal.RecursorCh <- tdns.ImrRequest{
			Qname:      qname,
			Qclass:     dns.ClassINET,
			Qtype:      qtype,
			ResponseCh: resp,
		}

		select {
		case r := <-resp:
			// Check cache entry to determine if this is a negative response
			var cached *cache.CachedRRset
			if Conf.Internal.RRsetCache != nil {
				cached = Conf.Internal.RRsetCache.Get(qname, qtype)
			}

			if cached != nil && (cached.Context == cache.ContextNXDOMAIN || cached.Context == cache.ContextNoErrNoAns) {
				// This is a negative response
				vstate := cached.State
				stateStr := cache.ValidationStateToString[vstate]
				ctxStr := cache.CacheContextToString[cached.Context]

				fmt.Printf("%s %s (state: %s)\n", qname, ctxStr, stateStr)

				// Print negative authority proof if present (only in verbose mode)
				// Check the global verbose flag set by the root command's PersistentFlags
				if tdns.Globals.Verbose {
					// For indeterminate zones, proof cannot be validated, so don't show it
					if vstate == cache.ValidationStateIndeterminate {
						fmt.Printf("Proof: not possible for zone in state=indeterminate\n")
					} else if len(cached.NegAuthority) > 0 {
						fmt.Printf("Proof:\n")
						for _, negRRset := range cached.NegAuthority {
							if negRRset != nil {
								for _, rr := range negRRset.RRs {
									fmt.Printf("  %s\n", rr.String())
								}
								for _, rr := range negRRset.RRSIGs {
									fmt.Printf("  %s\n", rr.String())
								}
							}
						}
					} else if cached.RRset != nil {
						// Fallback: print SOA if present
						for _, rr := range cached.RRset.RRs {
							if rr.Header().Rrtype == dns.TypeSOA {
								fmt.Printf("  %s\n", rr.String())
							}
						}
					}
				} else {
					fmt.Printf("Proof only presented in verbose mode\n")
				}
			} else if r.RRset != nil {
				// Positive response
				vstate := cache.ValidationStateNone
				if cached != nil {
					vstate = cached.State
				}
				suffix := fmt.Sprintf(" (state: %s)", cache.ValidationStateToString[vstate])

				for _, rr := range r.RRset.RRs {
					switch rr.Header().Rrtype {
					case qtype, dns.TypeCNAME:
						fmt.Printf("%s%s\n", rr.String(), suffix)
					default:
						fmt.Printf("Not printing: %q\n", rr.String())
					}
				}
				for _, rr := range r.RRset.RRSIGs {
					fmt.Printf("%s\n", rr.String())
				}
			} else if r.Error {
				fmt.Printf("Error: %s\n", r.ErrorMsg)
			} else {
				fmt.Printf("No records found: %s\n", r.Msg)
			}
		case <-time.After(3 * time.Second):
			fmt.Println("Timeout waiting for response")
			return
		}
	},
}

// Zone command - takes zone name
var ImrZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "prefix command for zone operations",
	Long:  `prefix command for zone operations`,
}

// List command - takes zone name
var imrZoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "List records in zone",
	Long:  `List all records in a DNS zone`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Error: no zone file argument")
			return
		}
		fmt.Printf("Listing records for zone: %s\n", args[0])
	},
}

// Server command - takes address and port
var imrServerCmd = &cobra.Command{
	Use:   "server [address] [port]",
	Short: "Set DNS server",
	Long:  `Set the DNS server to use for queries`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Setting server to %s:%s\n", args[0], args[1])
	},
}

// Check command - takes filename
var imrZoneCheckCmd = &cobra.Command{
	Use:   "check [filename]",
	Short: "Check zone file",
	Long:  `Check a zone file for syntax errors`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Error: no zone file argument")
		} else {
			fmt.Printf("Checking zone file: %s [NYI]\n", args[0])
		}
	},
}

// Stats command - no arguments
var ImrStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show statistics",
	Long:  `Show DNS query statistics`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Showing statistics")
	},
}

var imrStatsAuthTransportsCmd = &cobra.Command{
	Use:   "auth-transports [zone]",
	Short: "Show per-transport query counters for auth servers in a zone",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RecursorCache is nil")
			return
		}
		if len(args) == 1 {
			zone := dns.Fqdn(args[0])
			serverMap, ok := Conf.Internal.RRsetCache.ServerMap.Get(zone)
			if !ok {
				fmt.Printf("No auth servers recorded for zone %q\n", zone)
				return
			}
			fmt.Printf("Auth server transport counters for zone %s\n", zone)
			for name, server := range serverMap {
				fmt.Printf("\nServer: %s\n", name)
				// Show received transport percentage signal (pct). If none: do53=100
				fmt.Printf("  signal: %s\n", renderSignal(server))
				counters := server.SnapshotCounters()
				order := []core.Transport{core.TransportDo53, core.TransportDoT, core.TransportDoH, core.TransportDoQ}
				for _, t := range order {
					if c, ok := counters[t]; ok && c > 0 {
						fmt.Printf("  %-4s: %d\n", core.TransportToString[t], c)
					}
				}
			}
			return
		}
		// No zone provided: list all zones
		fmt.Printf("Auth server transport counters for all zones\n")
		for item := range Conf.Internal.RRsetCache.ServerMap.IterBuffered() {
			zone := item.Key
			serverMap := item.Val
			fmt.Printf("\nZone: %s\n", zone)
			for name, server := range serverMap {
				fmt.Printf("  Server: %s\n", name)
				fmt.Printf("    signal: %s\n", renderSignal(server))
				counters := server.SnapshotCounters()
				order := []core.Transport{core.TransportDo53, core.TransportDoT, core.TransportDoH, core.TransportDoQ}
				for _, t := range order {
					if c, ok := counters[t]; ok && c > 0 {
						fmt.Printf("    %-4s: %d\n", core.TransportToString[t], c)
					}
				}
			}
		}
	},
}

// Alias with requested name that prints the same information as auth-transports
var imrStatsAuthServersCmd = &cobra.Command{
	Use:   "auth-servers [zone]",
	Short: "Show per-transport query counters and signal for auth servers",
	Args:  cobra.MaximumNArgs(1),
	Run:   imrStatsAuthTransportsCmd.Run,
}

var ImrShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show IMR state",
}

var ImrFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flush cached data",
}

var imrFlushCommonCmd = &cobra.Command{
	Use:   "common [domain]",
	Short: "Flush non-structural cached RRsets for a domain",
	Args:  cobra.ExactArgs(1),
	Run:   newFlushRunner(true),
}

var imrFlushAllCmd = &cobra.Command{
	Use:   "all [domain]",
	Short: "Flush all cached RRsets for a domain and its subdomains",
	Args:  cobra.ExactArgs(1),
	Run:   newFlushRunner(false),
}

func newFlushRunner(keepStructural bool) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RRset cache is not initialized")
			return
		}
		domain := dns.Fqdn(args[0])
		trimmed := strings.TrimSuffix(domain, ".")
		if trimmed == "" {
			fmt.Println("Refusing to flush the root zone")
			return
		}
		if _, ok := dns.IsDomainName(trimmed); !ok {
			fmt.Printf("Not a valid domain name: %q\n", args[0])
			return
		}
		removed, err := Conf.Internal.RRsetCache.FlushDomain(domain, keepStructural)
		if err != nil {
			fmt.Printf("Flush failed: %v\n", err)
			return
		}
		if keepStructural {
			fmt.Printf("Removed %d non-structural cache RRsets at or below %s\n", removed, domain)
		} else {
			fmt.Printf("Removed %d cache RRsets at or below %s\n", removed, domain)
		}
	}
}

var imrShowConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Show running IMR configuration summary",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("IMR configuration summary:")

		if len(Conf.Imr.Addresses) == 0 {
			fmt.Println("  Listening addresses: (none configured)")
		} else {
			fmt.Printf("  Listening addresses: %s\n", strings.Join(Conf.Imr.Addresses, ", "))
		}

		primed := false
		if Conf.Internal.RRsetCache != nil {
			primed = Conf.Internal.RRsetCache.Primed
		}
		fmt.Printf("  Cache primed: %t\n", primed)

		dkKeys := cache.DnskeyCache.Map.Keys()
		if tdns.Globals.Debug {
			fmt.Printf("  DnskeyCache keys: %v\n", dkKeys)
		}
		if len(dkKeys) == 0 {
			fmt.Println("  Trust anchors: (none)")
		} else {
			fmt.Println("  Trust anchors:")
			sort.Strings(dkKeys)
			for _, key := range dkKeys {
				if val, ok := cache.DnskeyCache.Map.Get(key); ok {
					if val.TrustAnchor {
						fmt.Printf("    %s keyid=%d (TrustAnchor, state=%s expires=%s)\n",
							val.Name, val.Keyid, cache.ValidationStateToString[val.State], tdns.TtlPrint(val.Expiration))
					}
				}
			}
		}

		if len(Conf.Imr.Stubs) == 0 {
			fmt.Println("  Stub zones: (none)")
		} else {
			fmt.Println("  Stub zones:")
			for _, stub := range Conf.Imr.Stubs {
				var servers []string
				for _, server := range stub.Servers {
					servers = append(servers, fmt.Sprintf("%s (%s)", server.Name, strings.Join(server.Addrs, ", ")))
				}
				fmt.Printf("    %s -> %s\n", stub.Zone, strings.Join(servers, "; "))
			}
		}
	},
}

var imrShowOptionsCmd = &cobra.Command{
	Use:   "options",
	Short: "Show configured IMR options",
	Run: func(cmd *cobra.Command, args []string) {
		if len(Conf.Imr.OptionsStrs) == 0 && len(Conf.Imr.Options) == 0 {
			fmt.Println("No IMR options configured.")
			return
		}

		fmt.Println("IMR options:")
		type optionView struct {
			name  string
			value string
		}
		var rows []optionView
		normNames := make(map[string]struct{})
		for opt, val := range Conf.Imr.Options {
			name, ok := tdns.ImrOptionToString[opt]
			if !ok {
				name = fmt.Sprintf("unknown(%d)", opt)
			}
			normNames[strings.ToLower(name)] = struct{}{}
			rows = append(rows, optionView{name: name, value: val})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
		if len(rows) == 0 {
			fmt.Println("  (no normalized options)")
		} else {
			for _, row := range rows {
				switch strings.ToLower(row.value) {
				case "", "true":
					fmt.Printf("  %s\n", row.name)
				default:
					fmt.Printf("  %s = %s\n", row.name, row.value)
				}
			}
		}
		var invalid []string
		for _, raw := range Conf.Imr.OptionsStrs {
			name := raw
			if idx := strings.IndexAny(name, ":="); idx != -1 {
				name = name[:idx]
			}
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				invalid = append(invalid, raw)
				continue
			}
			if _, known := tdns.StringToImrOption[name]; !known {
				invalid = append(invalid, raw)
				continue
			}
			if _, parsed := normNames[name]; !parsed {
				invalid = append(invalid, raw)
			}
		}
		if len(invalid) > 0 {
			fmt.Println("  Invalid and ignored options:")
			for _, raw := range invalid {
				fmt.Printf("    %s\n", raw)
			}
		}
	},
}

// renderSignal formats the received transport percentage signal. If none, returns "do53=100".
func renderSignal(server *cache.AuthServer) string {
	// Prefer showing only the received signal (SVCB pct). If absent, fallback to do53=100.
	// Order by known transports for stable output.
	order := []core.Transport{core.TransportDoQ, core.TransportDoT, core.TransportDoH, core.TransportDo53}
	weights := server.TransportWeights
	if len(weights) == 0 {
		return "do53=100"
	}
	var parts []string
	for _, t := range order {
		if w, ok := weights[t]; ok && w > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", core.TransportToString[t], int(w)))
		}
	}
	if len(parts) == 0 {
		return "do53=100"
	}
	return strings.Join(parts, ",")
}

var ImrSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set IMR runtime parameters",
}

var imrSetLineWidthCmd = &cobra.Command{
	Use:   "linewidth [num]",
	Short: "Set line width for debug output",
	Long:  `Set the line width used to truncate long lines in logging and output (e.g., DNSKEYs and RRSIGs)`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		width, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Printf("Error: %q is not a valid number: %v\n", args[0], err)
			return
		}
		if width < 1 {
			fmt.Printf("Error: line width must be at least 1\n")
			return
		}
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("Error: RRset cache is not initialized")
			return
		}
		if Conf.Internal.ImrEngine == nil {
			fmt.Println("Error: IMR engine is not initialized")
			return
		}
		Conf.Internal.RRsetCache.LineWidth = width
		Conf.Internal.ImrEngine.LineWidth = width
		fmt.Printf("Line width set to %d\n", width)
	},
}

func init() {
	ImrZoneCmd.AddCommand(imrZoneListCmd, imrZoneCheckCmd)
	ImrQueryCmd.Annotations = map[string]string{
		"arg1_guide": "(domain name)",
		"arg2_guide": "(record type)",
	}

	imrZoneListCmd.Annotations = map[string]string{
		"guide": "(zone or car)",
	}

	ImrStatsCmd.AddCommand(imrStatsAuthTransportsCmd)
	ImrStatsCmd.AddCommand(imrStatsAuthServersCmd)
	ImrShowCmd.AddCommand(imrShowOptionsCmd)
	ImrShowCmd.AddCommand(imrShowConfigCmd)
	ImrFlushCmd.AddCommand(imrFlushCommonCmd, imrFlushAllCmd)
	ImrSetCmd.AddCommand(imrSetLineWidthCmd)

	// Add all IMR subcommands to ImrCmd
	ImrCmd.AddCommand(ImrQueryCmd, ImrZoneCmd, ImrStatsCmd, ImrShowCmd, ImrFlushCmd, ImrSetCmd)

	// Add ping and daemon commands to ImrCmd (PingCmd and DaemonCmd are defined elsewhere)
	ImrCmd.AddCommand(PingCmd)
	ImrCmd.AddCommand(DaemonCmd)
}
