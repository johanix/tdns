package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var Conf tdns.Config

// Query command - takes name and type
var ImrQueryCmd = &cobra.Command{
	Use:   "query [name] [type]",
	Short: "Query DNS records",
	Long:  `Query DNS records for a given name and type`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Querying %s for %s records\n", args[0], args[1])

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
			if r.RRset != nil {
				// fmt.Printf("%v\n", r.RRset)
				// Determine validation status from cache for the queried <qname,qtype>
				isValidated := false
				if Conf.Internal.RRsetCache != nil {
					if c := Conf.Internal.RRsetCache.Get(qname, qtype); c != nil && c.Validated {
						isValidated = true
					}
				}
				suffix := ""
				if isValidated {
					suffix = " (validated)"
				}
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

var ImrDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "List records in the RRsetCache",
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Listing records in the RRsetCache\n")
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RRsetCache is nil")
			return
		}

		// Get all keys from the concurrent map
		for item := range Conf.Internal.RRsetCache.RRsets.IterBuffered() {
			PrintCacheItem(item, ".")
		}
	},
}

var dumpSuffixCmd = &cobra.Command{
	Use:   "suffix",
	Short: "Dump records with owner names ending in suffix from the RRsetCache",
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RRsetCache is nil")
			return
		}
		var suffix string

		if len(args) == 1 {
			suffix = dns.Fqdn(args[0])
		}
		fmt.Printf("Listing records in the RRsetCache with owner names ending in %q\n", suffix)

		// Get all keys from the concurrent map
		for item := range Conf.Internal.RRsetCache.RRsets.IterBuffered() {
			PrintCacheItem(item, suffix)
		}
	},
}

var dumpServersCmd = &cobra.Command{
	Use:   "servers",
	Short: "List servers in the RecursorCache",
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Listing servers in the RecursorCache\n")
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RecursorCache is nil")
			return
		}

		// Get all keys from the concurrent map
		for item := range Conf.Internal.RRsetCache.Servers.IterBuffered() {
			fmt.Printf("\nZone: %s\n", item.Key)
			fmt.Printf("Servers: %v\n", item.Val)
		}
	},
}

var dumpAuthServersCmd = &cobra.Command{
	Use:   "auth-servers",
	Short: "List auth servers in the RecursorCache",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Listing auth servers in the RecursorCache\n")
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RecursorCache is nil")
			return
		}

		// Get all keys from the concurrent map
		for item := range Conf.Internal.RRsetCache.ServerMap.IterBuffered() {
			fmt.Printf("\nZone: %s\n", item.Key)
			for _, server := range item.Val {
				fmt.Printf("Server: %q (%s)\tAddrs: %v\tAlpn: %v \tPrefTransport: %q\n",
					server.Name, server.Src, server.Addrs, server.Alpn, tdns.TransportToString[server.PrefTransport])
			}
		}
	},
}

var dumpKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "List keys in the RecursorCache",
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Listing keys in the RecursorCache\n")
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RecursorCache is nil")
			return
		}

		// Get all keys from the concurrent map
		fmt.Printf("%v\n", Conf.Internal.RRsetCache.RRsets.Keys())
	},
}

// dumpDnskeysCmd dumps DNSKEYs (from DnskeyCache) and DS RRsets (from RRsetCache) with validation status
var dumpDnskeysCmd = &cobra.Command{
	Use:   "dnskeys",
	Short: "Dump DNSKEY trust anchors and cached DS RRsets with validation status",
	Run: func(cmd *cobra.Command, args []string) {
		// DNSKEYs from DnskeyCache
		fmt.Printf("DNSKEY trust anchors in cache:\n")
		keys := tdns.DnskeyCache.Map.Keys()
		if len(keys) == 0 {
			fmt.Printf("  (none)\n")
		}
		// Group by owner for readability
		type taView struct {
			keyid     uint16
			validated bool
			trusted   bool
			expires   string
			alg       uint8
			flags     uint16
		}
		byOwner := map[string][]taView{}
		for _, k := range keys {
			val, ok := tdns.DnskeyCache.Map.Get(k)
			if !ok {
				continue
			}
			byOwner[val.Name] = append(byOwner[val.Name], taView{
				keyid:     val.Keyid,
				validated: val.Validated,
				trusted:   val.Trusted,
				expires:   tdns.TtlPrint(val.Expiration),
				alg:       val.Dnskey.Algorithm,
				flags:     val.Dnskey.Flags,
			})
		}
		for owner, arr := range byOwner {
			fmt.Printf("\nOwner: %s (DNSKEY)\n", owner)
			for _, v := range arr {
				vStr := "unvalidated"
				if v.validated {
					vStr = "validated"
				}
				tStr := "untrusted"
				if v.trusted {
					tStr = "trusted"
				}
				fmt.Printf("  keyid %d: %s, %s, alg=%d, flags=%d, TTL: %s\n",
					v.keyid, vStr, tStr, v.alg, v.flags, v.expires)
			}
		}

		// DS RRsets from RRsetCache
		fmt.Printf("\nDS RRsets in cache:\n")
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RRsetCache is nil")
			return
		}
		var foundDS bool
		for item := range Conf.Internal.RRsetCache.RRsets.IterBuffered() {
			parts := strings.Split(item.Key, "::")
			if len(parts) != 2 {
				continue
			}
			rrtypeNum, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			if uint16(rrtypeNum) != dns.TypeDS {
				continue
			}
			foundDS = true
			val := item.Val
			valStr := "unvalidated"
			if val.Validated {
				valStr = "validated"
			}
			fmt.Printf("\nOwner: %s RRtype: DS (%s, TTL: %s)\n", parts[0], valStr, tdns.TtlPrint(val.Expiration))
			if val.RRset != nil {
				for _, rr := range val.RRset.RRs {
					fmt.Printf("  %s\n", rr.String())
				}
				// for _, s := range val.RRset.RRSIGs {
				// 	fmt.Printf("  %s\n", s.String())
				// }
			}
		}
		if !foundDS {
			fmt.Printf("  (none)\n")
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
				order := []tdns.Transport{tdns.TransportDo53, tdns.TransportDoT, tdns.TransportDoH, tdns.TransportDoQ}
				for _, t := range order {
					if c, ok := counters[t]; ok && c > 0 {
						fmt.Printf("  %-4s: %d\n", tdns.TransportToString[t], c)
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
				order := []tdns.Transport{tdns.TransportDo53, tdns.TransportDoT, tdns.TransportDoH, tdns.TransportDoQ}
				for _, t := range order {
					if c, ok := counters[t]; ok && c > 0 {
						fmt.Printf("    %-4s: %d\n", tdns.TransportToString[t], c)
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

// renderSignal formats the received transport percentage signal. If none, returns "do53=100".
func renderSignal(server *tdns.AuthServer) string {
	// Prefer showing only the received signal (SVCB pct). If absent, fallback to do53=100.
	// Order by known transports for stable output.
	order := []tdns.Transport{tdns.TransportDoQ, tdns.TransportDoT, tdns.TransportDoH, tdns.TransportDo53}
	weights := server.TransportWeights
	if len(weights) == 0 {
		return "do53=100"
	}
	var parts []string
	for _, t := range order {
		if w, ok := weights[t]; ok && w > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", tdns.TransportToString[t], int(w)))
		}
	}
	if len(parts) == 0 {
		return "do53=100"
	}
	return strings.Join(parts, ",")
}

// Compare command - takes two files
var XXXcompareCmd = &cobra.Command{
	Use:   "compare [file1] [file2]",
	Short: "Compare zone files",
	Long:  `Compare two zone files and show differences`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Comparing %s with %s\n", args[0], args[1])
	},
}

func init() {
	// rootCmd.AddCommand(ImrDumpCmd)
	ImrDumpCmd.AddCommand(dumpSuffixCmd, dumpServersCmd, dumpAuthServersCmd, dumpKeysCmd, dumpDnskeysCmd)
	dumpAuthServersCmd.AddCommand(dumpKeysCmd, dumpServersCmd)

	ImrZoneCmd.AddCommand(imrZoneListCmd, imrZoneCheckCmd)

	// rootCmd.AddCommand(ImrQueryCmd)

	// rootCmd.AddCommand(statsCmd)
	// rootCmd.AddCommand(imrServerCmd)

	ImrQueryCmd.Annotations = map[string]string{
		"arg1_guide": "(domain name)",
		"arg2_guide": "(record type)",
	}

	imrZoneListCmd.Annotations = map[string]string{
		"guide": "(zone or car)",
	}

	ImrStatsCmd.AddCommand(imrStatsAuthTransportsCmd)
	ImrStatsCmd.AddCommand(imrStatsAuthServersCmd)
}

func PrintCacheItem(item tdns.Tuple[string, tdns.CachedRRset], suffix string) {

	parts := strings.Split(item.Key, "::")
	if len(parts) != 2 {
		fmt.Printf("Invalid cache key format: %s (expected format: name::rrtype)\n", item.Key)
		return
	}
	tmp, err := strconv.Atoi(parts[1])
	if err != nil {
		fmt.Printf("ATOI error for %q: %v", parts[1], err)
		return
	}

	if !strings.HasSuffix(item.Val.Name, suffix) {
		// fmt.Printf("skipping item with name %q\n", item.Val.Name)
		return
	}

	// Evict expired entries on-the-fly to keep dump output consistent with effective cache state
	if !item.Val.Expiration.IsZero() && item.Val.Expiration.Before(time.Now()) {
		if Conf.Internal.RRsetCache != nil {
			Conf.Internal.RRsetCache.RRsets.Remove(item.Key)
			// If the expired RRset is NS, also remove its ServerMap entry, mirroring Get()
			if uint16(tmp) == dns.TypeNS {
				Conf.Internal.RRsetCache.ServerMap.Remove(parts[0])
			}
		}
		return
	}

	rrtype := dns.TypeToString[uint16(tmp)]
	fmt.Printf("\nOwner: %s RRtype: %s\n", parts[0], rrtype)

	switch item.Val.Context {
	case tdns.ContextNXDOMAIN:
		fmt.Printf("NXDOMAIN (negative response type 3)\n")
		fmt.Printf("%s %s (%s, TTL: %s)\n", item.Val.Name,
			dns.TypeToString[uint16(item.Val.RRtype)], tdns.CacheContextToString[item.Val.Context], tdns.TtlPrint(item.Val.Expiration))
	case tdns.ContextNoErrNoAns:
		// fmt.Printf("negative response type 0\n")
		fmt.Printf("%s %s (%s, TTL: %s)\n", item.Val.Name,
			dns.TypeToString[uint16(item.Val.RRtype)], tdns.CacheContextToString[item.Val.Context], tdns.TtlPrint(item.Val.Expiration))
	case tdns.ContextAnswer, tdns.ContextGlue, tdns.ContextHint, tdns.ContextPriming, tdns.ContextReferral:
		// Print each RR in the RRset
		valStr := "unvalidated"
		if item.Val.Validated {
			valStr = "validated"
		}
		for _, rr := range item.Val.RRset.RRs {
			ttlStr := tdns.TtlPrint(item.Val.Expiration)
			fmt.Printf("%v (%s, %s, TTL: %s)\n", rr,
				tdns.CacheContextToString[item.Val.Context], valStr, ttlStr)
		}
		for _, rr := range item.Val.RRset.RRSIGs {
			fmt.Printf("%v\n", rr)
		}
	default:
		fmt.Printf("Context: %q (which we don't know what to do with)",
			tdns.CacheContextToString[item.Val.Context])
	}
}
