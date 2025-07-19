package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

func init() {
	// Query command - takes name and type
	queryCmd := &cobra.Command{
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

			if conf.Internal.RecursorCh == nil {
				fmt.Printf("No active channel to RecursorEngine. Terminating.\n")
				return
			}

			resp := make(chan tdns.ImrResponse, 1)
			conf.Internal.RecursorCh <- tdns.ImrRequest{
				Qname:      qname,
				Qclass:     dns.ClassINET,
				Qtype:      qtype,
				ResponseCh: resp,
			}

			select {
			case r := <-resp:
				if r.RRset != nil {
					// fmt.Printf("%v\n", r.RRset)
					for _, rr := range r.RRset.RRs {
						switch rr.Header().Rrtype {
						case qtype, dns.TypeCNAME:
							fmt.Printf("%s\n", rr.String())
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
	queryCmd.Annotations = map[string]string{
		"arg1_guide": "(domain name)",
		"arg2_guide": "(record type)",
	}
	rootCmd.AddCommand(queryCmd)

	dumpCmd := &cobra.Command{
		Use:   "dump",
		Short: "List records in the RRsetCache",
		// Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Listing records in the RRsetCache\n")
			if conf.Internal.RRsetCache == nil {
				fmt.Println("RRsetCache is nil")
				return
			}

			// Get all keys from the concurrent map
			for item := range conf.Internal.RRsetCache.RRsets.IterBuffered() {
				PrintCacheItem(item, ".")
			}
		},
	}

	dumpSuffixCmd := &cobra.Command{
		Use:   "dump-only-suffix",
		Short: "Dump records with owner names ending in suffix from the RRsetCache",
		// Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if conf.Internal.RRsetCache == nil {
				fmt.Println("RRsetCache is nil")
				return
			}
			var suffix string

			if len(args) == 1 {
				suffix = dns.Fqdn(args[0])
			}
			fmt.Printf("Listing records in the RRsetCache with owner names ending in %q\n", suffix)

			// Get all keys from the concurrent map
			for item := range conf.Internal.RRsetCache.RRsets.IterBuffered() {
				PrintCacheItem(item, suffix)
			}
		},
	}

	dumpServersCmd := &cobra.Command{
		Use:   "servers",
		Short: "List servers in the RecursorCache",
		// Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Listing servers in the RecursorCache\n")
			if conf.Internal.RRsetCache == nil {
				fmt.Println("RecursorCache is nil")
				return
			}

			// Get all keys from the concurrent map
			for item := range conf.Internal.RRsetCache.Servers.IterBuffered() {
				fmt.Printf("\nZone: %s\n", item.Key)
				fmt.Printf("Servers: %v\n", item.Val)
			}
		},
	}
	dumpAuthServersCmd := &cobra.Command{
		Use:   "auth-servers",
		Short: "List auth servers in the RecursorCache",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Listing auth servers in the RecursorCache\n")
			if conf.Internal.RRsetCache == nil {
				fmt.Println("RecursorCache is nil")
				return
			}

			// Get all keys from the concurrent map
			for item := range conf.Internal.RRsetCache.ServerMap.IterBuffered() {
				fmt.Printf("\nZone: %s\n", item.Key)
				for _, server := range item.Val {
					fmt.Printf("Server: %q (%s)\tAddrs: %v\tAlpn: %v \tPrefTransport: %q\n",
						server.Name, server.Src, server.Addrs, server.Alpn, tdns.TransportToString[server.PrefTransport])
				}
			}
		},
	}

	dumpKeysCmd := &cobra.Command{
		Use:   "keys",
		Short: "List keys in the RecursorCache",
		// Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Listing keys in the RecursorCache\n")
			if conf.Internal.RRsetCache == nil {
				fmt.Println("RecursorCache is nil")
				return
			}

			// Get all keys from the concurrent map
			fmt.Printf("%v\n", conf.Internal.RRsetCache.RRsets.Keys())
		},
	}

	rootCmd.AddCommand(dumpCmd, dumpSuffixCmd)
	dumpCmd.AddCommand(dumpServersCmd, dumpAuthServersCmd, dumpKeysCmd)
	rootCmd.AddCommand(dumpServersCmd)

	// List command - takes zone name
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List records in zone",
		Long:  `List all records in a DNS zone`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Listing records for zone: %s\n", args[0])
		},
	}
	listCmd.Annotations = map[string]string{
		"guide": "(zone or car)",
	}

	listZoneCmd := &cobra.Command{
		Use:   "zone",
		Short: "List records in zone",
		Long:  `List all records in a DNS zone`,
		// Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Listing records in zone: %s\n", args[0])
		},
	}

	listCarCmd := &cobra.Command{
		Use:   "car",
		Short: "List cars",
		Long:  `List all cars in a DNS zone`,
		// Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Listing cars in zone: %s\n", args[0])
		},
	}

	rootCmd.AddCommand(listCmd)
	listCmd.AddCommand(listZoneCmd, listCarCmd)

	// Server command - takes address and port
	serverCmd := &cobra.Command{
		Use:   "server [address] [port]",
		Short: "Set DNS server",
		Long:  `Set the DNS server to use for queries`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Setting server to %s:%s\n", args[0], args[1])
		},
	}
	rootCmd.AddCommand(serverCmd)

	// Check command - takes filename
	checkCmd := &cobra.Command{
		Use:   "check [filename]",
		Short: "Check zone file",
		Long:  `Check a zone file for syntax errors`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Checking zone file: %s\n", args[0])
		},
	}

	rootCmd.AddCommand(checkCmd)

	// Stats command - no arguments
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show statistics",
		Long:  `Show DNS query statistics`,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Showing statistics")
		},
	}
	rootCmd.AddCommand(statsCmd)

	// Compare command - takes two files
	compareCmd := &cobra.Command{
		Use:   "compare [file1] [file2]",
		Short: "Compare zone files",
		Long:  `Compare two zone files and show differences`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Comparing %s with %s\n", args[0], args[1])
		},
	}
	rootCmd.AddCommand(compareCmd)
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

	rrtype := dns.TypeToString[uint16(tmp)]
	fmt.Printf("\nOwner: %s RRtype: %s\n", parts[0], rrtype)

	switch item.Val.Context {
	case tdns.ContextNXDOMAIN:
		fmt.Printf("NXDOMAIN (negative response type 3)\n")
	case tdns.ContextNoErrNoAns:
		fmt.Printf("negative response type 0\n")
	case tdns.ContextAnswer, tdns.ContextGlue, tdns.ContextHint, tdns.ContextPriming, tdns.ContextReferral:
		// Print each RR in the RRset
		for _, rr := range item.Val.RRset.RRs {
			fmt.Printf("%v (%s)\n", rr, tdns.CacheContextToString[item.Val.Context])
		}
		for _, rr := range item.Val.RRset.RRSIGs {
			fmt.Printf("%v\n", rr)
		}
	default:
		fmt.Printf("Context: %q (which we don't know what to do with)",
			tdns.CacheContextToString[item.Val.Context])
	}
}
