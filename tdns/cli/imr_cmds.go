package cli

import (
	"fmt"
	"sort"
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

		// Collect and sort items by owner name, comparing labels from right to left
		items := []tdns.Tuple[string, tdns.CachedRRset]{}
		for item := range Conf.Internal.RRsetCache.RRsets.IterBuffered() {
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool {
			return lessByReverseLabels(items[i].Val.Name, items[j].Val.Name)
		})
		for _, it := range items {
			PrintCacheItem(it, ".")
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

		// Collect and sort items by owner name (reverse label order)
		items := []tdns.Tuple[string, tdns.CachedRRset]{}
		for item := range Conf.Internal.RRsetCache.RRsets.IterBuffered() {
			if suffix == "" || strings.HasSuffix(item.Val.Name, suffix) {
				items = append(items, item)
			}
		}
		sort.Slice(items, func(i, j int) bool {
			return lessByReverseLabels(items[i].Val.Name, items[j].Val.Name)
		})
		for _, it := range items {
			PrintCacheItem(it, suffix)
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
		// Combined, sorted-by-owner (reverse labels): DS (first) then DNSKEYs
		type taView struct {
			keyid     uint16
			validated bool
			trusted   bool
			expires   string
			alg       uint8
			flags     uint16
			pub       string
		}
		type dsView struct {
			validated bool
			expires   string
			rrs       []string
			sigs      []string
		}
		type ownerView struct {
			ds     *dsView
			dnskey []taView
		}
		owners := map[string]*ownerView{}

		// DNSKEY trust anchors
		keys := tdns.DnskeyCache.Map.Keys()
		for _, k := range keys {
			val, ok := tdns.DnskeyCache.Map.Get(k)
			if !ok {
				continue
			}
			ov := owners[val.Name]
			if ov == nil {
				ov = &ownerView{}
				owners[val.Name] = ov
			}
			ov.dnskey = append(ov.dnskey, taView{
				keyid:     val.Keyid,
				validated: val.Validated,
				trusted:   val.Trusted,
				expires:   tdns.TtlPrint(val.Expiration),
				alg:       val.Dnskey.Algorithm,
				flags:     val.Dnskey.Flags,
				pub:       truncateKey(val.Dnskey.PublicKey, 15),
			})
		}
		// DS RRsets
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RRsetCache is nil")
			return
		}
		for item := range Conf.Internal.RRsetCache.RRsets.IterBuffered() {
			parts := strings.Split(item.Key, "::")
			if len(parts) != 2 {
				continue
			}
			rrtypeNum, err := strconv.Atoi(parts[1])
			if err != nil || uint16(rrtypeNum) != dns.TypeDS {
				continue
			}
			val := item.Val
			ov := owners[parts[0]]
			if ov == nil {
				ov = &ownerView{}
				owners[parts[0]] = ov
			}
			dsv := &dsView{
				validated: val.Validated,
				expires:   tdns.TtlPrint(val.Expiration),
			}
			if val.RRset != nil {
				// sort DS lines by key tag
				type dsLine struct {
					s string
					k int
				}
				var lines []dsLine
				for _, rr := range val.RRset.RRs {
					if d, ok := rr.(*dns.DS); ok {
						lines = append(lines, dsLine{s: rr.String(), k: int(d.KeyTag)})
					} else {
						lines = append(lines, dsLine{s: rr.String(), k: 0})
					}
				}
				sort.Slice(lines, func(i, j int) bool { return lines[i].k < lines[j].k || (lines[i].k == lines[j].k && lines[i].s < lines[j].s) })
				for _, ln := range lines {
					dsv.rrs = append(dsv.rrs, ln.s)
				}
				for _, s := range val.RRset.RRSIGs {
					dsv.sigs = append(dsv.sigs, s.String())
				}
			}
			ov.ds = dsv
		}

		// Sort owners by reverse-label
		var ownerKeys []string
		for o := range owners {
			ownerKeys = append(ownerKeys, o)
		}
		sort.Slice(ownerKeys, func(i, j int) bool { return lessByReverseLabels(ownerKeys[i], ownerKeys[j]) })
		if len(ownerKeys) == 0 {
			fmt.Printf("(no DS/DNSKEY data)\n")
			return
		}
		for _, owner := range ownerKeys {
			ov := owners[owner]
			// DS first
			if ov.ds != nil {
				valStr := "unvalidated"
				if ov.ds.validated {
					valStr = "validated"
				}
				// Include signer name and keyid in header if present in cached RRset
				var signerInfo string
				if Conf.Internal.RRsetCache != nil {
					if c := Conf.Internal.RRsetCache.Get(owner, dns.TypeDS); c != nil && c.RRset != nil && len(c.RRset.RRSIGs) > 0 {
						if s, ok := c.RRset.RRSIGs[0].(*dns.RRSIG); ok {
							signerInfo = fmt.Sprintf(", signer: %s keyid: %d", s.SignerName, s.KeyTag)
						}
					}
				}
				fmt.Printf("\n%s DS (%s%s, TTL: %s)\n", owner, valStr, signerInfo, ov.ds.expires)
				for _, s := range ov.ds.rrs {
					fmt.Printf("  %s\n", s)
				}
			}
			// DNSKEYs next, sorted by keyid
			if len(ov.dnskey) > 0 {
				sort.Slice(ov.dnskey, func(i, j int) bool { return ov.dnskey[i].keyid < ov.dnskey[j].keyid })
				// Try to fetch DNSKEY RRset from cache to get RRset-level validated + TTL
				var rrsetValidated bool
				var rrsetTTL string = "-"
				var signerInfo string
				if Conf.Internal.RRsetCache != nil {
					if c := Conf.Internal.RRsetCache.Get(owner, dns.TypeDNSKEY); c != nil {
						rrsetValidated = c.Validated
						rrsetTTL = tdns.TtlPrint(c.Expiration)
						if rrsetValidated && c.RRset != nil && len(c.RRset.RRSIGs) > 0 {
							if s, ok := c.RRset.RRSIGs[0].(*dns.RRSIG); ok {
								signerInfo = fmt.Sprintf(", signer: %s keyid: %d", s.SignerName, s.KeyTag)
							}
						}
					}
				}
				vStr := "unvalidated"
				if rrsetValidated {
					vStr = "validated"
				}
				fmt.Printf("\n%s DNSKEY (%s%s, TTL: %s)\n", owner, vStr, signerInfo, rrsetTTL)
				for _, v := range ov.dnskey {
					vStr := "unvalidated"
					if v.validated {
						vStr = "validated"
					}
					tStr := "untrusted"
					if v.trusted {
						tStr = "trusted"
					}
					fmt.Printf("  key %s (keyid: %d): %s, %s, alg=%d, flags=%d, TTL: %s\n",
						v.pub, v.keyid, vStr, tStr, v.alg, v.flags, v.expires)
				}
			}
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
	// Unified header format: "<owner> <TYPE> (validated|unvalidated, TTL: X)"
	valStr := "unvalidated"
	if item.Val.Validated {
		valStr = "validated"
	}
	ttlStr := tdns.TtlPrint(item.Val.Expiration)
	fmt.Printf("\n%s %s (%s, TTL: %s)\n", parts[0], rrtype, valStr, ttlStr)

	switch item.Val.Context {
	case tdns.ContextNXDOMAIN:
		// NXDOMAIN: no RRset to list
		fmt.Printf("  %s\n", tdns.CacheContextToString[item.Val.Context])
	case tdns.ContextNoErrNoAns:
		// Negative response type 0 (NOERROR/NODATA)
		fmt.Printf("  %s\n", tdns.CacheContextToString[item.Val.Context])
	case tdns.ContextAnswer, tdns.ContextGlue, tdns.ContextHint, tdns.ContextPriming, tdns.ContextReferral:
		// Print each RR in the RRset (no RRSIGs filtering unless requested)
		for _, rr := range item.Val.RRset.RRs {
			fmt.Printf("  %s\n", rr.String())
		}
		for _, rr := range item.Val.RRset.RRSIGs {
			fmt.Printf("  %s\n", rr.String())
		}
	default:
		fmt.Printf("  Context: %q", tdns.CacheContextToString[item.Val.Context])
	}
}

// lessByReverseLabels compares two FQDNs by labels from right to left.
// Returns true if a < b in that ordering.
func lessByReverseLabels(a, b string) bool {
	an := dns.Fqdn(strings.ToLower(strings.TrimSpace(a)))
	bn := dns.Fqdn(strings.ToLower(strings.TrimSpace(b)))
	// Fast path equal
	if an == bn {
		return false
	}
	al := dns.SplitDomainName(an)
	bl := dns.SplitDomainName(bn)
	// Compare from the rightmost label (closest to root)
	for ai, bi := len(al)-1, len(bl)-1; ai >= 0 && bi >= 0; ai, bi = ai-1, bi-1 {
		if al[ai] == bl[bi] {
			continue
		}
		return al[ai] < bl[bi]
	}
	// All compared equal up to the shorter; shorter one sorts first
	return len(al) < len(bl)
}

// truncateKey returns the first n characters of k (if longer) followed by "..."
// If k is shorter than n, returns k as-is.
func truncateKey(k string, n int) string {
	k = strings.TrimSpace(k)
	if n <= 0 {
		return ""
	}
	if len(k) <= n {
		return k
	}
	return k[:n] + "..."
}
