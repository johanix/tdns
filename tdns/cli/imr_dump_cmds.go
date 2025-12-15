package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/tdns"
	cache "github.com/johanix/tdns/tdns/cache"
	core "github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"zgo.at/acidtab"
)

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
		items := []core.Tuple[string, cache.CachedRRset]{}
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
		items := []core.Tuple[string, cache.CachedRRset]{}
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

var dumpServersCmd = newDumpServersCmd()

func newDumpServersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "servers",
		Short: "List servers in the RecursorCache",
		Run:   runDumpServers,
	}
}

func runDumpServers(cmd *cobra.Command, args []string) {
	fmt.Printf("Listing servers in the RecursorCache\n")
	if Conf.Internal.RRsetCache == nil {
		fmt.Println("RecursorCache is nil")
		return
	}

	for item := range Conf.Internal.RRsetCache.Servers.IterBuffered() {
		fmt.Printf("\nZone: %s\n", item.Key)
		fmt.Printf("Servers: %v\n", item.Val)
	}
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
			lines := []string{"Server | Source | Addresses | Transports | Connection"}
			var names []string
			for name := range item.Val {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				server := item.Val[name]
				addrs := formatList(server.Addrs)
				src := server.Src
				if src == "" {
					src = "-"
				}
				transports := formatTransportWeights(server)
				conn := server.ConnectionMode().String()
				lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s", name, src, addrs, transports, conn))
				if tdns.Globals.Verbose {
					fmt.Printf("  Server: %s\n", name)
					fmt.Printf("    Source: %s\n", src)
					fmt.Printf("    Addresses: %s\n", addrs)
					fmt.Printf("    ALPN: %s\n", formatList(server.Alpn))
					fmt.Printf("    Transports: %s\n", transports)
					fmt.Printf("    Connection mode: %s\n", conn)
					if len(server.TransportSignal) > 0 {
						fmt.Printf("    Transport signal (raw): %s\n", server.TransportSignal)
					}
					if tlsaSnapshot := server.SnapshotTLSARecords(); len(tlsaSnapshot) > 0 {
						fmt.Printf("    TLSA records:\n")
						var owners []string
						for owner := range tlsaSnapshot {
							owners = append(owners, owner)
						}
						sort.Strings(owners)
						for _, owner := range owners {
							rec := tlsaSnapshot[owner]
							if rec == nil {
								fmt.Printf("      %s (no TLSA record)\n", owner)
								continue
							}
							stateStr := validationStateString(rec.State)
							fmt.Printf("      %s (state: %s)\n", owner, stateStr)
							if rec.RRset != nil {
								for _, rr := range rec.RRset.RRs {
									fmt.Printf("        %s\n", rr.String())
								}
							}
						}
					}
				}
			}
			fmt.Println(columnize.SimpleFormat(lines))
		}
	},
}

var dumpAuthServersErrorsCmd = &cobra.Command{
	Use:   "errors",
	Short: "List auth servers with connection issues (addresses in backoff)",
	Run: func(cmd *cobra.Command, args []string) {
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RRsetCache is nil")
			return
		}

		now := time.Now()
		hasErrors := false
		var lines []string

		// Traverse AuthServerMap to find servers with backoff issues
		for item := range Conf.Internal.RRsetCache.AuthServerMap.IterBuffered() {
			nsname := item.Key
			server := item.Val

			// Get snapshot of addresses in backoff (thread-safe)
			backoffs := server.SnapshotAddressBackoffs(now)
			if backoffs != nil && len(backoffs) > 0 {
				hasErrors = true
				// Sort addresses for consistent output
				addrs := make([]string, 0, len(backoffs))
				for addr := range backoffs {
					addrs = append(addrs, addr)
				}
				sort.Strings(addrs)

				// Collect information for addresses in backoff
				for _, addr := range addrs {
					backoff := backoffs[addr]
					timeUntilRetry := backoff.NextTry.Sub(now)
					// Always include all 5 columns for alignment
					failures := "0"
					if backoff.FailureCount > 0 {
						failures = fmt.Sprintf("%d", backoff.FailureCount)
					}
					errorMsg := "-"
					if backoff.LastError != "" {
						errorMsg = backoff.LastError
					}
					line := fmt.Sprintf("%s | %s | retry in %s | %s | %s", nsname, addr, formatDuration(timeUntilRetry), failures, errorMsg)
					lines = append(lines, line)
				}
			}
		}

		if !hasErrors {
			fmt.Println("No auth servers with connection issues found.")
			return
		}

		// Print header and results
		fmt.Println("Nameserver | Address | Backoff Time | Failures | Error")
		fmt.Println(strings.Repeat("-", 80))
		for _, line := range lines {
			fmt.Println(line)
		}
	},
}

var dumpZonesCmd = &cobra.Command{
	Use:   "zones",
	Short: "List all zones in the ZoneMap with their secure delegation status",
	Run: func(cmd *cobra.Command, args []string) {
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RRsetCache is nil")
			return
		}

		// Collect all zones from ZoneMap
		zones := []core.Tuple[string, *cache.Zone]{}
		for item := range Conf.Internal.RRsetCache.ZoneMap.IterBuffered() {
			zones = append(zones, item)
		}

		// Sort zones by name (reverse label order)
		sort.Slice(zones, func(i, j int) bool {
			return lessByReverseLabels(zones[i].Key, zones[j].Key)
		})

		// Use acidtab for right-aligned zone names
		t := acidtab.New("Zone", "Status")
		t.AlignCol(0, acidtab.Right)
		t.AlignCol(1, acidtab.Right)
		for _, item := range zones {
			zone := item.Val
			secureStatus := cache.ValidationStateToString[zone.GetState()]
			if secureStatus == "" {
				secureStatus = "[unknown]"
			}
			t.Row(item.Key, secureStatus)
		}
		fmt.Println(t.String())
	},
}

var dumpZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Zone-specific dumps",
}

var dumpZoneServersCmd = &cobra.Command{
	Use:   "servers [zone]",
	Short: "List auth servers for a specific zone (verbose)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Error: zone name is required.")
			_ = cmd.Usage()
			return
		}
		zone := dns.Fqdn(args[0])
		if Conf.Internal.RRsetCache == nil {
			fmt.Println("RecursorCache is nil")
			return
		}
		serverMap, ok := Conf.Internal.RRsetCache.ServerMap.Get(zone)
		if !ok || len(serverMap) == 0 {
			fmt.Printf("No auth servers known for zone %s\n", zone)
			return
		}
		names := make([]string, 0, len(serverMap))
		for name := range serverMap {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			server := serverMap[name]
			printAuthServerVerbose(name, server)
		}
	},
}

var dumpKeysCmd = newDumpKeysCmd()

func newDumpKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keys",
		Short: "List keys in the RecursorCache",
		Run:   runDumpKeys,
	}
}

func runDumpKeys(cmd *cobra.Command, args []string) {
	fmt.Printf("Listing keys in the RecursorCache\n")
	if Conf.Internal.RRsetCache == nil {
		fmt.Println("RecursorCache is nil")
		return
	}

	fmt.Printf("%v\n", Conf.Internal.RRsetCache.RRsets.Keys())
}

// dumpDnskeysCmd dumps DNSKEYs (from DnskeyCache) and DS RRsets (from RRsetCache) with validation status
var dumpDnskeysCmd = &cobra.Command{
	Use:   "dnskeys",
	Short: "Dump DNSKEY trust anchors and cached DS RRsets with validation status",
	Run: func(cmd *cobra.Command, args []string) {
		// Combined, sorted-by-owner (reverse labels): DS (first) then DNSKEYs
		type dnskeyView struct {
			name        string
			keyid       uint16
			// validated   bool
			// trusted     bool
			trustanchor bool
			expires     string
			protocol    uint8
			alg         uint8
			flags       uint16
			pub         string
		}
		type dsView struct {
			state   cache.ValidationState
			expires string
			rrs     []string
			sigs    []string
		}
		type ownerView struct {
			ds     *dsView
			dnskey []dnskeyView
		}
		owners := map[string]*ownerView{}

		// DNSKEY trust anchors
		keys := cache.DnskeyCache.Map.Keys()
		for _, k := range keys {
			val, ok := cache.DnskeyCache.Map.Get(k)
			if !ok {
				continue
			}
			ov := owners[val.Name]
			if ov == nil {
				ov = &ownerView{}
				owners[val.Name] = ov
			}
			ov.dnskey = append(ov.dnskey, dnskeyView{
				name:        val.Name,
				keyid:       val.Keyid,
				// trusted:     val.Trusted,
				trustanchor: val.TrustAnchor,
				expires:     tdns.TtlPrint(val.Expiration),
				alg:         val.Dnskey.Algorithm,
				protocol:    val.Dnskey.Protocol,
				flags:       val.Dnskey.Flags,
				pub:         truncateKey(val.Dnskey.PublicKey, 15),
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
				state:   val.State,
				expires: tdns.TtlPrint(val.Expiration),
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
				sort.Slice(lines, func(i, j int) bool {
					return lines[i].k < lines[j].k || (lines[i].k == lines[j].k && lines[i].s < lines[j].s)
				})
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
				// Include signer name and keyid in header if present in cached RRset
				var signerInfo string
				var stateStr string
				if Conf.Internal.RRsetCache != nil {
					if c := Conf.Internal.RRsetCache.Get(owner, dns.TypeDS); c != nil {
						stateStr = validationStateString(c.State)
						if c.RRset != nil && len(c.RRset.RRSIGs) > 0 {
							if s, ok := c.RRset.RRSIGs[0].(*dns.RRSIG); ok {
								signerInfo = fmt.Sprintf(", signer: %s keyid: %d", s.SignerName, s.KeyTag)
							}
						}
					}
				}
				if stateStr == "" {
					stateStr = "none"
				}
				fmt.Printf("\n%s DS (state: %s%s, TTL: %s)\n", owner, stateStr, signerInfo, ov.ds.expires)
				for _, s := range ov.ds.rrs {
					fmt.Printf("  %s\n", maskDsLine(s))
				}
				// for range ov.ds.sigs {
				//	fmt.Printf("  [sig]\n")
				//}
			}
			// DNSKEYs next, sorted by keyid
			if len(ov.dnskey) > 0 {
				sort.Slice(ov.dnskey, func(i, j int) bool { return ov.dnskey[i].keyid < ov.dnskey[j].keyid })
				// Try to fetch DNSKEY RRset from cache to get RRset-level validated + TTL
				var rrsetState cache.ValidationState
				var rrsetTTL string = "-"
				var signerInfo string
				var stateStr string
				if Conf.Internal.RRsetCache != nil {
					if c := Conf.Internal.RRsetCache.Get(owner, dns.TypeDNSKEY); c != nil {
						rrsetState = c.State
						rrsetTTL = tdns.TtlPrint(c.Expiration)
						stateStr = validationStateString(c.State)
						if rrsetState == cache.ValidationStateSecure && c.RRset != nil && len(c.RRset.RRSIGs) > 0 {
							if s, ok := c.RRset.RRSIGs[0].(*dns.RRSIG); ok {
								signerInfo = fmt.Sprintf(", signer: %s keyid: %d", s.SignerName, s.KeyTag)
							}
						}
					}
				}

				fmt.Printf("\n%s DNSKEY (state: %s%s, TTL: %s)\n", owner, stateStr, signerInfo, rrsetTTL)
				lines := []string{"KeyID | Flags | TTL | Details"}
				for _, v := range ov.dnskey {
					ta := ""
					if v.trustanchor {
						ta = "trust anchor"
					}
					detail := fmt.Sprintf("%s DNSKEY %d %d %d %s", v.name, v.flags, v.protocol, v.alg, formatKeySnippet(v.pub))
					lines = append(lines, fmt.Sprintf("%d | %s | %s | %s", v.keyid, ta, v.expires, detail))
				}
				fmt.Println(columnize.SimpleFormat(lines))
				// for range ov.dnskey {
				//	fmt.Printf("  [sig]\n")
				//}
			}
		}
	},
}

func formatList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	return fmt.Sprintf("[%s]", strings.Join(items, " "))
}

func formatTransportWeights(server *cache.AuthServer) string {
	if len(server.TransportWeights) > 0 {
		order := []core.Transport{core.TransportDoQ, core.TransportDoT, core.TransportDoH, core.TransportDo53}
		var parts []string
		for _, t := range order {
			if w, ok := server.TransportWeights[t]; ok && w > 0 {
				parts = append(parts, fmt.Sprintf("%s:%d", core.TransportToString[t], w))
			}
		}
		if len(parts) > 0 {
			return fmt.Sprintf("[%s]", strings.Join(parts, " "))
		}
	}
	if len(server.Transports) > 0 {
		var parts []string
		for _, t := range server.Transports {
			name := core.TransportToString[t]
			if name == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s:100", name))
		}
		if len(parts) > 0 {
			return fmt.Sprintf("[%s]", strings.Join(parts, " "))
		}
	}
	return "[]"
}

func validationStateString(state cache.ValidationState) string {
	if s := cache.ValidationStateToString[state]; s != "" {
		return s
	}
	return "[unset]"
}

func printAuthServerVerbose(name string, server *cache.AuthServer) {
	fmt.Printf("  Server: %s\n", name)
	fmt.Printf("    Source: %s\n", server.Src)
	fmt.Printf("    Addresses: %s\n", formatList(server.Addrs))
	fmt.Printf("    ALPN: %s\n", formatList(server.Alpn))
	fmt.Printf("    Transports: %s\n", formatTransportWeights(server))
	fmt.Printf("    Connection mode: %s\n", server.ConnectionMode().String())
	if len(server.TransportSignal) > 0 {
		fmt.Printf("    Transport signal (raw): %s\n", server.TransportSignal)
	}
	if tlsaSnapshot := server.SnapshotTLSARecords(); len(tlsaSnapshot) > 0 {
		fmt.Printf("    TLSA records:\n")
		var owners []string
		for owner := range tlsaSnapshot {
			owners = append(owners, owner)
		}
		sort.Strings(owners)
		for _, owner := range owners {
			rec := tlsaSnapshot[owner]
			if rec == nil {
				fmt.Printf("      %s (no TLSA record)\n", owner)
				continue
			}
			stateStr := validationStateString(rec.State)
			ttlStr := "-"
			expires := "-"
			if rec.RRset != nil && len(rec.RRset.RRs) > 0 {
				ttlStr = fmt.Sprintf("%d", rec.RRset.RRs[0].Header().Ttl)
			}
			if !rec.Expiration.IsZero() {
				expires = tdns.TtlPrint(rec.Expiration)
			}
			fmt.Printf("      %s (state: %s, TTL: %s, Expires: %s)\n", owner, stateStr, ttlStr, expires)
			if rec.RRset != nil {
				for _, rr := range rec.RRset.RRs {
					fmt.Printf("        %s\n", rr.String())
				}
				if len(rec.RRset.RRSIGs) > 0 {
					fmt.Printf("        [%d RRSIGs]\n", len(rec.RRset.RRSIGs))
				}
			}
		}
	} else {
		fmt.Printf("      No TLSA records\n")
	}
}

// func dnskeyFlagList(validated, trusted, trustanchor bool) string {
//	var flags []string
//	if validated {
//		flags = append(flags, "validated")
//	}
//	if trusted {
//		flags = append(flags, "trusted")
//	}
//	if trustanchor {
//		flags = append(flags, "trust anchor")
//	}
//	if len(flags) == 0 {
//		flags = append(flags, "-")
//	}
//	return fmt.Sprintf("[%s]", strings.Join(flags, " "))
//}

func formatKeySnippet(key string) string {
	if len(key) <= 15 {
		return key
	}
	return fmt.Sprintf("%s...", key[:15])
}

func maskDnskeyLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) < 8 {
		return line
	}
	parts[7] = formatKeySnippet(parts[7])
	return strings.Join(parts, " ")
}

func maskDsLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) < 8 {
		return line
	}
	parts[7] = formatKeySnippet(parts[7])
	return strings.Join(parts, " ")
}

func maskRrsigLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) <= 12 {
		return line
	}
	parts[12] = "[sig]"
	return strings.Join(parts, " ")
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	hours := d.Hours()
	if hours < 24 {
		return fmt.Sprintf("%.1fh", hours)
	}
	days := hours / 24
	return fmt.Sprintf("%.1fd", days)
}

func init() {
	// rootCmd.AddCommand(ImrDumpCmd)
	ImrDumpCmd.AddCommand(dumpSuffixCmd, dumpServersCmd, dumpAuthServersCmd, dumpKeysCmd, dumpDnskeysCmd, dumpZoneCmd, dumpZonesCmd)
	dumpAuthServersCmd.AddCommand(newDumpKeysCmd(), newDumpServersCmd(), dumpAuthServersErrorsCmd)
	dumpZoneCmd.AddCommand(dumpZoneServersCmd)
}

func PrintCacheItem(item core.Tuple[string, cache.CachedRRset], suffix string) {

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
	stateStr := validationStateString(item.Val.State)
	ttlStr := tdns.TtlPrint(item.Val.Expiration)
	fmt.Printf("\n%s %s (state: %s, TTL: %s)\n", parts[0], rrtype, stateStr, ttlStr)

	switch item.Val.Context {
	case cache.ContextNXDOMAIN, cache.ContextNoErrNoAns:
		// NXDOMAIN: no RRset to list
		fmt.Printf("  %s %s\n", item.Val.Name, cache.CacheContextToString[item.Val.Context])
	case cache.ContextAnswer, cache.ContextGlue, cache.ContextHint, cache.ContextPriming, cache.ContextReferral:
		// Print each RR in the RRset (no RRSIGs filtering unless requested)
		ctxLabel := fmt.Sprintf("(%s)", cache.CacheContextToString[item.Val.Context])
		if item.Val.RRset == nil {
			fmt.Printf("  %s %s (no RRset)\n", item.Val.Name, ctxLabel)
			return
		}
		if len(item.Val.RRset.RRs) == 0 {
			fmt.Printf("  %s %s (no RRs)\n", item.Val.Name, ctxLabel)
			return
		}
		for _, rr := range item.Val.RRset.RRs {
			switch rr.Header().Rrtype {
			case dns.TypeDS:
				fmt.Printf("  %s %s", maskDsLine(rr.String()), ctxLabel)
			case dns.TypeDNSKEY:
				fmt.Printf("  %s %s", maskDnskeyLine(rr.String()), ctxLabel)
			default:
				fmt.Printf("  %s %s", rr.String(), ctxLabel)
			}
			fmt.Printf(" (state: %s)\n", cache.ValidationStateToString[item.Val.State])
		}
		for _, rr := range item.Val.RRset.RRSIGs {
			fmt.Printf("  %s %s\n", maskRrsigLine(rr.String()), ctxLabel)
		}
	default:
		fmt.Printf("  Context: %q", cache.CacheContextToString[item.Val.Context])
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
