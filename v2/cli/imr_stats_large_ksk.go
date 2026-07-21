package cli

import (
	"fmt"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

func pct(part, total uint64) string {
	if total == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100.0*float64(part)/float64(total))
}

func printLargeKskImrMetrics(m tdns.LargeKskImrMetrics) {
	var largeDSRRs uint64
	for _, e := range m.DSDLargeRRByAlgorithm {
		largeDSRRs += e.Count
	}

	fmt.Printf("DS RRsets encountered (referrals):  %d\n", m.DSEncounteredTotal)
	fmt.Printf("  with large-alg DS:                %d (%s of RRsets)\n",
		m.DSEncounteredLarge, pct(m.DSEncounteredLarge, m.DSEncounteredTotal))
	if len(m.DSDLargeRRByAlgorithm) == 0 {
		fmt.Printf("  large DS RRs by algorithm:        none\n")
	} else {
		fmt.Printf("  large DS RRs by algorithm:        %d total\n", largeDSRRs)
		for _, e := range m.DSDLargeRRByAlgorithm {
			fmt.Printf("    %s: %d\n", tdns.DNSSECAlgorithmLabel(e.Algorithm), e.Count)
		}
	}

	fmt.Printf("DNSKEY lookups:                     %d\n", m.DNSKEYLookupTotal)
	fmt.Printf("  bypassed probabilistic (tcp/enc):  %d (%s)\n",
		m.DNSKEYLookupBypassed, pct(m.DNSKEYLookupBypassed, m.DNSKEYLookupTotal))
	var normal uint64
	if m.DNSKEYLookupBypassed <= m.DNSKEYLookupTotal {
		normal = m.DNSKEYLookupTotal - m.DNSKEYLookupBypassed
	}
	fmt.Printf("  normal (probabilistic selection):  %d (%s)\n",
		normal, pct(normal, m.DNSKEYLookupTotal))
}

var imrStatsLargeKskCmd = &cobra.Command{
	Use:   "large-ksk",
	Short: "Show large-KSK IMR DS and DNSKEY lookup statistics",
	Long: `Counters for evaluating DNSKEY transport bypass when parent DS
signals a large KSK algorithm (dnssec.large_algorithms) or when
dnssec.dnskey_query_transport forces it.

DS RRsets are counted when cached from referrals; large-alg DS RRs are
counted individually per algorithm. DNSKEY lookups are counted at the
start of each outbound DNSKEY query; bypassed means the query skipped
probabilistic transport selection per dnssec.dnskey_query_transport and
used the server's best advertised transport instead (encrypted preferred,
else do53-tcp, never UDP).`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		printLargeKskImrMetrics(tdns.LargeKskImrMetricsSnapshot())
	},
}
