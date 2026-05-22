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
	fmt.Printf("  forced TCP from start (do53-tcp):  %d (%s)\n",
		m.DNSKEYLookupForcedTCP, pct(m.DNSKEYLookupForcedTCP, m.DNSKEYLookupTotal))
	normal := m.DNSKEYLookupTotal - m.DNSKEYLookupForcedTCP
	fmt.Printf("  normal (UDP / encrypted / other):  %d (%s)\n",
		normal, pct(normal, m.DNSKEYLookupTotal))
}

var imrStatsLargeKskCmd = &cobra.Command{
	Use:   "large-ksk",
	Short: "Show large-KSK IMR DS and DNSKEY lookup statistics",
	Long: `Counters for evaluating direct-TCP DNSKEY fetching when parent DS
signals a large KSK algorithm (dnssec.large_algorithms).

DS RRsets are counted when cached from referrals; large-alg DS RRs are
counted individually per algorithm. DNSKEY lookups are counted at the
start of each outbound DNSKEY query; forced-TCP means do53-tcp was
selected from the start (not UDP-to-TCP fallback).`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		printLargeKskImrMetrics(tdns.LargeKskImrMetricsSnapshot())
	},
}
