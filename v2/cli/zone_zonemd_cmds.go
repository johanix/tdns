/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"fmt"
	"log"
	"os"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

var zonemdIgnoreSerial bool

// AttachZoneZonemdCmds adds the "zone zonemd" subtree.
//
// A published ZONEMD is a claim the server makes about itself, and until this
// there was no way to ask whether the claim held. "status" reads what is
// published; "verify" recomputes and compares -- the same thing an external
// verifier does, run locally so an operator can find out before their
// secondaries do.
func AttachZoneZonemdCmds(c *cobra.Command, role string) {
	zonemd := &cobra.Command{
		Use:   "zonemd",
		Short: "Inspect and verify a zone's ZONEMD (RFC 8976)",
		Long: `A zone with the publish-zonemd option carries a message digest of its own
contents at the apex, recomputed inside every publish.

"status" reports what the zone publishes without recomputing anything.
"verify" digests the zone and reports whether the published value describes it,
which is what a recipient of an AXFR will do.`,
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show the zone's published ZONEMD and its configuration",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, args []string) { runZoneZonemd(role, "status") },
	}

	verify := &cobra.Command{
		Use:   "verify",
		Short: "Recompute the zone's digest and compare it with what is published",
		Long: `Digest the zone as it is currently served and compare the result with the
apex ZONEMD, the way a recipient would.

Costs one full pass over the zone, which for a large zone is not free; that is
why it is a separate verb from "status".`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { runZoneZonemd(role, "verify") },
	}
	verify.Flags().BoolVar(&zonemdIgnoreSerial, "ignore-serial", false,
		"digest against the serial each ZONEMD names rather than the SOA's"+
			" (a diagnostic for a zone whose serial moved after it was digested,"+
			" NOT a laxer check)")

	zonemd.AddCommand(status, verify)
	c.AddCommand(zonemd)
}

func runZoneZonemd(role, subcmd string) {
	PrepArgs("zonename")

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command:      "zonemd",
		SubCommand:   subcmd,
		Zone:         tdns.Globals.Zonename,
		IgnoreSerial: zonemdIgnoreSerial,
	})
	if err != nil {
		fmt.Printf("Error from %s: %s\n", role, err.Error())
		os.Exit(1)
	}
	if cr.Error {
		fmt.Printf("Error: %s\n", cr.ErrorMsg)
		os.Exit(1)
	}
	if cr.Zonemd == nil {
		fmt.Printf("%s: no ZONEMD information returned\n", tdns.Globals.Zonename)
		os.Exit(1)
	}

	printZonemdStatus(cr.Zonemd, subcmd == "verify")

	// A failed verification is an exit code, not just a paragraph. This is the
	// command an operator puts in a check script, and a check that always
	// succeeds is not one.
	if subcmd == "verify" && cr.Zonemd.Report != nil && cr.Zonemd.Report.Verdict == "invalid" {
		os.Exit(1)
	}
}

func printZonemdStatus(st *tdns.ZonemdStatus, verified bool) {
	fmt.Printf("%s:\n", st.Zone)

	switch {
	case st.Publishing:
		fmt.Printf("   publish-zonemd: on (scheme %d, %s)\n",
			st.Scheme, zonemdAlgList(st.Algorithms))
	default:
		fmt.Printf("   publish-zonemd: off\n")
	}
	switch {
	case st.Verifying:
		fmt.Printf("   verify-zonemd:  on (on failure: %s)\n", st.OnVerifyFailure)
	default:
		fmt.Printf("   verify-zonemd:  off\n")
	}

	r := st.Report
	if r == nil || len(r.Checks) == 0 {
		fmt.Printf("   published:      none\n")
		if st.Publishing {
			fmt.Printf("\nThe zone is configured to publish a ZONEMD and is not publishing one.\n" +
				"The server logs the reason at the publish that dropped it.\n")
		}
		return
	}

	fmt.Printf("   SOA serial:     %d\n", r.SoaSerial)
	if verified {
		fmt.Printf("   verdict:        %s", r.Verdict)
		if r.IgnoredSerial {
			fmt.Printf(" (serial ignored)")
		}
		fmt.Printf("   [digested in %s]\n", r.Duration.Round(1e6))
	}
	fmt.Printf("\n")

	for _, c := range r.Checks {
		fmt.Printf("   scheme %d, %s, serial %d\n", c.Scheme, c.AlgorithmName, c.Serial)
		fmt.Printf("      published:  %s\n", c.Published)
		if c.Computed != "" && !strings.EqualFold(c.Computed, c.Published) {
			fmt.Printf("      computed:   %s\n", c.Computed)
		}
		switch {
		case !verified:
			// status did not look; do not imply that it did.
			if !c.SerialMatch {
				fmt.Printf("      NOTE: the ZONEMD names serial %d but the zone is serving %d\n",
					c.Serial, r.SoaSerial)
			}
		case c.OK():
			fmt.Printf("      OK\n")
		default:
			fmt.Printf("      FAILED: %s\n", c.Reason)
		}
	}
}

func zonemdAlgList(algs []uint8) string {
	if len(algs) == 0 {
		return "no algorithms"
	}
	names := make([]string, len(algs))
	for i, a := range algs {
		switch a {
		case 1:
			names[i] = "SHA-384"
		case 2:
			names[i] = "SHA-512"
		default:
			names[i] = fmt.Sprintf("algorithm %d", a)
		}
	}
	return strings.Join(names, ", ")
}
