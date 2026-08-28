/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var zoneNameOwner string

// AttachZoneNameCmds adds "zone name get".
//
// The read half of "zone update" for ordinary names, as "zone delegation get"
// is for a delegated child. A client that provisions records in a zone -- glue
// for out-of-bailiwick nameservers, service addresses, anything it maintains --
// has to be able to tell "already correct" from "not there yet", over the same
// authenticated channel it wrote through.
//
// Querying the public DNS instead is a different channel with different
// authentication and caching, and a cached negative answer from before
// publication makes such a client publish again on every pass. On a signed zone
// that re-signs and bumps the serial, indefinitely.
func AttachZoneNameCmds(c *cobra.Command, role string) {
	name := &cobra.Command{
		Use:   "name",
		Short: "Inspect what a zone publishes at a single owner name",
	}

	get := &cobra.Command{
		Use:   "get",
		Short: "Show the RRsets this zone holds at one name",
		Long: `Report the RRsets the zone currently publishes at one owner name, grouped by
type, in presentation format.

Reports the PUBLISHED view, not staged data: the question is what the server
serves, and an update still in flight is not yet an answer to it.

A name with nothing at it is an empty report, not an error -- that is what
provisioning a name for the first time returns, and it has to be
distinguishable from a read that failed. A name outside the zone IS an error,
because answering "nothing" there reads as "that name has no records".

RRSIG, NSEC, NSEC3, NSEC3PARAM and ZONEMD are never reported. They are the
signer's and the zone policy's, and returning them would invite a
read-modify-write that tries to author them.`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { runZoneNameGet(role) },
	}
	get.Flags().StringVar(&zoneNameOwner, "name", "",
		"Owner name to report on (required; must be inside the zone)")
	_ = get.MarkFlagRequired("name")

	name.AddCommand(get)
	c.AddCommand(name)
}

// runZoneNameGet sends one get-name and prints the report.
//
// A missing report with no error is treated as a failure rather than as "no
// records": an empty name legitimately answers with an empty RRsets map, but
// the report itself is always present, so its absence means the server said
// something this client does not understand.
func runZoneNameGet(role string) {
	PrepArgs("zonename")

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command:    "get-name",
		Zone:       dns.Fqdn(tdns.Globals.Zonename),
		UpdateName: zoneNameOwner,
	})
	if err != nil {
		fmt.Printf("Error from %s: %s\n", role, err.Error())
		os.Exit(1)
	}
	if cr.Error {
		fmt.Printf("Error: %s\n", cr.ErrorMsg)
		os.Exit(1)
	}
	if cr.Name == nil {
		fmt.Printf("%s: no name information returned\n", tdns.Globals.Zonename)
		os.Exit(1)
	}
	printZoneName(cr.Name)
}

// printZoneName renders a report, types sorted so two runs over unchanged data
// are diffable.
//
// "nothing published" is spelled out rather than shown as an empty list: for
// this command that is a real answer -- what provisioning a name for the first
// time returns -- and an operator should not have to tell it apart from a
// truncated screen.
func printZoneName(n *tdns.ZoneNameReport) {
	// The report echoes the name as STORED, which may differ in case from what
	// was asked for. Print what came back, so the operator sees the zone's own
	// spelling rather than their own.
	if len(n.RRsets) == 0 {
		fmt.Printf("%s: nothing published at %s\n", n.Zone, n.Name)
		return
	}

	types := make([]string, 0, len(n.RRsets))
	for t := range n.RRsets {
		types = append(types, t)
	}
	sort.Strings(types)

	fmt.Printf("%s: %d RRset(s) at %s\n", n.Zone, len(types), n.Name)
	for _, t := range types {
		for _, rr := range n.RRsets[t] {
			fmt.Printf("   %s\n", rr)
		}
	}
}
