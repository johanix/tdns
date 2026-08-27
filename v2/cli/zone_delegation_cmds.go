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

var delegationChild string

// AttachZoneDelegationCmds adds the "zone delegation" subtree.
//
// The read half of "zone update". A client that has just written a delegation
// otherwise has no way to confirm what the server holds except by querying the
// public DNS -- a different channel, with different authentication and
// caching, and blind to anything the server has accepted but not yet
// published.
func AttachZoneDelegationCmds(c *cobra.Command, role string) {
	delegation := &cobra.Command{
		Use:   "delegation",
		Short: "Inspect the delegation data a parent zone holds for its children",
	}

	get := &cobra.Command{
		Use:   "get",
		Short: "Show what this parent publishes for a child (or list its children)",
		Long: `Report the delegation records the parent currently holds for a child zone,
grouped by owner name and type.

With no --child, list the children this parent has delegation data for -- the
question that comes first when reconciling an external store against the
server.

The answer comes from the zone's delegation backend, so it is what the SERVER
considers current. For a backend that records delegations somewhere other than
the served zone those differ deliberately, and reading the zone instead would
quietly give the wrong answer.`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { runZoneDelegationGet(role) },
	}
	get.Flags().StringVar(&delegationChild, "child", "",
		"Child zone to report on; omit to list the parent's children")

	delegation.AddCommand(get)
	c.AddCommand(delegation)
}

func runZoneDelegationGet(role string) {
	PrepArgs("zonename")

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command:   "get-delegation",
		Zone:      dns.Fqdn(tdns.Globals.Zonename),
		ChildZone: delegationChild,
	})
	if err != nil {
		fmt.Printf("Error from %s: %s\n", role, err.Error())
		os.Exit(1)
	}
	if cr.Error {
		fmt.Printf("Error: %s\n", cr.ErrorMsg)
		os.Exit(1)
	}
	if cr.Delegation == nil {
		fmt.Printf("%s: no delegation information returned\n", tdns.Globals.Zonename)
		os.Exit(1)
	}
	printDelegation(cr.Delegation)
}

func printDelegation(d *tdns.ChildDelegationReport) {
	owners := make([]string, 0, len(d.RRsets))
	for o := range d.RRsets {
		owners = append(owners, o)
	}
	sort.Strings(owners)

	if d.Child == "" {
		fmt.Printf("%s: %d child zone(s) with delegation data (backend: %s)\n",
			d.Parent, len(owners), d.Backend)
		for _, o := range owners {
			fmt.Printf("   %s\n", o)
		}
		return
	}

	fmt.Printf("%s: delegation of %s (backend: %s)\n", d.Parent, d.Child, d.Backend)
	if len(owners) == 0 {
		fmt.Printf("   (the parent holds no delegation data for this child)\n")
		return
	}
	for _, o := range owners {
		types := make([]string, 0, len(d.RRsets[o]))
		for t := range d.RRsets[o] {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			for _, rr := range d.RRsets[o][t] {
				fmt.Printf("   %s\n", rr)
			}
		}
	}
}
