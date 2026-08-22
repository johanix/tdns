/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"fmt"
	"log"
	"os"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

var (
	journalSerial       uint32
	journalForce        bool
	journalInstructions bool
	journalOutfile      string
)

// AttachZoneJournalCmds adds the "zone journal" subtree.
//
// The delta journal decides what a zone serves after a restart, and before
// this it had no operator surface at all: no way to see whether it held
// anything, what, or whether it would survive the next load. These four
// commands are that surface.
func AttachZoneJournalCmds(c *cobra.Command, role string) {
	journal := &cobra.Command{
		Use:   "journal",
		Short: "Inspect and manage a zone's delta journal",
		Long: `The delta journal holds zone changes that have not yet reached the zone file.

It is written when an update is published and replayed over the file on load, so
a restart loses nothing. "zone sync" folds it into the file and empties it.`,
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Summarise the journal, and whether it will replay on restart",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, args []string) { runZoneJournal(role, "status") },
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List the journal's deltas and the records in them",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, args []string) { runZoneJournal(role, "list") },
	}

	truncate := &cobra.Command{
		Use:   "truncate",
		Short: "Drop the journal's tail, keeping the chain through --serial",
		Long: `Keep the journal up to and including the delta that ends at --serial, drop the rest.

A journal is a chain: each delta continues where the previous one ended, and a
chain with a gap cannot be replayed at all. So only a suffix can be removed —
there is deliberately no way to delete one record from the middle. To undo a
single record, append a correction with an ordinary "zone update" instead.`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { runZoneJournal(role, "truncate") },
	}

	purge := &cobra.Command{
		Use:   "purge",
		Short: "Discard the whole journal, saving its content first",
		Long: `Discard every delta, after writing what they hold to {zonefile}.{serial}.purged
as ADD/DEL instructions. Nothing is lost silently: replay what you want back with

  tdns-cli ... zone update from-file --file {zonefile}.{serial}.purged --zone <zone> --via api

A journal that would replay cleanly holds changes that exist nowhere else, so
purging one needs --force. Prefer "zone sync", which folds the same changes into
the zone file and loses nothing. A journal that would NOT replay needs no flag:
its changes are already absent from what the zone serves.`,
		Args: cobra.NoArgs,
		Run:  func(cmd *cobra.Command, args []string) { runZoneJournal(role, "purge") },
	}

	for _, sub := range []*cobra.Command{status, list, truncate, purge} {
		sub.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone name")
		journal.AddCommand(sub)
	}
	truncate.Flags().Uint32Var(&journalSerial, "serial", 0,
		"Keep the chain through the delta ending at this serial (required)")
	purge.Flags().BoolVar(&journalForce, "force", false,
		"Discard a journal that would otherwise replay cleanly")
	list.Flags().BoolVar(&journalInstructions, "instructions", false,
		"Print as replayable ADD/DEL instructions instead of a summary")
	for _, sub := range []*cobra.Command{list, purge} {
		sub.Flags().StringVar(&journalOutfile, "out", "",
			"Write the instruction form to this file instead of stdout")
	}

	c.AddCommand(journal)
}

func runZoneJournal(role, subcmd string) {
	PrepArgs("zonename")

	if subcmd == "truncate" && journalSerial == 0 {
		fmt.Printf("Error: truncate requires --serial (the serial of the last delta to keep).\n" +
			"Run \"zone journal status\" to see the chain's boundaries.\n")
		os.Exit(1)
	}

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command:      "journal",
		SubCommand:   subcmd,
		Zone:         tdns.Globals.Zonename,
		Serial:       journalSerial,
		Force:        journalForce,
		Instructions: journalInstructions,
	})
	if err != nil {
		fmt.Printf("Error from %s: %s\n", role, err.Error())
		os.Exit(1)
	}

	switch {
	case journalInstructions && len(cr.Instructions) > 0:
		emitInstructions(cr.Instructions, cr.Zone)
	case cr.Journal != nil:
		printJournalInfo(cr.Journal, subcmd == "list")
	}

	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}

	// A purge that could not write its artefact -- a zone with no zone file --
	// returns the discarded content in the response and nowhere else. Printing
	// it is not a nicety, it is the only remaining copy, and a purge that
	// swallowed it would be exactly the `rm zone.jnl` this command exists to
	// improve on. An explicit --out is honoured either way.
	if subcmd == "purge" && len(cr.Instructions) > 0 {
		if journalOutfile != "" || cr.Artefact == "" {
			emitInstructions(cr.Instructions, cr.Zone)
		}
	}
}

func emitInstructions(insns []tdns.ZoneDeltaRR, zone string) {
	comments := []string{
		fmt.Sprintf("tdns journal contents for %s", zone),
		fmt.Sprintf("replay with: tdns-cli ... zone update from-file --file <this file> --zone %s --via api", zone),
	}

	if journalOutfile == "" {
		if err := tdns.WriteUpdateInstructions(os.Stdout, comments, insns); err != nil {
			fmt.Printf("Error writing instructions: %v\n", err)
			os.Exit(1)
		}
		return
	}

	f, err := os.Create(journalOutfile)
	if err != nil {
		fmt.Printf("Error creating %s: %v\n", journalOutfile, err)
		os.Exit(1)
	}
	defer f.Close()
	if err := tdns.WriteUpdateInstructions(f, comments, insns); err != nil {
		fmt.Printf("Error writing %s: %v\n", journalOutfile, err)
		os.Exit(1)
	}
	fmt.Printf("%d instruction(s) written to %s\n", len(insns), journalOutfile)
}

func printJournalInfo(info *tdns.ZoneJournalInfo, detail bool) {
	if !info.PersistenceActive {
		fmt.Printf("  !! delta persistence is DISABLED deployment-wide (journal: active: false).\n")
		fmt.Printf("     Updates are applied and served but will NOT survive a restart.\n\n")
	}

	if info.Deltas == 0 {
		fmt.Printf("Zone %s: journal is empty (zone file serial %d, serving %d)\n",
			info.Zone, info.FileSerial, info.ServedSerial)
		return
	}

	fmt.Printf("Zone %s journal:\n", info.Zone)
	fmt.Printf("  deltas:        %d (%d records)\n", info.Deltas, info.Records)
	fmt.Printf("  chain:         %d -> %d\n", info.AnchorSerial, info.HeadSerial)
	fmt.Printf("  zone file:     %s (serial %d)\n", info.Zonefile, info.FileSerial)
	fmt.Printf("  serving:       %d\n", info.ServedSerial)

	// The question an operator actually has, answered in those words.
	if info.Replayable {
		fmt.Printf("  will replay:   yes\n")
	} else {
		fmt.Printf("  will replay:   NO\n")
		fmt.Printf("  why not:       %s\n", info.Diagnosis)
	}
	if !info.Replayed {
		fmt.Printf("  applied now:   NO -- these changes are in the database but NOT in what\n")
		fmt.Printf("                 the zone is currently serving\n")
	}

	if detail {
		fmt.Printf("\n")
		for _, d := range info.Deltalist {
			fmt.Printf("  %d -> %d  (%d add, %d del)\n", d.FromSerial, d.ToSerial, d.Adds, d.Dels)
			for _, rr := range d.RRs {
				kw := tdns.InstrAdd
				if rr.Action == tdns.ZoneDeltaDel {
					kw = tdns.InstrDel
				}
				fmt.Printf("      %s %s\n", kw, rr.RR)
			}
		}
	}
}
