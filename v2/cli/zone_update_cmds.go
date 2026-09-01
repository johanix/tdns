/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var (
	zoneUpdateVia    string
	zoneUpdateRRs    []string
	zoneUpdateName   string
	zoneUpdateRrtype string
	zoneUpdateFile   string
)

// AttachZoneUpdateVerbs adds the one-off content statements to an existing
// "zone update" command, alongside the interactive "create" subtree.
//
// --via is required and has no default. The two channels are not
// interchangeable: the API bypasses update-policy because the API key is the
// credential, while DDNS enforces it. Defaulting to either one would mean an
// operator could get a different authorization model than they thought they
// asked for, purely by omitting a flag.
func AttachZoneUpdateVerbs(c *cobra.Command, role string) {
	addrr := &cobra.Command{
		Use:   "addrr",
		Short: "Add one or more RRs to a zone",
		Long: `Add resource records to a primary zone.

  tdns-cli ... zone update addrr --zone alpha.dnslab. --via api \
      --rr "foo.alpha.dnslab. 3600 IN A 1.2.3.4"`,
		Run: func(cmd *cobra.Command, args []string) { runZoneUpdateVerb(role, tdns.VerbAddRR) },
	}

	delrr := &cobra.Command{
		Use:   "delrr",
		Short: "Delete one specific RR from a zone",
		Long: `Delete individual resource records. The RR must be given in full; the TTL is
ignored, since it is not part of a record's identity.

  tdns-cli ... zone update delrr --zone alpha.dnslab. --via api \
      --rr "foo.alpha.dnslab. IN A 1.2.3.4"`,
		Run: func(cmd *cobra.Command, args []string) { runZoneUpdateVerb(role, tdns.VerbDelRR) },
	}

	delrrset := &cobra.Command{
		Use:   "delrrset",
		Short: "Delete an entire RRset (owner + type) from a zone",
		Long: `Delete every record of one type at one owner name.

  tdns-cli ... zone update delrrset --zone alpha.dnslab. --via api \
      --name foo.alpha.dnslab. --type A`,
		Run: func(cmd *cobra.Command, args []string) { runZoneUpdateVerb(role, tdns.VerbDelRRset) },
	}

	delname := &cobra.Command{
		Use:   "delname",
		Short: "Delete every RRset at an owner name",
		Long: `Delete all records at a name. At the zone apex, SOA and NS are retained --
deleting those would dismantle the zone rather than a name within it.

  tdns-cli ... zone update delname --zone alpha.dnslab. --via api \
      --name foo.alpha.dnslab.`,
		Run: func(cmd *cobra.Command, args []string) { runZoneUpdateVerb(role, tdns.VerbDelName) },
	}

	replacerrset := &cobra.Command{
		Use:   "replacerrset",
		Short: "Atomically replace an RRset with the supplied RRs",
		Long: `Replace an entire RRset in one transaction. The RRset to replace is inferred
from the owner and type of the supplied records, so they must all describe the
same one; mixed owners or types are refused rather than guessed at.

This is a single atomic operation, not a delete followed by an add: the empty
intermediate RRset is never published and no secondary can observe it.

  tdns-cli ... zone update replacerrset --zone alpha.dnslab. --via api \
      --rr "foo.alpha.dnslab. IN A 1.2.3.4" \
      --rr "foo.alpha.dnslab. IN A 2.3.4.5"

To remove an RRset entirely, use delrrset -- replacerrset with no records is an
error, not a silent delete.`,
		Run: func(cmd *cobra.Command, args []string) { runZoneUpdateVerb(role, tdns.VerbReplaceRRset) },
	}

	// --from-file is not a sixth statement, it is a way of supplying a mixture
	// of the others: an ADD/DEL instruction list, of the kind "journal purge"
	// writes out and a merge will one day leave behind as .rejected. The
	// intended workflow is to open that file, delete the lines you agree with,
	// keep the ones you do not, and replay what is left.
	fromFile := &cobra.Command{
		Use:   "from-file",
		Short: "Apply an ADD/DEL instruction file to a zone",
		Long: `Apply a list of update instructions from a file.

  ADD foo.alpha.dnslab. 3600 IN A 1.2.3.4
  DEL bar.alpha.dnslab. IN A 5.6.7.8

This is the format "zone journal purge" and "zone journal list --instructions"
produce, so a file the server wrote can be edited down to the changes you want
and fed straight back:

  tdns-cli ... zone update from-file --file /var/dns/zones/alpha.2026081704.purged \
      --zone alpha.dnslab. --via api

Comments (";" or "#") and blank lines are ignored. Everything that survives is
applied as ONE update — there is no half-applied outcome.`,
		Run: func(cmd *cobra.Command, args []string) { runZoneUpdateFromFile(role) },
	}

	rrVerbs := []*cobra.Command{addrr, delrr, replacerrset}
	nameVerbs := []*cobra.Command{delrrset, delname}

	// One flag, not two. --file and --from-file both wrote to this variable, so
	// giving both silently kept whichever cobra parsed last -- and on a command
	// already named "from-file", "--from-file" reads as a typo either way.
	fromFile.Flags().StringVar(&zoneUpdateFile, "file", "", "Instruction file to apply (required)")

	for _, sub := range append(append(append([]*cobra.Command{}, rrVerbs...), nameVerbs...), fromFile) {
		// Every verb takes its input through flags and runZoneUpdateVerb never
		// looks at args. Without this, "zone update addrr foo.example. --via api"
		// silently discards the positional and then fails with the builder's
		// generic "addrr requires at least one RR", which names the wrong
		// mistake.
		sub.Args = cobra.NoArgs
		sub.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to update")
		sub.Flags().StringVar(&zoneUpdateVia, "via", "", "Transport: \"api\" or \"ddns\" (required)")
		// --signer/--server/--key are only consulted for --via ddns, but are
		// attached everywhere so the flag set does not change shape per verb.
		AttachUpdateCreateFlags(sub)
		c.AddCommand(sub)
	}
	for _, sub := range rrVerbs {
		sub.Flags().StringArrayVar(&zoneUpdateRRs, "rr", nil,
			"Resource record in presentation format (repeatable)")
	}
	for _, sub := range nameVerbs {
		sub.Flags().StringVar(&zoneUpdateName, "name", "", "Owner name")
	}
	delrrset.Flags().StringVar(&zoneUpdateRrtype, "type", "", "RR type to delete")
}

// runZoneUpdateFromFile parses the instruction file locally and then hands the
// result to the ordinary update path.
//
// Parsing here rather than shipping the raw bytes is the whole point: this
// file is meant to have been edited by hand, so the operator needs to be told
// which LINE is wrong, and only the side holding the file can say that. The
// server re-parses the records when it builds the update, so it remains
// authoritative — this is an extra gate, not a substitute for one.
func runZoneUpdateFromFile(role string) {
	PrepArgs("zonename")

	if zoneUpdateFile == "" {
		fmt.Printf("Error: --file is required (the instruction file to apply).\n")
		os.Exit(1)
	}

	f, err := os.Open(zoneUpdateFile)
	if err != nil {
		fmt.Printf("Error: cannot read %s: %v\n", zoneUpdateFile, err)
		os.Exit(1)
	}
	defer f.Close()

	insns, err := tdns.ParseUpdateInstructions(f)
	if err != nil {
		fmt.Printf("Error in %s: %v\n", zoneUpdateFile, err)
		os.Exit(1)
	}

	adds, dels := 0, 0
	for _, insn := range insns {
		if insn.Action == tdns.ZoneDeltaDel {
			dels++
		} else {
			adds++
		}
	}
	fmt.Printf("Applying %d instruction(s) from %s: %d add, %d delete\n",
		len(insns), zoneUpdateFile, adds, dels)

	spec := tdns.ZoneUpdateSpec{Verb: tdns.VerbInstructions, Instructions: insns}
	zone := dns.Fqdn(tdns.Globals.Zonename)

	switch strings.ToLower(strings.TrimSpace(zoneUpdateVia)) {
	case "api":
		runZoneUpdateViaApi(role, zone, spec)
	case "ddns":
		runZoneUpdateViaDdns(zone, spec)
	case "":
		fmt.Printf("Error: --via is required (\"api\" or \"ddns\").\n")
		os.Exit(1)
	default:
		fmt.Printf("Error: unknown --via %q (want \"api\" or \"ddns\")\n", zoneUpdateVia)
		os.Exit(1)
	}
}

func runZoneUpdateVerb(role, verb string) {
	PrepArgs("zonename")

	zone := dns.Fqdn(tdns.Globals.Zonename)
	spec := tdns.ZoneUpdateSpec{
		Verb:   verb,
		RRs:    zoneUpdateRRs,
		Name:   zoneUpdateName,
		Rrtype: zoneUpdateRrtype,
	}

	switch strings.ToLower(strings.TrimSpace(zoneUpdateVia)) {
	case "api":
		runZoneUpdateViaApi(role, zone, spec)
	case "ddns":
		runZoneUpdateViaDdns(zone, spec)
	case "":
		fmt.Printf("Error: --via is required (\"api\" or \"ddns\").\n\n" +
			"The two channels differ in authorization: the API bypasses update-policy\n" +
			"(the API key is the credential), DDNS enforces it. There is deliberately\n" +
			"no default.\n")
		os.Exit(1)
	default:
		fmt.Printf("Error: unknown --via %q (want \"api\" or \"ddns\")\n", zoneUpdateVia)
		os.Exit(1)
	}
}

// runZoneUpdateViaApi ships the statement itself rather than pre-built update
// records. The server translates it through the same BuildZoneUpdateActions
// the DDNS path uses locally, so validation happens where it is authoritative
// instead of being trusted from the client.
func runZoneUpdateViaApi(role, zone string, spec tdns.ZoneUpdateSpec) {
	// Fail on obvious input errors before a round trip, using the very same
	// builder the server will run.
	if _, err := tdns.BuildZoneUpdateActions(zone, spec); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	cr, err := SendZoneCommand(api, tdns.ZonePost{
		Command:            "update",
		Zone:               zone,
		UpdateVerb:         spec.Verb,
		UpdateRRs:          spec.RRs,
		UpdateName:         spec.Name,
		UpdateRrtype:       spec.Rrtype,
		UpdateInstructions: spec.Instructions,
	})
	if err != nil {
		// cr is the zero value on a transport error, so cr.AppName would render
		// as an empty name -- `Error from "":`. The role is what the operator
		// actually asked for and is always known.
		fmt.Printf("Error from %s: %s\n", role, err.Error())
		os.Exit(1)
	}
	if cr.Msg != "" {
		fmt.Printf("%s\n", cr.Msg)
	}
}

// runZoneUpdateViaDdns builds an RFC 2136 UPDATE locally, signs it with SIG(0)
// when a key is available, and sends it to --server.
func runZoneUpdateViaDdns(zone string, spec tdns.ZoneUpdateSpec) {
	actions, err := tdns.BuildZoneUpdateActions(zone, spec)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if server == "" {
		fmt.Printf("Error: --via ddns requires --server (host:port of the primary to update)\n")
		os.Exit(1)
	}

	m := new(dns.Msg)
	m.SetUpdate(zone)
	// The records are appended to the update section as built, rather than
	// going through m.Insert/m.Remove/m.RemoveRRset. Those helpers re-derive
	// the class from the operation and cannot express DELNAME at all
	// (CLASS=ANY with TYPE=ANY), so re-deriving here would silently drop the
	// one statement that has no library helper.
	m.Ns = append(m.Ns, actions...)
	m.SetEdns0(1232, true)

	signerName := signer
	if signerName == "" {
		signerName = zone
	}
	signerName = dns.Fqdn(signerName)

	if keyfile != "" {
		pkc, err := tdns.ReadPrivateKey(keyfile)
		switch {
		case err != nil:
			fmt.Printf("Error reading SIG(0) key file %q: %v\n", keyfile, err)
			os.Exit(1)
		case pkc == nil:
			fmt.Printf("Keyfile %q yielded no key\n", keyfile)
			os.Exit(1)
		case pkc.KeyType != dns.TypeKEY:
			fmt.Printf("Keyfile %q does not contain a SIG(0) key\n", keyfile)
			os.Exit(1)
		}
		sak := &tdns.Sig0ActiveKeys{Keys: []*tdns.PrivateKeyCache{pkc}}
		signed, err := tdns.SignMsg(*m, signerName, sak)
		if err != nil {
			fmt.Printf("Error signing update: %v\n", err)
			os.Exit(1)
		}
		if signed == nil {
			fmt.Printf("Error: signing produced no message\n")
			os.Exit(1)
		}
		m = signed
	} else {
		fmt.Printf("Warning: no --key given, sending the update UNSIGNED.\n" +
			"A primary enforcing update-policy will almost certainly refuse it.\n")
	}

	fmt.Printf("Sending to %s:\n", server)
	for _, line := range tdns.ZoneUpdateActionsSummary(actions) {
		fmt.Printf("  %s\n", line)
	}

	rcode, _, err := tdns.SendUpdate(context.Background(), m, zone, []string{server})
	if err != nil {
		fmt.Printf("Error sending update: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Update sent, response rcode: %s\n", dns.RcodeToString[rcode])
	if rcode != dns.RcodeSuccess {
		os.Exit(1)
	}
}
