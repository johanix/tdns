/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// newConfigTransportSignalCmd is "config transport-signal [name]": the
// bridge from synthesized to provisioned transport signals. It prints the
// _dns.<name> SVCB RRset a running tdns-auth synthesizes from its current
// service.transport, for every name in service.identities or for the one
// name given, in zone-file format. "--release <name>" hands the name over:
// tdns-auth drops its record of the signal it stored there, so the RRset at
// the owner is the operator's from then on.
func newConfigTransportSignalCmd(role string) *cobra.Command {
	var release string
	cmd := &cobra.Command{
		Use:   "transport-signal [name]",
		Short: "Print the _dns SVCB records tdns-" + role + " synthesizes from service.transport, for the zone",
		Long: `Print, in zone-file format, the _dns.<name> SVCB RRset that tdns-` + role + `
synthesizes from its current service.transport: for every name in
service.identities, or for the one name given.

The loop from synthesized to provisioned: print the records, paste them into
the zone that holds the name, then release the name with --release <name>.
The release tells tdns-` + role + ` that the RRset at _dns.<name> is the
operator's: it stops synthesizing there, never rewrites the records, and
never withdraws them. After that the name may leave service.identities.
Release only once the records are in the zone's source (its zone file): a
signal the server no longer owns is not carried over a reload.

Each RRset is preceded by a comment line saying where things stand at the
name on the server: synthesized there now, provisioned (as printed or
differing), nothing there, or no zone served there holds the name.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			post := tdns.ConfigPost{Command: "transport-signal"}
			switch {
			case release != "" && len(args) == 1:
				fmt.Println("Error: give the name to --release, not beside it")
				os.Exit(1)
			case release != "":
				post = tdns.ConfigPost{Command: "transport-signal-release", Name: release}
			case len(args) == 1:
				post.Name = args[0]
			}
			api, err := GetApiClient(role, true)
			if err != nil {
				fmt.Printf("Error creating API client: %v\n", err)
				os.Exit(1)
			}
			resp, err := SendConfigCommand(api, post)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			if resp.Msg != "" && release != "" {
				fmt.Println("; " + resp.Msg)
			}
			fmt.Print(renderTransportSignal(resp.TransportSignal))
		},
	}
	cmd.Flags().StringVar(&release, "release", "", "hand _dns.<name> over to the operator: tdns-"+role+" drops its record of the signal it stored there")
	return cmd
}

// renderTransportSignal lays the previews out as a zone-file fragment: per
// name a comment line, then the records, then a blank line.
func renderTransportSignal(previews []tdns.TransportSignalPreview) string {
	var b strings.Builder
	for i, p := range previews {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("; " + transportSignalStateLine(p) + "\n")
		for _, rr := range p.Records {
			b.WriteString(rr + "\n")
		}
	}
	return b.String()
}

// transportSignalStateLine says where things stand at the name.
func transportSignalStateLine(p tdns.TransportSignalPreview) string {
	var s string
	switch p.State {
	case tdns.SignalStateSynthesized:
		s = fmt.Sprintf("%s: synthesized in %s now; paste these records into the zone, then run transport-signal --release %s; the name may then leave service.identities", p.Owner, p.Home, p.Name)
	case tdns.SignalStateProvisioned:
		if p.Matches {
			s = fmt.Sprintf("%s: provisioned in %s as below; not synthesized", p.Owner, p.Home)
		} else {
			s = fmt.Sprintf("%s: provisioned in %s, differing from below; not synthesized", p.Owner, p.Home)
		}
	case tdns.SignalStateNone:
		s = fmt.Sprintf("%s: nothing there in %s yet", p.Owner, p.Home)
	default:
		s = fmt.Sprintf("%s: no zone served here holds %s; provision these records in the zone that does", p.Owner, p.Name)
	}
	if !p.Identity {
		s += " (not one of service.identities)"
	}
	return s
}
