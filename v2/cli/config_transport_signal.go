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
// name given, in zone-file format. Pasted into the zone, those records are
// provisioned, and tdns-auth stops synthesizing there: it never writes
// where records exist.
func newConfigTransportSignalCmd(role string) *cobra.Command {
	return &cobra.Command{
		Use:   "transport-signal [name]",
		Short: "Print the _dns SVCB records tdns-" + role + " synthesizes from service.transport, for the zone",
		Long: `Print, in zone-file format, the _dns.<name> SVCB RRset that tdns-` + role + `
synthesizes from its current service.transport: for every name in
service.identities, or for the one name given. Paste the records into the
zone that holds the name. Once they are there they are provisioned, and
tdns-` + role + ` no longer synthesizes a signal at that name.

Each RRset is preceded by a comment line saying where things stand at the
name on the server: synthesized there now, provisioned (as printed or
differing), nothing there, or no zone served there holds the name.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var name string
			if len(args) == 1 {
				name = args[0]
			}
			api, err := GetApiClient(role, true)
			if err != nil {
				fmt.Printf("Error creating API client: %v\n", err)
				os.Exit(1)
			}
			resp, err := SendConfigCommand(api, tdns.ConfigPost{Command: "transport-signal", Name: name})
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Print(renderTransportSignal(resp.TransportSignal))
		},
	}
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
		s = fmt.Sprintf("%s: synthesized in %s now; provision these records there to replace it", p.Owner, p.Home)
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
