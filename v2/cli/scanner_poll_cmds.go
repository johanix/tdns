/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// NewAuthScannerCmd builds the "scanner" subtree of a tdns-auth command tree:
// the controls of tdns-auth's built-in CDS/CSYNC scanner. The standalone
// tdns-scanner has its own tree, ScannerCmd. The target daemon is read off the
// tree (GetApiClientForCmd), so one factory serves every instance.
func NewAuthScannerCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "scanner",
		Short: "Control tdns-auth's built-in CDS/CSYNC scanner",
	}
	c.AddCommand(newScannerPollCmd())
	return c
}

func newScannerPollCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "poll [on|off|status|follow-config]",
		Short: "Switch the poll scan of all children on or off, or show whether it is on",
		Long: `Without an argument, or with "status", shows whether tdns-auth polls the
children of its parent zones.

"on" and "off" switch polling while tdns-auth runs, overriding
scanner.poll.enabled until "follow-config" or a restart; the switch is not
persisted. "on" takes effect at the next round, within scanner.interval. "off"
also stops a round in progress from starting any more children.`,
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"on", "off", "status", "follow-config"},
		Run: func(cmd *cobra.Command, args []string) {
			command := "status"
			if len(args) == 1 {
				command = strings.ToLower(args[0])
			}
			api, err := GetApiClientForCmd(cmd, true)
			if err != nil {
				cliFatalf("error getting API client: %v", err)
			}
			status, body, err := api.RequestNG("POST", "/scanner/poll", tdns.ScannerPollPost{Command: command}, true)
			if err != nil {
				cliFatalf("error calling scanner/poll: %v", err)
			}
			if status != http.StatusOK {
				cliFatalf("scanner poll %s: status %d: %s", command, status, strings.TrimSpace(string(body)))
			}
			var resp tdns.ScannerPollResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				cliFatalf("error parsing scanner/poll response: %v", err)
			}
			fmt.Print(formatScannerPoll(resp))
		},
	}
}

// formatScannerPoll renders the answer for the terminal.
func formatScannerPoll(r tdns.ScannerPollResponse) string {
	state := "off"
	if r.Enabled {
		state = "on"
	}
	if r.Msg != "" {
		return fmt.Sprintf("%s\npolling %s\n", r.Msg, state)
	}
	return fmt.Sprintf("polling %s\n", state)
}
