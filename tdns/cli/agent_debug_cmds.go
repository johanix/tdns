/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var myIdentity, notifyRRtype, dnsRecord string

var DebugAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "TDNS-AGENT debugging commands",
}

var DebugAgentSendNotifyCmd = &cobra.Command{
	Use:   "send-notify",
	Short: "Tell agent to send a NOTIFY message to the other agents",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		notifyRRtype = strings.ToUpper(notifyRRtype)
		if notifyRRtype != "NS" && notifyRRtype != "DNSKEY" {
			log.Fatalf("Error: RR type must be either NS or DNSKEY (is %q)", notifyRRtype)
		}

		if dnsRecord == "" {
			log.Fatalf("Error: DNS record is required")
		}

		var rr dns.RR
		var err error

		if rr, err = dns.NewRR(dnsRecord); err != nil {
			log.Fatalf("Error: Invalid DNS record (did not parse): %v", err)
		}

		rrs := []string{rr.String()}

		prefixcmd, _ := getCommandContext("debug")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		rrtype := dns.StringToType[notifyRRtype]
		if rrtype == 0 {
			log.Fatalf("Error: Invalid RR type: %s", notifyRRtype)
		}

		req := tdns.AgentMgmtPost{
			//Command:     "send-notify",
			MessageType: "NOTIFY",
			RRType:      rrtype,
			Zone:        tdns.ZoneName(tdns.Globals.Zonename),
			AgentId:     tdns.AgentId(myIdentity),
			RRs:         rrs,
		}

		_, buf, err := api.RequestNG("POST", "/agent/debug", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if resp.Error {
			log.Fatalf("API error: %s", resp.ErrorMsg)
		}

		var prettyJSON bytes.Buffer

		err = json.Indent(&prettyJSON, buf, "", "  ")
		if err != nil {
			log.Println("JSON parse error: ", err)
		}
		fmt.Printf("Agent config:\n%s\n", prettyJSON.String())
	},
}

func init() {
	DebugCmd.AddCommand(DebugAgentCmd)
	DebugAgentCmd.AddCommand(DebugAgentSendNotifyCmd)
	DebugAgentSendNotifyCmd.Flags().StringVarP(&myIdentity, "id", "I", "", "agent identity to claim")
	DebugAgentSendNotifyCmd.Flags().StringVarP(&notifyRRtype, "rrtype", "R", "", "RR type sent notify for")
	DebugAgentSendNotifyCmd.Flags().StringVarP(&dnsRecord, "RR", "", "", "DNS record to send")
}
