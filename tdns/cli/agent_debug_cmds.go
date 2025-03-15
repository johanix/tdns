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
	"github.com/spf13/cobra"
)

var myIdentity, notifyRRtype string

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
			log.Fatalf("Error: RR type must be either NS or DNSKEY")
		}

		prefixcmd, _ := getCommandContext("debug")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		var notifyCmd string
		switch notifyRRtype {
		case "NS":
			notifyCmd = "send-notify-ns"
		case "DNSKEY":
			notifyCmd = "send-notify-dnskey"
		}

		req := tdns.AgentPost{
			Command: notifyCmd,
			Zone:    tdns.Globals.Zonename,
			AgentId: myIdentity,
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp tdns.AgentResponse
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
}
