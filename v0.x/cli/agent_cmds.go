/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/johanix/tdns/v0.x"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var dnsRecord string

var AgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "TDNS Agent commands",
}

var agentLocalCmd = &cobra.Command{
	Use:   "local",
	Short: "TDNS Agent local commands",
}

var agentLocalZoneDataCmd = &cobra.Command{
	Use:   "zonedata",
	Short: "TDNS Agent local zone data commands (adding or removing local data about zones)",
}

var agentLocalConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Show details of the local agent config",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("local")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "config",
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if amr.Error {
			log.Fatalf("API error: %s", amr.ErrorMsg)
		}

		var prettyYaml bytes.Buffer
		err = yaml.NewEncoder(&prettyYaml).Encode(amr.AgentConfig)
		if err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}
		fmt.Printf("Agent config for %q:\n%s\n", amr.AgentConfig.Identity, prettyYaml.String())
	},
}

var agentLocalZoneDataAddRRCmd = &cobra.Command{
	Use:   "add-rr",
	Short: "Add a new local DNS record for an existing zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		err := VerifyAndSendLocalDNSRecord(tdns.Globals.Zonename, dnsRecord, "add-rr")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var agentLocalZoneDataRemoveRRCmd = &cobra.Command{
	Use:   "remove-rr",
	Short: "Remove a local DNS record for an existing zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		err := VerifyAndSendLocalDNSRecord(tdns.Globals.Zonename, dnsRecord, "remove-rr")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var agentLocalZoneDataRemoveRRsetCmd = &cobra.Command{
	Use:   "remove-rrset",
	Short: "Remove a local DNS RRset for an existing zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		err := VerifyAndSendLocalDNSRecord(tdns.Globals.Zonename, dnsRecord, "remove-rrset")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	AgentCmd.AddCommand(agentLocalCmd)
	agentLocalCmd.AddCommand(agentLocalConfigCmd)
	agentLocalCmd.AddCommand(agentLocalZoneDataCmd)
	agentLocalZoneDataCmd.AddCommand(agentLocalZoneDataAddRRCmd)
	agentLocalZoneDataCmd.AddCommand(agentLocalZoneDataRemoveRRCmd)
	agentLocalZoneDataCmd.AddCommand(agentLocalZoneDataRemoveRRsetCmd)

	// agentLocalZoneDataCmd.PersistentFlags().StringVarP(&localRRtype, "rrtype", "R", "", "RR type to add")
	agentLocalZoneDataCmd.PersistentFlags().StringVarP(&dnsRecord, "RR", "", "", "DNS record to add")

}

func SendAgentMgmtCmd(req *tdns.AgentMgmtPost, prefix string) (*tdns.AgentMgmtResponse, error) {
	prefixcmd, _ := getCommandContext(prefix)
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	// api.Debug = true

	_, buf, err := api.RequestNG("POST", "/agent", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		return nil, fmt.Errorf("Failed to parse response: %v", err)
	}

	return &amr, nil
}

func VerifyAndSendLocalDNSRecord(zonename, dnsRecord, cmd string) error {
	var rr dns.RR
	var err error

	if dnsRecord == "" {
		return fmt.Errorf("Error: DNS record is required")
	}

	if rr, err = dns.NewRR(dnsRecord); err != nil {
		return fmt.Errorf("Error: Invalid DNS record (did not parse): %v", err)
	}

	if !strings.HasSuffix(rr.Header().Name, zonename) {
		return fmt.Errorf("DNS record name %q is not part of zone %q",
			rr.Header().Name, zonename)
	}

	switch rr.(type) {
	// let's only support NS, DNSKEY and KEYfor now
	case *dns.NS, *dns.DNSKEY, *dns.KEY:
		// all good
	default:
		return fmt.Errorf("Invalid RR type: %s (only NS, DNSKEY and KEY allowed)", dns.TypeToString[rr.Header().Rrtype])
	}

	switch cmd {
	case "add-rr":
		// This is a normal add RR, signaled by the CLASS=IN
		rr.Header().Class = dns.ClassINET
	case "remove-rr":
		// This is a delete RR, signaled by the CLASS=NONE
		rr.Header().Class = dns.ClassNONE
	case "remove-rrset":
		// This is a delete RRset, signaled by the CLASS=ANY
		rr.Header().Class = dns.ClassANY
	default:
		return fmt.Errorf("Invalid command: %s", cmd)
	}

	rrs := []string{rr.String()}

	amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
		Command: "update-local-zonedata",
		RRType:  rr.Header().Rrtype,
		Zone:    tdns.ZoneName(tdns.Globals.Zonename),
		AgentId: tdns.AgentId(myIdentity),
		RRs:     rrs,
	}, "local")

	if err != nil {
		fmt.Printf("Error sending agent management command: %v\n", err)
		os.Exit(1)
	}

	if amr.Error {
		fmt.Printf("Error: from agent %q: %s\n", amr.Identity, amr.ErrorMsg)
		os.Exit(1)
	}

	fmt.Printf("Agent management command sent successfully. Response: %s\n", amr.Msg)
	return nil
}
