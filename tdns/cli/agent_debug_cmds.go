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

	"github.com/gookit/goutil/dump"
	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var myIdentity, notifyRRtype, rfitype string

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

		rrtype := dns.StringToType[notifyRRtype]
		if rrtype == 0 {
			log.Fatalf("Error: Invalid RR type: %s", notifyRRtype)
		}

		req := tdns.AgentMgmtPost{
			Command:     "send-notify",
			MessageType: tdns.AgentMsgNotify,
			RRType:      rrtype,
			Zone:        tdns.ZoneName(tdns.Globals.Zonename),
			AgentId:     tdns.AgentId(myIdentity),
			RRs:         rrs,
		}

		SendAgentDebugCmd(req, true)
	},
}

var DebugAgentSendRfiCmd = &cobra.Command{
	Use:   "send-rfi",
	Short: "Tell agent to send an RFI message to another agent",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		rfitype = strings.ToUpper(rfitype)
		if rfitype != "UPSTREAM" && rfitype != "DOWNSTREAM" {
			log.Fatalf("Error: RFI type must be either UPSTREAM or DOWNSTREAM (is %q)", rfitype)
		}

		req := tdns.AgentMgmtPost{
			Command:     "send-rfi",
			MessageType: tdns.AgentMsgRfi,
			RfiType:     rfitype,
			Zone:        tdns.ZoneName(tdns.Globals.Zonename),
			AgentId:     tdns.AgentId(myIdentity),
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		// dump.P(amr)

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Result from %s RFI message sent to agent %q:\n", amr.RfiType, amr.Identity)
		if len(amr.RfiResponse) > 0 {
			var out []string
			if tdns.Globals.ShowHeaders {
				out = append(out, fmt.Sprintf("Zone|Provider|Where|XFR src|XFR dst|XFR auth"))
			}
			for aid, rfidata := range amr.RfiResponse {
				if len(rfidata.ZoneXfrSrcs) > 0 {
					out = append(out, fmt.Sprintf("%s|%s|UPSTREAM|%v|%v|%v", tdns.Globals.Zonename, aid, rfidata.ZoneXfrSrcs, "", rfidata.ZoneXfrAuth))
				}
				if len(rfidata.ZoneXfrDsts) > 0 {
					out = append(out, fmt.Sprintf("%s|%s|DOWNSTREAM|%v|%v|%v", tdns.Globals.Zonename, aid, "", rfidata.ZoneXfrDsts, rfidata.ZoneXfrAuth))
				}
				// if len(rfidata.ZoneXfrAuth) > 0 {
				// 	fmt.Printf("ZoneXfrAuth for %q: %s", aid, rfidata.ZoneXfrAuth)
				// }
			}
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		} else {
			fmt.Printf("No RFI data in response from agent %q", amr.Identity)
		}
	},
}

var DebugAgentDumpAgentRegistryCmd = &cobra.Command{
	Use:   "dump-agentregistry",
	Short: "Dump the agent registry",
	Run: func(cmd *cobra.Command, args []string) {
		req := tdns.AgentMgmtPost{
			Command: "dump-agentregistry",
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		// dump.P(amr.AgentRegistry)
		if len(amr.AgentRegistry.RegularS) == 0 {
			fmt.Printf("No agent registry data in response from agent %q", amr.Identity)
			os.Exit(1)
		}

		if len(amr.AgentRegistry.RegularS) > 0 {
			var agentNames []tdns.AgentId
			for _, agent := range amr.AgentRegistry.RegularS {
				agentNames = append(agentNames, agent.Identity)
			}
			fmt.Printf("Agent registry contains %d agents: %v\n", len(agentNames), agentNames)
			for _, agent := range amr.AgentRegistry.RegularS {
				err := PrintAgent(agent, false)
				if err != nil {
					log.Printf("Error printing agent: %v", err)
				}
				fmt.Println()
			}
		} else {
			fmt.Printf("No remote agents found in the agent registry data from agent %q", amr.Identity)
		}
	},
}

var DebugAgentDumpZoneDataRepoCmd = &cobra.Command{
	Use:   "dump-zonedatarepo",
	Short: "Dump the zone data repo",
	Run: func(cmd *cobra.Command, args []string) {
		req := tdns.AgentMgmtPost{
			Command: "dump-zonedatarepo",
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		// dump.P(amr)

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		dump.P(amr.ZoneDataRepo)

		if len(amr.ZoneDataRepo) > 0 {
			for zone, agentRepo := range amr.ZoneDataRepo {
				fmt.Printf("*** Zone: %s\n", zone)
				for agentId, data := range agentRepo {
					fmt.Printf("*** Data from agent %s:\n", agentId)
					// dump.P(data)
					for rrtype, rrset := range data {
						fmt.Printf("*** RRType: %s\n", dns.TypeToString[rrtype])
						// dump.P(rrset)
						for _, rr := range rrset {
							fmt.Printf("*** RR: %s\n", rr)
						}
					}
				}
			}
		} else {
			fmt.Printf("No ZoneDataRepo data in response from agent %q", amr.Identity)
		}
	},
}

var DebugAgentRegistryCmd = &cobra.Command{
	Use:   "agentregistry",
	Short: "Test the agent registry",
	Run: func(cmd *cobra.Command, args []string) {
		conf := tdns.Config{
			Agent: tdns.LocalAgentConf{
				Identity: "local",
			},
		}
		ar := conf.NewAgentRegistry()
		ar.LocateInterval = 10
		ar.S.Set("local", &tdns.Agent{
			Identity: "local",
		})

		ar.AddRemoteAgent("agent.example.com", &tdns.Agent{
			Identity: "agent.example.com",
		})

		ar.AddRemoteAgent("agent.example.org", &tdns.Agent{
			Identity: "agent.example.org",
		})

		fmt.Printf("Agent registry:\ntype=%T\n", ar.S)
		fmt.Printf("Agent registry:\n%d shards\n", ar.S.NumShards())
		for item := range ar.S.IterBuffered() {
			fmt.Printf("Agent registry:\n%s\n", item.Key)
			fmt.Printf("Agent registry:\n%v\n", item.Val)
		}
	},
}

func init() {
	DebugCmd.AddCommand(DebugAgentCmd)
	DebugAgentCmd.AddCommand(DebugAgentSendNotifyCmd)
	DebugAgentCmd.AddCommand(DebugAgentSendRfiCmd)
	DebugAgentCmd.AddCommand(DebugAgentDumpAgentRegistryCmd)
	DebugAgentCmd.AddCommand(DebugAgentDumpZoneDataRepoCmd)
	DebugAgentCmd.AddCommand(DebugAgentRegistryCmd)
	DebugAgentSendNotifyCmd.Flags().StringVarP(&myIdentity, "id", "I", "", "agent identity to claim")
	DebugAgentSendNotifyCmd.Flags().StringVarP(&notifyRRtype, "rrtype", "R", "", "RR type sent notify for")
	DebugAgentSendNotifyCmd.Flags().StringVarP(&dnsRecord, "RR", "", "", "DNS record to send")
	DebugAgentSendRfiCmd.Flags().StringVarP(&rfitype, "rfi", "", "", "RFI type (UPSTREAM|DOWNSTREAM)")
	// DebugAgentSendRfiCmd.Flags().StringVarP(&rfiupstream, "upstream", "", "", "Identity of upstream agent")
	// DebugAgentSendRfiCmd.Flags().StringVarP(&rfidownstream, "downstream", "", "", "Identity of downstream agent")
}

func SendAgentDebugCmd(req tdns.AgentMgmtPost, printJson bool) (*tdns.AgentMgmtResponse, error) {
	prefixcmd, _ := getCommandContext("debug")
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	api.Debug = true

	_, buf, err := api.RequestNG("POST", "/agent/debug", req, true)
	if err != nil {
		log.Fatalf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if printJson {
		var prettyJSON bytes.Buffer
		err = json.Indent(&prettyJSON, buf, "", "  ")
		if err != nil {
			log.Println("JSON parse error: ", err)
		}
		fmt.Printf("Agent debug response:\n%s\n", prettyJSON.String())
		return &amr, nil
	}

	if amr.Error {
		log.Fatalf("API error: %s", amr.ErrorMsg)
	}

	return &amr, nil
}
