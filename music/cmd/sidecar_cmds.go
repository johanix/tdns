/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package mcmd

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gookit/goutil/dump"
	"github.com/johanix/tdns/music"
	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var sidecarId, sidecarMethod string

// var ss = &music.Sidecars{
// 	S: cmap.New[*music.Sidecar](),
// }

var SidecarCmd = &cobra.Command{
	Use:   "sidecar",
	Short: "Prefix command, not usable directly",
}

var sidecarLocateCmd = &cobra.Command{
	Use:   "locate",
	Short: "Locate a sidecar, given its identity and method",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("identity", "method")
		new, sidecar, err := music.Globals.Sidecars.LocateSidecar(sidecarId, tdns.StringToMsignerMethod[sidecarMethod])
		if err != nil {
			log.Fatalf("Error locating sidecar: %v", err)
		}
		if new {
			fmt.Printf("New sidecar: %+v\n", sidecar)
		} else {
			fmt.Printf("Sidecar already known: %+v\n", sidecar)
		}
	},
}

var sidecarIdentifyCmd = &cobra.Command{
	Use:   "identify",
	Short: "Identify multi-signer sidecars for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		tst := &music.Sidecar{Identity: "test.test.net."}
		music.Globals.Sidecars.S.Set("test.test.net.", tst)

		tst2 := &music.Sidecar{Identity: "ploff.net."}
		music.Globals.Sidecars.S.Set("ploff.net.", tst2)

		msigners, sidecars, err := music.Globals.Sidecars.IdentifySidecars(tdns.Globals.Zonename)
		if err != nil {
			log.Fatalf("Error identifying sidecars: %v", err)
		}
		fmt.Printf("MSIGNER records:\n")
		for _, msigner := range msigners {
			fmt.Printf("%s\n", msigner.String())
		}
		var ids []string
		for _, s := range sidecars {
			ids = append(ids, s.Identity)
		}
		fmt.Printf("Sidecars: There are %d sidecars, with identities: %s\n", len(sidecars), strings.Join(ids, ", "))
		dump.P(sidecars)

		out := []string{}
		if tdns.Globals.ShowHeaders {
			out = append(out, "IDENTITY|METHOD|ADDRESSES|PORT|TLSA or KEY")
		}
		for _, sidecar := range music.Globals.Sidecars.S.Items() {
			// fmt.Printf("Sidecar: %v\n", sidecar)
			extra := ""
			addrs := ""
			var port uint16 = 0
			if sidecar.Methods["API"] {
				extra = sidecar.Details[tdns.MsignerMethodAPI].TlsaRR.String()
				addrs = strings.Join(sidecar.Details[tdns.MsignerMethodAPI].Addrs, ",")
				port = sidecar.Details[tdns.MsignerMethodAPI].Port
				out = append(out, fmt.Sprintf("%s|%s|%s|%d|%s", sidecar.Identity, "API",
					addrs, port, extra))
			}

			if sidecar.Methods["DNS"] {
				extra = sidecar.Details[tdns.MsignerMethodDNS].KeyRR.String()
				addrs = strings.Join(sidecar.Details[tdns.MsignerMethodDNS].Addrs, ",")
				port = sidecar.Details[tdns.MsignerMethodDNS].Port
				out = append(out, fmt.Sprintf("%s|%s|%s|%d|%s", sidecar.Identity, "DNS",
					addrs, port, extra))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var sidecarHelloCmd = &cobra.Command{
	Use:   "hello",
	Short: "Send a hello message to all sidecars for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		msigners, sidecars, err := music.Globals.Sidecars.IdentifySidecars(tdns.Globals.Zonename)
		if err != nil {
			log.Fatalf("Error identifying sidecars: %v", err)
		}
		fmt.Printf("MSIGNER records:\n")
		for _, msigner := range msigners {
			fmt.Printf("%s\n", msigner.String())
		}
		var ids []string
		for _, s := range sidecars {
			ids = append(ids, s.Identity)
		}
		fmt.Printf("Sidecars: There are %d sidecars, with identities: %s\n", len(sidecars), strings.Join(ids, ", "))

		out := []string{}
		if tdns.Globals.ShowHeaders {
			out = append(out, "IDENTITY|METHOD|RESPONSE")
		}
		for _, sidecar := range music.Globals.Sidecars.S.Items() {
			fmt.Printf("Sidecar: %s\n", sidecar.Identity)
			err := sidecar.SendHello()
			if err != nil {
				log.Printf("Error sending hello to sidecar %s: %v", sidecar.Identity, err)
			}
			if sidecar.Methods["API"] {
				fmt.Printf("API method\n")
				out = append(out, fmt.Sprintf("%s|%s|%s", sidecar.Identity, "API", err))
			}

			if sidecar.Methods["DNS"] {
				fmt.Printf("DNS method\n")
				out = append(out, fmt.Sprintf("%s|%s|%s", sidecar.Identity, "DNS", err))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var scUri, scAddr string
var scPort uint16

var sidecarDebugHelloCmd = &cobra.Command{
	Use:   "debug-hello",
	Short: "Send a hello message to a sidecar specified on the command line",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "port", "addr", "uri")

		out := []string{}
		if tdns.Globals.ShowHeaders {
			out = append(out, "IDENTITY|METHOD|RESPONSE")
		}

		sidecar := &music.Sidecar{
			Identity: "debug-sidecar",
			Methods:  map[string]bool{"API": true, "DNS": true},
			Details: map[tdns.MsignerMethod]music.SidecarDetails{
				tdns.MsignerMethodAPI: {
					Port:    scPort,
					Addrs:   []string{scAddr},
					BaseUri: scUri,
					TlsaRR: &dns.TLSA{
						Hdr: dns.RR_Header{
							Name:   "api.debug-sidecar. IN TLSA 3 1 1 123132345345345",
							Rrtype: dns.TypeTLSA,
							Class:  dns.ClassINET,
							Ttl:    3600,
						},
					},
					LastHB: time.Now(),
				},
				tdns.MsignerMethodDNS: {
					Port:   scPort,
					Addrs:  []string{scAddr},
					LastHB: time.Now(),
				},
			},
		}

		err := sidecar.NewMusicSyncApiClient(sidecar.Identity, tdns.Globals.BaseUri, "", "", "insecure")
		if err != nil {
			log.Fatalf("failed to create MUSIC API client for %s: %v", sidecar.Identity, err)
		}

		fmt.Printf("Sidecar: %s\n", sidecar.Identity)
		err = sidecar.SendHello()
		if err != nil {
			log.Printf("Error sending hello to sidecar %s: %v", sidecar.Identity, err)
		}
		if sidecar.Methods["API"] {
			fmt.Printf("API method\n")
			out = append(out, fmt.Sprintf("%s|%s|%s", sidecar.Identity, "API", err))
		}

		if sidecar.Methods["DNS"] {
			fmt.Printf("DNS method\n")
			out = append(out, fmt.Sprintf("%s|%s|%s", sidecar.Identity, "DNS", err))
		}

		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var sidecarStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of all known sidecars and their shared zones",
	Run: func(cmd *cobra.Command, args []string) {
		// Step 2: Implement the command logic
		response, err := sendStatusRequest()
		if err != nil {
			log.Fatalf("Error sending status request: %v", err)
		}

		// Step 3: Process the response
		displaySidecarStatus(response)
	},
}

func init() {
	//	rootCmd.AddCommand(showCmd)
	SidecarCmd.AddCommand(sidecarLocateCmd, sidecarIdentifyCmd, sidecarHelloCmd, sidecarDebugHelloCmd, sidecarStatusCmd)

	SidecarCmd.PersistentFlags().StringVarP(&sidecarId, "id", "i", "", "Identity of sidecar")
	SidecarCmd.PersistentFlags().StringVarP(&sidecarMethod, "method", "m", "", "Sidecar sync method")

	sidecarDebugHelloCmd.PersistentFlags().StringVarP(&tdns.Globals.BaseUri, "uri", "u", "", "URI of sidecar")
	sidecarDebugHelloCmd.PersistentFlags().StringVarP(&tdns.Globals.Address, "addr", "a", "", "Address of sidecar")
	sidecarDebugHelloCmd.PersistentFlags().Uint16VarP(&tdns.Globals.Port, "port", "p", 0, "Port of sidecar")
}

func sendStatusRequest() (music.SidecarResponse, error) {
	var response music.SidecarResponse

	// Create the SidecarPost with the "STATUS" command
	post := music.SidecarPost{
		Command: "status",
	}

	// Send the request to the /sidecar endpoint
	_, buf, err := tdns.Globals.Api.RequestNG("POST", "/sidecar", post, true)
	if err != nil {
		return response, fmt.Errorf("failed to send status request: %v", err)
	}

	// Unmarshal the response
	err = json.Unmarshal(buf, &response)
	if err != nil {
		return response, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

func displaySidecarStatus(response music.SidecarResponse) {
	if response.Error {
		log.Printf("Error: %s", response.ErrorMsg)
		return
	}

	for id, sidecar := range response.Sidecars {
		fmt.Printf("Sidecar ID: %s\n", id)
		if details, ok := sidecar.Details[tdns.MsignerMethodAPI]; ok {
			fmt.Printf("Shared Zones via API: %v\n", details.SharedZones)
		}
		if details, ok := sidecar.Details[tdns.MsignerMethodDNS]; ok {
			fmt.Printf("Shared Zones via DNS: %v\n", details.SharedZones)
		}
		fmt.Println("-----")
	}
}
