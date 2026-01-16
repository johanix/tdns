/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var CombinerCmd = &cobra.Command{
	Use:   "combiner",
	Short: "TDNS Combiner commands",
}

// Helper function to compute the Rdlength for an RR
func xxxcomputeRdlen(rr dns.RR) (int, error) {
	// Create a buffer to pack the RR
	buf := make([]byte, 4096)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return 0, err
	}

	// The wire format for RR is:
	// [Name][Type][Class][TTL][Rdlength][Rdata]
	// To get Rdlen, subtract the header length from total length
	nameLen := len(rr.Header().Name)
	return off - nameLen - 10, nil // 10 bytes for Type(2), Class(2), TTL(4), Rdlength(2)
}

// Helper function to read and parse a zone file
func readZoneFile(filename string) (map[string][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	// Map to store RR strings by owner
	data := make(map[string][]string)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue // Skip empty lines and comments
		}

		// Verify the line is a valid RR
		rr, err := dns.NewRR(line)
		if err != nil {
			return nil, fmt.Errorf("error parsing line '%s': %v", line, err)
		}

		// Store the original line string, grouped by owner
		owner := rr.Header().Name
		data[owner] = append(data[owner], line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return data, nil
}

// Helper function to execute a combiner API request
func executeCombinerRequest(cmdName, zone, command string, data map[string][]string) (*tdns.CombinerResponse, error) {
	parent, _ := getCommandContext(cmdName)

	api, err := getApiClient(parent, true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %w", err)
	}

	req := tdns.CombinerPost{
		Command: command,
		Zone:    dns.Fqdn(zone),
		Data:    data,
	}

	_, buf, err := api.RequestNG("POST", "/combiner", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	var resp tdns.CombinerResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if resp.Error {
		return nil, fmt.Errorf("API error: %s", resp.ErrorMsg)
	}

	return &resp, nil
}

var combinerListDataCmd = &cobra.Command{
	Use:   "list-data",
	Short: "List local data added to a zone in the combiner",
	Long:  `List local data added to a zone in the combiner. Zone can be specified via --zone flag.`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		resp, err := executeCombinerRequest("list-data", tdns.Globals.Zonename, "list", nil)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if len(resp.Data) == 0 {
			fmt.Printf("No local data found for zone %s\n", tdns.Globals.Zonename)
			return
		}

		fmt.Printf("Local data for zone %s:\n", tdns.Globals.Zonename)

		// Get sorted list of owners for consistent output
		owners := make([]string, 0, len(resp.Data))
		for owner := range resp.Data {
			owners = append(owners, owner)
		}
		sort.Strings(owners)

		for _, owner := range owners {
			rrsets := resp.Data[owner]
			fmt.Printf("\n%s\n", owner)

			// Sort RRsets by type for consistent output
			sort.Slice(rrsets, func(i, j int) bool {
				return rrsets[i].RRtype < rrsets[j].RRtype
			})

			for _, rrset := range rrsets {
				// Print RRs
				for _, rr := range rrset.RRs {
					fmt.Printf("  %s\n", rr)
				}

				// Print RRSIGs if present
				for _, rrsig := range rrset.RRSIGs {
					fmt.Printf("  %s\n", rrsig)
				}
			}
		}
	},
}

var combinerAddDataCmd = &cobra.Command{
	Use:   "add-data [file]",
	Short: "Add local data to a zone passing through the combiner",
	Long: `Add local data to a zone passing through the combiner.

Zone can be specified via --zone flag. The file should contain one RR per line.

Example contents (for a zone named "example.com"):
  example.com. 86400 IN NS ns1.provider.com.
  example.com. 86400 IN NS ns2.service.net.
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		file := args[0]

		// Read and parse the zone file
		data, err := readZoneFile(file)
		if err != nil {
			log.Fatalf("Error reading zone file: %v", err)
		}

		resp, err := executeCombinerRequest("add-data", tdns.Globals.Zonename, "add", data)
		if err != nil {
			log.Fatalf("%v", err)
		}

		fmt.Println(resp.Msg)
	},
}

var combinerRemoveDataCmd = &cobra.Command{
	Use:   "remove-data [file]",
	Short: "Remove local data from a zone passing through the combiner",
	Long: `Remove local data from a zone passing through the combiner.

Zone can be specified via --zone flag. The file should contain one RR per line.

Example contents (for a zone named "example.com"):
  example.com. 86400 IN NS ns1.provider.com.
  example.com. 86400 IN NS ns2.service.net.
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		file := args[0]

		// Read and parse the zone file
		data, err := readZoneFile(file)
		if err != nil {
			log.Fatalf("Error reading zone file: %v", err)
		}

		resp, err := executeCombinerRequest("remove-data", tdns.Globals.Zonename, "remove", data)
		if err != nil {
			log.Fatalf("%v", err)
		}

		fmt.Println(resp.Msg)
	},
}

func init() {
	CombinerCmd.AddCommand(combinerAddDataCmd, combinerRemoveDataCmd, combinerListDataCmd)
}
