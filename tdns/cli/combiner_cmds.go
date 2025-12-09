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

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var CombinerCmd = &cobra.Command{
	Use:   "combiner",
	Short: "TDNS Combiner commands",
}

// Helper function to compute the Rdlength for an RR
func computeRdlen(rr dns.RR) (int, error) {
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

var combinerListDataCmd = &cobra.Command{
	Use:   "list-data [zone]",
	Short: "List local data added to a zone in the combiner",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := getCommandContext("list-data")
		zone := args[0]

		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.CombinerPost{
			Command: "list",
			Zone:    zone,
		}

		_, buf, err := api.RequestNG("POST", "/combiner", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp tdns.CombinerResponse
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if resp.Error {
			log.Fatalf("API error: %s", resp.ErrorMsg)
		}

		if len(resp.Data) == 0 {
			fmt.Printf("No local data found for zone %s\n", zone)
			return
		}

		fmt.Printf("Local data for zone %s:\n", zone)

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
	Use:   "add-data [zone] [file]",
	Short: "Add local data to a zone passing through the combiner",
	Long: `Add local data to a zone passing through the combiner.

The file should contain one RR per line.

Example contents (for a zone named "example.com"):
  example.com. 86400 IN NS ns1.provider.com.
  example.com. 86400 IN NS ns2.service.net.
`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := getCommandContext("add-data")
		zone := dns.Fqdn(args[0])
		file := args[1]

		// Read and parse the zone file
		data, err := readZoneFile(file)
		if err != nil {
			log.Fatalf("Error reading zone file: %v", err)
		}

		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.CombinerPost{
			Command: "add",
			Zone:    zone,
			Data:    data,
		}

		_, buf, err := api.RequestNG("POST", "/combiner", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp tdns.CombinerResponse
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if resp.Error {
			log.Fatalf("API error: %s", resp.ErrorMsg)
		}

		fmt.Println(resp.Msg)
	},
}

var combinerRemoveDataCmd = &cobra.Command{
	Use:   "remove-data [zone] [file]",
	Short: "Remove local data from a zone passing through the combiner",
	Long: `Remove local data from a zone passing through the combiner.
The file should contain one RR per line.

Example contents (for a zone named "example.com"):
  example.com. 86400 IN NS ns1.provider.com.
  example.com. 86400 IN NS ns2.service.net.
`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		parent, _ := getCommandContext("remove-data")
		zone := dns.Fqdn(args[0])
		file := args[1]

		// Read and parse the zone file
		data, err := readZoneFile(file)
		if err != nil {
			log.Fatalf("Error reading zone file: %v", err)
		}

		api, err := getApiClient(parent, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.CombinerPost{
			Command: "remove",
			Zone:    zone,
			Data:    data,
		}

		_, buf, err := api.RequestNG("POST", "/combiner", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp tdns.CombinerResponse
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if resp.Error {
			log.Fatalf("API error: %s", resp.ErrorMsg)
		}

		fmt.Println(resp.Msg)
	},
}

func init() {
	CombinerCmd.AddCommand(combinerAddDataCmd, combinerRemoveDataCmd, combinerListDataCmd)
}
