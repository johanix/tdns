/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/johanix/tdns/v0.x"
	"github.com/spf13/cobra"
)

// Default domain suffix for CLI
const DefaultDomainSuffix = "example.com."

// base32Cmd represents the base32 command
var Base32Cmd = &cobra.Command{
	Use:   "base32",
	Short: "Convert data to/from base32 encoding and domain format",
	Long: `This command converts data to or from base32 encoding and domain format.
It can read from standard input or from a file.

Examples:
  echo '{"name":"example","value":123}' | tdns base32 encode --suffix=example.com.
  cat domains.txt | tdns base32 decode`,
}

// encodeCmd represents the encode subcommand
var Base32encodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "Encode JSON data to base32 domain format",
	Long:  `Encode JSON data from stdin to base32 domain format.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if stdin is being piped
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Println("No stdin data provided. Please pipe JSON data to this command.")
			fmt.Println("Example: echo '{\"name\":\"example\"}' | tdns base32 encode --suffix=example.com.")
			return
		}

		// Get flags
		suffix, _ := cmd.Flags().GetString("suffix")
		cookie, _ := cmd.Flags().GetString("cookie")

		// Validate suffix
		if suffix == "" {
			fmt.Fprintf(os.Stderr, "Error: domain suffix is required. Use --suffix flag.\n")
			return
		}

		// Ensure suffix ends with a dot
		if !strings.HasSuffix(suffix, ".") {
			suffix += "."
			fmt.Fprintf(os.Stderr, "Note: Added trailing dot to domain suffix: %s\n", suffix)
		}

		// Process stdin
		reader := bufio.NewReader(os.Stdin)
		processJsonToBase32Domains(reader, suffix, cookie)
	},
}

// decodeCmd represents the decode subcommand
var Base32decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "Decode base32 domain data to JSON",
	Long:  `Decode base32 domain data from stdin to JSON.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if stdin is being piped
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Println("No stdin data provided. Please pipe domain data to this command.")
			fmt.Println("Example: cat domains.txt | tdns base32 decode")
			return
		}

		// Get cookie flag
		cookie, _ := cmd.Flags().GetString("cookie")

		// Process stdin
		reader := bufio.NewReader(os.Stdin)
		processBase32DomainsToJson(reader, cmd, cookie)
	},
}

func init() {
	// Add base32 command to root command
	// RootCmd.AddCommand(base32Cmd)

	// Add subcommands to base32 command
	Base32Cmd.AddCommand(Base32encodeCmd)
	Base32Cmd.AddCommand(Base32decodeCmd)

	// Add flags for encode command
	Base32encodeCmd.Flags().StringP("suffix", "s", DefaultDomainSuffix, "Domain suffix to append (FQDN, must end with a dot)")
	Base32encodeCmd.Flags().StringP("cookie", "c", tdns.DefaultCookie, "Cookie prefix for chunk identification")
	Base32encodeCmd.MarkFlagRequired("suffix")

	// Add flags for decode command
	Base32decodeCmd.Flags().BoolP("pretty", "p", false, "Pretty-print JSON output")
	Base32decodeCmd.Flags().StringP("cookie", "c", tdns.DefaultCookie, "Cookie prefix for chunk identification")
}

func processJsonToBase32Domains(reader *bufio.Reader, suffix string, cookie string) {
	// Read all input at once
	jsonData, err := io.ReadAll(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		return
	}

	// Convert JSON to base32 domains
	domains, err := tdns.JsonToBase32Domains(jsonData, suffix, cookie)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting JSON to base32 domains: %v\n", err)
		return
	}

	// Output the domains
	for _, domain := range domains {
		fmt.Println(domain)
	}

	// Count total chunks correctly
	totalChunks := 0
	cookieLen := len(cookie)
	for _, domain := range domains {
		// Split the domain into parts
		parts := strings.Split(domain, ".")

		// Count only the parts that have the cookie prefix
		for _, part := range parts {
			if len(part) > cookieLen && strings.HasPrefix(part, cookie) {
				totalChunks++
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Converted %d bytes of JSON to %d domain names with %d total chunks\n",
		len(jsonData), len(domains), totalChunks)
}

func processBase32DomainsToJson(reader *bufio.Reader, cmd *cobra.Command, cookie string) {
	var domains []string
	pretty, _ := cmd.Flags().GetBool("pretty")

	// Read domains line by line
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			return
		}

		// Trim whitespace
		domain := strings.TrimSpace(line)
		if domain == "" {
			continue
		}

		domains = append(domains, domain)
	}

	// Convert domains to JSON
	jsonData, err := tdns.DomainsToJson(domains, cookie)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting domains to JSON: %v\n", err)
		return
	}

	// Output the JSON
	if pretty {
		var prettyJSON bytes.Buffer
		err = json.Indent(&prettyJSON, jsonData, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			fmt.Println(string(jsonData)) // Fallback to non-pretty output
		} else {
			fmt.Println(prettyJSON.String())
		}
	} else {
		fmt.Println(string(jsonData))
	}

	// Print summary
	fmt.Fprintf(os.Stderr, "Converted %d domain names to %d bytes of JSON\n",
		len(domains), len(jsonData))
}
