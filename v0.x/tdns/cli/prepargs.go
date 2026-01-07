/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/johanix/tdns/v0.x/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// PrepArgs validates and normalizes CLI parameters.
// It can work in two modes:
// 1. Legacy mode: reads from global variables (tdns.Globals.*)
// 2. Flag mode: reads from cobra.Command flags (pass cmd as first argument)
//
// Usage:
//   PrepArgs("zonename")                    // reads from tdns.Globals.Zonename
//   PrepArgs(cmd, "zonename")               // reads from --zone flag
//   PrepArgs(cmd, "zonename", "service")    // reads from --zone and --service flags
func PrepArgs(args ...interface{}) {
	var cmd *cobra.Command
	var required []string
	
	// Check if first argument is a *cobra.Command
	if len(args) > 0 {
		if c, ok := args[0].(*cobra.Command); ok {
			cmd = c
			// Convert remaining args to strings
			for i := 1; i < len(args); i++ {
				if s, ok := args[i].(string); ok {
					required = append(required, s)
				}
			}
		} else {
			// Legacy mode: all args are strings
			for _, arg := range args {
				if s, ok := arg.(string); ok {
					required = append(required, s)
				}
			}
		}
	}

	DefinedDnskeyStates := []string{"created", "published", "active", "retired", "foreign"}
	DefinedDnskeyTypes := []string{"KSK", "ZSK", "CSK"}
	// DefinedAlgorithms := []string{"RSASHA256", "RSASHA512", "ED25519", "ECDSAP256SHA256", "ECDSAP384SHA384"}

	for _, arg := range required {
		if tdns.Globals.Debug {
			fmt.Printf("Required: %s\n", arg)
		}
		switch arg {
		case "parentzone":
			if tdns.Globals.ParentZone == "" {
				fmt.Printf("Error: name of parent zone not specified\n")
				os.Exit(1)
			}
			tdns.Globals.ParentZone = dns.Fqdn(tdns.Globals.ParentZone)

		case "childzone", "child":
			if tdns.Globals.Zonename == "" {
				fmt.Printf("Error: name of child zone not specified\n")
				os.Exit(1)
			}
			tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)

		case "zonename":
			var zoneName string
			if cmd != nil {
				// Read from flag
				zoneFlag := cmd.Flag("zone")
				if zoneFlag == nil {
					fmt.Printf("Error: --zone flag not defined for this command\n")
					os.Exit(1)
				}
				zoneName = zoneFlag.Value.String()
			} else {
				// Read from global
				zoneName = tdns.Globals.Zonename
			}
			if zoneName == "" {
				fmt.Printf("Error: zone name not specified using --zone flag\n")
				os.Exit(1)
			}
			zoneName = dns.Fqdn(zoneName)
			// Store back to appropriate location
			if cmd != nil {
				// Update flag value (normalized)
				cmd.Flag("zone").Value.Set(zoneName)
			} else {
				tdns.Globals.Zonename = zoneName
			}

		case "agentid":
			if tdns.Globals.AgentId == "" {
				fmt.Printf("Error: agent id not specified using --agentid flag\n")
				os.Exit(1)
			}
			tdns.Globals.AgentId = tdns.AgentId(dns.Fqdn(string(tdns.Globals.AgentId)))

		case "keyid":
			if keyid == 0 {
				fmt.Printf("Error: key id not specified using --keyid flag\n")
				os.Exit(1)
			}

		case "parentprimary":
			if parpri == "" {
				fmt.Printf("Error: name of parent primary not specified\n")
				os.Exit(1)
			}
			if !strings.Contains(parpri, ":") {
				parpri = net.JoinHostPort(parpri, "53")
			}

		case "childprimary":
			if childpri == "" {
				fmt.Printf("Error: name of child primary not specified\n")
				os.Exit(1)
			}
			if !strings.Contains(childpri, ":") {
				childpri = net.JoinHostPort(childpri, "53")
			}

		case "filename":
			if filename == "" {
				fmt.Printf("Error: filename not specified\n")
				os.Exit(1)
			}
			_, err := os.ReadFile(filename)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				os.Exit(1)
			}

		case "src":
			if childSig0Src == "" {
				fmt.Printf("Error: source not specified\n")
				os.Exit(1)
			}

		case "algorithm":
			if tdns.Globals.Algorithm == "" {
				fmt.Printf("Error: algorithm not specified\n")
				os.Exit(1)
			}

			tdns.Globals.Algorithm = strings.ToUpper(tdns.Globals.Algorithm)
			_, exist := dns.StringToAlgorithm[tdns.Globals.Algorithm]
			if !exist {
				fmt.Printf("Error: algorithm \"%s\" is not known\n", tdns.Globals.Algorithm)
				os.Exit(1)
			}

		case "rrtype":
			if tdns.Globals.Rrtype == "" {
				fmt.Printf("Error: rrtype not specified\n")
				os.Exit(1)
			}
			rrtype, exist := dns.StringToType[strings.ToUpper(tdns.Globals.Rrtype)]
			if !exist {
				fmt.Printf("Error: rrtype \"%s\" is not known\n", tdns.Globals.Rrtype)
				os.Exit(1)
			}
			if rrtype != dns.TypeKEY && rrtype != dns.TypeDNSKEY {
				fmt.Printf("Error: rrtype \"%s\" is not KEY or DNSKEY\n", tdns.Globals.Rrtype)
				os.Exit(1)
			}

		case "keytype":
			if keytype == "" {
				fmt.Printf("Error: key type not specified (should be one of %v)\n", DefinedDnskeyTypes)
				os.Exit(1)
			}
			keytype = strings.ToUpper(keytype)
			if !slices.Contains(DefinedDnskeyTypes, keytype) {
				fmt.Printf("Error: key type \"%s\" is not known\n", keytype)
				os.Exit(1)
			}

		case "state":
			if NewState == "" {
				fmt.Printf("Error: key state not specified (should be one of %v)\n", DefinedDnskeyStates)
				os.Exit(1)
			}
			NewState = strings.ToLower(NewState)
			if !slices.Contains(DefinedDnskeyStates, NewState) {
				fmt.Printf("Error: key state \"%s\" is not known\n", NewState)
				os.Exit(1)
			}

		case "rollaction":
			rollaction = strings.ToLower(rollaction)
			if rollaction != "complete" && rollaction != "add" && rollaction != "remove" && rollaction != "update-local" {
				fmt.Printf("Error: roll action \"%s\" is not known\n", rollaction)
				os.Exit(1)
			}

		case "identity":
			if myIdentity == "" {
				fmt.Printf("Error: agent id not specified using --id flag\n")
				os.Exit(1)
			}
			tdns.Globals.AgentId = tdns.AgentId(dns.Fqdn(myIdentity))

		case "service":
			var serviceName string
			if cmd != nil {
				serviceFlag := cmd.Flag("service")
				if serviceFlag == nil {
					fmt.Printf("Error: --service flag not defined for this command\n")
					os.Exit(1)
				}
				serviceName = serviceFlag.Value.String()
			} else {
				// Could add a global variable if needed, but for now only flag mode
				fmt.Printf("Error: service parameter requires --service flag\n")
				os.Exit(1)
			}
			if serviceName == "" {
				fmt.Printf("Error: service name not specified using --service flag\n")
				os.Exit(1)
			}
			// Normalize: trim whitespace, but don't change case
			serviceName = strings.TrimSpace(serviceName)
			if cmd != nil {
				cmd.Flag("service").Value.Set(serviceName)
			}

		case "component":
			var componentName string
			if cmd != nil {
				componentFlag := cmd.Flag("component")
				if componentFlag == nil {
					fmt.Printf("Error: --component flag not defined for this command\n")
					os.Exit(1)
				}
				componentName = componentFlag.Value.String()
			} else {
				fmt.Printf("Error: component parameter requires --component flag\n")
				os.Exit(1)
			}
			if componentName == "" {
				fmt.Printf("Error: component name not specified using --component flag\n")
				os.Exit(1)
			}
			componentName = strings.TrimSpace(componentName)
			if cmd != nil {
				cmd.Flag("component").Value.Set(componentName)
			}

		case "nodeid":
			var nodeID string
			if cmd != nil {
				nodeFlag := cmd.Flag("nodeid")
				if nodeFlag == nil {
					fmt.Printf("Error: --nodeid flag not defined for this command\n")
					os.Exit(1)
				}
				nodeID = nodeFlag.Value.String()
			} else {
				// Legacy mode: read from global variable
				// Note: nodeid is defined in kdc_cmds.go as a global variable
				// We need to import it or access it via a function
				// For now, require flag mode
				fmt.Printf("Error: node parameter requires --nodeid flag\n")
				os.Exit(1)
			}
			if nodeID == "" {
				fmt.Printf("Error: node ID not specified using --nodeid flag\n")
				os.Exit(1)
			}
			// Normalize to FQDN
			nodeID = dns.Fqdn(nodeID)
			if cmd != nil {
				cmd.Flag("nodeid").Value.Set(nodeID)
			}
			// Also update global variable if it exists (for backward compatibility)
			// Note: This requires access to the global variable from kdc_cmds.go
			// For now, we'll just update the flag

		case "distid":
			var distID string
			if cmd != nil {
				distFlag := cmd.Flag("distid")
				if distFlag == nil {
					fmt.Printf("Error: --distid flag not defined for this command\n")
					os.Exit(1)
				}
				distID = distFlag.Value.String()
			} else {
				fmt.Printf("Error: distid parameter requires --distid flag\n")
				os.Exit(1)
			}
			if distID == "" {
				fmt.Printf("Error: distribution ID not specified using --distid flag\n")
				os.Exit(1)
			}
			// Trim whitespace
			distID = strings.TrimSpace(distID)
			if cmd != nil {
				cmd.Flag("distid").Value.Set(distID)
			}

		case "sname":
			var serviceName string
			if cmd != nil {
				serviceFlag := cmd.Flag("sname")
				if serviceFlag == nil {
					fmt.Printf("Error: --sname flag not defined for this command\n")
					os.Exit(1)
				}
				serviceName = serviceFlag.Value.String()
			} else {
				fmt.Printf("Error: service name not specified using --sname flag\n")
				os.Exit(1)
			}
			if serviceName == "" {
				fmt.Printf("Error: service name not specified using --sname flag\n")
				os.Exit(1)
			}
			serviceName = strings.TrimSpace(serviceName)
			if cmd != nil {
				cmd.Flag("sname").Value.Set(serviceName)
			}

		case "cname":
			var componentName string
			if cmd != nil {
				componentFlag := cmd.Flag("cname")
				if componentFlag == nil {
					fmt.Printf("Error: --cname flag not defined for this command\n")
					os.Exit(1)
				}
				componentName = componentFlag.Value.String()
			} else {
				fmt.Printf("Error: component name not specified using --cname flag\n")
				os.Exit(1)
			}
			if componentName == "" {
				fmt.Printf("Error: component name not specified using --cname flag\n")
				os.Exit(1)
			}
			componentName = strings.TrimSpace(componentName)
			if cmd != nil {
				cmd.Flag("cname").Value.Set(componentName)
			}

		case "tx":
			var txID string
			if cmd != nil {
				txFlag := cmd.Flag("tx")
				if txFlag == nil {
					fmt.Printf("Error: --tx flag not defined for this command\n")
					os.Exit(1)
				}
				txID = txFlag.Value.String()
			} else {
				fmt.Printf("Error: transaction ID not specified using --tx flag\n")
				os.Exit(1)
			}
			if txID == "" {
				fmt.Printf("Error: transaction ID not specified using --tx flag\n")
				os.Exit(1)
			}
			txID = strings.TrimSpace(txID)
			if cmd != nil {
				cmd.Flag("tx").Value.Set(txID)
			}

		default:
			fmt.Printf("Unknown required argument: \"%s\"\n", arg)
			os.Exit(1)
		}
	}
}
