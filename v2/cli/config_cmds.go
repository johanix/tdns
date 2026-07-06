/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// NewConfigCmd returns a fresh "config" command tree bound to the given
// role. Each attachment point gets its own *cobra.Command.
func NewConfigCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Commands to reload config, reload zones, etc",
	}

	reload := &cobra.Command{
		Use:   "reload",
		Short: "Send config reload command to tdns-auth",
		Run: func(cmd *cobra.Command, args []string) {
			runConfigCmd(role, "reload", false)
		},
	}

	reloadZones := &cobra.Command{
		Use:   "reload-zones",
		Short: "Send reload-zones command to tdns-auth",
		Run: func(cmd *cobra.Command, args []string) {
			runConfigCmd(role, "reload-zones", false)
		},
	}

	var force, interactive bool
	reloadTsig := &cobra.Command{
		Use:   "reload-tsig",
		Short: "Reconcile keys.tsig into the TSIG keystore (config reload-tsig)",
		Long: `Re-read keys.tsig from the config file and reconcile into the DB-backed
TSIG keystore. Secret conflicts are withheld by default; use --force to
overwrite all conflicts, or --interactive to prompt per conflict.`,
		Run: func(cmd *cobra.Command, args []string) {
			runReloadTsigCmd(role, force, interactive)
		},
	}
	reloadTsig.Flags().BoolVar(&force, "force", false, "overwrite all secret/algorithm conflicts with keys.tsig")
	reloadTsig.Flags().BoolVar(&interactive, "interactive", false, "prompt per conflict before overwriting")

	status := &cobra.Command{
		Use:   "status",
		Short: "Send config status command to tdns-auth",
		Run: func(cmd *cobra.Command, args []string) {
			runConfigCmd(role, "status", true)
		},
	}

	c.AddCommand(reload, reloadZones, reloadTsig, status)
	return c
}

func runReloadTsigCmd(role string, force, interactive bool) {
	if tsigForceInteractiveConflict(force, interactive) {
		fmt.Println("Error: --force and --interactive are mutually exclusive")
		os.Exit(1)
	}
	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	post := tdns.ConfigPost{Command: "reload-tsig", Force: force}
	if interactive {
		requireInteractiveTTY()
		probe, err := SendConfigCommand(api, tdns.ConfigPost{Command: "reload-tsig"})
		if err != nil && len(probe.TsigConflicts) == 0 {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if len(probe.TsigConflicts) == 0 {
			if probe.Msg != "" {
				fmt.Println(probe.Msg)
			}
			if reloadTsigWithheld(probe) {
				os.Exit(1)
			}
			return
		}
		reader := bufio.NewReader(os.Stdin)
		var overwrite []string
		for _, name := range probe.TsigConflicts {
			fmt.Printf("Overwrite TSIG key %q with keys.tsig? [y/N] ", name)
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(strings.ToLower(line))
			if line == "y" || line == "yes" {
				overwrite = append(overwrite, name)
			}
		}
		if len(overwrite) == 0 {
			fmt.Println("No keys overwritten.")
			os.Exit(1) // withheld conflicts remain — signal incomplete reconciliation
		}
		post.TsigOverwrite = overwrite
	}

	resp, err := SendConfigCommand(api, post)
	if err != nil {
		if resp.Msg != "" {
			fmt.Println(resp.Msg)
		}
		if reloadTsigWithheld(resp) {
			os.Exit(1)
		}
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	if resp.Error {
		fmt.Printf("Error from %s: %s\n", resp.AppName, resp.ErrorMsg)
		os.Exit(1)
	}
	if resp.Msg != "" {
		fmt.Println(resp.Msg)
	}
	if reloadTsigWithheld(resp) {
		os.Exit(1)
	}
}

// reloadTsigWithheld reports whether the reload-tsig response withheld changes.
func reloadTsigWithheld(resp tdns.ConfigResponse) bool {
	n := len(resp.TsigConflicts) + len(resp.TsigWithheldRemovals)
	if n == 0 {
		return false
	}
	fmt.Fprintf(os.Stderr, "%d TSIG reconcile item(s) withheld (conflicts or referenced removals)\n", n)
	return true
}

// runConfigCmd posts a ConfigPost with the given command and prints the
// response. showVerboseStatus expands the verbose dump used by the
// "status" subcommand.
func runConfigCmd(role, command string, showVerboseStatus bool) {
	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	resp, err := SendConfigCommand(api, tdns.ConfigPost{Command: command})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	if resp.Error {
		fmt.Printf("Error from %s: %s\n", resp.AppName, resp.ErrorMsg)
		os.Exit(1)
	}

	if showVerboseStatus && tdns.Globals.Verbose {
		fmt.Printf("Status for %s:\n", resp.AppName)
		if len(resp.DnsEngine.Addresses) > 0 {
			fmt.Printf("DnsEngine: listening on %v\n", resp.DnsEngine.Addresses)
			fmt.Printf("DnsEngine: active transports: %v\n", resp.DnsEngine.Transports)
		} else {
			fmt.Printf("DnsEngine: not listening on any addresses\n")
		}
		if len(resp.DnsEngine.Options) > 0 {
			fmt.Printf("DnsEngine: auth options:\n")
			for opt, val := range resp.DnsEngine.Options {
				optName, ok := tdns.AuthOptionToString[opt]
				if !ok {
					optName = fmt.Sprintf("unknown option %d", opt)
				}
				if val != "" {
					fmt.Printf("  %s: %s\n", optName, val)
				} else {
					fmt.Printf("  %s: (enabled)\n", optName)
				}
			}
		} else if len(resp.DnsEngine.OptionsStrs) > 0 {
			fmt.Printf("DnsEngine: auth options:\n")
			for _, optStr := range resp.DnsEngine.OptionsStrs {
				fmt.Printf("  %s\n", optStr)
			}
		} else {
			fmt.Printf("DnsEngine: no auth options configured\n")
		}
		if resp.DBFile != "" {
			fmt.Printf("DB: %s\n", resp.DBFile)
		} else {
			fmt.Printf("DB: not configured\n")
		}
		if len(resp.Identities) > 0 {
			fmt.Printf("Identities: %v\n", resp.Identities)
		} else {
			fmt.Printf("Identities: not set\n")
		}

		if len(resp.ApiServer.Addresses) > 0 {
			fmt.Printf("ApiServer: listening on %v\n", resp.ApiServer.Addresses)
		} else {
			fmt.Printf("ApiServer: not listening on any addresses\n")
		}
		if resp.ApiServer.ApiKey.Value() != "" {
			ak := resp.ApiServer.ApiKey.Value()
			// Reveal 3 chars at each end only when the key is long
			// enough that the reveal doesn't expose the whole secret
			// (>= 8 chars). Shorter keys are fully masked.
			if len(ak) >= 8 {
				fmt.Printf("ApiServer: api key (%d characters): %s***%s\n", len(ak), ak[:3], ak[len(ak)-3:])
			} else {
				fmt.Printf("ApiServer: api key (%d characters): ***\n", len(ak))
			}
		} else {
			fmt.Printf("ApiServer: api key is not set\n")
		}
	}

	if resp.Msg != "" {
		fmt.Printf("%s\n", resp.Msg)
	}
}

func SendConfigCommand(api *tdns.ApiClient, data tdns.ConfigPost) (tdns.ConfigResponse, error) {
	var cr tdns.ConfigResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/config", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return cr, fmt.Errorf("error from api post: %v", err)
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if cr.Error {
		return cr, fmt.Errorf("error from tdns-auth: %s", cr.ErrorMsg)
	}

	return cr, nil
}
