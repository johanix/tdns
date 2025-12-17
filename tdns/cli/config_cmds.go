/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/cobra"
)

var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Commands to reload config, reload zones, etc",
}

var configReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Send config reload command to tdns-auth",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("config")
		api, _ := getApiClient(prefixcmd, true)

		resp, err := SendConfigCommand(api, tdns.ConfigPost{
			Command: "reload",
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from %s: %s\n", resp.AppName, resp.ErrorMsg)
			os.Exit(1)
		}

		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var configReloadZonesCmd = &cobra.Command{
	Use:   "reload-zones",
	Short: "Send reload-zones command to tdns-auth",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("config")
		api, _ := getApiClient(prefixcmd, true)

		resp, err := SendConfigCommand(api, tdns.ConfigPost{
			Command: "reload-zones",
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from %s: %s\n", resp.AppName, resp.ErrorMsg)
			os.Exit(1)
		}

		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

var configStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Send config status command to tdns-auth",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("config")
		api, _ := getApiClient(prefixcmd, true)

		resp, err := SendConfigCommand(api, tdns.ConfigPost{
			Command: "status",
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from %s: %s\n", resp.AppName, resp.ErrorMsg)
			os.Exit(1)
		}

		if tdns.Globals.Verbose {
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
			if resp.ApiServer.ApiKey != "" {
				fmt.Printf("ApiServer: api key (%d characters): %s***%s\n", len(resp.ApiServer.ApiKey), resp.ApiServer.ApiKey[:3], resp.ApiServer.ApiKey[len(resp.ApiServer.ApiKey)-3:])
			} else {
				fmt.Printf("ApiServer: api key is not set\n")
			}
		}

		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
	},
}

func init() {
	ConfigCmd.AddCommand(configReloadCmd, configReloadZonesCmd, configStatusCmd)
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
