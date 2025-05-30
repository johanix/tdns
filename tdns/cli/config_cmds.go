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
	Short: "Send config reload command to tdns-server",
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
	Short: "Send reload-zones command to tdns-server",
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
	Short: "Send config status command to tdns-server",
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
			if len(resp.DnsEngine.Do53.Addresses) > 0 {
				fmt.Printf("DnsEngine: listening for UDP/TCP on %v\n", resp.DnsEngine.Do53.Addresses)
			} else {
				fmt.Printf("DnsEngine: not listening for UDP/TCP on any addresses\n")
			}

			if len(resp.DnsEngine.DoT.Addresses) > 0 {
				fmt.Printf("DnsEngine: listening for DoT connections on %v\n", resp.DnsEngine.DoT.Addresses)
			} else {
				fmt.Printf("DnsEngine: not listening for DoT connections on any addresses\n")
			}

			if len(resp.DnsEngine.DoH.Addresses) > 0 {
				fmt.Printf("DnsEngine: listening for DoH connections on %v\n", resp.DnsEngine.DoH.Addresses)
			} else {
				fmt.Printf("DnsEngine: not listening for DoH connections on any addresses\n")
			}

			if len(resp.DnsEngine.DoQ.Addresses) > 0 {
				fmt.Printf("DnsEngine: listening for DoQ connections on %v\n", resp.DnsEngine.DoQ.Addresses)
			} else {
				fmt.Printf("DnsEngine: not listening for DoQ connections on any addresses\n")
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
		return cr, fmt.Errorf("error from tdns-server: %s", cr.ErrorMsg)
	}

	return cr, nil
}
