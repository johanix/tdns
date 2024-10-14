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
	Short: "Prefix command, not useable by itself",
}

var configReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Send config reload command to tdns-server",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := SendConfigCommand(tdns.Globals.Api, tdns.ConfigPost{
			Command: "reload",
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-server: %s\n", resp.ErrorMsg)
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
		resp, err := SendConfigCommand(tdns.Globals.Api, tdns.ConfigPost{
			Command: "reload-zones",
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-server: %s\n", resp.ErrorMsg)
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
		resp, err := SendConfigCommand(tdns.Globals.Api, tdns.ConfigPost{
			Command: "status",
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.Error {
			fmt.Printf("Error from tdns-server: %s\n", resp.ErrorMsg)
			os.Exit(1)
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
