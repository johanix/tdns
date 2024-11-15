/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/cobra"
)

var force bool

var StopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Send stop command to tdns-server / tdns-agent",
	Run: func(cmd *cobra.Command, args []string) {
		SendCommand("stop", ".")
	},
}

var showhdr, showfile, shownotify, showprimary bool

func init() {
}

func SendCommand(cmd, zone string) (string, error) {

	data := tdns.CommandPost{
		Command: cmd,
		Zone:    zone,
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := tdns.Globals.Api.Post("/command", bytebuf.Bytes())
	if err != nil {

		return "", fmt.Errorf("error from api post: %v", err)
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var cr tdns.CommandResponse

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return "", fmt.Errorf("error from unmarshal: %v", err)
	}

	if cr.Error {
		return "", fmt.Errorf("error from tdnsd: %s", cr.ErrorMsg)
	}

	return cr.Msg, nil
}

func SendCommandNG(api *tdns.ApiClient, data tdns.CommandPost) (tdns.CommandResponse, error) {
	var cr tdns.CommandResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/command", bytebuf.Bytes())
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
		return cr, fmt.Errorf("error from tdnsd: %s", cr.ErrorMsg)
	}

	return cr, nil
}
