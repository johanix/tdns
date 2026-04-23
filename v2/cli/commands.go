/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

var force bool
var showError bool
var errorTimeout string

var showfile, shownotify, showprimary bool

// NewStopCmd returns a fresh "stop" *cobra.Command bound to the given
// role. Each attachment site must create its own command (root "server"
// default in tdns-cli; signer / combiner / agent in mpcli).
func NewStopCmd(role string) *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Send stop command to the daemon",
		Run: func(cmd *cobra.Command, args []string) {
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error getting API client: %v", err)
			}
			resp, err := SendCommandNG(api, tdns.CommandPost{
				Command: "stop",
				Zone:    ".",
			})
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}
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
	// Only print status if it's not 200 (success) - useful for debugging errors
	if status != 200 && tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if cr.Error {
		return cr, fmt.Errorf("error from %s: %s", cr.AppName, cr.ErrorMsg)
	}

	return cr, nil
}
