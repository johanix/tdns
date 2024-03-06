/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/cobra"
)

var pings, fetches, updates int

var PingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Send a ping request to the upstream nameserver, used for debugging",
	Run: func(cmd *cobra.Command, args []string) {
		PingUpstreamServer()
	},
}

func init() {
	rootCmd.AddCommand(PingCmd)
	PingCmd.Flags().IntVarP(&pings, "count", "c", 1, "ping counter to send to server")
}

func PingUpstreamServer() {

	data := tdns.PingPost{
		Pings: pings,
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/ping", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return
	}
	if verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var pr tdns.PingResponse

	err = json.Unmarshal(buf, &pr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	fmt.Printf("Pings: %d Pongs: %d Message: %s\n", pr.Pings, pr.Pongs, pr.Message)
}
