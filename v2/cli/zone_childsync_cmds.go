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

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// newZoneChildSyncCmd returns a fresh "childsync" subtree for the parent role.
func newZoneChildSyncCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "childsync",
		Short: "Parent-side child delegation sync commands",
	}

	publish := &cobra.Command{
		Use:   "publish",
		Short: "Publish the DSYNC RRset into the zone",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendChildSyncCommand(api, tdns.ZoneChildSyncPost{
				Command: "publish",
				Zone:    dns.Fqdn(tdns.Globals.Zonename),
			})
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}
			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}

	unpublish := &cobra.Command{
		Use:   "unpublish",
		Short: "Unpublish the DSYNC RRset from the zone",
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs("zonename")
			api, err := GetApiClient(role, true)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			resp, err := SendChildSyncCommand(api, tdns.ZoneChildSyncPost{
				Command: "unpublish",
				Zone:    dns.Fqdn(tdns.Globals.Zonename),
			})
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from server: %s\n", resp.ErrorMsg)
				os.Exit(1)
			}
			if resp.Msg != "" {
				fmt.Printf("%s\n", resp.Msg)
			}
		},
	}

	c.AddCommand(publish, unpublish)
	return c
}

// SendChildSyncCommand POSTs a ZoneChildSyncPost to /zone/childsync.
func SendChildSyncCommand(api *tdns.ApiClient, data tdns.ZoneChildSyncPost) (tdns.ZoneChildSyncResponse, error) {
	var cr tdns.ZoneChildSyncResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/zone/childsync", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return cr, fmt.Errorf("error from api post: %v", err)
	}
	if status != 200 && tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from unmarshal: %v", err)
	}
	// cr.Error is NOT turned into a Go error: the callers render it
	// themselves ("Error from server: ..."), and wrapping it here made that
	// branch unreachable and doubled the prefix on the path that did run.
	// A non-nil error from this function means the exchange failed.
	return cr, nil
}
