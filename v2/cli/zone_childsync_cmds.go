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
	"github.com/ryanuber/columnize"
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

	// The childsync-proxy's commands (tdns-agent). The server refuses them
	// on a zone that is not a proxy.
	proxyCmd := func(command, short string) *cobra.Command {
		return &cobra.Command{
			Use:   command,
			Short: short,
			Run: func(cmd *cobra.Command, args []string) {
				PrepArgs("zonename")
				api, err := GetApiClient(role, true)
				if err != nil {
					log.Fatalf("Error: %v", err)
				}
				resp, err := SendChildSyncCommand(api, tdns.ZoneChildSyncPost{
					Command: command,
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
				if resp.Advert != "" {
					fmt.Printf("\n%s", resp.Advert)
				}
				printChildSyncProxyStatus(resp)
			},
		}
	}
	proxyStatus := proxyCmd("proxy-status", "Report a childsync-proxy's advertisement and push state")
	advert := proxyCmd("advert", "Print what the parent primary still lacks of the DSYNC advertisement, as an nsupdate block")
	reconcile := proxyCmd("reconcile", "Reconcile the advertisement and the known children against the served zone now")

	c.AddCommand(publish, unpublish, proxyStatus, advert, reconcile)
	return c
}

// printChildSyncProxyStatus renders the proxy and push state the server
// attached to a proxy command's response.
func printChildSyncProxyStatus(resp tdns.ZoneChildSyncResponse) {
	if resp.ProxyStatus != nil {
		ps := resp.ProxyStatus
		out := []string{"Advertisement|" + string(ps.State)}
		out = append(out, fmt.Sprintf("Records missing|%d", ps.Delta))
		if !ps.LastReconcile.IsZero() {
			out = append(out, "Last reconcile|"+ps.LastReconcile.Format("2006-01-02 15:04:05"))
		}
		if ps.Error != "" {
			out = append(out, "Error|"+ps.Error)
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
		if ps.Instruction != "" && resp.Advert == "" {
			fmt.Printf("\nTo publish at the primary by hand:\n%s", ps.Instruction)
		}
	}
	if resp.PushStatus != nil {
		pu := resp.PushStatus
		out := []string{fmt.Sprintf("Pushes pending|%d", len(pu.Pending))}
		if pu.Running {
			out = append(out, "Push worker|running")
		}
		if !pu.LastPush.IsZero() {
			out = append(out, "Last push|"+pu.LastPush.Format("2006-01-02 15:04:05"))
		}
		if !pu.LastOK.IsZero() {
			out = append(out, "Last push that landed|"+pu.LastOK.Format("2006-01-02 15:04:05"))
		}
		fmt.Printf("\n%s\n", columnize.SimpleFormat(out))
		if len(pu.Failures) > 0 {
			rows := []string{"Subject|Attempts|Terminal|Since|Error"}
			for _, f := range pu.Failures {
				rows = append(rows, fmt.Sprintf("%s|%d|%v|%s|%s", f.Subject, f.Attempts, f.Terminal, f.At.Format("15:04:05"), f.LastErr))
			}
			fmt.Printf("\nPushes that did not land:\n%s\n", columnize.SimpleFormat(rows))
		}
	}
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
