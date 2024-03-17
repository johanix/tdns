/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var ddnsCmd = &cobra.Command{
	Use:   "ddns",
	Short: "Send a DDNS update. Only usable via sub-commands.",
}

var ddnsSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Send a DDNS update to sync parent delegation info with child data",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			log.Fatalf("Error: child zone name not specified.")
		}
		tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)

		if tdns.Globals.ParentZone == "" {
		   log.Fatalf("Error: parent zone name not specified.")
		}
		tdns.Globals.ParentZone = dns.Fqdn(tdns.Globals.ParentZone)

		if childpri == "" {
		   log.Fatalf("Error: child primary nameserver not specified.")
		}
		if parpri == "" {
		   log.Fatalf("Error: parent primary nameserver not specified.")
		}

		unsynched, adds, removes, err := tdns.ChildDelegationDataUnsynched(tdns.Globals.Zonename, tdns.Globals.ParentZone, childpri, parpri)
		if err != nil {
			log.Fatalf("Error from ChildSyncDelegationData(): %v", err)
		}
		if !unsynched {
			fmt.Printf("No change to delegation data. No need to update.\n")
			os.Exit(0)
		}
		err = tdns.ChildSendDdnsSync(adds, removes)
		if err != nil {
			log.Fatalf("Error from ChildSendDdnsSync(): %v", err)
		}
	},
}

var ddnsRollCmd = &cobra.Command{
	Use:   "roll",
	Short: "Send a DDNS update to roll the SIG(0) key used to sign updates",
	Run: func(cmd *cobra.Command, args []string) {
		err := tdns.SendSig0KeyUpdate(true)
		if err != nil {
			fmt.Printf("Error from SendSig0KeyUpdate(): %v", err)
		}
	},
}

var ddnsUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Send a DDNS update to upload the initial SIG(0) public key to parent",
	Run: func(cmd *cobra.Command, args []string) {
		err := tdns.SendSig0KeyUpdate(false)
		if err != nil {
			fmt.Printf("Error from SendSig0KeyUpdate(): %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(ddnsCmd)

	ddnsCmd.AddCommand(ddnsSyncCmd)
	ddnsCmd.AddCommand(ddnsRollCmd, ddnsUploadCmd)

	ddnsCmd.PersistentFlags().StringVarP(&tdns.Globals.Sig0Keyfile, "keyfile", "k", "", "name of file with private SIG(0) key")
	ddnsCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	ddnsCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
}

