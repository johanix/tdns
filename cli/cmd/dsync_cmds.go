/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	// "github.com/spf13/viper"
)

var DsyncDiscoveryCmd = &cobra.Command{
	Use:   "dsync-query",
	Short: "Send a DNS query for 'zone. DSYNC' and present the result.",
	Run: func(cmd *cobra.Command, args []string) {
		tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)
		tdns.SetupIMR()

		dsync_res, err := tdns.DsyncDiscovery(tdns.Globals.Zonename,
			tdns.Globals.IMR, tdns.Globals.Verbose)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		fmt.Printf("Parent: %s\n", dsync_res.Parent)
		if len(dsync_res.Rdata) == 0 {
			fmt.Printf("No DSYNC record associated with '%s'\n", tdns.Globals.Zonename)
		} else {
			for _, nr := range dsync_res.Rdata {
				fmt.Printf("%s\tIN\tDSYNC\t%s\n", dsync_res.Qname, nr.String())
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(DsyncDiscoveryCmd)
	DsyncDiscoveryCmd.PersistentFlags().StringVarP(&tdns.Globals.IMR, "imr", "i", "",
		"IMR to send the query to")
}

// func SetupIMR() {
// 	if tdns.Globals.IMR == "" {
// 		tdns.Globals.IMR = viper.GetString("resolver.address")
// 	}
//
// 	if tdns.Globals.Verbose {
// 		fmt.Printf("Using resolver \"%s\"\n", tdns.Globals.IMR)
// 	}
// }
