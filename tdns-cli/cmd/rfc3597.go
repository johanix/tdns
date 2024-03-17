/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var rrstr string

var ToRFC3597Cmd = &cobra.Command{
	Use:   "rfc3597",
	Short: "Generate the RFC 3597 representation of a DNS record",
	Run: func(cmd *cobra.Command, args []string) {
		if rrstr == "" {
			log.Fatalf("Record to generate RFC 3597 representation for not specified.")
		}

		rr, err := dns.NewRR(rrstr)
		if err != nil {
			log.Fatal("Could not parse record \"%s\": %v", rrstr, err)
		}

		fmt.Printf("Normal   (len=%d): \"%s\"\n", dns.Len(rr), rr.String())
		u := new(dns.RFC3597)
		u.ToRFC3597(rr)
		fmt.Printf("RFC 3597 (len=%d): \"%s\"\n", dns.Len(u), u.String())
	},
}

func init() {
     rootCmd.AddCommand(ToRFC3597Cmd)
	//	rootCmd.AddCommand(sendCmd)
	//	sendCmd.AddCommand(sendCdsCmd, sendCsyncCmd, sendDnskeyCmd, sendSoaCmd)
	//	rootCmd.AddCommand(torfc3597Cmd)

	//	sendCmd.PersistentFlags().StringVarP(&zonename, "zone", "z", "", "Zone to send a parent notify for")
	ToRFC3597Cmd.Flags().StringVarP(&rrstr, "record", "r", "", "Record to convert to RFC 3597 notation")
}

