/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"log"
	"strings"

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
	//	rootCmd.AddCommand(sendCmd)
	//	sendCmd.AddCommand(sendCdsCmd, sendCsyncCmd, sendDnskeyCmd, sendSoaCmd)
	//	rootCmd.AddCommand(torfc3597Cmd)

	//	sendCmd.PersistentFlags().StringVarP(&zonename, "zone", "z", "", "Zone to send a parent notify for")
	ToRFC3597Cmd.Flags().StringVarP(&rrstr, "record", "r", "", "Record to convert to RFC 3597 notation")
}

func ParentZone(z, imr string) string {
	labels := strings.Split(z, ".")
	var parent string

	if len(labels) == 1 {
		return z
	} else if len(labels) > 1 {
		upone := dns.Fqdn(strings.Join(labels[1:], "."))

		m := new(dns.Msg)
		m.SetQuestion(upone, dns.TypeSOA)
		m.SetEdns0(4096, true)
		m.CheckingDisabled = true

		r, err := dns.Exchange(m, imr)
		if err != nil {
			return fmt.Sprintf("Error from dns.Exchange: %v\n", err)
		}
		if r != nil {
			if len(r.Answer) != 0 {
				parent = r.Answer[0].Header().Name
				return parent
			}
			if len(r.Ns) > 0 {
				for _, rr := range r.Ns {
					if rr.Header().Rrtype == dns.TypeSOA {
						parent = r.Ns[0].Header().Name
						return parent
					}
				}
			}

			log.Printf("ParentZone: ERROR: Failed to locate parent of '%s' via Answer and Authority. Now guessing.", z)
			return upone
		}
	}
	log.Printf("ParentZone: had difficulties splitting zone '%s'\n", z)
	return z
}
