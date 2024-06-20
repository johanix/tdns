/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package cmd

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var short bool
var rrtype uint16

var port = "53"
var server = "8.8.8.8"

var rootCmd = &cobra.Command{
	Use:   "dog",
	Short: "CLI utility used issue DNS queries and present the result",

	Run: func(cmd *cobra.Command, args []string) {

		var cleanArgs []string
		var do_bit = false
//		var err error
		var serial uint32

		for _, arg := range args {
			if strings.HasPrefix(arg, "@") {
				server = arg[1:]
				if tdns.Globals.Verbose {
					fmt.Printf("*** Will send remaining queries to server %s\n", server)
				}
				continue
			}

			ucarg := strings.ToUpper(arg)
			if foo, exist := dns.StringToType[ucarg]; exist {
				rrtype = foo
				continue
			}

			if strings.HasPrefix(ucarg, "IXFR=") {
			   serialstr, _ := strings.CutPrefix(ucarg, "IXFR=")
			   tmp, err := strconv.Atoi(serialstr)
			   if err != nil {
			      log.Fatalf("Error: %v", err)
			   }
			   serial = uint32(tmp)
			   fmt.Printf("RRtype is ixfr, using base serial %d\n", serial)
			}

			if ucarg == "+DNSSEC" {
			   do_bit = true
			   continue
			}

			cleanArgs = append(cleanArgs, arg)
		}

		if rrtype == 0 {
			rrtype = dns.TypeA
		}

		if port != "53" {
			_, err := strconv.Atoi(port)
			if err != nil {
				fmt.Printf("Error: port \"%s\" is not valid: %v\n", port, err)
			}
		}

		server = server + ":" + port

		for _, qname := range cleanArgs {
			fmt.Printf("dog processing arg \"%s\"\n", qname)

			qname = dns.Fqdn(qname)
			if tdns.Globals.Verbose {
				fmt.Printf("*** Querying for %s IN %s:\n", qname, dns.TypeToString[rrtype])
			}

			switch rrtype {
			case dns.TypeAXFR, dns.TypeIXFR:
				tdns.ZoneTransferPrint(qname, server, serial, rrtype)

			default:

				m := new(dns.Msg)
				m.SetQuestion(qname, rrtype)
				m.SetEdns0(4096, do_bit)
				res, err := dns.Exchange(m, server)
				if err != nil {
					fmt.Printf("Error from %s: %v\n", server, err)
					os.Exit(1)
				}
				if short {
					for _, rr := range res.Answer {
						fmt.Printf("%s\n", rr.String())
					}
				} else {
					fmt.Printf(res.String())
				}
			}
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "Verbose mode")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "Debugging output")
	rootCmd.PersistentFlags().BoolVarP(&short, "short", "", false, "Only list RRs that are part of the Answer section")
	//	rootCmd.PersistentFlags().StringVarP(&rrtype, "rrtype", "r", "", "DNS RR type to query for")
	rootCmd.PersistentFlags().StringVarP(&port, "port", "p", "53", "Port to send DNS query to")

	err := tdns.RegisterNotifyRR()
	if err != nil {
		fmt.Printf("Error registering NOTIFY RR type: %v\n", err)
	}
	err = tdns.RegisterDsyncRR()
	if err != nil {
		fmt.Printf("Error registering DSYNC RR type: %v\n", err)
	}
	err = tdns.RegisterDelegRR()
	if err != nil {
		fmt.Printf("Error registering DELEG RR type: %v\n", err)
	}
}
