/*
 * Copyright (c) DNS TAPIR
 */
package cmd

import (

	//	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var zone, server, keyfile string

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example: to quickly create a Cobra application.`,
}

var updateCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create and ultimately send a DNS UPDATE msg",
	Long: `Will query for operation (add|del|show|send|set-ttl|list-tags|quit), domain name and tags.
Will end the loop on the operation (or domain name) "QUIT"`,
	Run: func(cmd *cobra.Command, args []string) {

		kdb, err := tdns.NewKeyDB(viper.GetString("db.file"), false)
		if err != nil {
			fmt.Printf("Error from NewKeyDB(): %v\n", err)
			os.Exit(1)
		}

		var adds, removes []dns.RR

		var ops = []string{"zone", "add", "del", "show", "send", "set-ttl", "server", "quit"}
		fmt.Printf("Defined operations are: %v\n", ops)

		var ttl int = 60
		var op, rrstr, port string

		zone = dns.Fqdn(zone)

		var sak *tdns.Sig0ActiveKeys

	cmdloop:
		for {
			// count++
			op = tdns.TtyRadioButtonQ("Operation", "add", ops)
			switch op {
			case "quit":
				fmt.Println("QUIT cmd recieved.")
				break cmdloop

			case "zone":
				zone = tdns.TtyQuestion("Zone", "127.0.0.1", false)
				zone = dns.Fqdn(zone)

			case "set-ttl":
				ttl = tdns.TtyIntQuestion("TTL (in seconds)", 60, false)
				// fmt.Printf("TTL: got: %d\n", tmp)
				// ttl = time.Duration(tmp) * time.Second
				// fmt.Printf("TTL: got: %d ttl: %v\n", tmp, ttl)
			case "add", "del":
				if zone == "." {
					fmt.Println("Target zone not set, please set it first")
					continue
				}
				rrstr = tdns.TtyQuestion("Record", rrstr, false)
				if len(rrstr) > 0 && strings.ToUpper(rrstr) == "QUIT" {
					break cmdloop
				}
				rr, err := dns.NewRR(rrstr)
				if err != nil {
					fmt.Printf("Error parsing RR: %v\n", err)
					continue
				}

				if ttl > 0 {
					rr.Header().Ttl = uint32(ttl)
				}

				if op == "add" {
					adds = append(adds, rr)
				} else {
					removes = append(removes, rr)
				}

			case "show":
				if zone == "." {
					fmt.Println("Target zone not set, please set it first")
					continue
				}
				var out = []string{"Operation|Record"}
				for _, rr := range adds {
					out = append(out, fmt.Sprintf("ADD|%s", rr.String()))
				}
				for _, rr := range removes {
					out = append(out, fmt.Sprintf("DEL|%s", rr.String()))
				}
				fmt.Println(columnize.SimpleFormat(out))

				tdns.Globals.Debug = true
				_, err := tdns.CreateUpdate(zone, adds, removes)
				if err != nil {
					fmt.Printf("Error creating update: %v\n", err)
					continue
				}
				tdns.Globals.Debug = false

			case "server":
				server = tdns.TtyQuestion("Server", "localhost", false)
				port = tdns.TtyQuestion("Port", "53", false)
				server = net.JoinHostPort(server, port)

			case "send":
				if server == "" {
					fmt.Println("Target server not set, please set it first")
					continue
				}
				if zone == "" {
					fmt.Println("Target zone not set, please set it first")
					continue
				}
				msg, err := tdns.CreateUpdate(zone, adds, removes)
				if err != nil {
					fmt.Printf("Error creating update: %v\n", err)
					continue
				}

				if keyfile != "" {
					pkc, err := tdns.ReadKeyNG(keyfile)
					if err != nil {
						fmt.Printf("Error reading SIG(0) key file '%s': %v\n", keyfile, err)
						os.Exit(1)
					}
					if pkc.KeyType != dns.TypeKEY {
						fmt.Printf("Keyfile did not contain a SIG(0) key\n")
						os.Exit(1)
					}

					sak.Keys = append(sak.Keys, pkc)

					// m, err := tdns.SignMsgNG(*msg, zone, &cs, keyrr)
					m, err := tdns.SignMsgNG2(*msg, zone, sak)
					if err != nil {
						fmt.Printf("Error signing message: %v\n", err)
						os.Exit(1)
					}
					msg = m
				} else {
					fmt.Printf("No SIG(0) keyfile specified, trying to fetch active key from keystore\n")
					sak, err := kdb.GetSig0ActiveKeys(zone)
					if err != nil {
						fmt.Printf("Error fetching active SIG(0) key for zone %s: %v\n", zone, err)
						os.Exit(1)
					}
					m, err := tdns.SignMsgNG2(*msg, zone, sak)
					if err != nil {
						fmt.Printf("Error signing message: %v\n", err)
						os.Exit(1)
					}
					msg = m
				}

				fmt.Printf("Sending update to %s\n", server)
				rcode, err := tdns.SendUpdate(msg, zone, []string{server})
				if err != nil {
					fmt.Printf("Error sending update: %v\n", err)
					continue
				}
				fmt.Printf("Update sent, rcode: %d (%s)\n", rcode, dns.RcodeToString[rcode])

				adds = []dns.RR{}
				removes = []dns.RR{}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.AddCommand(updateCreateCmd)
	updateCreateCmd.Flags().StringVarP(&zone, "zone", "z", "", "Zone to update")
	updateCreateCmd.Flags().StringVarP(&server, "server", "S", "", "Server to send update to")
	updateCreateCmd.Flags().StringVarP(&keyfile, "key", "K", "", "SIG(0) keyfile to use for signing the update")
}
