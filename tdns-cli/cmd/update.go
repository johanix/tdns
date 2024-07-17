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
	Short: "Prefix, only useable via the 'update create' subcommand",
}

var updateCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create and ultimately send a DNS UPDATE msg",
	Long: `Will query for details about the DNS UPDATE via (add|del|show|set-ttl) commands.
When the message is complete it may be signed and sent by the 'send' command. After a 
message has been send the loop will start again with a new, empty message to create.
Loop ends on the command "QUIT"

The zone to update is mandatory to specify on the command line with the --zone flag.`,
	Run: func(cmd *cobra.Command, args []string) {

		PrepArgs("zonename")

		kdb, err := tdns.NewKeyDB(viper.GetString("db.file"), false)
		if err != nil {
			fmt.Printf("Error from NewKeyDB(): %v\n", err)
			os.Exit(1)
		}

		var adds, removes []dns.RR

		var ttl int = 60
		var op, rrstr, port string

		zone = dns.Fqdn(tdns.Globals.Zonename)

		var sak *tdns.Sig0ActiveKeys
		var signing bool = false

		if keyfile != "" {
			pkc, err := tdns.ReadPrivateKey(keyfile)
			if err != nil {
				fmt.Printf("Error reading SIG(0) key file '%s': %v\n", keyfile, err)
				signing = true
			}
			if pkc.KeyType != dns.TypeKEY {
				fmt.Printf("Keyfile did not contain a SIG(0) key\n")
				signing = true
			}
			if signing {
				fmt.Printf("Using keyfile %s\n", keyfile)
				sak = &tdns.Sig0ActiveKeys{
					Keys: []*tdns.PrivateKeyCache{pkc},
				}
			} else {
				fmt.Printf("Warning: no SIG(0) signing of update messages possible.\n")
			}
		} else {
			sak, err = kdb.GetSig0ActiveKeys(zone)
			if err != nil {
				fmt.Printf("Error fetching active SIG(0) key for zone %s: %v\n", zone, err)
			} else {
				fmt.Printf("SIG(0) private key for zone %s successfully fetched from keystore\n", zone)
			}
		}

		var ops = []string{"zone", "add", "del", "show", "send", "set-ttl", "server", "quit"}
		fmt.Printf("Defined operations are: %v\n", ops)

	cmdloop:
		for {
			// count++
			op = tdns.TtyRadioButtonQ("Operation", "add", ops)
			switch op {
			case "quit":
				fmt.Println("QUIT cmd recieved.")
				break cmdloop

			case "zone":
				fmt.Printf("Zone must be specified on the command line\n")
				os.Exit(1)
				// zone = tdns.TtyQuestion("Zone", "foo.com", false)
				// zone = dns.Fqdn(zone)

			case "set-ttl":
				ttl = tdns.TtyIntQuestion("TTL (in seconds)", 60, false)

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
					pkc, err := tdns.ReadPrivateKey(keyfile)
					if err != nil {
						fmt.Printf("Error reading SIG(0) key file '%s': %v\n", keyfile, err)
						os.Exit(1)
					}
					if pkc.KeyType != dns.TypeKEY {
						fmt.Printf("Keyfile did not contain a SIG(0) key\n")
						os.Exit(1)
					}

					sak.Keys = append(sak.Keys, pkc)

					m, err := tdns.SignMsg(*msg, zone, sak)
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
					m, err := tdns.SignMsg(*msg, zone, sak)
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
	// updateCreateCmd.Flags().StringVarP(&zone, "zone", "z", "", "Zone to update")
	updateCreateCmd.Flags().StringVarP(&server, "server", "S", "", "Server to send update to (in addr:port format)")
	updateCreateCmd.Flags().StringVarP(&keyfile, "key", "K", "", "SIG(0) keyfile to use for signing the update")
}
