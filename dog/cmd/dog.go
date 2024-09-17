/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var short bool
var rrtype uint16

var port = "53"

var server string
var cfgFile string

var options = make(map[string]string, 2)

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

			if strings.HasPrefix(ucarg, "+") {
				fmt.Printf("processing dog option: %s\n", ucarg)
				options = ProcessOptions(options, ucarg)
				continue
			}

			cleanArgs = append(cleanArgs, arg)
		}

		if server == "" {
			// Read /etc/resolv.conf to get the default nameserver
			content, err := os.ReadFile("/etc/resolv.conf")
			if err != nil {
				fmt.Println("Error: Unable to read /etc/resolv.conf and no nameserver specified")
				os.Exit(1)
			}
			lines := strings.Split(string(content), "\n")
			foundNameserver := false
			for _, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), "nameserver") {
					fields := strings.Fields(line)
					if len(fields) == 2 {
						server = fields[1]
						foundNameserver = true
						break
					}
				}
			}
			if !foundNameserver {
				fmt.Println("Error: No nameserver entry found in /etc/resolv.conf and no nameserver specified")
				os.Exit(1)
			}
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

		server = net.JoinHostPort(server, port)

		if tdns.Globals.Verbose {
			fmt.Printf("*** Will send %s to server %s\n", options["opcode"], server)
		}

		for _, qname := range cleanArgs {
			qname = dns.Fqdn(qname)
			if tdns.Globals.Verbose {
				fmt.Printf("*** %s for %s IN %s:\n", options["opcode"], qname, dns.TypeToString[rrtype])
			}

			switch rrtype {
			case dns.TypeAXFR, dns.TypeIXFR:
				tdns.ZoneTransferPrint(qname, server, serial, rrtype, options)

			default:

				m := new(dns.Msg)
				if options["opcode"] == "NOTIFY" {
					m.SetNotify(qname)
					m.Question = []dns.Question{dns.Question{Name: qname, Qtype: rrtype, Qclass: dns.ClassINET}}
				} else if options["opcode"] == "UPDATE" {
					m.SetUpdate(qname)
				} else {
					m.SetQuestion(qname, rrtype)
				}
				do_bit = options["do_bit"] == "true"
				m.SetEdns0(4096, do_bit)
				start := time.Now()
				res, err := dns.Exchange(m, server)
				elapsed := time.Since(start)
				if err != nil {
					fmt.Printf("Error from %s: %v\n", server, err)
					os.Exit(1)
				}
				tdns.MsgPrint(res, server, elapsed, short, options)
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
	rootCmd.PersistentFlags().StringVarP(&port, "port", "p", "53", "Port to send DNS query to")
}

func ProcessOptions(options map[string]string, ucarg string) map[string]string {
	if ucarg == "+DNSSEC" {
		options["do_bit"] = "true"
		return options
	}
	if ucarg == "+MULTI" {
		options["multi"] = "true"
		return options
	}

	if ucarg == "+TCP" {
		options["tcp"] = "true"
		return options
	}

	if strings.HasPrefix(ucarg, "+OPCODE=") {
		parts := strings.Split(ucarg, "=")
		if len(parts) > 1 {
			opcode, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return options
			}
			switch opcode {
			case dns.OpcodeQuery:
				options["opcode"] = "QUERY"
			case dns.OpcodeNotify:
				options["opcode"] = "NOTIFY"
			case dns.OpcodeUpdate:
				options["opcode"] = "UPDATE"
			}
		}
		return options
	}

	return options
}
