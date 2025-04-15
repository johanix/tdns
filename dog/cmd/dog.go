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

	"crypto/tls"

	"github.com/johanix/tdns/tdns"
	// cli "github.com/johanix/tdns/tdns/cli"
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
		var err error
		var serial uint32

		for _, arg := range args {
			if strings.HasPrefix(arg, "@") {
				serverArg := arg[1:]
				host, port, transport, err := ParseServer(serverArg, options)
				if err != nil {
					log.Fatalf("Error parsing server specification: %v", err)
				}
				options["server"] = net.JoinHostPort(host, port)
				if transport != "do53" {
					if existingTransport, exists := options["transport"]; exists && existingTransport != transport {
						log.Fatalf("Conflicting transport specifications: %s vs %s", existingTransport, transport)
					}
					options["transport"] = transport
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
				fmt.Printf("RRtype is IXFR, using base serial %d\n", serial)
			}

			if strings.HasPrefix(ucarg, "+") {
				if tdns.Globals.Debug {
					fmt.Printf("processing dog option: %s\n", ucarg)
				}
				options = ProcessOptions(options, ucarg)
				continue
			}

			cleanArgs = append(cleanArgs, arg)
		}

		if options["server"] == "" {
			server, err = ParseResolvConf()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			options["server"] = server
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

		if options["opcode"] == "" {
			options["opcode"] = "QUERY"
		}

		if tdns.Globals.Debug {
			fmt.Printf("*** Will send %s to server %s using transport %s\n", options["opcode"], options["server"], options["transport"])
		}

		for _, qname := range cleanArgs {
			qname = dns.Fqdn(qname)
			if tdns.Globals.Verbose {
				fmt.Printf("*** %s for %s IN %s:\n", options["opcode"], qname, dns.TypeToString[rrtype])
			}

			switch rrtype {
			case dns.TypeAXFR, dns.TypeIXFR:
				if options["transport"] == "Do53" {
					tdns.ZoneTransferPrint(qname, server, serial, rrtype, options)
				} else {
					fmt.Printf("Zone transfer only supported for transport Do53 (TCP), this is %s\n", options["transport"])
					os.Exit(1)
				}

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
				// do_bit = options["do_bit"] == "true"
				// m.SetEdns0(4096, do_bit)
				opt := &dns.OPT{
					Hdr: dns.RR_Header{
						Name:   ".",
						Rrtype: dns.TypeOPT,
						Class:  4096, // This is the UDP buffer size
						Ttl:    0,    // Extended RCODE and flags
					},
				}
				if options["do_bit"] == "true" {
					// Set DO bit (bit 15)
					opt.Hdr.Ttl |= 1 << 15
				}
				if options["compact"] == "true" {
					// Set CO bit (bit 14)
					opt.Hdr.Ttl |= 1 << 14
				}
				if options["deleg"] == "true" {
					// Set DE bit (bit 13)
					opt.Hdr.Ttl |= 1 << 13
				}
				m.Extra = append(m.Extra, opt)
				start := time.Now()

				server, ok := options["server"]
				if !ok {
					log.Fatal("No server specified")
				}

				var tlsConfig *tls.Config
				if transport, ok := options["transport"]; ok && transport != "do53" {
					tlsConfig = &tls.Config{
						InsecureSkipVerify: true,
					}
					// Add ALPN for DoQ
					if transport == "DoQ" {
						tlsConfig.NextProtos = []string{"doq"}
					}
				}

				transport := "do53" // default
				if t, ok := options["transport"]; ok {
					transport = t
				}

				t, err := tdns.StringToTransport(transport)
				if err != nil {
					log.Fatalf("Error: %v", err)
				}
				client := tdns.NewDNSClient(t, server, tlsConfig)
				res, err := client.Exchange(m)
				// if err != nil {
				// log.Fatalf("Error: %v", err)
				// }

				// res, err := dns.Exchange(m, server)
				elapsed := time.Since(start)
				if err != nil {
					fmt.Printf("Error from %s: %v\n", server, err)
					fmt.Printf("*** This is what we got: %+v\n", res)
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
	//	rootCmd.AddCommand(cli.VersionCmd)

	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "Verbose mode")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "Debugging output")
	rootCmd.PersistentFlags().BoolVarP(&short, "short", "", false, "Only list RRs that are part of the Answer section")
	rootCmd.PersistentFlags().StringVarP(&port, "port", "p", "53", "Port to send DNS query to")
}

func ProcessOptions(options map[string]string, ucarg string) map[string]string {
	if options == nil {
		options = make(map[string]string)
	}

	switch ucarg {
	case "+DNSSEC":
		options["do_bit"] = "true"
		return options
	case "+COMPACT":
		options["compact"] = "true"
		return options
	case "+DELEG":
		options["deleg"] = "true"
		return options
	case "+MULTI":
		options["multi"] = "true"
		return options
	case "+TCP":
		if _, exists := options["transport"]; exists {
			log.Fatalf("Error: multiple transport options specified (+TCP/+TLS/+HTTPS/+QUIC)")
		}
		options["transport"] = "tcp"
		return options
	case "+TLS", "+DOT":
		if _, exists := options["transport"]; exists {
			log.Fatalf("Error: multiple transport options specified (+TCP/+TLS/+HTTPS/+QUIC)")
		}
		options["transport"] = "DoT"
		return options
	case "+HTTPS", "+DOH":
		if _, exists := options["transport"]; exists {
			log.Fatalf("Error: multiple transport options specified (+TCP/+TLS/+HTTPS/+QUIC)")
		}
		options["transport"] = "DoH"
		return options
	case "+QUIC", "+DOQ":
		if _, exists := options["transport"]; exists {
			log.Fatalf("Error: multiple transport options specified (+TCP/+TLS/+HTTPS/+QUIC)")
		}
		options["transport"] = "DoQ"
		return options
	case "+OPCODE=":
		parts := strings.Split(ucarg, "=")
		if len(parts) > 1 {
			switch parts[1] {
			case "QUERY", "NOTIFY", "UPDATE":
				options["opcode"] = parts[1]
			default:
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
		}
		return options
	default:
		log.Fatalf("Error: Unknown option: %s", ucarg)
	}

	return options
}

func ParseResolvConf() (string, error) {
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
		return "", fmt.Errorf("Error: No nameserver entry found in /etc/resolv.conf and no nameserver specified")
	}
	return server, nil
}

// Example usage in dog CLI
func queryWithTransport(msg *dns.Msg, server string, transport string, tlsConfig *tls.Config) (*dns.Msg, error) {
	var t tdns.Transport
	switch transport {
	case "do53", "Do53", "Do53-TCP":
		t = tdns.TransportDo53
	case "dot", "DoT":
		t = tdns.TransportDoT
	case "doh", "DoH":
		t = tdns.TransportDoH
	case "doq", "DoQ":
		t = tdns.TransportDoQ
	default:
		return nil, fmt.Errorf("unsupported transport: %s", transport)
	}

	client := tdns.NewDNSClient(t, server, tlsConfig)
	return client.Exchange(msg)
}

// ParseServer parses a server specification like "tls://1.2.3.4:853" or "quic://1.2.3.4"
// and returns the host, port, and transport. If no scheme is specified, defaults to Do53.
// If no port is specified, uses the default port for the transport.
func ParseServer(serverArg string, options map[string]string) (host, port, transport string, err error) {
	// Default transport if no scheme is specified
	transport = options["transport"]
	if transport == "" {
		transport = "do53"
	}

	// Default ports for each transport
	defaultPorts := map[string]string{
		"Do53":     "53",
		"Do53-TCP": "53",
		"DoT":      "853",
		"DoH":      "443",
		"DoQ":      "8853",
	}

	// Check if we have a scheme
	if strings.Contains(serverArg, "://") {
		parts := strings.SplitN(serverArg, "://", 2)
		scheme := strings.ToLower(parts[0])
		serverArg = parts[1]

		// Map scheme to transport
		switch scheme {
		case "dns":
			transport = "Do53"
		case "tcp":
			transport = "Do53-TCP"
		case "tls":
			transport = "DoT"
		case "https":
			transport = "DoH"
		case "quic":
			transport = "DoQ"
		default:
			return "", "", "", fmt.Errorf("unsupported scheme: %s", scheme)
		}
	}

	// Split host and port
	host = serverArg
	if strings.Contains(serverArg, ":") {
		var portErr error
		host, port, portErr = net.SplitHostPort(serverArg)
		if portErr != nil {
			return "", "", "", fmt.Errorf("invalid host:port format: %v", portErr)
		}
	} else {
		// No port specified, use default
		port = defaultPorts[transport]
	}

	// Basic validation
	if host == "" {
		return "", "", "", fmt.Errorf("empty host specified")
	}

	return host, port, transport, nil
}
