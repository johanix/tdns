/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package cmd

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"crypto/tls"

	"github.com/johanix/tdns/v0.x/tdns"
	core "github.com/johanix/tdns/v0.x/tdns/core"
	edns0 "github.com/johanix/tdns/v0.x/tdns/edns0"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var short bool
var rrtype uint16

var port = "53"

var server string
var cfgFile string

var options = make(map[string]string, 2)

// Default ports for each transport
var defaultPorts = map[string]string{
	"Do53":     "53",
	"Do53-TCP": "53",
	"DoT":      "853",
	"DoH":      "443",
	"DoQ":      "8853",
}

var rootCmd = &cobra.Command{
	Use:   "dog",
	Short: "CLI utility used issue DNS queries and present the result",
	Long:  `dog is a CLI utility used issue DNS queries and present the result.
	
	Options:
		+DNSSEC: Set the DO (DNSEC OK) bit in queries
		+CD: Set the CD (Checking Disabled) bit in queries
		+COMPACT: Set the COMPACT bit in queries (for compact denial of existence proofs)
		+TCP: Force TCP transport
		+TLS: Force TLS transport
		+HTTPS: Force HTTPS transport
		+QUIC: Force QUIC transport
		+WIDTH=N: Set the width of the output to N characters
		+OPCODE=QUERY|NOTIFY|UPDATE: Set the opcode of the query
		+OTS=opt_in|opt_out: Set the OTS (transport signaling) EDNS(0)option
		+ER=agent.domain: Add EDNS(0) Error Reporting option with agent domain (RFC9567)
		+DO_BIT: Set the DO (DNSEC OK) bit
		+DELEG: Set the DELEG bit in queries
		+MULTI: Present RRs in multi-line format
	`,

	Run: func(cmd *cobra.Command, args []string) {

		var cleanArgs []string
		var err error
		var serial uint32

		for _, arg := range args {
			if tdns.Globals.Debug {
				fmt.Printf("processing arg: %s, options: %+v\n", arg, options)
			}
			if strings.HasPrefix(arg, "@") || strings.Contains(arg, "://") {
				serverArg := arg
				if strings.HasPrefix(arg, "@") {
					serverArg = arg[1:]
				}
				options, err = ParseServer(serverArg, options)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(1)
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
				options, err = ProcessOptions(options, ucarg)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(1)
				}
				continue
			}

			cleanArgs = append(cleanArgs, arg)
		}

		if _, exists := options["transport"]; !exists {
			options["transport"] = "Do53"
		}

		if options["server"] == "" {
			server, err = ParseResolvConf()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			options["server"] = server
		}

		// If -p/--port was explicitly provided, let it override any other port source
		if cmd.Flags().Changed("port") && port != "" {
			options["port"] = port
		}

		if options["port"] == "" {
			options["port"] = defaultPorts[options["transport"]]
			if options["port"] == "" {
				fmt.Printf("Error: port for transport %s not specified\n", options["transport"])
				os.Exit(1)
			}
		}

		if rrtype == 0 {
			rrtype = dns.TypeA
		}

		_, err = strconv.Atoi(options["port"])
		if err != nil {
			fmt.Printf("Error: port \"%s\" is not valid: %v\n", options["port"], err)
		}

		// All args parsed, join server and port
		// options["server"] = net.JoinHostPort(options["server"], options["port"])

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
					upstream := net.JoinHostPort(options["server"], options["port"])
					tdns.ZoneTransferPrint(qname, upstream, serial, rrtype, options)
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
				// Set CD (Checking Disabled) flag if requested
				if options["cd_bit"] == "true" {
					m.MsgHdr.CheckingDisabled = true
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
				if options["co_bit"] == "true" {
					// Set CO bit (bit 14)
					opt.Hdr.Ttl |= 1 << 14
				}
				if options["de_bit"] == "true" {
					// Set DE bit (bit 13)
					opt.Hdr.Ttl |= 1 << 13
				}
				if ots, ok := options["ots"]; ok {
					var otsValue uint8
					switch ots {
					case "opt_in":
						otsValue = edns0.OTS_OPT_IN
					case "opt_out":
						otsValue = edns0.OTS_OPT_OUT
					}
					err := edns0.AddOTSOption(opt, otsValue)
					if err != nil {
						fmt.Printf("Error from AddOTSOption: %v", err)
						os.Exit(1)
					}
				}
				if erDomain, ok := options["er"]; ok {
					err := edns0.AddEROption(opt, erDomain)
					if err != nil {
						fmt.Printf("Error from AddEROption: %v", err)
						os.Exit(1)
					}
				}
				m.Extra = append(m.Extra, opt)

				if tdns.Globals.Debug {
					fmt.Printf("*** Outbound DNS message: %s\n", m.String())
				}
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
				if tval, ok := options["transport"]; ok {
					transport = tval
				} else {
					options["transport"] = transport
				}
				forceTCP := strings.EqualFold(transport, "Do53-TCP") || strings.EqualFold(transport, "tcp")

				t, err := core.StringToTransport(transport)
				if err != nil {
					log.Fatalf("Error: %v", err)
				}
				clientOpts := []core.DNSClientOption{}
				if t == core.TransportDo53 {
					if forceTCP {
						clientOpts = append(clientOpts, core.WithForceTCP())
						options["transport"] = "Do53-TCP"
					} else {
						clientOpts = append(clientOpts, core.WithDisableFallback())
						options["transport"] = "do53"
					}
				} else {
					options["transport"] = transport
				}
				client := core.NewDNSClient(t, options["port"], tlsConfig, clientOpts...)
				res, _, err := client.Exchange(m, server, false) // FIXME: duration is always zero
				if err == nil && res != nil && res.Truncated && t == core.TransportDo53 && !forceTCP {
					fmt.Println(";; Truncated UDP response received; retrying over TCP")
					tcpClient := core.NewDNSClient(core.TransportDo53, options["port"], tlsConfig, core.WithForceTCP())
					res, _, err = tcpClient.Exchange(m, server, false)
					options["transport"] = "Do53-TCP"
				}

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

func ProcessOptions(options map[string]string, ucarg string) (map[string]string, error) {
	if options == nil {
		options = make(map[string]string)
	}

	switch ucarg {
	case "+DNSSEC", "+DO":
		options["do_bit"] = "true"
		return options, nil
	case "+CD":
		options["cd_bit"] = "true"
		return options, nil
	case "+COMPACT", "+CO":
		options["co_bit"] = "true"
		return options, nil
	case "+DELEG", "+DE":
		options["de_bit"] = "true"
		return options, nil
	case "+MULTI":
		options["multi"] = "true"
		return options, nil
	case "+TCP":
		if transport, exists := options["transport"]; exists {
			return nil, fmt.Errorf("Error: multiple transport options specified (%s and TCP)", transport)
		}
		options["transport"] = "Do53-TCP"
		return options, nil
	case "+TLS", "+DOT":
		if transport, exists := options["transport"]; exists {
			return nil, fmt.Errorf("Error: multiple transport options specified (%s and DoT)", transport)
		}
		options["transport"] = "DoT"
		return options, nil
	case "+HTTPS", "+DOH":
		if transport, exists := options["transport"]; exists {
			return nil, fmt.Errorf("Error: multiple transport options specified (%s and DoH)", transport)
		}
		options["transport"] = "DoH"
		return options, nil
	case "+QUIC", "+DOQ":
		if transport, exists := options["transport"]; exists {
			return nil, fmt.Errorf("Error: multiple transport options specified (%s and DoQ)", transport)
		}
		options["transport"] = "DoQ"
		return options, nil
	default:
		// Cannot match on "+OPCODE=", as the string would be "+OPCODE=QUERY", etc.
		if strings.HasPrefix(ucarg, "+OPCODE=") {
			parts := strings.Split(ucarg, "=")
			if len(parts) > 1 {
				switch parts[1] {
				case "QUERY", "NOTIFY", "UPDATE":
					options["opcode"] = parts[1]
				default:
					opcode, err := strconv.Atoi(parts[1])
					if err != nil {
						fmt.Printf("Error: %v\n", err)
						return options, nil
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
			return options, nil
		}

		// Add support for +OTS=opt_in, +OTS=opt_out, +OTS=1, +OTS=2, and +OTS (default to opt_in)
		if strings.HasPrefix(strings.ToUpper(ucarg), "+OTS") {
			otsArg := ""
			if strings.Contains(ucarg, "=") {
				parts := strings.SplitN(ucarg, "=", 2)
				otsArg = strings.ToLower(parts[1])
			}
			if otsArg == "" || otsArg == "opt_in" || otsArg == "1" {
				options["ots"] = "opt_in"
				return options, nil
			} else if otsArg == "opt_out" || otsArg == "2" {
				options["ots"] = "opt_out"
				return options, nil
			} else {
				return nil, fmt.Errorf("Error: Unknown OTS option: %s", otsArg)
			}
		}

		// Add support for +ER={agent domain} (RFC9567: DNS Error Reporting)
		if strings.HasPrefix(strings.ToUpper(ucarg), "+ER") {
			if !strings.Contains(ucarg, "=") {
				return nil, fmt.Errorf("Error: +ER option requires an agent domain (e.g., +ER=agent.example.com)")
			}
			parts := strings.SplitN(ucarg, "=", 2)
			if len(parts) > 1 && parts[1] != "" {
				options["er"] = parts[1]
				return options, nil
			} else {
				return nil, fmt.Errorf("Error: +ER option requires a non-empty agent domain")
			}
		}

		if strings.HasPrefix(strings.ToUpper(ucarg), "+WIDTH") {
			parts := strings.SplitN(ucarg, "=", 2)
			if len(parts) > 1 {
				if _, err := strconv.Atoi(parts[1]); err != nil {
					return nil, fmt.Errorf("Error: +WIDTH option requires a valid integer width")
				}
				options["width"] = parts[1]
				return options, nil
			}
			return nil, fmt.Errorf("Error: +WIDTH option requires a valid integer width (e.g., +WIDTH=100)")
		}

		return nil, fmt.Errorf("Error: Unknown option: %s", ucarg)
	}

	return options, nil
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

// ParseServer parses a server specification like "tls://1.2.3.4:853" or "quic://1.2.3.4"
// and returns the host, port, and transport. If no scheme is specified, defaults to Do53.
// If no port is specified, uses the default port for the transport.
func ParseServer(serverArg string, options map[string]string) (map[string]string, error) {
	var u *url.URL
	var err error
	var transport string
	// Try to parse as URL if it contains "://"
	if strings.Contains(serverArg, "://") {
		u, err = url.Parse(serverArg)
		if err != nil {
			return nil, fmt.Errorf("Invalid server URL: %v", err)
		}
	} else {
		// If no scheme, treat as host[:port]
		u = &url.URL{
			Scheme: "dns",
			Host:   serverArg,
		}
	}

	// Map scheme to transport
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "dns", "do53":
		transport = "Do53"
	case "tcp":
		transport = "Do53-TCP"
	case "tls", "dot":
		transport = "DoT"
	case "https", "doh":
		transport = "DoH"
	case "quic", "doq":
		transport = "DoQ"
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", scheme)
	}

	// Only signal error if there are two explicit transport specifications that conflict
	// A transport is explicit if it comes from a flag or a non-default URI scheme
	if existingTransport, exists := options["transport"]; exists {
		if scheme != "dns" && existingTransport != transport {
			return nil, fmt.Errorf("Conflicting transport specifications: %s (from flag) vs %s (from URI)", existingTransport, transport)
		}
		// If we have a flag-specified transport, keep it
		transport = existingTransport
	}
	options["transport"] = transport

	// Extract host and port
	host := u.Host
	port := ""
	
	// Check if host contains a colon (could be IPv6 or host:port)
	if strings.Contains(host, ":") {
		// Check if it's an IPv6 address in brackets (e.g., [::1]:port)
		if strings.HasPrefix(host, "[") && strings.Contains(host, "]:") {
			// IPv6 with port: [::1]:5354
			var portErr error
			host, port, portErr = net.SplitHostPort(host)
			if portErr != nil {
				return nil, fmt.Errorf("%s is not in host:port format: %v", u.Host, portErr)
			}
		} else if net.ParseIP(host) != nil {
			// XXX: This is not correct, as it will not work for IPv6 addresses in brackets
			// 
			// Valid IP address (IPv4 or IPv6) without port - use as-is
			// net.ParseIP handles both IPv4 and IPv6 correctly
			// No need to split, it's just the IP address
		} else {
			// Try to split as host:port (for hostnames with ports)
			var portErr error
			host, port, portErr = net.SplitHostPort(host)
			if portErr != nil {
				return nil, fmt.Errorf("%s is not in host:port format: %v", u.Host, portErr)
			}
		}
	}
	options["server"] = host
	if port != "" {
		options["port"] = port
	} else if u.Port() != "" {
		options["port"] = u.Port()
	}

	// For DoH, DoQ, etc., the path may be important
	if u.Path != "" && u.Path != "/" {
		options["path"] = u.Path
	}

	if strings.HasSuffix(options["server"], "/") {
		options["server"] = options["server"][:len(options["server"])-1]
	}

	if tdns.Globals.Debug {
		fmt.Printf("ParseServer: server: %s, port: %s, transport: %s, path: %s\n",
			options["server"], options["port"], options["transport"], options["path"])
	}

	// Basic validation
	if options["server"] == "" {
		return nil, fmt.Errorf("empty host specified")
	}

	return options, nil
}
