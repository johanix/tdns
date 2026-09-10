/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"crypto/tls"

	dogopts "dog/internal/options"
	dogtransport "dog/internal/transport"
	"github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var short bool
var rrtype uint16

var port = "53"

var server string
var cfgFile string
var trustAnchorFile string // -k / --trust-anchor
var tsigKeyFlag string     // -y / --tsig : [algorithm:]name:secret (dig-compatible)
var showVersion bool       // --version : print version + supported algorithms, then exit

var options = make(map[string]string, 2)

// Default ports for each transport
var defaultPorts = map[string]string{
	"Do53":     "53",
	"Do53-TCP": "53",
	"DoT":      "853",
	"DoH":      "443",
	"DoQ":      "853",
}

var rootCmd = &cobra.Command{
	Use:   "dog",
	Short: "CLI utility used to issue DNS queries and present the result",
	Long: `dog issues DNS queries and presents the result. The CLI is as close to
dig's as possible; arguments are case-insensitive and may appear in any order.

  dog [@server] [name] [type] [+option ...]

@server takes @host, @host:port, @[ipv6], @[ipv6]:port, or a URL form that
selects the transport directly: dns:// tcp:// tls:// dot:// https:// doh://
quic:// doq://. Queries are always class IN.

Query:
  +opcode=QUERY|NOTIFY|UPDATE
                          set the opcode (numeric 0/4/5 also accepted)
  +recurse, +rec          set the RD (Recursion Desired) bit (the default)
  +norecurse, +norec      clear it: ask a cache or an authoritative server a
                          non-recursive question

DNSSEC and EDNS flags:
  +dnssec, +do            set the DO (DNSSEC OK) bit
  +cd                     set the CD (Checking Disabled) bit
  +adflag, +ad            set the AD bit on the outgoing query
  +noadflag, +noad        clear it (the default)
  +compact, +co           set the CO bit (RFC 9824 compact denial of existence)
  +deleg, +de             set the DE (Delegation Extension) bit
  +bufsize=N, +bufsiz=N   EDNS(0) UDP payload size (default 4096, floor 512)
  +oots, +oots=opt_in|opt_out
                          EDNS(0) transport-signaling option
  +er=<agent.domain>      EDNS(0) Error Reporting (RFC 9567)
  +privacy, +pr[=strict|opportunistic|none]
                          PRIVACY EDNS(0) option; bare +pr is strict

Transport:
  +tcp                    force Do53 over TCP
  +tls, +dot              DoT (default port 853)
  +https, +doh            DoH (default port 443)
  +quic, +doq             DoQ (default port 853)

Timeouts and retries:
  +time=T, +timeout=T     per-attempt timeout in seconds (below 1 becomes 1,
                          above 65535 is refused, as in dig)
  +tries=A                total attempts, default 1 (dig's default is 3)
  +retry=T                retries after the first, i.e. tries = T+1
                          Only a transport failure is retried; a response that
                          came back is an answer.

Server certificate (encrypted transports only):
  +cert=<file>, +key=<file>
                          present a client certificate (XoT / mutual DoT)
  +cafile=<file>          verify the server cert against a PEM CA bundle
  +pin=<spki-b64>         verify the server cert by SPKI pin (repeatable)
  +tlsa                   DANE-verify against _port._tcp.<server>
  +showpin                print the server cert's SPKI pin and exit

Zone transfers:
  AXFR, IXFR=<serial>     as the query type; both run over Do53-TCP and DoT
  +zonemd, +zmd           after an AXFR, verify the apex ZONEMD (RFC 8976);
                          exits non-zero if it does not verify
  +ignoreserial, +ignser  with +zonemd, digest against the serial each ZONEMD
                          names rather than the SOA's

DNSSEC chain validation:
  +sigchase, +sigcha, +sc walk and validate the chain, per-link verdict
  +algchase, +algcha, +ac as +sigchase, naming each algorithm number

Output:
  +short                  print only the answer RDATA (same as --short)
  +multi                  multi-line RR output
  +width=N                right margin for +multi

Anything else is rejected. A truncated UDP response is retried over TCP.
See guide/app-dog.md for the long form.
	`,

	Run: func(cmd *cobra.Command, args []string) {
		if showVersion {
			tdns.PrintVersionAndExit()
		}

		var cleanArgs []string
		var err error
		var serial uint32

		for _, arg := range args {
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
				rrtype = dns.TypeIXFR // Set rrtype so the later switch on rrtype triggers IXFR logic
				fmt.Printf("RRtype is IXFR, using base serial %d\n", serial)
				continue
			}

			if strings.HasPrefix(ucarg, "+") {
				options, err = ProcessOptions(options, ucarg, arg)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(1)
				}
				continue
			}

			cleanArgs = append(cleanArgs, arg)
		}

		// +SHORT (and --short) both flow through to MsgPrint via the
		// short variable. Either source enables short mode.
		if options["short"] == "true" {
			short = true
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

		// Warn if strict privacy was requested over an unencrypted hop to the
		// resolver itself. Opportunistic gets no warning: accepting cleartext
		// is precisely what it asked for.
		// TODO: Once resolver supports encrypted transports, change this to hard fail
		if level, ok := privacyLevel(options); ok && level == edns0.PrivacyStrict {
			transportStr := options["transport"]
			transport, err := core.StringToTransport(transportStr)
			if err != nil {
				fmt.Printf("Error: invalid transport %s: %v\n", transportStr, err)
				os.Exit(1)
			}
			if !core.IsEncryptedTransport(transport) {
				// Hard fail (commented out until resolver supports encrypted transports):
				// fmt.Printf("Error: strict privacy requires an encrypted transport, but %s is unencrypted\n", transportStr)
				// os.Exit(1)
				fmt.Fprintf(os.Stderr, "Warning: strict privacy requested but transport %s is unencrypted. This is unsafe and leaks information.\n", transportStr)
			}
		}

		if rrtype == 0 {
			rrtype = dns.TypeA
		}

		_, err = strconv.Atoi(options["port"])
		if err != nil {
			fmt.Printf("Error: port %q is not valid: %v\n", options["port"], err)
			os.Exit(1)
		}

		// All args parsed, join server and port
		// options["server"] = net.JoinHostPort(options["server"], options["port"])

		if options["opcode"] == "" {
			options["opcode"] = "QUERY"
		}

		if tdns.Globals.Debug {
			fmt.Printf("*** Will send %s to server %s using transport %s, port %s\n",
				options["opcode"], options["server"], options["transport"], options["port"])
		}

		// +showpin needs no qname: connect, print the server cert's SPKI pin
		// (and TLSA 3-1-1 record) and exit. Bootstrap helper for pins: config
		// and TLSA publication.
		if options["showpin"] == "true" {
			showServerPin(options)
			return
		}

		for _, qname := range cleanArgs {
			qname = dns.Fqdn(qname)
			if tdns.Globals.Verbose {
				fmt.Printf("*** %s for %s IN %s:\n", options["opcode"], qname, dns.TypeToString[rrtype])
			}

			// +sigchase short-circuits the normal Exchange path and
			// runs the chain-walker against the configured server
			// (which must be a recursive resolver). Walker output is
			// a structured per-link tree; no normal answer is printed.
			if options["sigchase"] == "true" {
				chaserTransport, err := core.StringToTransport(options["transport"])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: invalid transport %s: %v\n", options["transport"], err)
					os.Exit(1)
				}
				// +time= bounds the chase too. This is the third client dog
				// builds, and it drifted for the same reason the TCP fallback
				// did -- a separate construction site with its own option
				// list. A chain walk is many queries rather than one, so an
				// unbounded chase is the place a timeout matters most.
				//
				// +tries and +adflag do not reach it: retries and the outgoing
				// AD bit are the chaser's own to decide, and neither is
				// reachable from here without changing its API.
				chaserClient := core.NewDNSClient(chaserTransport, options["port"], nil, timeoutOptions(options)...)
				dss := loadChaserAnchors()
				chaser := tdns.NewChaser(chaserClient, options["server"], dss)
				result, err := chaser.Chase(qname, rrtype)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: chase failed: %v\n", err)
					os.Exit(1)
				}
				tdns.RenderChain(result, os.Stdout, options["algchase"] == "true")
				continue
			}

			// Parse -y once (if given); used by both the AXFR/IXFR and the
			// regular-query paths below. Base64 secrets never contain ':'.
			var tsigName, tsigAlgo, tsigSecret string
			if tsigKeyFlag != "" {
				var terr error
				tsigName, tsigAlgo, tsigSecret, terr = parseTsigFlag(tsigKeyFlag)
				if terr != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", terr)
					os.Exit(1)
				}
			}

			switch rrtype {
			case dns.TypeAXFR, dns.TypeIXFR:
				upstream := net.JoinHostPort(options["server"], options["port"])
				// Verify flags only take effect over an encrypted transport;
				// refuse rather than silently ignore them on plain Do53 (else
				// +pin/+cafile/+tlsa/+cert/+key give a false sense of a
				// verified/authenticated transfer).
				if (verifyFlagsGiven(options) || clientIdentityGiven(options)) && dogtransport.PlainDo53(options["transport"]) {
					fmt.Fprintf(os.Stderr, "Error: +pin/+cafile/+tlsa/+cert/+key require an encrypted transport (+dot); refusing to ignore them over Do53\n")
					os.Exit(1)
				}
				var xferTLS *tls.Config
				switch {
				case dogtransport.PlainDo53(options["transport"]):
					// nil TLS config: plain TCP, unchanged.
				case strings.EqualFold(options["transport"], "DoT"):
					var terr error
					xferTLS, terr = buildDogTLSConfig(options)
					if terr != nil {
						fmt.Fprintf(os.Stderr, "Error: %v\n", terr)
						os.Exit(1)
					}
				default:
					fmt.Printf("Zone transfer only supported over Do53/TCP and DoT, not %s\n", options["transport"])
					os.Exit(1)
				}
				if err := tdns.ZoneTransferPrint(qname, upstream, serial, rrtype, options, tsigName, tsigAlgo, tsigSecret, xferTLS); err != nil {
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
				// The AD bit on the OUTGOING query (+adflag / +noadflag).
				// Absent unless asked for: dog's default stays off.
				if options["ad_bit"] == "true" {
					m.MsgHdr.AuthenticatedData = true
				}
				if options["ad_bit"] == "false" {
					m.MsgHdr.AuthenticatedData = false
				}
				// RD (+recurse / +norecurse). SetQuestion/SetUpdate leave it
				// set, so only an explicit +norec clears it.
				if options["rd_bit"] == "true" {
					m.MsgHdr.RecursionDesired = true
				}
				if options["rd_bit"] == "false" {
					m.MsgHdr.RecursionDesired = false
				}
				ednsUDPSize, err := dogopts.EDNSUDPSizeFromMap(options)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(1)
				}
				opt := &dns.OPT{
					Hdr: dns.RR_Header{
						Name:   ".",
						Rrtype: dns.TypeOPT,
						Class:  ednsUDPSize, // EDNS UDP payload size (RFC 6891)
						Ttl:    0,           // Extended RCODE and flags
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
					// Set DE bit (bit 13) - Delegation Extension
					opt.Hdr.Ttl |= 1 << 13
				}
				if level, ok := privacyLevel(options); ok {
					if err := edns0.AddPrivacyOption(opt, uint8(level)); err != nil {
						fmt.Printf("Error from AddPrivacyOption: %v", err)
						os.Exit(1)
					}
				}
				if _, ok := options["oots"]; ok {
					// -03: zero-length OOTS option; presence is opt-in.
					if err := edns0.AddOOTSOption(opt); err != nil {
						fmt.Printf("Error from AddOOTSOption: %v", err)
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

				start := time.Now()

				server, ok := options["server"]
				if !ok {
					log.Fatal("No server specified")
				}

				var tlsConfig *tls.Config
				// Verify flags only take effect over an encrypted transport;
				// refuse rather than silently ignore them on plain Do53 (else
				// +pin/+cafile/+tlsa/+cert/+key give a false sense of a
				// verified/authenticated transfer).
				if (verifyFlagsGiven(options) || clientIdentityGiven(options)) && dogtransport.PlainDo53(options["transport"]) {
					fmt.Fprintf(os.Stderr, "Error: +pin/+cafile/+tlsa/+cert/+key require an encrypted transport (+dot/+doh/+doq); refusing to ignore them over Do53\n")
					os.Exit(1)
				}
				// PlainDo53 is case-insensitive and also covers Do53-TCP/tcp;
				// a bare transport != "do53" mishandles the canonical "Do53"
				// spelling and would wrap a plain query in a TLS config.
				if transport, ok := options["transport"]; ok && !dogtransport.PlainDo53(transport) {
					if verifyFlagsGiven(options) {
						var terr error
						tlsConfig, terr = buildDogTLSConfig(options)
						if terr != nil {
							fmt.Fprintf(os.Stderr, "Error: %v\n", terr)
							os.Exit(1)
						}
						// ALPN is per-transport; the builder assumes DoT.
						switch transport {
						case "DoQ":
							tlsConfig.NextProtos = []string{"doq"}
						case "DoH":
							tlsConfig.NextProtos = nil // http client negotiates
						}
					} else {
						fmt.Fprintf(os.Stderr, ";; WARNING: server certificate NOT verified; use +tlsa, +pin=<spki-b64> or +cafile=<pem>\n")
						tlsConfig = &tls.Config{
							InsecureSkipVerify: true,
							MinVersion:         tls.VersionTLS12,
						}
						// Add ALPN for DoQ
						if transport == "DoQ" {
							tlsConfig.NextProtos = []string{"doq"}
						}
						// Still present a client identity if one was given.
						if cerr := attachDogClientCert(tlsConfig, options); cerr != nil {
							fmt.Fprintf(os.Stderr, "Error: %v\n", cerr)
							os.Exit(1)
						}
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

				// Warn if strict privacy was requested but the chosen
				// transport is unencrypted.
				// TODO: Once resolver supports encrypted transports, change this to hard fail
				if level, ok := privacyLevel(options); ok && level == edns0.PrivacyStrict {
					if !core.IsEncryptedTransport(t) {
						// Hard fail (commented out until resolver supports encrypted transports):
						// fmt.Printf("Error: strict privacy requires an encrypted transport, but %s is unencrypted\n", options["transport"])
						// os.Exit(1)
						fmt.Fprintf(os.Stderr, "Warning: strict privacy requested but transport %s is unencrypted. This is unsafe and leaks information.\n", options["transport"])
					}
				}

				// TSIG-sign the query (dig -y). Only the miekg-client transports
				// (Do53/Do53-TCP/DoT) have a TSIG path here; warn otherwise. The
				// option is reused on the TCP-fallback client below so a
				// truncated, retried query stays signed and verifiable.
				var tsigOpt core.DNSClientOption
				var tsigSigned bool // true only if the query was ACTUALLY TSIG-signed
				if tsigKeyFlag != "" {
					switch t {
					case core.TransportDo53, core.TransportDo53TCP, core.TransportDoT:
						m.SetTsig(dns.Fqdn(tsigName), tsigAlgo, 300, time.Now().Unix())
						tsigOpt = core.WithTsigSecret(tsigName, tsigSecret)
						clientOpts = append(clientOpts, tsigOpt)
						tsigSigned = true
					default:
						fmt.Fprintf(os.Stderr, "Warning: -y (TSIG) is only supported on Do53/Do53-TCP/DoT; not signing over %s\n", transport)
					}
				}

				if showDNSMessageTrace() {
					fmt.Println("*** Outbound DNS message:")
					out := m.String()
					fmt.Print(out)
					if !strings.HasSuffix(out, "\n") {
						fmt.Println()
					}
				}

				// +time=: bound each attempt. Without this the client's own
				// default applies and there is no way to shorten it from the
				// command line.
				clientOpts = append(clientOpts, timeoutOptions(options)...)
				client := core.NewDNSClient(t, options["port"], tlsConfig, clientOpts...)

				tries := triesFrom(options)
				var res *dns.Msg
				res, err = exchangeWithTries(client, m, server, tries) // FIXME: duration is always zero
				if err == nil && res != nil && res.Truncated && t == core.TransportDo53 && !forceTCP {
					// Warn if strict privacy was requested and we are falling
					// back to unencrypted TCP.
					// TODO: Once resolver supports encrypted transports, change this to hard fail
					if level, ok := privacyLevel(options); ok && level == edns0.PrivacyStrict {
						// Hard fail (commented out until resolver supports encrypted transports):
						// fmt.Printf("Error: strict privacy requires an encrypted transport, but response was truncated and fallback to Do53-TCP is unencrypted\n")
						// os.Exit(1)
						fmt.Fprintf(os.Stderr, "Warning: strict privacy requested but response was truncated, falling back to unencrypted Do53-TCP. This is unsafe and leaks information.\n")
					}
					fmt.Println(";; Truncated UDP response received; retrying over TCP")
					tcpOpts := []core.DNSClientOption{core.WithForceTCP()}
					if tsigOpt != nil {
						tcpOpts = append(tcpOpts, tsigOpt)
					}
					// The retry is a second client built from a separate
					// option list, so +time= has to be applied again here.
					// Without it the timeout silently stopped applying at
					// exactly the point a query got slower.
					tcpOpts = append(tcpOpts, timeoutOptions(options)...)
					tcpClient := core.NewDNSClient(core.TransportDo53, options["port"], tlsConfig, tcpOpts...)
					// dig's +tries is "the number of times to try UDP AND TCP
					// queries"; the fallback is a second client on a path that
					// is already slower than the one that truncated, so it gets
					// the same budget rather than a single shot.
					res, err = exchangeWithTries(tcpClient, m, server, tries)
					options["transport"] = "Do53-TCP"
				}

				elapsed := time.Since(start)
				// A TSIG issue does not mean "no answer": a bad response MAC
				// still returns the message, and an ABSENT response TSIG returns
				// no error at all (miekg only verifies a TSIG that is present).
				// So when we signed the query (-y) we always show the response
				// and append a dig-style TSIG status footer below, covering all
				// three cases: validated OK, failed to validate, or absent. A
				// real transport error with no response stays fatal.
				if err != nil && !(tsigSigned && res != nil) {
					fmt.Printf("Error from %s: %v\n", server, err)
					fmt.Printf("*** This is what we got: %+v\n", res)
					os.Exit(1)
				}
				if showDNSMessageTrace() {
					fmt.Println()
					fmt.Println("*** Incoming DNS response:")
				}
				tdns.MsgPrint(res, server, elapsed, short, options)
				if tsigSigned && res != nil {
					switch {
					case err != nil:
						fmt.Printf(";; WARNING: response TSIG did not validate: %v\n", err)
					case res.IsTsig() != nil:
						fmt.Printf(";; TSIG: response signature validated OK (key %s)\n", res.IsTsig().Hdr.Name)
					default:
						fmt.Printf(";; WARNING: query was TSIG-signed but the response carried NO TSIG\n")
					}
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

// ExecuteContext adds all child commands to the root command and sets flags appropriately.
// This is called by main.main() with a context for signal handling.
func ExecuteContext(ctx context.Context) {
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	//	rootCmd.AddCommand(cli.VersionCmd)

	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "Verbose mode")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "Debugging output")
	rootCmd.PersistentFlags().BoolVar(&showVersion, "version", false, "print version and supported algorithms, then exit")
	rootCmd.PersistentFlags().BoolVarP(&short, "short", "", false, "Only list RRs that are part of the Answer section")
	rootCmd.PersistentFlags().StringVarP(&port, "port", "p", "53", "Port to send DNS query to")
	rootCmd.PersistentFlags().StringVarP(&trustAnchorFile, "trust-anchor", "k", "", "Path to DNSSEC trust anchor file (zone-file format DS or DNSKEY records). Used by +sigchase. Default: read from "+tdns.DefaultImrCfgFile+" or fall back to compiled-in root KSK DS records.")
	rootCmd.PersistentFlags().StringVarP(&tsigKeyFlag, "tsig", "y", "", "TSIG-sign the query. Format [algorithm:]name:secret (dig-compatible); algorithm defaults to hmac-sha256. Do53/Do53-TCP/DoT only.")
}

// parseTsigFlag parses a dig-style -y value "[algorithm:]name:secret". The
// secret is base64 and never contains ':', so a 3-way split is unambiguous. The
// returned algo is a canonical miekg TSIG algorithm name (e.g. dns.HmacSHA256).
func parseTsigFlag(s string) (name, algo, secret string, err error) {
	parts := strings.SplitN(s, ":", 3)
	switch len(parts) {
	case 2:
		name, secret = parts[0], parts[1]
		algo = dns.HmacSHA256
	case 3:
		name, secret = parts[1], parts[2]
		// A TSIG algorithm identifier is a DOMAIN NAME (hmac-sha256., ...), so
		// it folds by the DNS rule like any other: US-ASCII A-Z and nothing
		// else.
		algo = core.CanonicalizeName(dns.Fqdn(parts[0]))
	default:
		return "", "", "", fmt.Errorf("-y must be [algorithm:]name:secret")
	}
	switch algo {
	case dns.HmacSHA1, dns.HmacSHA224, dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512:
	default:
		return "", "", "", fmt.Errorf("unsupported TSIG algorithm %q (use hmac-sha1|hmac-sha224|hmac-sha256|hmac-sha384|hmac-sha512)", algo)
	}
	if name == "" || secret == "" {
		return "", "", "", fmt.Errorf("-y must be [algorithm:]name:secret")
	}
	return name, algo, secret, nil
}

// showDNSMessageTrace enables outbound/incoming DNS message printouts for
// --verbose and --debug (the latter also prints lower-level parse tracing).
func showDNSMessageTrace() bool {
	return tdns.Globals.Verbose || tdns.Globals.Debug
}

// loadChaserAnchors resolves DS trust anchors via the standard priority
// chain (--trust-anchor flag -> IMR config -> compiled-in). Some TA files
// (autotrust / RFC 5011 managed) hold DNSKEY records rather than DS; each
// KSK DNSKEY is converted to its SHA-256 DS equivalent so the chaser, which
// keys off DS, can anchor the root regardless of file format.
func loadChaserAnchors() []*dns.DS {
	// Not gated on --verbose. Every message on this path means an anchor the
	// operator configured is NOT being used -- a stale key spelling, an
	// unreadable file, an RR that would not parse. The chase still produces a
	// verdict afterwards, and a verdict reached with the wrong anchors is the
	// one failure a user cannot spot from the output.
	taLogf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, ";; "+format+"\n", args...)
	}
	dss, keys, taSource := tdns.LoadDefaultTrustAnchors(trustAnchorFile, taLogf)
	for _, k := range keys {
		if k.Flags&dns.SEP == 0 {
			continue
		}
		if ds := k.ToDS(dns.SHA256); ds != nil {
			dss = append(dss, ds)
		}
	}
	if tdns.Globals.Verbose {
		fmt.Fprintf(os.Stderr, ";; trust anchor source: %s (%d DS records, %d DNSKEYs)\n", taSource, len(dss), len(keys))
	}
	return dss
}

// verifyFlagsGiven reports whether any of the certificate-verification
// options (+tlsa, +pin=, +cafile=) was requested.
func verifyFlagsGiven(options map[string]string) bool {
	return options["tlsa"] == "true" || options["pins"] != "" || options["cafile"] != ""
}

// timeoutOptions returns the client options implied by +time=, or nil.
//
// Shared because dog builds TWO clients: the one that sends the query, and the
// one that retries over TCP when the answer comes back truncated. They are
// constructed from separate option lists, and a +time= that applies to the
// first but not the second is a timeout that lapses precisely when a response
// is large enough to need the retry.
func timeoutOptions(options map[string]string) []core.DNSClientOption {
	v := options["timeout"]
	if v == "" {
		return nil
	}
	// ProcessOptions has already rejected anything unparsable and raised
	// anything below 1, so this cannot fail; it is here so a future caller
	// that has not been through the parser cannot produce an instant timeout.
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return nil
	}
	return []core.DNSClientOption{core.WithTimeout(time.Duration(n) * time.Second)}
}

// triesFrom is the +tries= budget: the TOTAL number of attempts, not the
// number after the first. One when nothing was asked for -- dog sends a single
// query by default, where dig sends three; changing that would alter every
// existing dog invocation, so it is left alone.
func triesFrom(options map[string]string) int {
	v := options["tries"]
	if v == "" {
		return 1
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// exchangeWithTries spends the +tries= budget on one client.
//
// Only a transport failure is retried. A response that came back at all is an
// answer -- SERVFAIL, NXDOMAIN, or one whose TSIG did not verify (miekg
// returns the message alongside that error, which is why the caller prints it)
// -- and asking the same server the same question again cannot change it,
// only make the failure slower and noisier.
func exchangeWithTries(client *core.DNSClient, m *dns.Msg, server string, tries int) (*dns.Msg, error) {
	var res *dns.Msg
	var err error
	for attempt := 1; ; attempt++ {
		res, _, err = client.Exchange(m, server, false)
		if err == nil || res != nil || attempt >= tries {
			return res, err
		}
		if tdns.Globals.Verbose {
			fmt.Fprintf(os.Stderr, ";; attempt %d/%d failed: %v\n", attempt, tries, err)
		}
	}
}

// clientIdentityGiven reports whether a client identity (+cert=/+key=) was
// requested. Either flag alone counts, so a lone +cert or +key is also caught
// (over plaintext it would otherwise be silently dropped).
func clientIdentityGiven(options map[string]string) bool {
	return options["clientcert"] != "" || options["clientkey"] != ""
}

// buildDogTLSConfig returns the TLS config for an encrypted-transport dog
// operation. With +pin/+cafile it builds a verifying config through
// tdns.ClientTLSConfigForPeer (a synthetic PeerConf from the flags); with
// +tlsa it chase-validates the server's TLSA RRset from the root trust
// anchors and pins the handshake to it. Without any verify flag it keeps
// dog's historical InsecureSkipVerify behavior, with a warning.
// buildDogTLSConfig returns the outbound tls.Config: how we verify the
// server's certificate (dogServerVerifyConfig) plus, when +cert=/+key= are
// given, our own client identity to present for the server's mutual-TLS /
// per-zone downstream-auth check.
func buildDogTLSConfig(options map[string]string) (*tls.Config, error) {
	cfg, err := dogServerVerifyConfig(options)
	if err != nil {
		return nil, err
	}
	if err := attachDogClientCert(cfg, options); err != nil {
		return nil, err
	}
	return cfg, nil
}

// attachDogClientCert loads +cert=/+key= into cfg.Certificates so dog can
// present a client identity. No-op when neither is set.
func attachDogClientCert(cfg *tls.Config, options map[string]string) error {
	cc, ck := options["clientcert"], options["clientkey"]
	if cc == "" && ck == "" {
		return nil
	}
	if cc == "" || ck == "" {
		return fmt.Errorf("+cert= and +key= must be given together")
	}
	pair, err := tls.LoadX509KeyPair(cc, ck)
	if err != nil {
		return fmt.Errorf("loading client cert/key (+cert/+key): %v", err)
	}
	cfg.Certificates = []tls.Certificate{pair}
	return nil
}

func dogServerVerifyConfig(options map[string]string) (*tls.Config, error) {
	server := options["server"]
	port := options["port"]

	nVerify := 0
	if options["tlsa"] == "true" {
		nVerify++
	}
	if options["pins"] != "" {
		nVerify++
	}
	if options["cafile"] != "" {
		nVerify++
	}
	switch nVerify {
	case 0:
		fmt.Fprintf(os.Stderr, ";; WARNING: server certificate NOT verified; use +tlsa, +pin=<spki-b64> or +cafile=<pem>\n")
		return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, nil
	case 1:
	default:
		return nil, fmt.Errorf("choose ONE of +tlsa, +pin=, +cafile=")
	}

	if options["tlsa"] == "true" {
		return dogDaneTLSConfig(server, port)
	}

	peer := tdns.PeerConf{
		Addr:      net.JoinHostPort(server, port),
		Key:       tdns.NOKEY,
		Transport: tdns.TransportDoT,
	}
	if options["pins"] != "" {
		peer.TLSAuth = tdns.TLSAuthPin
		peer.Pins = strings.Split(options["pins"], ",")
	} else {
		peer.TLSAuth = tdns.TLSAuthPKIX
		peer.CAFile = options["cafile"]
		if net.ParseIP(server) != nil {
			// PKIX against an IP literal matches the cert's IP SANs; a
			// verify failure here is usually a missing IP SAN, not a bad CA.
			fmt.Fprintf(os.Stderr, ";; note: server %s is an IP literal — PKIX will match the certificate's IP SANs (a name-mismatch failure usually means the cert lacks this IP SAN)\n", server)
		}
	}
	conf := &tdns.Config{}
	return conf.ClientTLSConfigForPeer(peer)
}

// dogDaneTLSConfig implements +tlsa: fetch and chain-validate (from the root
// trust anchors, via the system resolver) the TLSA RRset at
// _<port>._tcp.<server>, then pin the TLS handshake to it. Fails closed when
// the chain is not provably secure. The lookup goes through the system
// resolver rather than @server because @server is typically the
// authoritative primary being transferred from, not a recursive.
func dogDaneTLSConfig(server, port string) (*tls.Config, error) {
	if net.ParseIP(server) != nil {
		return nil, fmt.Errorf("+tlsa needs a server NAME for the TLSA base; got IP literal %s (use +pin= or +cafile=)", server)
	}
	resolver, err := ParseResolvConf()
	if err != nil {
		return nil, fmt.Errorf("+tlsa: cannot determine system resolver: %v", err)
	}
	client := core.NewDNSClient(core.TransportDo53, "53", nil)
	chaser := tdns.NewChaser(client, resolver, loadChaserAnchors())
	owner := fmt.Sprintf("_%s._tcp.%s", port, dns.Fqdn(server))
	res, err := chaser.Chase(owner, dns.TypeTLSA)
	if err != nil {
		return nil, fmt.Errorf("+tlsa: TLSA chase for %s failed: %v", owner, err)
	}
	if res.Status != tdns.ChainStatusSecure || res.Leaf.RRset == nil || len(res.Leaf.RRset.RRs) == 0 {
		return nil, fmt.Errorf("+tlsa: TLSA RRset for %s is not provably secure; refusing (fail closed)", owner)
	}
	tlsaRRs := res.Leaf.RRset.RRs
	if tdns.Globals.Verbose {
		for _, rr := range tlsaRRs {
			fmt.Fprintf(os.Stderr, ";; validated TLSA: %s\n", rr.String())
		}
	}
	return &tls.Config{
		ServerName: server,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"dot"},
		// DANE-EE replaces PKIX chain building; VerifyConnection is the gate.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("server presented no certificate")
			}
			for _, rr := range tlsaRRs {
				if tlsa, ok := rr.(*dns.TLSA); ok {
					if err := tdns.VerifyCertAgainstTlsaRR(tlsa, cs.PeerCertificates[0]); err == nil {
						return nil
					}
				}
			}
			return fmt.Errorf("no validated TLSA record at %s matches the server certificate", owner)
		},
	}, nil
}

// showServerPin implements +showpin: connect over TLS (unverified — this IS
// the bootstrap step), print the server certificate's SPKI SHA-256 pin and
// the equivalent TLSA 3-1-1 record, then move on. A plain-Do53 transport
// implies DoT on port 853.
func showServerPin(options map[string]string) {
	server := options["server"]
	port := options["port"]
	if dogtransport.PlainDo53(options["transport"]) {
		port = "853"
		fmt.Fprintf(os.Stderr, ";; +showpin: assuming DoT on port %s (use +dot with -p to override)\n", port)
	}
	addr := net.JoinHostPort(server, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"dot"}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot fetch server certificate from %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: %s presented no certificate\n", addr)
		os.Exit(1)
	}
	leaf := certs[0]
	fmt.Printf(";; server:  %s\n", addr)
	fmt.Printf(";; subject: %s\n", leaf.Subject)
	fmt.Printf(";; SPKI pin (for pins: / +pin=): %s\n", tdns.SPKISHA256(leaf))
	if portNum, perr := strconv.ParseUint(port, 10, 16); perr == nil {
		if tlsa, terr := tdns.NewTlsaRR(dns.Fqdn(server), uint16(portNum), leaf); terr == nil {
			fmt.Printf(";; TLSA:    %s\n", tlsa.String())
		}
	}
}

// privacyLevel returns the PRIVACY level +PR put in the options map, and
// whether the option was asked for at all. An unparseable value cannot occur:
// ProcessOptions only ever writes back what edns0.ParsePrivacyLevel accepted.
func privacyLevel(options map[string]string) (edns0.PrivacyLevel, bool) {
	raw, ok := options["privacy"]
	if !ok {
		return edns0.PrivacyNone, false
	}
	level, err := edns0.ParsePrivacyLevel(raw)
	if err != nil {
		return edns0.PrivacyNone, false
	}
	return level, true
}

// ProcessOptions interprets one +option argument. ucarg is the uppercased
// form (used for matching); arg is the original argument, needed whenever the
// option value is case-sensitive (base64 pins, file paths).
func ProcessOptions(options map[string]string, ucarg, arg string) (map[string]string, error) {
	if options == nil {
		options = make(map[string]string)
	}

	// XoT/TLS verification options (case-sensitive values -> parse from arg).
	if strings.HasPrefix(ucarg, "+PIN=") {
		pin := arg[len("+pin="):]
		if pin == "" {
			return nil, fmt.Errorf("+pin= requires a base64 SPKI SHA-256 digest")
		}
		// Repeatable; base64 std alphabet never contains ',' so join on it.
		if options["pins"] != "" {
			options["pins"] += ","
		}
		options["pins"] += pin
		return options, nil
	}
	// dig compatibility: +time=/+timeout= bound one query, +tries=/+retry=
	// decide how many attempts it gets. Scripts reach for these when they must
	// not hang, and rejecting them fatally means a dig-shaped script dies here
	// rather than degrading.
	if strings.HasPrefix(ucarg, "+TIME=") || strings.HasPrefix(ucarg, "+TIMEOUT=") {
		v := arg[strings.Index(arg, "=")+1:]
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("+time= requires a number of seconds, not %q", v)
		}
		// dig raises anything below 1 to 1 silently ("An attempt to set T to
		// less than 1 is silently set to 1"), and REFUSES anything above
		// MAXTIMEOUT -- 0xffff in bin/dig/dighost.h, where the +timeout case
		// does parse_uint(&timeout, value, MAXTIMEOUT, "timeout") and exits
		// when that fails. Match both. Silently shortening a timeout the
		// caller asked for is the same class of trap as reading "+time=5s" as
		// 5: the script gets a value it did not choose and no diagnostic.
		if n < 1 {
			n = 1
		}
		if n > 65535 {
			return nil, fmt.Errorf("+time= must be at most 65535 seconds, not %q", v)
		}
		options["timeout"] = strconv.Itoa(n)
		return options, nil
	}
	if strings.HasPrefix(ucarg, "+TRIES=") || strings.HasPrefix(ucarg, "+RETRY=") {
		v := arg[strings.Index(arg, "=")+1:]
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s requires a number, not %q", strings.SplitN(ucarg, "=", 2)[0], v)
		}
		// dig's two spellings differ by one: +tries is the total number of
		// attempts, +retry is the number AFTER the first. Both clamp to at
		// least one attempt -- +tries=0 in dig still sends one query.
		if strings.HasPrefix(ucarg, "+RETRY=") {
			n = n + 1
		}
		if n < 1 {
			n = 1
		}
		options["tries"] = strconv.Itoa(n)
		return options, nil
	}
	if strings.HasPrefix(ucarg, "+CAFILE=") {
		path := arg[len("+cafile="):]
		if path == "" {
			return nil, fmt.Errorf("+cafile= requires a path to a PEM cert bundle")
		}
		options["cafile"] = path
		return options, nil
	}
	// Client identity for mutual TLS / a server's per-zone downstream-auth
	// (tls-pin/pkix/dane): present this cert so the server can authenticate us.
	if strings.HasPrefix(ucarg, "+CERT=") {
		path := arg[len("+cert="):]
		if path == "" {
			return nil, fmt.Errorf("+cert= requires a path to a PEM certificate")
		}
		options["clientcert"] = path
		return options, nil
	}
	if strings.HasPrefix(ucarg, "+KEY=") {
		path := arg[len("+key="):]
		if path == "" {
			return nil, fmt.Errorf("+key= requires a path to a PEM private key")
		}
		options["clientkey"] = path
		return options, nil
	}

	switch ucarg {
	case "+TLSA":
		// DANE-verify the server cert: TLSA at _<port>._tcp.<server>,
		// chase-validated from the root trust anchors.
		options["tlsa"] = "true"
		return options, nil
	case "+SHOWPIN":
		// Connect, print the server cert's SPKI pin (and TLSA 3-1-1 rdata),
		// and exit. For bootstrapping pins: / TLSA records.
		options["showpin"] = "true"
		return options, nil
	}

	switch ucarg {
	case "+DNSSEC", "+DO":
		options["do_bit"] = "true"
		return options, nil
	case "+CD":
		options["cd_bit"] = "true"
		return options, nil
	case "+ADFLAG", "+AD":
		// The AD bit in the OUTGOING query. dig sets it by default; dog does
		// not, and this does not change that -- it makes the flag work for
		// callers that ask explicitly. Changing the default is a separate
		// decision, tracked in the issue.
		options["ad_bit"] = "true"
		return options, nil
	case "+NOADFLAG", "+NOAD":
		options["ad_bit"] = "false"
		return options, nil
	// dig's +recurse/+norecurse, with dig's abbreviations. miekg's SetQuestion
	// sets RD, so without these there is no way to ask a cache or an
	// authoritative server a non-recursive question -- which is what a debug
	// window onto a resolver's cache is for.
	case "+RECURSE", "+REC":
		options["rd_bit"] = "true"
		return options, nil
	case "+NORECURSE", "+NOREC":
		options["rd_bit"] = "false"
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
	case "+SHORT":
		// dig-compatible: only print the RDATA of the Answer RRset.
		// Acts as the +XYZ-syntax equivalent of the --short flag.
		options["short"] = "true"
		return options, nil
	case "+SIGCHASE", "+SIGCHA", "+SC":
		// drill-style: walk the DNSSEC chain for the qname/qtype and
		// emit a per-link verdict tree. Dispatches into the chase
		// library in tdns/v2/chase.go instead of the normal query
		// path. Verifies each (parent DS) <-> (child KSK) <-> (DNSKEY
		// RRset signature) link and the final leaf RRSIG against the
		// deepest zone's keys.
		options["sigchase"] = "true"
		return options, nil
	case "+ALGCHASE", "+ALGCHA", "+AC":
		// Annotate each algorithm number in the +sigchase chain output
		// with its algorithm name (from the in-process registry), e.g.
		// "alg=214 (CROSSRSDPG128SMALL)". Meaningless on its own — it
		// enriches what +sigchase already walks — so it implies +sigchase.
		options["sigchase"] = "true"
		options["algchase"] = "true"
		return options, nil
	case "+ZONEMD", "+ZMD":
		// Verify the transferred zone's apex ZONEMD (RFC 8976) against the
		// records that arrived. Meaningful only with AXFR: an IXFR returns a
		// difference, which has no digest, and the transfer path refuses
		// rather than producing a meaningless one.
		options["zonemd"] = "true"
		return options, nil
	case "+IGNORESERIAL", "+IGNSER":
		// Digest against the serial each ZONEMD names rather than the one the
		// SOA carries -- the question "was this digest right for the serial it
		// claims?", which is what an operator wants when a pipeline digests a
		// zone and then bumps its serial. NOT a laxer verification: a zone that
		// only passes this way is one no RFC 8976 verifier will accept.
		options["ignoreserial"] = "true"
		return options, nil
	case "+TCP":
		// A pre-existing "Do53" is the default ParseServer writes when
		// the user supplied @host without a scheme; treat it as an
		// upgrade target. Only reject when a different encrypted
		// transport was already explicitly selected.
		if transport, exists := options["transport"]; exists && transport != "Do53" {
			return nil, fmt.Errorf("Error: multiple transport options specified (%s and TCP)", transport)
		}
		options["transport"] = "Do53-TCP"
		return options, nil
	case "+TLS", "+DOT":
		if transport, exists := options["transport"]; exists && transport != "Do53" {
			return nil, fmt.Errorf("Error: multiple transport options specified (%s and DoT)", transport)
		}
		options["transport"] = "DoT"
		return options, nil
	case "+HTTPS", "+DOH":
		if transport, exists := options["transport"]; exists && transport != "Do53" {
			return nil, fmt.Errorf("Error: multiple transport options specified (%s and DoH)", transport)
		}
		options["transport"] = "DoH"
		return options, nil
	case "+QUIC", "+DOQ":
		if transport, exists := options["transport"]; exists && transport != "Do53" {
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
					// Try to parse as numeric opcode
					opcode, err := strconv.Atoi(parts[1])
					if err != nil {
						return nil, fmt.Errorf("invalid +OPCODE=%q: must be QUERY, NOTIFY, UPDATE, or a valid numeric opcode", parts[1])
					}
					// Validate numeric opcode is one of the accepted values
					switch opcode {
					case dns.OpcodeQuery:
						options["opcode"] = "QUERY"
					case dns.OpcodeNotify:
						options["opcode"] = "NOTIFY"
					case dns.OpcodeUpdate:
						options["opcode"] = "UPDATE"
					default:
						return nil, fmt.Errorf("invalid +OPCODE=%q: opcode %d is not supported (use QUERY, NOTIFY, or UPDATE)", parts[1], opcode)
					}
				}
			}
			return options, nil
		}

		// +OOTS: include the zero-length OOTS EDNS option (opt-in by presence).
		ucargUpper := strings.ToUpper(ucarg)
		if ucargUpper == "+OOTS" || strings.HasPrefix(ucargUpper, "+OOTS=") {
			if strings.Contains(ucarg, "=") {
				parts := strings.SplitN(ucarg, "=", 2)
				arg := strings.ToLower(parts[1])
				if arg != "" && arg != "opt_in" && arg != "1" {
					return nil, fmt.Errorf("OOTS is presence-only (-03); unsupported argument %q", arg)
				}
			}
			options["oots"] = "opt_in"
			return options, nil
		}

		// +PR / +PRIVACY: the PRIVACY EDNS(0) option, one octet.
		//
		// Bare +PR is strict, which is what the PR flag bit this option
		// replaced always meant -- an existing "+PR" on a command line keeps
		// doing what it did. Anything softer has to be asked for by name.
		if ucargUpper == "+PR" || ucargUpper == "+PRIVACY" ||
			strings.HasPrefix(ucargUpper, "+PR=") || strings.HasPrefix(ucargUpper, "+PRIVACY=") {
			level := edns0.PrivacyStrict
			if idx := strings.Index(ucarg, "="); idx >= 0 {
				parsed, err := edns0.ParsePrivacyLevel(ucarg[idx+1:])
				if err != nil {
					return nil, fmt.Errorf("Error: %v", err)
				}
				level = parsed
			}
			options["privacy"] = strconv.Itoa(int(level))
			return options, nil
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

		if val, ok := dogopts.ParseBufsizeFlag(ucarg); ok {
			if val == "" {
				return nil, fmt.Errorf("Error: +bufsize requires a value (e.g. +bufsize=512)")
			}
			if _, err := dogopts.ParseEDNSUDPSize(val); err != nil {
				return nil, fmt.Errorf("Error: %v", err)
			}
			options["bufsize"] = val
			return options, nil
		}

		return nil, fmt.Errorf("Error: Unknown option: %s", ucarg)
	}
}

func ParseResolvConf() (string, error) {
	// Read /etc/resolv.conf to get the default nameserver
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("unable to read /etc/resolv.conf: %w", err)
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
		return "", fmt.Errorf("no nameserver entry found in /etc/resolv.conf")
	}
	return server, nil
}

// bracketBareIPv6URL rewrites "<scheme>://<bare-ipv6>[/path]" as
// "<scheme>://[<bare-ipv6>][/path]" when the authority is an unbracketed IPv6
// literal, and reports whether it rewrote anything. url.Parse rejects the
// unbracketed form outright ("invalid port \":5\" after host"), which reads as
// a complaint about a port the user never typed.
func bracketBareIPv6URL(arg string) (string, bool) {
	scheme, rest, found := strings.Cut(arg, "://")
	if !found {
		return "", false
	}
	host, tail := rest, ""
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		host, tail = rest[:i], rest[i:]
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil { // not an IPv6 literal: nothing to bracket
		return "", false
	}
	return scheme + "://[" + host + "]" + tail, true
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
			// A scheme'd bare IPv6 literal ("dot://2001:db8::5") fails to
			// parse for the same reason the bare form dialled the wrong
			// port (#441): the trailing hextet reads as a port. Retry with
			// the authority bracketed before giving up.
			if fixed, ok := bracketBareIPv6URL(serverArg); ok {
				u, err = url.Parse(fixed)
			}
		}
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
	// bareIP records that u.Host turned out to be an unbracketed IP literal,
	// so the u.Port() fallback below must not run: url.URL.Port() splits at
	// the LAST colon, so on "2001:db8::5" it returns "5" and dog would dial
	// port 5 (#441).
	bareIP := false

	// Check if host contains a colon (could be IPv6 or host:port)
	if strings.Contains(host, ":") {
		// Check if it's an IPv6 address in brackets with port (e.g., [::1]:5354)
		if strings.HasPrefix(host, "[") && strings.Contains(host, "]:") {
			// IPv6 with port: [::1]:5354
			var portErr error
			host, port, portErr = net.SplitHostPort(host)
			if portErr != nil {
				return nil, fmt.Errorf("%s is not in host:port format: %v", u.Host, portErr)
			}
		} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			// Bare bracketed IPv6 without port (e.g., [::1])
			// Strip the brackets and validate as IPv6
			host = strings.Trim(host, "[]")
			if net.ParseIP(host) == nil {
				return nil, fmt.Errorf("%s is not a valid IPv6 address", u.Host)
			}
			// port remains empty
		} else if net.ParseIP(host) != nil {
			// Valid IP address (IPv4 or IPv6) without port - use as-is
			// net.ParseIP handles both IPv4 and IPv6 correctly
			// No need to split, it's just the IP address
			bareIP = true
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
	switch {
	case port != "":
		options["port"] = port
	case bareIP:
		// No port was given: leave it unset so the caller applies the
		// transport's default. Asking u.Port() here is what dialled
		// @2001:db8::5 on port 5 (#441).
	case u.Port() != "":
		options["port"] = u.Port()
	}

	// For DoH, DoQ, etc., the path may be important
	if u.Path != "" && u.Path != "/" {
		options["path"] = u.Path
	}

	if strings.HasSuffix(options["server"], "/") {
		options["server"] = options["server"][:len(options["server"])-1]
	}

	// Basic validation
	if options["server"] == "" {
		return nil, fmt.Errorf("empty host specified")
	}

	return options, nil
}
