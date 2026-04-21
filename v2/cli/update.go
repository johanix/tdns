/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/gookit/goutil/dump"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var zone, server, keyfile, signer string

var ChildCmd = &cobra.Command{
	Use:   "child",
	Short: "Prefix, only useable via the 'child update create' subcommand",
}

var childUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Prefix, only useable via the 'update create' subcommand",
}

var childUpdateCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create and ultimately send a DNS UPDATE msg for a child zone to the parent zone",
	Long: `Will query for details about the DNS UPDATE via (add|del|show|set-ttl) commands.
When the message is complete it may be signed and sent by the 'send' command. After a 
message has been send the loop will start again with a new, empty message to create.
Loop ends on the command "QUIT"

The zone to update is mandatory to specify on the command line with the --zone flag.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		CreateUpdate("child")
	},
}

var UpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "[OBE] Create and ultimately send a DNS UPDATE msg for zone auth data",
}

var updateCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "[OBE] Create and ultimately send a DNS UPDATE msg for zone auth data",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		CreateUpdate("foo")
	},
}

var zoneUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Create and ultimately send a DNS UPDATE msg for zone auth data",
}

var zoneUpdateCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create and ultimately send a DNS UPDATE msg for zone auth data",
	Long: `Will query for details about the DNS UPDATE via (add|del|show|set-ttl) commands.
When the message is complete it may be signed and sent by the 'send' command. After a 
message has been send the loop will start again with a new, empty message to create.
Loop ends on the command "QUIT"

The zone to update is mandatory to specify on the command line with the --zone flag.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		CreateUpdate("zone")
	},
}

// AttachUpdateCreateFlags adds the three flags common to every
// "update create" entry point — --signer, --server, --key — to cmd,
// bound to the package-level vars CreateUpdate reads. Use this from
// every leaf create command (including cross-package ones in
// tdns-mp/v2/cli) so the signer name, target server, and keyfile can
// always be overridden from the CLI.
func AttachUpdateCreateFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&signer, "signer", "", "",
		"Name of signer (key used to sign the update; defaults to --zone)")
	cmd.Flags().StringVarP(&server, "server", "S", "",
		"Server to send the update to (addr:port)")
	cmd.Flags().StringVarP(&keyfile, "key", "K", "",
		"SIG(0) keyfile to use for signing (.private/.key basename)")
}

// init registers update-related Cobra subcommands and binds their
// command-line flags.
func init() {
	ChildCmd.AddCommand(childUpdateCmd)
	childUpdateCmd.AddCommand(childUpdateCreateCmd)
	childUpdateCreateCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to update")
	childUpdateCreateCmd.Flags().StringVarP(&tdns.Globals.ParentZone, "parent", "P", "", "Parent zone to send update to")
	AttachUpdateCreateFlags(childUpdateCreateCmd)

	ZoneCmd.AddCommand(zoneUpdateCmd)
	zoneUpdateCmd.AddCommand(zoneUpdateCreateCmd)
	zoneUpdateCreateCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to update")
	AttachUpdateCreateFlags(zoneUpdateCreateCmd)

	UpdateCmd.AddCommand(updateCreateCmd)
	AttachUpdateCreateFlags(updateCreateCmd)
}

// CreateUpdate starts an interactive CLI for composing, signing, and sending DNS UPDATEs.
//
// It initializes the keystore and signing state, then enters a prompt loop that lets the
// user add or delete RRs, view the pending update, sign it with SIG(0) keys (from a keyfile
// or the keystore), select the target server, and send the update.
// The function updates package-level globals such as `zone`, `signer`, and `server` as needed.
// It may call os.Exit on fatal initialization or signing errors.
//
// The updateType parameter selects the operational context used to initialize the interactive
// session (for example "child" or "zone") and does not affect the format of the DNS UPDATE
// messages produced.
func CreateUpdate(updateType string) {
	kdb, err := tdns.NewKeyDB(viper.GetString("db.file"), false, nil)
	if err != nil {
		fmt.Printf("Error from NewKeyDB(): %v\n", err)
		os.Exit(1)
	}

	// Single ordered list of update actions. RFC 2136 processes the
	// Update section in order on the receiver, so we must preserve the
	// exact entry sequence — separate add/del/del-rrset slices would
	// reshuffle them.
	type updateAction struct {
		op string // "add" | "del" | "del-rrset"
		rr dns.RR
	}
	var actions []updateAction

	var ttl int = 60
	var op, rrstr, port string

	// buildUpdate assembles a *dns.Msg from the ordered actions list
	// using the library helpers (Insert/Remove/RemoveRRset) one record
	// at a time, so each one gets the correct class/rdata treatment
	// without losing entry order.
	buildUpdate := func() (*dns.Msg, error) {
		if zone == "" || zone == "." {
			return nil, fmt.Errorf("zone not set")
		}
		m := new(dns.Msg)
		m.SetUpdate(zone)
		for _, a := range actions {
			switch a.op {
			case "add":
				m.Insert([]dns.RR{a.rr})
			case "del":
				m.Remove([]dns.RR{a.rr})
			case "del-rrset":
				m.RemoveRRset([]dns.RR{a.rr})
			}
		}
		m.SetEdns0(1232, true)
		return m, nil
	}

	zone = dns.Fqdn(tdns.Globals.Zonename)
	if signer == "" {
		signer = zone
	}

	signer = dns.Fqdn(signer)

	var sak *tdns.Sig0ActiveKeys
	var signing bool = false

	if keyfile != "" {
		pkc, err := tdns.ReadPrivateKey(keyfile)
		switch {
		case err != nil:
			fmt.Printf("Error reading SIG(0) key file '%s': %v\n", keyfile, err)
		case pkc == nil:
			fmt.Printf("Keyfile '%s' yielded no key\n", keyfile)
		case pkc.KeyType != dns.TypeKEY:
			fmt.Printf("Keyfile '%s' did not contain a SIG(0) key\n", keyfile)
		default:
			fmt.Printf("Using keyfile %s (signer=%s, keyid=%d)\n",
				keyfile, pkc.KeyRR.Header().Name, pkc.KeyRR.KeyTag())
			sak = &tdns.Sig0ActiveKeys{
				Keys: []*tdns.PrivateKeyCache{pkc},
			}
			signing = true
		}
		if !signing {
			fmt.Printf("Warning: no SIG(0) signing of update messages possible.\n")
		}
	} else {
		sak, err = kdb.GetSig0Keys(signer, tdns.Sig0StateActive)
		if err != nil {
			fmt.Printf("Error fetching active SIG(0) key for zone %s: %v\n", signer, err)
		} else if len(sak.Keys) == 0 {
			fmt.Printf("No SIG(0) private key for zone %s found in keystore\n", signer)
		} else {
			fmt.Printf("SIG(0) private key for zone %s (keyid %d) successfully fetched from keystore\n", signer, sak.Keys[0].KeyId)
		}
		fmt.Printf("Update will be sent to zone %s\n", zone)
	}

	var ops = []string{"zone", "add", "del", "replace", "show", "send", "sign", "set-ttl", "server", "quit"}
	fmt.Printf("Defined operations are: %v\n", ops)

	var msgSigned bool = false

	SignUpdate := func(msg *dns.Msg, zone string) (*dns.Msg, error) {
		if server == "" {
			fmt.Println("Target server not set, please set it first")
			return nil, fmt.Errorf("target server not set")
		}
		if zone == "" {
			fmt.Println("Target zone not set, please set it first")
			return nil, fmt.Errorf("target zone not set")
		}
		if len(actions) == 0 {
			fmt.Println("No records to send, please add or delete some records first")
			return nil, fmt.Errorf("no records to send")
		}
		updateMsg, err := buildUpdate()
		if err != nil {
			fmt.Printf("Error creating update: %v\n", err)
			return nil, fmt.Errorf("error creating update: %v", err)
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

			m, err := tdns.SignMsg(*updateMsg, zone, sak)
			if err != nil {
				fmt.Printf("Error signing message: %v\n", err)
				os.Exit(1)
			}
			return m, nil
		} else {
			fmt.Printf("No SIG(0) keyfile specified, trying to fetch active key from keystore\n")
			sak, err := kdb.GetSig0Keys(signer, tdns.Sig0StateActive)
			if err != nil {
				fmt.Printf("Error fetching active SIG(0) key for zone %s: %v\n", signer, err)
				os.Exit(1)
			}
			if len(sak.Keys) == 0 {
				fmt.Printf("No SIG(0) private key for zone %s found in keystore. Signing not possible.\n", signer)
			}
			// if tdns.Globals.Verbose {
			fmt.Printf("Will sign update with SIG(0) key for %s with keyid %d\n",
				signer, sak.Keys[0].KeyId)
			// }
			if len(sak.Keys) > 0 {
				m, err := tdns.SignMsg(*updateMsg, signer, sak)
				if err != nil {
					fmt.Printf("Error signing message: %v\n", err)
					os.Exit(1)
				}
				return m, nil
			}
			return nil, fmt.Errorf("no SIG(0) private key for zone %s found in keystore. Signing not possible", signer)
		}
	}

	var msg *dns.Msg

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
			if len(rrstr) == 0 {
				fmt.Println("No record to add or delete, please specify a complete record")
				continue
			}
			rr, err := dns.NewRR(rrstr)
			if err != nil {
				fmt.Printf("Error parsing RR: %v\n", err)
				continue
			}

			if ttl > 0 {
				rr.Header().Ttl = uint32(ttl)
			}

			wantOp := op // "add" or "del"
			duplicate := false
			for _, a := range actions {
				if a.op == wantOp && dns.IsDuplicate(rr, a.rr) {
					fmt.Printf("Record already %sed: %s\n", wantOp, rrstr)
					duplicate = true
					break
				}
			}
			if !duplicate {
				actions = append(actions, updateAction{op: wantOp, rr: rr})
			}

		case "replace":
			if zone == "." {
				fmt.Println("Target zone not set, please set it first")
				continue
			}
			input := tdns.TtyQuestion("Owner name of RRset to replace (e.g. 'foo.bar. NS')", "", true)
			if strings.ToUpper(input) == "QUIT" {
				break cmdloop
			}

			// Accept either a bare owner name or an RR-style prefix
			// like "foo.bar. IN NS" — first token is owner, scan the
			// rest for a type, skip class/TTL tokens.
			fields := strings.Fields(input)
			owner := dns.Fqdn(fields[0])
			var rrtype uint16
			for _, tok := range fields[1:] {
				if t, ok := dns.StringToType[strings.ToUpper(tok)]; ok {
					rrtype = t
					break
				}
			}
			if rrtype == 0 {
				typestr := tdns.TtyQuestion("RR type", "A", true)
				t, ok := dns.StringToType[strings.ToUpper(typestr)]
				if !ok {
					fmt.Printf("Unknown RR type: %s\n", typestr)
					continue
				}
				rrtype = t
			}

			// Queue the §2.5.2 delete-RRset first, then the replacement
			// adds, in entry order. m.RemoveRRset only reads Name+Rrtype
			// from the placeholder.
			actions = append(actions, updateAction{
				op: "del-rrset",
				rr: &dns.ANY{Hdr: dns.RR_Header{Name: owner, Rrtype: rrtype}},
			})
			fmt.Printf("Queued DEL-RRSET for %s %s\n",
				owner, dns.TypeToString[rrtype])

			fmt.Println("Enter replacement records (blank line to finish):")
			for {
				rrstr = tdns.TtyQuestion("Record", "", false)
				if rrstr == "" {
					break
				}
				if strings.ToUpper(rrstr) == "QUIT" {
					break cmdloop
				}
				rr, err := dns.NewRR(rrstr)
				if err != nil {
					fmt.Printf("Error parsing RR: %v\n", err)
					continue
				}
				if rr.Header().Name != owner {
					fmt.Printf("Warning: record owner %q differs from RRset owner %q\n",
						rr.Header().Name, owner)
				}
				if rr.Header().Rrtype != rrtype {
					fmt.Printf("Warning: record type %s differs from RRset type %s\n",
						dns.TypeToString[rr.Header().Rrtype],
						dns.TypeToString[rrtype])
				}
				if ttl > 0 {
					rr.Header().Ttl = uint32(ttl)
				}
				actions = append(actions, updateAction{op: "add", rr: rr})
			}

		case "show":
			if zone == "." {
				fmt.Println("Target zone not set, please set it first")
				continue
			}
			if msg == nil {
				var out = []string{"Operation|Record"}
				for _, a := range actions {
					switch a.op {
					case "add":
						out = append(out, fmt.Sprintf("ADD|%s", a.rr.String()))
					case "del":
						out = append(out, fmt.Sprintf("DEL|%s", a.rr.String()))
					case "del-rrset":
						h := a.rr.Header()
						out = append(out, fmt.Sprintf("DEL-RRSET|%s %s",
							h.Name, dns.TypeToString[h.Rrtype]))
					}
				}
				fmt.Println(columnize.SimpleFormat(out))

				preview, err := buildUpdate()
				if err != nil {
					fmt.Printf("Error creating update: %v\n", err)
					continue
				}
				fmt.Printf("Update message:\n%s\n", preview.String())
			} else {
				fmt.Printf("Update message:\n%s\n", msg.String())
			}

		case "sign":
			if msgSigned {
				fmt.Println("Message already signed, please create a new message first")
				continue
			}

			msg, err = SignUpdate(msg, zone)
			if err != nil {
				fmt.Printf("Error signing message: %v\n", err)
				continue
			}
			msgSigned = true

		case "server":
			server = tdns.TtyQuestion("Server", "localhost", false)
			port = tdns.TtyQuestion("Port", "53", false)
			if server == "" {
				fmt.Println("Error: server cannot be empty")
				continue
			}
			portNum, err := strconv.Atoi(port)
			if err != nil || portNum < 1 || portNum > 65535 {
				fmt.Printf("Error: invalid port %q (must be 1-65535)\n", port)
				continue
			}
			server = net.JoinHostPort(server, port)

		case "send":
			if !msgSigned {

				msg, err = SignUpdate(msg, zone)
				if err != nil {
					fmt.Printf("Error signing message: %v\n", err)
					continue
				}
			}

			fmt.Printf("Sending update to %s\n", server)
			dump.P(msg)
			rcode, ur, err := tdns.SendUpdate(msg, zone, []string{server})
			if err != nil {
				fmt.Printf("Error sending update: %v\n", err)
				continue
			}
			PrintUpdateResult(ur)
			fmt.Printf("Update sent, rcode: %d (%s)\n", rcode, dns.RcodeToString[rcode])

			actions = nil
			msg = nil
			msgSigned = false
		}
	}

}
