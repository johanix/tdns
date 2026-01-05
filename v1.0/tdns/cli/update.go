/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/gookit/goutil/dump"
	"github.com/johanix/tdns/v1.0/tdns"
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

// init registers update-related Cobra subcommands and binds their command-line flags.
// It wires the child, zone, and top-level update create commands and defines flags for
// zone, parent, signer, server, and keyfile.
func init() {
	ChildCmd.AddCommand(childUpdateCmd)
	childUpdateCmd.AddCommand(childUpdateCreateCmd)
	childUpdateCreateCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to update")
	childUpdateCreateCmd.Flags().StringVarP(&tdns.Globals.ParentZone, "parent", "P", "", "Parent zone to send update to")

	ZoneCmd.AddCommand(zoneUpdateCmd)
	zoneUpdateCmd.AddCommand(zoneUpdateCreateCmd)
	zoneUpdateCreateCmd.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone to update")

	UpdateCmd.AddCommand(updateCreateCmd)
	updateCreateCmd.Flags().StringVarP(&signer, "signer", "", "", "Name of signer (i.e. key used to sign update)")
	updateCreateCmd.Flags().StringVarP(&server, "server", "S", "", "Server to send update to (in addr:port format)")
	updateCreateCmd.Flags().StringVarP(&keyfile, "key", "K", "", "SIG(0) keyfile to use for signing the update")
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

	var adds, removes []dns.RR

	var ttl int = 60
	var op, rrstr, port string

	zone = dns.Fqdn(tdns.Globals.Zonename)
	if signer == "" {
		signer = zone
	}

	signer = dns.Fqdn(signer)

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

	var ops = []string{"zone", "add", "del", "show", "send", "sign", "set-ttl", "server", "quit"}
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
		if len(adds) == 0 && len(removes) == 0 {
			fmt.Println("No records to send, please add or delete some records first")
			return nil, fmt.Errorf("no records to send")
		}
		msg, err = tdns.CreateUpdate(zone, adds, removes)
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

			m, err := tdns.SignMsg(*msg, zone, sak)
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
				m, err := tdns.SignMsg(*msg, signer, sak)
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

			if op == "add" {
				duplicate := false
				for _, arr := range adds {
					if dns.IsDuplicate(rr, arr) {
						fmt.Printf("Record already added: %s\n", rrstr)
						duplicate = true
						break
					}
				}
				if !duplicate {
					adds = append(adds, rr)
				}
			} else {
				duplicate := false
				for _, rrr := range removes {
					if dns.IsDuplicate(rr, rrr) {
						fmt.Printf("Record already removed: %s\n", rrstr)
						duplicate = true
						break
					}
				}
				if !duplicate {
					removes = append(removes, rr)
				}
			}

		case "show":
			if zone == "." {
				fmt.Println("Target zone not set, please set it first")
				continue
			}
			if msg == nil {
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

			adds = []dns.RR{}
			removes = []dns.RR{}
			msg = nil
			msgSigned = false
		}
	}

}
