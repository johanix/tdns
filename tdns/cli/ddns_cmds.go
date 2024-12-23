/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var DdnsCmd = &cobra.Command{
	Use:   "ddns",
	Short: "Send a DDNS update. Only usable via sub-commands.",
}

var DelCmd = &cobra.Command{
	Use:   "del",
	Short: "Delegation prefix command. Only usable via sub-commands.",
}

var delStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Make an API call to request TDNSD to analyse whether delegation is in sync or not",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		dr, err := SendDelegationCmd(tdns.Globals.Api, tdns.DelegationPost{
			Command: "status",
			Zone:    tdns.Globals.Zonename,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if dr.Error {
			fmt.Printf("Error: %s\n", dr.ErrorMsg)
			os.Exit(1)
		}

		fmt.Printf("%s\n", dr.Msg)
		if dr.SyncStatus.InSync {
			fmt.Printf("Delegation information in parent %s is in sync with child %s. No action needed.\n",
				dr.SyncStatus.Parent, dr.SyncStatus.ZoneName)
			os.Exit(0)
		}
		fmt.Printf("Delegation information in parent \"%s\" is NOT in sync with child \"%s\". Changes needed:\n",
			dr.SyncStatus.Parent, dr.SyncStatus.ZoneName)
		out := []string{"Change|RR|RR"}
		for _, rr := range dr.SyncStatus.NsAdds {
			out = append(out, fmt.Sprintf("ADD NS|%s", rr.String()))
		}
		for _, rr := range dr.SyncStatus.NsRemoves {
			out = append(out, fmt.Sprintf("DEL NS|%s", rr.String()))
		}
		for _, rr := range dr.SyncStatus.AAdds {
			out = append(out, fmt.Sprintf("ADD IPv4 GLUE|%s", rr.String()))
		}
		for _, rr := range dr.SyncStatus.ARemoves {
			out = append(out, fmt.Sprintf("DEL IPv4 GLUE|%s", rr.String()))
		}
		for _, rr := range dr.SyncStatus.AAAAAdds {
			out = append(out, fmt.Sprintf("ADD IPv6 GLUE|%s", rr.String()))
		}
		for _, rr := range dr.SyncStatus.AAAAAdds {
			out = append(out, fmt.Sprintf("DEL IPv6 GLUE|%s", rr.String()))
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var schemestr string
var scheme uint8

var delSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Make an API call to request TDNSD to send a DDNS update to sync parent delegation info with child data",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		dr, err := SendDelegationCmd(tdns.Globals.Api, tdns.DelegationPost{
			Command: "sync",
			Scheme:  scheme,
			Zone:    tdns.Globals.Zonename,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if dr.Error {
			fmt.Printf("Error: %s\n", dr.ErrorMsg)
			os.Exit(1)
		}

		fmt.Printf("%s\n", dr.Msg)
	},
}

// Send a SIG(0) key rollover request to parent directly from CLI (not via tdns-server). This is mostly a debug command.
var ddnsRollCmd = &cobra.Command{
	Use:   "roll",
	Short: "Send a DDNS update to roll the SIG(0) key used to sign updates",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone", "parentzone", "childPrimary", "parentprimary")
		kdb, err := tdns.NewKeyDB(viper.GetString("db.file"), false)
		if err != nil {
			fmt.Printf("Error from NewKeyDB(): %v\n", err)
			os.Exit(1)
		}
		err = kdb.SendSig0KeyUpdate(childpri, parpri, true)
		if err != nil {
			fmt.Printf("Error from SendSig0KeyUpdate(): %v", err)
		}
	},
}

// Send a SIG(0) key upload request to parent directly from CLI (not via tdns-server). This is mostly a debug command.
var ddnsUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Send a DDNS update to upload the initial SIG(0) public key to parent",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone", "parentzone", "childPrimary", "parentprimary")
		kdb, err := tdns.NewKeyDB(viper.GetString("db.file"), false)
		if err != nil {
			fmt.Printf("Error from NewKeyDB(): %v\n", err)
			os.Exit(1)
		}
		err = kdb.SendSig0KeyUpdate(childpri, parpri, false)
		if err != nil {
			fmt.Printf("Error from SendSig0KeyUpdate(): %v", err)
		}
	},
}

func init() {
	DelCmd.AddCommand(delStatusCmd, delSyncCmd)
	delSyncCmd.Flags().StringVarP(&schemestr, "scheme", "S", "", "Scheme to use for synchronization of delegation")

	delSyncCmd.MarkFlagRequired("zone")

	DdnsCmd.AddCommand(ddnsRollCmd, ddnsUploadCmd)

	DdnsCmd.PersistentFlags().StringVarP(&tdns.Globals.Sig0Keyfile, "keyfile", "k", "", "name of file with private SIG(0) key")
	DdnsCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	DdnsCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
}

func PrepArgs(required ...string) {

	DefinedDnskeyStates := []string{"created", "published", "active", "retired", "foreign"}
	DefinedDnskeyTypes := []string{"KSK", "ZSK", "CSK"}
	// DefinedAlgorithms := []string{"RSASHA256", "RSASHA512", "ED25519", "ECDSAP256SHA256", "ECDSAP384SHA384"}

	for _, arg := range required {
		if tdns.Globals.Debug {
			fmt.Printf("Required: %s\n", arg)
		}
		switch arg {
		case "parentzone":
			if tdns.Globals.ParentZone == "" {
				fmt.Printf("Error: name of parent zone not specified\n")
				os.Exit(1)
			}
			tdns.Globals.ParentZone = dns.Fqdn(tdns.Globals.ParentZone)

		case "childzone", "child":
			if tdns.Globals.Zonename == "" {
				fmt.Printf("Error: name of child zone not specified\n")
				os.Exit(1)
			}
			tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)

		case "zonename":
			if tdns.Globals.Zonename == "" {
				fmt.Printf("Error: zone name not specified using --zone flag\n")
				os.Exit(1)
			}
			tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)

		case "keyid":
			if keyid == 0 {
				fmt.Printf("Error: key id not specified using --keyid flag\n")
				os.Exit(1)
			}

		case "parentprimary":
			if parpri == "" {
				fmt.Printf("Error: name of parent primary not specified\n")
				os.Exit(1)
			}
			if !strings.Contains(parpri, ":") {
				parpri = net.JoinHostPort(parpri, "53")
			}

		case "childprimary":
			if childpri == "" {
				fmt.Printf("Error: name of child primary not specified\n")
				os.Exit(1)
			}
			if !strings.Contains(childpri, ":") {
				childpri = net.JoinHostPort(childpri, "53")
			}

		case "filename":
			if filename == "" {
				fmt.Printf("Error: filename not specified\n")
				os.Exit(1)
			}
			_, err := os.ReadFile(filename)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				os.Exit(1)
			}

		case "src":
			if childSig0Src == "" {
				fmt.Printf("Error: source not specified\n")
				os.Exit(1)
			}

		case "algorithm":
			if tdns.Globals.Algorithm == "" {
				fmt.Printf("Error: algorithm not specified\n")
				os.Exit(1)
			}

			tdns.Globals.Algorithm = strings.ToUpper(tdns.Globals.Algorithm)
			_, exist := dns.StringToAlgorithm[tdns.Globals.Algorithm]
			if !exist {
				fmt.Printf("Error: algorithm \"%s\" is not known\n", tdns.Globals.Algorithm)
				os.Exit(1)
			}

		case "rrtype":
			if tdns.Globals.Rrtype == "" {
				fmt.Printf("Error: rrtype not specified\n")
				os.Exit(1)
			}
			rrtype, exist := dns.StringToType[strings.ToUpper(tdns.Globals.Rrtype)]
			if !exist {
				fmt.Printf("Error: rrtype \"%s\" is not known\n", tdns.Globals.Rrtype)
				os.Exit(1)
			}
			if rrtype != dns.TypeKEY && rrtype != dns.TypeDNSKEY {
				fmt.Printf("Error: rrtype \"%s\" is not KEY or DNSKEY\n", tdns.Globals.Rrtype)
				os.Exit(1)
			}

		case "keytype":
			if keytype == "" {
				fmt.Printf("Error: key type not specified (should be one of %v)\n", DefinedDnskeyTypes)
				os.Exit(1)
			}
			keytype = strings.ToUpper(keytype)
			if !slices.Contains(DefinedDnskeyTypes, keytype) {
				fmt.Printf("Error: key type \"%s\" is not known\n", keytype)
				os.Exit(1)
			}

		case "state":
			if NewState == "" {
				fmt.Printf("Error: key state not specified (should be one of %v)\n", DefinedDnskeyStates)
				os.Exit(1)
			}
			NewState = strings.ToLower(NewState)
			if !slices.Contains(DefinedDnskeyStates, NewState) {
				fmt.Printf("Error: key state \"%s\" is not known\n", NewState)
				os.Exit(1)
			}

		case "rollaction":
			rollaction = strings.ToLower(rollaction)
			if rollaction != "complete" && rollaction != "add" && rollaction != "remove" && rollaction != "update-local" {
				fmt.Printf("Error: roll action \"%s\" is not known\n", rollaction)
				os.Exit(1)
			}

		default:
			fmt.Printf("Unknown required argument: \"%s\"\n", arg)
			os.Exit(1)
		}
	}
}

func SendDelegationCmd(api *tdns.ApiClient, data tdns.DelegationPost) (tdns.DelegationResponse, error) {
	var dr tdns.DelegationResponse

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/delegation", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return dr, fmt.Errorf("error from api post: %v", err)
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &dr)
	if err != nil {
		return dr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if dr.Error {
		return dr, fmt.Errorf(dr.ErrorMsg)
	}

	return dr, nil
}
