/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var ddnsCmd = &cobra.Command{
	Use:   "ddns",
	Short: "Send a DDNS update. Only usable via sub-commands.",
}

var delCmd = &cobra.Command{
	Use:   "del",
	Short: "Delegation prefix command. Only usable via sub-commands.",
}

var delStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Make an API call to request TDNSD to analyse whether delegation is in sync or not",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		dr, err := SendDelegationCmd(api, tdns.DelegationPost{
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
		dr, err := SendDelegationCmd(api, tdns.DelegationPost{
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

var ddnsOldSyncCmd = &cobra.Command{
	Use:   "oldsync",
	Short: "Send a DDNS update to sync parent delegation info with child data",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			log.Fatalf("Error: child zone name not specified.")
		}
		PrepArgs("parentzone", "parentprimary", "childzone", "childprimary")
		// 		tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)

		tdns.SetupIMR()

		// 		if tdns.Globals.ParentZone == "" {
		// 		   log.Fatalf("Error: parent zone name not specified.")
		// 		}
		// 		tdns.Globals.ParentZone = dns.Fqdn(tdns.Globals.ParentZone)
		//
		// 		if childpri == "" {
		// 		   log.Fatalf("Error: child primary nameserver not specified.")
		// 		}
		// 		if parpri == "" {
		// 		   log.Fatalf("Error: parent primary nameserver not specified.")
		// 		}

		// 1. Is the delegation in sync or not?
		fmt.Printf("Is delegation for %s in sync or not?\n", tdns.Globals.Zonename)
		unsynched, adds, removes, err := tdns.ChildDelegationDataUnsynched(
			tdns.Globals.Zonename, tdns.Globals.ParentZone, childpri, parpri)
		if err != nil {
			log.Fatalf("Error from ChildSyncDelegationData(): %v", err)
		}
		if !unsynched {
			fmt.Printf("No change to delegation data. No need to update.\n")
			os.Exit(0)
		} else {
			fmt.Printf("Delegation for %s is not in sync. Needs fixing.\n",
				tdns.Globals.Zonename)
		}

		// 2. Ok, sync needed. Is DNS UPDATE a supported scheme?
		// [figure out if yes, and all target details]
		const update_scheme = 2
		dsynctarget, err := tdns.LookupDSYNCTarget(tdns.Globals.ParentZone,
			parpri, dns.StringToType["ANY"], update_scheme)
		if err != nil {
			log.Fatalf("Error from LookupDSYNCTarget(%s, %s): %v",
				tdns.Globals.ParentZone, parpri, err)
		}

		// 3. Create UPDATE msg

		// 4. Sign UPDATE msg

		// 5. Send UPDATE msg to target
		err = tdns.ChildSendDdnsSync(tdns.Globals.ParentZone, dsynctarget, adds, removes)
		if err != nil {
			log.Fatalf("Error from ChildSendDdnsSync(): %v", err)
		}
	},
}

var ddnsRollCmd = &cobra.Command{
	Use:   "roll",
	Short: "Send a DDNS update to roll the SIG(0) key used to sign updates",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone", "parentzone", "childPrimary", "parentprimary")
		err := tdns.SendSig0KeyUpdate(childpri, parpri, true)
		if err != nil {
			fmt.Printf("Error from SendSig0KeyUpdate(): %v", err)
		}
	},
}

var ddnsUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Send a DDNS update to upload the initial SIG(0) public key to parent",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone", "parentzone", "childPrimary", "parentprimary")
		err := tdns.SendSig0KeyUpdate(childpri, parpri, false)
		if err != nil {
			fmt.Printf("Error from SendSig0KeyUpdate(): %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(ddnsCmd, delCmd)
	delCmd.AddCommand(delStatusCmd, delSyncCmd)
	delSyncCmd.Flags().StringVarP(&schemestr, "scheme", "S", "", "Scheme to use for synchronization of delegation")

	delSyncCmd.MarkFlagRequired("zone")

	ddnsCmd.AddCommand(ddnsOldSyncCmd)
	ddnsCmd.AddCommand(ddnsRollCmd, ddnsUploadCmd)

	ddnsCmd.PersistentFlags().StringVarP(&tdns.Globals.Sig0Keyfile, "keyfile", "k", "", "name of file with private SIG(0) key")
	ddnsCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	ddnsCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
}

func PrepArgs(required ...string) {
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

		case "state":
			if NewState == "" {
				fmt.Printf("Error: new state of key mnot specified \n")
				os.Exit(1)
			}
			switch NewState {
			case "created", "active", "retired":
			default:
				fmt.Printf("Error: key state \"%s\" is not known\n", NewState)
				os.Exit(1)
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

		default:
			fmt.Printf("Unknown required argument: \"%s\"\n", arg)
			os.Exit(1)
		}
	}
}

func SendDelegationCmd(api *tdns.Api, data tdns.DelegationPost) (tdns.DelegationResponse, error) {
	var dr tdns.DelegationResponse

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := api.Post("/delegation", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return dr, fmt.Errorf("error from api post: %v", err)
	}
	if verbose {
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
