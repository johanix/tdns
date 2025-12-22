/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/johanix/tdns/tdns"
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
		for _, rr := range dr.SyncStatus.AAAARemoves {
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

var childpri, parpri string

// Send a SIG(0) key rollover request to parent directly from CLI (not via tdns-auth). This is mostly a debug command.
var ddnsRollCmd = &cobra.Command{
	Use:   "roll",
	Short: "Send a DDNS update to roll the SIG(0) key used to sign updates",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone", "parentzone", "childPrimary", "parentprimary")
		kdb, err := tdns.NewKeyDB(viper.GetString("db.file"), false, nil)
		if err != nil {
			fmt.Printf("Error from NewKeyDB(): %v\n", err)
			os.Exit(1)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err = kdb.SendSig0KeyUpdate(ctx, childpri, parpri, true)
		if err != nil {
			fmt.Printf("Error from SendSig0KeyUpdate(): %v", err)
		}
	},
}

// Send a SIG(0) key upload request to parent directly from CLI (not via tdns-auth). This is mostly a debug command.
var ddnsUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Send a DDNS update to upload the initial SIG(0) public key to parent",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("childzone", "parentzone", "childPrimary", "parentprimary")
		kdb, err := tdns.NewKeyDB(viper.GetString("db.file"), false, nil)
		if err != nil {
			fmt.Printf("Error from NewKeyDB(): %v\n", err)
			os.Exit(1)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err = kdb.SendSig0KeyUpdate(ctx, childpri, parpri, false)
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
