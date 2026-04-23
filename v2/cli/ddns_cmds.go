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
	"strconv"

	tdns "github.com/johanix/tdns/v2"
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
		if schemestr != "" {
			val, err := strconv.ParseUint(schemestr, 10, 8)
			if err != nil {
				fmt.Printf("Error: invalid scheme value %q: %s\n", schemestr, err)
				return
			}
			scheme = uint8(val)
		}

		api, err := GetApiClient("auth", true)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
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
		fmt.Printf("Delegation information in parent %q is NOT in sync with child %q. Changes needed:\n",
			dr.SyncStatus.Parent, dr.SyncStatus.ZoneName)
		out := []string{"Change|RR"}
		for _, rr := range dr.SyncStatus.NsAddsStr {
			out = append(out, fmt.Sprintf("ADD NS|%s", rr))
		}
		for _, rr := range dr.SyncStatus.NsRemovesStr {
			out = append(out, fmt.Sprintf("DEL NS|%s", rr))
		}
		for _, rr := range dr.SyncStatus.AAddsStr {
			out = append(out, fmt.Sprintf("ADD IPv4 GLUE|%s", rr))
		}
		for _, rr := range dr.SyncStatus.ARemovesStr {
			out = append(out, fmt.Sprintf("DEL IPv4 GLUE|%s", rr))
		}
		for _, rr := range dr.SyncStatus.AAAAAddsStr {
			out = append(out, fmt.Sprintf("ADD IPv6 GLUE|%s", rr))
		}
		for _, rr := range dr.SyncStatus.AAAARemovesStr {
			out = append(out, fmt.Sprintf("DEL IPv6 GLUE|%s", rr))
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
		if schemestr != "" {
			val, err := strconv.ParseUint(schemestr, 10, 8)
			if err != nil {
				fmt.Printf("Error: invalid scheme value %q: %s\n", schemestr, err)
				return
			}
			scheme = uint8(val)
		}

		api, err := GetApiClient("auth", true)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
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

var delExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export delegation data from a parent zone's backend to a zone file",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		outfile, _ := cmd.Flags().GetString("outfile")
		if outfile == "" {
			fmt.Println("Error: --outfile is required")
			os.Exit(1)
		}

		if schemestr != "" {
			val, err := strconv.ParseUint(schemestr, 10, 8)
			if err != nil {
				fmt.Printf("Error: invalid scheme value %q: %s\n", schemestr, err)
				return
			}
			scheme = uint8(val)
		}

		api, err := GetApiClient("auth", true)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		dr, err := SendDelegationCmd(api, tdns.DelegationPost{
			Command: "export",
			Zone:    tdns.Globals.Zonename,
			Outfile: outfile,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(dr.Msg)
	},
}

func init() {
	DelCmd.AddCommand(delStatusCmd, delSyncCmd, delExportCmd)
	delSyncCmd.Flags().StringVarP(&schemestr, "scheme", "S", "", "Scheme to use for synchronization of delegation")

	delSyncCmd.MarkFlagRequired("zone")

	delExportCmd.Flags().String("outfile", "", "Destination file path (required)")

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
		return dr, fmt.Errorf("%s", dr.ErrorMsg)
	}

	return dr, nil
}
