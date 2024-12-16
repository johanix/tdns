/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package mcmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	tdns "github.com/johanix/tdns/tdns"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var SignerGroupCmd = &cobra.Command{
	Use:   "signergroup",
	Short: "Signer group commands",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var addSignerGroupCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new signer group to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		sgr := SendSignerGroupCmd(music.Globals.Sgroupname, music.SignerGroupPost{
			Command: "add",
			Name:    music.Globals.Sgroupname,
		})
		if sgr.Msg != "" {
			fmt.Printf("%s\n", sgr.Msg)
		}
	},
}

var deleteSignerGroupCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a signer group from MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		data := music.SignerGroupPost{
			Command: "delete",
			Name:    music.Globals.Sgroupname,
		}

		sgr := SendSignerGroupCmd(music.Globals.Sgroupname, data)
		if sgr.Msg != "" {
			fmt.Printf("%s\n", sgr.Msg)
		}
	},
}

var listSignerGroupsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all signer groups known to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		sgr := SendSignerGroupCmd("none", music.SignerGroupPost{
			Command: "list",
		})
		PrintSignerGroups(sgr)
	},
}

func init() {
	//	rootCmd.AddCommand(signerGroupCmd)
	SignerGroupCmd.AddCommand(addSignerGroupCmd, deleteSignerGroupCmd, listSignerGroupsCmd)
}

func SendSignerGroupCmd(group string, data music.SignerGroupPost) music.SignerGroupResponse {
	if group == "" {
		log.Fatalf("Signer group must be specified.\n")
	}

	// bytebuf := new(bytes.Buffer)
	// json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := tdns.Globals.Api.RequestNG("POST", "/signergroup", data, true)
	if err != nil {
		log.Fatalf("SendSignerGroupCmd: Error from APIpost: %v\n", err)
	}
	if tdns.Globals.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var sgr music.SignerGroupResponse
	err = json.Unmarshal(buf, &sgr)
	if err != nil {
		log.Fatalf("SendSignerGroupCmd: Error from unmarshal: %v\n", err)
	}

	return sgr
}

func PrintSignerGroups(sgr music.SignerGroupResponse) {
	if len(sgr.SignerGroups) > 0 {
		var out []string
		if tdns.Globals.Verbose || tdns.Globals.ShowHeaders {
			out = append(out, "Group|Locked|Signers|# Zones|# Proc Zones|Current Process|PendingAddition|PendingRemoval")
		}

		for k, v := range sgr.SignerGroups {
			var ss string
			for k1, _ := range v.SignerMap {
				ss += fmt.Sprintf(", %s", k1)
			}
			if len(ss) > 2 {
				ss = ss[1:]
			}
			cp := v.CurrentProcess
			if cp == "" {
				cp = "---"
			}
			pa := v.PendingAddition
			if pa == "" {
				pa = "---"
			}
			pr := v.PendingRemoval
			if pr == "" {
				pr = "---"
			}
			out = append(out, fmt.Sprintf("%s|%v|%s|%d|%d|%s|%s|%s", k, v.Locked, ss,
				v.NumZones, v.NumProcessZones, cp, pa, pr))
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	}
}
