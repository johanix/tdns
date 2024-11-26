/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package mcmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/johanix/tdns/music"
	tdns "github.com/johanix/tdns/tdns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var sidecarId, sidecarMethod string

var SidecarCmd = &cobra.Command{
	Use:   "sidecar",
	Short: "Prefix command, not usable directly",
}

var sidecarLocateCmd = &cobra.Command{
	Use:   "locate",
	Short: "Locate a sidecar, given its identity and method",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("identity", "method")
		sidecar, err := music.LocateSidecar(sidecarId, tdns.StringToMsignerMethod[sidecarMethod])
		if err != nil {
			log.Fatalf("Error locating sidecar: %v", err)
		}
		fmt.Printf("Sidecar: %+v\n", sidecar)
	},
}

var sidecarIdentifyCmd = &cobra.Command{
	Use:   "identify",
	Short: "Identify multi-signer sidecars for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		msigners, sidecars, err := music.IdentifySidecars(tdns.Globals.Zonename)
		if err != nil {
			log.Fatalf("Error identifying sidecars: %v", err)
		}
		fmt.Printf("MSIGNER records:\n")
		for _, msigner := range msigners {
			fmt.Printf("%s\n", msigner.String())
		}
		fmt.Printf("Sidecars:\n")
		out := []string{}
		if tdns.Globals.ShowHeaders {
			out = append(out, "IDENTITY|METHOD|ADDRESSES|TLSA or KEY")
		}
		for _, sidecar := range sidecars {
			extra := ""
			if sidecar.Method == tdns.MsignerMethodAPI {
				extra = sidecar.TlsaRR.String()
			} else if sidecar.Method == tdns.MsignerMethodDNS {
				extra = sidecar.KeyRR.String()
			}
			out = append(out, fmt.Sprintf("%s|%s|%s|%s", sidecar.Identity, tdns.MsignerMethodToString[sidecar.Method],
				strings.Join(sidecar.Addresses, ","), extra))
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

func init() {
	//	rootCmd.AddCommand(showCmd)
	SidecarCmd.AddCommand(sidecarLocateCmd, sidecarIdentifyCmd)

	SidecarCmd.PersistentFlags().StringVarP(&sidecarId, "id", "i", "", "Identity of sidecar")
	SidecarCmd.PersistentFlags().StringVarP(&sidecarMethod, "method", "m", "", "Sidecar sync method")
}
