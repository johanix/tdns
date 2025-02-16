/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package mcmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	tdns "github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"

	"github.com/johanix/tdns/music"
)

var fsmnextstate, ownername, rrtype, fromsigner, tosigner, zonetype string
var metakey, metavalue, fsmmode string

var ZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "MUSIC Zone commands",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var statusZoneCmd = &cobra.Command{
	Use:   "status",
	Short: "Get status of a zone according to MuSiC",
	Run: func(cmd *cobra.Command, arg []string) {
		PrepArgs("zonename")
		data := music.ZonePost{
			Command: "status",
			Zone: music.Zone{
				Name: music.Globals.Zonename,
			},
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
		if len(zr.Zones) > 0 {
			PrintZones(zr.Zones, true, "")
		}
	},
}

var addZoneCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new zone to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		if zonetype == "" {
			zonetype = "normal"
		}
		if fsmmode == "" {
			fsmmode = "manual"
		}
		data := music.ZonePost{
			Command: "add",
			Zone: music.Zone{
				Name:     tdns.Globals.Zonename,
				ZoneType: zonetype,
				FSMMode:  fsmmode,
			},
			SignerGroup: music.Globals.Sgroupname, // may be unspecified
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	},
}

var updateZoneCmd = &cobra.Command{
	Use:   "update",
	Short: "Update information about an existing zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "fsmmode")

		data := music.ZonePost{
			Command: "update",
			Zone: music.Zone{
				Name: tdns.Globals.Zonename,
			},
		}

		if zonetype != "" {
			data.Zone.ZoneType = zonetype
		}
		if music.Globals.FSMmode != "" {
			data.Zone.FSMMode = music.Globals.FSMmode
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	},
}

var zoneJoinGroupCmd = &cobra.Command{
	Use:   "join",
	Short: "Join a zone to a signer group",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "signergroupname")

		data := music.ZonePost{
			Command: "join",
			Zone: music.Zone{
				Name: tdns.Globals.Zonename,
			},
			SignerGroup: music.Globals.Sgroupname,
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	},
}

var zoneLeaveGroupCmd = &cobra.Command{
	Use:   "leave",
	Short: "Remove a zone from a signer group",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "signergroupname")

		data := music.ZonePost{
			Command: "leave",
			Zone: music.Zone{
				Name: tdns.Globals.Zonename,
			},
			SignerGroup: music.Globals.Sgroupname,
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	},
}

var deleteZoneCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a zone from MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		data := music.ZonePost{
			Command: "delete",
			Zone: music.Zone{
				Name: tdns.Globals.Zonename,
			},
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	},
}

var zoneMetaCmd = &cobra.Command{
	Use:   "meta",
	Short: "Add or update metadata for zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		switch metakey {
		case "":
			log.Fatalf("ZoneMeta: Metadata key not specified. Terminating.\n")

		case "parentaddr":
			err := music.Validate.Var(metavalue, "required,hostname_port")
			if err != nil {
				log.Fatalf("ZoneMeta: Metadata value not a host:port: %v\n", err)
			}
		}

		data := music.ZonePost{
			Command: "meta",
			Zone: music.Zone{
				Name: tdns.Globals.Zonename,
			},
			Metakey:   metakey,
			Metavalue: metavalue,
		}
		if zonetype != "" {
			data.Zone.ZoneType = zonetype
		}

		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		if zr.Error {
			fmt.Printf("Error: %s\n", zr.ErrorMsg)
		}
	},
}

var zoneFsmCmd = &cobra.Command{
	Use:   "fsm",
	Short: "Insert zone into an FSM",
	Long: `Inserting a zone into a FSM will cause it to start a set of transitions
from one state to the next under control of specific criteria for each
transition. At each stage the current state is presented and manual
transition may be initiated with the 'music-cli zone step -z {zone}'
command.`,
	Run: func(cmd *cobra.Command, args []string) {
		// failure, _ := ZoneFsm(dns.Fqdn(Zonename), fsmname)

		fmt.Println(
			`NOTE: It is not up to a zone to enter a multi signer process (or not), it is
up to the signer group. This command is only here for development and debugging
reasons and will disappear.`)

		PrepArgs("zonename", "fsmname", "signername")

		data := music.ZonePost{
			Command: "fsm",
			Zone: music.Zone{
				Name: tdns.Globals.Zonename,
			},
			FSM:       music.Globals.FSMname,
			FSMSigner: music.Globals.Signername,
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		if zr.Error {
			fmt.Printf("Error: %s\n", zr.ErrorMsg)
		}
	},
}

var zoneStepFsmCmd = &cobra.Command{
	Use:   "step-fsm",
	Short: "Try to make the zone transition from one state to the next in the FSM",
	Run: func(cmd *cobra.Command, args []string) {
		// failure, _, zm := ZoneStepFsm(dns.Fqdn(Zonename))

		PrepArgs("zonename")

		data := music.ZonePost{
			Command: "list",
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)

		fsm := zr.Zones[tdns.Globals.Zonename].FSM

		if fsm == "" || fsm == "none" {
			log.Fatalf("ZoneStepFsm: Zone %s is not attached to any FSM. Terminating.\n", tdns.Globals.Zonename)
		}
		data = music.ZonePost{
			Command: "step-fsm",
			Zone: music.Zone{
				Name: tdns.Globals.Zonename,
			},
			FsmNextState: fsmnextstate, // may be empty
		}

		zr = SendZoneCommand(tdns.Globals.Zonename, data)
		zm := zr.Zones

		if zr.Msg != "" {
			fmt.Printf("%s\n", zr.Msg)
		}
		z := zr.Zones[tdns.Globals.Zonename]
		if z.StopReason != "" {
			fmt.Printf("Latest stop-reason: %s\n", z.StopReason)
		}

		if zr.Error {
			fmt.Printf("Error: %s\n", zr.ErrorMsg)
		}
		if tdns.Globals.Verbose {
			PrintZones(zm, true, "")
		}
	},
}

var zoneGetRRsetsCmd = &cobra.Command{
	Use:   "get-rrsets",
	Short: "Retrieve an rrset from the signers in the signer group for this zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "owner", "rrtype")
		failure, errmsg, rrsets := ZoneGetRRsets(dns.Fqdn(tdns.Globals.Zonename), dns.Fqdn(ownername),
			rrtype)
		if failure {
			fmt.Printf("Error: %s\n", errmsg)
		} else {
			PrintRRsets(rrsets)
		}
	},
}

var zoneListRRsetCmd = &cobra.Command{
	Use:   "list-rrset",
	Short: "Retrieve an rrset from the db for one signer in the signer group for this zone (debug)",
	Run: func(cmd *cobra.Command, args []string) {
		failure, errmsg, rrset := ZoneListRRset(dns.Fqdn(tdns.Globals.Zonename),
			dns.Fqdn(ownername), rrtype, music.Globals.Signername)
		if failure {
			fmt.Printf("Error: %s\n", errmsg)
		} else {
			PrintRRset(rrset)
		}
	},
}

var zoneCopyRRsetCmd = &cobra.Command{
	Use:   "copy-rrset",
	Short: "Copy an rrset from one signer in the signer group to another",
	Run: func(cmd *cobra.Command, args []string) {
		failure, errmsg, rrset := ZoneCopyRRset(dns.Fqdn(tdns.Globals.Zonename),
			dns.Fqdn(ownername), rrtype, music.Globals.Signername)
		if failure {
			fmt.Printf("Error: %s\n", errmsg)
		} else {
			PrintRRset(rrset)
		}
	},
}

var listZonesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all zones known to MuSiC",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			tdns.Globals.Zonename = "zone-name-not-set.se." // must have something, not used
		}
		data := music.ZonePost{
			Command: "list",
			Zone: music.Zone{
				Name: tdns.Globals.Zonename,
			},
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
		PrintZones(zr.Zones, true, "")
	},
}

var listBlockedZonesCmd = &cobra.Command{
	Use:   "blocked",
	Short: "List zones that are blocked for some reason",
	Run: func(cmd *cobra.Command, args []string) {
		if tdns.Globals.Zonename == "" {
			tdns.Globals.Zonename = "." // must have something, not used
		}
		data := music.ZonePost{
			Command: "list",
			Zone: music.Zone{
				Name: tdns.Globals.Zonename,
			},
		}
		zr := SendZoneCommand(tdns.Globals.Zonename, data)
		PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
		PrintZones(zr.Zones, false, "blocked")
	},
}

func init() {
	//	rootCmd.AddCommand(zoneCmd)
	ZoneCmd.AddCommand(addZoneCmd, updateZoneCmd, deleteZoneCmd, listZonesCmd,
		zoneJoinGroupCmd, zoneLeaveGroupCmd, zoneFsmCmd,
		zoneStepFsmCmd, zoneGetRRsetsCmd, zoneListRRsetCmd,
		zoneCopyRRsetCmd, zoneMetaCmd, statusZoneCmd)
	listZonesCmd.AddCommand(listBlockedZonesCmd)

	ZoneCmd.PersistentFlags().StringVarP(&zonetype, "type", "t", "",
		"type of zone, 'normal' or 'debug'")
	ZoneCmd.PersistentFlags().StringVarP(&music.Globals.FSMmode, "fsmmode", "", "manual",
		"FSM mode ('auto' or 'manual')")
	zoneFsmCmd.Flags().StringVarP(&music.Globals.FSMname, "fsm", "f", "",
		"name of finite state machine to attach zone to")
	zoneStepFsmCmd.Flags().StringVarP(&fsmnextstate, "nextstate", "", "",
		"name of next state in on-going FSM process")
	zoneCopyRRsetCmd.Flags().StringVarP(&fromsigner, "from", "", "",
		"name of signer to copy from")
	zoneCopyRRsetCmd.Flags().StringVarP(&tosigner, "to", "", "",
		"name of signer to copy to")
	ZoneCmd.PersistentFlags().StringVarP(&ownername, "owner", "o", "",
		"DNS owner name (FQDN) of RRset")
	ZoneCmd.PersistentFlags().StringVarP(&rrtype, "rrtype", "r", "",
		"RRtype of RRset")
	zoneMetaCmd.Flags().StringVarP(&metakey, "metakey", "", "",
		"Metadata key (known keys:'parentaddr')")
	zoneMetaCmd.Flags().StringVarP(&metavalue, "metavalue", "", "",
		"Metadata value")
	zoneMetaCmd.MarkFlagRequired("zone")
	zoneMetaCmd.MarkFlagRequired("metakey")
	zoneMetaCmd.MarkFlagRequired("metavalue")
}

func SendZoneCommand(Zonename string, data music.ZonePost) music.ZoneResponse {
	// IsDomainName() is too liberal, we need a stricter test.
	if _, ok := dns.IsDomainName(tdns.Globals.Zonename); !ok {
		log.Fatalf("SendZoneCommand: Error: '%s' is not a legal domain name. Terminating.",
			tdns.Globals.Zonename)
	}

	// bytebuf := new(bytes.Buffer)
	// json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := tdns.Globals.Api.RequestNG("POST", "/zone", data, true)
	if err != nil {
		log.Fatalf("SendZoneCommand: Error from api.Post: %v", err)

	}
	if tdns.Globals.Debug {
		fmt.Println()
		fmt.Printf("SendZoneCommand Status: %d\n", status)
	}

	var zr music.ZoneResponse
	err = json.Unmarshal(buf, &zr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v", err)
	}
	return zr
}

func ZoneGetRRsets(zone, owner, rrtype string) (bool, string, map[string][]string) {
	if !strings.HasSuffix(owner, zone) {
		fmt.Printf("Error: zone name %s is not a suffix of owner name %s\n", zone, owner)
		os.Exit(1)
	}

	data := music.ZonePost{
		Command: "get-rrsets",
		Zone: music.Zone{
			Name: zone,
		},
		Owner:  owner,
		RRtype: strings.ToUpper(rrtype),
	}

	// bytebuf := new(bytes.Buffer)
	// json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := tdns.Globals.Api.RequestNG("POST", "/zone", data, true)
	if err != nil {
		log.Println("Error from APIpost:", err)
		return true, err.Error(), map[string][]string{}
	}
	if tdns.Globals.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var zr = music.ZoneResponse{
		Zones:  map[string]music.Zone{},
		RRsets: map[string][]string{},
	}
	err = json.Unmarshal(buf, &zr)
	if err != nil {
		log.Fatalf("ZoneGetRRsets: Error from unmarshal: %v\n", err)
	}

	PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	return false, "", zr.RRsets
}

func ZoneListRRset(zone, owner, rrtype, signer string) (bool, string, []string) {
	PrepArgs("zonename", "signer")

	if !strings.HasSuffix(owner, tdns.Globals.Zonename) {
		fmt.Printf("Error: zone name %s is not a suffix of owner name %s\n", tdns.Globals.Zonename, owner)
		os.Exit(1)
	}

	data := music.ZonePost{
		Command: "list-rrset",
		Zone: music.Zone{
			Name: tdns.Globals.Zonename,
		},
		Owner:  ownername,
		RRtype: strings.ToUpper(rrtype),
		Signer: music.Globals.Signername,
	}

	// bytebuf := new(bytes.Buffer)
	// json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := tdns.Globals.Api.RequestNG("POST", "/zone", data, true)
	if err != nil {
		log.Println("Error from APIpost:", err)
		return true, err.Error(), []string{}
	}
	if tdns.Globals.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var zr = music.ZoneResponse{
		Zones:  map[string]music.Zone{},
		RRsets: map[string][]string{},
	}
	err = json.Unmarshal(buf, &zr)
	if err != nil {
		log.Fatalf("ZoneListRRset: Error from unmarshal: %v\n", err)
	}

	PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	return false, "", zr.RRset
}

func ZoneCopyRRset(zone, owner, rrtype, signer string) (bool, string, []string) {
	PrepArgs("zonename", "signer")

	if !strings.HasSuffix(owner, tdns.Globals.Zonename) {
		fmt.Printf("Error: zone name %s is not a suffix of owner name %s\n", tdns.Globals.Zonename, owner)
		os.Exit(1)
	}

	data := music.ZonePost{
		Command: "copy-rrset",
		Zone: music.Zone{
			Name: tdns.Globals.Zonename,
		},
		Owner:      owner,
		RRtype:     strings.ToUpper(rrtype),
		Signer:     music.Globals.Signername,
		FromSigner: fromsigner,
		ToSigner:   tosigner,
	}

	// bytebuf := new(bytes.Buffer)
	// json.NewEncoder(bytebuf).Encode(data)

	status, buf, err := tdns.Globals.Api.RequestNG("POST", "/zone", data, true)
	if err != nil {
		log.Println("Error from APIpost:", err)
		return true, err.Error(), []string{}
	}
	if tdns.Globals.Debug {
		fmt.Printf("Status: %d\n", status)
	}

	var zr = music.ZoneResponse{
		Zones:  map[string]music.Zone{},
		RRsets: map[string][]string{},
	}
	err = json.Unmarshal(buf, &zr)
	if err != nil {
		log.Fatalf("ZoneListRRset: Error from unmarshal: %v\n", err)
	}

	PrintZoneResponse(zr.Error, zr.ErrorMsg, zr.Msg)
	return false, "", zr.RRset
}

// Is this actually exactly the same as PrintSignerResponse?
func PrintZoneResponse(iserr bool, errormsg, msg string) {
	if iserr {
		fmt.Printf("%s\n", errormsg)
	}

	if msg != "" {
		fmt.Printf("%s\n", msg)
	}
}

func PrintZones(zm map[string]music.Zone, showall bool, fsmstatus string) {
	if len(zm) != 0 {
		var out []string
		var zone music.Zone

		if tdns.Globals.Verbose || tdns.Globals.ShowHeaders {
			// out = append(out, "Zone|SignerGroup|Process|State|Timestamp|Next State(s)|ZSK State")
			if showall {
				out = append(out, "Zone|SignerGroup|Process|State|Timestamp|Next State(s)")
			} else if fsmstatus == "blocked" {
				out = append(out, "Zone|SignerGroup|Process|State|Timestamp|Stop reason")
			} else if fsmstatus == "delayed" {
				out = append(out, "Zone|SignerGroup|Process|State|Timestamp|Delay reason|Until")
			}
		}

		Zonenames := make([]string, 0, len(zm))
		for k := range zm {
			Zonenames = append(Zonenames, k)
		}
		sort.Strings(Zonenames)

		for _, zn := range Zonenames {
			modebits := ""
			zone = zm[zn]
			zname := zn
			if zone.FSMMode == "auto" {
				modebits += "A"
			}

			if zone.ZoneType == "debug" {
				modebits += "D"
			}
			if len(modebits) != 0 {
				zname += fmt.Sprintf("[%s]", modebits)
			}

			group := "---"
			if zone.SGname != "" {
				group = zone.SGname
			}

			fsm := "---"
			if zone.FSM != "" {
				fsm = zone.FSM
			}

			if zone.State == "" {
				zone.State = "---"
				if zone.FSM == "" {
					zone.State = "IN-SYNC"
				}
			}

			// if zone.ZskState == "" {
			//	zone.ZskState = "---"
			// }

			nextStates := []string{}
			for k := range zone.NextState {
				nextStates = append(nextStates, k)
			}
			if showall {
				out = append(out, fmt.Sprintf("%s|%s|%s|%s|%s|[%s]", zname, group, fsm,
					zone.State, zone.Statestamp.Format("2006-01-02 15:04:05"),
					strings.Join(nextStates, " ")))
			} else if zone.FSMStatus == fsmstatus {
				out = append(out, fmt.Sprintf("%s|%s|%s|%s|%s|%s", zname, group, fsm,
					zone.State, zone.Statestamp.Format("2006-01-02 15:04:05"),
					zone.StopReason))
			}
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	}
}

func PrintRRsets(msrrs map[string][]string) {
	for signer, rrs := range msrrs {
		fmt.Printf("Data from signer: %s:\n", signer)
		PrintRRset(rrs)
	}
}

func PrintRRset(rrset []string) {
	var out []string
	var row string

	if tdns.Globals.Verbose {
		out = append(out, "Owner|Class|Type|Rdata")
	}

	for _, r := range rrset {
		rr, err := dns.NewRR(r)
		if err != nil {
			fmt.Printf("RR '%s' failed to parse. Error: %v\n", r, err)
		} else {
			switch rr := rr.(type) {
			case *dns.DNSKEY:
				row = fmt.Sprintf("%s|IN|DNSKEY|%d %d %d|%s...%s",
					rr.Header().Name,
					rr.Flags,
					rr.Protocol,
					rr.Algorithm,
					rr.PublicKey[0:30],
					rr.PublicKey[len(rr.PublicKey)-30:])
			default:
				parts := strings.Split(rr.String(), "\t")
				parts = parts[4:]
				rdata := strings.Join(parts, " ")
				row = fmt.Sprintf("%s|IN|%s|%s", rr.Header().Name,
					dns.TypeToString[rr.Header().Rrtype], rdata)
			}
		}
		out = append(out, row)
	}
	fmt.Printf("%s\n", columnize.SimpleFormat(out))
}
