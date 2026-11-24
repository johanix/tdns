/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newDdnsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ddns",
		Short: "Send a DDNS update. Only usable via sub-commands.",
	}
}

func newDelCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "del",
		Short: "Delegation prefix command. Only usable via sub-commands.",
	}
}

func newDelStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Make an API call to request the daemon to analyse whether delegation is in sync or not",
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

			api, err := GetApiClientForCmd(cmd, true)
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
			printDelegationDelta(os.Stdout, dr.SyncStatus)
		},
	}
}

var schemestr string
var scheme uint8

func newDelSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Make an API call to request the daemon to send a DDNS update to sync parent delegation info with child data",
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

			api, err := GetApiClientForCmd(cmd, true)
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
}

var childpri, parpri string

// Send a SIG(0) key rollover request to parent directly from CLI (not via tdns-auth). This is mostly a debug command.
func newDdnsRollCmd() *cobra.Command {
	return &cobra.Command{
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
}

// Send a SIG(0) key upload request to parent directly from CLI (not via tdns-auth). This is mostly a debug command.
func newDdnsUploadCmd() *cobra.Command {
	return &cobra.Command{
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
}

// The daemon sends the delegation data back and this command writes it, as
// the user who runs it: to --outfile, or to stdout. The daemon writes no file.
func newDelExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export a parent zone's delegation data as zone file text",
		Long: `Export a parent zone's delegation data as zone file text.

The daemon returns the data. With --outfile it is written to that file
on this host, with your permissions; without it, it goes to stdout.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Not PrepArgs: it reports a missing zone on stdout, where
			// the export's data goes.
			zone, err := delExportZone(tdns.Globals.Zonename)
			if err == nil {
				outfile, _ := cmd.Flags().GetString("outfile")
				err = runDelExport(cmd, zone, outfile)
			}
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
}

// delExportZone is the zone del export exports: the --zone value, fully
// qualified, or an error when none was given.
func delExportZone(zone string) (string, error) {
	if zone == "" {
		return "", errors.New("zone name not specified using --zone flag")
	}
	return dns.Fqdn(zone), nil
}

func runDelExport(cmd *cobra.Command, zone, outfile string) error {
	api, err := GetApiClientForCmd(cmd, false)
	if err != nil {
		return err
	}
	dr, err := SendDelegationCmd(api, tdns.DelegationPost{
		Command: "export",
		Zone:    zone,
	})
	if err != nil {
		return err
	}
	if outfile == "" {
		_, err := io.WriteString(cmd.OutOrStdout(), dr.Export)
		return err
	}
	if err := writeExportFile(outfile, []byte(dr.Export)); err != nil {
		return err
	}
	msg := fmt.Sprintf("%s: delegation data written to %s", zone, outfile)
	if len(msg) > 72 {
		msg = fmt.Sprintf("%s: delegation data written to\n  %s", zone, outfile)
	}
	fmt.Fprintln(cmd.OutOrStdout(), msg)
	return nil
}

// writeExportFile writes data to a new file next to path and renames it over
// path, so that a reader sees the old file or the whole new one. The file is
// created 0644 less the umask, like os.WriteFile; os.CreateTemp would make it
// 0600 and a chmod would ignore the umask.
func writeExportFile(path string, data []byte) error {
	dir, base := filepath.Split(path)
	var f *os.File
	var tmp string
	for i := 0; ; i++ {
		tmp = filepath.Join(dir, fmt.Sprintf(".%s.tmp%08x", base, rand.Uint32()))
		var err error
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || i == 9 {
			return err
		}
	}
	_, err := f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// NewDdnsCmd and NewDelCmd build the ddns and del subtrees for one daemon
// instance. Both were an init() wiring package-level command vars, which could
// hang off only one tree; see NewCatalogCmd for the reasoning.
//
// Two factories rather than one because these are two sibling subtrees that
// happen to share a file and a helper (SendDelegationCmd), not one tree with
// two roots.
func NewDdnsCmd(role string) *cobra.Command {
	ddns := newDdnsCmd()
	TagRole(ddns, role)

	ddns.AddCommand(newDdnsRollCmd(), newDdnsUploadCmd())

	ddns.PersistentFlags().StringVarP(&tdns.Globals.Sig0Keyfile, "keyfile", "k", "", "name of file with private SIG(0) key")
	ddns.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	ddns.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")

	return ddns
}

func NewDelCmd(role string) *cobra.Command {
	del := newDelCmd()
	TagRole(del, role)

	sync := newDelSyncCmd()
	export := newDelExportCmd()
	del.AddCommand(newDelStatusCmd(), sync, export)

	sync.Flags().StringVarP(&schemestr, "scheme", "S", "", "Scheme to use for synchronization of delegation")
	sync.MarkFlagRequired("zone")

	export.Flags().String("outfile", "", "Write the data to this file on this host (default: stdout)")

	return del
}

// DdnsCmd and DelCmd are the canonical instance's subtrees, kept so the
// existing wiring in cmdv2/cli/shared_cmds.go compiles unchanged.
var (
	DdnsCmd = NewDdnsCmd("auth")
	DelCmd  = NewDelCmd("auth")
)

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
		// stderr: del export's data goes to stdout.
		fmt.Fprintf(os.Stderr, "Status: %d\n", status)
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
