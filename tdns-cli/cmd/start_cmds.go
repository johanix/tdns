/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func xxxShellExec(cmdline string) (string, error) {
	args := strings.Fields(cmdline)
	if tdns.Globals.Verbose {
		fmt.Printf("ShellExec cmd: '%s'\n", cmdline)
	}

	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if len(out) > 1 {
		out = out[:len(out)-1] // chop of trailing newline
	}
	if err != nil {
		fmt.Printf("ShellExec of cmd '%s' failed. Error: %v\nOutput: %s\n", cmd, err, string(out))
		return fmt.Sprintf("shell exec of cmd '%s' failed. Error: %v", cmd, err), err
	}
	if tdns.Globals.Debug {
		fmt.Printf("ShellExec output: '%s'\n", string(out))
	}
	return string(out), nil
}

var newapi bool

const timelayout = "2006-01-02 15:04:05"

var ServerName string = "PLACEHOLDER"

var updateBinary bool

var DaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Only useful via sub-commands",
}

var DaemonStatusCmd = &cobra.Command{
	Use: "status",
	// Short: fmt.Sprintf("Query for the status of the %s daemon", ServerName),
	Short: "Query for the status of the management daemon",
	Long:  `Query for the status of the management daemon`,
	Run: func(cmd *cobra.Command, args []string) {
		_, resp, _ := tdns.Globals.Api.UpdateDaemon(tdns.CommandPost{Command: "status"},
			true)
		fmt.Printf("Status: %s Message: %s\n", resp.Status, resp.Msg)
	},
}

var DaemonReloadCmd = &cobra.Command{
	Use: "reload",
	// Short: fmt.Sprintf("Reload %s config from file", ServerName),
	Short: "Reload config from file",
	Long: `Reload config from file (the assumption is that something in the config has changed).
Right now this doesn't do much, but later on various services will be able to restart.`,
	Run: func(cmd *cobra.Command, args []string) {
		_, resp, _ := tdns.Globals.Api.UpdateDaemon(tdns.CommandPost{Command: "reload"}, true)
		fmt.Printf("Reload: %s Message: %s\n", resp.Status, resp.Msg)
	},
}

var MaxWait int

var DaemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the axfr-statusd daemon",
	Long:  `Start the axfr-statusd daemon. If it was already running, then this is a no-op.`,
	Run: func(cmd *cobra.Command, args []string) {
		maxwait := viper.GetInt("cli.maxwait")
		if maxwait < MaxWait {
			maxwait = MaxWait
		}
		tdns.Globals.Api.StartDaemon(maxwait, tdns.Globals.Slurp)
	},
}

var DaemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the management daemon",
	Long:  `Stop the management daemon. If it was not running, then this is a no-op.`,
	Run: func(cmd *cobra.Command, args []string) {
		tdns.Globals.Api.StopDaemon()
	},
}

var DaemonRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Stop and then start the management daemon",
	Run: func(cmd *cobra.Command, args []string) {
		tdns.Globals.Api.StopDaemon()
		time.Sleep(4 * time.Second)
		maxwait := viper.GetInt("cli.maxwait")
		if maxwait < MaxWait {
			maxwait = MaxWait
		}
		if updateBinary {
			dstbin := viper.GetString("common.command")
			srcbin := "/tmp/" + filepath.Base(dstbin)
			dstat, err := os.Stat(dstbin)
			if err != nil {
				fmt.Printf("Error from stat(%s): %v\n", dstbin, err)
				os.Exit(1)
			}
			if tdns.Globals.Debug {
				fmt.Printf("ModTime(%s): %v\n", dstbin, dstat.ModTime())
			}

			sstat, err := os.Stat(srcbin)
			if err != nil {
				fmt.Printf("Error from stat(%s): %v\n", srcbin, err)
				os.Exit(1)
			}
			if tdns.Globals.Debug {
				fmt.Printf("ModTime(%s): %v\n", srcbin, sstat.ModTime())
			}

			if sstat.ModTime().After(dstat.ModTime()) {
				fmt.Printf("%s is newer than %s. Will update installed binary.\n",
					srcbin, dstbin)
				n, err := tdns.CopyFile(srcbin, dstbin)
				if err != nil {
					fmt.Printf("Error copying %s to %s: %v\n", srcbin, dstbin, err)
					os.Exit(1)
				}
				fmt.Printf("Successfully copied %s to %s (%d bytes)\n", srcbin, dstbin, n)
			} else {
				fmt.Printf("%s is not newer than %s. No update.\n", srcbin, dstbin)
			}
		}
		tdns.Globals.Api.StartDaemon(maxwait, false) // no slurping on restart
	},
}

var DaemonApiCmd = &cobra.Command{
	Use:   "api",
	Short: "request a statusd api summary",
	Long: `The daemon api queries the statusd for the provided API
and prints that out in a (hopefully) comprehensible fashion.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			log.Fatal("api must have no arguments")
		}
		tdns.Globals.Api.ShowApi()
	},
}

func init() {
	rootCmd.AddCommand(PingCmd)
	rootCmd.AddCommand(DaemonCmd)
	DaemonCmd.AddCommand(DaemonStatusCmd, DaemonReloadCmd)
	DaemonCmd.AddCommand(DaemonStartCmd, DaemonStopCmd, DaemonRestartCmd)
	DaemonCmd.AddCommand(DaemonApiCmd)

	DaemonStartCmd.Flags().BoolVarP(&tdns.Globals.Slurp, "slurp", "", false,
		"Slurp stdout/stderr for errors (debug tool only)")
	DaemonStartCmd.Flags().IntVarP(&MaxWait, "maxwait", "W", 5,
		"Max seconds to wait until declaring start to have failed")
	DaemonRestartCmd.Flags().BoolVarP(&updateBinary, "update", "", false,
		"Update the server binary from /tmp/{binary} to /usr/local/libexec/ before starting")

	PingCmd.Flags().IntVarP(&tdns.Globals.PingCount, "count", "c", 0, "#pings to send")
	PingCmd.Flags().BoolVarP(&newapi, "newapi", "n", false, "use new api client")
}
