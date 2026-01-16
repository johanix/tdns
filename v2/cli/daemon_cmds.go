/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
		prefixcmd, _ := getCommandContext("daemon")
		api, _ := getApiClient(prefixcmd, true)
		_, resp, _ := api.UpdateDaemon(tdns.CommandPost{Command: "status"},
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
		prefixcmd, _ := getCommandContext("daemon")
		api, _ := getApiClient(prefixcmd, true)

		_, resp, _ := api.UpdateDaemon(tdns.CommandPost{Command: "reload"}, true)
		fmt.Printf("Reload: %s Message: %s\n", resp.Status, resp.Msg)
	},
}

var MaxWait int

var DaemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the axfr-statusd daemon",
	Long:  `Start the axfr-statusd daemon. If it was already running, then this is a no-op.`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("daemon")
		api, _ := getApiClient(prefixcmd, true)

		maxwait := viper.GetInt("cli.maxwait")
		if maxwait < MaxWait {
			maxwait = MaxWait
		}

		// Get command from CLI config if available
		clientKey := getClientKeyFromParent(prefixcmd)
		if clientKey == "" {
			clientKey = "tdns-auth" // fallback for unknown commands
		}
		daemonCommand := ""
		if apiDetails := getApiDetailsByClientKey(clientKey); apiDetails != nil {
			if cmdStr, ok := apiDetails["command"].(string); ok && cmdStr != "" {
				daemonCommand = cmdStr
			}
		}

		api.StartDaemon(maxwait, tdns.Globals.Slurp, daemonCommand)
	},
}

var DaemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the management daemon",
	Long:  `Stop the management daemon. If it was not running, then this is a no-op.`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("daemon")
		api, _ := getApiClient(prefixcmd, true)

		api.StopDaemon()
	},
}

var DaemonRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Stop and then start the management daemon",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("daemon")
		api, _ := getApiClient(prefixcmd, true)

		api.StopDaemon()
		time.Sleep(4 * time.Second)
		maxwait := viper.GetInt("cli.maxwait")
		if maxwait < MaxWait {
			maxwait = MaxWait
		}

		// Get command from CLI config if available
		clientKey := getClientKeyFromParent(prefixcmd)
		if clientKey == "" {
			clientKey = "tdns-auth" // fallback for unknown commands
		}
		daemonCommand := ""
		if apiDetails := getApiDetailsByClientKey(clientKey); apiDetails != nil {
			if cmdStr, ok := apiDetails["command"].(string); ok && cmdStr != "" {
				daemonCommand = cmdStr
			}
		}

		// Fallback to viper for backward compatibility
		if daemonCommand == "" {
			daemonCommand = viper.GetString("common.command")
		}

		if updateBinary {
			dstbin := daemonCommand
			if dstbin == "" {
				fmt.Printf("Update binary: destination unspecified (key: apiservers[].command or common.command)\n")
				os.Exit(1)
			}
			srcbin := "/tmp/" + filepath.Base(dstbin)
			dstat, err := os.Stat(dstbin)
			if err != nil {
				fmt.Printf("Error from stat(dst: %q): %v\n", dstbin, err)
				os.Exit(1)
			}
			if tdns.Globals.Debug {
				fmt.Printf("ModTime(%s): %v\n", dstbin, dstat.ModTime())
			}

			sstat, err := os.Stat(srcbin)
			if err != nil {
				fmt.Printf("Error from stat(src: %q): %v\n", srcbin, err)
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
		tdns.Globals.Api.StartDaemon(maxwait, false, daemonCommand) // no slurping on restart
	},
}

var DaemonApiCmd = &cobra.Command{
	Use:   "api",
	Short: "request a statusd api summary",
	Long: `The daemon api queries the statusd for the provided API
and prints that out in a (hopefully) comprehensible fashion.`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("daemon")
		api, _ := getApiClient(prefixcmd, true)

		if len(args) != 0 {
			log.Fatal("api must have no arguments")
		}
		api.ShowApi()
	},
}

func init() {
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
