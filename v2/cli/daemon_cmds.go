/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var newapi bool

const timelayout = "2006-01-02 15:04:05"

var ServerName string = "PLACEHOLDER"

var updateBinary bool
var clearLogFile string

// MaxWait bound by --maxwait on "daemon start".
var MaxWait int

// extractDaemonFlags collects flags from the CLI command that should be
// passed through to the daemon when it starts (e.g., --config, --debug, -v)
func extractDaemonFlags(cmd *cobra.Command) []string {
	return daemonFlagsFrom(cmd, true)
}

// daemonFlagsFrom is extractDaemonFlags, with the root --config passed on
// only when withConfig is set.
func daemonFlagsFrom(cmd *cobra.Command, withConfig bool) []string {
	var flags []string

	// Walk up to root command to collect all flags
	root := cmd.Root()

	// Check for --config flag
	if configFlag := root.Flag("config"); withConfig && configFlag != nil && configFlag.Changed {
		flags = append(flags, "--config", configFlag.Value.String())
	}

	// Check for --debug flag
	if debugFlag := root.Flag("debug"); debugFlag != nil && debugFlag.Changed {
		flags = append(flags, "--debug")
	}

	// Check for -v/--verbose flag
	if verboseFlag := root.Flag("verbose"); verboseFlag != nil && verboseFlag.Changed {
		flags = append(flags, "-v")
	}

	return flags
}

// daemonStartFlags is extractDaemonFlags for starting the daemon behind ad:
// when ad has a config-file:, the daemon is started with --config
// <config-file:>. Without it the daemon reads its compiled-in default, which
// is the canonical daemon's file: `auth2 daemon start` would start a second
// tdns-auth on the first one's config, and then wait in vain for auth2's API.
//
// The CLI's own --config is then not passed on. It names the CLI config
// (tdns-ncli.yaml), not a daemon's, so it must neither replace the entry's
// config-file: nor follow it.
//
// A named instance (an entry with a role:) with no config-file: is refused:
// its daemon would read the compiled-in default, the canonical daemon's
// config, and the CLI's --config is the CLI's. Neither is the instance's, so
// there is nothing right to start it with. A canonical entry with no
// config-file: gets the flags as before, the CLI's --config included.
func daemonStartFlags(cmd *cobra.Command, ad *ApiDetails) ([]string, error) {
	switch {
	case ad != nil && ad.ConfigFile != "":
		return append([]string{"--config", ad.ConfigFile}, daemonFlagsFrom(cmd, false)...), nil
	case ad != nil && ad.Role != "" && roleEntryOf(*ad, builtinRoles()) == "":
		// An instance (auth2). A role's own entry (auth, as config update
		// --rename writes it, role: and all) starts on the role's default
		// config, as it did without role:.
		return nil, fmt.Errorf("apiservers entry %q has no config-file:, so its daemon would start on the "+
			"canonical daemon's config. Add config-file: <its daemon config> to the entry", ad.Name)
	}
	return extractDaemonFlags(cmd), nil
}

// daemonCommandLine is how to start the daemon: the binary and its arguments.
// command is the entry's command: (or common.command), split as a shell
// splits a command line, so that it may carry arguments, as in
// "/usr/local/libexec/tdns-auth --config /etc/tdns-enc/tdns-auth.yaml".
// flags (daemonStartFlags) follow its own options, before a "--" in it: after
// "--" an option is an argument to the daemon. A --config in both is passed
// once when the two name the same file, and refused when they do not: the
// daemon would start on the one while the entry waits for the other. So is a
// command: naming two different config files (the daemon takes the last), and
// one with a one-dash -config, which the daemons (pflag) do not take: the new
// daemon would exit at once. All of it is decided before anything is stopped. An empty command gives an
// empty binary, which StartDaemon refuses if it has to start anything.
func daemonCommandLine(command string, flags []string) (string, []string, error) {
	words, err := splitCommandLine(command)
	if err != nil {
		return "", nil, fmt.Errorf("command: %q: %v", command, err)
	}
	if len(words) == 0 {
		return "", flags, nil
	}
	bin, own := words[0], words[1:]
	opts, rest := own, []string(nil)
	if i := slices.Index(own, "--"); i >= 0 {
		opts, rest = own[:i], own[i:]
	}
	for _, a := range opts {
		if a == "-config" || strings.HasPrefix(a, "-config=") {
			return "", nil, fmt.Errorf("command: has %s with one dash; the daemons take --config (two dashes)", a)
		}
	}
	if cmdCfgs := configArgs(opts); len(cmdCfgs) > 0 {
		for _, c := range cmdCfgs[1:] {
			if resolvedPath(c) != resolvedPath(cmdCfgs[0]) {
				return "", nil, fmt.Errorf("command: names two config files, %s and %s; the daemon would start on the last. Keep one", cmdCfgs[0], c)
			}
		}
		if flagCfg, ok := configArg(flags); ok {
			if resolvedPath(cmdCfgs[0]) != resolvedPath(flagCfg) {
				return "", nil, fmt.Errorf("command: starts the daemon with --config %s, but its entry's config file is %s; make them the same (or take --config out of command:)",
					cmdCfgs[0], flagCfg)
			}
			flags = withoutConfigArg(flags)
		}
	}
	args := append(append([]string(nil), opts...), flags...)
	return bin, append(args, rest...), nil
}

// configArgs are the values of the --config arguments in args, in order, up
// to a "--": --config x and --config=x, the forms pflag takes (the daemons
// parse their flags with it; a one-dash -config is refused before this).
func configArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return out
		case a == "--config" && i+1 < len(args):
			out = append(out, args[i+1])
			i++
		case strings.HasPrefix(a, "--config="):
			out = append(out, strings.TrimPrefix(a, "--config="))
		}
	}
	return out
}

// configArg is the value of the first --config argument in args (configArgs).
func configArg(args []string) (string, bool) {
	if c := configArgs(args); len(c) > 0 {
		return c[0], true
	}
	return "", false
}

// withoutConfigArg is args without its --config argument.
func withoutConfigArg(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--config" && i+1 < len(args):
			i++
		case strings.HasPrefix(args[i], "--config="):
		default:
			out = append(out, args[i])
		}
	}
	return out
}

// splitCommandLine splits s into words as a POSIX shell does, without
// expanding anything: blanks separate words; single quotes keep everything
// up to the next one; double quotes keep everything but \" and \\, which a
// backslash escapes; outside quotes a backslash escapes the next character.
func splitCommandLine(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("a single quote is not closed")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
			inWord = true
		case c == '"':
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
					i++
				}
				cur.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, errors.New("a double quote is not closed")
			}
			inWord = true
		case c == '\\':
			if i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			}
			inWord = true
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

// mustDaemonCommandLine is daemonCommandLine, exiting on its refusal: before
// anything is stopped or started.
func mustDaemonCommandLine(command string, flags []string) (string, []string) {
	bin, args, err := daemonCommandLine(command, flags)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return bin, args
}

// mustDaemonStartFlags is daemonStartFlags, exiting on its refusal.
func mustDaemonStartFlags(cmd *cobra.Command, ad *ApiDetails) []string {
	flags, err := daemonStartFlags(cmd, ad)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return flags
}

// NewDaemonCmd returns a fresh "daemon" command tree bound to the given
// role. Each attachment point (auth, agent, imr, scanner in tdns-cli;
// signer, combiner, agent in mpcli; plus root "server") gets its own
// *cobra.Command.
func NewDaemonCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "daemon",
		Short: "Only useful via sub-commands",
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Query for the status of the management daemon",
		Long:  `Query for the status of the management daemon`,
		Run: func(cmd *cobra.Command, args []string) {
			api, _ := GetApiClient(role, true)
			_, resp, _ := api.UpdateDaemon(tdns.CommandPost{Command: "status"}, true)
			for _, w := range resp.Warnings {
				fmt.Println(w)
			}
			fmt.Printf("Status: %s Message: %s\n", resp.Status, resp.Msg)
		},
	}

	reload := &cobra.Command{
		Use:   "reload",
		Short: "Reload config from file",
		Long: `Reload config from file (the assumption is that something in the config has changed).
Right now this doesn't do much, but later on various services will be able to restart.`,
		Run: func(cmd *cobra.Command, args []string) {
			api, _ := GetApiClient(role, true)
			_, resp, _ := api.UpdateDaemon(tdns.CommandPost{Command: "reload"}, true)
			fmt.Printf("Reload: %s Message: %s\n", resp.Status, resp.Msg)
		},
	}

	start := &cobra.Command{
		Use:   "start",
		Short: "Start the tdns-" + role + " daemon",
		Long:  `Start the tdns-` + role + ` daemon. If it was already running, then this is a no-op.`,
		Run: func(cmd *cobra.Command, args []string) {
			api, _ := GetApiClient(role, true)

			maxwait := viper.GetInt("cli.maxwait")
			if maxwait < MaxWait {
				maxwait = MaxWait
			}

			// Get command from CLI config if available
			clientKey := getClientKeyFromParent(role)
			if clientKey == "" {
				clientKey = "auth" // fallback for unknown roles
			}
			daemonCommand := ""
			ad := getApiDetailsByClientKey(clientKey)
			if ad != nil {
				daemonCommand = ad.Command
			}

			// Flags to pass to the daemon: --config <the entry's config-file:>
			// (or the CLI's --config, for a canonical entry without one),
			// --debug, -v.
			daemonFlags := mustDaemonStartFlags(cmd, ad)
			if daemonCommand == "" {
				daemonCommand = viper.GetString("common.command")
			}
			// command: may carry arguments of its own, --config among them.
			daemonBinary, daemonArgs := mustDaemonCommandLine(daemonCommand, daemonFlags)

			api.StartDaemon(maxwait, tdns.Globals.Slurp, daemonBinary, daemonArgs)
		},
	}
	start.Flags().BoolVarP(&tdns.Globals.Slurp, "slurp", "", false,
		"Slurp stdout/stderr for errors (debug tool only)")
	start.Flags().IntVarP(&MaxWait, "maxwait", "W", 5,
		"Max seconds to wait until declaring start to have failed")

	stop := &cobra.Command{
		Use:   "stop",
		Short: "Stop the management daemon",
		Long:  `Stop the management daemon. If it was not running, then this is a no-op.`,
		Run: func(cmd *cobra.Command, args []string) {
			api, _ := GetApiClient(role, true)
			if err := api.StopDaemon(); err != nil {
				os.Exit(1)
			}
		},
	}

	restart := &cobra.Command{
		Use:   "restart",
		Short: "Stop and then start the management daemon",
		Run: func(cmd *cobra.Command, args []string) {
			api, _ := GetApiClient(role, true)

			clientKey := getClientKeyFromParent(role)
			if clientKey == "" {
				clientKey = "auth" // fallback for unknown roles
			}
			ad := getApiDetailsByClientKey(clientKey)

			// The flags as for start, worked out before the stop, so that a
			// refusal (a named instance with no config-file:) leaves the
			// running daemon alone.
			daemonFlags := mustDaemonStartFlags(cmd, ad)
			// The command line too: command: (or common.command), which may
			// carry arguments of its own, --config among them.
			daemonCommand := ""
			if ad != nil {
				daemonCommand = ad.Command
			}
			if daemonCommand == "" {
				daemonCommand = viper.GetString("common.command")
			}
			daemonBinary, daemonArgs := mustDaemonCommandLine(daemonCommand, daemonFlags)

			// A daemon that refused to stop (a 403: stop needs admin) is
			// still running; starting another would only fail, so stop here.
			if err := api.StopDaemon(); err != nil {
				os.Exit(1)
			}
			time.Sleep(4 * time.Second)

			if clearLogFile != "" {
				if f, err := os.OpenFile(clearLogFile, os.O_WRONLY|os.O_TRUNC, 0); err != nil {
					fmt.Printf("Warning: could not truncate log file %q: %v\n", clearLogFile, err)
				} else {
					f.Close()
					fmt.Printf("Log file truncated: %s\n", clearLogFile)
				}
			}

			maxwait := viper.GetInt("cli.maxwait")
			if maxwait < MaxWait {
				maxwait = MaxWait
			}

			if updateBinary {
				dstbin := daemonBinary
				if dstbin == "" {
					fmt.Printf("Update binary: destination unspecified (key: apiservers[].command or common.command)\n")
					os.Exit(1)
				}
				srcbin := filepath.Join(os.TempDir(), filepath.Base(dstbin))
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

			api.StartDaemon(maxwait, false, daemonBinary, daemonArgs) // no slurping on restart
		},
	}
	restart.Flags().BoolVarP(&updateBinary, "update", "", false,
		"Update the server binary from /tmp/{binary} to /usr/local/libexec/ before starting")
	restart.Flags().StringVarP(&clearLogFile, "clear", "", "",
		"Truncate the specified log file before starting")

	apiCmd := &cobra.Command{
		Use:   "api",
		Short: "request an API summary from the tdns-" + role + " daemon",
		Long: `The daemon api command queries tdns-` + role + ` for the provided API
and prints that out in a (hopefully) comprehensible fashion.`,
		Run: func(cmd *cobra.Command, args []string) {
			api, _ := GetApiClient(role, true)
			if len(args) != 0 {
				log.Fatal("api must have no arguments")
			}
			api.ShowApi()
		},
	}

	c.AddCommand(status, reload, start, stop, restart, apiCmd)
	return c
}
