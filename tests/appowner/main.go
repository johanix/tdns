/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * appowner is an application client of tdns-auth's management API. It does
 * what a provisioning application does, over TCP with its own pinned client
 * certificate, and checks the API ownership model from the outside: what an
 * application may do works, what it may not is refused, and a refusal leaves
 * the state as it was. Design: docs/2026-11-23-tdns-api-ownership-design.md.
 *
 * run.sh builds this, sets up a daemon in a temporary directory and runs
 * "appowner run" against it. See README.md.
 */
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	tdns "github.com/johanix/tdns/v2"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  appowner ports N        print N free TCP ports on 127.0.0.1, one per line
  appowner run [flags]    run the checks (run.sh passes the flags)
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "ports":
		if len(os.Args) != 3 {
			usage()
		}
		n, err := strconv.Atoi(os.Args[2])
		if err != nil || n < 1 {
			usage()
		}
		if err := printFreePorts(n); err != nil {
			fmt.Fprintf(os.Stderr, "appowner ports: %v\n", err)
			os.Exit(1)
		}
	case "run":
		os.Exit(runCmd(os.Args[2:]))
	default:
		usage()
	}
}

// printFreePorts prints n distinct ports that the kernel just handed out on
// 127.0.0.1. They are free now; run.sh uses them at once.
func printFreePorts(n int) error {
	var ls []net.Listener
	defer func() {
		for _, l := range ls {
			l.Close()
		}
	}()
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		ls = append(ls, l)
		fmt.Println(l.Addr().(*net.TCPAddr).Port)
	}
	return nil
}

// options are what run.sh tells the checks about the rig.
type options struct {
	API          string // the daemon's TCP management API, https://127.0.0.1:PORT/api/v1
	Pin          string // the SPKI pin of the daemon's certificate
	Clients      string // directory with app1, app2 and op .crt/.key
	ApiKey       string // the daemon's API key (check 11)
	Socket       string // the daemon's local admin socket (read-only audits)
	DaemonConfig string // the daemon's config file
	Ncli         string // tdns-ncli, for the operator's steps
	NcliConfig   string // tdns-ncli's CLI config, with the daemon's entry
	Primary      string // an address:port for secondaries' primaries (nothing answers there)
	Primary2     string // another one, for zone modify
	Template     string // the dynamiczones template for primaries
	Transcript   string // file for every request and reply
	DaemonLog    string // the daemon's log file (risk R9: exports are logged)
	Scratch      string // a directory the daemon may write to (delegation export)
	DNS          string // the daemon's DNS address, 127.0.0.1:PORT
}

func runCmd(args []string) int {
	var o options
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.StringVar(&o.API, "api", "", "management API base URL")
	fs.StringVar(&o.Pin, "pin", "", "SPKI pin of the daemon's certificate")
	fs.StringVar(&o.Clients, "clients", "", "directory with the clients' certificates and keys")
	fs.StringVar(&o.ApiKey, "apikey", "", "the daemon's API key")
	fs.StringVar(&o.Socket, "socket", "", "the daemon's local admin socket")
	fs.StringVar(&o.DaemonConfig, "daemon-config", "", "the daemon's config file")
	fs.StringVar(&o.Ncli, "ncli", "", "tdns-ncli binary")
	fs.StringVar(&o.NcliConfig, "ncli-config", "", "tdns-ncli CLI config")
	fs.StringVar(&o.Primary, "primary", "", "primary address for secondaries")
	fs.StringVar(&o.Primary2, "primary2", "", "second primary address, for zone modify")
	fs.StringVar(&o.Template, "template", "app-primary", "dynamiczones template for primaries")
	fs.StringVar(&o.Transcript, "transcript", "", "file to log every request and reply to")
	fs.StringVar(&o.DaemonLog, "daemon-log", "", "the daemon's log file")
	fs.StringVar(&o.Scratch, "scratch", "", "a directory the daemon may write files to")
	fs.StringVar(&o.DNS, "dns", "", "the daemon's DNS address")
	fs.Parse(args)
	for name, v := range map[string]string{"api": o.API, "pin": o.Pin, "clients": o.Clients, "apikey": o.ApiKey,
		"socket": o.Socket, "daemon-config": o.DaemonConfig, "ncli": o.Ncli, "ncli-config": o.NcliConfig,
		"primary": o.Primary, "primary2": o.Primary2, "transcript": o.Transcript, "daemon-log": o.DaemonLog,
		"scratch": o.Scratch, "dns": o.DNS} {
		if v == "" {
			fmt.Fprintf(os.Stderr, "appowner run: --%s is required\n", name)
			return 2
		}
	}
	tdns.SetupCliLogging()

	s, err := newSuite(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "appowner run: %v\n", err)
		return 2
	}
	defer s.close()
	s.run()
	return s.summary()
}
