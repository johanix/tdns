/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// The imr commands are the same *cobra.Command values in two binaries (see
// newFlushRunner). Inside tdns-imr's shell, Conf.Internal holds the live engine
// and cache. In tdns-cli it holds nothing and never will, and the commands that
// read it answered for the wrong process: "imr query" printed "No active channel
// to RecursorEngine", "imr stats auth-servers" printed "RecursorCache is nil",
// and "imr show config" reported tdns-cli's own empty configuration as if it were
// the daemon's -- no listeners, not primed, no trust anchors -- about a resolver
// that was up and serving.
//
// flush and "stats transport-stats" already dispatched to the daemon's API. This
// does the same for "query" and "stats auth-servers"/"auth-transports", and makes
// the commands that have no API equivalent say so instead of printing tdns-cli's
// state.

// imrIsRemote reports whether this command runs in tdns-cli, reaching the
// resolver over its API, rather than inside the resolver's own shell.
func imrIsRemote() bool { return flushViaApiWanted() }

// inProcessOnly refuses a command that can only describe the process it runs in
// when that process is tdns-cli. Returns true when it refused.
func inProcessOnly(w io.Writer, name, alternative string) bool {
	if !imrIsRemote() {
		return false
	}
	fmt.Fprintf(w, "%q reports on the process it runs in, which here is tdns-cli, not the resolver; run it in \"tdns-imr --cli\"", name)
	if alternative != "" {
		fmt.Fprintf(w, ", or use %s against a running daemon", alternative)
	}
	fmt.Fprintln(w, ".")
	return true
}

func guardInProcess(c *cobra.Command, name, alternative string) {
	run := c.Run
	c.Run = func(cmd *cobra.Command, args []string) {
		if inProcessOnly(os.Stderr, name, alternative) {
			return
		}
		run(cmd, args)
	}
}

func dispatchRemote(c *cobra.Command, remote func(cmd *cobra.Command, args []string)) {
	run := c.Run
	c.Run = func(cmd *cobra.Command, args []string) {
		if imrIsRemote() {
			remote(cmd, args)
			return
		}
		run(cmd, args)
	}
}

func init() {
	dispatchRemote(ImrQueryCmd, queryViaApi)

	authServersRemote := func(cmd *cobra.Command, args []string) {
		var f transportStatsFilter
		if len(args) == 1 {
			f.zone = dns.Fqdn(args[0])
		}
		renderTransportStatsRemote(cmd.Context(), f)
	}
	// Both: auth-servers copied auth-transports' Run when the vars were built.
	dispatchRemote(imrStatsAuthTransportsCmd, authServersRemote)
	dispatchRemote(imrStatsAuthServersCmd, authServersRemote)

	guardInProcess(ImrStatsCmd, "imr stats", `"tdns-cli imr stats transport-stats"`)
	guardInProcess(imrStatsLargeKskCmd, "imr stats large-ksk", "")
	guardInProcess(imrShowConfigCmd, "imr show config", `"tdns-cli imr config status"`)
	guardInProcess(imrShowOptionsCmd, "imr show options", `"tdns-cli imr config status"`)
	guardInProcess(imrSetLineWidthCmd, "imr set linewidth", "")
}

// queryViaApi is "imr query" for tdns-cli: the daemon resolves, and says what
// its validator concluded.
func queryViaApi(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		fmt.Println("Error: both name and type are required.")
		_ = cmd.Usage()
		return
	}
	qname := dns.Fqdn(args[0])
	if _, ok := dns.IsDomainName(qname); !ok {
		fmt.Printf("Not a valid domain name: '%s'\n", qname)
		return
	}
	qtype, ok := dns.StringToType[strings.ToUpper(args[1])]
	if !ok {
		fmt.Printf("Not a valid DNS RR type: '%s'\n", args[1])
		return
	}

	amr, err := SendImrMgmtCmd(cmd.Context(), "imr", &tdns.ImrMgmtPost{
		Command: "imr-resolve",
		Data:    map[string]interface{}{"qname": qname, "qtype": dns.TypeToString[qtype]},
	})
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	data, _ := amr.Data.(map[string]interface{})
	state, _ := data["state"].(string)
	if amr.Error {
		fmt.Printf("Error: %s\n", amr.ErrorMsg)
		return
	}
	if neg, _ := data["negative"].(string); neg != "" {
		fmt.Printf("%s %s (state: %s)\n", qname, neg, state)
		return
	}
	records := stringsOf(data["records"])
	if len(records) == 0 {
		fmt.Printf("No records found for %s %s (state: %s)\n", qname, dns.TypeToString[qtype], state)
		return
	}
	for _, rr := range records {
		fmt.Printf("%s (state: %s)\n", rr, state)
	}
	for _, rr := range stringsOf(data["rrsigs"]) {
		fmt.Println(rr)
	}
}

// stringsOf reads a JSON-decoded list of strings.
func stringsOf(v interface{}) []string {
	list, _ := v.([]interface{})
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
