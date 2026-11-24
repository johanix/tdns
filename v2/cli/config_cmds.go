/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// NewConfigCmd returns a fresh "config" command tree bound to the given
// role. Each attachment point gets its own *cobra.Command.
func NewConfigCmd(role string) *cobra.Command {
	return NewConfigCmdFor(role, role)
}

// NewConfigCmdFor is NewConfigCmd for a tree whose role is not the daemon type:
// an extra instance, whose role is its own name ("sectagent") while the daemon
// it is an instance OF is the flavour ("agent").
//
// The flavour has to be passed, not looked up: which commands exist is decided
// here, at construction, before the CLI config is loaded, and an instance's
// flavour lives in that config. The tree factory (NewAgentTree, NewAuthTree)
// knows what it is building.
func NewConfigCmdFor(role, flavour string) *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Commands to reload config, reload zones, etc",
	}

	var reloadConfirm bool
	reload := &cobra.Command{
		Use:   "reload",
		Short: "Send config reload command to tdns-" + role,
		Run: func(cmd *cobra.Command, args []string) {
			runConfigCmd(role, "reload", false, reloadConfirm)
		},
	}
	reload.Flags().BoolVar(&reloadConfirm, "confirm", false,
		"apply even if the reload would strand a signed zone by a same-name DNSSEC policy algorithm change")

	var reloadZonesConfirm bool
	reloadZones := &cobra.Command{
		Use:   "reload-zones",
		Short: "Send reload-zones command to tdns-" + role,
		Run: func(cmd *cobra.Command, args []string) {
			runConfigCmd(role, "reload-zones", false, reloadZonesConfirm)
		},
	}
	reloadZones.Flags().BoolVar(&reloadZonesConfirm, "confirm", false,
		"apply even if the reload would strand a signed zone by a same-name DNSSEC policy algorithm change")

	var force, interactive bool
	reloadTsig := &cobra.Command{
		Use:   "reload-tsig",
		Short: "Reconcile keys.tsig into the TSIG keystore (config reload-tsig)",
		Long: `Re-read keys.tsig from the config file and reconcile into the DB-backed
TSIG keystore. Secret conflicts are withheld by default; use --force to
overwrite all conflicts, or --interactive to prompt per conflict.`,
		Run: func(cmd *cobra.Command, args []string) {
			runReloadTsigCmd(role, force, interactive)
		},
	}
	reloadTsig.Flags().BoolVar(&force, "force", false, "overwrite all secret/algorithm conflicts with keys.tsig")
	reloadTsig.Flags().BoolVar(&interactive, "interactive", false, "prompt per conflict before overwriting")

	status := &cobra.Command{
		Use:   "status",
		Short: "Send config status command to tdns-" + role,
		Run: func(cmd *cobra.Command, args []string) {
			runConfigCmd(role, "status", true, false)
		},
	}

	c.AddCommand(reload, reloadZones, reloadTsig, status)
	if flavour != "agent" {
		// tdns-auth (and named auth instances) synthesize the transport
		// signal; tdns-agent (and named agent instances) does not.
		c.AddCommand(newConfigTransportSignalCmd(role))
	}
	c.AddCommand(newConfigCheckCmd(role))
	c.AddCommand(newConfigMweCmd(role))
	return c
}

// renderProcStatus prints the process-resource block of a config-status
// response, with a loud line when descriptors are close to the limit — the
// #443 wedge (fd exhaustion starving outbound dials) grows visibly here
// before it bites. No-op when the daemon reported no block.
func renderProcStatus(ps *tdns.ProcStatus) {
	if ps == nil {
		return
	}
	if ps.FDMethod == "unavailable" {
		// Two causes share this state: an unsupported platform, and — on
		// linux/darwin — descriptor exhaustion, where counting needs the
		// one fd that no longer exists. Post-wedge, this line IS the signal.
		fmt.Printf("Process: fd count unavailable (unsupported platform, or descriptors exhausted — see tdns#443), goroutines %d\n", ps.Goroutines)
		return
	}
	kind := "open fds"
	if ps.FDMethod == "maxfd" {
		kind = "highest fd"
	}
	line := fmt.Sprintf("Process: %s %d", kind, ps.OpenFDs)
	if ps.FDLimit > 0 {
		line += fmt.Sprintf(" (limit %d)", ps.FDLimit)
	}
	line += fmt.Sprintf(", goroutines %d", ps.Goroutines)
	fmt.Println(line)
	// Divide before multiplying and require a sane finite limit: an
	// RLIM_INFINITY soft limit would overflow FDLimit*8/10 and misfire.
	if ps.FDLimit > 0 && ps.FDLimit < 1<<40 && uint64(ps.OpenFDs) >= ps.FDLimit/10*8 {
		fmt.Printf("WARNING: file descriptors at %d of %d — a leak here starves outbound queries (see tdns#443)\n",
			ps.OpenFDs, ps.FDLimit)
	}
}

// renderImrStatus prints the IMR block of a config-status response: priming
// state, stub zones, and forward zones with per-upstream reachability. No-op
// when the daemon reported no IMR block.
func renderImrStatus(st *tdns.ImrStatus) {
	if st == nil {
		return
	}
	if st.DataClock != "" {
		fmt.Printf("IMR: data time is a TEST CLOCK (%s)\n", st.DataClock)
	}
	fmt.Print(imrRootStatusLines(st))

	if !st.ZonesLoadedAt.IsZero() {
		fmt.Printf("IMR: stub/forward zones loaded at %s\n", st.ZonesLoadedAt.Format(tdns.TimeLayout))
	}
	if len(st.StubZones) > 0 {
		fmt.Printf("IMR: stub zones: %s\n", strings.Join(st.StubZones, ", "))
	}
	for _, fz := range st.ForwardZones {
		printForwardZoneStatus(fz, "IMR: ")
	}
}

// imrRootStatusLines renders the root part of the IMR block: how the cache was
// primed and what it holds for the root NS, or that the root is forwarded.
func imrRootStatusLines(st *tdns.ImrStatus) string {
	// A forwarded root is neither primed nor kept: nothing is iterated, so a
	// root NS expiry says nothing about whether the resolver can answer.
	if st.RootForwarded {
		return "IMR: root forwarded: not primed, no root NS kept\n"
	}
	primed := "not primed"
	if st.Primed {
		primed = "primed"
		if st.PrimedVia != "" {
			primed += " via " + st.PrimedVia
		}
		if !st.PrimedAt.IsZero() {
			primed += " at " + st.PrimedAt.Format(tdns.TimeLayout)
		}
	}
	out := fmt.Sprintf("IMR: %s\n", primed)

	// The line that matters when a resolver has stopped resolving. "primed at
	// <boot>" is about the past; this is about whether an iteration can still
	// be started at all.
	if st.RootNSPresent {
		left := time.Until(st.RootNSExpires).Round(time.Second)
		out += fmt.Sprintf("IMR: root NS: %d server(s), expires %s (in %s)\n",
			st.RootNSCount, st.RootNSExpires.Format(tdns.TimeLayout), left)
	} else {
		out += "IMR: root NS: ABSENT -- iteration cannot start;" +
			" every uncached name will SERVFAIL\n"
	}
	return out
}

// printForwardZoneStatus renders one forward zone's reachability block.
// Shared by renderImrStatus (config status) and `imr forward status`.
func printForwardZoneStatus(fz tdns.ImrForwardZoneStatus, prefix string) {
	trust := ""
	if fz.TrustAD {
		trust = ", trust-ad"
	}
	// A quarantined zone is not serving; say so on the header line rather
	// than leaving the reader to infer it from every upstream being marked.
	if fz.Quarantined {
		fmt.Printf("%sforward zone %s (%d upstream(s)%s): QUARANTINED, names under it SERVFAIL: %s\n",
			prefix, fz.Zone, len(fz.Upstreams), trust, fz.QuarantineReason)
	} else {
		fmt.Printf("%sforward zone %s (%d upstream(s)%s):\n", prefix, fz.Zone, len(fz.Upstreams), trust)
	}
	for _, up := range fz.Upstreams {
		state := "ok"
		if up.Quarantined {
			// Checked before Unreachable: a quarantined upstream is never
			// dialled, so any reachability verdict on it is from before the
			// config that quarantined it.
			state = fmt.Sprintf("QUARANTINED (%s)", up.QuarantineReason)
		} else if up.Unreachable {
			state = fmt.Sprintf("UNREACHABLE (%s)", up.LastError)
		} else if up.Queries == 0 {
			state = "untried"
		}
		line := fmt.Sprintf("  %-30s %s, queries %d, failures %d", up.Upstream, state, up.Queries, up.Failures)
		if !up.LastSuccess.IsZero() {
			line += ", last success " + up.LastSuccess.Format(tdns.TimeLayout)
		}
		fmt.Println(line)
	}
}

func runReloadTsigCmd(role string, force, interactive bool) {
	if tsigForceInteractiveConflict(force, interactive) {
		fmt.Println("Error: --force and --interactive are mutually exclusive")
		os.Exit(1)
	}
	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	post := tdns.ConfigPost{Command: "reload-tsig", Force: force}
	if interactive {
		requireInteractiveTTY()
		probe, err := SendConfigCommand(api, tdns.ConfigPost{Command: "reload-tsig"})
		if err != nil && len(probe.TsigConflicts) == 0 {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		if len(probe.TsigConflicts) == 0 {
			if probe.Msg != "" {
				fmt.Println(probe.Msg)
			}
			if reloadTsigWithheld(probe) {
				os.Exit(1)
			}
			return
		}
		reader := bufio.NewReader(os.Stdin)
		var overwrite []string
		for _, name := range probe.TsigConflicts {
			fmt.Printf("Overwrite TSIG key %q with keys.tsig? [y/N] ", name)
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(strings.ToLower(line))
			if line == "y" || line == "yes" {
				overwrite = append(overwrite, name)
			}
		}
		if len(overwrite) == 0 {
			fmt.Println("No keys overwritten.")
			os.Exit(1) // withheld conflicts remain — signal incomplete reconciliation
		}
		post.TsigOverwrite = overwrite
	}

	resp, err := SendConfigCommand(api, post)
	if err != nil {
		if resp.Msg != "" {
			fmt.Println(resp.Msg)
		}
		if reloadTsigWithheld(resp) {
			os.Exit(1)
		}
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	if resp.Error {
		fmt.Printf("Error from %s: %s\n", resp.AppName, resp.ErrorMsg)
		os.Exit(1)
	}
	if resp.Msg != "" {
		fmt.Println(resp.Msg)
	}
	if reloadTsigWithheld(resp) {
		os.Exit(1)
	}
}

// reloadTsigWithheld reports whether the reload-tsig response withheld changes.
func reloadTsigWithheld(resp tdns.ConfigResponse) bool {
	n := len(resp.TsigConflicts) + len(resp.TsigWithheldRemovals)
	if n == 0 {
		return false
	}
	fmt.Fprintf(os.Stderr, "%d TSIG reconcile item(s) withheld (conflicts or referenced removals)\n", n)
	return true
}

// runConfigCmd posts a ConfigPost with the given command and prints the
// response. showVerboseStatus expands the verbose dump used by the
// "status" subcommand.
func runConfigCmd(role, command string, showVerboseStatus, confirm bool) {
	api, err := GetApiClient(role, true)
	if err != nil {
		fmt.Printf("Error creating API client: %v\n", err)
		os.Exit(1)
	}

	resp, err := SendConfigCommand(api, tdns.ConfigPost{Command: command, Confirm: confirm})
	// A daemon-side error is carried structurally on resp (resp.Error, and for a
	// guardrail refusal resp.GuardrailBlocked) *and* returned as a non-nil err by
	// SendConfigCommand. Let the resp.Error block below handle those so the guardrail
	// refusal renders; only bail here on a transport-level error (err set, resp not
	// populated by the daemon).
	if err != nil && !resp.Error {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	if resp.Error {
		if resp.GuardrailBlocked {
			renderReloadGuardrail(resp)
			os.Exit(1)
		}
		fmt.Printf("Error from %s: %s\n", resp.AppName, resp.ErrorMsg)
		os.Exit(1)
	}

	if showVerboseStatus && tdns.Globals.Verbose {
		fmt.Printf("Status for %s:\n", resp.AppName)
		if len(resp.Listeners.Addresses) > 0 {
			fmt.Printf("Listeners: listening on %v\n", resp.Listeners.Addresses)
			fmt.Printf("Listeners: configured transports: %v\n", resp.Listeners.Transports)
			if resp.Do53QueriesRefused {
				fmt.Printf("Listeners: Do53 queries REFUSED (debug-do53-queries-refused): over Do53 only NOTIFY, UPDATE, _dns SVCB and DNSKEY are answered\n")
			}
		} else {
			fmt.Printf("Listeners: not listening on any addresses\n")
		}
		if len(resp.ServerErrors) > 0 {
			fmt.Printf("Active errors:\n")
			for _, e := range resp.ServerErrors {
				fmt.Printf("  [%s/%s] %s\n", e.Category, e.Subtype, e.Message)
			}
		}
		renderImrStatus(resp.Imr)
		renderProcStatus(resp.Proc)
		if len(resp.AuthEngine.Options) > 0 {
			fmt.Printf("AuthEngine: options:\n")
			for opt, val := range resp.AuthEngine.Options {
				optName, ok := tdns.AuthOptionToString[opt]
				if !ok {
					optName = fmt.Sprintf("unknown option %d", opt)
				}
				if val != "" {
					fmt.Printf("  %s: %s\n", optName, val)
				} else {
					fmt.Printf("  %s: (enabled)\n", optName)
				}
			}
		} else if len(resp.AuthEngine.OptionsStrs) > 0 {
			fmt.Printf("AuthEngine: options:\n")
			for _, optStr := range resp.AuthEngine.OptionsStrs {
				fmt.Printf("  %s\n", optStr)
			}
		} else {
			fmt.Printf("AuthEngine: no auth options configured\n")
		}
		if resp.DBFile != "" {
			fmt.Printf("DB: %s\n", resp.DBFile)
		} else {
			fmt.Printf("DB: not configured\n")
		}
		if len(resp.Identities) > 0 {
			fmt.Printf("Identities: %v\n", resp.Identities)
		} else {
			fmt.Printf("Identities: not set\n")
		}

		fmt.Println(apiListeningLine(resp))
		if line := apiSocketStatusLine(resp); line != "" {
			fmt.Println(line)
		}
		// The daemon sends the key redacted (SensitiveString.MarshalJSON), so
		// all there is to say is whether one is set.
		if resp.ApiServer.ApiKey.Value() != "" {
			fmt.Printf("ApiServer: api key is set (not shown)\n")
		} else {
			fmt.Printf("ApiServer: api key is not set\n")
		}
		printAccessStatus(resp.Access)
		printApiTCPNotStarted(resp.ApiTCPNotStarted, resp.ApiTCPNoCert)
		printApiTCPStopped(resp.ApiTCPStopped, resp.ApiTCPStoppedBy, resp.Access != nil)
		printApiTCPFailed(resp.ApiTCPFailed)
	}

	if resp.Msg != "" {
		fmt.Printf("%s\n", resp.Msg)
	}
}

// apiListeningLine is the `config status` line for the TCP API: the
// addresses the daemon says listen now, not the configured ones (a reload
// re-reads those, and an address may have failed to bind). Those that do
// not listen are reported by printApiTCPNotStarted, printApiTCPStopped and
// printApiTCPFailed; with nothing listening and nothing reported, the daemon
// has no TCP API.
func apiListeningLine(resp tdns.ConfigResponse) string {
	switch {
	case len(resp.ApiTCPListening) > 0:
		return fmt.Sprintf("ApiServer: listening on %v", resp.ApiTCPListening)
	case len(resp.ApiTCPNotStarted) > 0 || len(resp.ApiTCPStopped) > 0 || len(resp.ApiTCPFailed) > 0:
		return "ApiServer: NOT listening on any TCP address (see TCP API below)"
	default:
		return "ApiServer: not listening on any addresses"
	}
}

// apiSocketStatusLine is the `config status` line for the daemon's local
// admin socket, or "" when it has none. Both status printers use it (the
// auth/agent one above and imr's). A socket the daemon is configured with
// but could not serve is said to be so, so the line does not read as if the
// socket were there; the Transport/ApiSocket error carries the reason.
func apiSocketStatusLine(resp tdns.ConfigResponse) string {
	sock := resp.ApiServer.Socket
	if sock == "" {
		return ""
	}
	for _, e := range resp.ServerErrors {
		if e.Category == tdns.ErrCatTransport && e.Subtype == tdns.ErrSubApiSocket {
			return fmt.Sprintf("ApiServer: local admin socket %s is configured but NOT served (see the active errors)", sock)
		}
	}
	return fmt.Sprintf("ApiServer: local admin socket %s", sock)
}

// renderReloadGuardrail prints the DNSSEC policy-change guardrail refusal returned
// by a `config reload` / `reload-zones` (server-side gate): the per-zone would-be
// stranding and how to proceed. The server already refused atomically — nothing on
// the running server changed.
func renderReloadGuardrail(resp tdns.ConfigResponse) {
	fmt.Printf("Reload REFUSED by %s — a DNSSEC policy algorithm change would strand %d signed zone(s):\n\n",
		resp.AppName, len(resp.GuardrailZones))
	for _, z := range resp.GuardrailZones {
		for _, r := range z.Roles {
			have := strings.Join(r.HaveAlgs, ", ")
			if have == "" {
				have = "none"
			}
			fmt.Printf("  - %s (policy %q): %s algorithm is now %s, but the zone's active %s key(s) are [%s]\n",
				z.Zone, z.PolicyName, r.Role, r.WantAlg, r.Role, have)
		}
	}
	fmt.Println()
	fmt.Println("The running server was NOT changed — these zones keep serving under their current keys.")
	fmt.Println("The signer has no automatic key-algorithm rollover, so applying this as-is would freeze")
	fmt.Println("their signatures until expiry, then go BOGUS. To proceed, either:")
	fmt.Println("  * roll the key deliberately via the auto-rollover engine, or")
	fmt.Println("  * (test zones) run `tdns-cli auth zone dnssec policy-reset` to drop+regenerate keys, or")
	fmt.Println("  * re-run this command with --confirm to apply the config anyway (the signer will still")
	fmt.Println("    refuse to re-sign until the key is rolled).")
}

func SendConfigCommand(api *tdns.ApiClient, data tdns.ConfigPost) (tdns.ConfigResponse, error) {
	var cr tdns.ConfigResponse
	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	// The caller prints the returned error; printing it here as well showed
	// a daemon's refusal twice.
	status, buf, err := api.Post("/config", bytebuf.Bytes())
	if err != nil {
		// Wrapped, so a caller can tell a socket it may not open (EACCES)
		// or a daemon that is not there (ENOENT) from a refusal.
		return cr, fmt.Errorf("error from api post: %w", err)
	}
	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	err = json.Unmarshal(buf, &cr)
	if err != nil {
		return cr, fmt.Errorf("error from unmarshal: %v", err)
	}

	if cr.Error {
		// Generic: this helper is shared by every role (auth/agent/imr), so it
		// must not name a specific daemon.
		return cr, fmt.Errorf("error from the daemon: %s", cr.ErrorMsg)
	}

	return cr, nil
}

// printApiTCPStopped prints the plaintext TCP listeners an access file
// closed. They stay closed until a restart, also once the access file is
// removed, so this is printed whether the daemon runs a policy or not. by is
// the access file that stopped them, on a line of its own (a path can be
// long); a daemon that does not say gets the text without it.
func printApiTCPStopped(stopped []string, by string, policy bool) {
	if len(stopped) == 0 {
		return
	}
	fmt.Printf("TCP API STOPPED on %s:\n", strings.Join(stopped, ", "))
	switch {
	case policy && by != "":
		fmt.Println("  it was plaintext, and the access file requires TLS:")
		fmt.Printf("    %s\n", by)
		fmt.Println("  restart the daemon with usetls: true (the local socket works)")
	case policy:
		fmt.Println("  it was plaintext, and the access file requires TLS;")
		fmt.Println("  restart the daemon with usetls: true (the local socket works)")
	case by != "":
		fmt.Println("  it was plaintext when the access file came into force:")
		fmt.Printf("    %s\n", by)
		fmt.Println("  no access file is set now, but it stays closed until the daemon")
		fmt.Println("  restarts (the local socket works)")
	default:
		fmt.Println("  it was plaintext when an access file came into force; no access")
		fmt.Println("  file is set now, but it stays closed until the daemon restarts")
		fmt.Println("  (the local socket works)")
	}
}

// printApiTCPNotStarted prints the TCP listeners the daemon did not start
// because it had no API certificate (it could not write its default pair).
// cert is that certificate, on a line of its own (a path can be long); a
// daemon that does not say gets the text without it. They stay off until a
// restart, also once the pair is there.
func printApiTCPNotStarted(addrs []string, cert string) {
	if len(addrs) == 0 {
		return
	}
	fmt.Printf("TCP API NOT STARTED on %s:\n", strings.Join(addrs, ", "))
	if cert != "" {
		fmt.Println("  no API certificate; the daemon could not write its default pair:")
		fmt.Printf("    %s\n", cert)
	} else {
		fmt.Println("  no API certificate; the daemon could not write its default pair")
	}
	fmt.Println("  the daemon's log says why; fix that and restart the daemon")
	fmt.Println("  (the local socket works)")
}

// printApiTCPFailed prints the TCP listeners the daemon could not bind, or
// whose server stopped with an error, each with that error; with one, the
// error alone, as the address is in the line above. They stay off until a
// restart.
func printApiTCPFailed(failed []tdns.ApiTCPFailure) {
	if len(failed) == 0 {
		return
	}
	addrs := make([]string, 0, len(failed))
	for _, f := range failed {
		addrs = append(addrs, f.Address)
	}
	fmt.Printf("TCP API FAILED on %s:\n", strings.Join(addrs, ", "))
	for _, f := range failed {
		if len(failed) > 1 {
			fmt.Printf("  %s: %s\n", f.Address, f.Error)
		} else {
			fmt.Printf("  %s\n", f.Error)
		}
	}
	fmt.Println("  fix that and restart the daemon (the local socket works)")
}

// printAccessStatus prints the network API's access policy as the daemon is
// running it, if it has one.
func printAccessStatus(a *tdns.ApiAccessStatus) {
	if a == nil {
		return
	}
	if a.Error != "" {
		fmt.Printf("Access file: %s CANNOT BE USED, so the TCP API answers 503 (the local socket works): %s\n", a.File, a.Error)
		return
	}
	keyauth := "the API key is accepted (read-write)"
	if !a.KeyAuth {
		keyauth = "the API key is off"
	}
	fmt.Printf("Access file: %s; %s; %d client(s)\n", a.File, keyauth, len(a.Clients))
	for _, c := range a.Clients {
		state := ""
		if c.Disabled {
			state = ", disabled"
		}
		fmt.Printf("   %s (%s%s)\n", c.Name, c.Role, state)
	}
}
