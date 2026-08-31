/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// NewConfigCmd returns a fresh "config" command tree bound to the given
// role. Each attachment point gets its own *cobra.Command.
func NewConfigCmd(role string) *cobra.Command {
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
	fmt.Printf("IMR: %s\n", primed)
	if len(st.StubZones) > 0 {
		fmt.Printf("IMR: stub zones: %s\n", strings.Join(st.StubZones, ", "))
	}
	for _, fz := range st.ForwardZones {
		printForwardZoneStatus(fz, "IMR: ")
	}
}

// printForwardZoneStatus renders one forward zone's reachability block.
// Shared by renderImrStatus (config status) and `imr forward status`.
func printForwardZoneStatus(fz tdns.ImrForwardZoneStatus, prefix string) {
	trust := ""
	if fz.TrustAD {
		trust = ", trust-ad"
	}
	fmt.Printf("%sforward zone %s (%d upstream(s)%s):\n", prefix, fz.Zone, len(fz.Upstreams), trust)
	for _, up := range fz.Upstreams {
		state := "ok"
		if up.Unreachable {
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
			fmt.Printf("DnsEngine: listening on %v\n", resp.Listeners.Addresses)
			fmt.Printf("DnsEngine: configured transports: %v\n", resp.Listeners.Transports)
		} else {
			fmt.Printf("DnsEngine: not listening on any addresses\n")
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
			fmt.Printf("DnsEngine: auth options:\n")
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
			fmt.Printf("DnsEngine: auth options:\n")
			for _, optStr := range resp.AuthEngine.OptionsStrs {
				fmt.Printf("  %s\n", optStr)
			}
		} else {
			fmt.Printf("DnsEngine: no auth options configured\n")
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

		if len(resp.ApiServer.Addresses) > 0 {
			fmt.Printf("ApiServer: listening on %v\n", resp.ApiServer.Addresses)
		} else {
			fmt.Printf("ApiServer: not listening on any addresses\n")
		}
		if resp.ApiServer.ApiKey.Value() != "" {
			ak := resp.ApiServer.ApiKey.Value()
			// Reveal 3 chars at each end only when the key is long
			// enough that the reveal doesn't expose the whole secret
			// (>= 8 chars). Shorter keys are fully masked.
			if len(ak) >= 8 {
				fmt.Printf("ApiServer: api key (%d characters): %s***%s\n", len(ak), ak[:3], ak[len(ak)-3:])
			} else {
				fmt.Printf("ApiServer: api key (%d characters): ***\n", len(ak))
			}
		} else {
			fmt.Printf("ApiServer: api key is not set\n")
		}
	}

	if resp.Msg != "" {
		fmt.Printf("%s\n", resp.Msg)
	}
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

	status, buf, err := api.Post("/config", bytebuf.Bytes())
	if err != nil {
		log.Println("Error from Api Post:", err)
		return cr, fmt.Errorf("error from api post: %v", err)
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
