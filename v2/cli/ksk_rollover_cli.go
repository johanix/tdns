package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// cliFatalf prints a message to stderr (so it's visible on the terminal,
// unlike the structured logger which writes to a file) and exits non-zero.
// Use for user-facing CLI errors. Reserve log.Fatal* for places where
// stderr output is undesirable.
func cliFatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	if !strings.HasSuffix(format, "\n") {
		fmt.Fprintln(os.Stderr)
	}
	os.Exit(1)
}

// formatTimeWithDelta formats t as HH:MM:SS (Δ ago) in local time, with a
// two-digit hour even when < 10. Returns "-" for the zero time. Used by
// auto-rollover status output for human-readable timestamps.
func formatTimeWithDelta(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	delta := time.Since(t).Truncate(time.Second)
	suffix := "ago"
	if delta < 0 {
		delta = -delta
		suffix = "ahead"
	}
	return fmt.Sprintf("%02d:%02d:%02d (%s %s)", t.Hour(), t.Minute(), t.Second(), delta, suffix)
}

// injectEstimatedTag rewrites a "HH:MM:SS (Δ ago)" / "HH:MM:SS (Δ ahead)"
// time-with-delta string so the parenthetical reads "(Δ, estimated)".
// Drops the "ahead"/"ago" suffix for projected entries — the
// "estimated" tag is what matters and the column space is at a
// premium. Defensive: if the input doesn't match the expected shape,
// append " (estimated)" instead.
func injectEstimatedTag(timeWithDelta string) string {
	if i := strings.LastIndex(timeWithDelta, " ago)"); i >= 0 {
		return timeWithDelta[:i] + ", estimated)"
	}
	if i := strings.LastIndex(timeWithDelta, " ahead)"); i >= 0 {
		return timeWithDelta[:i] + ", estimated)"
	}
	return timeWithDelta + " (estimated)"
}

// formatTimeWithDeltaStr is the SQL-NullString variant: parses RFC3339 from
// the DB and formats. Returns "-" for empty/invalid values.
func formatTimeWithDeltaStr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s // fall back to raw value
	}
	return formatTimeWithDelta(t)
}

// refuseIfDaemonAlive checks the keystore's daemon-sentinel row and
// terminates the CLI if a live daemon process is detected, unless
// --force is set. Used by --offline writers (reset, unstick) to
// prevent operators from racing the rollover tick with direct DB
// writes when the daemon is actually still running.
func refuseIfDaemonAlive(kdb *tdns.KeyDB, force bool) {
	pid, appname, started, alive := tdns.LiveRolloverDaemon(kdb)
	if !alive {
		return
	}
	name := appname
	if name == "" {
		name = "daemon"
	}
	if force {
		fmt.Fprintf(os.Stderr, "warning: %s (pid %d, started %s) appears to be running; --force overrides the daemon-alive check\n", name, pid, started)
		return
	}
	cliFatalf(`error: %s (pid %d) appears to be running on this keystore.
  started: %s
Refusing --offline write to avoid racing the rollover tick.
Stop the daemon and retry, or pass --force to override (you must ensure
the daemon is genuinely stopped first; --force on a live daemon will
produce non-deterministic state).`, name, pid, started)
}

// truncate trims s to maxLen characters, appending "..." if truncated.
// When verbose is true, returns s unchanged.
func truncate(s string, maxLen int, verbose bool) string {
	if verbose || len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func newKeystoreDnssecPolicyCmd(_ string) *cobra.Command {
	var policyFile string

	validate := &cobra.Command{
		Use:   "validate",
		Short: "Validate a YAML fragment with a top-level dnssecpolicies: block",
		Long: `Reads a YAML file that contains the same dnssecpolicies: structure as tdns-auth
config (policy names as keys, algorithm / ksk / zsk / csk / optional rollover+ttls+clamping).
Runs the same validation as runtime config load. Exits non-zero on any error.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := tdns.ValidateDnssecPoliciesFromFile(policyFile); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			fmt.Println("dnssecpolicies: OK")
		},
	}
	validate.Flags().StringVarP(&policyFile, "file", "f", "", "YAML file path")
	_ = validate.MarkFlagRequired("file")

	policy := &cobra.Command{
		Use:   "policy",
		Short: "DNSSEC policy utilities",
	}
	policy.AddCommand(validate)
	return policy
}

func newKeystoreDnssecDsPushCmd(_ string) *cobra.Command {
	var dryRun bool

	c := &cobra.Command{
		Use:   "ds-push",
		Short: "Compute DS RRset from keystore and push to parent (UPDATE-only in this offline mode)",
		Long: `Loads tdns config (same as other CLI commands using -c), opens the local keystore DB,
and pushes the whole DS RRset to the parent. Requires imrengine in config.

Offline mode: this CLI invocation builds a stub *ZoneData with no rollover policy
attached, so PushDSRRsetForRollover falls through to the legacy single-scheme
UPDATE path (whole-DS replacement, signed with the zone's active SIG(0) key).
The auto / prefer-* / force-* dsync-scheme-preference values are honored only
inside the daemon's rollover engine, where the policy is loaded from
dnssecpolicies. To exercise NOTIFY pushes, run the daemon and let
RolloverAutomatedTick drive the push.

Use --dry-run to print the DS set and the UPDATE without sending.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			ctx := context.Background()
			tdns.Globals.App.Type = tdns.AppTypeCli

			cfg := viper.ConfigFileUsed()
			if cfg == "" {
				cfg = tdns.DefaultCliCfgFile
			}
			if err := Conf.MainInit(ctx, cfg); err != nil {
				log.Fatalf("config init: %v", err)
			}

			ctxIMR, cancelIMR, imr, err := StartImrForCli("")
			if err != nil {
				log.Fatalf("imr: %v", err)
			}
			defer cancelIMR()
			_ = ctxIMR

			dbPath := viper.GetString("db.file")
			if dbPath == "" {
				log.Fatal("db.file not set in config (required for keystore)")
			}
			kdb, err := tdns.NewKeyDB(dbPath, false, nil)
			if err != nil {
				log.Fatalf("keystore: %v", err)
			}
			defer kdb.DB.Close()

			z := dns.Fqdn(tdns.Globals.Zonename)
			zd := &tdns.ZoneData{ZoneName: z}
			// Intentionally leave zd.DnssecPolicy nil. The dispatcher
			// (PushDSRRsetForRollover) gates DSYNC scheme selection on
			// a non-nil policy and falls through to the legacy
			// UPDATE-only path when policy is nil. Attaching the policy
			// here would let an operator running the offline CLI on
			// auto/prefer-notify silently take the NOTIFY path,
			// contradicting the "UPDATE-only offline mode" contract
			// documented above.

			if dryRun {
				dsSet, low, high, idxOK, err := tdns.ComputeTargetDSSetForZone(kdb, z, uint8(dns.SHA256), nil)
				if err != nil {
					log.Fatalf("compute DS: %v", err)
				}
				fmt.Printf("rollover_index range known=%v low=%d high=%d\n", idxOK, low, high)
				for _, rr := range dsSet {
					fmt.Println(rr.String())
				}
				parent, err := imr.ParentZone(z)
				if err != nil {
					log.Fatalf("parent: %v", err)
				}
				msg, err := tdns.BuildChildWholeDSUpdate(dns.Fqdn(parent), z, dsSet)
				if err != nil {
					log.Fatalf("build UPDATE: %v", err)
				}
				fmt.Printf("UPDATE would be sent to parent zone %q:\n%s\n", parent, msg.String())
				return
			}

			deps := tdns.RolloverEngineDeps{
				Conf: &Conf,
				KDB:  kdb,
				Zone: zd,
				Imr:  imr,
				// Policy: nil is deliberate — see comment above where
				// zd is constructed. Forces the dispatcher onto the
				// legacy UPDATE-only path.
			}
			res, err := tdns.PushDSRRsetForRollover(ctx, deps)
			if err != nil {
				log.Fatalf("ds-push: %v", err)
			}
			fmt.Printf("rcode=%s\n", dns.RcodeToString[res.Rcode])
			if len(res.UpdateResult.TargetStatus) > 0 {
				for _, ts := range res.UpdateResult.TargetStatus {
					fmt.Printf("target: %+v\n", ts)
				}
			}
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Child zone (owner of DS RRset)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "Print DS RRset and UPDATE only; do not send")
	_ = c.MarkFlagRequired("zone")
	return c
}

func newKeystoreDnssecQueryParentCmd(_ string) *cobra.Command {
	var parentAgentFlag string
	var once bool

	c := &cobra.Command{
		Use:   "query-parent",
		Short: "Query configured parent-agent for child DS (poll until match or timeout)",
		Long: `Uses rollover.parent-agent from the zone's dnssec policy (addr:port), or --parent-agent.
Queries that address over TCP for the zone's DS RRset and compares to the keystore-derived
expected set (ComputeTargetDSSetForZone, §7.5). Default poll schedule uses policy confirm-* timings,
or 2s / 60s / 1h when those are unset.

--once performs a single query and exits (no backoff loop).`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			ctx := context.Background()
			tdns.Globals.App.Type = tdns.AppTypeCli

			cfg := viper.ConfigFileUsed()
			if cfg == "" {
				cfg = tdns.DefaultCliCfgFile
			}
			if err := Conf.MainInit(ctx, cfg); err != nil {
				log.Fatalf("config init: %v", err)
			}

			dbPath := viper.GetString("db.file")
			if dbPath == "" {
				log.Fatal("db.file not set in config (required for keystore)")
			}
			kdb, err := tdns.NewKeyDB(dbPath, false, nil)
			if err != nil {
				log.Fatalf("keystore: %v", err)
			}
			defer kdb.DB.Close()

			z := dns.Fqdn(tdns.Globals.Zonename)
			pol := dnssecPolicyForZone(&Conf, z)
			if pol == nil {
				log.Fatal("no dnssec policy for this zone (dnssec_policy in zone config)")
			}

			agent := strings.TrimSpace(parentAgentFlag)
			if agent != "" {
				var normErr error
				agent, normErr = tdns.NormalizeParentAgentAddr(agent)
				if normErr != nil {
					log.Fatalf("parent-agent: %v", normErr)
				}
			} else {
				agent = pol.Rollover.ParentAgent
			}
			if agent == "" {
				log.Fatal("parent-agent not set: configure rollover.parent-agent on the dnssec policy or pass --parent-agent host:port")
			}

			expected, _, _, _, err := tdns.ComputeTargetDSSetForZone(kdb, z, uint8(dns.SHA256), pol)
			if err != nil {
				log.Fatalf("compute expected DS: %v", err)
			}
			if len(expected) == 0 {
				log.Fatal("expected DS set is empty (no SEP keys in rollover-related states?)")
			}

			if once {
				obs, err := tdns.QueryParentAgentDS(ctx, z, agent)
				if err != nil {
					log.Fatalf("query: %v", err)
				}
				ok := tdns.ObservedDSSetMatchesExpected(obs, expected)
				fmt.Printf("match=%v (single query to %s)\n", ok, agent)
				return
			}

			iw := pol.Rollover.ConfirmInitialWait
			if iw == 0 {
				iw = 2 * time.Second
			}
			pm := pol.Rollover.ConfirmPollMax
			if pm == 0 {
				pm = 60 * time.Second
			}
			ct := pol.Rollover.ConfirmTimeout
			if ct == 0 {
				ct = time.Hour
			}
			ok, err := tdns.PollParentDSUntilMatch(ctx, z, expected, agent, iw, pm, ct)
			if err != nil {
				log.Fatalf("poll: %v", err)
			}
			fmt.Printf("match=%v (polled parent-agent %s)\n", ok, agent)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Child zone (owner of DS RRset)")
	c.Flags().StringVar(&parentAgentFlag, "parent-agent", "", "Override policy rollover.parent-agent (host:port)")
	c.Flags().BoolVar(&once, "once", false, "Single TCP query; do not poll")
	_ = c.MarkFlagRequired("zone")
	return c
}

func dnssecPolicyForZone(conf *tdns.Config, zname string) *tdns.DnssecPolicy {
	want := dns.Fqdn(zname)
	for i := range conf.Zones {
		zc := &conf.Zones[i]
		if dns.Fqdn(zc.Name) != want {
			continue
		}
		if zc.DnssecPolicy == "" {
			return nil
		}
		if p, ok := conf.Internal.DnssecPolicies[zc.DnssecPolicy]; ok {
			return &p
		}
	}
	return nil
}

// openKeystoreForCli is a small helper used by the auto-rollover commands.
// It loads config, opens the local keystore, and returns the policy for the
// given zone (or nil if the zone has none).
func openKeystoreForCli() (*tdns.KeyDB, string, *tdns.DnssecPolicy, error) {
	cfg := viper.ConfigFileUsed()
	if cfg == "" {
		cfg = tdns.DefaultCliCfgFile
	}
	if err := Conf.MainInit(context.Background(), cfg); err != nil {
		return nil, "", nil, fmt.Errorf("config init: %w", err)
	}
	dbPath := viper.GetString("db.file")
	if dbPath == "" {
		return nil, "", nil, fmt.Errorf("db.file not set in config (required for keystore)")
	}
	kdb, err := tdns.NewKeyDB(dbPath, false, nil)
	if err != nil {
		return nil, "", nil, fmt.Errorf("keystore: %w", err)
	}
	z := dns.Fqdn(tdns.Globals.Zonename)
	pol := dnssecPolicyForZone(&Conf, z)
	return kdb, z, pol, nil
}

func newAutoRolloverWhenCmd() *cobra.Command {
	var offline bool
	c := &cobra.Command{
		Use:   "when",
		Short: "Compute the earliest moment a KSK rollover could safely fire (no state change)",
		Long: `Asks the running daemon to compute ComputeEarliestRollover (§8.5) and
prints the result. Side-effect free; does not request a rollover. Use
'auto-rollover asap' to actually schedule one.

Default mode talks to the daemon's API server (no daemon config needed
on the CLI host). Use --offline to compute locally against the keystore
file when the daemon is down — this requires --config with the daemon's
config file so the CLI can find db.file and the zone's policy.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli
			z := dns.Fqdn(tdns.Globals.Zonename)

			if offline {
				runWhenOffline(z)
				return
			}
			runWhenOnline(z)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	c.Flags().BoolVar(&offline, "offline", false, "Compute locally against keystore file (postmortem use; daemon is down)")
	_ = c.MarkFlagRequired("zone")
	return c
}

// runWhenOnline is the default path: GET /api/v1/rollover/when via
// the configured API client. No daemon config loaded on the CLI host.
func runWhenOnline(z string) {
	api, err := GetApiClient("auth", true)
	if err != nil {
		cliFatalf("error getting API client: %v", err)
	}
	endpoint := "/rollover/when?zone=" + z
	// "when" is observational; the daemon always returns 200 with a
	// structured response (any caveats land in resp.Note). Non-2xx
	// here would mean network-level failure, in which case the API
	// client's dieOnError path is the right thing.
	_, body, err := api.RequestNG("GET", endpoint, nil, true)
	if err != nil {
		cliFatalf("error contacting daemon: %v", err)
	}
	var resp tdns.RolloverWhenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		cliFatalf("error parsing daemon response: %v", err)
	}
	renderRolloverWhen(&resp)
}

// runWhenOffline preserves the legacy direct-DB path for postmortem
// use when the daemon is down.
func runWhenOffline(z string) {
	kdb, _, pol, err := openKeystoreForCli()
	if err != nil {
		cliFatalf("error: %v", err)
	}
	defer kdb.DB.Close()

	resp, err := tdns.ComputeRolloverWhen(kdb, z, pol, time.Now())
	if err != nil {
		cliFatalf("%s", err.Error())
	}
	renderRolloverWhen(resp)
}

// printRolloverPolicyErrors emits the operator-facing header lines for
// hard rollover-engine-blocking conditions (E5/E10/parent-DSYNC).
// Returns true if anything was printed. The "Error:" prefix signals
// that the engine has stopped advancing keys.
func printRolloverPolicyErrors(errs []string) bool {
	if len(errs) == 0 {
		return false
	}
	if len(errs) == 1 {
		fmt.Printf("Error: rollover stopped: %s\n", errs[0])
	} else {
		fmt.Println("Error: rollover stopped:")
		for _, e := range errs {
			fmt.Printf("  - %s\n", e)
		}
	}
	return true
}

// printRolloverPolicyWarnings emits the operator-facing header lines
// for rule-of-thumb concerns (E11). Engine keeps rolling; the
// "Warning:" prefix tells the operator the policy is outside
// recommended params but the rollover is still being attempted.
// Returns true if anything was printed.
func printRolloverPolicyWarnings(warns []string) bool {
	if len(warns) == 0 {
		return false
	}
	if len(warns) == 1 {
		fmt.Printf("Warning: rollover-policy: %s\n", warns[0])
	} else {
		fmt.Println("Warning: rollover-policy:")
		for _, w := range warns {
			fmt.Printf("  - %s\n", w)
		}
	}
	return true
}

// renderRolloverWhen prints the dual-line schedule view. NextScheduled
// is the policy-driven rollover time (active_at + KSK.Lifetime);
// EarliestPossible is the gate-driven earliest the engine would
// permit. They share the same from→to keyids; the difference is the
// time. During in-progress rollovers, both lines reflect projected
// times for the rollover after the current one completes.
func renderRolloverWhen(resp *tdns.RolloverWhenResponse) {
	if printRolloverPolicyErrors(resp.PolicyErrors) {
		// Schedule output is meaningless while the policy is violated.
		// Suppress remaining lines except the bare zone header so the
		// operator still sees which zone they queried.
		fmt.Printf("KSK rollover schedule for zone %s: blocked\n", resp.Zone)
		return
	}
	// Warnings don't block — render schedule below the warning header.
	printRolloverPolicyWarnings(resp.PolicyWarnings)

	// Case 1 / waiting-for-parent: render the structured blocker
	// instead of the schedule view. The schedule has no meaningful
	// EarliestPossible in this state.
	if resp.Status == "waiting-for-parent" && resp.Blocker != nil {
		fmt.Printf("KSK rollover for zone %s: not currently possible.\n", resp.Zone)
		fmt.Printf("  Reason: %s\n", resp.Blocker.Reason)
		if resp.Blocker.Cause != "" {
			fmt.Printf("  Cause:  %s\n", resp.Blocker.Cause)
		}
		if resp.Blocker.Detail != "" {
			fmt.Printf("  Detail: %s\n", resp.Blocker.Detail)
		}
		if resp.FromKeyID != 0 {
			fmt.Printf("  Active keyid: %d\n", resp.FromKeyID)
		}
		fmt.Println("  Time until possible: unknown")
		return
	}

	currentTime := formatRolloverTimeAbsolute(resp.CurrentTime)
	if currentTime == "-" {
		// Fallback when daemon didn't supply CurrentTime (legacy
		// daemon, offline path, etc.) — use local now so the header
		// still has the operator anchor.
		currentTime = time.Now().UTC().Format("15:04:05 UTC (Mon Jan 2 2006)")
	}
	fmt.Printf("KSK rollover schedule for zone %s  Current time: %s\n", resp.Zone, currentTime)
	if resp.InProgress {
		fmt.Println("  (current rollover in progress; times below project the rollover after it completes)")
	}

	keyidPair := ""
	if resp.FromKeyID != 0 || resp.ToKeyID != 0 {
		keyidPair = fmt.Sprintf("active keyid %d --> %d", resp.FromKeyID, resp.ToKeyID)
	}

	// Pad the time-with-delta to the wider of the two time strings.
	// This keeps the keyid columns aligned between the two lines
	// without bloating to a worst-case width that would push the
	// keyid info too far right for the typical case.
	nextStr := whenTimeOrPlaceholder(resp.NextScheduled)
	earliestStr := whenTimeOrPlaceholder(resp.EarliestPossible)
	timeColWidth := len(nextStr)
	if len(earliestStr) > timeColWidth {
		timeColWidth = len(earliestStr)
	}

	fmt.Printf("  next scheduled       %-*s  %s\n", timeColWidth, nextStr, keyidPair)
	earliestLine := fmt.Sprintf("  earliest possible    %-*s  %s", timeColWidth, earliestStr, keyidPair)
	if resp.EarliestPossible != "" && !resp.InProgress {
		earliestLine += "  (request via \"asap\" cmd)"
	}
	fmt.Println(earliestLine)

	if resp.Note != "" {
		fmt.Printf("  note: %s\n", resp.Note)
	}

	if len(resp.Gates) > 0 {
		fmt.Println("  gates (earliest possible):")
		for _, g := range resp.Gates {
			fmt.Printf("    %-20s %s\n", g.Name, formatRolloverTime(g.At))
		}
	}
}

// whenTimeOrPlaceholder formats t for the schedule lines. Empty input
// renders as "(not available)" so the column line still aligns.
func whenTimeOrPlaceholder(t string) string {
	if t == "" {
		return "(not available)"
	}
	return formatRolloverTime(t)
}

func newAutoRolloverAsapCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "asap",
		Short: "Schedule a manual KSK rollover at the earliest safe moment",
		Long: `Asks the daemon to compute ComputeEarliestRollover and persist
manual_rollover_* on the zone row. The rollover worker fires
AtomicRollover when t_earliest is reached. Rejects the request if a
rollover is already in progress or the pipeline has no standby SEP key.

Online-only: scheduling against a stopped daemon is meaningless
(the manual_rollover_* row would never be read).`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli
			z := dns.Fqdn(tdns.Globals.Zonename)

			api, err := GetApiClient("auth", true)
			if err != nil {
				cliFatalf("error getting API client: %v", err)
			}
			status, body, err := api.RequestNG("POST", "/rollover/asap",
				tdns.RolloverAsapRequest{Zone: z}, true)
			if err != nil {
				cliFatalf("error calling rollover/asap: %v", err)
			}
			if status == http.StatusBadRequest {
				cliFatalf("cannot schedule for zone %s: %s", z, strings.TrimSpace(string(body)))
			}
			if status != http.StatusOK {
				cliFatalf("unexpected status %d from rollover/asap: %s", status, strings.TrimSpace(string(body)))
			}
			var resp tdns.RolloverAsapResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				cliFatalf("error parsing rollover/asap response: %v", err)
			}
			fmt.Printf("scheduled manual rollover for zone %s\n", resp.Zone)
			fmt.Printf("  earliest          %s\n", formatRolloverTime(resp.Earliest))
			fmt.Printf("  from active keyid %d to %d\n", resp.FromKeyID, resp.ToKeyID)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	_ = c.MarkFlagRequired("zone")
	return c
}

func newAutoRolloverCancelCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "cancel",
		Short: "Cancel a pending manual KSK rollover request",
		Long: `Asks the daemon to clear manual_rollover_requested_at and
manual_rollover_earliest on the zone row. Has no effect on rollovers
that have already fired or on scheduled (lifetime-driven) rollovers.

Online-only: cancelling against a stopped daemon is meaningless (the
manual_rollover_* row isn't being read by anything).`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli
			z := dns.Fqdn(tdns.Globals.Zonename)

			api, err := GetApiClient("auth", true)
			if err != nil {
				cliFatalf("error getting API client: %v", err)
			}
			status, body, err := api.RequestNG("POST", "/rollover/cancel",
				tdns.RolloverCancelRequest{Zone: z}, true)
			if err != nil {
				cliFatalf("error calling rollover/cancel: %v", err)
			}
			if status != http.StatusOK {
				cliFatalf("unexpected status %d from rollover/cancel: %s", status, strings.TrimSpace(string(body)))
			}
			fmt.Printf("cleared manual rollover request for zone %s\n", z)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	_ = c.MarkFlagRequired("zone")
	return c
}

func newAutoRolloverStatusCmd() *cobra.Command {
	var verbose, offline bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Print rollover state for a zone (KSK and ZSK)",
		Long: `Prints rollover state for the zone with an OK / ACTIVE / SOFTFAIL
headline and per-key tables for KSKs and ZSKs.

Default mode talks to the daemon's API server (no daemon config needed
on the CLI host). Use --offline to render against the keystore file
when the daemon is down — that requires --config with the daemon's
config file so the CLI can find db.file and the zone's policy.

Use --ksk or --zsk to print only the KSK block or only the ZSK block
(the two flags are mutually exclusive). These flags are inherited
from the auto-rollover parent and accepted by every subcommand for
consistency.

The DS range line lists SEP keyids (same numbering as the KSK table and
as DS digest key tags at the parent).

Use -v / --verbose to show rollover_index spans behind the keyid lists
and the policy summary.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli
			z := dns.Fqdn(tdns.Globals.Zonename)

			if autoRolloverFlags.kskOnly && autoRolloverFlags.zskOnly {
				cliFatalf("flags --ksk and --zsk are mutually exclusive")
			}
			showKSK := !autoRolloverFlags.zskOnly
			showZSK := !autoRolloverFlags.kskOnly

			var s *tdns.RolloverStatus
			if offline {
				s = fetchRolloverStatusOffline(z)
			} else {
				s = fetchRolloverStatusOnline(z)
			}
			renderRolloverStatus(s, verbose, showKSK, showZSK)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show full last_error text and policy summary")
	c.Flags().BoolVar(&offline, "offline", false, "Render against keystore file (postmortem use; daemon is down)")
	_ = c.MarkFlagRequired("zone")
	return c
}

// fetchRolloverStatusOnline is the default path: GET
// /api/v1/rollover/status via the configured API client. No daemon
// config loaded on the CLI host.
func fetchRolloverStatusOnline(z string) *tdns.RolloverStatus {
	api, err := GetApiClient("auth", true)
	if err != nil {
		cliFatalf("error getting API client: %v", err)
	}
	endpoint := "/rollover/status?zone=" + z
	status, body, err := api.RequestNG("GET", endpoint, nil, true)
	if err != nil {
		cliFatalf("error calling rollover/status: %v", err)
	}
	if status != http.StatusOK {
		cliFatalf("unexpected status %d from rollover/status: %s", status, strings.TrimSpace(string(body)))
	}
	var s tdns.RolloverStatus
	if err := json.Unmarshal(body, &s); err != nil {
		cliFatalf("error parsing rollover/status response: %v", err)
	}
	return &s
}

// fetchRolloverStatusOffline preserves a direct-DB code path for
// postmortem use. Reuses ComputeRolloverStatus so the renderer sees
// the same struct shape as in online mode — output stays consistent.
func fetchRolloverStatusOffline(z string) *tdns.RolloverStatus {
	kdb, _, pol, err := openKeystoreForCli()
	if err != nil {
		cliFatalf("error: %v", err)
	}
	defer kdb.DB.Close()
	// Offline path: the daemon isn't running, so we can't query its
	// kasp.check_interval. Pass 0, which suppresses the warning —
	// surfacing it requires daemon-runtime context, and the operator
	// running offline-mode is doing postmortem analysis where the
	// warning would be noise.
	// Offline mode: no daemon-runtime kasp config in scope. Pass
	// 0 for both check_interval and propagation_delay; the
	// renderer treats unknown propagation_delay as "skip the
	// ds-published timing math" which is the right thing for
	// postmortem use anyway.
	s, err := tdns.ComputeRolloverStatus(kdb, z, pol, 0, 0, time.Now())
	if err != nil {
		cliFatalf("error: %v", err)
	}
	return s
}

// formatKeyidBracketList renders keyids like "[10773, 41502, 13007]".
func formatKeyidBracketList(ids []uint16) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d", id)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func dashKeyidsBracket(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// renderRolloverStatus prints a *RolloverStatus per the design spec
// in 2026-04-29-rollover-overhaul.md. Same renderer regardless of
// whether the struct came from the API or from local computation.
func renderRolloverStatus(s *tdns.RolloverStatus, verbose, showKSK, showZSK bool) {
	if s == nil {
		return
	}
	headerPrinted := false
	if len(s.PolicyErrors) > 0 {
		printRolloverPolicyErrors(s.PolicyErrors)
		headerPrinted = true
	}
	if len(s.PolicyWarnings) > 0 {
		printRolloverPolicyWarnings(s.PolicyWarnings)
		headerPrinted = true
	}
	if headerPrinted {
		// Status output continues below — operators still want to see
		// per-key state and recent attempts. The header makes the
		// rollover-engine state explicit before the rest of the report.
		fmt.Println()
	}
	currentTime := formatRolloverTimeAbsolute(s.CurrentTime)

	// Track whether the current-time anchor has been printed yet, so
	// it lands on the first section header (KSK if shown, else ZSK)
	// without duplicating across sections.
	currentTimePrinted := false

	if showKSK {
		fmt.Printf("KSK rollover state for zone %s  Current time: %s\n", s.Zone, currentTime)
		currentTimePrinted = true
		printStateTable(s)
		printStateNotes(s, verbose)

		if len(s.KSKs) > 0 {
			fmt.Println()
			fmt.Println("  KSKs:")
			printRolloverKeyTable(s.KSKs, verbose, true)
			if s.HiddenRemovedKskCount > 0 {
				fmt.Printf("  ... %d older removed key(s) not shown\n", s.HiddenRemovedKskCount)
			}
		}
	}

	if showZSK {
		fmt.Println()
		if currentTimePrinted {
			fmt.Printf("ZSK rollover state for zone %s\n", s.Zone)
		} else {
			fmt.Printf("ZSK rollover state for zone %s  Current time: %s\n", s.Zone, currentTime)
			currentTimePrinted = true
		}
		fmt.Println("  no rollovers ongoing (automated ZSK rollover not implemented)")
		if len(s.ZSKs) > 0 {
			fmt.Println()
			printRolloverKeyTable(s.ZSKs, verbose, false)
		}
	}

	// Errors section: aggregate per-key errors across both tables
	// into a single tail-end block. The per-row "last_error" column
	// was wasted space (almost always empty, and when set it's set
	// for one or two keys); a dedicated section reads better and
	// gives the message room to breathe.
	printRolloverKeyErrors(s, showKSK, showZSK, verbose)

	if verbose && s.Policy != nil && showKSK {
		fmt.Println()
		fmt.Println("  policy:")
		fmt.Printf("    name                         %s\n", s.Policy.Name)
		fmt.Printf("    algorithm                    %s\n", s.Policy.Algorithm)
		fmt.Printf("    ksk.lifetime                 %s\n", s.Policy.KskLifetime)
		fmt.Printf("    rollover.ds-publish-delay    %s\n", s.Policy.DsPublishDelay)
		fmt.Printf("    rollover.max-attempts        %d\n", s.Policy.MaxAttemptsBeforeBackoff)
		fmt.Printf("    rollover.softfail-delay      %s\n", s.Policy.SoftfailDelay)
		if s.Policy.ClampingMargin != "" {
			fmt.Printf("    clamping.margin              %s\n", s.Policy.ClampingMargin)
		}
	}
}

// printStateTable renders the principal state info as a two-column
// table (label/value | label/value) via ryanuber/columnize. Left
// column tracks the current attempt; right column tracks history and
// polling activity. Conditional fields collapse cleanly — empty
// cells just leave that row's slot blank.
func printStateTable(s *tdns.RolloverStatus) {
	type kv struct{ label, value string }
	var left, right []kv

	// Left column: this zone's current intent + DS state.
	left = append(left, kv{"status:", s.Headline + " — " + headlinePhraseFor(s.Headline, s.Phase)})
	if s.Phase != "" && s.Phase != "idle" {
		left = append(left, kv{"phase:", s.Phase})
	}
	if s.AttemptMax > 0 {
		switch s.Headline {
		case "ACTIVE":
			if s.AttemptIndex > 0 {
				left = append(left, kv{"attempts:", fmt.Sprintf("%d / %d in current group", s.AttemptIndex, s.AttemptMax)})
			}
		case "SOFTFAIL":
			// child-config:waiting-for-parent intentionally never
			// increments HardfailCount (the engine just waits for
			// the parent to publish DSYNC). Rendering the generic
			// "initial flurry (0/N) failed" line in that state
			// reads as a counter bug; show a parent-blocker-specific
			// summary instead.
			if s.LastSoftfailCat == tdns.SoftfailChildConfigWaitingForParent {
				left = append(left, kv{"attempts:", "blocked by parent (no usable DSYNC scheme advertised)"})
			} else {
				left = append(left, kv{"attempts:", fmt.Sprintf("initial flurry (%d/%d) failed; in long-term mode", s.HardfailCount, s.AttemptMax)})
			}
		}
	}
	if s.LastUpdate != "" {
		v := formatRolloverTime(s.LastUpdate)
		if s.LastAttemptScheme != "" {
			v = fmt.Sprintf("%s via %s", v, s.LastAttemptScheme)
		}
		left = append(left, kv{"last push:", v})
	}
	if s.ExpectedBy != "" {
		left = append(left, kv{"expected by:", formatRolloverTime(s.ExpectedBy)})
	}
	if s.AttemptTimeout != "" {
		left = append(left, kv{"attempt timeout:", formatRolloverTime(s.AttemptTimeout)})
	}
	// Per-scheme lines: DS UPDATE / CDS published / DS observed.
	// Each is rendered as (kidPart [+timePart]). The bracket parts
	// are pre-padded to a common width across the three lines so
	// timestamps align vertically — easier to scan during incidents.
	//
	// State semantics for the bracket part:
	//   - parent advertises the scheme + engine has pushed → keyid list
	//   - parent advertises the scheme + no push yet      → "[no UPDATE sent yet]" / "[no CDS RRset published yet]"
	//   - parent doesn't advertise the scheme             → "Parent has no DSYNC UPDATE/NOTIFY CDS support"
	//   - parent advertisement state unknown              → render legacy line shape
	type schemeRow struct {
		label    string
		kidPart  string
		timePart string
	}
	var schemeRows []schemeRow

	switch {
	case s.ParentAdvertisesUpdateKnown && !s.ParentAdvertisesUpdate:
		schemeRows = append(schemeRows, schemeRow{"DS UPDATE:", "Parent has no DSYNC UPDATE support", ""})
	case s.Submitted != nil:
		// Submitted is the engine's most recent submitted DS RRset.
		// Render the timestamp from LastUpdate (= last_attempt_started_at)
		// regardless of whether the most recent attempt's wire scheme
		// was UPDATE, NOTIFY, or both — the operator's question is
		// "when did we last ask the parent for this set," and the
		// scheme breakdown is shown by LastAttemptScheme on the
		// "last push:" line.
		t := ""
		if s.LastUpdate != "" {
			t = "sent " + formatRolloverTime(s.LastUpdate)
		}
		schemeRows = append(schemeRows, schemeRow{
			"DS UPDATE:",
			dashKeyidsBracket(formatKeyidBracketList(s.SubmittedKeyIDs)),
			t,
		})
	case s.ParentAdvertisesUpdateKnown && s.ParentAdvertisesUpdate:
		// Parent advertises UPDATE but engine hasn't pushed yet.
		schemeRows = append(schemeRows, schemeRow{"DS UPDATE:", "[no UPDATE sent yet]", ""})
	}

	switch {
	case s.ParentAdvertisesNotifyKnown && !s.ParentAdvertisesNotify:
		schemeRows = append(schemeRows, schemeRow{"CDS published:", "Parent has no DSYNC NOTIFY CDS support", ""})
	case len(s.CdsPublishedKeyIDs) > 0:
		t := ""
		if s.CdsPublishedAt != "" {
			t = "sent " + formatRolloverTime(s.CdsPublishedAt)
		}
		schemeRows = append(schemeRows, schemeRow{
			"CDS published:",
			formatKeyidBracketList(s.CdsPublishedKeyIDs),
			t,
		})
	case s.ParentAdvertisesNotifyKnown && s.ParentAdvertisesNotify:
		schemeRows = append(schemeRows, schemeRow{"CDS published:", "[no CDS RRset published yet]", ""})
	}

	// DS observed line. Use ObservedAt (the timestamp of the latest
	// successful poll) as the presence bit, NOT len(ObservedKeyIDs).
	// An empty observed keyid list with a recent ObservedAt means the
	// parent just lost DS — the renderer must not hide that behind
	// stale confirmed data.
	//
	// "seen" rather than "observed" so the verb width matches "sent"
	// on the DS UPDATE / CDS published lines: post-bracket timestamps
	// then align column-for-column, not just keyid-for-keyid.
	switch {
	case s.ObservedAt != "":
		schemeRows = append(schemeRows, schemeRow{
			"DS observed:",
			dashKeyidsBracket(formatKeyidBracketList(s.ObservedKeyIDs)),
			"seen " + formatRolloverTime(s.ObservedAt),
		})
	case s.Confirmed != nil:
		// Pre-existing-row fallback (daemon pre-dates the observe-poll
		// persistence work).
		schemeRows = append(schemeRows, schemeRow{
			"DS observed:",
			dashKeyidsBracket(formatKeyidBracketList(s.ConfirmedKeyIDs)),
			"",
		})
	}

	// Compute max width of the bracket part across the three rows so
	// timestamps align vertically. Apply only when at least one row
	// has a timePart — single-column rows don't need padding.
	maxKidWidth := 0
	hasAnyTime := false
	for _, r := range schemeRows {
		if r.timePart != "" {
			hasAnyTime = true
		}
		if len(r.kidPart) > maxKidWidth {
			maxKidWidth = len(r.kidPart)
		}
	}
	for _, r := range schemeRows {
		v := r.kidPart
		if r.timePart != "" {
			pad := ""
			if hasAnyTime && len(r.kidPart) < maxKidWidth {
				pad = strings.Repeat(" ", maxKidWidth-len(r.kidPart))
			}
			v = fmt.Sprintf("%s%s  %s", r.kidPart, pad, r.timePart)
		}
		left = append(left, kv{r.label, v})
	}

	// Right column: timing config + scheduling. Dropped:
	//   - "last success" — same instant as DS observed <time> when
	//     populated; redundant.
	//   - "last poll"    — same instant as DS observed <time> by
	//     construction (every poll updates last_ds_observed_*).
	if s.Policy != nil && s.Policy.DsPublishDelay != "" {
		right = append(right, kv{"ds-publish-delay:", s.Policy.DsPublishDelay})
	}
	if s.NextPoll != "" {
		right = append(right, kv{"next poll:", formatRolloverTime(s.NextPoll)})
	}
	if s.NextPushAt != "" {
		right = append(right, kv{"next probe:", formatRolloverTime(s.NextPushAt)})
	}
	if s.LastSoftfailAt != "" {
		right = append(right, kv{"last failure:", formatRolloverTime(s.LastSoftfailAt)})
	}

	// Zip into 4-cell rows. Use a non-breaking-ish placeholder for
	// empty cells so columnize's column-width computation still
	// produces aligned output.
	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	rows := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var ll, lv, rl, rv string
		if i < len(left) {
			ll, lv = left[i].label, left[i].value
		}
		if i < len(right) {
			rl, rv = right[i].label, right[i].value
		}
		rows = append(rows, fmt.Sprintf("%s|%s|%s|%s", ll, lv, rl, rv))
	}
	formatted := columnize.SimpleFormat(rows)
	for _, line := range strings.Split(formatted, "\n") {
		fmt.Printf("  %s\n", line)
	}
}

// printStateNotes renders multi-line / full-width annotations below
// the two-column state table: hint, last-failure detail, optional
// rollover_index range in verbose mode, optional unstick suggestion
// in SOFTFAIL.
func printStateNotes(s *tdns.RolloverStatus, verbose bool) {
	if s.Hint != "" {
		fmt.Printf("  hint:             %s\n", s.Hint)
		if s.Headline == "SOFTFAIL" && s.LastSoftfailCat != tdns.SoftfailChildConfigWaitingForParent {
			fmt.Printf("                    use 'auto-rollover unstick --zone %s' to skip the wait and probe now\n", s.Zone)
		}
	}
	for _, w := range s.Warnings {
		fmt.Printf("  WARNING:          %s\n", w)
	}
	if s.LastSoftfailCat != "" || s.LastSoftfailDetail != "" {
		if s.LastSoftfailCat != "" {
			fmt.Printf("  failure category: %s\n", s.LastSoftfailCat)
		}
		if s.LastSoftfailDetail != "" {
			detail := s.LastSoftfailDetail
			if !verbose && len(detail) > 80 {
				detail = detail[:77] + "..."
			}
			fmt.Printf("  failure detail:   %s\n", detail)
		}
	}
	if verbose {
		var parts []string
		if s.Submitted != nil {
			parts = append(parts, fmt.Sprintf("submitted rollover_index [%d, %d]", s.Submitted.Low, s.Submitted.High))
		}
		if s.Confirmed != nil {
			parts = append(parts, fmt.Sprintf("confirmed rollover_index [%d, %d]", s.Confirmed.Low, s.Confirmed.High))
		}
		if len(parts) > 0 {
			fmt.Printf("  ranges:           %s\n", strings.Join(parts, "  "))
		}
	}
}

// printRolloverKeyErrors emits a tail-end "Errors:" section listing
// any per-key error messages, one per line. Skipped entirely when
// no key has an error. Replaces the per-row "last_error" column,
// which was almost always empty and column-truncated when set.
func printRolloverKeyErrors(s *tdns.RolloverStatus, showKSK, showZSK, verbose bool) {
	type entry struct {
		section string
		keyid   uint16
		msg     string
	}
	var rows []entry
	if showKSK {
		for _, k := range s.KSKs {
			if k.LastRolloverErr != "" {
				rows = append(rows, entry{"KSK", k.KeyID, k.LastRolloverErr})
			}
		}
	}
	if showZSK {
		for _, k := range s.ZSKs {
			if k.LastRolloverErr != "" {
				rows = append(rows, entry{"ZSK", k.KeyID, k.LastRolloverErr})
			}
		}
	}
	if len(rows) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("  Errors:")
	for _, r := range rows {
		msg := r.msg
		if !verbose {
			msg = truncate(msg, 100, false)
		}
		fmt.Printf("    %s keyid %d: %s\n", r.section, r.keyid, msg)
	}
}

// printRolloverKeyTable prints KSK or ZSK rows via columnize. Header
// row + separator row + data rows; columnize handles column-width
// alignment so we don't have to maintain padding-format strings.
func printRolloverKeyTable(keys []tdns.RolloverKeyEntry, verbose bool, kskTable bool) {
	if len(keys) == 0 {
		return
	}
	var rows []string
	if kskTable {
		rows = append(rows, "active_seq|keyid|state|published|state_since|next_transition|expected_at")
		for _, k := range keys {
			seqStr := "-"
			if k.ActiveSeq != nil {
				seqStr = fmt.Sprintf("%d", *k.ActiveSeq)
			}
			sinceStr := "-"
			if k.StateSince != "" {
				if t, err := time.Parse(time.RFC3339, k.StateSince); err == nil {
					sinceStr = formatTimeWithDelta(t)
				}
			}
			pub := k.Published
			if pub == "" {
				pub = "?"
			}
			nextCol := k.NextTransition
			if nextCol == "" {
				nextCol = "-"
			}
			expectedCol := "-"
			if k.NextTransitionAt != "" {
				if t, err := time.Parse(time.RFC3339, k.NextTransitionAt); err == nil {
					expectedCol = formatTimeWithDelta(t)
					if k.NextTransitionEstimate {
						// Mark projected times so the operator knows
						// the schedule shifts when prior rollovers
						// fire (asap, parent failure, etc).
						expectedCol = injectEstimatedTag(expectedCol)
					}
				}
			} else if k.NextTransitionNote != "" {
				// No concrete time, but engine has a qualifier.
				expectedCol = k.NextTransitionNote
			}
			// Synthetic "future key" row: render keyid as "-----"
			// and state_since as "-" (state isn't a real database
			// state yet). The next_transition / expected_at carry
			// the operator-facing info: when the engine will
			// generate the next key.
			keyidStr := fmt.Sprintf("%d", k.KeyID)
			if k.IsSynthetic {
				keyidStr = "-----"
				sinceStr = "-"
			}
			rows = append(rows, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
				seqStr, keyidStr, k.State, pub, sinceStr, nextCol, expectedCol))
		}
	} else {
		rows = append(rows, "keyid|state|published_at")
		for _, k := range keys {
			pub := "-"
			if k.Published != "" {
				if t, err := time.Parse(time.RFC3339, k.Published); err == nil {
					pub = formatTimeWithDelta(t)
				}
			}
			rows = append(rows, fmt.Sprintf("%d|%s|%s", k.KeyID, k.State, pub))
		}
	}
	formatted := columnize.SimpleFormat(rows)
	for _, line := range strings.Split(formatted, "\n") {
		fmt.Printf("  %s\n", line)
	}
}

// headlinePhraseFor returns the phrase appended after the headline
// word to give the operator a human-readable summary of the state.
func headlinePhraseFor(headline, phase string) string {
	switch headline {
	case "OK":
		return "idle, in sync with parent"
	case "SOFTFAIL":
		return "in long-term retry mode"
	case "ACTIVE":
		switch phase {
		case "pending-parent-push":
			return "pushing DS to parent"
		case "pending-parent-observe":
			return "observing parent for DS publication"
		case "pending-child-publish":
			return "waiting for propagation to child secondaries"
		case "pending-child-withdraw":
			return "waiting for retired keys to expire"
		default:
			return "in flight"
		}
	}
	return ""
}

// formatRolloverTime renders an RFC3339 timestamp as
// "HH:MM:SS UTC (Δ ago/in Δ)" for times on today's UTC date, or
// "Mon Jan 2 HH:MM:SS UTC (...)" when the date differs from today.
// Returns "-" for empty input. The date prefix avoids the "08:57
// today? yesterday? next week?" ambiguity for far-out times.
func formatRolloverTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	now := time.Now().UTC()
	tu := t.UTC()
	delta := time.Until(t).Truncate(time.Second)

	var formatted string
	if tu.Year() == now.Year() && tu.YearDay() == now.YearDay() {
		formatted = tu.Format("15:04:05") + " UTC"
	} else {
		formatted = tu.Format("Mon Jan 2 15:04:05") + " UTC"
	}

	switch {
	case delta == 0:
		return fmt.Sprintf("%s (now)", formatted)
	case delta > 0:
		return fmt.Sprintf("%s (in %s)", formatted, delta)
	default:
		return fmt.Sprintf("%s (%s ago)", formatted, -delta)
	}
}

// formatRolloverTimeAbsolute is like formatRolloverTime but adds the
// date for the always-first "Current time" line — gives the operator
// a full reference-frame anchor when reading the rest of the output.
func formatRolloverTimeAbsolute(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format("15:04:05 UTC (Mon Jan 2 2006)")
}

// printCSKRolloverStatus prints the CSK section. Currently informational
// only — automated CSK rollover is not implemented and CSK mode shares the
// SEP flag with KSK so individual keys are not distinguishable here without
// policy-mode context.
func printCSKRolloverStatus(kdb *tdns.KeyDB, z string, verbose bool) {
	fmt.Printf("CSK rollover state for zone %s:\n", z)
	fmt.Println("  no rollovers ongoing (automated CSK rollover not implemented)")
	_ = kdb
	_ = z
	_ = verbose
}

func newAutoRolloverResetCmd() *cobra.Command {
	var keyid int
	var offline, force bool
	c := &cobra.Command{
		Use:   "reset",
		Short: "Clear last_rollover_error for one key (after operator intervention)",
		Long: `Asks the daemon to clear the last_rollover_error column on a single
key's RolloverKeyState row. Use after diagnosing and fixing a
hard-failed rollover so status output isn't misleading.

Default mode talks to the daemon's API server. Use --offline to write
directly to the keystore file when the daemon is down (postmortem
use). The CLI checks the daemon-sentinel row in the keystore and
refuses to run --offline if it sees a live daemon process; pass
--force to override (you must ensure the daemon is genuinely
stopped first).`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli
			z := dns.Fqdn(tdns.Globals.Zonename)

			if keyid <= 0 || keyid > 0xFFFF {
				cliFatalf("error: --keyid must be in 1..65535, got %d", keyid)
			}

			if offline {
				kdb, _, _, err := openKeystoreForCli()
				if err != nil {
					cliFatalf("error: %v", err)
				}
				defer kdb.DB.Close()
				refuseIfDaemonAlive(kdb, force)
				if err := tdns.ClearLastRolloverError(kdb, z, uint16(keyid)); err != nil {
					cliFatalf("error: clear last_rollover_error: %v", err)
				}
				fmt.Printf("cleared last_rollover_error for zone %s keyid %d (offline)\n", z, keyid)
				return
			}

			api, err := GetApiClient("auth", true)
			if err != nil {
				cliFatalf("error getting API client: %v", err)
			}
			status, body, err := api.RequestNG("POST", "/rollover/reset",
				tdns.RolloverResetRequest{Zone: z, KeyID: uint16(keyid)}, true)
			if err != nil {
				cliFatalf("error calling rollover/reset: %v", err)
			}
			if status == http.StatusBadRequest {
				cliFatalf("rollover/reset rejected for zone %s keyid %d: %s", z, keyid, strings.TrimSpace(string(body)))
			}
			if status != http.StatusOK {
				cliFatalf("unexpected status %d from rollover/reset: %s", status, strings.TrimSpace(string(body)))
			}
			fmt.Printf("cleared last_rollover_error for zone %s keyid %d\n", z, keyid)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	c.Flags().IntVar(&keyid, "keyid", 0, "Key ID to reset (RFC 4034 keytag)")
	c.Flags().BoolVar(&offline, "offline", false, "Write directly to keystore file (postmortem use; daemon is down)")
	c.Flags().BoolVar(&force, "force", false, "With --offline: override the daemon-alive check")
	_ = c.MarkFlagRequired("zone")
	_ = c.MarkFlagRequired("keyid")
	return c
}

func newAutoRolloverUnstickCmd() *cobra.Command {
	var offline, force bool
	c := &cobra.Command{
		Use:   "unstick",
		Short: "Skip the softfail-delay and probe the parent on the next tick",
		Long: `Asks the daemon to clear next_push_at on the zone row so the
rollover engine fires a probe UPDATE on its very next tick instead of
waiting out the rest of the softfail-delay window. Operator override
for "I just fixed the parent and want to retry now."

Operationally optional: the engine polls the parent continuously
regardless of softfail-delay, so a parent fix is auto-detected within
confirm-poll-max even without 'unstick'. Use only to skip the wait.

Default mode talks to the daemon's API server. Use --offline to write
directly to the keystore file when the daemon is down (postmortem
use). The CLI checks the daemon sentinel via refuseIfDaemonAlive
and refuses to run if a live daemon is detected; --force overrides
the check for cases where the sentinel is stale.

Hardfail_count and last_softfail_* are preserved so status output
still shows the most recent failure context. The counter resets to 0
on the next successful confirmed observation.

Differs from 'reset' (which clears last_rollover_error for one keyid).`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli
			z := dns.Fqdn(tdns.Globals.Zonename)

			if offline {
				kdb, _, _, err := openKeystoreForCli()
				if err != nil {
					cliFatalf("error: %v", err)
				}
				defer kdb.DB.Close()
				refuseIfDaemonAlive(kdb, force)
				if err := tdns.UnstickRollover(kdb, z); err != nil {
					cliFatalf("error: unstick: %v", err)
				}
				fmt.Printf("unstuck zone %s (offline) — next tick will probe the parent (softfail-delay skipped)\n", z)
				return
			}

			api, err := GetApiClient("auth", true)
			if err != nil {
				cliFatalf("error getting API client: %v", err)
			}
			status, body, err := api.RequestNG("POST", "/rollover/unstick",
				tdns.RolloverUnstickRequest{Zone: z}, true)
			if err != nil {
				cliFatalf("error calling rollover/unstick: %v", err)
			}
			if status != http.StatusOK {
				cliFatalf("unexpected status %d from rollover/unstick: %s", status, strings.TrimSpace(string(body)))
			}
			fmt.Printf("unstuck zone %s — next tick will probe the parent (softfail-delay skipped)\n", z)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	c.Flags().BoolVar(&offline, "offline", false, "Write directly to keystore file (postmortem use; daemon is down)")
	c.Flags().BoolVar(&force, "force", false, "With --offline: override the daemon-alive check")
	_ = c.MarkFlagRequired("zone")
	return c
}

// autoRolloverFlags holds the --ksk / --zsk filter flags so they can
// be registered as persistent flags on the auto-rollover parent and
// inherited by all subcommands. Only `status` and `when` use them
// today; others accept the flags as no-ops so an operator can copy a
// command line between subcommands without "unknown flag" errors.
var autoRolloverFlags struct {
	kskOnly bool
	zskOnly bool
}

// newAutoRolloverCmd returns the parent command holding the auto-rollover
// subcommands. Sits alongside the legacy `rollover` (manual swap via API)
// rather than replacing it.
func newAutoRolloverCmd(_ string) *cobra.Command {
	c := &cobra.Command{
		Use:   "auto-rollover",
		Short: "Manage and inspect automated KSK rollover (scheduled + manual-ASAP)",
		Long: `Subcommands operate on local keystore state for a zone:

  when      — compute the earliest safe rollover moment (no state change)
  asap      — schedule a manual rollover at that earliest moment
  cancel    — clear a pending manual rollover request
  status    — print phase + per-key state for the zone
  reset     — clear last_rollover_error on one key after operator action
  unstick   — skip the softfail-delay and probe the parent on the next tick
  validate  — re-parse policy from YAML and report which §4 invariants pass/fail`,
	}
	// Persistent --ksk / --zsk filter flags inherited by every
	// subcommand. Most subcommands ignore them; status and when use
	// them to suppress KSK or ZSK rendering.
	c.PersistentFlags().BoolVar(&autoRolloverFlags.kskOnly, "ksk", false,
		"Render only the KSK section (status / when); ignored by other subcommands")
	c.PersistentFlags().BoolVar(&autoRolloverFlags.zskOnly, "zsk", false,
		"Render only the ZSK section (status / when); ignored by other subcommands")
	c.AddCommand(
		newAutoRolloverWhenCmd(),
		newAutoRolloverAsapCmd(),
		newAutoRolloverCancelCmd(),
		newAutoRolloverStatusCmd(),
		newAutoRolloverResetCmd(),
		newAutoRolloverUnstickCmd(),
		newAutoRolloverValidateCmd(),
	)
	return c
}
