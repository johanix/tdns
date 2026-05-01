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
		Short: "Compute DS RRset from keystore and push whole RRset to parent via SIG(0) UPDATE",
		Long: `Loads tdns config (same as other CLI commands using -c), opens the local keystore DB,
resolves parent + DSYNC UPDATE target, builds a whole-DS replacement UPDATE, signs with the
zone's active SIG(0) key, and sends it. Requires imrengine in config.

Use --dry-run to print the DS set and UPDATE without sending.`,
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
			zd.DnssecPolicy = dnssecPolicyForZone(&Conf, z)

			if dryRun {
				dsSet, low, high, idxOK, err := tdns.ComputeTargetDSSetForZone(kdb, z, uint8(dns.SHA256))
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

			res, err := tdns.PushWholeDSRRset(ctx, zd, kdb, imr)
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

			expected, _, _, _, err := tdns.ComputeTargetDSSetForZone(kdb, z, uint8(dns.SHA256))
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

// renderRolloverWhen prints the dual-line schedule view. NextScheduled
// is the policy-driven rollover time (active_at + KSK.Lifetime);
// EarliestPossible is the gate-driven earliest the engine would
// permit. They share the same from→to keyids; the difference is the
// time. During in-progress rollovers, both lines reflect projected
// times for the rollover after the current one completes.
func renderRolloverWhen(resp *tdns.RolloverWhenResponse) {
	header := fmt.Sprintf("zone %s — rollover schedule", resp.Zone)
	if resp.InProgress {
		header += "  (current rollover in progress; times below project the rollover after it completes)"
	}
	fmt.Println(header)

	keyidPair := ""
	if resp.FromKeyID != 0 || resp.ToKeyID != 0 {
		keyidPair = fmt.Sprintf("  from active keyid %d to %d", resp.FromKeyID, resp.ToKeyID)
	}

	fmt.Printf("  next scheduled       %s%s\n", whenTimeOrPlaceholder(resp.NextScheduled), keyidPair)
	fmt.Printf("  earliest possible    %s%s\n", whenTimeOrPlaceholder(resp.EarliestPossible), keyidPair)

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
	var verbose, offline, kskOnly, zskOnly bool
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
(the two flags are mutually exclusive).

The DS range line lists SEP keyids (same numbering as the KSK table and
as DS digest key tags at the parent).

Use -v / --verbose to show rollover_index spans behind the keyid lists
and the policy summary.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli
			z := dns.Fqdn(tdns.Globals.Zonename)

			if kskOnly && zskOnly {
				cliFatalf("flags --ksk and --zsk are mutually exclusive")
			}
			showKSK := !zskOnly
			showZSK := !kskOnly

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
	c.Flags().BoolVar(&kskOnly, "ksk", false, "Print only the KSK rollover section (omit ZSK)")
	c.Flags().BoolVar(&zskOnly, "zsk", false, "Print only the ZSK rollover section (omit KSK)")
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
	s, err := tdns.ComputeRolloverStatus(kdb, z, pol, time.Now())
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
	fmt.Printf("Current time:     %s\n", formatRolloverTimeAbsolute(s.CurrentTime))

	if showKSK {
		fmt.Printf("KSK rollover state for zone %s:\n", s.Zone)
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
		fmt.Printf("ZSK rollover state for zone %s:\n", s.Zone)
		fmt.Println("  no rollovers ongoing (automated ZSK rollover not implemented)")
		if len(s.ZSKs) > 0 {
			fmt.Println()
			printRolloverKeyTable(s.ZSKs, verbose, false)
		}
	}

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
			left = append(left, kv{"attempts:", fmt.Sprintf("initial flurry (%d/%d) failed; in long-term mode", s.HardfailCount, s.AttemptMax)})
		}
	}
	if s.LastUpdate != "" {
		left = append(left, kv{"last UPDATE:", formatRolloverTime(s.LastUpdate)})
	}
	if s.ExpectedBy != "" {
		left = append(left, kv{"expected by:", formatRolloverTime(s.ExpectedBy)})
	}
	if s.AttemptTimeout != "" {
		left = append(left, kv{"attempt timeout:", formatRolloverTime(s.AttemptTimeout)})
	}
	if s.Submitted != nil {
		left = append(left, kv{"DS submitted:", dashKeyidsBracket(formatKeyidBracketList(s.SubmittedKeyIDs))})
	}
	if s.Confirmed != nil {
		left = append(left, kv{"DS confirmed:", dashKeyidsBracket(formatKeyidBracketList(s.ConfirmedKeyIDs))})
	}

	// Right column: timing config + history & polling.
	if s.Policy != nil && s.Policy.DsPublishDelay != "" {
		right = append(right, kv{"ds-publish-delay:", s.Policy.DsPublishDelay})
	}
	if s.LastSuccess != "" {
		right = append(right, kv{"last success:", formatRolloverTime(s.LastSuccess)})
	}
	if s.LastPoll != "" {
		right = append(right, kv{"last poll:", formatRolloverTime(s.LastPoll)})
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
		if s.Headline == "SOFTFAIL" {
			fmt.Printf("                    use 'auto-rollover unstick --zone %s' to skip the wait and probe now\n", s.Zone)
		}
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

// printRolloverKeyTable prints KSK or ZSK rows via columnize. Header
// row + separator row + data rows; columnize handles column-width
// alignment so we don't have to maintain padding-format strings.
func printRolloverKeyTable(keys []tdns.RolloverKeyEntry, verbose bool, kskTable bool) {
	if len(keys) == 0 {
		return
	}
	var rows []string
	if kskTable {
		rows = append(rows, "active_seq|keyid|state|published|state_since|last_error")
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
			errCol := ""
			if k.LastRolloverErr != "" {
				errCol = truncate(k.LastRolloverErr, 40, verbose)
			}
			pub := k.Published
			if pub == "" {
				pub = "?"
			}
			rows = append(rows, fmt.Sprintf("%s|%d|%s|%s|%s|%s",
				seqStr, k.KeyID, k.State, pub, sinceStr, errCol))
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
		return formatted
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
use; the operator is responsible for ensuring the daemon is genuinely
stopped — there is no lockfile guard yet).

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

// newAutoRolloverCmd returns the parent command holding the auto-rollover
// subcommands. Sits alongside the legacy `rollover` (manual swap via API)
// rather than replacing it.
func newAutoRolloverCmd(_ string) *cobra.Command {
	c := &cobra.Command{
		Use:   "auto-rollover",
		Short: "Manage and inspect automated KSK rollover (scheduled + manual-ASAP)",
		Long: `Subcommands operate on local keystore state for a zone:

  when     — compute the earliest safe rollover moment (no state change)
  asap     — schedule a manual rollover at that earliest moment
  cancel   — clear a pending manual rollover request
  status   — print phase + per-key state for the zone
  reset    — clear last_rollover_error on one key after operator action
  unstick  — skip the softfail-delay and probe the parent on the next tick`,
	}
	c.AddCommand(
		newAutoRolloverWhenCmd(),
		newAutoRolloverAsapCmd(),
		newAutoRolloverCancelCmd(),
		newAutoRolloverStatusCmd(),
		newAutoRolloverResetCmd(),
		newAutoRolloverUnstickCmd(),
	)
	return c
}
