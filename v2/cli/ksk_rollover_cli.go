package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
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
	status, body, err := api.RequestNG("GET", endpoint, nil, true)
	if err != nil {
		cliFatalf("error calling rollover/when: %v", err)
	}
	if status == http.StatusBadRequest {
		// Operationally-expected rejection (no policy, rollover in
		// progress, etc.). Body is the explanation.
		cliFatalf("cannot schedule for zone %s: %s", z, strings.TrimSpace(string(body)))
	}
	if status != http.StatusOK {
		cliFatalf("unexpected status %d from rollover/when: %s", status, string(body))
	}
	var resp tdns.RolloverWhenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		cliFatalf("error parsing rollover/when response: %v", err)
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
	if pol == nil {
		cliFatalf("error: no DNSSEC policy for zone %s (dnssecpolicy in zone config)", z)
	}

	res, err := tdns.ComputeEarliestRollover(kdb, z, pol, time.Now())
	if err != nil {
		row, rerr := tdns.LoadRolloverZoneRow(kdb, z)
		suffix := ""
		if rerr == nil && row != nil && row.RolloverInProgress {
			phaseAt := ""
			if row.RolloverPhaseAt.Valid {
				phaseAt = " " + formatTimeWithDeltaStr(row.RolloverPhaseAt.String)
			}
			suffix = fmt.Sprintf(" (phase=%s%s)", row.RolloverPhase, phaseAt)
		}
		cliFatalf("cannot schedule for zone %s: %v%s", z, err, suffix)
	}

	resp := &tdns.RolloverWhenResponse{
		Zone:     z,
		Earliest: res.Earliest.UTC().Format(time.RFC3339),
		FromIdx:  res.FromIdx,
		ToIdx:    res.ToIdx,
		Gates:    make([]tdns.RolloverWhenGateEntry, 0, len(res.Gates)),
	}
	for _, g := range res.Gates {
		resp.Gates = append(resp.Gates, tdns.RolloverWhenGateEntry{
			Name: g.Name,
			At:   g.At.UTC().Format(time.RFC3339),
		})
	}
	renderRolloverWhen(resp)
}

func renderRolloverWhen(resp *tdns.RolloverWhenResponse) {
	fmt.Printf("zone %s — earliest scheduled rollover\n", resp.Zone)
	fmt.Printf("  earliest          %s\n", formatRolloverTime(resp.Earliest))
	fmt.Printf("  from_active_seq   %d  →  to_active_seq   %d\n", resp.FromIdx, resp.ToIdx)
	if len(resp.Gates) > 0 {
		fmt.Println("  gates:")
		for _, g := range resp.Gates {
			fmt.Printf("    %-20s %s\n", g.Name, formatRolloverTime(g.At))
		}
	}
}

func newAutoRolloverAsapCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "asap",
		Short: "Schedule a manual KSK rollover at the earliest safe moment",
		Long: `Computes ComputeEarliestRollover; on success, persists
manual_rollover_requested_at = now and manual_rollover_earliest = t_earliest
on the zone row. The rollover worker fires AtomicRollover when t_earliest is
reached. Rejects the request if a rollover is already in progress or the
pipeline has no standby SEP key.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli

			kdb, z, pol, err := openKeystoreForCli()
			if err != nil {
				cliFatalf("error: %v", err)
			}
			defer kdb.DB.Close()
			if pol == nil {
				cliFatalf("error: no DNSSEC policy for zone %s (dnssecpolicy in zone config)", z)
			}

			now := time.Now()
			res, err := tdns.ComputeEarliestRollover(kdb, z, pol, now)
			if err != nil {
				cliFatalf("cannot schedule for zone %s: %v", z, err)
			}
			if err := tdns.SetManualRolloverRequest(kdb, z, now, res.Earliest); err != nil {
				cliFatalf("error: persist manual_rollover_*: %v", err)
			}
			fmt.Printf("scheduled manual rollover for zone %s\n", z)
			fmt.Printf("  earliest          %s\n", formatTimeWithDelta(res.Earliest))
			fmt.Printf("  from_active_seq   %d  →  to_active_seq   %d\n", res.FromIdx, res.ToIdx)
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
		Long: `Clears manual_rollover_requested_at and manual_rollover_earliest on the
zone row. Has no effect on rollovers that have already fired or on scheduled
(lifetime-driven) rollovers.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli

			kdb, z, _, err := openKeystoreForCli()
			if err != nil {
				cliFatalf("error: %v", err)
			}
			defer kdb.DB.Close()

			if err := tdns.ClearManualRolloverRequest(kdb, z); err != nil {
				cliFatalf("error: clear manual_rollover_*: %v", err)
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

Use -v / --verbose to show full last_error text and the policy summary.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli
			z := dns.Fqdn(tdns.Globals.Zonename)

			var s *tdns.RolloverStatus
			if offline {
				s = fetchRolloverStatusOffline(z)
			} else {
				s = fetchRolloverStatusOnline(z)
			}
			renderRolloverStatus(s, verbose)
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
	s, err := tdns.ComputeRolloverStatus(kdb, z, pol, time.Now())
	if err != nil {
		cliFatalf("error: %v", err)
	}
	return s
}

// renderRolloverStatus prints a *RolloverStatus per the design spec
// in 2026-04-29-rollover-overhaul.md. Same renderer regardless of
// whether the struct came from the API or from local computation.
func renderRolloverStatus(s *tdns.RolloverStatus, verbose bool) {
	if s == nil {
		return
	}
	// First line: server's wallclock at response time. Reference
	// frame for the relative-time annotations on every other field.
	fmt.Printf("Current time:     %s\n", formatRolloverTimeAbsolute(s.CurrentTime))

	fmt.Printf("KSK rollover state for zone %s:\n", s.Zone)

	headlinePhrase := headlinePhraseFor(s.Headline, s.Phase)
	fmt.Printf("  status            %s — %s\n", s.Headline, headlinePhrase)
	if s.Phase != "" && s.Phase != "idle" {
		fmt.Printf("  phase             %s\n", s.Phase)
	}

	if s.AttemptMax > 0 {
		switch s.Headline {
		case "ACTIVE":
			if s.AttemptIndex > 0 {
				fmt.Printf("  attempts          %d / %d in current group\n", s.AttemptIndex, s.AttemptMax)
			}
		case "SOFTFAIL":
			fmt.Printf("  attempts          initial flurry (%d/%d) failed; in long-term mode\n", s.HardfailCount, s.AttemptMax)
		}
	}

	// Anchor timestamps for ACTIVE attempts.
	if s.LastUpdate != "" {
		fmt.Printf("  last UPDATE       %s\n", formatRolloverTime(s.LastUpdate))
	}
	if s.Policy != nil && s.Policy.DsPublishDelay != "" {
		fmt.Printf("  ds-publish-delay  %s\n", s.Policy.DsPublishDelay)
	}
	if s.ExpectedBy != "" {
		fmt.Printf("  expected by       %s\n", formatRolloverTime(s.ExpectedBy))
	}
	if s.AttemptTimeout != "" {
		fmt.Printf("  attempt timeout   %s\n", formatRolloverTime(s.AttemptTimeout))
	}

	// Softfail block.
	if s.LastSoftfailAt != "" {
		fmt.Printf("  last failure      %s\n", formatRolloverTime(s.LastSoftfailAt))
		if s.LastSoftfailCat != "" {
			fmt.Printf("                    category: %s\n", s.LastSoftfailCat)
		}
		if s.LastSoftfailDetail != "" {
			detail := s.LastSoftfailDetail
			if !verbose && len(detail) > 80 {
				detail = detail[:77] + "..."
			}
			fmt.Printf("                    detail:   %s\n", detail)
		}
	}
	if s.NextPushAt != "" {
		fmt.Printf("  next probe        %s\n", formatRolloverTime(s.NextPushAt))
	}

	// Polling activity.
	if s.LastPoll != "" {
		fmt.Printf("  last poll         %s — DS not yet observed\n", formatRolloverTime(s.LastPoll))
	}
	if s.NextPoll != "" {
		fmt.Printf("  next poll         %s\n", formatRolloverTime(s.NextPoll))
	}

	if s.Hint != "" {
		fmt.Printf("  hint              %s\n", s.Hint)
		if s.Headline == "SOFTFAIL" {
			fmt.Printf("                    use 'auto-rollover unstick --zone %s' to skip the wait and probe now\n", s.Zone)
		}
	}

	if s.LastSuccess != "" {
		fmt.Printf("  last success      %s\n", formatRolloverTime(s.LastSuccess))
	}

	// DS index ranges (diagnostic).
	if s.Submitted != nil {
		fmt.Printf("  DS submitted      [%d, %d]\n", s.Submitted.Low, s.Submitted.High)
	}
	if s.Confirmed != nil {
		fmt.Printf("  DS confirmed      [%d, %d]\n", s.Confirmed.Low, s.Confirmed.High)
	}

	// Per-key tables.
	if len(s.KSKs) > 0 {
		fmt.Println()
		fmt.Println("  KSKs:")
		printRolloverKeyTable(s.KSKs, verbose)
	}
	if len(s.ZSKs) > 0 {
		fmt.Println()
		fmt.Println("  ZSKs:")
		printRolloverKeyTable(s.ZSKs, verbose)
	}

	// Policy summary in verbose mode.
	if verbose && s.Policy != nil {
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

// printRolloverKeyTable renders a list of RolloverKeyEntry as a
// simple aligned table.
func printRolloverKeyTable(keys []tdns.RolloverKeyEntry, verbose bool) {
	for _, k := range keys {
		seq := "-"
		if k.ActiveSeq != nil {
			seq = fmt.Sprintf("%d", *k.ActiveSeq)
		}
		errStr := k.LastRolloverErr
		if !verbose && len(errStr) > 40 {
			errStr = errStr[:37] + "..."
		}
		stateSince := ""
		if k.StateSince != "" {
			stateSince = formatRolloverTime(k.StateSince)
		}
		fmt.Printf("    keyid=%-5d  seq=%-3s  state=%-13s  state_since=%-30s  %s\n",
			k.KeyID, seq, k.State, stateSince, errStr)
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
// "HH:MM:SS UTC (Δ ago)" for past times or
// "HH:MM:SS UTC (in Δ)" for future times. Returns "-" for empty.
func formatRolloverTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	delta := time.Until(t).Truncate(time.Second)
	formatted := t.UTC().Format("15:04:05") + " UTC"
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

// kskFSMSequence describes the multi-ds rollover phase sequence for verbose
// output. Static text since the FSM itself is fixed.
var kskFSMSequence = []struct{ phase, desc string }{
	{"idle", "steady state; rolloverDue checks active_at + ksk.lifetime"},
	{"pending-child-publish", "wait kasp.propagation_delay for new DNSKEY to reach secondaries"},
	{"pending-parent-push", "send DS UPDATE to parent (one tick)"},
	{"pending-parent-observe", "poll parent for DS RRset until match or confirm-timeout"},
	{"pending-child-withdraw", "wait effective_margin for each retired key, then retired→removed"},
}

// estimateNextKSKTransition returns a best-effort string describing when the
// current phase is expected to advance. Returns "" if we can't compute it
// (e.g. phase=idle without a known active_at, or unfamiliar phase).
func estimateNextKSKTransition(kdb *tdns.KeyDB, z string, pol *tdns.DnssecPolicy, row *tdns.RolloverZoneRow) string {
	if pol == nil || row == nil {
		return ""
	}
	switch row.RolloverPhase {
	case "idle":
		if pol.KSK.Lifetime == 0 {
			return "never (ksk.lifetime: 0)"
		}
		// Find the active SEP KSK and use its active_at + ksk.lifetime.
		active, err := tdns.GetDnssecKeysByState(kdb, z, tdns.DnskeyStateActive)
		if err != nil {
			return ""
		}
		for _, k := range active {
			if k.Flags&dns.SEP == 0 {
				continue
			}
			at, err := tdns.RolloverKeyActiveAt(kdb, z, k.KeyTag)
			if err != nil || at == nil {
				continue
			}
			due := at.Add(time.Duration(pol.KSK.Lifetime) * time.Second)
			return fmt.Sprintf("%s — rolloverDue → AtomicRollover", formatTimeWithDelta(due))
		}
		return ""
	case "pending-child-publish":
		// Advances after kasp.propagation_delay from phase_at.
		t, ok := parsePhaseAt(row)
		if !ok {
			return ""
		}
		// kasp.propagation_delay is in the runtime config; we don't have
		// it here. Best we can do: name the trigger.
		return fmt.Sprintf("after kasp.propagation_delay from %s → pending-parent-push", formatTimeWithDelta(t))
	case "pending-parent-push":
		return "next tick → pending-parent-observe (DS UPDATE sent)"
	case "pending-parent-observe":
		if row.ObserveNextPollAt.Valid {
			return fmt.Sprintf("next poll at %s → advance when DS RRset matches at parent",
				formatTimeWithDeltaStr(row.ObserveNextPollAt.String))
		}
		return "advances when DS RRset is observed at parent"
	case "pending-child-withdraw":
		// effective_margin from each retired SEP key's retired_at. Show
		// the soonest expected retired→removed time.
		eff, err := tdns.EffectiveMarginForZone(kdb, z, pol)
		if err != nil {
			return ""
		}
		retired, err := tdns.GetDnssecKeysByState(kdb, z, tdns.DnskeyStateRetired)
		if err != nil {
			return ""
		}
		var soonest time.Time
		for _, k := range retired {
			if k.Flags&dns.SEP == 0 || k.RetiredAt == nil {
				continue
			}
			due := k.RetiredAt.Add(eff)
			if soonest.IsZero() || due.Before(soonest) {
				soonest = due
			}
		}
		if soonest.IsZero() {
			return fmt.Sprintf("(no retired SEP keys with retired_at; effective_margin=%s)", eff)
		}
		return fmt.Sprintf("%s — soonest retired→removed (effective_margin=%s)",
			formatTimeWithDelta(soonest), eff)
	}
	return ""
}

func parsePhaseAt(row *tdns.RolloverZoneRow) (time.Time, bool) {
	if row == nil || !row.RolloverPhaseAt.Valid {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(row.RolloverPhaseAt.String))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// stateSinceFor returns the timestamp at which the given key entered its
// current state, picking the most appropriate column in
// RolloverKeyState/DnssecKeyStore. Returns the zero time if no useful
// timestamp is available.
func stateSinceFor(kdb *tdns.KeyDB, z string, k *tdns.DnssecKeyWithTimestamps) time.Time {
	switch k.State {
	case tdns.DnskeyStatePublished:
		if k.PublishedAt != nil {
			return *k.PublishedAt
		}
	case tdns.DnskeyStateRetired:
		if k.RetiredAt != nil {
			return *k.RetiredAt
		}
	case tdns.DnskeyStateActive:
		at, err := tdns.RolloverKeyActiveAt(kdb, z, k.KeyTag)
		if err == nil && at != nil {
			return *at
		}
	case tdns.DnskeyStateStandby:
		t, err := tdns.RolloverKeyStandbyAt(kdb, z, k.KeyTag)
		if err == nil && t != nil {
			return *t
		}
	case tdns.DnskeyStateDsPublished:
		t, err := tdns.RolloverKeyDsObservedAt(kdb, z, k.KeyTag)
		if err == nil && t != nil {
			return *t
		}
	}
	// Fallback: rollover_state_at (RolloverKeyState row's last-update).
	t, err := tdns.RolloverKeyStateAt(kdb, z, k.KeyTag)
	if err == nil && t != nil {
		return *t
	}
	return time.Time{}
}

// printKSKRolloverStatus prints the KSK section of auto-rollover status:
// rollover-zone-row fields, then a table of SEP keys grouped by state.
func printKSKRolloverStatus(kdb *tdns.KeyDB, z string, pol *tdns.DnssecPolicy, verbose bool) {
	fmt.Printf("KSK rollover state for zone %s:\n", z)
	row, err := tdns.LoadRolloverZoneRow(kdb, z)
	if err != nil {
		fmt.Printf("  (load rollover zone row failed: %v)\n", err)
		return
	}
	if row == nil {
		fmt.Println("  no rollovers ongoing (zone not yet touched by the rollover worker)")
	} else {
		fmt.Printf("  phase             %s\n", row.RolloverPhase)
		fmt.Printf("  in_progress       %v\n", row.RolloverInProgress)
		if row.RolloverPhaseAt.Valid {
			fmt.Printf("  entered_phase     %s\n", formatTimeWithDeltaStr(row.RolloverPhaseAt.String))
		}
		if next := estimateNextKSKTransition(kdb, z, pol, row); next != "" {
			fmt.Printf("  next_transition   %s\n", next)
		}
		if row.ManualRolloverEarliest.Valid {
			fmt.Printf("  manual_requested  %s\n", formatTimeWithDeltaStr(row.ManualRolloverRequestedAt.String))
			fmt.Printf("  manual_earliest   %s\n", formatTimeWithDeltaStr(row.ManualRolloverEarliest.String))
		}
		// DS submitted/confirmed are translated to keyids so the line
		// reconciles with the per-key table below. Values describe the most
		// recent push/observe round — current in idle (those keys' DS RRs
		// are still at the parent), briefly stale in the window between
		// AtomicRollover and the next push fires.
		subKids := keyidsForRange(kdb, z, row.LastSubmittedLow, row.LastSubmittedHigh)
		confKids := keyidsForRange(kdb, z, row.LastConfirmedLow, row.LastConfirmedHigh)
		if subKids != "" || confKids != "" {
			fmt.Printf("  DS range:         submitted to parent: %s confirmed: %s\n",
				orDash(subKids), orDash(confKids))
		}
		if row.ObserveStartedAt.Valid {
			fmt.Printf("  observe_started   %s\n", formatTimeWithDeltaStr(row.ObserveStartedAt.String))
			if row.ObserveNextPollAt.Valid {
				fmt.Printf("  next_poll         %s\n", formatTimeWithDeltaStr(row.ObserveNextPollAt.String))
			}
			if row.ObserveBackoffSecs.Valid {
				fmt.Printf("  observe_backoff   %ds\n", row.ObserveBackoffSecs.Int64)
			}
		}
		if pol != nil {
			maxTTL, err := tdns.LoadZoneSigningMaxTTL(kdb, z)
			if err == nil {
				margin := pol.Clamping.Margin
				eff := max(time.Duration(maxTTL)*time.Second, margin)
				fmt.Printf("  max_observed_ttl  %ds\n", maxTTL)
				fmt.Printf("  effective_margin  %s  (max of clamping.margin=%s and max_observed_ttl)\n", eff, margin)
			}
		}
	}

	if verbose {
		fmt.Println()
		fmt.Println("  phase sequence (multi-ds rollover):")
		for _, p := range kskFSMSequence {
			marker := "  "
			if row != nil && p.phase == row.RolloverPhase {
				marker = "→ "
			}
			fmt.Printf("    %s%-22s  %s\n", marker, p.phase, p.desc)
		}
	}

	// Per-key table.
	type keyRow struct {
		keyid      uint16
		state      string
		seq        int
		stateSince time.Time
		errStr     string
		hasError   bool
	}
	var rows []keyRow
	var removedHidden int
	const removedCap = 3
	states := []string{
		tdns.DnskeyStateCreated,
		tdns.DnskeyStateDsPublished,
		tdns.DnskeyStatePublished,
		tdns.DnskeyStateStandby,
		tdns.DnskeyStateActive,
		tdns.DnskeyStateRetired,
		tdns.DnskeyStateRemoved,
	}
	for _, st := range states {
		keys, err := tdns.GetDnssecKeysByState(kdb, z, st)
		if err != nil {
			fmt.Printf("  (list keys %s failed: %v)\n", st, err)
			return
		}
		stateRows := make([]keyRow, 0, len(keys))
		for i := range keys {
			k := &keys[i]
			if k.Flags&dns.SEP == 0 {
				continue
			}
			seq, _ := tdns.RolloverKeyActiveSeq(kdb, z, k.KeyTag)
			errStr, _ := tdns.LoadLastRolloverError(kdb, z, k.KeyTag)
			stateRows = append(stateRows, keyRow{
				keyid:      k.KeyTag,
				state:      st,
				seq:        seq,
				stateSince: stateSinceFor(kdb, z, k),
				errStr:     errStr,
				hasError:   errStr != "",
			})
		}
		// Within "removed", sort by active_seq desc so the most-recently-
		// retired key is at the top of the removed block; keys without an
		// active_seq (seq < 0, never promoted to active) sink to the bottom.
		// Then cap to removedCap rows so the table doesn't grow unboundedly
		// over many rollover cycles.
		if st == tdns.DnskeyStateRemoved {
			sort.SliceStable(stateRows, func(i, j int) bool {
				si, sj := stateRows[i].seq, stateRows[j].seq
				if (si < 0) != (sj < 0) {
					return si >= 0 // rows with a seq come first
				}
				return si > sj
			})
			if len(stateRows) > removedCap {
				removedHidden = len(stateRows) - removedCap
				stateRows = stateRows[:removedCap]
			}
		}
		rows = append(rows, stateRows...)
	}
	if len(rows) == 0 {
		fmt.Println()
		fmt.Println("  (no KSKs)")
		return
	}
	fmt.Println()
	fmt.Println("  active_seq  keyid    state           published   state_since                last_error")
	fmt.Println("  ----------  -----    -------------   ---------   ------------------------   ----------")
	for _, r := range rows {
		seqStr := "-"
		if r.seq >= 0 {
			seqStr = fmt.Sprintf("%d", r.seq)
		}
		sinceStr := "-"
		if !r.stateSince.IsZero() {
			sinceStr = formatTimeWithDelta(r.stateSince)
		}
		errCol := ""
		if r.hasError {
			errCol = truncate(r.errStr, 40, verbose)
		}
		fmt.Printf("  %-10s  %-5d    %-13s   %-9s   %-24s   %s\n",
			seqStr, r.keyid, r.state, kskPublishedSummary(r.state), sinceStr, errCol)
	}
	if removedHidden > 0 {
		fmt.Printf("  ... %d older removed key(s) not shown\n", removedHidden)
	}
}

// kskPublishedSummary returns a short label describing what's published in
// DNS for a KSK in the given state, derived from the rollover state machine
// (RFC 7583 §3.3.3 / §3.4 of the design doc).
//
//	created       — key generated, not yet pushed anywhere → "none"
//	ds-published  — DS pushed to parent and observed; DNSKEY not yet at apex → "DS"
//	published     — DNSKEY at apex; DS at parent → "DS+DNSKEY"
//	standby       — DNSKEY at apex; DS at parent (idle in pipeline) → "DS+DNSKEY"
//	active        — DNSKEY at apex; DS at parent; signing the zone → "DS+DNSKEY"
//	retired       — DNSKEY at apex; DS still at parent until pending-child-withdraw → "DS+DNSKEY"
//	removed       — DNSKEY removed; DS removed → "none"
func kskPublishedSummary(state string) string {
	switch state {
	case tdns.DnskeyStateCreated, tdns.DnskeyStateRemoved:
		return "none"
	case tdns.DnskeyStateDsPublished:
		return "DS"
	case tdns.DnskeyStatePublished, tdns.DnskeyStateStandby,
		tdns.DnskeyStateActive, tdns.DnskeyStateRetired:
		return "DS+DNSKEY"
	default:
		return "?"
	}
}

// printZSKRolloverStatus prints the ZSK section. Currently informational
// only — the rollover worker doesn't manage ZSKs.
func printZSKRolloverStatus(kdb *tdns.KeyDB, z string, verbose bool) {
	fmt.Printf("ZSK rollover state for zone %s:\n", z)
	fmt.Println("  no rollovers ongoing (automated ZSK rollover not implemented)")

	type keyRow struct {
		keyid       uint16
		state       string
		publishedAt *time.Time
	}
	var rows []keyRow
	states := []string{
		tdns.DnskeyStatePublished,
		tdns.DnskeyStateStandby,
		tdns.DnskeyStateActive,
		tdns.DnskeyStateRetired,
		tdns.DnskeyStateRemoved,
	}
	for _, st := range states {
		keys, err := tdns.GetDnssecKeysByState(kdb, z, st)
		if err != nil {
			fmt.Printf("  (list keys %s failed: %v)\n", st, err)
			return
		}
		for i := range keys {
			k := &keys[i]
			// ZSK = 256, KSK = 257; we want the non-SEP keys here.
			if k.Flags&dns.SEP != 0 {
				continue
			}
			rows = append(rows, keyRow{
				keyid:       k.KeyTag,
				state:       st,
				publishedAt: k.PublishedAt,
			})
		}
	}
	if len(rows) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("  keyid    state           published_at")
	fmt.Println("  -----    -------------   ------------")
	for _, r := range rows {
		pub := "-"
		if r.publishedAt != nil {
			pub = formatTimeWithDelta(*r.publishedAt)
		}
		fmt.Printf("  %-5d    %-13s   %s\n", r.keyid, r.state, pub)
	}
	_ = verbose // reserved for future per-ZSK detail
}

// keyidsForRange formats the keyids whose rollover_index falls in [lo, hi]
// as a comma-separated bracketed list, e.g. "[20655, 26803, 61725]". Returns
// "" when the range is unset or the lookup fails.
func keyidsForRange(kdb *tdns.KeyDB, z string, lo, hi sql.NullInt64) string {
	if !lo.Valid || !hi.Valid {
		return ""
	}
	kids, err := tdns.RolloverKeyidsByIndexRange(kdb, z, lo.Int64, hi.Int64)
	if err != nil || len(kids) == 0 {
		return ""
	}
	parts := make([]string, len(kids))
	for i, k := range kids {
		parts[i] = fmt.Sprintf("%d", k)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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
	c := &cobra.Command{
		Use:   "reset",
		Short: "Clear last_rollover_error for one key (after operator intervention)",
		Long: `Clears the last_rollover_error column on a single key's RolloverKeyState
row. Use after diagnosing and fixing a hard-failed rollover (e.g. parent-agent
DS observation timeout) so the worker can resume normal handling on the next
tick.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli

			if keyid <= 0 || keyid > 0xFFFF {
				cliFatalf("error: --keyid must be in 1..65535, got %d", keyid)
			}
			kdb, z, _, err := openKeystoreForCli()
			if err != nil {
				cliFatalf("error: %v", err)
			}
			defer kdb.DB.Close()

			if err := tdns.ClearLastRolloverError(kdb, z, uint16(keyid)); err != nil {
				cliFatalf("error: clear last_rollover_error: %v", err)
			}
			fmt.Printf("cleared last_rollover_error for zone %s keyid %d\n", z, keyid)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	c.Flags().IntVar(&keyid, "keyid", 0, "Key ID to reset (RFC 4034 keytag)")
	_ = c.MarkFlagRequired("zone")
	_ = c.MarkFlagRequired("keyid")
	return c
}

func newAutoRolloverUnstickCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "unstick",
		Short: "Skip the softfail-delay and probe the parent on the next tick",
		Long: `Clears next_push_at on the zone row so the rollover engine fires a probe
UPDATE on its very next tick instead of waiting out the rest of the
softfail-delay window. The narrow operator override for "I just fixed the
parent and want to retry now."

This is operationally optional. The engine polls the parent continuously
regardless of softfail-delay, so a parent fix is auto-detected within
confirm-poll-max even without 'unstick'. Use 'unstick' only when you know
the fix is in place AND want to skip the wait.

Hardfail_count and last_softfail_* are preserved so status output still
shows the most recent failure context. The counter resets to 0 on the
next successful confirmed observation (which the post-unstick probe will
trigger if the parent is genuinely fixed).

Differs from 'reset' (which clears last_rollover_error for one keyid).`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli

			kdb, z, _, err := openKeystoreForCli()
			if err != nil {
				cliFatalf("error: %v", err)
			}
			defer kdb.DB.Close()

			if err := tdns.UnstickRollover(kdb, z); err != nil {
				cliFatalf("error: unstick: %v", err)
			}
			fmt.Printf("unstuck zone %s — next tick will probe the parent (softfail-delay skipped)\n", z)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
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
