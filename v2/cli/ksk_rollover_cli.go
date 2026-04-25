package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
	c := &cobra.Command{
		Use:   "when",
		Short: "Compute the earliest moment a KSK rollover could safely fire (no state change)",
		Long: `Reads the local keystore and dnssec policy for the zone, computes
ComputeEarliestRollover (§8.5), and prints the result. Side-effect free; does
not request a rollover. Use 'auto-rollover asap' to actually schedule one.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli

			kdb, z, pol, err := openKeystoreForCli()
			if err != nil {
				log.Fatal(err)
			}
			defer kdb.DB.Close()
			if pol == nil {
				log.Fatal("no dnssec policy for this zone (dnssec_policy in zone config)")
			}

			res, err := tdns.ComputeEarliestRollover(kdb, z, pol, time.Now())
			if err != nil {
				log.Fatalf("compute earliest: %v", err)
			}
			fmt.Printf("zone=%s\n", z)
			fmt.Printf("earliest=%s (in %s)\n", res.Earliest.Format(time.RFC3339), time.Until(res.Earliest).Truncate(time.Second))
			fmt.Printf("from_index=%d  to_index=%d\n", res.FromIdx, res.ToIdx)
			fmt.Println("gates:")
			for _, g := range res.Gates {
				fmt.Printf("  %-20s %s\n", g.Name, g.At.Format(time.RFC3339))
			}
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	_ = c.MarkFlagRequired("zone")
	return c
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
				log.Fatal(err)
			}
			defer kdb.DB.Close()
			if pol == nil {
				log.Fatal("no dnssec policy for this zone (dnssec_policy in zone config)")
			}

			now := time.Now()
			res, err := tdns.ComputeEarliestRollover(kdb, z, pol, now)
			if err != nil {
				log.Fatalf("cannot schedule: %v", err)
			}
			if err := tdns.SetManualRolloverRequest(kdb, z, now, res.Earliest); err != nil {
				log.Fatalf("persist manual_rollover_*: %v", err)
			}
			fmt.Printf("scheduled manual rollover for zone %s\n", z)
			fmt.Printf("  earliest=%s (in %s)\n", res.Earliest.Format(time.RFC3339), time.Until(res.Earliest).Truncate(time.Second))
			fmt.Printf("  from_index=%d  to_index=%d\n", res.FromIdx, res.ToIdx)
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
				log.Fatal(err)
			}
			defer kdb.DB.Close()

			if err := tdns.ClearManualRolloverRequest(kdb, z); err != nil {
				log.Fatalf("clear manual_rollover_*: %v", err)
			}
			fmt.Printf("cleared manual rollover request for zone %s\n", z)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	_ = c.MarkFlagRequired("zone")
	return c
}

func newAutoRolloverStatusCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "status",
		Short: "Print KSK rollover state for a zone",
		Long: `Prints the rollover phase, manual_rollover_* schedule (if any), the
observe-poll backoff state (if any), and per-key state / rollover_index /
last_rollover_error for every SEP key under rollover management.`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli

			kdb, z, _, err := openKeystoreForCli()
			if err != nil {
				log.Fatal(err)
			}
			defer kdb.DB.Close()

			row, err := tdns.LoadRolloverZoneRow(kdb, z)
			if err != nil {
				log.Fatalf("load rollover zone row: %v", err)
			}
			fmt.Printf("zone=%s\n", z)
			if row == nil {
				fmt.Println("  (no RolloverZoneState row — zone has not been touched by the rollover worker)")
			} else {
				fmt.Printf("  phase=%s  in_progress=%v\n", row.RolloverPhase, row.RolloverInProgress)
				if row.RolloverPhaseAt.Valid {
					fmt.Printf("  phase_at=%s\n", row.RolloverPhaseAt.String)
				}
				if row.ManualRolloverEarliest.Valid {
					fmt.Printf("  manual_requested_at=%s  manual_earliest=%s\n",
						row.ManualRolloverRequestedAt.String, row.ManualRolloverEarliest.String)
				}
				if row.LastSubmittedLow.Valid && row.LastSubmittedHigh.Valid {
					fmt.Printf("  last_submitted_index=[%d, %d]\n", row.LastSubmittedLow.Int64, row.LastSubmittedHigh.Int64)
				}
				if row.LastConfirmedLow.Valid && row.LastConfirmedHigh.Valid {
					fmt.Printf("  last_confirmed_index=[%d, %d]\n", row.LastConfirmedLow.Int64, row.LastConfirmedHigh.Int64)
				}
				if row.ObserveStartedAt.Valid {
					fmt.Printf("  observe_started_at=%s", row.ObserveStartedAt.String)
					if row.ObserveNextPollAt.Valid {
						fmt.Printf("  next_poll_at=%s", row.ObserveNextPollAt.String)
					}
					if row.ObserveBackoffSecs.Valid {
						fmt.Printf("  backoff=%ds", row.ObserveBackoffSecs.Int64)
					}
					fmt.Println()
				}
			}
			fmt.Println("keys:")
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
					log.Fatalf("list keys (%s): %v", st, err)
				}
				for i := range keys {
					k := &keys[i]
					if k.Flags&dns.SEP == 0 {
						continue
					}
					ri, riOK, _ := tdns.RolloverIndexForKey(kdb, z, k.KeyTag)
					riStr := "-"
					if riOK {
						riStr = fmt.Sprintf("%d", ri)
					}
					errStr, _ := tdns.LoadLastRolloverError(kdb, z, k.KeyTag)
					line := fmt.Sprintf("  keyid=%-5d state=%-13s rollover_index=%s", k.KeyTag, st, riStr)
					if errStr != "" {
						line += fmt.Sprintf("  last_error=%q", errStr)
					}
					fmt.Println(line)
				}
			}
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	_ = c.MarkFlagRequired("zone")
	return c
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
				log.Fatalf("--keyid must be in 1..65535, got %d", keyid)
			}
			kdb, z, _, err := openKeystoreForCli()
			if err != nil {
				log.Fatal(err)
			}
			defer kdb.DB.Close()

			if err := tdns.ClearLastRolloverError(kdb, z, uint16(keyid)); err != nil {
				log.Fatalf("clear last_rollover_error: %v", err)
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

// newAutoRolloverCmd returns the parent command holding the five Phase 4C
// subcommands. Sits alongside the legacy `rollover` (manual swap via API)
// rather than replacing it.
func newAutoRolloverCmd(_ string) *cobra.Command {
	c := &cobra.Command{
		Use:   "auto-rollover",
		Short: "Manage and inspect automated KSK rollover (scheduled + manual-ASAP)",
		Long: `Subcommands operate on local keystore state for a zone:

  when    — compute the earliest safe rollover moment (no state change)
  asap    — schedule a manual rollover at that earliest moment
  cancel  — clear a pending manual rollover request
  status  — print phase + per-key state for the zone
  reset   — clear last_rollover_error on one key after operator action`,
	}
	c.AddCommand(
		newAutoRolloverWhenCmd(),
		newAutoRolloverAsapCmd(),
		newAutoRolloverCancelCmd(),
		newAutoRolloverStatusCmd(),
		newAutoRolloverResetCmd(),
	)
	return c
}
