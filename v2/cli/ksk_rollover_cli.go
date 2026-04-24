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
