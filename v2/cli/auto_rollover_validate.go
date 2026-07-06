/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	tdns "github.com/johanix/tdns/v2"
)

// newAutoRolloverValidateCmd returns the `auto-rollover validate`
// subcommand. Re-parses the daemon's main config YAML (or an
// explicitly-supplied file) and runs every §4 cache-flush invariant
// check against the dnssecpolicy attached to the named zone, with
// PASS/FAIL/WARN output and operator-actionable suggestions.
//
// Online mode (default): asks the daemon for its config + db file
// paths and the zone's policy name via GET /api/v1/config/paths,
// then reads the YAML directly. Lets the operator validate a
// candidate change by editing the daemon's config and running this
// command before reload.
//
// Offline mode (--serverconfig <path>): skips the daemon entirely
// and reads the supplied YAML. Useful for pre-deploy checks or when
// the daemon is down.
func newAutoRolloverValidateCmd() *cobra.Command {
	var (
		serverConfig string
		parentDSTTL  string
		policyName   string
	)
	c := &cobra.Command{
		Use:   "validate",
		Short: "Validate a zone's rollover policy against §4 cache-flush invariants",
		Long: `Re-parses the YAML config the daemon is running and runs every §4
cache-flush invariant check (E5, E10, E11) against the dnssecpolicy
attached to the named zone. Reports PASS / FAIL / WARN per invariant
with operator-actionable suggestions.

Online (default): contacts the daemon for its config-file path and the
zone's active policy name, then reads the YAML directly. Useful for
checking a candidate change before reload.

Offline (--serverconfig PATH): skips the daemon and reads PATH. The
zone's policy must be either supplied via --policy or inferable from
the YAML's zones: block (when --zone matches a configured zone).

DS_TTL handling: the runtime engine uses the parent's observed DS
RRset TTL. validate doesn't have that observation, so it uses the
ttls.parent-ds policy override if set, OR --parent-ds-ttl <duration> if
supplied. Without either, E10/E11 are skipped (and the report says
so).`,
		Run: func(cmd *cobra.Command, args []string) {
			PrepArgs(cmd, "zonename")
			tdns.Globals.App.Type = tdns.AppTypeCli
			z := dns.Fqdn(tdns.Globals.Zonename)

			cfgPath := serverConfig
			polName := policyName
			if cfgPath == "" {
				// Online: ask the daemon for the config-file path
				// and (best-effort) the zone's policy name. The
				// daemon's policy name takes precedence over an
				// inferred-from-YAML lookup; explicit --policy still
				// overrides both.
				api, err := GetApiClient("auth", true)
				if err != nil {
					cliFatalf("error getting API client: %v", err)
				}
				_, body, err := api.RequestNG("GET", "/config/paths?zone="+z, nil, true)
				if err != nil {
					cliFatalf("error contacting daemon: %v", err)
				}
				var resp tdns.ConfigPathsResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					cliFatalf("error parsing /config/paths: %v", err)
				}
				cfgPath = resp.ConfigFile
				if cfgPath == "" {
					cliFatalf("daemon did not report a config-file path")
				}
				if polName == "" {
					polName = resp.PolicyName
				}
			}

			// loadPolicyFromYAMLFile will infer the policy name from
			// the zones: block when polName is empty (offline mode
			// without --policy). Errors out cleanly if no mapping
			// exists.
			pol, resolvedPol, err := loadPolicyFromYAMLFile(cfgPath, z, polName)
			if err != nil {
				cliFatalf("%v", err)
			}
			polName = resolvedPol

			var dsTTL time.Duration
			var dsTTLSrc string
			switch {
			case parentDSTTL != "":
				d, err := time.ParseDuration(parentDSTTL)
				if err != nil {
					cliFatalf("invalid --parent-ds-ttl: %v", err)
				}
				if d <= 0 {
					cliFatalf("invalid --parent-ds-ttl: must be > 0 (got %s)", d)
				}
				dsTTL = d
				dsTTLSrc = fmt.Sprintf("--parent-ds-ttl %s", parentDSTTL)
			case pol.TTLS.ParentDS > 0:
				dsTTL = time.Duration(pol.TTLS.ParentDS) * time.Second
				dsTTLSrc = fmt.Sprintf("ttls.parent-ds = %s (policy override)", dsTTL)
			default:
				dsTTLSrc = "(unknown — no ttls.parent-ds in policy and no --parent-ds-ttl supplied; E10/E11 skipped)"
			}

			renderValidateReport(cfgPath, z, polName, pol, dsTTL, dsTTLSrc)
		},
	}
	c.Flags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "Zone")
	c.Flags().StringVar(&serverConfig, "serverconfig", "", "Read this YAML file instead of asking the daemon (offline)")
	c.Flags().StringVar(&policyName, "policy", "", "Override the dnssecpolicy name to validate (offline mode only)")
	c.Flags().StringVar(&parentDSTTL, "parent-ds-ttl", "", "Hypothetical parent DS RRset TTL (e.g. 1h) for E10/E11; overrides ttls.parent-ds")
	_ = c.MarkFlagRequired("zone")
	return c
}

// minimalConfigForValidate is the subset of the daemon YAML the
// validate command needs. Reuses tdns.DnssecPolicyConf and the
// zone→policy mapping so the offline path can infer the policy
// from the zone when --policy isn't supplied.
type minimalConfigForValidate struct {
	Dnssec struct {
		Policies map[string]tdns.DnssecPolicyConf `yaml:"policies"`
	} `yaml:"dnssec"`
	Zones []minimalZoneEntry `yaml:"zones"`
}

// minimalZoneEntry mirrors just the fields of tdns.ZoneConf that the
// validate command reads. Independent declaration so a new field on
// ZoneConf doesn't change the validate parse surface unexpectedly.
type minimalZoneEntry struct {
	Name         string `yaml:"name"`
	DnssecPolicy string `yaml:"dnssecpolicy"`
}

// inferPolicyForZone looks up the dnssecpolicy attached to the named
// zone in raw.Zones. Returns "" if the zone isn't listed or has no
// policy. Comparison is case-insensitive on the FQDN form.
func inferPolicyForZone(raw *minimalConfigForValidate, zone string) string {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	for _, z := range raw.Zones {
		if strings.ToLower(strings.TrimSuffix(z.Name, ".")) == zone {
			return z.DnssecPolicy
		}
	}
	return ""
}

// loadPolicyFromYAMLFile parses cfgPath, resolves the policy name
// (preferring the explicit name if non-empty, otherwise inferring
// from the zone→policy mapping in zones:), and returns the parsed
// runtime DnssecPolicy. Returns the resolved policy name as the
// second return so the caller can render it.
func loadPolicyFromYAMLFile(path, zone, policyName string) (*tdns.DnssecPolicy, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", path, err)
	}
	var raw minimalConfigForValidate
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", path, err)
	}
	resolved := policyName
	if resolved == "" {
		resolved = inferPolicyForZone(&raw, zone)
	}
	if resolved == "" {
		return nil, "", fmt.Errorf("zone %s has no dnssecpolicy in %s and --policy was not supplied", zone, path)
	}
	pc, ok := raw.Dnssec.Policies[resolved]
	if !ok {
		known := make([]string, 0, len(raw.Dnssec.Policies))
		for n := range raw.Dnssec.Policies {
			known = append(known, n)
		}
		return nil, "", fmt.Errorf("dnssec.policies.%s not found in %s (have: %s)",
			resolved, path, strings.Join(known, ", "))
	}
	pc.Name = resolved
	// Quiet variant suppresses the daemon-style logger calls inside
	// FinishDnssecPolicy; structured warnings are rendered by the
	// validate report via tdns.CollectDnssecPolicyCouplingWarnings.
	out, err := tdns.ParseDnssecPolicyConfQuiet(resolved, &pc)
	if err != nil {
		return nil, "", fmt.Errorf("parse policy: %w", err)
	}
	return out, resolved, nil
}

func renderValidateReport(cfgPath, zone, policyName string, pol *tdns.DnssecPolicy, dsTTL time.Duration, dsTTLSrc string) {
	fmt.Printf("Zone:    %s\n", zone)
	fmt.Printf("Policy:  %s  (from %s)\n", policyName, cfgPath)
	fmt.Printf("Method:  %s, num-ds: %d, ksk.lifetime: %s\n",
		rolloverMethodString(pol.Rollover.Method),
		pol.Rollover.NumDS,
		(time.Duration(pol.KSK.Lifetime) * time.Second).String())
	fmt.Printf("SigValidity: default=%s dnskey=%s ds=%s\n",
		(time.Duration(pol.SigValidity.Default) * time.Second).String(),
		(time.Duration(pol.SigValidity.DNSKEY) * time.Second).String(),
		(time.Duration(pol.SigValidity.DS) * time.Second).String())
	fmt.Printf("Clamping: enabled=%t margin=%s\n", pol.Clamping.Enabled, pol.Clamping.Margin)
	fmt.Printf("TTLs:    dnskey=%ss max_served=%ss parent-ds(override)=%ss child-ds(fallback)=%ss\n",
		fmt.Sprintf("%d", pol.TTLS.DNSKEY),
		fmt.Sprintf("%d", pol.TTLS.MaxServed),
		fmt.Sprintf("%d", pol.TTLS.ParentDS),
		fmt.Sprintf("%d", pol.TTLS.DS))
	fmt.Printf("Cadence: ds-publish-delay=%s scheme-pref=%s parent-cds-poll-estimate=%s standby-time=%s\n",
		pol.Rollover.DsPublishDelay,
		pol.Rollover.DsyncSchemePreference,
		pol.Rollover.ParentCdsPollEstimate,
		pol.Rollover.StandbyTime)
	fmt.Printf("DS TTL for validation: %s\n", dsTTLSrc)
	fmt.Println()

	var failed, warned int

	// Rule-of-thumb coupling concerns (rapid-rollover patterns,
	// sig-validity vs lifetime, clamping-margin floor). These aren't
	// §4 cache-flush invariants but warrant operator attention.
	couplingWarnings := tdns.CollectDnssecPolicyCouplingWarnings(pol, nil)
	if len(couplingWarnings) > 0 {
		fmt.Println("Policy coupling warnings:")
		for _, w := range couplingWarnings {
			fmt.Printf("  WARN  %s\n", w)
			warned++
		}
		fmt.Println()
	}

	fmt.Println("Cache-flush invariants:")

	// E5
	r := tdns.CheckE5(pol)
	switch {
	case !r.Failed():
		fmt.Println("  E5  retirement_period sizing       PASS")
	default:
		fmt.Printf("  E5  retirement_period sizing       FAIL  %s\n", r.Message)
		fmt.Printf("                                            Suggestion: %s\n", r.Suggestion)
		failed++
	}

	if dsTTL == 0 {
		fmt.Println("  E10 cache-flush vs cadence         SKIP  (DS TTL unknown)")
		fmt.Println("  E11 production headroom            SKIP  (DS TTL unknown)")
	} else {
		// E10
		r := tdns.CheckE10(pol, dsTTL)
		switch {
		case !r.Failed():
			fmt.Println("  E10 cache-flush vs cadence         PASS")
		default:
			fmt.Printf("  E10 cache-flush vs cadence         FAIL  %s\n", r.Message)
			fmt.Printf("                                            Suggestion: %s\n", r.Suggestion)
			failed++
		}

		// E11
		r = tdns.CheckE11(pol, dsTTL)
		switch {
		case !r.Failed():
			fmt.Println("  E11 production headroom            PASS")
		default:
			fmt.Printf("  E11 production headroom            WARN  %s\n", r.Message)
			fmt.Printf("                                            Suggestion: %s\n", r.Suggestion)
			warned++
		}
	}

	fmt.Println()
	switch {
	case failed > 0:
		fmt.Printf("Result: %d ERROR, %d WARNING — automated rollovers will not proceed safely.\n", failed, warned)
		os.Exit(1)
	case warned > 0:
		fmt.Printf("Result: %d ERROR, %d WARNING — engine will proceed with reduced safety margin.\n", failed, warned)
	default:
		fmt.Println("Result: all invariants pass.")
	}
}

func rolloverMethodString(m tdns.RolloverMethod) string {
	switch m {
	case tdns.RolloverMethodNone:
		return "none"
	case tdns.RolloverMethodMultiDS:
		return "multi-ds"
	case tdns.RolloverMethodDoubleSignature:
		return "double-signature"
	}
	return fmt.Sprintf("unknown(%d)", m)
}

// _ keep http import alive when no other CLI subcommand below uses it
var _ = http.StatusOK
