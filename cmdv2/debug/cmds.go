/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/johanix/tdns/v2/debug"
)

var (
	targetName string
	dnsServer  string
	zoneName   string
	baseZone   string
	testId     string

	genConfig      bool
	outDir         string
	publishCadence string
	reportJson     bool
	rmArtifacts    bool
)

// ---- probe ----------------------------------------------------------------

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Probe a target's capabilities (mgmt API endpoints/commands + plain DNS)",
	Long: `Probes the target once and prints the capability matrix that would gate a
test run: mgmt-API reachability (the endpoint walker), command-level support
for the optional actors (zone bump, zone resign-zone, debug zone-txlog —
probed side-effect-free against a zone that cannot exist), and plain-DNS
reachability. Works against tdns and non-tdns servers alike.`,
	Run: func(cmd *cobra.Command, args []string) {
		rep := debug.NewReport(appName+" "+appVersion, "probe")
		m := debug.ProbeApi(cmd.Context(), targetName, apiClientFor(targetName))
		if dnsServer != "" {
			debug.ProbeDns(cmd.Context(), m, dnsServer, zoneName)
		}
		rep.Capabilities = m
		if reportJson {
			_ = rep.RenderJSON(os.Stdout)
		} else {
			fmt.Print(m.Render())
		}
	},
}

// ---- test churn -----------------------------------------------------------

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run (or provision) a test scenario",
}

var testChurnCmd = &cobra.Command{
	Use:   "churn",
	Short: "Slow-churn correctness test: updates vs txlog vs published zone",
	Long: `The snapshot-correctness live gate (design doc §10.1). With
--generate-config it only provisions: allocates a test identity, generates
the SIG(0) keypair locally, and emits the zone file + config snippet the
operator installs on the target. The run stage arrives with M2.`,
	Run: func(cmd *cobra.Command, args []string) {
		st, err := debug.LoadState(statePath)
		if err != nil {
			log.Fatalf("state: %v", err)
		}

		if genConfig {
			prov, err := debug.GenerateChurnConfig(st, debug.ChurnProvisionInput{
				BaseZone:       baseZone,
				DnsServer:      dnsServer,
				Target:         targetName,
				PublishCadence: publishCadence,
				OutDir:         outDir,
			})
			if err != nil {
				log.Fatalf("generate-config: %v", err)
			}
			if err := st.Save(statePath); err != nil {
				log.Fatalf("state save: %v", err)
			}
			rec := prov.Record
			fmt.Printf("Provisioned %s: zone %s\n", rec.Id, rec.Zone)
			fmt.Printf("  SIG(0) key : %s (%s, private: %s)\n", rec.Sig0KeyName, rec.Sig0KeyFile, rec.Sig0PrivFile)
			fmt.Printf("  zone file  : %s\n", prov.ZoneFile)
			fmt.Printf("  cfg snippet: %s\n", prov.SnippetFile)
			fmt.Printf("\nOperator to-do:\n")
			for i, s := range prov.Todo {
				fmt.Printf("  %d. %s\n", i+1, s)
			}
			return
		}

		if testId == "" && zoneName == "" {
			log.Fatal("either --generate-config, --test <id>, or --zone <zone> is required")
		}
		// The run engine (actors + ledger + checkers) is milestone M2.
		fmt.Fprintln(os.Stderr, "test churn run engine arrives with M2 (design doc §14); only --generate-config is available in M1")
		os.Exit(debug.ExitSetup)
	},
}

// ---- list-tests / cleanup ---------------------------------------------------

var listTestsCmd = &cobra.Command{
	Use:   "list-tests",
	Short: "List known test identities from the state file",
	Run: func(cmd *cobra.Command, args []string) {
		st, err := debug.LoadState(statePath)
		if err != nil {
			log.Fatalf("state: %v", err)
		}
		if len(st.Tests) == 0 {
			fmt.Println("no tests recorded")
			return
		}
		for _, id := range sortedIds(st) {
			rec := st.Tests[id]
			status := "active"
			if rec.Cleaned {
				status = "cleaned"
			}
			last := "never"
			if n := len(rec.History); n > 0 {
				last = fmt.Sprintf("%s %s", rec.History[n-1].Stage, rec.History[n-1].Time.Format("2006-01-02 15:04"))
			}
			fmt.Printf("%-9s %-6s %-8s zone %-40s last: %s\n", id, rec.Kind, status, rec.Zone, last)
		}
	},
}

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up a test's artifacts and print the operator's removal list",
	Long: `Removes local artifacts (with --rm) and marks the test cleaned in the
state file. Idempotent. API-side cleanup (keystore/truststore removal of
auto-installed keys) arrives with M3; until then the server-side steps are
printed for the operator.`,
	Run: func(cmd *cobra.Command, args []string) {
		if testId == "" {
			log.Fatal("--test <id> is required")
		}
		st, err := debug.LoadState(statePath)
		if err != nil {
			log.Fatalf("state: %v", err)
		}
		rec, err := st.Get(testId)
		if err != nil {
			log.Fatal(err)
		}
		if rmArtifacts && rec.ArtifactDir != "" {
			// Only ever remove the tool's own artifact directory.
			if strings.Contains(rec.ArtifactDir, "tdns-debug-") {
				if err := os.RemoveAll(rec.ArtifactDir); err != nil {
					log.Printf("removing %s: %v", rec.ArtifactDir, err)
				} else {
					fmt.Printf("removed local artifacts: %s\n", rec.ArtifactDir)
				}
			} else {
				log.Printf("refusing to remove %q (not a tdns-debug artifact dir)", rec.ArtifactDir)
			}
		}
		fmt.Printf("Operator removal list for %s (zone %s):\n", rec.Id, rec.Zone)
		fmt.Printf("  1. remove the zone declaration for %s from the server config\n", rec.Zone)
		fmt.Printf("  2. remove the zone file for %s from the server\n", rec.Zone)
		fmt.Printf("  3. untrust the SIG(0) key %s (truststore)\n", rec.Sig0KeyName)
		fmt.Printf("  4. reload the server\n")
		rec.Cleaned = true
		rec.AddStage("cleaned", "local artifacts handled; server-side steps printed")
		if err := st.Save(statePath); err != nil {
			log.Fatalf("state save: %v", err)
		}
	},
}

func sortedIds(st *debug.State) []string {
	ids := make([]string, 0, len(st.Tests))
	for id := range st.Tests {
		ids = append(ids, id)
	}
	// test IDs are zero-padded, so lexicographic == numeric
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if ids[j] < ids[i] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	return ids
}

func init() {
	probeCmd.Flags().StringVar(&targetName, "target", "", "apiservers entry name for the mgmt API")
	probeCmd.Flags().StringVar(&dnsServer, "dns", "", "DNS server addr:port to probe")
	probeCmd.Flags().StringVarP(&zoneName, "zone", "z", "", "zone for the DNS probe")
	probeCmd.Flags().BoolVar(&reportJson, "json", false, "JSON report")

	testChurnCmd.Flags().BoolVar(&genConfig, "generate-config", false, "provision only: emit zone/config/keys, do not run")
	testChurnCmd.Flags().StringVar(&baseZone, "base-zone", "", "parent zone under which the test zone is invented")
	testChurnCmd.Flags().StringVar(&targetName, "target", "", "apiservers entry name for the mgmt API")
	testChurnCmd.Flags().StringVar(&dnsServer, "dns", "", "DNS server addr:port (also used as ns glue)")
	testChurnCmd.Flags().StringVar(&outDir, "out", "", "artifact directory (default ./tdns-debug-<id>)")
	testChurnCmd.Flags().StringVar(&publishCadence, "publishcadence", "", "publish-cadence for the emitted config (default 20s)")
	testChurnCmd.Flags().StringVar(&testId, "test", "", "test identity from a prior --generate-config")
	testChurnCmd.Flags().StringVarP(&zoneName, "zone", "z", "", "operator-provided zone (no provisioning)")
	testCmd.AddCommand(testChurnCmd)

	cleanupCmd.Flags().StringVar(&testId, "test", "", "test identity to clean up")
	cleanupCmd.Flags().BoolVar(&rmArtifacts, "rm", false, "also remove the local artifact directory")
}
