/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
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

	updateCadence string
	axfrCadence   string
	durationStr   string
	deltaStr      string
	qps           int
	seed          int64

	// test reload: dedicated cadence/duration vars (distinct defaults from
	// churn's, so a shared var would bleed the wrong default into churn).
	reloadCadence      string
	reloadAxfrCadence  string
	reloadQueryCadence string
	reloadDuration     string
	zoneSize           int
	algorithm          string

	// test policy-reload: the DNSSEC policy-reload no-re-sign/backfill test (A2).
	policyReloadPhase  string
	policyReloadReload bool
	policyReloadZones  string
	policyReloadTol    int
	policyReloadSnap   string
	policyReloadReady  string

	// perf qps: adaptive max-QPS finder (query path only).
	perfUDP         bool
	perfTCP         bool
	perfTarget      string
	perfInitialQPS  int
	perfThreshold   int
	perfMaxQPS      int
	perfDuration    string
	perfTimeout     string
	perfMaxDropRate float64
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
operator installs on the target. With --test <id> it runs the churn: signed
updates vs concurrent AXFR/query observations, checked against the ledger.`,
	Run: func(cmd *cobra.Command, args []string) {
		st, err := debug.LoadState(effectiveStatePath())
		if err != nil {
			log.Fatalf("state: %v", err)
		}

		if genConfig {
			prov, err := debug.GenerateChurnConfig(st, debug.ChurnProvisionInput{
				BaseZone:       baseZone,
				DnsServer:      dnsServer,
				Target:         targetName,
				PublishCadence: publishCadence,
				ConfigDir:      configDir,
				OutDir:         outDir,
			})
			if err != nil {
				log.Fatalf("generate-config: %v", err)
			}
			if err := st.Save(effectiveStatePath()); err != nil {
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

		if testId == "" {
			log.Fatal("--test <id> is required to run (provision first with --generate-config); operator-provided --zone runs land in a later slice")
		}
		rec, err := st.Get(testId)
		if err != nil {
			log.Fatal(err)
		}
		runChurn(cmd.Context(), st, rec)
	},
}

// runChurn resolves a provisioned test into a ChurnConfig and executes it.
func runChurn(ctx context.Context, st *debug.State, rec *debug.TestRecord) {
	server := dnsServer
	if server == "" {
		server = rec.DnsServer
	}
	if server == "" {
		log.Fatal("no DNS server: pass --dns or re-provision with --dns")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	cfg := debug.ChurnConfig{
		Zone:          rec.Zone,
		ChurnKeyName:  rec.Sig0KeyName,
		DnsServer:     server,
		KeyFile:       rec.Sig0KeyFile,
		PrivFile:      rec.Sig0PrivFile,
		UpdateCadence: mustDur(updateCadence, "updatecadence"),
		AxfrCadence:   mustDur(axfrCadence, "axfrcadence"),
		QueryQPS:      qps,
		Duration:      mustDur(durationStr, "duration"),
		Delta:         mustDur(deltaStr, "delta"),
		Seed:          seed,
		Tool:          appName + " " + appVersion,
		TestId:        rec.Id,
	}

	rep, err := debug.RunChurn(ctx, cfg)
	if err != nil {
		log.Printf("churn setup error: %v", err)
		os.Exit(debug.ExitSetup)
	}
	rec.AddStage("ran", fmt.Sprintf("%d violation(s), %d ops accepted", len(rep.Violations), rep.Stats["ops.accepted"]))
	// Persist the "ran" stage so list-tests reflects it (AddStage only mutates
	// the in-memory record). Must happen before os.Exit below, which never
	// returns. A save failure is non-fatal: the run itself succeeded.
	if err := st.Save(effectiveStatePath()); err != nil {
		log.Printf("state save: %v", err)
	}
	if reportJson {
		_ = rep.RenderJSON(os.Stdout)
	} else {
		rep.RenderText(os.Stdout)
	}
	os.Exit(rep.ExitCode())
}

func mustDur(s, name string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Fatalf("invalid --%s %q: %v", name, s, err)
	}
	return d
}

// ---- test reload ----------------------------------------------------------

var testReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload-window test: a signed zone must never be served/transferred unsigned (I10)",
	Long: `Repeatedly reloads the zone (mgmt API) while transferring it, and checks
that a signed zone is never transferred UNSIGNED during the reload re-sign
window (I10). With --generate-config it only provisions: allocates an identity
and emits a large online-signed zone + config snippet (default SQISIGN1, whose
slow signing widens the window). With --test <id> it runs the test.`,
	Run: func(cmd *cobra.Command, args []string) {
		st, err := debug.LoadState(effectiveStatePath())
		if err != nil {
			log.Fatalf("state: %v", err)
		}

		if genConfig {
			prov, err := debug.GenerateReloadConfig(st, debug.ReloadProvisionInput{
				BaseZone:       baseZone,
				DnsServer:      dnsServer,
				Target:         targetName,
				PublishCadence: publishCadence,
				ConfigDir:      configDir,
				OutDir:         outDir,
				ZoneSize:       zoneSize,
				Algorithm:      algorithm,
			})
			if err != nil {
				log.Fatalf("generate-config: %v", err)
			}
			if err := st.Save(effectiveStatePath()); err != nil {
				log.Fatalf("state save: %v", err)
			}
			rec := prov.Record
			fmt.Printf("Provisioned %s: zone %s\n", rec.Id, rec.Zone)
			fmt.Printf("  zone file  : %s\n", prov.ZoneFile)
			fmt.Printf("  cfg snippet: %s\n", prov.SnippetFile)
			fmt.Printf("\nOperator to-do:\n")
			for i, s := range prov.Todo {
				fmt.Printf("  %d. %s\n", i+1, s)
			}
			return
		}

		if testId == "" {
			log.Fatal("--test <id> is required to run (provision first with --generate-config)")
		}
		rec, err := st.Get(testId)
		if err != nil {
			log.Fatal(err)
		}
		runReload(cmd.Context(), st, rec)
	},
}

// runReload resolves a provisioned reload test, probes the zone-reload
// capability (printing the matrix so a limited run cannot masquerade as full
// coverage), and executes it.
func runReload(ctx context.Context, st *debug.State, rec *debug.TestRecord) {
	server := dnsServer
	if server == "" {
		server = rec.DnsServer
	}
	if server == "" {
		log.Fatal("no DNS server: pass --dns or re-provision with --dns")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	target := targetName
	if target == "" {
		target = rec.Target
	}
	api := apiClientFor(target)

	m := debug.ProbeApi(ctx, target, api)
	debug.ProbeDns(ctx, m, server, rec.Zone)
	fmt.Print(m.Render())

	cfg := debug.ReloadConfig{
		Zone:           rec.Zone,
		DnsServer:      server,
		Api:            api,
		Target:         target,
		ReloadCapable:  m.Available(debug.CapZoneReload),
		DeclaredSigned: true, // reload zones are always provisioned signed
		ReloadCadence:  mustDur(reloadCadence, "reloadcadence"),
		AxfrCadence:    mustDur(reloadAxfrCadence, "axfrcadence"),
		QueryCadence:   mustDur(reloadQueryCadence, "querycadence"),
		Duration:       mustDur(reloadDuration, "duration"),
		Tool:           appName + " " + appVersion,
		TestId:         rec.Id,
	}

	rep, err := debug.RunReload(ctx, cfg)
	if err != nil {
		log.Printf("reload setup error: %v", err)
		os.Exit(debug.ExitSetup)
	}
	rec.AddStage("ran", fmt.Sprintf("%d violation(s)", len(rep.Violations)))
	if err := st.Save(effectiveStatePath()); err != nil {
		log.Printf("state save: %v", err)
	}
	if reportJson {
		_ = rep.RenderJSON(os.Stdout)
	} else {
		rep.RenderText(os.Stdout)
	}
	os.Exit(rep.ExitCode())
}

// ---- test policy-reload -----------------------------------------------------

var testPolicyReloadCmd = &cobra.Command{
	Use:   "policy-reload",
	Short: "DNSSEC policy-reload no-re-sign/backfill test (A2): first-bind must backfill applied=intent WITHOUT re-signing",
	Long: `Validates the transactional DNSSEC policy-reload guarantee (test A2): the
first time the server binds a signed, config-only zone that has no applied
policy record, it must record applied = intent WITHOUT re-signing the (already
correctly signed) zone. The failure mode is a thundering herd — SignZone(force)
on every zone at once at daemon startup.

There is no server-side sign counter, so a re-sign is inferred from RRSIG
inception: a re-sign stamps a fresh inception, a backfill leaves the served
signature untouched. This tool snapshots the apex SOA and DNSKEY RRSIG
inceptions (per keytag) before and after the herd-risk moment and flags any zone
whose inception advanced.

Trigger modes:
  restart (primary):  --phase before snapshots and exits; you restart the
                      daemon; --phase after snapshots again and emits the verdict.
  reload  (secondary): --reload drives one 'config reload' between the two
                      snapshots in a single invocation (needs the mgmt API).

Zone set: enumerated from the mgmt API (signed zones) or given with
--zones a,b,c | @file.

Operational flow (control for the background resigner — take the 'before'
snapshot right after a full sign, no zone near RRSIG expiry, and keep
before/after close in time):

  1. arm: with the server stopped,
       sqlite3 <keystore.db> "UPDATE ZonePolicyOverride \
         SET applied_policy=NULL, applied_source=NULL, applied_at=NULL;"
     (reload mode: clear applied_* under the running server, then use --reload).
  2. tdns-debug test policy-reload --phase before --target <t> --dns <a:p>
  3. restart the daemon (or run with --reload instead of --phase).
  4. wait for all zones Ready.
  5. tdns-debug test policy-reload --phase after  --target <t> --dns <a:p>

Applied-policy readback and the reload drive are optional capabilities; an
absent one is SKIPPED, never a failure (so the inception-only check can also run
differentially against BIND/NSD). Exit: 0 = A2 held, 1 = a zone was re-signed
(or dropped unsigned), 2 = setup error.`,
	Run: func(cmd *cobra.Command, args []string) { runPolicyReload(cmd.Context()) },
}

// runPolicyReload resolves the zone set, probes capabilities (printing the
// matrix so a limited run cannot masquerade as full coverage), and executes the
// requested phase/mode.
func runPolicyReload(ctx context.Context) {
	server := dnsServer
	if server == "" {
		log.Fatal("no DNS server: pass --dns")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	api := apiClientFor(targetName)
	snapPath := effectivePolicyReloadSnapshot()

	// Resolve the zone set. before/reload enumerate (or take --zones); after
	// reuses the exact set recorded in the before snapshot.
	var zones []string
	switch {
	case policyReloadReload || policyReloadPhase == "before":
		z, err := resolvePolicyReloadZones(ctx, api)
		if err != nil {
			log.Printf("resolving zones: %v", err)
			os.Exit(debug.ExitSetup)
		}
		zones = z
	case policyReloadPhase == "after":
		z, err := debug.PolicyReloadSnapshotZones(snapPath)
		if err != nil {
			log.Printf("reading before snapshot %s (run --phase before first): %v", snapPath, err)
			os.Exit(debug.ExitSetup)
		}
		zones = z
	default:
		log.Fatal("choose a mode: --phase before|after (restart) or --reload")
	}
	if len(zones) == 0 {
		log.Fatal("no zones to test: pass --zones or ensure the mgmt API lists signed zones")
	}

	// Capability probe + matrix (applied-readback is probed against a real zone;
	// the bulk list-zones path never populates the applied_* fields). In text mode
	// print the matrix up front so the operator sees what is gated before any
	// ready-wait; in JSON mode it is attached to the report below so stdout stays
	// a single valid JSON document.
	m := debug.ProbeApi(ctx, targetName, api)
	debug.ProbeDns(ctx, m, server, zones[0])
	debug.ProbeAppliedPolicy(ctx, m, api, zones[0])
	if !reportJson {
		fmt.Print(m.Render())
	}

	cfg := debug.PolicyReloadConfig{
		DnsServer:      server,
		Api:            api,
		Target:         targetName,
		Zones:          zones,
		Phase:          policyReloadPhase,
		Reload:         policyReloadReload,
		Tolerance:      policyReloadTol,
		AppliedCapable: m.Available(debug.CapAppliedRead),
		ReloadCapable:  m.Available(debug.CapApi),
		SnapshotPath:   snapPath,
		ReadyTimeout:   mustDur(policyReloadReady, "ready-timeout"),
		Tool:           appName + " " + appVersion,
	}
	rep, err := debug.RunPolicyReload(ctx, cfg)
	if err != nil {
		if reportJson {
			// The matrix was not printed up front in JSON mode; surface it on
			// stderr so the gating context is not lost on a setup error.
			fmt.Fprint(os.Stderr, m.Render())
		}
		log.Printf("policy-reload setup error: %v", err)
		os.Exit(debug.ExitSetup)
	}
	if reportJson {
		rep.Capabilities = m
		_ = rep.RenderJSON(os.Stdout)
	} else {
		rep.RenderText(os.Stdout)
	}
	os.Exit(rep.ExitCode())
}

// resolvePolicyReloadZones returns the explicit --zones set (comma list or
// @file) or, absent that, the target's signed zones via the mgmt API.
func resolvePolicyReloadZones(ctx context.Context, api *tdns.ApiClient) ([]string, error) {
	if policyReloadZones != "" {
		return parseZoneList(policyReloadZones)
	}
	return debug.EnumerateSignedZones(ctx, api)
}

// parseZoneList parses "a,b,c" or "@file" (one zone per line, # comments and
// blanks ignored).
func parseZoneList(spec string) ([]string, error) {
	var raw []string
	if strings.HasPrefix(spec, "@") {
		buf, err := os.ReadFile(spec[1:])
		if err != nil {
			return nil, fmt.Errorf("reading zone list %s: %w", spec[1:], err)
		}
		raw = strings.Split(string(buf), "\n")
	} else {
		raw = strings.Split(spec, ",")
	}
	var zones []string
	for _, z := range raw {
		z = strings.TrimSpace(z)
		if z == "" || strings.HasPrefix(z, "#") {
			continue
		}
		zones = append(zones, z)
	}
	if len(zones) == 0 {
		return nil, fmt.Errorf("no zones in %q", spec)
	}
	return zones, nil
}

// effectivePolicyReloadSnapshot resolves the before-snapshot file: an explicit
// --snapshot wins, otherwise it lives under --configdir keyed by target so
// concurrent tests against different targets don't collide.
func effectivePolicyReloadSnapshot() string {
	if policyReloadSnap != "" {
		return policyReloadSnap
	}
	name := targetName
	if name == "" {
		name = "default"
	}
	return filepath.Join(configDir, "policy-reload-"+name+".json")
}

// ---- list-tests / cleanup ---------------------------------------------------

var listTestsCmd = &cobra.Command{
	Use:   "list-tests",
	Short: "List known test identities from the state file",
	Run: func(cmd *cobra.Command, args []string) {
		st, err := debug.LoadState(effectiveStatePath())
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
		st, err := debug.LoadState(effectiveStatePath())
		if err != nil {
			log.Fatalf("state: %v", err)
		}
		rec, err := st.Get(testId)
		if err != nil {
			log.Fatal(err)
		}
		if rmArtifacts && rec.ArtifactDir != "" {
			// Only ever remove a directory that carries this tool's artifact
			// marker for this test id (written at provision time). This is a
			// positive ownership check independent of the path string, so it
			// works for custom --out/--configdir layouts and refuses any
			// unrelated or hand-edited path.
			if debug.IsToolArtifactDir(rec.ArtifactDir, rec.Id) {
				if err := os.RemoveAll(rec.ArtifactDir); err != nil {
					log.Printf("removing %s: %v", rec.ArtifactDir, err)
				} else {
					fmt.Printf("removed local artifacts: %s\n", rec.ArtifactDir)
				}
			} else {
				log.Printf("refusing to remove %q (missing tdns-debug artifact marker for %s)", rec.ArtifactDir, rec.Id)
			}
		}
		fmt.Printf("Operator removal list for %s (zone %s):\n", rec.Id, rec.Zone)
		fmt.Printf("  1. remove the zone declaration for %s from the server config\n", rec.Zone)
		fmt.Printf("  2. remove the zone file for %s from the server\n", rec.Zone)
		fmt.Printf("  3. untrust the SIG(0) key %s (truststore)\n", rec.Sig0KeyName)
		fmt.Printf("  4. reload the server\n")
		rec.Cleaned = true
		rec.AddStage("cleaned", "local artifacts handled; server-side steps printed")
		if err := st.Save(effectiveStatePath()); err != nil {
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

// ---- perf (benchmark, not invariant checks) --------------------------------

var perfCmd = &cobra.Command{
	Use:   "perf",
	Short: "Performance/benchmark tools (measure throughput; not pass/fail invariant checks)",
	Run:   func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var perfQpsCmd = &cobra.Command{
	Use:   "qps",
	Short: "Find the max sustainable query rate (adaptive doubling + bisect)",
	Long: `Stresses ONLY the query path. Queries the zone apex for SOA at a rate for
--duration, drains for --timeout, and counts exactly how many correct answers
came back. A step is "clean" if the drop fraction is <= --max-drop-rate; the
search doubles the rate while clean, then bisects between the last clean rate
and the first dropping rate until the gap is below --threshold. Exact query and
correct-response counts are printed for every step (a single drop is visible).

Note: run the generator off-box for a true ceiling — on localhost it competes
with the server for CPU, so the number is a lower bound.`,
	Run: func(cmd *cobra.Command, args []string) { runPerfQps(cmd.Context()) },
}

func runPerfQps(ctx context.Context) {
	if perfTarget == "" {
		log.Fatal("no target: pass --target {ip|ip:port}")
	}
	if zoneName == "" {
		log.Fatal("no zone: pass --zone")
	}
	cfg := debug.PerfConfig{
		Tool:        appName + " " + appVersion,
		Target:      perfTarget,
		Zone:        zoneName,
		UDP:         perfUDP,
		TCP:         perfTCP,
		InitialQPS:  perfInitialQPS,
		Threshold:   perfThreshold,
		Duration:    mustDur(perfDuration, "duration"),
		Timeout:     mustDur(perfTimeout, "timeout"),
		MaxDropRate: perfMaxDropRate,
		MaxQPS:      perfMaxQPS,
	}
	rep, err := debug.RunQPS(ctx, cfg)
	if err != nil {
		log.Printf("perf qps setup error: %v", err)
		os.Exit(debug.ExitSetup)
	}
	if reportJson {
		_ = rep.RenderJSON(os.Stdout)
	} else {
		rep.RenderText(os.Stdout)
	}
	os.Exit(rep.ExitCode())
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
	testChurnCmd.Flags().StringVar(&updateCadence, "updatecadence", "1s", "interval between DNS UPDATEs")
	testChurnCmd.Flags().StringVar(&axfrCadence, "axfrcadence", "3s", "interval between AXFR polls")
	testChurnCmd.Flags().IntVar(&qps, "qps", 0, "concurrent query-hammer rate (0 = off)")
	testChurnCmd.Flags().StringVar(&durationStr, "duration", "2m", "total run duration")
	testChurnCmd.Flags().StringVar(&deltaStr, "delta", "2s", "publish-boundary tolerance for I2/timing checks")
	testChurnCmd.Flags().Int64Var(&seed, "seed", 0, "PRNG seed for a reproducible op mix")
	testChurnCmd.Flags().BoolVar(&reportJson, "json", false, "JSON report")
	testCmd.AddCommand(testChurnCmd)

	testReloadCmd.Flags().BoolVar(&genConfig, "generate-config", false, "provision only: emit zone/config, do not run")
	testReloadCmd.Flags().StringVar(&baseZone, "base-zone", "", "parent zone under which the test zone is invented")
	testReloadCmd.Flags().StringVar(&targetName, "target", "", "apiservers entry name for the mgmt API")
	testReloadCmd.Flags().StringVar(&dnsServer, "dns", "", "DNS server addr:port (also used as ns glue)")
	testReloadCmd.Flags().StringVar(&outDir, "out", "", "artifact directory (default <configdir>/<id>)")
	testReloadCmd.Flags().StringVar(&publishCadence, "publishcadence", "", "publish-cadence for the emitted config (default 20s)")
	testReloadCmd.Flags().IntVar(&zoneSize, "zone-size", 0, "filler RRsets in the generated zone (default 10000)")
	testReloadCmd.Flags().StringVar(&algorithm, "algorithm", "", "signing algorithm for the generated zone (default SQISIGN1)")
	testReloadCmd.Flags().StringVar(&testId, "test", "", "test identity from a prior --generate-config")
	testReloadCmd.Flags().StringVar(&reloadCadence, "reloadcadence", "30s", "interval between zone reloads")
	testReloadCmd.Flags().StringVar(&reloadAxfrCadence, "axfrcadence", "500ms", "interval between AXFR observations")
	testReloadCmd.Flags().StringVar(&reloadQueryCadence, "querycadence", "500ms", "interval between +dnssec query-signedness observations")
	testReloadCmd.Flags().StringVar(&reloadDuration, "duration", "5m", "total run duration")
	testReloadCmd.Flags().BoolVar(&reportJson, "json", false, "JSON report")
	testCmd.AddCommand(testReloadCmd)

	testPolicyReloadCmd.Flags().StringVar(&targetName, "target", "", "apiservers entry name for the mgmt API")
	testPolicyReloadCmd.Flags().StringVar(&dnsServer, "dns", "", "DNS server addr:port to observe")
	testPolicyReloadCmd.Flags().StringVar(&policyReloadZones, "zones", "", "explicit signed-zone set: a,b,c or @file (default: enumerate signed zones via the mgmt API)")
	testPolicyReloadCmd.Flags().StringVar(&policyReloadPhase, "phase", "", "restart mode: 'before' (snapshot+exit) or 'after' (snapshot+compare)")
	testPolicyReloadCmd.Flags().BoolVar(&policyReloadReload, "reload", false, "reload mode: single invocation, drive 'config reload' between the before/after snapshots")
	testPolicyReloadCmd.Flags().IntVar(&policyReloadTol, "tolerance", 0, "allowed count of coincidentally re-signed zones (background-resigner ticks) before A2 fails")
	testPolicyReloadCmd.Flags().StringVar(&policyReloadSnap, "snapshot", "", "before-snapshot file (default <configdir>/policy-reload-<target>.json)")
	testPolicyReloadCmd.Flags().StringVar(&policyReloadReady, "ready-timeout", "60s", "how long to wait for all zones to answer SOA again after the trigger")
	testPolicyReloadCmd.Flags().BoolVar(&reportJson, "json", false, "JSON report")
	testCmd.AddCommand(testPolicyReloadCmd)

	cleanupCmd.Flags().StringVar(&testId, "test", "", "test identity to clean up")
	cleanupCmd.Flags().BoolVar(&rmArtifacts, "rm", false, "also remove the local artifact directory")

	perfQpsCmd.Flags().BoolVar(&perfUDP, "udp", true, "drive the rate search over UDP")
	perfQpsCmd.Flags().BoolVar(&perfTCP, "tcp", false, "also send 10% of the UDP rate over TCP (reported separately)")
	perfQpsCmd.Flags().StringVar(&perfTarget, "target", "", "DNS server addr (ip or ip:port; default port 53)")
	perfQpsCmd.Flags().StringVarP(&zoneName, "zone", "z", "", "zone (queried at the apex for SOA)")
	perfQpsCmd.Flags().IntVar(&perfInitialQPS, "initial-qps", 1000, "starting query rate")
	perfQpsCmd.Flags().IntVar(&perfThreshold, "threshold", 1000, "stop when the bisect gap (qps) drops below this")
	perfQpsCmd.Flags().StringVar(&perfDuration, "duration", "5s", "send window per rate step")
	perfQpsCmd.Flags().StringVar(&perfTimeout, "timeout", "1s", "straggler drain after each send window")
	perfQpsCmd.Flags().Float64Var(&perfMaxDropRate, "max-drop-rate", 0.005, "a step is clean if the drop fraction is <= this (0.005 = 0.5%)")
	perfQpsCmd.Flags().IntVar(&perfMaxQPS, "max-qps", 1000000, "safety cap on the rate search")
	perfQpsCmd.Flags().BoolVar(&reportJson, "json", false, "JSON report")
	perfCmd.AddCommand(perfQpsCmd)
}
