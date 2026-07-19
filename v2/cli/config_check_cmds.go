/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * `tdns-cli auth config check` — validate a tdns-auth configuration file and
 * correlate it against the running daemon.
 *
 * The command is deliberately CLI-side and self-contained: it re-reads the
 * YAML the same way the daemon's loader does (main file + single-level
 * include: merge), reuses the exported tdns validators for the parts that
 * have them (required-field tags, DNSSEC policy algorithm gating), and adds
 * its own referential / filesystem / cross-file checks on top. When a daemon
 * is reachable it also pulls the running config (via the mgmt API) and reports
 * drift between what is on disk and what the server actually loaded.
 *
 * Modeled on `auto-rollover validate` (auto_rollover_validate.go), which
 * established the "ask the daemon for its config path via /config/paths, then
 * re-parse the YAML offline" pattern.
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	tdns "github.com/johanix/tdns/v2"
)

// ---------------------------------------------------------------------------
// Result model
// ---------------------------------------------------------------------------

type ccLevel int

const (
	ccPASS ccLevel = iota
	ccINFO
	ccWARN
	ccFAIL
)

func (l ccLevel) label() string {
	switch l {
	case ccPASS:
		return "PASS"
	case ccINFO:
		return "INFO"
	case ccWARN:
		return "WARN"
	case ccFAIL:
		return "FAIL"
	}
	return "????"
}

type ccResult struct {
	level      ccLevel
	check      string // short check name
	msg        string // one-line detail
	suggestion string // optional operator-actionable hint
}

// ccReport accumulates results grouped by section, preserving insertion order.
type ccReport struct {
	sections []string
	byGroup  map[string][]ccResult
}

func newCCReport() *ccReport {
	return &ccReport{byGroup: map[string][]ccResult{}}
}

func (r *ccReport) add(group string, level ccLevel, check, msg, suggestion string) {
	if _, seen := r.byGroup[group]; !seen {
		r.sections = append(r.sections, group)
	}
	r.byGroup[group] = append(r.byGroup[group], ccResult{level, check, msg, suggestion})
}

func (r *ccReport) pass(group, check, msg string) { r.add(group, ccPASS, check, msg, "") }
func (r *ccReport) info(group, check, msg string) { r.add(group, ccINFO, check, msg, "") }
func (r *ccReport) warn(group, check, msg, suggestion string) {
	r.add(group, ccWARN, check, msg, suggestion)
}
func (r *ccReport) fail(group, check, msg, suggestion string) {
	r.add(group, ccFAIL, check, msg, suggestion)
}

func (r *ccReport) counts() (fails, warns int) {
	for _, g := range r.sections {
		for _, res := range r.byGroup[g] {
			switch res.level {
			case ccFAIL:
				fails++
			case ccWARN:
				warns++
			}
		}
	}
	return
}

// render prints the grouped report. In non-verbose mode PASS lines are
// suppressed (only WARN/FAIL/INFO shown) unless a group has nothing but
// passes, in which case a single summary line is printed for the group.
func (r *ccReport) render(verbose bool) {
	for _, g := range r.sections {
		results := r.byGroup[g]
		// Decide whether to print the group at all in non-verbose mode.
		var nonPass int
		for _, res := range results {
			if res.level != ccPASS {
				nonPass++
			}
		}
		fmt.Printf("%s\n", g)
		if !verbose && nonPass == 0 {
			fmt.Printf("  PASS  (%d checks)\n", len(results))
			continue
		}
		for _, res := range results {
			if res.level == ccPASS && !verbose {
				continue
			}
			line := res.check
			if res.msg != "" {
				line = fmt.Sprintf("%s — %s", res.check, res.msg)
			}
			fmt.Printf("  %-4s  %s\n", res.level.label(), line)
			if res.suggestion != "" {
				fmt.Printf("        ↳ %s\n", res.suggestion)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

// newConfigCheckCmd builds the `config check` command for the given role. Only
// wired for "auth" today; the role parameter keeps the door open for imr/agent.
func newConfigCheckCmd(role string) *cobra.Command {
	var (
		serverConfig string
		offline      bool
	)
	c := &cobra.Command{
		Use:   "check [config-file]",
		Short: "Validate the tdns-" + role + " config and correlate it with the running daemon",
		Long: `Validate a tdns-` + role + ` configuration file for completeness and internal
consistency, and (unless --offline) correlate it against the running daemon to
report drift between the file on disk and what the server actually loaded.

Target config resolution:
  1. an explicit path (positional arg or --serverconfig)
  2. otherwise, online, the path the daemon reports via GET /config/paths
  3. otherwise the compiled-in default (/etc/tdns/tdns-` + role + `.yaml)

Exit status is non-zero if any check FAILs (WARNs do not fail the run).`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 && serverConfig == "" {
				serverConfig = args[0]
			}
			runConfigCheck(role, serverConfig, offline)
		},
	}
	c.Flags().StringVar(&serverConfig, "serverconfig", "", "path to the tdns-"+role+" config file to check (default: ask the daemon, else the compiled-in default)")
	c.Flags().BoolVar(&offline, "offline", false, "do not contact the daemon; run static checks only")
	return c
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

func runConfigCheck(role, explicitPath string, offline bool) {
	// config check renders its own structured findings; silence the reused
	// tdns validators' per-section "validating config section" Info chatter
	// (genuine config ERRORs still surface).
	tdns.SetSubsystemLevel("config", slog.LevelError)

	rep := newCCReport()

	// Resolve which config file to check, and whether we can reach the daemon.
	online := !offline
	var daemonCfgPath, daemonDBPath string
	if online {
		if p, db, ok := fetchDaemonPaths(role); ok {
			daemonCfgPath, daemonDBPath = p, db
		} else {
			online = false
			rep.warn("Daemon", "reachability",
				fmt.Sprintf("could not reach the %s daemon; running static checks only", role),
				"start the daemon (or pass --offline) to enable running-config correlation")
		}
	}

	cfgPath := explicitPath
	switch {
	case cfgPath != "":
		// explicit path wins
	case daemonCfgPath != "":
		cfgPath = daemonCfgPath
	default:
		cfgPath = tdns.DefaultAuthCfgFile
	}
	cfgPath = absClean(cfgPath)

	fmt.Printf("Checking %s config: %s\n", role, cfgPath)
	if online {
		fmt.Printf("Correlating against the running %s daemon.\n", role)
		if daemonCfgPath != "" && absClean(daemonCfgPath) != cfgPath {
			rep.warn("Config file", "daemon-config-mismatch",
				fmt.Sprintf("checking %s, but the running daemon loaded %s", cfgPath, absClean(daemonCfgPath)),
				"check the file the daemon is actually running, or reconcile the two")
		}
	}
	fmt.Println()

	// Load the config the way the daemon does (main + single-level includes).
	v, loadErr := loadConfigViper(cfgPath, rep)
	if loadErr != nil {
		rep.fail("Config file", "load", fmt.Sprintf("cannot load %s: %v", cfgPath, loadErr),
			"fix the YAML syntax / missing file, then re-run")
		finishCheckconf(rep)
		return
	}
	rep.pass("Config file", "load", "config file (and includes) parsed as YAML")

	// Required-field validation via the exported tdns validator (drives the
	// `validate:"required"` struct tags AND the cert/key pair validation).
	checkRequiredFields(v, cfgPath, rep, tdns.AppTypeAuth)

	// Decode into a typed Config for the structural checks. Best-effort: the
	// legacy bare-string primary/ACL decode hooks live in the tdns package and
	// are not reachable here, but modern {addr,key} configs decode cleanly.
	var cfg tdns.Config
	if err := v.Unmarshal(&cfg); err != nil {
		rep.warn("Config file", "decode",
			fmt.Sprintf("could not fully decode config into structs: %v", err),
			"structural checks below may be incomplete; often caused by legacy bare-string primaries:/downstreams:")
	}

	checkDnsEngine(&cfg, rep)
	checkApiServer(&cfg, cfgPath, rep)
	checkDnssecPolicies(v, rep)
	checkZones(&cfg, rep, online, role)
	checkApiServerCorrelation(role, &cfg, rep)

	// Running-config correlation.
	if online {
		correlateRunningConfig(role, &cfg, cfgPath, daemonDBPath, rep)
	}

	finishCheckconf(rep)
}

func finishCheckconf(rep *ccReport) {
	fmt.Println()
	rep.render(tdns.Globals.Verbose)
	fails, warns := rep.counts()
	fmt.Println()
	switch {
	case fails > 0:
		fmt.Printf("Result: %d FAIL, %d WARN — config is not valid.\n", fails, warns)
		os.Exit(1)
	case warns > 0:
		fmt.Printf("Result: 0 FAIL, %d WARN — config is usable but has warnings.\n", warns)
	default:
		fmt.Println("Result: all checks passed.")
	}
}

// ---------------------------------------------------------------------------
// Config loading (mirrors cmdv2/cli/root.go initConfig include handling)
// ---------------------------------------------------------------------------

// loadConfigViper reads path into a fresh viper instance and merges any
// top-level include: files (single level, non-recursive), exactly as the
// daemon/CLI loaders do. A missing include is reported as a WARN, not fatal.
func loadConfigViper(path string, rep *ccReport) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	for _, inc := range v.GetStringSlice("include") {
		incPath := inc
		if !filepath.IsAbs(incPath) {
			incPath = filepath.Join(filepath.Dir(path), incPath)
		}
		if _, err := os.Stat(incPath); err != nil {
			if os.IsNotExist(err) {
				rep.warn("Config file", "include",
					fmt.Sprintf("included file not found: %s", incPath),
					"create the file or remove it from the include: list")
				continue
			}
			return nil, fmt.Errorf("stat include %s: %w", incPath, err)
		}
		v.SetConfigFile(incPath)
		if err := v.MergeInConfig(); err != nil {
			return nil, fmt.Errorf("merge include %s: %w", incPath, err)
		}
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Static checks
// ---------------------------------------------------------------------------

// checkRequiredFields runs the exported required-field validator for the given
// app type (which selects the sections tdns.ValidateConfig checks: auth →
// service/db/apiserver/dnsengine + log; imr → imrengine + log).
func checkRequiredFields(v *viper.Viper, cfgPath string, rep *ccReport, appType tdns.AppType) {
	saved := tdns.Globals.App.Type
	tdns.Globals.App.Type = appType
	defer func() { tdns.Globals.App.Type = saved }()

	suggestion := "add the missing required keys (service.name, dnsengine.addresses/transports, apiserver.*, db.file, log.file)"
	passMsg := "all required sections/keys present; apiserver cert/key pair valid"
	if appType == tdns.AppTypeImr {
		suggestion = "add the missing required keys (imrengine.addresses, imrengine.transports, log.file)"
		passMsg = "required sections present (imrengine.addresses/transports, log.file)"
	}

	if err := tdns.ValidateConfig(v, cfgPath); err != nil {
		rep.fail("Required fields", "required", firstLine(err.Error()), suggestion)
		// Fall through: also surface the raw multi-line detail for the operator.
		for _, ln := range extraLines(err.Error()) {
			rep.info("Required fields", "detail", ln)
		}
		return
	}
	rep.pass("Required fields", "required", passMsg)
}

func checkDnsEngine(cfg *tdns.Config, rep *ccReport) {
	const g = "DNS engine"
	if len(cfg.DnsEngine.Addresses) == 0 {
		rep.fail(g, "addresses", "dnsengine.addresses is empty — the server would not listen on any address",
			"add at least one addr:port, e.g. [ 127.0.0.1:53, '[::1]:53' ]")
	} else {
		rep.pass(g, "addresses", fmt.Sprintf("listening on %v", cfg.DnsEngine.Addresses))
	}

	validT := map[string]bool{"do53": true, "dot": true, "doh": true, "doq": true}
	if len(cfg.DnsEngine.Transports) == 0 {
		rep.fail(g, "transports", "dnsengine.transports is empty",
			"list at least one of do53, dot, doh, doq")
	}
	needCert := false
	for _, t := range cfg.DnsEngine.Transports {
		lt := strings.ToLower(strings.TrimSpace(t))
		if !validT[lt] {
			rep.fail(g, "transports", fmt.Sprintf("unknown transport %q", t),
				"valid transports are do53, dot, doh, doq")
			continue
		}
		if lt != "do53" {
			needCert = true
		}
	}
	if needCert {
		if cfg.DnsEngine.CertFile == "" || cfg.DnsEngine.KeyFile == "" {
			rep.warn(g, "cert", "dot/doh/doq configured but dnsengine.certfile/keyfile not set — those listeners will be skipped",
				"set dnsengine.certfile and dnsengine.keyfile, or remove the encrypted transports")
		} else {
			checkFileExists(rep, g, "certfile", cfg.DnsEngine.CertFile)
			checkFileExists(rep, g, "keyfile", cfg.DnsEngine.KeyFile)
		}
	}
}

func checkApiServer(cfg *tdns.Config, cfgPath string, rep *ccReport) {
	const g = "API server"
	if len(cfg.ApiServer.Addresses) == 0 {
		rep.fail(g, "addresses", "apiserver.addresses is empty",
			"set at least one addr:port (loopback is fine, e.g. 127.0.0.1:8989)")
	} else {
		rep.pass(g, "addresses", fmt.Sprintf("listening on %v", cfg.ApiServer.Addresses))
	}
	if cfg.ApiServer.ApiKey.Value() == "" {
		rep.fail(g, "apikey", "apiserver.apikey is empty — the API router refuses to start without it",
			"set a long random apiserver.apikey")
	} else {
		rep.pass(g, "apikey", "apiserver.apikey is set")
	}
	// certfile/keyfile are required even with usetls:false; the required-fields
	// check validates the pair, but surface the plain existence here too.
	if cfg.ApiServer.CertFile == "" || cfg.ApiServer.KeyFile == "" {
		rep.fail(g, "cert", "apiserver.certfile/keyfile must be set (required even when usetls:false)",
			"generate a cert/key pair (see `tdns-cli auth config mwe`) and point certfile/keyfile at it")
	} else {
		checkFileExists(rep, g, "certfile", cfg.ApiServer.CertFile)
		checkFileExists(rep, g, "keyfile", cfg.ApiServer.KeyFile)
	}
}

// checkDnssecPolicies validates every DNSSEC policy the same way the daemon
// does (template expansion + split-algorithm gating + role-capability + key
// lifetimes) by handing the merged dnssec: subtree to the exported
// tdns.ValidateDnssecPoliciesFromFile.
func checkDnssecPolicies(v *viper.Viper, rep *ccReport) {
	const g = "DNSSEC policies"
	sub := v.Get("dnssec")
	if sub == nil {
		rep.info(g, "policies", "no dnssec: block; zones needing signing fall back to the built-in default policy")
		return
	}
	pols, _ := v.Get("dnssec.policies").(map[string]interface{})
	if len(pols) == 0 {
		rep.info(g, "policies", "no dnssec.policies defined (built-in default policy applies)")
		return
	}

	tmp, err := writeTempYAML(map[string]interface{}{"dnssec": sub})
	if err != nil {
		rep.warn(g, "policies", fmt.Sprintf("could not stage dnssec block for validation: %v", err), "")
		return
	}
	defer os.Remove(tmp)

	if err := tdns.ValidateDnssecPoliciesFromFile(tmp); err != nil {
		for _, ln := range strings.Split(strings.TrimRight(err.Error(), "\n"), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			rep.fail(g, "policy", ln,
				"fix the policy (algorithm/lifetime/mode), or allowlist a differing KSK/ZSK pair in dnssec.split_algorithms")
		}
		return
	}
	rep.pass(g, "policies", fmt.Sprintf("all %d policy definition(s) valid (algorithms, split-gating, lifetimes)", len(pols)))
}

func checkZones(cfg *tdns.Config, rep *ccReport, online bool, role string) {
	const g = "Zones"
	if len(cfg.Zones) == 0 {
		rep.info(g, "zones", "no zones declared in config")
		return
	}

	// Build lookup sets for referential integrity (case-insensitive).
	templateNames := map[string]tdns.ZoneConf{}
	for _, t := range cfg.Templates {
		templateNames[lc(t.Name)] = t
	}
	policyNames := map[string]bool{"": true, "none": true, "default": true}
	for name := range collectPolicyNames(cfg) {
		policyNames[lc(name)] = true
	}
	msNames := map[string]bool{"": true, "none": true}
	for name := range cfg.MultiSigner {
		msNames[lc(name)] = true
	}

	// Config TSIG key names (for the secondary-zone key check).
	configTsig := map[string]bool{}
	for _, k := range cfg.Keys.Tsig {
		configTsig[lc(dns.Fqdn(k.Name))] = true
	}
	var keystoreTsig map[string]bool
	keystoreOK := false
	if online {
		var ksErr error
		keystoreTsig, ksErr = fetchKeystoreTsigNames(role)
		if ksErr != nil {
			rep.warn(g, "keystore",
				fmt.Sprintf("could not list TSIG keys from the keystore: %v — TSIG key presence not verified against the keystore", ksErr),
				"re-run when the daemon/keystore is reachable")
		} else {
			keystoreOK = true
		}
	}

	seen := map[string]bool{}
	for i := range cfg.Zones {
		z := cfg.Zones[i]
		zname := z.Name
		zlabel := zname
		if zlabel == "" {
			zlabel = fmt.Sprintf("zones[%d]", i)
		}

		if zname == "" {
			rep.fail(g, zlabel, "zone has no name", "every zone needs a name (FQDN with trailing dot)")
			continue
		}
		if !strings.HasSuffix(zname, ".") {
			rep.warn(g, zname, "zone name is not a FQDN (missing trailing dot)", "write the name with a trailing dot, e.g. example.com.")
		}
		if seen[lc(zname)] {
			rep.fail(g, zname, "duplicate zone declaration", "remove the duplicate entry")
			continue
		}
		seen[lc(zname)] = true

		// Resolve the effective zone (apply template gap-fill for the fields we check).
		eff := effectiveZone(z, templateNames)

		// Template reference.
		if z.Template != "" {
			if _, ok := templateNames[lc(z.Template)]; !ok {
				rep.fail(g, zname, fmt.Sprintf("references template %q which is not defined", z.Template),
					"define the template under templates: or fix the name")
			}
		}

		// dnssecpolicy reference.
		if !policyNames[lc(eff.DnssecPolicy)] {
			rep.fail(g, zname, fmt.Sprintf("references dnssecpolicy %q which is not defined", eff.DnssecPolicy),
				"define the policy under dnssec.policies: (not dnssec.templates:) or fix the name")
		}

		// multisigner reference.
		if !msNames[lc(eff.MultiSigner)] {
			rep.fail(g, zname, fmt.Sprintf("references multisigner %q which is not defined", eff.MultiSigner),
				"define it under multisigner: or fix the name")
		}

		// Signing option requires a policy.
		if hasSigningOption(eff.OptionsStrs) && lc(eff.DnssecPolicy) == "" {
			rep.fail(g, zname, "online-signing/inline-signing set but no dnssecpolicy — the zone will be quarantined",
				"set dnssecpolicy: on the zone or its template")
		}

		switch lc(eff.Type) {
		case "primary", "":
			if lc(eff.Type) == "" {
				rep.warn(g, zname, "no zone type (and none inherited from a template)", "set type: primary or secondary")
			}
			checkPrimaryZone(rep, g, zname, eff)
		case "secondary":
			checkSecondaryZone(rep, g, zname, eff, configTsig, keystoreTsig, online, keystoreOK)
		default:
			rep.fail(g, zname, fmt.Sprintf("unknown zone type %q", eff.Type), "type must be primary or secondary")
		}
	}
}

func checkPrimaryZone(rep *ccReport, g, zname string, eff tdns.ZoneConf) {
	zf := eff.Zonefile
	if zf == "" {
		rep.fail(g, zname, "primary zone has no zonefile (and none inherited from a template)",
			"set zonefile: on the zone or a zonefile pattern on its template")
		return
	}
	if _, err := os.Stat(zf); err != nil {
		rep.fail(g, zname, fmt.Sprintf("zonefile %s not found: %v", zf, err),
			"create the zone file or fix the path")
		return
	}
	if err := parseZonefile(zf, zname); err != nil {
		rep.fail(g, zname, fmt.Sprintf("zonefile %s failed to parse: %v", zf, err),
			"fix the zone file so the miekg/dns parser accepts it (apex SOA, valid RRs)")
		return
	}
	rep.pass(g, zname, fmt.Sprintf("primary; zonefile %s exists and parses", zf))
}

func checkSecondaryZone(rep *ccReport, g, zname string, eff tdns.ZoneConf, configTsig, keystoreTsig map[string]bool, online, keystoreOK bool) {
	if len(eff.Primaries) == 0 {
		rep.fail(g, zname, "secondary zone has no primaries:", "add at least one primaries: {addr, key} entry")
	}
	// Collect TSIG key names referenced by this zone.
	for _, p := range eff.Primaries {
		checkTsigRef(rep, g, zname, "primaries", p.Key, configTsig, keystoreTsig, online, keystoreOK)
	}
	for _, p := range eff.Notify {
		checkTsigRef(rep, g, zname, "notify", p.Key, configTsig, keystoreTsig, online, keystoreOK)
	}
	for _, a := range eff.AllowNotify {
		checkTsigRef(rep, g, zname, "allow-notify", a.Key, configTsig, keystoreTsig, online, keystoreOK)
	}
	for _, a := range eff.Downstreams {
		checkTsigRef(rep, g, zname, "downstreams", a.Key, configTsig, keystoreTsig, online, keystoreOK)
	}
	if len(eff.Primaries) > 0 {
		rep.pass(g, zname, "secondary; primaries configured")
	}
}

// checkTsigRef verifies a referenced TSIG key resolves. A hard FAIL ("zone will
// be quarantined") is reported ONLY when the keystore was actually consulted
// (online && keystoreOK) and the key is absent there and in keys.tsig. When the
// keystore could not be queried (offline, or the list call failed), the key's
// keystore presence is unknown, so it is a WARN — never a FAIL — to avoid
// manufacturing a false quarantine from a transient API error.
func checkTsigRef(rep *ccReport, g, zname, field, key string, configTsig, keystoreTsig map[string]bool, online, keystoreOK bool) {
	k := strings.TrimSpace(key)
	if k == "" || strings.EqualFold(k, "NOKEY") || strings.EqualFold(k, "BLOCKED") {
		return
	}
	fk := lc(dns.Fqdn(k))
	if configTsig[fk] {
		return
	}
	if online && keystoreOK {
		if keystoreTsig[fk] {
			return
		}
		rep.fail(g, zname, fmt.Sprintf("%s references TSIG key %q that is in neither keys.tsig nor the keystore — the zone will be quarantined", field, key),
			"add the key under keys.tsig: or via `tdns-cli auth keystore tsig add`")
		return
	}
	reason := "offline: keystore not checked"
	if online {
		reason = "keystore query failed: not verified"
	}
	rep.warn(g, zname, fmt.Sprintf("%s references TSIG key %q not found in keys.tsig (%s)", field, key, reason),
		"verify the key exists in the keystore, or run online against a reachable daemon")
}

// checkApiServerCorrelation cross-checks the auth config's apiserver block
// against the tdns-cli.yaml entry that `tdns-cli <role> ...` would actually use.
func checkApiServerCorrelation(role string, cfg *tdns.Config, rep *ccReport) {
	const g = "tdns-cli correlation"
	if !listensOnLocalhost(cfg.ApiServer.Addresses) {
		rep.info(g, "apiserver", "apiserver does not listen on localhost; skipping tdns-cli.yaml port/key correlation")
		return
	}
	clientKey := GetClientKeyFromParent(role)
	det := GetApiDetailsByClientKey(clientKey)
	if det == nil {
		rep.fail(g, "apiservers-entry",
			fmt.Sprintf("tdns-cli.yaml has no apiservers entry named %q — `tdns-cli %s ...` cannot reach this server", clientKey, role),
			fmt.Sprintf("add an apiservers: entry named %q pointing at this server's apiserver address", clientKey))
		return
	}

	// Compare port.
	cfgPort := firstPort(cfg.ApiServer.Addresses)
	cliPort := urlPort(det.BaseURL)
	if cfgPort != "" && cliPort != "" && cfgPort != cliPort {
		rep.fail(g, "port",
			fmt.Sprintf("apiserver listens on port %s but tdns-cli.yaml %q targets port %s", cfgPort, clientKey, cliPort),
			"align the tdns-cli.yaml baseurl port with apiserver.addresses")
	} else if cfgPort != "" && cliPort == cfgPort {
		rep.pass(g, "port", fmt.Sprintf("tdns-cli.yaml %q targets the right port (%s)", clientKey, cfgPort))
	}

	// Compare api key.
	if cfg.ApiServer.ApiKey.Value() != "" && det.ApiKey != "" {
		if cfg.ApiServer.ApiKey.Value() != det.ApiKey {
			rep.fail(g, "apikey",
				fmt.Sprintf("apiserver.apikey does not match the apikey in tdns-cli.yaml %q", clientKey),
				"copy the server's apiserver.apikey into the matching tdns-cli.yaml apiservers entry")
		} else {
			rep.pass(g, "apikey", fmt.Sprintf("tdns-cli.yaml %q apikey matches apiserver.apikey", clientKey))
		}
	}
}

// ---------------------------------------------------------------------------
// Running-config correlation (online)
// ---------------------------------------------------------------------------

func correlateRunningConfig(role string, cfg *tdns.Config, cfgPath, daemonDBPath string, rep *ccReport) {
	const g = "Running-config drift"

	// db.file drift.
	if daemonDBPath != "" && cfg.Db.File != "" && absClean(daemonDBPath) != absClean(cfg.Db.File) {
		rep.warn(g, "db-file",
			fmt.Sprintf("config db.file=%s but the daemon is using %s", cfg.Db.File, daemonDBPath),
			"a reload does not move the DB; restart is needed to switch db.file")
	}

	// /config status: running dnsengine + apiserver.
	if api, err := GetApiClient(role, false); err != nil {
		rep.warn(g, "status", fmt.Sprintf("could not reach the daemon for status: %v — status drift not correlated", err), "")
	} else if resp, err := SendConfigCommand(api, tdns.ConfigPost{Command: "status"}); err != nil {
		rep.warn(g, "status", fmt.Sprintf("could not fetch running status: %v — status drift not correlated", err), "")
	} else {
		correlateStatus(cfg, resp, rep, g)
	}

	// Running zones vs config zones.
	correlateZones(role, cfg, rep, g)

	// Policies the server actually loaded (and any it rejected).
	if pols, err := fetchServerPolicies(role); err != nil {
		rep.warn("DNSSEC policies", "loaded", fmt.Sprintf("could not fetch loaded policies: %v — server-side policy errors not correlated", err), "")
	} else {
		var broken []string
		for _, p := range pols {
			if p.PolicyError != "" {
				broken = append(broken, fmt.Sprintf("%s: %s", p.Name, p.PolicyError))
			}
		}
		if len(broken) > 0 {
			for _, b := range broken {
				rep.fail("DNSSEC policies", "loaded-policy", "server rejected policy "+b,
					"fix the policy definition and reload")
			}
		} else {
			rep.pass("DNSSEC policies", "loaded", fmt.Sprintf("server loaded %d policy(ies) with no errors", len(pols)))
		}
	}
}

func correlateStatus(cfg *tdns.Config, resp tdns.ConfigResponse, rep *ccReport, g string) {
	if !sameStringSet(cfg.DnsEngine.Addresses, resp.DnsEngine.Addresses) {
		rep.warn(g, "dnsengine-addresses",
			fmt.Sprintf("config dnsengine.addresses %v differ from running %v", cfg.DnsEngine.Addresses, resp.DnsEngine.Addresses),
			"a `config reload` does not re-open DNS listeners; restart to change listen addresses")
	}
	if resp.ApiServer.ApiKey.Value() != "" && cfg.ApiServer.ApiKey.Value() != "" &&
		resp.ApiServer.ApiKey.Value() != cfg.ApiServer.ApiKey.Value() {
		rep.warn(g, "apikey",
			"apiserver.apikey in the file differs from the running server's apikey",
			"the running apikey changes only on restart")
	}
}

func correlateZones(role string, cfg *tdns.Config, rep *ccReport, g string) {
	api, err := GetApiClient(role, false)
	if err != nil {
		rep.warn(g, "zones", fmt.Sprintf("could not reach the daemon to list zones: %v — zone drift not correlated", err), "")
		return
	}
	resp, err := SendZoneCommand(api, tdns.ZonePost{Command: "list-zones"})
	if err != nil {
		rep.warn(g, "zones", fmt.Sprintf("could not list running zones: %v — zone drift not correlated", err), "")
		return
	}
	running := map[string]tdns.ZoneConf{}
	for name, zc := range resp.Zones {
		running[lc(dns.Fqdn(name))] = zc
	}
	configured := map[string]bool{}
	for _, z := range cfg.Zones {
		if z.Name == "" {
			continue
		}
		configured[lc(dns.Fqdn(z.Name))] = true
		rn := lc(dns.Fqdn(z.Name))
		if _, ok := running[rn]; !ok {
			rep.warn(g, "zone-not-running",
				fmt.Sprintf("zone %s is in the config but not running", z.Name),
				"run `config reload-zones` to load newly-added zones")
		}
	}
	for rn, zc := range running {
		// Skip dynamic/managed zones — they are never in the static config.
		if zc.ApiManaged || zc.SourceCatalog != "" {
			continue
		}
		if !configured[rn] {
			rep.info(g, "zone-not-in-config",
				fmt.Sprintf("zone %s is running but not in this config file", strings.TrimSuffix(rn, ".")+"."))
		}
	}
	if len(cfg.Zones) > 0 {
		rep.pass(g, "zones", "compared configured zones against the running set")
	}
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

func fetchDaemonPaths(role string) (cfgFile, dbFile string, ok bool) {
	api, err := GetApiClient(role, false)
	if err != nil {
		return "", "", false
	}
	_, body, err := api.RequestNG("GET", "/config/paths", nil, false)
	if err != nil {
		return "", "", false
	}
	var resp tdns.ConfigPathsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", "", false
	}
	return resp.ConfigFile, resp.DBFile, true
}

// fetchKeystoreTsigNames lists the TSIG key names held in the daemon's
// keystore. It returns an error rather than an empty map on failure: a failed
// keystore-list must NOT be mistaken for "the key is absent" (that would turn a
// transient API error into a false quarantine FAIL — see checkTsigRef).
func fetchKeystoreTsigNames(role string) (map[string]bool, error) {
	out := map[string]bool{}
	api, err := GetApiClient(role, false)
	if err != nil {
		return nil, err
	}
	resp, err := SendKeystoreCmd(api, tdns.KeystorePost{Command: "tsig-mgmt", SubCommand: "list"})
	if err != nil {
		return nil, err
	}
	for _, k := range resp.TsigKeys {
		out[lc(dns.Fqdn(k.Name))] = true
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func lc(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func absClean(p string) string {
	if p == "" {
		return p
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return filepath.Clean(p)
}

func checkFileExists(rep *ccReport, g, check, path string) {
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err != nil {
		rep.fail(g, check, fmt.Sprintf("%s not found: %s", check, path), "create the file or fix the path")
		return
	}
	rep.pass(g, check, fmt.Sprintf("%s exists: %s", check, path))
}

func parseZonefile(path, origin string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zp := dns.NewZoneParser(f, origin, path)
	zp.SetIncludeAllowed(true)
	sawSOA := false
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rr != nil && rr.Header().Rrtype == dns.TypeSOA {
			sawSOA = true
		}
	}
	if err := zp.Err(); err != nil {
		return err
	}
	if !sawSOA {
		return fmt.Errorf("no SOA record found")
	}
	return nil
}

func hasSigningOption(opts []string) bool {
	for _, o := range opts {
		lo := lc(o)
		if lo == "online-signing" || lo == "inline-signing" {
			return true
		}
	}
	return false
}

// effectiveZone applies the documented template gap-fill for the subset of
// fields config check inspects (type, store, zonefile, dnssecpolicy, multisigner,
// options-union). The zone's own non-zero values always win.
func effectiveZone(z tdns.ZoneConf, templates map[string]tdns.ZoneConf) tdns.ZoneConf {
	eff := z
	if z.Template == "" {
		return eff
	}
	t, ok := templates[lc(z.Template)]
	if !ok {
		return eff
	}
	if eff.Type == "" {
		eff.Type = t.Type
	}
	if eff.Store == "" {
		eff.Store = t.Store
	}
	if eff.DnssecPolicy == "" {
		eff.DnssecPolicy = t.DnssecPolicy
	}
	if eff.MultiSigner == "" {
		eff.MultiSigner = t.MultiSigner
	}
	if eff.Zonefile == "" && t.Zonefile != "" {
		if strings.Contains(t.Zonefile, "%s") {
			// Template zonefile is a %s pattern substituted with the zone
			// name (incl. trailing dot). ReplaceAll (not Sprintf) keeps this
			// a non-format string, avoiding a go vet warning.
			eff.Zonefile = strings.ReplaceAll(t.Zonefile, "%s", z.Name)
		} else {
			eff.Zonefile = t.Zonefile
		}
	}
	if len(eff.Primaries) == 0 {
		eff.Primaries = t.Primaries
	}
	// options: is a union.
	eff.OptionsStrs = append(append([]string{}, z.OptionsStrs...), t.OptionsStrs...)
	return eff
}

func collectPolicyNames(cfg *tdns.Config) map[string]bool {
	out := map[string]bool{}
	for name := range cfg.Dnssec.Policies {
		out[name] = true
	}
	return out
}

func listensOnLocalhost(addrs []string) bool {
	for _, a := range addrs {
		host := hostOf(a)
		if host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost") {
			return true
		}
	}
	return false
}

func hostOf(addr string) string {
	addr = strings.TrimSpace(addr)
	// strip [::1]:port form
	if strings.HasPrefix(addr, "[") {
		if i := strings.Index(addr, "]"); i >= 0 {
			return addr[1:i]
		}
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

func firstPort(addrs []string) string {
	for _, a := range addrs {
		if p := portOf(a); p != "" {
			return p
		}
	}
	return ""
}

func portOf(addr string) string {
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, "[") {
		if i := strings.Index(addr, "]"); i >= 0 {
			rest := addr[i+1:]
			if strings.HasPrefix(rest, ":") {
				return rest[1:]
			}
			return ""
		}
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return ""
}

// urlPort extracts the port from a baseurl like https://127.0.0.1:8989/api/v1.
func urlPort(baseurl string) string {
	s := baseurl
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return portOf(s)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string{}, a...)
	sb := append([]string{}, b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

func writeTempYAML(v interface{}) (string, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "configcheck-*.yaml")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func extraLines(s string) []string {
	parts := strings.Split(s, "\n")
	var out []string
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
