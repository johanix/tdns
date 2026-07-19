/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * `tdns-cli imr config check` and `tdns-cli imr config mwe` — the tdns-imr
 * counterparts of the auth config commands. Considerably simpler than auth:
 * tdns-imr has no zones, no DNSSEC policies, no keystore, and no
 * GET /config/paths endpoint, so validation is mostly static (imrengine +
 * apiserver + trust anchors) with a thin online correlation (reachability +
 * apiserver drift via /config status). The shared report model, generic
 * helpers, cert generation and required-field validator are reused from
 * config_check_cmds.go / config_mwe_cmds.go.
 */
package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
)

// NewImrConfigCmd builds the `imr config` command group. tdns-imr has no
// zone/tsig/keystore state, so this group carries just check and mwe (unlike
// auth's config group, which also has reload*/status).
func NewImrConfigCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Validate or generate a tdns-imr configuration",
	}
	c.AddCommand(newImrConfigCheckCmd())
	c.AddCommand(newImrConfigMweCmd())
	return c
}

func init() {
	ImrCmd.AddCommand(NewImrConfigCmd())
}

// ---------------------------------------------------------------------------
// imr config check
// ---------------------------------------------------------------------------

func newImrConfigCheckCmd() *cobra.Command {
	var (
		serverConfig string
		offline      bool
	)
	c := &cobra.Command{
		Use:   "check [config-file]",
		Short: "Validate the tdns-imr config and correlate it with the running daemon",
		Long: `Validate a tdns-imr configuration file for completeness and internal
consistency, and (unless --offline) check that the daemon is reachable and its
apiserver matches the file.

tdns-imr exposes no GET /config/paths endpoint, so the target file is the
positional arg / --serverconfig, else the compiled-in default
(/etc/tdns/tdns-imr.yaml).

Exit status is non-zero if any check FAILs (WARNs do not fail the run).`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 && serverConfig == "" {
				serverConfig = args[0]
			}
			runImrConfigCheck(serverConfig, offline)
		},
	}
	c.Flags().StringVar(&serverConfig, "serverconfig", "", "path to the tdns-imr config file to check (default: /etc/tdns/tdns-imr.yaml)")
	c.Flags().BoolVar(&offline, "offline", false, "do not contact the daemon; run static checks only")
	return c
}

func runImrConfigCheck(explicitPath string, offline bool) {
	tdns.SetSubsystemLevel("config", slog.LevelError)
	rep := newCCReport()

	// imr has no /config/paths; the only online signal is /config status
	// (which for imr carries just the apiserver block).
	online := !offline
	var status tdns.ConfigResponse
	if online {
		if s, err := fetchImrStatus(); err == nil {
			status = s
		} else {
			online = false
			rep.warn("Daemon", "reachability",
				fmt.Sprintf("could not reach the imr daemon: %v; running static checks only", err),
				"start the daemon (or pass --offline) to enable apiserver correlation")
		}
	}

	cfgPath := explicitPath
	if cfgPath == "" {
		cfgPath = tdns.DefaultImrCfgFile
	}
	cfgPath = absClean(cfgPath)

	fmt.Printf("Checking imr config: %s\n", cfgPath)
	if online {
		fmt.Printf("Correlating against the running imr daemon.\n")
	}
	fmt.Println()

	v, loadErr := loadConfigViper(cfgPath, rep)
	if loadErr != nil {
		rep.fail("Config file", "load", fmt.Sprintf("cannot load %s: %v", cfgPath, loadErr),
			"fix the YAML syntax / missing file, then re-run")
		finishCheckconf(rep)
		return
	}
	rep.pass("Config file", "load", "config file (and includes) parsed as YAML")

	checkRequiredFields(v, cfgPath, rep, tdns.AppTypeImr)

	var cfg tdns.Config
	if err := v.Unmarshal(&cfg); err != nil {
		rep.warn("Config file", "decode",
			fmt.Sprintf("could not fully decode config into structs: %v", err), "")
	}

	checkImrEngine(&cfg, rep)
	checkImrTrustAnchors(&cfg, rep)
	checkImrApiServer(&cfg, v, rep)
	checkApiServerCorrelation("imr", &cfg, rep)

	if online {
		correlateImrApiServer(&cfg, status, rep)
	}

	finishCheckconf(rep)
}

func checkImrEngine(cfg *tdns.Config, rep *ccReport) {
	const g = "IMR engine"
	if len(cfg.Imr.Addresses) == 0 {
		rep.fail(g, "addresses", "imrengine.addresses is empty — the resolver would not listen on any address",
			"add at least one addr:port, e.g. [ 127.0.0.1:53, '[::1]:53' ]")
	} else {
		rep.pass(g, "addresses", fmt.Sprintf("listening on %v", cfg.Imr.Addresses))
	}

	validT := map[string]bool{"do53": true, "dot": true, "doh": true, "doq": true}
	if len(cfg.Imr.Transports) == 0 {
		rep.fail(g, "transports", "imrengine.transports is empty", "list at least one of do53, dot, doh, doq")
	}
	needCert := false
	for _, t := range cfg.Imr.Transports {
		lt := lc(t)
		if !validT[lt] {
			rep.fail(g, "transports", fmt.Sprintf("unknown transport %q", t), "valid transports are do53, dot, doh, doq")
			continue
		}
		if lt != "do53" {
			needCert = true
		}
	}
	if needCert {
		if cfg.Imr.CertFile == "" || cfg.Imr.KeyFile == "" {
			rep.warn(g, "cert", "dot/doh/doq configured but imrengine.certfile/keyfile not set — those listeners will be skipped",
				"set imrengine.certfile and imrengine.keyfile, or remove the encrypted transports")
		} else {
			checkFileExists(rep, g, "certfile", cfg.Imr.CertFile)
			checkFileExists(rep, g, "keyfile", cfg.Imr.KeyFile)
		}
	}
	if cfg.Imr.RootHints != "" {
		checkFileExists(rep, g, "root-hints", cfg.Imr.RootHints)
	}
}

// checkImrTrustAnchors flags the classic imr footgun: DNSSEC validation is on
// by default, but if no trust anchor is configured the resolver validates
// against an empty anchor set and returns SERVFAIL/bogus for everything.
func checkImrTrustAnchors(cfg *tdns.Config, rep *ccReport) {
	const g = "Trust anchors"
	hasAnchor := cfg.Imr.TrustAnchorDS != "" || cfg.Imr.TrustAnchorDNSKEY != "" || cfg.Imr.TrustAnchorFile != ""
	requireValidation := cfg.Imr.RequireDnssecValidation == nil || *cfg.Imr.RequireDnssecValidation

	if cfg.Imr.TrustAnchorFile != "" {
		checkFileExists(rep, g, "trust-anchor-file", cfg.Imr.TrustAnchorFile)
	}

	switch {
	case hasAnchor:
		rep.pass(g, "anchor", "a DNSSEC trust anchor is configured")
	case !requireValidation:
		rep.info(g, "anchor", "no trust anchor, but require_dnssec_validation is false (lab mode) — validation disabled")
	default:
		rep.fail(g, "anchor",
			"no trust anchor configured and DNSSEC validation is on (the default) — the resolver validates against an empty anchor set and everything is BOGUS",
			"set imrengine.trust-anchor-file (or trust_anchor_ds), or set imrengine.require_dnssec_validation: false for lab use")
	}
}

func checkImrApiServer(cfg *tdns.Config, v *viper.Viper, rep *ccReport) {
	const g = "API server"
	if len(cfg.ApiServer.Addresses) == 0 {
		rep.info(g, "addresses", "apiserver.addresses is empty — the management API will not listen (the resolver still runs)")
		return
	}
	rep.pass(g, "addresses", fmt.Sprintf("listening on %v", cfg.ApiServer.Addresses))

	if cfg.ApiServer.ApiKey.Value() == "" {
		rep.fail(g, "apikey", "apiserver.apikey is empty — the imr API router refuses to start without it",
			"set a long random apiserver.apikey")
	} else {
		rep.pass(g, "apikey", "apiserver.apikey is set")
	}

	// usetls defaults TRUE for imr unless explicitly set false.
	usetls := true
	if v.IsSet("apiserver.usetls") {
		usetls = v.GetBool("apiserver.usetls")
	}
	if usetls {
		if cfg.ApiServer.CertFile == "" || cfg.ApiServer.KeyFile == "" {
			rep.fail(g, "cert", "apiserver.usetls is true (the imr default) but certfile/keyfile are not set — the API listener fails to start",
				"set apiserver.certfile/keyfile (see `tdns-cli imr config mwe`) or set usetls: false")
		} else {
			checkFileExists(rep, g, "certfile", cfg.ApiServer.CertFile)
			checkFileExists(rep, g, "keyfile", cfg.ApiServer.KeyFile)
		}
	} else {
		rep.info(g, "usetls", "apiserver.usetls is false — plaintext management API")
	}
}

// ---------------------------------------------------------------------------
// imr online correlation (thin: apiserver only)
// ---------------------------------------------------------------------------

func fetchImrStatus() (tdns.ConfigResponse, error) {
	api, err := GetApiClient("imr", false)
	if err != nil {
		return tdns.ConfigResponse{}, err
	}
	resp, err := SendConfigCommand(api, tdns.ConfigPost{Command: "status"})
	if err != nil {
		return tdns.ConfigResponse{}, err
	}
	return resp, nil
}

func correlateImrApiServer(cfg *tdns.Config, status tdns.ConfigResponse, rep *ccReport) {
	const g = "Running-config drift"
	if status.ApiServer.ApiKey.Value() != "" && cfg.ApiServer.ApiKey.Value() != "" &&
		status.ApiServer.ApiKey.Value() != cfg.ApiServer.ApiKey.Value() {
		rep.warn(g, "apikey",
			"apiserver.apikey in the file differs from the running server's apikey",
			"the running apikey changes only on restart")
	}
	if len(status.ApiServer.Addresses) > 0 && len(cfg.ApiServer.Addresses) > 0 &&
		!sameStringSet(cfg.ApiServer.Addresses, status.ApiServer.Addresses) {
		rep.warn(g, "apiserver-addresses",
			fmt.Sprintf("config apiserver.addresses %v differ from running %v", cfg.ApiServer.Addresses, status.ApiServer.Addresses),
			"apiserver listen addresses change only on restart")
	}
	rep.pass(g, "apiserver", "correlated apiserver against the running daemon")
}

// ---------------------------------------------------------------------------
// imr config mwe
// ---------------------------------------------------------------------------

func newImrConfigMweCmd() *cobra.Command {
	var dir string
	c := &cobra.Command{
		Use:   "mwe",
		Short: "Generate a minimal working example config (+ cert) for tdns-imr",
		Long: `Generate a Minimal Working Example configuration for tdns-imr.

Writes a single self-contained YAML to <dir>/tdns-imr.yaml (or <dir>/tdns-imr.yaml.mwe
if that file already exists), and generates a self-signed cert/key pair under
<dir>/certs unless one is already there. The resolver listens on IPv4 and IPv6
localhost; DNSSEC validation is disabled so it resolves out of the box (the
config shows, commented, how to turn it into a validating resolver). The
generated tree passes ` + "`tdns-cli imr config check`" + `.`,
		Run: func(cmd *cobra.Command, args []string) {
			runImrConfigMwe(dir)
		},
	}
	c.Flags().StringVar(&dir, "dir", "/etc/tdns", "base directory for the generated config and cert")
	return c
}

func runImrConfigMwe(dir string) {
	dir = filepath.Clean(dir)
	cfgPath := filepath.Join(dir, "tdns-imr.yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		cfgPath += ".mwe"
		fmt.Printf("Config %s already exists; writing MWE to %s instead.\n",
			filepath.Join(dir, "tdns-imr.yaml"), cfgPath)
	}

	certsDir := filepath.Join(dir, "certs")
	for _, d := range []string{dir, certsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			cliFatalf("could not create directory %s: %v", d, err)
		}
	}

	certFile := filepath.Join(certsDir, "localhost.crt")
	keyFile := filepath.Join(certsDir, "localhost.key")
	certCreated, err := ensureSelfSignedCert(certFile, keyFile)
	if err != nil {
		cliFatalf("could not generate certificate: %v", err)
	}

	apiKey, err := randomAPIKey()
	if err != nil {
		cliFatalf("could not generate api key: %v", err)
	}

	apiPort := "8080"
	dnsPort := "5353"
	content := renderImrMweConfig(dir, certFile, keyFile, apiKey, apiPort, dnsPort)
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		cliFatalf("could not write config %s: %v", cfgPath, err)
	}

	fmt.Printf("\nWrote MWE config:  %s\n", cfgPath)
	if certCreated {
		fmt.Printf("Generated cert:    %s\n", certFile)
		fmt.Printf("Generated key:     %s\n", keyFile)
	} else {
		fmt.Printf("Reused cert/key:   %s , %s\n", certFile, keyFile)
	}

	fmt.Printf("\nTo let `tdns-cli imr ...` reach this server, add to your tdns-cli.yaml:\n\n")
	fmt.Printf("  apiservers:\n")
	fmt.Printf("     - name:       tdns-imr\n")
	fmt.Printf("       baseurl:    https://127.0.0.1:%s/api/v1\n", apiPort)
	fmt.Printf("       apikey:     %s\n", apiKey)
	fmt.Printf("       authmethod: X-API-Key\n")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  tdns-imr --config %s        # start the resolver\n", cfgPath)
	fmt.Printf("  tdns-cli imr config check --serverconfig %s   # validate\n", cfgPath)
}

func renderImrMweConfig(dir, certFile, keyFile, apiKey, apiPort, dnsPort string) string {
	r := strings.NewReplacer(
		"{{DIR}}", dir,
		"{{CERT}}", certFile,
		"{{KEY}}", keyFile,
		"{{APIKEY}}", apiKey,
		"{{APIPORT}}", apiPort,
		"{{DNSPORT}}", dnsPort,
	)
	return r.Replace(imrMweConfigTemplate)
}

const imrMweConfigTemplate = `# Minimal Working Example — tdns-imr
#
# Generated by ` + "`tdns-cli imr config mwe`" + `. Self-contained: one file plus a
# self-signed cert. Validate it any time with:
#   tdns-cli imr config check --serverconfig <this file>

imrengine:
   # Listen on IPv4 and IPv6 localhost. Port {{DNSPORT}} is used so the resolver
   # runs unprivileged; use 53 for a real deployment (needs root/capabilities).
   addresses:   [ 127.0.0.1:{{DNSPORT}}, '[::1]:{{DNSPORT}}' ]
   #   addresses: [ 127.0.0.1:{{DNSPORT}}, '[::1]:{{DNSPORT}}', 192.0.2.53:53 ]
   transports:  [ do53 ]
   # For encrypted transports the cert/key below are ready to use:
   #   transports: [ do53, dot, doh, doq ]
   # certfile:  {{CERT}}
   # keyfile:   {{KEY}}

   # DNSSEC validation is DISABLED in this MWE so the resolver answers out of
   # the box without a root trust anchor. To make it a validating resolver,
   # supply a root anchor and flip this to true:
   #   trust-anchor-file:          /etc/tdns/root.key
   #   require_dnssec_validation:  true
   # or paste the current root DS inline:
   #   trust_anchor_ds: ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
   require_dnssec_validation:  false

apiserver:
   addresses:  [ 127.0.0.1:{{APIPORT}} ]
   apikey:     {{APIKEY}}
   certfile:   {{CERT}}
   keyfile:    {{KEY}}
   usetls:     true

log:
   file:   {{DIR}}/tdns-imr.log
   level:  info
`
