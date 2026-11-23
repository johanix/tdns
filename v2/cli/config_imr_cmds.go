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
// zone/tsig/keystore state, so this group carries check, mwe and status
// (unlike auth's config group, which also has reload*).
func NewImrConfigCmd() *cobra.Command {
	return NewImrConfigCmdFor("imr")
}

// NewImrConfigCmdFor is NewImrConfigCmd for a given instance: role is the key
// GetApiClient resolves, "imr" for the canonical tdns-imr and the instance's
// own name for an extra one. check and status talk to THAT daemon, and check
// reads that instance's config-file by default.
func NewImrConfigCmdFor(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Validate or generate a tdns-imr configuration",
	}
	c.AddCommand(newImrConfigCheckCmd(role))
	c.AddCommand(newImrConfigMweCmd(role))
	c.AddCommand(newImrConfigStatusCmd(role))
	return c
}

// ---------------------------------------------------------------------------
// imr config status
// ---------------------------------------------------------------------------

func newImrConfigStatusCmd(role string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report the running tdns-imr daemon's status, including priming and forward upstreams",
		Long: `Query the running tdns-imr daemon's /config status endpoint and report:
overall health (active server errors), whether the resolver cache is primed
and how, and the configured stub and forward zones with per-upstream
reachability (fed by the startup probe and live queries), plus the
process's descriptor and goroutine counts (tdns#443).`,
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := fetchImrStatus(role)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			if resp.Error {
				fmt.Printf("Error from %s: %s\n", resp.AppName, resp.ErrorMsg)
				os.Exit(1)
			}
			printImrConfigStatus(resp)
		},
	}
}

// printImrConfigStatus prints a tdns-imr daemon's `config status` reply.
func printImrConfigStatus(resp tdns.ConfigResponse) {
	fmt.Println(resp.Msg)
	if len(resp.ServerErrors) > 0 {
		fmt.Printf("Active errors:\n")
		for _, e := range resp.ServerErrors {
			fmt.Printf("  [%s/%s] %s\n", e.Category, e.Subtype, e.Message)
		}
	}
	if line := apiSocketStatusLine(resp); line != "" {
		fmt.Println(line)
	}
	// As in the auth printer: a TCP API an access file stopped stays
	// stopped after the file is removed, so this does not depend on Access.
	printApiTCPStopped(resp.ApiTCPStopped, resp.ApiTCPStoppedBy, resp.Access != nil)
	// Proc renders BEFORE the nil-Imr return: a daemon whose IMR
	// init failed (the Upstream/ImrPriming husk) is precisely a
	// moment to look at process resources, not to hide them.
	renderProcStatus(resp.Proc)
	printAccessStatus(resp.Access)
	if resp.Imr == nil {
		fmt.Println("IMR: no resolver state reported (engine not running)")
		return
	}
	renderImrStatus(resp.Imr)
}

func init() {
	ImrCmd.AddCommand(NewImrConfigCmd())
}

// ---------------------------------------------------------------------------
// imr config check
// ---------------------------------------------------------------------------

func newImrConfigCheckCmd(role string) *cobra.Command {
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
positional arg / --serverconfig, else the config-file: recorded for this daemon
in the CLI config, else the compiled-in default (/etc/tdns/tdns-imr.yaml).

Exit status is non-zero if any check FAILs (WARNs do not fail the run).`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 && serverConfig == "" {
				serverConfig = args[0]
			}
			runImrConfigCheck(role, serverConfig, offline)
		},
	}
	c.Flags().StringVar(&serverConfig, "serverconfig", "", "path to the tdns-imr config file to check (default: this daemon's config-file:, else /etc/tdns/tdns-imr.yaml)")
	c.Flags().BoolVar(&offline, "offline", false, "do not contact the daemon; run static checks only")
	return c
}

func runImrConfigCheck(role, explicitPath string, offline bool) {
	tdns.SetSubsystemLevel("config", slog.LevelError)
	rep := newCCReport()

	// imr has no /config/paths; the only online signal is /config status
	// (which for imr carries just the apiserver block).
	online := !offline
	var status tdns.ConfigResponse
	if online {
		if s, err := fetchImrStatus(role); err == nil {
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
		// The entry's config-file: if it has one, else tdns-imr's default.
		cfgPath = defaultCfgFileForRole(role)
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
	checkLogSection(v, cfgPath, rep)

	checkRequiredFields(v, cfgPath, rep, tdns.AppTypeImr)

	var cfg tdns.Config
	if err := v.Unmarshal(&cfg); err != nil {
		rep.warn("Config file", "decode",
			fmt.Sprintf("could not fully decode config into structs: %v", err), "")
	}
	// The socket the daemon serves, and its API certificate (looked for, not
	// written), as ParseConfig fills them in.
	cfg.ApiServer.Socket = tdns.ApiSocketPath(cfg.ApiServer.Socket, cfgPath)
	cfg.ApiServer.LookupCertDefaults(cfgPath)

	checkImrEngine(&cfg, rep)
	checkImrTrustAnchors(&cfg, rep)
	checkImrApiServer(&cfg, v, rep)
	checkApiServerCorrelation(role, &cfg, rep)

	if online {
		correlateImrApiServer(&cfg, status, acceptedApiKey(role), rep)
	}

	finishCheckconf(rep)
}

func checkImrEngine(cfg *tdns.Config, rep *ccReport) {
	const g = "IMR engine"
	if len(cfg.Listeners.Addresses) == 0 {
		rep.fail(g, "addresses", "listeners.addresses is empty — the resolver would not listen on any address",
			"add at least one addr:port, e.g. [ 127.0.0.1:53, '[::1]:53' ]")
	} else {
		rep.pass(g, "addresses", fmt.Sprintf("listening on %v", cfg.Listeners.Addresses))
	}

	validT := map[string]bool{"do53": true, "dot": true, "doh": true, "doq": true}
	if len(cfg.Listeners.Transports) == 0 {
		rep.fail(g, "transports", "listeners.transports is empty", "list at least one of do53, dot, doh, doq")
	}
	needCert, doh := false, false
	for _, t := range cfg.Listeners.Transports {
		lt := lc(t)
		if !validT[lt] {
			rep.fail(g, "transports", fmt.Sprintf("unknown transport %q", t), "valid transports are do53, dot, doh, doq")
			continue
		}
		if lt != "do53" {
			needCert = true
		}
		if lt == "doh" {
			doh = true
		}
	}
	checkDoHPath(cfg, rep, g, doh)
	if needCert {
		if cfg.Listeners.CertFile == "" || cfg.Listeners.KeyFile == "" {
			rep.warn(g, "cert", "dot/doh/doq configured but listeners.certfile/keyfile not set — those listeners will be skipped",
				"set listeners.certfile and listeners.keyfile, or remove the encrypted transports")
		} else {
			checkFileExists(rep, g, "certfile", cfg.Listeners.CertFile)
			checkFileExists(rep, g, "keyfile", cfg.Listeners.KeyFile)
		}
	}
	if cfg.Imr.RootHints != "" {
		checkFileExists(rep, g, "root-hints", cfg.Imr.RootHints)
	}
	switch v4, v6, err := tdns.ParseAddressFamilies(cfg.Imr.OutboundAddressFamilies); {
	case err != nil:
		rep.fail(g, "outbound-address-families", "imrengine.outbound-address-families: "+err.Error()+" — the resolver would not start",
			"list ipv4, ipv6, or both, e.g. [ ipv4, ipv6 ]")
	case !v6:
		rep.pass(g, "outbound-address-families", "IPv4 only: IPv6 addresses of authoritative servers are neither looked up nor used")
	case !v4:
		rep.pass(g, "outbound-address-families", "IPv6 only: IPv4 addresses of authoritative servers are neither looked up nor used")
	}
	t := cfg.Imr.Testing
	if t.SkipPriming() {
		rep.warn(g, "testing",
			"imrengine.testing.priming is false: the resolver seeds its cache from the root hints and never primes."+
				" This is a test-harness switch, not for production",
			"remove imrengine.testing from a production config")
	}
	switch err := t.Validate(); {
	case err != nil:
		rep.fail(g, "testing", "imrengine.testing: "+err.Error()+" — the resolver would not start",
			"remove root-refresh, or faketime")
	case t.FaketimeOn():
		file := t.FaketimePath()
		if file == "" {
			file = "$FAKETIME_TIMESTAMP_FILE, which is not set here"
		}
		rep.warn(g, "testing",
			"imrengine.testing.faketime is on: signatures, cache expiry and served TTLs follow a test clock read from "+file+
				", and the root NS is not refreshed. This is a test-harness switch, not for production",
			"remove imrengine.testing from a production config")
	case t.SkipRootRefresh():
		rep.warn(g, "testing",
			"imrengine.testing.root-refresh is false: the root NS is not refreshed before it expires."+
				" This is a test-harness switch, not for production",
			"remove imrengine.testing from a production config")
	}
}

// checkImrTrustAnchors says which trust anchor the resolver will use. With
// none configured it uses the compiled-in IANA root anchor, but only with the
// compiled-in root hints and the root neither forwarded nor stubbed: anything
// else may be a private root, and the resolver then has no anchor and
// validates nothing (every answer Indeterminate). That case is the footgun:
// validation is on by default.
func checkImrTrustAnchors(cfg *tdns.Config, rep *ccReport) {
	const g = "Trust anchors"
	requireValidation := cfg.Imr.RequireDnssecValidation == nil || *cfg.Imr.RequireDnssecValidation

	if cfg.Imr.TrustAnchorFile != "" {
		checkFileExists(rep, g, "trust-anchor-file", cfg.Imr.TrustAnchorFile)
	}

	useDefault, why := cfg.Imr.RootAnchorFallback()
	switch {
	case cfg.Imr.AnchorConfigured():
		rep.pass(g, "anchor", "a DNSSEC trust anchor is configured")
	case useDefault:
		rep.pass(g, "anchor", "no trust anchor configured: the compiled-in IANA root anchor is used,"+
			" as the root hints are the compiled-in ones and the root is neither forwarded nor stubbed")
	case !requireValidation:
		rep.info(g, "anchor", fmt.Sprintf("no trust anchor, and the compiled-in root anchor is not used (%s);"+
			" require-dnssec-validation is false (lab mode), so lookups that require validation do without it", why))
	default:
		rep.fail(g, "anchor",
			fmt.Sprintf("no trust anchor configured, and the compiled-in root anchor is not used because %s"+
				" (the root may be a private one): nothing validates, every answer is Indeterminate,"+
				" and lookups that require validation fail", why),
			"set imrengine.trust-anchor-file or trust-anchor-ds for the root in use (the compiled-in IANA root"+
				" anchor is used only when nothing is set and the root hints are the compiled-in ones),"+
				" or set imrengine.require-dnssec-validation: false for lab use")
	}
}

func checkImrApiServer(cfg *tdns.Config, v *viper.Viper, rep *ccReport) {
	const g = "API server"
	// tdns-imr builds its API router whatever the addresses say, and stops
	// at startup if that fails, so the key is checked first, for every case.
	if cfg.ApiServer.ApiKey.Value() == "" {
		rep.fail(g, "apikey", "apiserver.apikey is empty — the imr API router refuses to start without it",
			"set a long random apiserver.apikey")
	} else {
		rep.pass(g, "apikey", "apiserver.apikey is set")
	}
	sock := cfg.ApiServer.Socket
	var sockErr error
	if sock != "" {
		if sockErr = tdns.CheckApiSocketPath(sock); sockErr != nil {
			rep.warn(g, "socket", fmt.Sprintf("%v: the daemon does not serve the local admin socket", sockErr), socketPathHint)
		}
	}
	if len(cfg.ApiServer.Addresses) == 0 {
		if sock != "" && sockErr == nil {
			rep.info(g, "addresses", fmt.Sprintf("apiserver.addresses is empty: the management API is served only on the local admin socket %s", sock))
		} else {
			rep.info(g, "addresses", "apiserver.addresses is empty — the management API will not listen (the resolver still runs)")
		}
		return
	}
	rep.pass(g, "addresses", fmt.Sprintf("listening on %v", cfg.ApiServer.Addresses))

	// usetls defaults TRUE for imr unless explicitly set false.
	usetls := true
	if v.IsSet("apiserver.usetls") {
		usetls = v.GetBool("apiserver.usetls")
	}
	if usetls {
		if cfg.ApiServer.CertPending {
			rep.info(g, "cert", "no apiserver.certfile/keyfile: the daemon writes a self-signed pair (certs/<config name>-api.crt and .key, next to its config) when it first starts")
		} else if cfg.ApiServer.CertFile == "" || cfg.ApiServer.KeyFile == "" {
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

func fetchImrStatus(role string) (tdns.ConfigResponse, error) {
	api, err := GetApiClient(role, false)
	if err != nil {
		return tdns.ConfigResponse{}, err
	}
	resp, err := SendConfigCommand(api, tdns.ConfigPost{Command: "status"})
	if err != nil {
		return tdns.ConfigResponse{}, err
	}
	return resp, nil
}

// correlateImrApiServer compares the file's apiserver block with the running
// resolver's. acceptedKey is the API key the status request was sent with:
// the reply came back, so the resolver accepted it. The reply itself no
// longer carries the key (it is redacted).
func correlateImrApiServer(cfg *tdns.Config, status tdns.ConfigResponse, acceptedKey string, rep *ccReport) {
	const g = "Running-config drift"
	warnApiKeyDrift(cfg, acceptedKey, rep, g)
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

func newImrConfigMweCmd(role string) *cobra.Command {
	var dir string
	c := &cobra.Command{
		Use:   "mwe",
		Short: "Generate a minimal working example config (+ cert) for tdns-imr",
		Long: `Generate a Minimal Working Example configuration for tdns-imr.

Writes a single self-contained YAML to <dir>/tdns-imr.yaml, or, for an extra
instance, to the config-file: of its apiservers entry. If that file already
exists the MWE goes to <file>.mwe instead. A self-signed
cert/key pair is generated under <dir>/certs unless one is already there. The
resolver listens on IPv4 and IPv6 localhost; DNSSEC validation is disabled so it
resolves out of the box (the config shows, commented, how to turn it into a
validating resolver). The generated tree passes ` + "`tdns-cli imr config check`" + `.

An extra instance (tdns-ncli imr2 config mwe) needs a config-file: on its entry,
or --dir: without either the only name there is to write is the canonical
resolver's tdns-imr.yaml.`,
		Run: func(cmd *cobra.Command, args []string) {
			cfgPath, err := imrMwePath(role, dir, cmd.Flags().Changed("dir"))
			if err != nil {
				cliFatalf("%v", err)
			}
			runImrConfigMwe(role, cfgPath)
		},
	}
	c.Flags().StringVar(&dir, "dir", "/etc/tdns", "base directory for the generated config and cert (for an extra instance the default is the directory of its config-file:)")
	return c
}

// imrMwePath is the file `config mwe` writes for role. For an extra instance
// it is the entry's config-file: when there is one (with --dir moving it to
// another directory), else tdns-imr.yaml in dir. The canonical resolver keeps
// what `imr config mwe` has always written, tdns-imr.yaml in dir, whatever its
// entry's config-file: says: tdns-cli runs this same command.
//
// An extra instance with neither a config-file: nor --dir is refused: the
// fallback name is the canonical resolver's file, so writing it would create
// the wrong daemon's config (in /etc/tdns, next to the real one).
func imrMwePath(role, dir string, dirGiven bool) (string, error) {
	cf := ""
	if ad := apiDetailsForRole(role); ad != nil && role != "imr" {
		cf = ad.ConfigFile
	}
	switch {
	case cf != "":
		if !dirGiven {
			return filepath.Clean(cf), nil
		}
		return filepath.Join(filepath.Clean(dir), filepath.Base(cf)), nil
	case role != "imr" && !dirGiven:
		return "", fmt.Errorf("%s has no config-file: in the CLI config, so config mwe does not know where its config goes; set config-file: on its apiservers entry, or give --dir", role)
	}
	return filepath.Join(filepath.Clean(dir), "tdns-imr.yaml"), nil
}

func runImrConfigMwe(role, cfgPath string) {
	dir := filepath.Dir(cfgPath)
	existing := ""
	if _, err := os.Stat(cfgPath); err == nil {
		existing = cfgPath
		cfgPath += ".mwe"
		fmt.Printf("Config %s already exists; writing MWE to %s instead.\n", existing, cfgPath)
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

	if role == "imr" {
		fmt.Printf("\nTo let `tdns-cli imr ...` reach this server, add to your tdns-cli.yaml:\n\n")
		fmt.Printf("  apiservers:\n")
		fmt.Printf("     - name:       tdns-imr\n")
	} else {
		// An extra instance lives in tdns-ncli's own config, where its entry
		// already exists; say what it should hold.
		// config-file: is the file the start command below uses, so a later
		// `config check` reads the config this key and port came from. An
		// existing file (with its own key and port) is left alone.
		fmt.Printf("\nThe CLI entry for %s should read:\n\n", role)
		fmt.Printf("     - name:        %s\n", role)
		fmt.Printf("       role:        imr\n")
		fmt.Printf("       config-file: %s\n", cfgPath)
	}
	fmt.Printf("       baseurl:    https://127.0.0.1:%s/api/v1\n", apiPort)
	fmt.Printf("       apikey:     %s\n", apiKey)
	fmt.Printf("       authmethod: X-API-Key\n")
	if role != "imr" {
		fmt.Printf("\nThe MWE uses API port %s and DNS port %s. A second resolver on the same\nhost needs ports of its own: change them before starting it.\n", apiPort, dnsPort)
	}
	if existing != "" {
		fmt.Printf("\n%s is left as it was. If you move the MWE over it, use that path instead.\n", existing)
	}
	// An instance is checked through its own entry: `imr config check` would
	// compare the file with the canonical resolver's port and key.
	check := "tdns-cli imr config check"
	if role != "imr" {
		check = "tdns-ncli " + role + " config check"
	}
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  tdns-imr --config %s        # start the resolver\n", cfgPath)
	fmt.Printf("  %s --serverconfig %s   # validate\n", check, cfgPath)
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

listeners:
   # Listen on IPv4 and IPv6 localhost. Port {{DNSPORT}} is used so the resolver
   # runs unprivileged; use 53 for a real deployment (needs root/capabilities).
   addresses:   [ 127.0.0.1:{{DNSPORT}}, '[::1]:{{DNSPORT}}' ]
   #   addresses: [ 127.0.0.1:{{DNSPORT}}, '[::1]:{{DNSPORT}}', 192.0.2.53:53 ]
   transports:  [ do53 ]
   # For encrypted transports the cert/key below are ready to use:
   #   transports: [ do53, dot, doh, doq ]
   #   ports:
   #      dot: [ 853 ]
   #      doh: [ 443 ]
   #      doq: [ 853 ]
   #   doh-path: /dns-query   # the one path DoH answers on; this is the default
   # certfile:  {{CERT}}
   # keyfile:   {{KEY}}

imrengine:
   # No trust anchor is set and the root hints are the compiled-in ones, so
   # the resolver validates against the compiled-in IANA root anchor. To name
   # the anchor yourself (needed with a root-hints file or a forwarded root):
   #   trust-anchor-file:          /etc/tdns/root.key
   # or paste the root DS records inline, one per line:
   #   trust-anchor-ds: |
   #      . IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
   #      . IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
   # Validation is not ENFORCED in this MWE: the lookups that need a secure
   # answer (TLSA and the like) take one that is not. Flip this to true to
   # enforce it.
   require-dnssec-validation:  false

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
