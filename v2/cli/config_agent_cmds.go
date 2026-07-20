/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent-specific parts of `tdns-cli agent config check` and the tdns-agent
 * variant of `tdns-cli agent config mwe`.
 *
 * The bulk of `config check` is shared with auth (config_check_cmds.go): the
 * agent uses the same Config struct, the same required-field validation
 * (ValidateConfig treats AppTypeAgent exactly like AppTypeAuth), the same
 * dnsengine/apiserver/zone/TSIG machinery, and the same mgmt-API endpoints
 * minus GET /config/paths. What lives here is only what genuinely differs:
 * config this binary silently ignores, and options the agent rejects.
 */
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/viper"
)

// ---------------------------------------------------------------------------
// Agent-specific static checks
// ---------------------------------------------------------------------------

// checkAgentSpecifics reports the ways a tdns-agent config differs from the
// auth config it otherwise shares a schema with. Each check predicts a concrete
// startup behaviour: a block this binary cannot parse, a subsystem the
// required-field validator does not cover, or an option the agent refuses.
func checkAgentSpecifics(cfg *tdns.Config, v *viper.Viper, rep *ccReport) {
	checkAgentInertConfig(cfg, v, rep)
	checkAgentImrEngine(cfg, v, rep)
	checkAgentZoneOptions(cfg, v, rep)
}

// checkAgentInertConfig flags config blocks that a standalone tdns-agent parses
// into nothing. These are the highest-surprise findings: the YAML is well
// formed and the daemon starts, but the block has no effect whatsoever.
func checkAgentInertConfig(cfg *tdns.Config, v *viper.Viper, rep *ccReport) {
	const g = "Agent-specific"

	// multi-provider: has no field in tdns.Config in this repo — the struct is
	// owned by tdns-mp. A standalone tdns-agent drops the whole subtree into
	// mapstructure's Unused set, where it surfaces only as a generic "unknown
	// config keys ignored (possible misspellings)" warning in the log.
	if v.Get("multi-provider") != nil {
		rep.warn(g, "multi-provider",
			"a multi-provider: block is present, but standalone tdns-agent cannot parse it — the entire block is ignored",
			"remove it, or run tdns-mpagent (tdns-mp) if you need the multi-provider role")
	}

	// The agent never signs: SetupZoneSigning returns early for AppTypeAgent
	// and no ResignerEngine/KeyStateWorker is started. A dnssec: block is still
	// parsed (and a malformed one is startup-fatal), so this is INFO, not WARN:
	// the policies are validated above, they just never sign anything.
	if len(cfg.Dnssec.Policies) > 0 {
		rep.info(g, "dnssec",
			fmt.Sprintf("%d DNSSEC policy definition(s) present; tdns-agent never signs, so these only gate zone dnssecpolicy: references",
				len(cfg.Dnssec.Policies)))
	}
}

// checkAgentImrEngine sanity-checks imrengine:. The agent starts an in-process
// IMR, but ValidateConfig only enforces imrengine for AppTypeImr — so for the
// agent this block is entirely unvalidated and a bad one fails at engine start.
func checkAgentImrEngine(cfg *tdns.Config, v *viper.Viper, rep *ccReport) {
	const g = "Agent-specific"

	if v.Get("imrengine") == nil {
		rep.info(g, "imrengine", "no imrengine: block; the agent runs with IMR defaults")
		return
	}
	// Tri-state: nil or true means active, matching the daemon
	// (imrActive := conf.Imr.Active == nil || *conf.Imr.Active).
	if !(cfg.Imr.Active == nil || *cfg.Imr.Active) {
		rep.info(g, "imrengine", "imrengine.active is false; the in-process resolver is disabled")
		return
	}
	if len(cfg.Imr.Addresses) == 0 {
		rep.warn(g, "imrengine",
			"imrengine is active but has no addresses: — the resolver listener will not be started",
			"set imrengine.addresses (e.g. [ 127.0.0.1:5453, '[::1]:5453' ]) or set active: false")
	}
	if rh := v.GetString("imrengine.root-hints"); rh != "" {
		if _, err := os.Stat(rh); err != nil {
			rep.fail(g, "imrengine",
				fmt.Sprintf("imrengine.root-hints %s not found: %v", rh, err),
				"create the file or fix the path")
			return
		}
	}
	if len(cfg.Imr.Addresses) > 0 {
		rep.pass(g, "imrengine",
			fmt.Sprintf("in-process resolver active on %d address(es)", len(cfg.Imr.Addresses)))
	}
}

// checkAgentZoneOptions checks the two zone options whose validity depends on
// the app being an agent. Both put the zone in ConfigError state at startup
// when misapplied, so both are predictable statically.
func checkAgentZoneOptions(cfg *tdns.Config, v *viper.Viper, rep *ccReport) {
	const g = "Agent-specific"

	templates := map[string]tdns.ZoneConf{}
	for _, t := range cfg.Templates {
		templates[lc(t.Name)] = t
	}
	childSchemes := v.GetStringSlice("delegationsync.child.schemes")

	for i := range cfg.Zones {
		eff := effectiveZone(cfg.Zones[i], templates)
		zname := cfg.Zones[i].Name
		if zname == "" {
			continue
		}
		opts := map[string]bool{}
		for _, o := range eff.OptionsStrs {
			opts[lc(o)] = true
		}

		// delegation-sync-proxy is valid ONLY on an agent secondary.
		if opts["delegation-sync-proxy"] && lc(eff.Type) != "secondary" {
			rep.fail(g, zname,
				fmt.Sprintf("delegation-sync-proxy requires a secondary zone (this zone is %q) — it will be quarantined at startup",
					eff.Type),
				"set type: secondary, or drop the delegation-sync-proxy option")
		}

		// On an agent, delegation-sync-child only engages when the zone also
		// carries multi-provider; otherwise the setup block is skipped and the
		// option is silently inert.
		if opts["delegation-sync-child"] {
			switch {
			case !opts["multi-provider"]:
				rep.warn(g, zname,
					"delegation-sync-child without multi-provider is inert on tdns-agent — child delegation sync will not run",
					"add the multi-provider option, or host the zone on tdns-auth where delegation-sync-child works standalone")
			case len(childSchemes) == 0:
				rep.fail(g, zname,
					"delegation-sync-child is enabled but delegationsync.child.schemes is empty — the zone will be quarantined",
					"set delegationsync.child.schemes (e.g. [ notify, update ])")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Agent MWE
// ---------------------------------------------------------------------------

// runAgentConfigMwe generates a minimal working tdns-agent tree. It differs
// from the auth MWE in what it can legally contain: tdns-agent refuses primary
// zones and never signs, so there are no zone files and no dnssec: block to
// generate. The result is a zone-less agent that starts clean; two secondary
// templates and a commented-out secondary zone show how to add one.
func runAgentConfigMwe(role, dir string) {
	dir = filepath.Clean(dir)
	cfgPath := filepath.Join(dir, "tdns-"+role+".yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		cfgPath += ".mwe"
		fmt.Printf("Config %s already exists; writing MWE to %s instead.\n",
			filepath.Join(dir, "tdns-"+role+".yaml"), cfgPath)
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

	apiPort := "8987"
	dnsPort := "5356"
	content := renderAgentMweConfig(role, dir, certFile, keyFile, apiKey, apiPort, dnsPort)
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

	fmt.Printf("\nTo let `tdns-cli %s ...` reach this server, add to your tdns-cli.yaml:\n\n", role)
	fmt.Printf("  apiservers:\n")
	fmt.Printf("     - name:       tdns-%s\n", role)
	fmt.Printf("       baseurl:    https://127.0.0.1:%s/api/v1\n", apiPort)
	fmt.Printf("       apikey:     %s\n", apiKey)
	fmt.Printf("       authmethod: X-API-Key\n")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  tdns-%s --config %s        # start the server\n", role, cfgPath)
	fmt.Printf("  tdns-cli %s config check --serverconfig %s   # validate\n", role, cfgPath)
}

func renderAgentMweConfig(role, dir, certFile, keyFile, apiKey, apiPort, dnsPort string) string {
	r := strings.NewReplacer(
		"{{ROLE}}", role,
		"{{DIR}}", dir,
		"{{CERT}}", certFile,
		"{{KEY}}", keyFile,
		"{{APIKEY}}", apiKey,
		"{{APIPORT}}", apiPort,
		"{{DNSPORT}}", dnsPort,
	)
	return r.Replace(agentMweConfigTemplate)
}

// agentMweConfigTemplate is the single-file agent MWE. Placeholders in {{...}}
// form are substituted by renderAgentMweConfig (the template contains a literal
// %s zonefile pattern in a comment, so fmt verbs are unusable here).
const agentMweConfigTemplate = `# Minimal Working Example — tdns-{{ROLE}}
#
# Generated by ` + "`tdns-cli {{ROLE}} config mwe`" + `. Self-contained: one file plus a
# self-signed cert. Validate it any time with:
#   tdns-cli {{ROLE}} config check --serverconfig <this file>
#
# NOTE: tdns-agent is a SECONDARY-only server. It refuses primary zones
# (they are quarantined at startup) and it never signs — online-signing and
# inline-signing are ignored. Host primary and/or signed zones on tdns-auth,
# or use tdns-mpagent (tdns-mp) for multi-provider roles.

service:
   name:  TDNS-AGENT

dnsengine:
   # Listen on IPv4 and IPv6 localhost. Port {{DNSPORT}} is used so the server
   # runs unprivileged; use 53 for a real deployment (needs root/capabilities).
   addresses:   [ 127.0.0.1:{{DNSPORT}}, '[::1]:{{DNSPORT}}' ]
   # Add more listen addresses by uncommenting/extending, e.g.:
   #   addresses: [ 127.0.0.1:{{DNSPORT}}, '[::1]:{{DNSPORT}}', 192.0.2.53:53, '[2001:db8::53]:53' ]
   transports:  [ do53 ]
   # For encrypted transports, add them here and the cert/key are already set:
   #   transports: [ do53, dot, doh, doq ]
   certfile:  {{CERT}}
   keyfile:   {{KEY}}

apiserver:
   addresses:  [ 127.0.0.1:{{APIPORT}} ]
   apikey:     {{APIKEY}}
   certfile:   {{CERT}}
   keyfile:    {{KEY}}
   usetls:     true

db:
   file:  {{DIR}}/tdns-{{ROLE}}.db

# The log: block must live in THIS file. Logging is set up from the main
# config file before include: is resolved, so a log: block in an included
# file is not found and startup fails.
log:
   file:   {{DIR}}/tdns-{{ROLE}}.log
   level:  info

# The agent runs an in-process iterative resolver, used e.g. to look up peer
# records. Disable it with active: false if the host has a resolver already.
imrengine:
   active:      true
   addresses:   [ 127.0.0.1:5453, '[::1]:5453' ]
   transports:  [ do53 ]
   # In a lab without a complete DNSSEC chain, relax validation:
   #   require_dnssec_validation: false

# Zone templates. Both are SECONDARY templates — see the note at the top.
# The commented-out zone below uses the first one.
templates:
   - name:   basic-secondary
     type:   secondary
     store:  map

   - name:   proxy-secondary
     type:   secondary
     store:  map
     # delegation-sync-proxy: act on behalf of a DSYNC-unaware primary
     # (BIND/Knot) by watching transfers for CDS/CSYNC changes. Valid only
     # on an agent secondary.
     options: [ delegation-sync-proxy ]

# No zones are configured, so this agent starts clean. To serve a zone, point
# primaries: at your real primary and uncomment. A template may instead carry
# a zonefile pattern like  zonefile: {{DIR}}/zones/%szone  to derive the path.
zones: []
   # - name:      secondary.example.
   #   template:  basic-secondary
   #   zonefile:  {{DIR}}/zones/secondary.example.zone
   #   primaries:
   #      - { addr: "192.0.2.1:53", key: NOKEY }
   #   allow-notify:
   #      - { prefix: "192.0.2.1", key: NOKEY }
`
