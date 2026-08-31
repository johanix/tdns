/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	// "flag"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var lgConfig = Logger("config")

// Add near the top of the file with other vars
var Templates = make(map[string]ZoneConf)

// OrderedConfig preserves the order of configuration entries
type ConfigEntry struct {
	Key   string
	Value interface{}
}

// processConfigFile reads and processes a YAML config file and any included files.
// IMPORTANT: All includes must be specified as a single array at the top level of the config:
//
//	include:
//	  - file1.yaml
//	  - file2.yaml
//
//	# Rest of configuration...
//	stuff1: value1
//	stuff2: value2
//
// The older style of multiple separate 'include' statements throughout the file
// is not supported.
// Returns the processed config map and a list of all included file paths (absolute).

// LoadRawConfigMap loads a config file and its (single-level) includes into a
// case-PRESERVING map, exactly as the daemon does before alias normalization
// and viper decoding. `config check` uses it so NormalizeXfrAliases (and the
// mis-cased-key scan) see the same key case the daemon sees: viper's
// AllSettings lower-cases keys, which would make a mis-cased transfer-list key
// like `Provide-Xfr:` look accepted while the daemon leaves it unknown and
// silently drops it. Returns the merged map and the list of included files.
func LoadRawConfigMap(file string) (map[string]interface{}, []string, error) {
	return processConfigFile(file, filepath.Dir(file), 0, newMergeState())
}

// decodeConfigFile turns a config FILE into a Config exactly as the daemon
// does: include processing, transfer-alias normalisation, the apiserver.usetls
// default, then a STRICT mapstructure decode.
//
// Shared by ParseConfig and ValidateConfig so that `config check` cannot pass a
// file the daemon would refuse to start on. The checker used to decode through
// viper.Unmarshal instead, which is materially more permissive: viper sets
// WeaklyTypedInput and adds StringToSlice/StringToTimeDuration hooks this
// decoder does not have. A config writing `schemes: notify` where the struct
// wants a slice, or `port: "5354"` where it wants a uint16, therefore validated
// clean and then failed at startup -- a checker handing out a green light on a
// config that could not boot.
func decodeConfigFile(cfgfile string, conf *Config) (mapstructure.Metadata, []string, map[string]string, error) {
	var md mapstructure.Metadata

	configMap, includedFiles, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0, newMergeState())
	if err != nil {
		return md, nil, nil, err
	}
	aliasConflicts := NormalizeXfrAliases(configMap)

	if err := decodeConfigMap(configMap, conf, &md); err != nil {
		return md, includedFiles, aliasConflicts, err
	}
	return md, includedFiles, aliasConflicts, nil
}

// rejectMovedConfigKeys refuses the pre-#446 config schema outright, with
// the key-for-key migration in the error. Hard error by design — no
// fallbacks, no aliases: a stale config fails loudly at load (daemon and
// `config check` alike, since every decode path runs through
// decodeConfigMap), never half-works. See
// docs/2026-08-31-config-schema-listeners-design.md.
func rejectMovedConfigKeys(configMap map[string]interface{}) error {
	var errs []string
	if _, ok := configMap["dnsengine"]; ok {
		errs = append(errs,
			"the dnsengine: block is gone: its listener keys (addresses, transports, certfile, keyfile, ports) moved to listeners:, its behavior keys (options, outbound-soa-serial, transfer-src) to authengine:")
	}
	if imrRaw, ok := configMap["imrengine"]; ok {
		if imrMap, ok := imrRaw.(map[string]interface{}); ok {
			for _, key := range []string{"addresses", "transports", "certfile", "keyfile", "ports"} {
				if _, ok := imrMap[key]; ok {
					errs = append(errs, fmt.Sprintf(
						"imrengine.%s moved to listeners.%s (tdns-imr listens via listeners:; the embedded imr of tdns-auth/tdns-agent is internal and listens only via listeners.imr-debug-address)",
						key, key))
				}
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("config uses pre-#446 schema keys:\n  - %s", strings.Join(errs, "\n  - "))
}

// decodeConfigMap is the decode half alone, for callers that already hold a
// settings map. Same strictness, same hooks, same tag: a divergence here is a
// checker that disagrees with the daemon.
func decodeConfigMap(configMap map[string]interface{}, conf *Config, md *mapstructure.Metadata) error {
	if err := rejectMovedConfigKeys(configMap); err != nil {
		return err
	}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  conf,
		// Replace, don't merge. Result is the long-lived conf, reused across
		// reloads, and ParseZones writes template-expanded options/policy back
		// into conf.Zones[i] (*zconf = updated). Without ZeroFields, a reload
		// merges the new zones list into the stale slice, so a zone whose YAML
		// omits a field silently inherits a former slot-neighbour's value --
		// e.g. a plain secondary gaining online-signing + a dnssecpolicy. It
		// also drops Templates/Policies deleted from the config. Absent keys are
		// still skipped, so runtime state in conf.Internal is untouched.
		ZeroFields: true,
		Metadata:   md,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			// Durations written the way the config documents them: `8s`, `1h`.
			// Without this the only shape that decodes into a time.Duration
			// field is a raw nanosecond integer, so `query-budget: 8s` -- the
			// form tdns-imr.sample.yaml shows -- fails the decode and the
			// daemon does not start. The hook fires only for time.Duration
			// targets, so it does not loosen the strictness that keeps a scalar
			// out of a slice or a quoted integer out of a uint16.
			mapstructure.StringToTimeDurationHookFunc(),
			stringToPeerConfHook(),
			stringToAclEntryHook(),
			legacyDynamicAllowedHook(),
		),
	}
	decoder, derr := mapstructure.NewDecoder(decoderConfig)
	if derr != nil {
		return fmt.Errorf("error creating decoder: %v", derr)
	}

	// apiserver.usetls defaults to true, applied to the raw map so an absent
	// key and an explicit `usetls: true` decode identically.
	if apiserverMap, ok := configMap["apiserver"].(map[string]interface{}); ok {
		if _, explicitlySet := apiserverMap["usetls"]; !explicitlySet {
			apiserverMap["usetls"] = true
		}
	}

	// Reset raw fields that derive an internal default when omitted, so a
	// reload after the operator removes the YAML key reverts to the default
	// instead of preserving the previously-decoded value (mapstructure leaves
	// absent keys untouched).
	conf.Dnssec.DNSKEYTransport = ""

	if derr := decoder.Decode(configMap); derr != nil {
		return fmt.Errorf("error decoding config: %v", derr)
	}
	return nil
}

// processConfigFile reads one config file and folds in whatever it include:s.
//
// st carries provenance and findings across the whole recursive load. It is
// threaded rather than returned because an item's origin has to be recorded
// where it is READ -- a parent stamping its own name on an already-flattened
// child map would blame a nested include on the file that merged it.
func processConfigFile(file string, baseDir string, depth int, st *mergeState) (map[string]interface{}, []string, error) {
	if depth > 10 {
		return nil, nil, errors.New("maximum include depth exceeded (10 levels)")
	}

	// Read the file
	lgConfig.Debug("reading config file", "file", file)
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading file %s: %v", file, err)
	}

	// Parse YAML directly into a map
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		// On parse error, show context around the reported line to help diagnose
		// (e.g. tabs, wrong indentation, stray colons). Both log it (server-side
		// detail) AND fold it into the returned error so callers over RPC see it.
		errStr := err.Error()
		var lineNum int
		if idx := strings.Index(errStr, "line "); idx >= 0 {
			rest := errStr[idx+5:]
			end := 0
			for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
				end++
			}
			if end > 0 {
				fmt.Sscanf(rest[:end], "%d", &lineNum)
			}
		}
		var contextBuf strings.Builder
		if lineNum > 0 {
			lines := strings.Split(string(data), "\n")
			start := lineNum - 4
			if start < 0 {
				start = 0
			}
			end := lineNum + 2
			if end > len(lines) {
				end = len(lines)
			}
			lgConfig.Error("YAML parse error", "line", lineNum, "contextStart", start+1, "contextEnd", end)
			for i := start; i < end; i++ {
				line := lines[i]
				marker := "  "
				if i == lineNum-1 {
					marker = "> "
				}
				// Reveal tabs and other problematic chars for the failing line
				if i == lineNum-1 {
					reveal := strings.ReplaceAll(line, "\t", "\\t")
					reveal = strings.ReplaceAll(reveal, "\r", "\\r")
					if reveal != line {
						lgConfig.Error("context line", "num", i+1, "line", line, "raw", reveal)
						fmt.Fprintf(&contextBuf, "  %s%4d: %s\n", marker, i+1, reveal)
						continue
					}
					lgConfig.Error("context line", "num", i+1, "line", line)
				} else {
					lgConfig.Error("context line", "num", i+1, "line", line)
				}
				fmt.Fprintf(&contextBuf, "  %s%4d: %s\n", marker, i+1, line)
			}
		}
		lgConfig.Debug("error unmarshalling YAML to struct", "file", file)
		if Globals.Debug {
			fmt.Printf("Config that we failed to unmarshal:\n%s\n", string(data))
		}
		if contextBuf.Len() > 0 {
			return nil, nil, fmt.Errorf("error parsing YAML in %s: %v\n%s(tabs shown as \\t; '>' marks the reported line — actual mistake often on a previous line)", file, err, contextBuf.String())
		}
		return nil, nil, fmt.Errorf("error parsing YAML in %s: %v", file, err)
	}

	// Track included files
	includedFiles := make([]string, 0)

	// Record what THIS file contributes, before folding in anything it
	// includes. It has to happen for every file, not only ones with an
	// include: block -- a leaf that includes nothing is exactly the file a
	// nested collision needs to be able to name.
	for path := range mergeAllowlist {
		if v, ok := lookupPath(config, path); ok {
			recordOrigins(path, v, file, st, nil, false)
		}
	}

	// Handle includes if present
	if includes, ok := config["include"].([]interface{}); ok {
		delete(config, "include")

		for _, inc := range includes {
			entry, err := parseIncludeEntry(inc)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: include: %v", file, err)
			}
			fullPath := entry.File
			if !filepath.IsAbs(fullPath) {
				fullPath = filepath.Join(baseDir, fullPath)
			}
			fullPath = filepath.Clean(fullPath)
			includedFiles = append(includedFiles, fullPath)

			// The child gets its own origin map so the items it returns carry
			// the file each was actually READ from, however deep. Merging into
			// one shared map would blame a nested include on this file.
			childState := st.forChild()
			included, subIncluded, err := processConfigFile(fullPath, filepath.Dir(fullPath), depth+1, childState)
			if err != nil {
				return nil, nil, err
			}

			if err := mergeConfigMaps(config, included, "", fullPath, entry.Merge, st, childState); err != nil {
				return nil, nil, fmt.Errorf("%s: merging %s: %v", file, fullPath, err)
			}
			st.adopt(childState)

			includedFiles = append(includedFiles, subIncluded...)
		}
	}

	if depth == 0 {
		st.report(file)
	}

	return config, includedFiles, nil
}

// deprecatedConfigKey describes a config key (or key fragment) that the
// code no longer reads, together with operator-facing migration advice.
// `match` is tested against each unused config key path reported by
// mapstructure (dotted, e.g. "dnssec.policies[fastroll].KSK.sigvalidity"):
//   - exact: the unused path equals match (use for top-level keys)
//   - else: match is treated as a substring (use ".suffix" forms to catch
//     a renamed leaf wherever it appears, e.g. ".sigvalidity")
type deprecatedConfigKey struct {
	match  string
	exact  bool
	advice string
	key    string // populated per-occurrence by classifyUnusedConfigKeys (the actual offending path)
}

// deprecatedConfigKeys is the registry of config keys removed or moved by
// past restructures. When the operator's config still uses one, the loader
// emits a specific migration error instead of a generic "unknown key"
// warning — turning a silent, system-wide breakage (e.g. every signed zone
// losing its policy) into a one-line "here is what to change."
//
// TEMPLATE — adding a new entry as the config evolves:
//   - Removed/renamed a TOP-LEVEL key (foo: → bar.foo:)? Add
//     {match: "foo", exact: true, advice: "`foo:` moved to `bar.foo:` (restructure YYYY-MM-DD)"}.
//   - Renamed/moved a LEAF that can appear under many parents
//     (x: → y: under each policy)? Add
//     {match: ".oldleaf", advice: "`oldleaf` moved to ...; see <doc>"}.
//     A non-exact entry is matched against the END of the unused path, so it
//     fires on the leaf itself and not on a valid block of the same name that
//     merely happens to contain a typo'd child.
//
// Keep advice concrete: name the new location and, ideally, the change date
// or doc so an operator can find the migration.
var deprecatedConfigKeys = append([]deprecatedConfigKey{
	// Config restructure 2026-06-16 (per-role KSK/ZSK algorithms + nesting):
	// the DNSSEC config moved under a single top-level `dnssec:` block.
	{match: "dnssecpolicies", exact: true,
		advice: "`dnssecpolicies:` moved under `dnssec:` as `dnssec.policies:` (restructure 2026-06-16)"},
	{match: "kasp", exact: true,
		advice: "`kasp:` moved under `dnssec:` as `dnssec.kasp:` (restructure 2026-06-16)"},
	{match: "large_algorithms", exact: true,
		advice: "`large-algorithms:` moved under `dnssec:` as `dnssec.large-algorithms:` (restructure 2026-06-16)"},
	{match: "split_algorithms", exact: true,
		advice: "`split-algorithms:` moved under `dnssec:` as `dnssec.split-algorithms:` (restructure 2026-06-16)"},
	// sigvalidity reshape: was a per-key scalar (ksk/zsk/csk: sigvalidity: X);
	// is now a policy-level subtree `sigvalidity: { default, dnskey, ds }`
	// with `default` required.
	{match: ".sigvalidity",
		advice: "per-key `sigvalidity:` is now a policy-level subtree `sigvalidity: { default, dnskey, ds }` (default required)"},
	{match: ".sig-validity",
		advice: "`sig-validity:` is spelled `sigvalidity:` and is a policy-level subtree `{ default, dnskey, ds }` (default required), not a key under ksk:/zsk:"},
	// Zone-level leaves whose misspelling silently disables the feature: an
	// unrecognized dnssec_policy/dnssec-policy leaves the zone with no policy,
	// which then rejects online-signing/inline-signing at validation.
	{match: ".dnssec_policy",
		advice: "zone key is `dnssecpolicy:` (one word, no underscore); `dnssec_policy:` is ignored, leaving the zone unsigned"},
	{match: ".dnssec-policy",
		advice: "zone key is `dnssecpolicy:` (one word, no hyphen); `dnssec-policy:` is ignored, leaving the zone unsigned"},
	{match: ".multi_signer",
		advice: "zone key is `multisigner:` (one word, no underscore); `multi_signer:` is ignored"},
}, underscoreSpellingMigrations()...)

// snakeCaseConfigKeys lists every config key that was spelled with underscores
// before the 2026-08-27 rename to hyphens. Kept as data so the migration
// advice below cannot drift from the rename itself.
//
// This registry is not cosmetic. Config is loaded through viper, which
// silently ignores a key it cannot map -- the same failure that left
// trust-anchor-ds parsing to "" for as long as it lacked a mapstructure tag.
// Without an entry here, an operator whose config still says
// "propagation-delay:" would get no error, no warning, and a rollover engine
// quietly running on defaults.
var snakeCaseConfigKeys = []string{
	"address_family",
	"catalog_members",
	"catalog_zones",
	"check_interval",
	"config_file",
	"config_groups",
	"dnskey_query_transport",
	"failure_threshold",
	"first_failure",
	"group_prefixes",
	"jitter_fraction",
	"lame_delegation",
	"large_algorithms",
	"max_failure",
	"max_failures",
	"max_served",
	"meta_groups",
	"outbound_soa_serial",
	"probe_interval",
	"propagation_delay",
	"query_budget",
	"require_dnssec_validation",
	"retry_after_failure",
	"routing_failure",
	"signing_groups",
	"split_algorithms",
	"standby_ksk_count",
	"standby_zsk_count",
	"suspect_duration",
	"transfer_src",
	"trust_anchor_dnskey",
	"trust_anchor_file",
	"trust_anchor_ds",
	"tsig_key",
	"upgrade_indirect_cache_hits",
	"window_duration",
}

// SnakeCaseKeysIn walks a decoded YAML tree and returns, as dotted paths, any
// key still using a pre-2026-08-27 snake_case spelling.
//
// deprecatedConfigKeys only ever sees the decoder's unused-key list, so it
// covers the main config load and nothing else. A file read by a plain
// yaml.Unmarshal -- the offline `dnssec policy validate --file` path, and the
// IMR config that dog reads for trust anchors -- drops a renamed key in
// silence. For an allowlist like split-algorithms that means reporting a
// perfectly good configuration as broken; for a trust anchor it means falling
// through to the compiled-in IANA root keys and calling every other root
// bogus. Driven off the same snakeCaseConfigKeys list so no two loaders can
// disagree about what an old spelling is.
func SnakeCaseKeysIn(node any, path string) []string {
	old := make(map[string]bool, len(snakeCaseConfigKeys))
	for _, k := range snakeCaseConfigKeys {
		old[k] = true
	}
	var found []string
	var walk func(any, string)
	walk = func(n any, at string) {
		switch v := n.(type) {
		case map[string]any:
			for k, child := range v {
				here := k
				if at != "" {
					here = at + "." + k
				}
				if old[strings.ToLower(k)] {
					found = append(found, here)
				}
				walk(child, here)
			}
		case []any:
			for _, child := range v {
				walk(child, at)
			}
		}
	}
	walk(node, path)
	sort.Strings(found)
	return found
}

// SnakeCaseKeyAdvice renders the migration advice for keys found by
// SnakeCaseKeysIn, naming each new spelling.
func SnakeCaseKeyAdvice(keys []string) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		leaf := k
		if i := strings.LastIndex(k, "."); i >= 0 {
			leaf = k[i+1:]
		}
		parts = append(parts, fmt.Sprintf("%s (now %s)", k, strings.ReplaceAll(leaf, "_", "-")))
	}
	return strings.Join(parts, ", ") + " — config keys use hyphens, not underscores (2026-08-27)"
}

// underscoreSpellingMigrations turns snakeCaseConfigKeys into deprecated-key
// entries. Each is a LEAF match ("." + name): these keys sit under several
// different parents, and the old spelling is unambiguous wherever it appears.
func underscoreSpellingMigrations() []deprecatedConfigKey {
	out := make([]deprecatedConfigKey, 0, len(snakeCaseConfigKeys))
	for _, old := range snakeCaseConfigKeys {
		out = append(out, deprecatedConfigKey{
			match: "." + old,
			advice: fmt.Sprintf("`%s:` is now spelled `%s:` (config keys use hyphens, not underscores, 2026-08-27)",
				old, strings.ReplaceAll(old, "_", "-")),
		})
	}
	return out
}

// classifyUnusedConfigKeys splits mapstructure's unused-key list into keys
// that match a known deprecated shape (with migration advice) and keys that
// are merely unrecognized (likely typos). Case-insensitive on the path;
// mapstructure reports field paths in the Go struct's case (e.g. ".KSK.").
func classifyUnusedConfigKeys(unused []string) (deprecated []deprecatedConfigKey, unknown []string) {
	for _, key := range unused {
		lk := strings.ToLower(key)
		var hit *deprecatedConfigKey
		for i := range deprecatedConfigKeys {
			d := &deprecatedConfigKeys[i]
			ml := strings.ToLower(d.match)
			// A non-exact entry names a deprecated LEAF (".oldleaf") that may sit
			// under many parents, so it must match the END of the path. Matching
			// anywhere in the path would also fire on a valid parent block: a typo
			// inside the (valid) `sigvalidity:` subtree reports as
			// "dnssec.policies[p].SigValidity.defualt", which contains
			// ".sigvalidity" but is a misspelled `default`, not a deprecated key.
			if (d.exact && lk == ml) || (!d.exact && strings.HasSuffix(lk, ml)) {
				hit = d
				break
			}
		}
		if hit != nil {
			// Carry the actual key in a per-occurrence copy so the log line
			// names the offending path, not just the pattern.
			deprecated = append(deprecated, deprecatedConfigKey{key: key, advice: hit.advice})
		} else {
			unknown = append(unknown, key)
		}
	}
	return deprecated, unknown
}

func (conf *Config) ParseConfig(reload bool) error {
	lgConfig.Debug("entering ParseConfig")

	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		lgConfig.Warn("no config file specified, proceed at own risk")
		return nil
	}

	// Process the config file and all includes
	configMap, includedFiles, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0, newMergeState())
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	// Transfer-terminology aliases: rewrite upstreams:/request-xfr: ->
	// primaries and secondaries:/provide-xfr: -> downstreams in every
	// zones:/templates: entry BEFORE decoding (so aliases neither fail to
	// decode nor warn as unknown keys). Conflicting spellings are recorded;
	// ParseZones quarantines the affected zones.
	aliasConflicts := NormalizeXfrAliases(configMap)

	// Decode through the shared helper, so ValidateConfig -- and therefore
	// `config check` -- applies byte-for-byte the same strictness. A decoder
	// written out twice is a checker that eventually disagrees with the daemon.
	var md mapstructure.Metadata
	if err := decodeConfigMap(configMap, conf, &md); err != nil {
		return err
	}

	// peers: block — validate/normalize definitions; a broken peer does not
	// abort (zones referencing it are quarantined at expansion in ParseZones).
	conf.Internal.XfrAliasConflicts = aliasConflicts
	conf.Internal.BrokenPeers = conf.ValidatePeers()

	// Server-wide error registry: create once, preserve across reloads (so
	// boot-scoped Transport errors survive a reload). parseconfig owns the
	// Config/CertMissing check (clear-then-reassert on every load).
	if conf.Internal.ServerErrors == nil {
		conf.Internal.ServerErrors = NewServerErrorRegistry()
	}
	conf.validateListenerCerts()

	// dynamiczones: value validation (e.g. an unknown zone type in
	// dynamic.allowed) is a hard config error — the decoder accepts any
	// string, so the check lives here. A legacy bool for dynamic.allowed is
	// caught earlier, by legacyDynamicAllowedHook failing the decode.
	if err := conf.DynamicZones.Validate(); err != nil {
		return err
	}

	// transfer-src: same reasoning as dynamiczones above -- the decoder takes
	// any string, and a bad entry here fails silently at transfer time rather
	// than loudly at load.
	if err := ValidateAllTransferSrc(conf); err != nil {
		return err
	}

	// listeners.imr-debug-address: loopback or refuse to load (#446) — a
	// non-loopback debug window is an open resolver inside an auth server.
	if err := validateImrDebugAddress(conf.Listeners.ImrDebugAddress); err != nil {
		return err
	}

	if len(md.Unused) > 0 {
		// Split the unused keys into two buckets: keys that match a known
		// DEPRECATED/RENAMED config shape (the config lags the code — emit
		// a specific migration message), and genuinely unrecognized keys
		// (likely typos — the generic warning). A deprecated key carries a
		// real risk (e.g. a moved DNSSEC policy block silently disables
		// signing for every zone), so it gets a loud, actionable line of
		// its own rather than being buried in the generic list.
		deprecated, unknown := classifyUnusedConfigKeys(md.Unused)
		for _, d := range deprecated {
			lgConfig.Error("deprecated config key (config lags the code) — "+d.advice,
				"key", d.key)
		}
		if len(unknown) > 0 {
			lgConfig.Warn("unknown config keys ignored (possible misspellings)", "keys", unknown)
		}
	}

	// Parse the entire dnssec: block (large-algorithms, split-algorithms,
	// kasp, and the named policies) into conf.Internal.*. The zone-reload
	// paths call this same helper so reloading zones also refreshes the
	// policy definitions they depend on. ParseZones (later) validates zone
	// dnssec_policy references against the resolved map.
	if err := conf.parseDnssecConfig(); err != nil {
		return err
	}

	dnskeyXport, err := parseDNSKEYTransportPolicy(conf.Dnssec.DNSKEYTransport)
	if err != nil {
		return err
	}
	conf.Internal.DNSKEYTransport = dnskeyXport

	// Normalize service.transport.type (default: none)
	if conf.Service.Transport.Type == "" {
		conf.Service.Transport.Type = "none"
	} else {
		ts := strings.ToLower(conf.Service.Transport.Type)
		switch ts {
		case "svcb", "tsync", "none":
			conf.Service.Transport.Type = ts
		default:
			lgConfig.Warn("unknown service.transport.type, defaulting to none", "type", conf.Service.Transport.Type)
			conf.Service.Transport.Type = "none"
		}
	}

	lgConfig.Debug("templates defined", "count", len(conf.Templates))

	if err := conf.buildTemplateMap(); err != nil {
		return err
	}

	// log.Printf("*** ParseConfig: 1")
	// Set up viper with the same config for compatibility
	processedConfig, err := yaml.Marshal(configMap)
	if err != nil {
		return fmt.Errorf("error marshaling processed config: %v", err)
	}

	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(strings.NewReader(string(processedConfig))); err != nil {
		return fmt.Errorf("error reading processed config: %v", err)
	}

	// Populate ConfigGroupConfig.Name from map keys after parsing CatalogConf
	if conf.Catalog != nil {
		if conf.Catalog.ConfigGroups != nil {
			for name, configGroup := range conf.Catalog.ConfigGroups {
				if configGroup != nil {
					configGroup.Name = name
				}
			}
		}
		// Also populate MetaGroups (deprecated) if present
		if conf.Catalog.MetaGroups != nil {
			for name, metaGroup := range conf.Catalog.MetaGroups {
				if metaGroup != nil {
					metaGroup.Name = name
				}
			}
		}
	}

	// Set default values for DynamicZonesConf if not configured
	conf.setDynamicZonesDefaults()

	// Handle backward compatibility migrations
	conf.migrateCatalogPolicyToDynamicZones()
	conf.migrateMetaGroupsToConfigGroups()

	// Validate group prefixes (required if config-groups or signing-groups are defined)
	if err := conf.validateGroupPrefixes(); err != nil {
		return err
	}

	// Validate dynamiczones configuration (check if configfile is included)
	conf.validateDynamicZonesConfig(includedFiles)

	if Globals.App.Type == AppTypeImr {
		conf.parseImrOptions()
	}

	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent:
		conf.ParseAuthOptions()
	}

	// KDC and KRS configuration parsing has been moved to tdns-nm
	// See kdc.ParseKdcConfigFromFile() and krs.ParseKrsConfigFromFile()

	// Install the parsed delegationsync: block for the readers that have no
	// *Config in hand (PublishDsyncRRs and friends). Unconditional and before
	// anything that could publish: on reload this must be swapped in before a
	// zone re-reads it, and on first start it must be present before
	// SetupZoneSync runs further down.
	SetDelegationSyncConfig(conf.DelegationSync)

	// On first start: build the KeyDB. On reload: keep the existing
	// KeyDB but re-apply outbound-soa-serial so a config edit takes
	// effect without a full restart.
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent:
		if !reload {
			err = conf.InitializeKeyDB()
			if err != nil {
				return err
			}
		} else if conf.Internal.KeyDB != nil {
			// Refresh the live KeyDB's options from the freshly-parsed config so
			// a reloaded option (e.g. minimal-responses) takes effect without a
			// restart. The KeyDB is built once at startup and reused across
			// reloads, but the query responder reads them — without this, reload
			// updated only conf.AuthEngine.Options (the presentation) while the
			// responder kept the stale startup map. SetOptions swaps the map
			// atomically, so the per-query lock-free readers are race-free.
			conf.Internal.KeyDB.SetOptions(conf.AuthEngine.Options)
			conf.Internal.KeyDB.SetTransferSrc(conf.AuthEngine.TransferSrc)
			if err := applyOutboundSoaSerial(conf.Internal.KeyDB, conf.AuthEngine.OutboundSoaSerial); err != nil {
				return err
			}
		}
	}

	err = ValidateConfig(nil, conf.Internal.CfgFile) // will terminate on error
	if err != nil {
		return err
	}

	if Globals.App.Type == AppTypeAuth && len(conf.Service.Identities) > 0 {
		var transports []string
		for _, t := range conf.Listeners.Transports {
			t = strings.ToLower(t)
			switch t {
			case "do53", "dot", "doh", "doq":
				transports = append(transports, t)
			default:
				lgConfig.Error("unknown transport", "transport", t)
			}
		}
		// Add do53 if not already present
		if !slices.Contains(transports, "do53") {
			transports = append(transports, "do53")
		}

		transports = slices.Compact(transports)
		if len(transports) > 0 {
			alpn := []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: transports},
			}
			Globals.ServerSVCB = &dns.SVCB{
				Priority: 1,
				Target:   dns.Fqdn(conf.Service.Identities[0]),
				Value:    alpn,
			}
		}
	}

	if hook := conf.Internal.PostParseConfigHook; hook != nil {
		if err := hook(conf, configMap); err != nil {
			return fmt.Errorf("PostParseConfigHook: %w", err)
		}
	}

	return nil
}

// KDC and KRS configuration parsing has been moved to tdns-nm
// See kdc.ParseKdcConfigFromFile() and krs.ParseKrsConfigFromFile()

func (conf *Config) InitializeKeyDB() error {
	// dbFile := viper.GetString("db.file")
	dbFile := strings.TrimSpace(conf.Db.File)
	// Hard fail if database file is unset (before filepath.Clean which would turn "" into ".")
	if dbFile == "" {
		return fmt.Errorf("db.file is required but not set (must be specified in config)")
	}
	// Ensure the database file path is within allowed boundaries
	dbFile = filepath.Clean(dbFile)
	if dbFile == "." {
		return fmt.Errorf("db.file is unset (got '.' from empty path); must specify a valid database file path")
	}
	if strings.Contains(dbFile, "..") {
		return errors.New("invalid database file path: must not contain directory traversal")
	}
	// M42: Check for symlinks in database path
	if info, err := os.Lstat(dbFile); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("database file path %q is a symlink (not allowed)", dbFile)
	}
	// Create DB file and parent directory if missing (auto-initialize on first run).
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		lgConfig.Info("TDNS DB file does not exist, creating", "file", dbFile)
		dir := filepath.Dir(dbFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("ParseConfig: failed to create DB directory %s: %v", dir, err)
		}
		if err := os.WriteFile(dbFile, nil, 0664); err != nil {
			return fmt.Errorf("ParseConfig: failed to create TDNS DB file %s: %v", dbFile, err)
		}
	}
	kdb, err := NewKeyDB(dbFile, false, conf.AuthEngine.Options)
	if err != nil {
		return fmt.Errorf("error from NewKeyDB: %v", err)
	}
	conf.Internal.KeyDB = kdb

	kdb.SetTransferSrc(conf.AuthEngine.TransferSrc)
	if err := applyOutboundSoaSerial(kdb, conf.AuthEngine.OutboundSoaSerial); err != nil {
		return err
	}

	return nil
}

// applyOutboundSoaSerial resolves the configured outbound-soa-serial mode
// onto the KeyDB and ensures the persist-mode table exists. Called from
// InitializeKeyDB on first start AND from the reload path in ParseConfig
// so a config edit that flips authengine.outbound-soa-serial takes effect
// without a full restart.
func applyOutboundSoaSerial(kdb *KeyDB, raw string) error {
	// Default to "keep" when unset. Validation (oneof=keep|unixtime|persist)
	// is enforced by the struct tag at config-validate time.
	mode := strings.TrimSpace(strings.ToLower(raw))
	if mode == "" {
		mode = OutboundSoaSerialKeep
	}
	kdb.SetOutboundSoaSerial(mode)

	// Create the table unconditionally. The mode is now a PER-ZONE setting that
	// merely defaults to this global one (zd.EffectiveOutboundSoaSerial), so any
	// individual zone may be in persist mode even when the global is keep — and
	// zones are parsed after this runs, so we cannot know yet whether one is.
	// CREATE IF NOT EXISTS on an unused table is cheap.
	schema := DefaultTables["OutgoingSerials"]
	if _, err := kdb.DB.Exec(schema); err != nil {
		return fmt.Errorf("failed to create OutgoingSerials table: %w", err)
	}
	return nil
}

// zoneNameKey is the key two zone declarations are compared under to decide
// whether they are the same zone: canonical and FQDN-normalized. DNS names are
// case-insensitive (RFC 4343), and tdns accepts a name with or without its
// trailing dot, so "Example.com" and "example.com." are one zone written twice.
//
// It is the SAME function the Zones registry keys by, deliberately: two
// declarations recognised as one zone here must land on one entry there, and
// two functions that agree today are two functions that can drift.
//
// core.CanonicalizeName rather than strings.ToLower, which folds by Unicode:
// it maps U+212A KELVIN SIGN onto "k", so two distinct zone names would be
// quarantined as duplicates of each other. RFC 4343 folds US-ASCII A-Z only.
//
// tdns-cli's config check compares under the same rule, so what it reports and
// what this quarantines are the same set.
func zoneNameKey(name string) string {
	return core.CanonicalizeName(dns.Fqdn(strings.TrimSpace(name)))
}

// func ParseZones(zones map[string]tdns.ZoneConf, zrch chan tdns.ZoneRefresher) error {
//
// Returns (allZones, brokenZones, err). allZones lists zones whose
// config parsed cleanly and were queued for refresh. brokenZones lists
// zones whose config had a fatal error; these are still registered in
// the Zones map with the error attached so they remain visible to the
// zone-list API and survive reload-diffs, but are not sent to the
// RefreshEngine.
func (conf *Config) ParseZones(ctx context.Context, reload bool) ([]string, []string, error) {
	if len(conf.Zones) == 0 {
		lgConfig.Info("no authoritative zones defined")
		return nil, nil, nil
	}

	lgConfig.Debug("parsing authoritative zones", "count", len(conf.Zones))
	var all_zones []string
	var broken_zones []string
	// Zones where a GLOBAL persist/unixtime outbound mode is being suppressed
	// because the zone is a mirroring secondary. Collected in-loop from the
	// freshly resolved role/mode; see warnGlobalOutboundSerialSuppressed.
	var serialSuppressedZones []string

	// Duplicate names are found in a PRE-PASS, before the loop below touches
	// anything.
	//
	// It cannot be done inline. That loop get-or-creates the ZoneData, mutates
	// it and enqueues a refresh, so by the time a second entry of the same name
	// came round the first would already be live and possibly queued -- and
	// "neither definition wins" would be a thing we said rather than a thing
	// that happened.
	//
	// Comparison is on the FQDN because that is what the daemon compares:
	// zname := dns.Fqdn(zconf.Name) right below means example.com and
	// example.com. are already one zone, and a raw-string check would miss
	// exactly the pair this loop then silently collapses.
	//
	// This applies to a single zones: block as much as to a merged one. Before
	// this, two entries of one name were last-wins with nothing recording
	// which of them was being served.
	duplicateZones := map[string]bool{}
	seenZoneName := map[string]bool{}
	for i := range conf.Zones {
		zkey := zoneNameKey(conf.Zones[i].Name)
		if zkey == "." {
			continue // an unnamed entry is caught by the validation below
		}
		if seenZoneName[zkey] {
			duplicateZones[zkey] = true
			continue
		}
		seenZoneName[zkey] = true
	}

	// Process each zone configuration
	for i := range conf.Zones {
		zconf := &conf.Zones[i]
		zname := dns.Fqdn(zconf.Name)
		zconf.Name = zname

		// A zone name that is not already canonical is served correctly -- the
		// registry, the owner map and every index fold it -- but it is worth
		// saying out loud, ONCE, because two things keyed by the name outside
		// those indexes do not follow it:
		//
		//   - the keystore tables (OutgoingSerials, ZoneSigningState, the
		//     rollover state tables, ZonePolicyOverride) hold rows written
		//     under whatever spelling an OLDER tdns used, and an older tdns
		//     folded the zone name only when the fold-case option was set,
		//     which defaulted off. Rows written under "Example.COM." are not
		//     found by a lookup for "example.com.", and the outgoing-serial
		//     read treats "no row" as "nothing served yet" rather than as an
		//     error -- so the zone can republish BELOW a serial a secondary
		//     already holds and that secondary serves stale data indefinitely,
		//     with nothing logged.
		//
		//   - the zone file path is derived from the folded name, so a file
		//     written by an older tdns under the config spelling is orphaned
		//     on a case-sensitive filesystem.
		//
		// Renaming the zone to its canonical spelling in the config makes this
		// go away. Warn rather than refuse: the zone works, and refusing to
		// start over a cosmetic difference would be worse than the problem.
		if canon := core.CanonicalizeName(zname); canon != zname {
			lgConfig.Warn("zone name is not canonical; keystore rows and zone files "+
				"written by an older tdns under the configured spelling will not be "+
				"found, and an unfound outgoing serial is silently treated as "+
				"'nothing served yet'",
				"configured", zname, "served_as", canon)
		}

		// Get-or-create the registry entry up front so SetError calls
		// during validation attach to the actual zone object, not a
		// throwaway stack value. On reload, clear any prior error so a
		// previously-broken zone can become healthy without restart.
		zd, exists := Zones.Get(zname)
		if !exists {
			zd = &ZoneData{
				ZoneName:      core.CanonicalizeName(zname),
				Logger:        log.Default(),
				FirstZoneLoad: true,
			}
			Zones.Set(zname, zd)
		}

		// A zone defined more than once is served under NEITHER definition.
		// Quarantining it rather than refusing the whole config is the same
		// trade the loader makes everywhere else: a host carrying a hundred
		// thousand zones does not stop because one of them was pasted twice.
		if duplicateZones[zoneNameKey(zname)] {
			lgConfig.Error("zone defined more than once; not serving it under either definition",
				"zone", zname)
			zd.SetError(ConfigError, "zone %s is defined more than once in the configuration; "+
				"remove the extra definition", zname)
			broken_zones = append(broken_zones, zname)
			all_zones = append(all_zones, zname)
			continue
		}
		zd.Zonefile = zconf.Zonefile
		if zd.Error {
			zd.SetError(NoError, "")
		}

		// M46: Validate zone name length (DNS max is 255 octets)
		if len(zname) > 255 {
			lgConfig.Error("zone name too long, ignoring", "zone", zname)
			zd.SetError(ConfigError, "zone name too long: %q", zname)
			broken_zones = append(broken_zones, zname)
			continue
		}

		if strings.Contains(zconf.Name, "..") || strings.Contains(zconf.Name, "//") {
			lgConfig.Error("zone name contains invalid characters, ignoring", "zone", zconf.Name)
			zd.SetError(ConfigError, "zone name contains invalid characters: %q", zconf.Name)
			broken_zones = append(broken_zones, zname)
			continue
		}

		// A zone whose raw config used two spellings of the same transfer
		// list (primaries:+upstreams:, etc.) is quarantined — never a
		// silent preference between them. The conflict may live on the zone
		// itself OR on the template it references (NormalizeXfrAliases keys
		// template conflicts by the template name); a conflicted template
		// would otherwise silently hand the zone its broader canonical ACL.
		conflict := zoneOrTemplateAliasConflict(conf.Internal.XfrAliasConflicts, zconf.Name, zconf.Template)
		if conflict != "" {
			lgConfig.Error("conflicting transfer-list spellings, zone in error state", "zone", zname, "conflict", conflict)
			zd.SetError(ConfigError, "conflicting transfer-list spellings: %s", conflict)
			broken_zones = append(broken_zones, zname)
			continue
		}

		// Handle template expansion if specified
		if zconf.Template != "" {
			if tmpl, exist := Templates[zconf.Template]; exist {
				updated, err := ExpandTemplate(*zconf, &tmpl, Globals.App.Type)
				if err != nil {
					lgConfig.Error("template expansion failed, zone in error state", "zone", zname, "template", zconf.Template, "err", err)
					zd.SetError(ConfigError, "template expansion error: %q: %v", zconf.Template, err)
					broken_zones = append(broken_zones, zname)
					continue
				}
				*zconf = updated
			} else {
				lgConfig.Error("zone refers to undefined template, zone in error state", "zone", zname, "template", zconf.Template)
				zd.SetError(ConfigError, "template %q does not exist", zconf.Template)
				broken_zones = append(broken_zones, zname)
				continue
			}
		}

		// Expand `- peers: [ id, ... ]` references (from the zone or its
		// template) into concrete PeerConf/AclEntry entries. Errors —
		// unknown id, broken peer definition, mixed reference+inline entry,
		// peer unusable in this role — quarantine just this zone.
		if err := conf.expandPeerRefs(zconf, conf.Internal.BrokenPeers); err != nil {
			lgConfig.Error("peer reference expansion failed, zone in error state", "zone", zname, "err", err)
			zd.SetError(ConfigError, "peers: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}

		// downstream-auth mechanism ladder: validate/normalize the names
		// (unknown => quarantine), then emit the never-fatal cross-check
		// warnings (unsatisfiable mechanism, dead entry, tls-dane w/o IMR).
		if err := validateDownstreamAuth(zconf.DownstreamAuth); err != nil {
			lgConfig.Error("invalid downstream-auth, zone in error state", "zone", zname, "err", err)
			zd.SetError(ConfigError, "downstream-auth: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}
		crossCheckDownstreamAuth(zname, zconf.DownstreamAuth, zconf.Downstreams, conf.Internal.ImrEngine != nil)

		zonestore := parseZoneStore(zconf.Store)

		var zonetype ZoneType
		// resolvedPrimaries holds the addr:port tuples for a secondary zone's
		// upstreams, resolved (hostnames -> addresses) at parse time. nil for
		// primary zones. Carried to the ZoneRefresher build below.
		var resolvedPrimaries []PeerConf

		switch strings.ToLower(zconf.Type) {
		case "primary":
			zonetype = Primary
			_ = append([]string{}, zname) // primary_zones was unused
		case "secondary":
			zonetype = Secondary
			if len(zconf.Primaries) == 0 {
				lgConfig.Error("secondary zone has no primary configured, zone in error state", "zone", zname)
				zd.SetError(ConfigError, "secondary zone but has no primary (upstream) configured")
				broken_zones = append(broken_zones, zname)
				continue
			}
			secondaryOK := true
			for i := range zconf.Primaries {
				p := &zconf.Primaries[i]
				if p.Legacy != "" {
					lgConfig.Error("secondary zone uses legacy bare-string primary, zone in error state", "zone", zname, "primary", p.Legacy)
					zd.SetError(ConfigError, "primary now requires {addr, key} (got bare string %q)", p.Legacy)
					secondaryOK = false
					break
				}
				if p.Addr == "" {
					lgConfig.Error("secondary zone primary has no address, zone in error state", "zone", zname)
					zd.SetError(ConfigError, "secondary zone but has no primary (upstream) configured")
					secondaryOK = false
					break
				}
				if p.Key == "" {
					lgConfig.Error("secondary zone primary has no key, zone in error state", "zone", zname)
					zd.SetError(ConfigError, "primary requires an explicit key (use key: NOKEY for no TSIG)")
					secondaryOK = false
					break
				}
				if !conf.tsigKeyDefined(p.Key) {
					lgConfig.Error("secondary zone primary references unknown key, zone in error state", "zone", zname, "key", p.Key)
					zd.SetError(ConfigError, "unknown primary key %q (define it in keys.tsig or keystore tsig, or use NOKEY for no TSIG)", p.Key)
					secondaryOK = false
					break
				}
				if err := validatePeerXoT(p); err != nil {
					lgConfig.Error("secondary zone primary has invalid XoT config, zone in error state", "zone", zname, "primary", p.Addr, "err", err)
					zd.SetError(ConfigError, "primary %s: %v", p.Addr, err)
					secondaryOK = false
					break
				}
				origPrimary := p.Addr
				p.Addr = NormalizeAddressPort(p.Addr, defaultPortForPeer(*p))
				if origPrimary != p.Addr {
					lgConfig.Warn("primary has no port specified, using transport default", "zone", zname, "primary", origPrimary, "port", defaultPortForPeer(*p))
				}
			}
			if !secondaryOK {
				broken_zones = append(broken_zones, zname)
				continue
			}

			// Resolve the as-written primaries to addr:port tuples (hostnames
			// -> addresses via the IMR), re-resolved on every parse/reload.
			// Zero resolved -> ConfigError (quarantine); partial -> ConfigWarning
			// (serve from the rest). A prior parse's ConfigWarning was already
			// cleared by the SetError(NoError) reset at the top of the loop.
			res := resolvePrimaries(ctx, conf.Internal.ImrEngine, zconf.Primaries)
			if len(res.Resolved) == 0 {
				// D1: an unresolved hostname primary at parse time is NOT fatal.
				// The zone is created and the refresh engine re-resolves on every
				// cycle, so a transient failure (or an IMR not yet up at boot)
				// self-heals instead of permanently quarantining the zone. It
				// serves nothing until a primary resolves, surfacing as a refresh
				// error rather than a config quarantine.
				lgConfig.Warn("secondary zone: no primary resolved yet, will retry at refresh", "zone", zname, "unresolved", res.Unresolved)
				zd.SetError(ConfigWarning, "no primary resolved yet (unresolved: %v); retrying at refresh", res.Unresolved)
			} else if len(res.Unresolved) > 0 || len(res.KeyCollisions) > 0 {
				// Count resolved addresses actually usable for transfer — not
				// entries-minus-unresolved, which over-counts when a key
				// collision drops an otherwise-resolved address.
				served := len(res.Resolved)
				lgConfig.Warn("secondary zone: some primaries unavailable, serving from the rest", "zone", zname, "unresolved", res.Unresolved, "key_collisions", res.KeyCollisions, "resolved_upstreams", served, "configured_primaries", len(zconf.Primaries))
				zd.SetError(ConfigWarning, "serving from %d resolved upstream(s) of %d configured primaries (unresolved: %v, key-collisions: %v)", served, len(zconf.Primaries), res.Unresolved, res.KeyCollisions)
			}
			resolvedPrimaries = res.Resolved

		default:
			lgConfig.Error("unknown zone type, zone in error state", "zone", zname, "type", zconf.Type)
			zd.SetError(ConfigError, "unknown zone type: %s", zconf.Type)
			broken_zones = append(broken_zones, zname)
			continue
		}

		// Legacy bare-string notify: entries (the decode hook recorded each as a
		// Legacy marker) quarantine the zone, mirroring the primary check —
		// otherwise an empty-Addr PeerConf silently drops that notify target.
		legacyNotify := false
		for _, n := range zconf.Notify {
			if n.Legacy != "" {
				lgConfig.Error("zone uses legacy bare-string notify entry, zone in error state", "zone", zname, "notify", n.Legacy)
				zd.SetError(ConfigError, "notify now requires {addr, key} (got bare string %q)", n.Legacy)
				legacyNotify = true
				break
			}
			// The XoT fields only apply to the transfer path (primaries:).
			// NOTIFY goes out over Do53; reject rather than silently ignore
			// a configured security setting.
			if n.Transport != "" || n.TLSAuth != "" || n.TLSName != "" || len(n.Pins) > 0 || n.CAFile != "" {
				lgConfig.Error("zone notify entry carries XoT fields, zone in error state", "zone", zname, "notify", n.Addr)
				zd.SetError(ConfigError, "notify %s: transport/tls-* not supported for notify targets", n.Addr)
				legacyNotify = true
				break
			}
		}
		if legacyNotify {
			broken_zones = append(broken_zones, zname)
			continue
		}

		// allow-notify: / downstreams: ACL validation — every ip-spec must parse
		// and every key must be NOKEY, BLOCKED, or a defined keys.tsig name.
		// A bad ACL quarantines just this zone (same rule as the primary check).
		if err := ValidateACL(zconf.AllowNotify, conf.tsigKeyDefined); err != nil {
			lgConfig.Error("zone allow-notify ACL invalid, zone in error state", "zone", zname, "err", err)
			zd.SetError(ConfigError, "allow-notify: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}
		if err := ValidateACL(zconf.Downstreams, conf.tsigKeyDefined); err != nil {
			lgConfig.Error("zone downstreams ACL invalid, zone in error state", "zone", zname, "err", err)
			zd.SetError(ConfigError, "downstreams: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}

		publishCadence, err := parsePublishCadence(zconf.PublishCadence)
		if err != nil {
			lgConfig.Error("zone publish-cadence invalid, zone in error state", "zone", zname, "err", err)
			zd.SetError(ConfigError, "publish-cadence: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}

		lgConfig.Debug("checking DNSSEC policy", "zone", zname)
		// dump.P(zconf)

		if zconf.DnssecPolicy == "none" {
			lgConfig.Info("DNSSEC policy is none, zone will not be signed", "zone", zname)
			zconf.DnssecPolicy = ""
		}
		if zconf.DnssecPolicy != "" {
			polName := zconf.DnssecPolicy
			usable, errMsg := resolveZonePolicyRef(polName, conf.Internal.DnssecPolicies)
			if errMsg != "" {
				lgConfig.Error("zone DNSSEC policy unusable, zone will not be signed", "zone", zname, "policy", polName, "err", errMsg)
				zconf.DnssecPolicy = ""
				zd.SetError(DnssecError, "%s", errMsg)
			} else if usable {
				lgConfig.Info("DNSSEC policy accepted", "zone", zname, "policy", polName)
			}
		}

		options := parseZoneOptions(conf, zname, zconf, zd)

		// Strip origination settings a tdns-auth secondary may not act on
		// (Fix B). This MUST run before activateUpdatePolicy below: that
		// function returns a HARD error — quarantining the zone — when
		// allow-child-updates is set without a delegationbackend, and a
		// secondary configured that way should get the soft warning and keep
		// serving, not be taken out of service. Running here also means the
		// delegation-sync setup block further down sees delegation-sync-parent
		// already false, so SetupZoneSync never registers for a secondary and
		// the DSYNC vector is closed at parse time with no extra wiring.
		//
		// zd.ZoneType is not yet assigned at this point in the parse, so the
		// locally resolved zonetype is passed explicitly.
		// Under zd.mu, which applyOptionNormalization requires. The zone is
		// still being constructed here and is not yet shared, so the lock is
		// uncontended -- it is taken to honour the contract, not because
		// anything is racing for it today.
		zd.mu.Lock()
		options, zconf.OutboundSoaSerial = zd.applyOptionNormalization(zonetype, options, zconf.OutboundSoaSerial)
		zd.mu.Unlock()
		// Validated per zone as well as globally: a per-zone override is the
		// more likely place for a typo, and it silently shadows a correct
		// global list rather than falling back to it.
		if err := ValidateTransferSrc(fmt.Sprintf("zone %s: transfer-src", zname), zconf.TransferSrc); err != nil {
			return nil, nil, err
		}
		zd.TransferSrc = zconf.TransferSrc

		var outopts []string
		for o, val := range options {
			if val {
				outopts = append(outopts, ZoneOptionToString[o])
			}
		}
		lgConfig.Debug("zone outgoing options", "zone", zname, "options", outopts)

		lgConfig.Info("zone configuration", "zone", zname, "type", zconf.Type, "store", zconf.Store, "primaries", zconf.Primaries, "notify", zconf.Notify, "zonefile", zconf.Zonefile)

		lgConfig.Debug("zone incoming update policy", "zone", zname, "policy", fmt.Sprintf("%+v", zconf.UpdatePolicy))

		// Captured BEFORE the call, because activateUpdatePolicy mutates
		// options in place: an absent or "none" child policy silently clears
		// allow-child-updates, and afterwards there is no way to tell a zone
		// that never asked for it from one whose request was dropped.
		wantedChildUpdates := options[OptAllowChildUpdates]

		policy, perr := activateUpdatePolicy(zconf, options)
		if perr != nil {
			lgConfig.Error("zone update policy invalid, zone in error state", "zone", zname, "err", perr)
			zd.SetError(ConfigError, "%s", perr)
			broken_zones = append(broken_zones, zname)
			continue
		}

		// Record it ON THE ZONE, not just in the log. The zone is otherwise
		// perfectly healthy -- it loads, serves, and simply refuses every child
		// update -- so a log line at startup is the only trace, and by the time
		// anyone asks why "zone list" no longer shows the option, that line has
		// scrolled away. ConfigWarning rather than ConfigError deliberately:
		// the zone is serving correctly for every other purpose and taking it
		// out of service would be a worse answer than telling the truth about
		// one disabled option.
		if wantedChildUpdates && !options[OptAllowChildUpdates] {
			zd.SetError(ConfigWarning,
				"allow-child-updates was requested but is DISABLED: updatepolicy.child.type "+
					"is unset or \"none\". Set it to selfsub or self.")
		}

		if Globals.App.Type == AppTypeAgent && zconf.Type == "primary" {
			// tdns-agent doesn't serve primary zones. MP roles are
			// hosted by tdns-mp (tdns-mpagent etc.), not by standalone
			// tdns-agent. A primary zone in a tdns-agent config is a
			// configuration error.
			lgConfig.Error("tdns-agent does not support primary zones, zone in error state", "zone", zname)
			zd.SetError(ConfigError, "tdns-agent does not support primary zones; use tdns-mpagent for multi-provider roles")
			broken_zones = append(broken_zones, zname)
			continue
		}

		// log.Printf("*** ParseZones: 5. Refreshch: %v", conf.Internal.RefreshZoneCh)

		// Validate this zone's configuration
		var zones = make(map[string]interface{}, 1)
		zones["zone:"+zname] = zconf
		if errmsg, err := ValidateBySection(conf, zones, "foobar"); err != nil {
			lgConfig.Error("zone validation failed, zone in error state", "zone", zname, "detail", errmsg)
			zd.SetError(ConfigError, "config validation: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}

		all_zones = append(all_zones, zname)

		// The registry entry (zd) was created up front; rebind to zdp
		// here for the remaining post-parse setup that uses zdp.
		zdp := zd

		// Apply static options via copy-on-write to avoid racing with
		// concurrent readers of zdp.Options / zdp.MP.MPdata.Options.
		// Build from fresh parsed options only; on reload this clears
		// options that were removed from the config file.
		newOpts := make(map[ZoneOption]bool, len(options))
		for opt, val := range options {
			newOpts[opt] = val
		}

		// Resolved here rather than in parseZoneOptions, which has nowhere to
		// put a value. It cannot fail: the option only survives the switch
		// when the block validates, so an off zone resolves the defaults and
		// nothing reads them.
		zonemdSet, _ := resolveZonemdConf(zconf.Zonemd)

		zdp.mu.Lock()
		// Whether this parse changes what the zone should publish. Captured
		// before the assignment, because a reload that turns publish-zonemd
		// OFF (or switches its algorithms) changes nothing in the zone itself,
		// so no publish would otherwise be queued -- and the stale ZONEMD
		// would go on being served until something unrelated touched the zone.
		zonemdChanged := zonemdSettingsDiffer(
			zdp.Options[OptPublishZonemd], zdp.zonemdScheme, zdp.zonemdAlgs,
			newOpts[OptPublishZonemd], zonemdSet.Scheme, zonemdSet.Algorithms)
		zdp.Options = newOpts
		zdp.publishCadence = publishCadence
		zdp.ixfrChainMaxBytes = zconf.IxfrChainMaxBytes
		zdp.zonemdScheme = zonemdSet.Scheme
		zdp.zonemdAlgs = zonemdSet.Algorithms
		zdp.zonemdOnVerifyFailure = zonemdSet.OnVerifyFailure
		// A changed budget takes effect on the next digest: zonemdDigestsLocked
		// reads it every pass, admits within it and prunes what no longer fits
		// on the pass after that. Nothing to invalidate here.
		zdp.zonemdWireCacheMaxBytes = zonemdSet.WireCacheMaxBytes
		// A zone that has never published has nothing to correct, and the
		// first load publishes with the new settings anyway.
		zonemdChanged = zonemdChanged && zdp.snapshot.Load() != nil
		zdp.mu.Unlock()

		if zonemdChanged {
			lgConfig.Info("zonemd configuration changed; republishing the zone to apply it",
				"zone", zname, "publish", newOpts[OptPublishZonemd])
			zdp.requestPublish(false)
		}

		invokeOptionHandlers(zname, options)

		// Wire the delegation backend synchronously on every parse pass
		// (initial load + reload). Backend constructors don't touch zone
		// data, so this works before FirstZoneLoad has completed.
		// Config validation above guarantees that OptAllowChildUpdates
		// implies a non-empty zconf.DelegationBackend.
		if options[OptAllowChildUpdates] {
			kdb := conf.Internal.KeyDB
			if kdb == nil {
				lgConfig.Error("KeyDB unavailable, cannot wire delegation backend", "zone", zname)
				zd.SetError(ConfigError, "KeyDB unavailable")
				broken_zones = append(broken_zones, zname)
				continue
			}
			backend, err := LookupDelegationBackend(zconf.DelegationBackend, kdb, zdp)
			if err != nil {
				lgConfig.Error("failed to create delegation backend, zone in error state", "zone", zname, "backend", zconf.DelegationBackend, "error", err)
				zd.SetError(ConfigError, "delegationbackend %q: %v", zconf.DelegationBackend, err)
				broken_zones = append(broken_zones, zname)
				continue
			}
			zdp.mu.Lock()
			zdp.DelegationBackend = backend
			zdp.mu.Unlock()
			lgConfig.Info("delegation backend wired", "zone", zname, "backend", backend.Name())
		} else {
			// Reload may have cleared OptAllowChildUpdates; drop any
			// previously-wired backend so the live state matches config.
			zdp.mu.Lock()
			zdp.DelegationBackend = nil
			zdp.mu.Unlock()
		}

		lgConfig.Info("evaluating zone option flags", "zone", zname,
			"online-signing", options[OptOnlineSigning],
			"inline-signing", options[OptInlineSigning],
			"multi-provider", options[OptMultiProvider],
			"firstLoad", zdp.FirstZoneLoad,
			"apptype", AppTypeToString[Globals.App.Type])

		// Condition checks are evaluated on every parse pass (initial +
		// reload) so config-reload picks up flag changes. The setup
		// functions need the zone to be loaded; on initial load we defer
		// via OnFirstLoad, on reload (zone already loaded) we call them
		// directly. The setup functions are idempotent.

		// Signing setup: zones with explicit signing options in config.
		//
		// First load: sign once the zone data is available (deferred via
		// OnFirstLoad). Reload: we deliberately do NOT sign synchronously here.
		// A synchronous SignZone on the reload branch ran under confMu (held
		// across ParseZones by ReloadZoneConfig), serializing every signed
		// zone's signing behind the global config lock (Finding 4). It was also
		// redundant: the config-bearing forced refresh queued for every zone at
		// the end of this loop already re-signs off-lock in the RefreshEngine —
		// triggerResign() when the policy rebinds (see applyReloadedPolicyLocked
		// in refreshengine.go) and the post-refresh SetupZoneSigning when the
		// zone data changed. Both run in the refresh path, not under confMu.
		if options[OptOnlineSigning] || options[OptInlineSigning] {
			if zdp.FirstZoneLoad {
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
					if err := zd.SetupZoneSigning(conf.Internal.ResignQ); err != nil {
						lgConfig.Error("SetupZoneSigning failed in OnFirstLoad", "zone", zd.ZoneName, "error", err)
					}
				})
			}
		}

		// Sig-validity floor: config-load check on every parse pass so
		// policy/kasp edits on reload refresh DnssecError/Warning state.
		if options[OptOnlineSigning] || options[OptInlineSigning] {
			if zdp.DnssecPolicy != nil {
				UpdateSigValidityFloor(zdp, zdp.DnssecPolicy, conf.KaspPropagationDelay(), 0, false, conf.IsLargeAlgorithm, false)
			}
		}

		// Rollover policy validation: requires loaded zone data. Only
		// registered on first load; the ObserveParentDSTTL goroutine it
		// spawns is long-running and re-spawning on reload would leak.
		// (See follow-up: make rollover setup reload-safe.)
		if zdp.FirstZoneLoad {
			zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
				if zd.DnssecPolicy == nil || zd.DnssecPolicy.Rollover.Method == RolloverMethodNone {
					return
				}
				EvaluateRolloverPolicyInvariants(zd, zd.DnssecPolicy)
				// Use the ParseZones ctx so the parent-DS observation
				// goroutine cancels on daemon shutdown.
				go ObserveParentDSTTL(ctx, zd, zd.DnssecPolicy)
			})
		}

		// Delegation sync setup: DSYNC publication (parent) or
		// delegation sync monitoring (child), or proxy forwarding for a
		// DSYNC-unaware primary (agent secondary).
		if options[OptDelSyncParent] || options[OptDelSyncChild] || options[OptDelSyncProxy] {
			capturedOpts := options
			setupSync := func(zd *ZoneData) {
				// Skip if the MP HSYNCPARAM callback already set up delegation sync for this zone.
				if zd.Options[OptDelSyncChild] && !capturedOpts[OptDelSyncChild] {
					return
				}
				if zd.Options[OptDelSyncParent] && !capturedOpts[OptDelSyncParent] {
					return
				}
				delegationSyncQ := conf.Internal.DelegationSyncQ
				if delegationSyncQ == nil {
					lgConfig.Error("DelegationSyncQ not available", "zone", zd.ZoneName)
					return
				}
				if err := zd.SetupZoneSync(delegationSyncQ); err != nil {
					lgConfig.Error("SetupZoneSync failed", "zone", zd.ZoneName, "error", err)
				}
			}
			if zdp.FirstZoneLoad {
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, setupSync)
			} else {
				setupSync(zdp)
			}
		}

		// delegation-sync-proxy: register the post-transfer change-detection
		// hook so an agent secondary forwards NOTIFY(CDS/CSYNC) to the parent
		// when a relevant RRset changes in an incoming transfer. The hook is an
		// OnZonePreRefresh callback (it needs both old and new zone data to
		// diff) that records what changed in zd.ProxyRefreshAnalysis; the
		// matching OnZonePostRefresh callback acts on it (P-3). Mirrors the
		// tdns-mp MPPreRefresh/PostRefresh pattern (tdns-mp/v2/config.go), for
		// the non-MP agent path.
		// Register only on first load: on reload zdp is the existing registry
		// entry and its OnZone*Refresh slices already carry these hooks, so
		// appending again would accumulate duplicates (same convention as the
		// OnFirstLoad-guarded setupSync block above).
		if options[OptDelSyncProxy] && zdp.FirstZoneLoad {
			delegationSyncQ := conf.Internal.DelegationSyncQ
			zdp.OnZonePreRefresh = append(zdp.OnZonePreRefresh,
				func(zd, new_zd *ZoneData) {
					zd.ProxyDelegationPreRefresh(new_zd)
				})
			zdp.OnZonePostRefresh = append(zdp.OnZonePostRefresh,
				func(zd *ZoneData) {
					zd.ProxyDelegationPostRefresh(delegationSyncQ)
				})
		}

		// Note: DelegationBackend wiring is done synchronously above,
		// outside the FirstZoneLoad guard, so config-reload picks up
		// changes to the 'delegationbackend' key.

		// Republish-at-signal-names consumer (RFC 9615 at-NS bootstrap):
		// every tdns-auth SECONDARY watches incoming transfers for an apex
		// HSYNCPARAM pubkey/pubcds flag and republishes the customer's apex
		// KEY / CDS(+CDNSKEY) under the _sig0key/_dsboot signal names owned
		// by each NS, into whichever local primary zone the signal name
		// falls in. Always-on, no option gate (see signal_republish.go).
		// Registered only on first load (the OnZonePostRefresh slice would
		// otherwise accumulate duplicate callbacks across reloads).
		if Globals.App.Type == AppTypeAuth && zonetype == Secondary && zdp.FirstZoneLoad {
			zdp.OnZonePostRefresh = append(zdp.OnZonePostRefresh, func(zd *ZoneData) {
				zd.RepublishAtSignalNames()
			})
		}

		// Leader election OnFirstLoad is registered in StartAgent() (not here)
		// because LeaderElectionManager doesn't exist until StartAgent runs.
		// MP zone KEY publication is registered in tdns-mp's StartAgent.

		// Collect zones where a GLOBAL persist/unixtime outbound mode is being
		// suppressed, from the role and per-zone mode resolved in THIS pass.
		// (Reading them back off the registry instead would see a ZoneType the
		// RefreshEngine has not assigned yet — see serialSuppressionCandidate.)
		//
		// Deliberately here, at the bottom of the loop body: every `continue`
		// above rejects the zone (bad ACL, invalid update policy, unusable
		// store, ...), and a rejected zone is not serving, so reporting it as a
		// secondary with a suppressed serial policy would be noise about a zone
		// that is not running at all.
		if serialSuppressionCandidate(Globals.App.Type, zonetype, options, zconf.OutboundSoaSerial) {
			serialSuppressedZones = append(serialSuppressedZones, zname)
		}

		// Non-zone-serving app types skip zone refresh. Everything
		// else (Auth, Agent, downstream MP/NM/ES roles) queues each
		// parsed zone for refresh.
		switch Globals.App.Type {
		case AppTypeImr, AppTypeCli, AppTypeReporter, AppTypeScanner, AppTypeKdc, AppTypeKrs, AppTypeEdgeSigner:
			// skip — these app types don't serve zones
		default:
			if conf.Internal.RefreshZoneCh == nil {
				lgConfig.Error("refresh channel is not configured, zones will not be refreshed, terminating")
				return nil, nil, errors.New("parseZones: error: refresh channel is not configured, zones will not be refreshed, terminating")
			}
			zr := ZoneRefresher{
				Name:           zname,
				Force:          true,     // force refresh, ignoring SOA serial, when reloading from file
				ZoneType:       zonetype, // primary | secondary
				PrimariesConf:  clonePeerConfs(zconf.Primaries),
				Primaries:      resolvedPrimaries,
				ZoneStore:      zonestore,
				Notify:         zconf.Notify,
				AllowNotify:    zconf.AllowNotify,
				Downstreams:    zconf.Downstreams,
				DownstreamAuth: zconf.DownstreamAuth,
				ConfigUpdate:   true, // config-bearing: lets reload clear removed ACLs
				Zonefile:       zconf.Zonefile,
				Options:        options,
				UpdatePolicy:   policy,
				DnssecPolicy:   zconf.DnssecPolicy,
				// Always carried (empty == inherit the global), so a config
				// edit that REMOVES a per-zone mode actually reverts the zone
				// to the global on reload instead of keeping the stale value.
				OutboundSoaSerial: zconf.OutboundSoaSerial,
			}
			select {
			case conf.Internal.RefreshZoneCh <- zr:
			case <-ctx.Done():
				return all_zones, broken_zones, ctx.Err()
			}
		}
	}

	lgConfig.Info("zones parsed and refreshing", "count", len(all_zones), "zones", all_zones, "broken", broken_zones, "queued", len(conf.Internal.RefreshZoneCh))

	warnGlobalOutboundSerialSuppressed(conf, serialSuppressedZones)

	lgConfig.Debug("ParseZones complete")
	return all_zones, broken_zones, nil
}

// warnGlobalOutboundSerialSuppressed tells the operator, once per parse, that a
// server-wide outbound-soa-serial of persist/unixtime is being ignored for the
// tdns-auth secondaries on this server.
//
// The option normalizer warns per zone about an EXPLICIT per-zone mode, but a
// secondary that merely inherits a global one gets no per-zone warning — that
// would be noise on every secondary of a server whose primaries legitimately
// use persist. Without this, though, the suppression would be entirely
// invisible: the operator set a server-wide policy and some zones quietly do
// not follow it. Name them once instead.
//
// suppressed is collected by the caller DURING the parse loop, from the
// zonetype/options/serial-mode it has just resolved. It deliberately does NOT
// re-scan the Zones registry: zd.ZoneType is assigned asynchronously by the
// RefreshEngine when it consumes the ZoneRefresher, so at this point a
// cold-start registry entry still has ZoneType == 0 — which would read as
// "not a primary" and mis-report every zone without inline-signing, PRIMARIES
// INCLUDED, as a suppressed secondary. On reload it would read the previous
// parse's values rather than this one's.
// serialSuppressionCandidate reports whether a zone — described by the role,
// options and per-zone mode resolved DURING the parse — is one where a global
// persist/unixtime outbound mode will be silently suppressed.
//
// Takes loose values rather than a *ZoneData on purpose: the registry entry's
// ZoneType is assigned asynchronously by the RefreshEngine, so at parse time it
// is still 0 and reading it would classify primaries as secondaries.
//
// A zone carrying its OWN explicit mode is not a candidate: the normalizer
// already warned about it per zone, and reporting it twice would just be noise.
func serialSuppressionCandidate(appType AppType, ztype ZoneType, opts map[ZoneOption]bool, perZoneMode string) bool {
	if appType != AppTypeAuth || perZoneMode != "" {
		return false
	}
	return ztype == Secondary && !opts[OptInlineSigning]
}

func warnGlobalOutboundSerialSuppressed(conf *Config, suppressed []string) {
	mode := strings.TrimSpace(strings.ToLower(conf.AuthEngine.OutboundSoaSerial))
	if mode != OutboundSoaSerialPersist && mode != OutboundSoaSerialUnixtime {
		return
	}
	if Globals.App.Type != AppTypeAuth || len(suppressed) == 0 {
		return
	}
	sort.Strings(suppressed)
	lgConfig.Warn("global outbound-soa-serial is suppressed for secondary zones",
		"mode", mode, "count", len(suppressed), "zones", suppressed,
		"reason", "a secondary must serve the serial it received from upstream, unmodified")
}

// activateUpdatePolicy validates a zone's update-policy config and builds the
// runtime UpdatePolicy, mutating options to reflect it: a "none"/unset policy
// type forces the corresponding OptAllowChildUpdates/OptAllowUpdates option
// off, and allow-child-updates without a delegation backend is refused (the
// write path would mutate in-memory zone data while the scanner queries the
// nil backend — silent misbehavior). Extracted verbatim from ParseZones so the
// dynamic-primary add/load paths activate policy through the SAME code and
// cannot drift; error strings are the exact former ConfigError texts. Unknown
// RRtype names are silently dropped (pre-extraction behavior, preserved).
func activateUpdatePolicy(zconf *ZoneConf, options map[ZoneOption]bool) (UpdatePolicy, error) {
	switch zconf.UpdatePolicy.Child.Type {
	case "selfsub", "self":
		// all ok, we know these
	case "none", "":
		// these are also ok, but imply that no updates are allowed
		//
		// Say so when the operator asked for the opposite. Clearing an option
		// the config explicitly requested, silently, produces a zone that
		// starts, looks healthy, and refuses every child update -- with the
		// option simply absent from "zone list" and nothing anywhere saying
		// why. An unset policy is the easy way to hit this, because "" lands
		// in the same case as an explicit "none".
		if options[OptAllowChildUpdates] {
			why := "no updatepolicy.child.type is set"
			if zconf.UpdatePolicy.Child.Type == "none" {
				why = "updatepolicy.child.type is \"none\""
			}
			lgConfig.Error("allow-child-updates requested but DISABLED by update policy",
				"zone", zconf.Name, "reason", why,
				"fix", "set updatepolicy.child.type to selfsub or self")
		}
		options[OptAllowChildUpdates] = false
	default:
		return UpdatePolicy{}, fmt.Errorf("unknown child update policy type: %s", zconf.UpdatePolicy.Child.Type)
	}

	// A zone that accepts child updates MUST have a delegation backend.
	// Without one, the write path mutates in-memory zone data while the
	// scanner read path queries the (nil) backend, so diff computation
	// always sees "empty current state" and child updates accumulate
	// without ever being removed. Refuse to start such a zone rather
	// than letting it silently misbehave.
	if options[OptAllowChildUpdates] && zconf.DelegationBackend == "" {
		return UpdatePolicy{}, fmt.Errorf("allow-child-updates requires delegationbackend to be configured (e.g. 'delegationbackend: direct')")
	}

	// Conflict resolution: exactly one of the two is always set on the zone.
	//
	// Setting both is a contradiction, not a preference order, so it is a hard
	// config error rather than a silent pick.
	//
	// Otherwise db-wins is MATERIALISED here rather than left to be inferred at
	// each decision point. A default that lives in the code as "if neither is
	// set, assume db-wins" has to be remembered everywhere it is asked, and the
	// day one site forgets, a zone quietly resolves conflicts the other way.
	// Setting it once means the merge faces a question with two answers rather
	// than three, and `zone status` reports what the zone actually runs under
	// instead of a blank the operator has to interpret.
	if options[OptOnConflictDBWins] && options[OptOnConflictZonefileWins] {
		return UpdatePolicy{}, fmt.Errorf(
			"zone options on-conflict-db-wins and on-conflict-zonefile-wins are mutually exclusive;" +
				" set one or neither (neither means on-conflict-db-wins)")
	}
	if !options[OptOnConflictZonefileWins] {
		options[OptOnConflictDBWins] = true
	}

	// With the conflict options settled, the backend can be checked against
	// them. Order matters: rule (2) below reads OptOnConflictDBWins.
	// Only when the backend can actually run. Without allow-child-updates
	// nothing ever reaches the backend, so a combination that "cannot work" has
	// no effect to speak of -- and failing here would mark the zone broken and
	// refuse to load it over a setting that does nothing.
	//
	// delegationBackendUnusedWarning is the right response to that case, and it
	// only gets the chance to say so if we do not error first.
	if options[OptAllowChildUpdates] {
		if err := validateDelegationBackendCombination(zconf, options); err != nil {
			return UpdatePolicy{}, err
		}
	}
	if msg := delegationBackendUnusedWarning(zconf, options); msg != "" {
		lgConfig.Warn(msg, "zone", zconf.Name)
	}
	if msg := delegationBackendContract(zconf, options); msg != "" {
		lgConfig.Info(msg, "zone", zconf.Name, "backend", zconf.DelegationBackend)
	}

	switch zconf.UpdatePolicy.Zone.Type {
	case "selfsub", "self":
		// all ok, we know these
	case "none", "":
		// these are also ok, but imply that no updates are allowed
		options[OptAllowUpdates] = false
	default:
		return UpdatePolicy{}, fmt.Errorf("unknown update policy type: %s", zconf.UpdatePolicy.Zone.Type)
	}

	var rrt uint16
	var exist bool
	childrrtypes := map[uint16]bool{}
	for _, rrtype := range zconf.UpdatePolicy.Child.RRtypes {
		rrtype = strings.ToUpper(rrtype)
		if rrt, exist = dns.StringToType[rrtype]; exist {
			childrrtypes[rrt] = true
		}
	}

	zonerrtypes := map[uint16]bool{}
	for _, rrtype := range zconf.UpdatePolicy.Zone.RRtypes {
		rrtype = strings.ToUpper(rrtype)
		if rrt, exist = dns.StringToType[rrtype]; exist {
			zonerrtypes[rrt] = true
		}
	}

	childTTL := zconf.UpdatePolicy.Child.TTL
	if childTTL == 0 {
		childTTL = 120
	}
	zoneTTL := zconf.UpdatePolicy.Zone.TTL
	if zoneTTL == 0 {
		zoneTTL = 120
	}
	return UpdatePolicy{
		Child: UpdatePolicyDetail{
			Type:         zconf.UpdatePolicy.Child.Type,
			RRtypes:      childrrtypes,
			KeyBootstrap: zconf.UpdatePolicy.Child.KeyBootstrap,
			KeyUpload:    zconf.UpdatePolicy.Child.KeyUpload,
			TTL:          childTTL,
		},
		Zone: UpdatePolicyDetail{
			Type:    zconf.UpdatePolicy.Zone.Type,
			RRtypes: zonerrtypes,
			TTL:     zoneTTL,
		},
	}, nil
}

// ExpandTemplate applies template tmpl's settings to zone zconf. Every config
// field the template SETS is copied to the zone UNLESS the zone already set it
// (the zone always wins), so new ZoneConf config fields are propagated
// automatically without editing this function. Three fields need bespoke
// handling and are excluded from the generic copy: Zonefile (%-substituted with
// the zone name), OptionsStrs (unioned, not gap-filled) and DnssecPolicy (gated
// off for agents). Name and Template are never copied from a template. Runtime/
// display fields (Error, Frozen, RefreshCount, Provisioning, …) are never set in
// a template config, so the zero-value check skips them naturally.
func ExpandTemplate(zconf ZoneConf, tmpl *ZoneConf, appMode AppType) (ZoneConf, error) {
	// --- bespoke fields (cannot be a plain gap-fill copy) ---

	// Zonefile: the template carries a pattern that is %-substituted with the
	// zone name, not copied verbatim.
	if zconf.Zonefile == "" && tmpl.Zonefile != "" {
		if strings.ContainsAny(zconf.Name, "%") {
			return zconf, fmt.Errorf("zone name %q contains format specifiers", zconf.Name)
		}
		expanded := filepath.Clean(fmt.Sprintf(tmpl.Zonefile, zconf.Name))
		if strings.Contains(expanded, "..") {
			return zconf, fmt.Errorf("expanded zonefile path %q contains directory traversal", expanded)
		}
		zconf.Zonefile = expanded
	}

	// OptionsStrs: union (append template options the zone lacks), not gap-fill.
	for _, option := range tmpl.OptionsStrs {
		if !slices.Contains(zconf.OptionsStrs, option) {
			zconf.OptionsStrs = append(zconf.OptionsStrs, option)
		}
	}

	// DnssecPolicy: gap-fill, but agents do not sign so it is gated off there.
	if appMode != AppTypeAgent && zconf.DnssecPolicy == "" && tmpl.DnssecPolicy != "" {
		zconf.DnssecPolicy = tmpl.DnssecPolicy
	}

	// Zonemd: merged FIELD BY FIELD, not copied whole. Under the shallow rule
	// below a struct field is taken from the template only when the zone's is
	// entirely zero, so a zone that sets one field of the block -- say
	// `algorithms` -- would silently drop every other field the template gave
	// it, `on-verify-failure` included. That is the wrong direction for a
	// block that carries policy: the zone author sets the field they care
	// about and has no reason to expect the fleet-wide setting beside it to
	// vanish. Merging per field means the zone overrides what it names and
	// inherits the rest.
	//
	// (The gapFillStruct caveat applies within the block: a leaf counts as set
	// only when non-zero, so a zone cannot override a template's value back to
	// the zero value. For wire-cache-max-bytes, whose 0 means "default", the
	// way to say "not the template's size" is the explicit -1 that disables
	// caching.)
	gapFillStruct(reflect.ValueOf(&zconf.Zonemd).Elem(),
		reflect.ValueOf(&tmpl.Zonemd).Elem(), nil, false)

	// --- generic gap-fill for every other config field (zone wins) ---
	// Shallow (deep=false): UpdatePolicy is copied whole if the zone left it
	// unset. Zonemd is the one nested block that wants a per-field merge and
	// is handled above.
	// A template config never sets runtime/display fields, so IsZero skips them.
	bespoke := map[string]bool{
		"Name": true, "Template": true, // never copied from a template
		"Zonefile": true, "OptionsStrs": true, "DnssecPolicy": true, // handled above
		"Zonemd": true, // handled above (per-field merge, not whole-block copy)
		// DynamicZones is a property of the TEMPLATE (API-instantiable), not
		// of the zones stamped out from it — never copied.
		"DynamicZones": true,
	}
	gapFillStruct(reflect.ValueOf(&zconf).Elem(), reflect.ValueOf(tmpl).Elem(), bespoke, false)
	return zconf, nil
}

// gapFillStruct fills fields of dst that are still at their zero value from the
// matching field of src; dst always wins. dst and src must be addressable
// structs of the same type. skip names top-level fields that are never copied.
//
// When deep is false a struct-typed field is treated as a single value (copied
// whole only if dst's is entirely zero). When deep is true a struct-typed field
// is merged recursively, so dst can set part of a nested block and inherit the
// rest from src. Slices are cloned so dst never aliases src's backing array.
//
// Caveat (both modes): a leaf counts as "set" iff it is non-zero, so dst cannot
// override an src value back to the zero value ("" / 0 / false / nil) — that
// reads as unset and src fills it.
func gapFillStruct(dst, src reflect.Value, skip map[string]bool, deep bool) {
	for i := 0; i < dst.NumField(); i++ {
		if skip[dst.Type().Field(i).Name] {
			continue
		}
		df, sf := dst.Field(i), src.Field(i)
		if !df.CanSet() {
			continue
		}
		if deep && df.Kind() == reflect.Struct {
			gapFillStruct(df, sf, nil, deep) // skip set applies only at the top level
			continue
		}
		if !df.IsZero() || sf.IsZero() {
			continue // dst already set it, or src has nothing to give
		}
		if df.Kind() == reflect.Slice {
			c := reflect.MakeSlice(df.Type(), sf.Len(), sf.Len())
			reflect.Copy(c, sf)
			df.Set(c)
		} else {
			df.Set(sf)
		}
	}
}

// ExpandPolicyTemplate fills the gaps in a DNSSEC policy from a named template
// (the policy's own values win). Unlike zone templates it deep-merges: a policy
// that sets only some fields of a nested block (ksk, zsk, rollover, ttls,
// sigvalidity, clamping, ...) inherits the remaining fields of that block from
// the template, rather than overriding the whole block.
func ExpandPolicyTemplate(pconf DnssecPolicyConf, tmpl *DnssecPolicyConf) DnssecPolicyConf {
	skip := map[string]bool{"Name": true, "Template": true}
	gapFillStruct(reflect.ValueOf(&pconf).Elem(), reflect.ValueOf(tmpl).Elem(), skip, true)
	return pconf
}

// resolveDnssecPolicyTemplate applies a policy's `template:` reference (if any)
// by deep-merging the named template into dp (the policy's own values win).
// Returns the possibly-expanded policy, or an error if the referenced template
// is unknown. Shared by the runtime config parse and the standalone
// `policy validate --file` path so the two cannot drift.
func resolveDnssecPolicyTemplate(dp DnssecPolicyConf, templates map[string]DnssecPolicyConf) (DnssecPolicyConf, error) {
	if dp.Template == "" {
		return dp, nil
	}
	tmpl, ok := templates[dp.Template]
	if !ok {
		return dp, fmt.Errorf("references unknown dnssec template %q", dp.Template)
	}
	return ExpandPolicyTemplate(dp, &tmpl), nil
}

// buildTemplateMap rebuilds the global Templates map from conf.Templates.
// Called from ParseConfig() and reloadTemplatesFromFile().
func (conf *Config) buildTemplateMap() error {
	if Globals.App.Type == AppTypeReporter || Globals.App.Type == AppTypeImr {
		return nil
	}

	// Build template map
	Templates = make(map[string]ZoneConf) // Clear existing entries on reload
	for _, tmpl := range conf.Templates {
		if tmpl.Name == "" {
			return fmt.Errorf("template missing required 'name' field")
		}
		if _, exists := Templates[tmpl.Name]; exists {
			return fmt.Errorf("duplicate template name: %s", tmpl.Name)
		}
		Templates[tmpl.Name] = tmpl
	}

	// Handle template expansion if specified
	// Robust expansion with cycle detection
	var done = make(map[string]bool)
	for _, t := range conf.Templates {
		if _, ok := Templates[t.Name]; !ok {
			continue
		}
		_, _ = expandTemplateChain(t.Name, []string{}, make(map[string]bool), done, Globals.App.Type)
	}

	lgConfig.Debug("buildTemplateMap complete", "count", len(Templates))
	return nil
}

// reloadTemplatesFromFile re-reads the config file and rebuilds the Templates map.
// Used by ReloadZoneConfig() to pick up template changes without a full config reload.
func (conf *Config) reloadTemplatesFromFile() error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		return nil
	}

	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0, newMergeState())
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	// Decode only the templates from the config
	// Note: TagName:"yaml" means mapstructure reads yaml struct tags
	var partial struct {
		Templates []ZoneConf `yaml:"templates"`
	}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  &partial,
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}
	if err := decoder.Decode(configMap); err != nil {
		return fmt.Errorf("error decoding templates: %v", err)
	}

	conf.Templates = partial.Templates
	return conf.buildTemplateMap()
}

// reloadDnssecFromFile re-reads the config file, decodes just the dnssec:
// block into conf.Dnssec, and re-parses it into conf.Internal.*. Used by the
// zone-reload paths so an edited policy (or other dnssec setting) is picked up
// without a full config reload — parseDnssecConfig alone would re-parse the
// already-decoded (startup) conf.Dnssec, missing the operator's edits. Mirrors
// reloadTemplatesFromFile.
func (conf *Config) reloadDnssecFromFile() error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		// No config file (e.g. embedded use) — just re-parse what we have.
		return conf.parseDnssecConfig()
	}

	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0, newMergeState())
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	var partial struct {
		Dnssec DnssecConf `yaml:"dnssec"`
	}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  &partial,
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}
	if err := decoder.Decode(configMap); err != nil {
		return fmt.Errorf("error decoding dnssec config: %v", err)
	}

	conf.Dnssec = partial.Dnssec
	return conf.parseDnssecConfig()
}

// reloadZonesFromFile re-reads the config file(s), decodes just the zones: block,
// and replaces conf.Zones. Used by the zone-reload path (ReloadZoneConfig) so a
// config-file edit to the ZONE set — an added or removed zone, or a changed
// dnssecpolicy/primaries/ACLs/options/zonefile — is picked up by a single
// `reload-zones`, not only policy-definition edits. Without this, ParseZones
// iterates the stale startup conf.Zones (the longstanding "must get the zones
// config file from outside" gap in ReloadZoneConfig), so zone edits needed a
// restart. Uses the SAME decode hooks + ZeroFields as the full ParseConfig so a
// legacy bare-string primary:/notify: entry decodes to a PeerConf legacy marker
// (quarantined per-zone) instead of failing the whole decode, and so a zone whose
// YAML omits a field does not inherit a stale slot-neighbour's value.
func (conf *Config) reloadZonesFromFile() error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		// No config file (e.g. embedded use) — keep the in-memory zone set.
		return nil
	}

	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0, newMergeState())
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	var partial struct {
		Zones []ZoneConf `yaml:"zones"`
	}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName:    "yaml",
		Result:     &partial,
		ZeroFields: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			stringToPeerConfHook(),
			stringToAclEntryHook(),
		),
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}
	if err := decoder.Decode(configMap); err != nil {
		return fmt.Errorf("error decoding zones config: %v", err)
	}

	conf.Zones = partial.Zones
	return nil
}

// reloadImrEngineFromFile re-reads the config file(s) and decodes just the
// RELOADABLE half of the imrengine: block -- stubs and forward zones -- into
// conf.Imr. Used by the zone-reload path (SIGHUP), which otherwise re-reads
// zones and DNSSEC policy only, so a stub or forward edit needed a restart
// (#436).
//
// Reads only: conf.Imr is NOT touched here. Decoding cleanly is not the same
// as being usable -- ReloadZones still refuses, say, trust-ad over a plaintext
// upstream -- and committing at decode time left conf.Imr describing zones
// that were then rejected, while the resolver kept running the old ones. The
// caller commits the two reloadable fields once the apply has succeeded.
//
// The whole decoded block is returned, and the caller needs all of it:
// imrRestartRequiredKeys diffs it against what the Imr was built from, to name
// the edited keys a reload cannot apply. Diffing against conf.Imr instead
// would compare the boot values with themselves on this path and report
// nothing. Only Stubs and Forward are ever copied into conf.Imr, though --
// copying tuning or the trust anchors would leave it advertising values the
// running resolver is not using, and `config status` would describe a
// resolver that does not exist.
//
// Returns a nil block when there is no config file to read (embedded use);
// the caller then falls back to whatever is in memory.
func (conf *Config) reloadImrEngineFromFile() (*ImrEngineConf, error) {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		// No config file (e.g. embedded use): keep the in-memory zones.
		return nil, nil
	}

	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0, newMergeState())
	if err != nil {
		return nil, fmt.Errorf("error processing config: %v", err)
	}

	raw, present := configMap["imrengine"]
	if !present {
		// No imrengine: block at all. Legitimate — an app whose config
		// configures no resolver zones — and distinct from a mistyped one,
		// which the strict decode below catches. The empty block clears the
		// zones when the caller commits it.
		return &ImrEngineConf{}, nil
	}

	// Decode the block into the REAL ImrEngineConf, with ErrorUnused, rather
	// than into a two-field partial. A partial ignores every key it does not
	// name, so a typo -- `forwrd:` for `forward:` -- would decode to an empty
	// list and this function would then hand ReloadZones an empty table: a
	// misspelling would silently DELETE every forward zone on the next
	// SIGHUP. Decoding the whole block means an unknown key anywhere in it
	// fails the reload instead, and the running zones are kept.
	//
	// Same hooks as the full parse (decodeConfigMap), or `query-budget: 8s`
	// -- valid in the config the daemon booted from -- would fail here.
	var block ImrEngineConf
	decoderConfig := &mapstructure.DecoderConfig{
		TagName:     "yaml",
		Result:      &block,
		ZeroFields:  true,
		ErrorUnused: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
		),
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating decoder: %v", err)
	}
	if err := decoder.Decode(raw); err != nil {
		return nil, fmt.Errorf("error decoding imrengine config: %v", err)
	}

	return &block, nil
}

// reloadTsigKeysFromFile re-reads the config file and decodes just the keys:
// block into conf.Keys. Used by reload-tsig without a full config reload.
func (conf *Config) reloadTsigKeysFromFile() error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		return nil
	}

	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0, newMergeState())
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	var partial struct {
		Keys KeyConf `yaml:"keys"`
	}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  &partial,
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}
	if err := decoder.Decode(configMap); err != nil {
		return fmt.Errorf("error decoding keys config: %v", err)
	}

	conf.Keys = partial.Keys
	return nil
}

// expandTemplateChain expands a template by following its parent chain (via the Template field)
// using DFS with cycle detection. It updates the global Templates map with the fully expanded
// template on success. If a cycle is detected, all templates in the cycle are removed from the
// Templates map and an error is returned. Missing parent references also remove the referring
// template.
func expandTemplateChain(name string, stack []string, onStack map[string]bool, done map[string]bool, appMode AppType) (ZoneConf, error) {
	if done[name] {
		return Templates[name], nil
	}
	t, exists := Templates[name]
	if !exists {
		return ZoneConf{}, fmt.Errorf("expandTemplateChain: template %q not found", name)
	}

	if onStack[name] {
		// Cycle detected: find cycle in stack
		var cycle []string
		for i := range stack {
			if stack[i] == name {
				cycle = append([]string{}, stack[i:]...)
				break
			}
		}
		cycle = append(cycle, name)
		lgConfig.Error("template cycle detected", "cycle", strings.Join(cycle, " -> "))
		for _, n := range cycle {
			delete(Templates, n)
		}
		return ZoneConf{}, fmt.Errorf("template cycle: %s", strings.Join(cycle, " -> "))
	}

	onStack[name] = true
	stack = append(stack, name)

	if t.Template != "" && t.Template != name {
		parent, exists := Templates[t.Template]
		if !exists {
			lgConfig.Warn("template refers to non-existing template, ignored", "template", t.Name, "parent", t.Template)
			delete(Templates, t.Name)
			onStack[name] = false
			return ZoneConf{}, fmt.Errorf("missing parent template %q for %q", t.Template, t.Name)
		}
		// Recurse to expand parent first
		expandedParent, err := expandTemplateChain(parent.Name, stack, onStack, done, appMode)
		if err != nil {
			onStack[name] = false
			return ZoneConf{}, err
		}
		// Apply parent's fields into child
		expandedChild, err := ExpandTemplate(t, &expandedParent, appMode)
		if err != nil {
			lgConfig.Error("error expanding template from parent", "template", t.Name, "parent", t.Template, "err", err)
			delete(Templates, t.Name)
			onStack[name] = false
			return ZoneConf{}, err
		}
		t = expandedChild
	} else if t.Template == name {
		// Self-cycle
		lgConfig.Error("self-referential template cycle, removing", "template", name)
		delete(Templates, name)
		onStack[name] = false
		return ZoneConf{}, fmt.Errorf("self-referential template %q", name)
	}

	// Mark done and store expanded result
	done[name] = true
	onStack[name] = false
	Templates[name] = t
	return t, nil
}

// parseDnssecConfig resolves the entire dnssec: block (large-algorithms,
// split-algorithms, kasp, and the named policies) from conf.Dnssec into the
// derived conf.Internal.* structures. Called from ParseConfig at startup, and
// from the zone-reload paths so that reloading zones also refreshes the policy
// definitions they depend on (closing the "reload policies before zones" gap).
//
// Rebuilds conf.Internal.DnssecPolicies from scratch every call: on reload,
// removed or rejected policies must not survive from the previous parse. A
// policy that fails to parse is kept in the map with its Error field set
// (visible to the operator; zones referencing it are quarantined), rather than
// dropped — the server still starts.
func (conf *Config) parseDnssecConfig() error {
	if err := validateKaspPropagationDelay(conf.Dnssec.Kasp.PropagationDelay); err != nil {
		return err
	}
	largeAlgs, err := buildLargeAlgorithmSet(conf.Dnssec.LargeAlgorithms)
	if err != nil {
		return err
	}
	conf.Internal.LargeAlgorithms = largeAlgs
	conf.Internal.SplitAlgorithms = buildSplitAlgorithmSet(conf.Dnssec.SplitAlgorithms)
	mode, err := resolveCompletenessMode(conf.Dnssec.Completeness)
	if err != nil {
		return err
	}
	conf.Internal.Completeness = mode

	conf.Internal.DnssecPolicies = make(map[string]DnssecPolicy)
	for name, dp := range conf.Dnssec.Policies {
		dpLocal := dp
		// markBroken records a rejected policy in the map (Name + Error) so it
		// stays visible to the operator and zones referencing it can be
		// quarantined with a reason. The server still starts.
		markBroken := func(reason string) {
			lgConfig.Error("DNSSEC policy rejected, unusable", "policy", name, "err", reason)
			conf.Internal.DnssecPolicies[name] = DnssecPolicy{Name: name, Error: reason}
		}
		// A policy may inherit the gaps in its definition from a named template
		// (deep merge; the policy's own values win). An unknown template name
		// quarantines just this policy and keeps the server running.
		expanded, terr := resolveDnssecPolicyTemplate(dpLocal, conf.Dnssec.Templates)
		if terr != nil {
			markBroken(terr.Error())
			continue
		}
		dpLocal = expanded
		alg, kskAlg, zskAlg, err := resolvePolicyRoleAlgorithms(name, &dpLocal)
		if err != nil {
			markBroken(err.Error())
			continue
		}
		if err := validateSplitAlgorithm(name, kskAlg, zskAlg, conf.Internal.SplitAlgorithms); err != nil {
			markBroken(err.Error())
			continue
		}
		if err := validateRoleCapabilities(name, kskAlg, zskAlg); err != nil {
			markBroken(err.Error())
			continue
		}
		kskLT, err := GenKeyLifetime(dpLocal.KSK.Lifetime)
		if err != nil {
			markBroken(fmt.Sprintf("ksk.lifetime: %v", err))
			continue
		}
		zskLT, err := GenKeyLifetime(dpLocal.ZSK.Lifetime)
		if err != nil {
			markBroken(fmt.Sprintf("zsk.lifetime: %v", err))
			continue
		}
		cskLT, err := GenKeyLifetime(dpLocal.CSK.Lifetime)
		if err != nil {
			markBroken(fmt.Sprintf("csk.lifetime: %v", err))
			continue
		}
		tmp := DnssecPolicy{
			Name:         name,
			Algorithm:    alg,
			KSKAlgorithm: kskAlg,
			ZSKAlgorithm: zskAlg,
			KSK:          kskLT,
			ZSK:          zskLT,
			CSK:          cskLT,
		}
		if err := FinishDnssecPolicy(name, &dpLocal, &tmp); err != nil {
			markBroken(err.Error())
			continue
		}
		conf.Internal.DnssecPolicies[name] = tmp
	}
	// If no "default" policy in config, use built-in default (e.g. for agent autozone).
	// An explicit dnssec.policies.default in YAML overrides this. A broken
	// "default" stays broken (it is in the map with Error set, so "exists" is
	// true): we surface the operator's error rather than silently substituting
	// the builtin. Zones referencing it are quarantined with the reason.
	if _, exists := conf.Internal.DnssecPolicies["default"]; !exists {
		conf.Internal.DnssecPolicies["default"] = BuiltinDefaultDnssecPolicy()
	}
	return nil
}

// resolveZonePolicyRef decides whether a zone's named DNSSEC policy is usable.
// It returns (usable, errMsg): usable is true only for a healthy policy;
// errMsg is a quarantine reason (empty when usable). The three cases are kept
// distinct so the operator can tell a typo (policy does not exist) from a
// genuinely broken policy (defined but rejected at parse).
func resolveZonePolicyRef(polName string, policies map[string]DnssecPolicy) (usable bool, errMsg string) {
	pol, exist := policies[polName]
	switch {
	case !exist:
		return false, fmt.Sprintf("DNSSEC policy %q does not exist", polName)
	case pol.Error != "":
		return false, fmt.Sprintf("configured DNSSEC policy %q is broken: %s", polName, pol.Error)
	default:
		return true, ""
	}
}

// builtinDefaultDnssecPolicy returns the built-in "default" DNSSEC policy used when
// no dnssec.policies.default is defined in config (e.g. for agent autozone). An explicit
// dnssec.policies.default in YAML overrides this. No automatic key rollovers.
func BuiltinDefaultDnssecPolicy() DnssecPolicy {
	const day = 24 * time.Hour
	kskLT, err := GenKeyLifetime("forever")
	if err != nil {
		panic(err)
	}
	zskLT, err := GenKeyLifetime("forever")
	if err != nil {
		panic(err)
	}
	cskLT, err := GenKeyLifetime("none")
	if err != nil {
		panic(err)
	}
	return DnssecPolicy{
		Name:         "default",
		Algorithm:    dns.ED25519,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		Mode:         DnssecPolicyModeKSKZSK,
		KSK:          kskLT,
		ZSK:          zskLT,
		CSK:          cskLT,
		SigValidity: PolicySigValidity{
			Default: uint32((14 * day).Seconds()),
			DNSKEY:  uint32((30 * day).Seconds()),
			DS:      uint32((14 * day).Seconds()),
		},
	}
}

func GenKeyLifetime(lifetime string) (KeyLifetime, error) {
	var lifetime_secs time.Duration
	var err error

	switch lifetime {
	case "forever":
		lifetime_secs = time.Duration(10000) * time.Hour

	case "", "none":
		lifetime_secs = time.Duration(0)

	default:
		lifetime_secs, err = parseExtendedDuration(lifetime)
		if err != nil {
			return KeyLifetime{}, fmt.Errorf("invalid key lifetime %q: %w", lifetime, err)
		}
	}
	return KeyLifetime{
		Lifetime: uint32(lifetime_secs.Seconds()),
	}, nil
}

// NormalizeAddress ensures an address has a port number.
// If the address doesn't have a port, ":53" is appended.
// This allows users to specify addresses as either "IP" or "IP:port" in config.
// Returns empty string if input is empty.
func NormalizeAddress(addr string) string {
	return NormalizeAddressPort(addr, "53")
}

// NormalizeAddressPort is NormalizeAddress with a caller-chosen default port
// (DoT peers default to 853, everything else to 53).
func NormalizeAddressPort(addr, defaultPort string) string {
	if addr == "" {
		return ""
	}

	// Try to split host and port
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		// If SplitHostPort fails, it means no port is present
		return net.JoinHostPort(addr, defaultPort)
	}
	// Address already has a port, use as-is
	return addr
}

// stringToPeerConfHook returns a mapstructure decode hook that converts a
// bare-string value (the legacy primary:/notify: shape) into a PeerConf carrying
// a Legacy marker, instead of letting mapstructure fail the whole-file decode on
// the string->struct type mismatch. mapstructure applies the hook element-wise
// for []PeerConf, so a bare-string entry inside a notify: list is handled too.
// Per-zone validation later sees a non-empty Legacy and quarantines that zone.
func stringToPeerConfHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String || to != reflect.TypeOf(PeerConf{}) {
			return data, nil
		}
		return PeerConf{Legacy: data.(string)}, nil
	}
}

// stringToAclEntryHook is the AclEntry analogue of stringToPeerConfHook: it turns
// a legacy bare-string allow-notify:/downstreams: value into an AclEntry carrying
// a Legacy marker (applied element-wise across the []AclEntry list), so a
// pre-{prefix,key} list quarantines just that zone (ValidateACL rejects the
// marker) instead of failing the whole-file decode on the string->struct
// mismatch.
func stringToAclEntryHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String || to != reflect.TypeOf(AclEntry{}) {
			return data, nil
		}
		return AclEntry{Legacy: data.(string)}, nil
	}
}

// legacyDynamicAllowedHook turns a legacy bool value for
// dynamiczones.dynamic.allowed into a hard config error naming the new list
// syntax. The field decodes into ZoneTypeList — a named type used by exactly
// that key — so the hook cannot misfire on any other config field. There is
// deliberately NO legacy decode (true -> [secondary]): the dynamic-primary
// extension made "allowed" mean two independent capabilities, and a silent
// mapping would hide that the operator has a decision to make.
func legacyDynamicAllowedHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if to != reflect.TypeOf(ZoneTypeList(nil)) || from.Kind() != reflect.Bool {
			return data, nil
		}
		return nil, fmt.Errorf("dynamiczones.dynamic.allowed is now a list of zone types, not a bool: use `allowed: [secondary]` (add `primary` to also allow API-created primary zones)")
	}
}

// NormalizeAddresses ensures all addresses have a port number.
// If an address doesn't have a port, ":53" is appended.
// This allows users to specify addresses as either "IP" or "IP:port" in config.
func NormalizeAddresses(addresses []string) []string {
	if len(addresses) == 0 {
		return addresses
	}

	normalized := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		normalized = append(normalized, NormalizeAddress(addr))
	}
	return normalized
}

// normalizePeerAddrs returns a copy of peers with each .Addr run through
// NormalizeAddress (ensuring a port). The Key and Legacy fields are preserved.
func normalizePeerAddrs(peers []PeerConf) []PeerConf {
	if len(peers) == 0 {
		return peers
	}
	normalized := make([]PeerConf, 0, len(peers))
	for _, p := range peers {
		p.Addr = NormalizeAddress(p.Addr)
		normalized = append(normalized, p)
	}
	return normalized
}

// peerAddrs extracts the .Addr value from each PeerConf into a []string.
func peerAddrs(peers []PeerConf) []string {
	if len(peers) == 0 {
		return nil
	}
	addrs := make([]string, 0, len(peers))
	for _, p := range peers {
		addrs = append(addrs, p.Addr)
	}
	return addrs
}

// setDynamicZonesDefaults sets default values for DynamicZonesConf if not configured
func (conf *Config) setDynamicZonesDefaults() {
	// Default: catalog zones allowed, memory storage
	if conf.DynamicZones.CatalogZones.Storage == "" {
		conf.DynamicZones.CatalogZones.Storage = "memory"
	}
	if !conf.DynamicZones.CatalogZones.Allowed {
		// Default to true if not explicitly set (zero value is false, but we want true as default)
		// Check if it was explicitly set by checking if any dynamiczones config exists
		// For now, default to true
		conf.DynamicZones.CatalogZones.Allowed = true
	}

	// Default: catalog members allowed, memory storage, manual add/remove
	if conf.DynamicZones.CatalogMembers.Storage == "" {
		conf.DynamicZones.CatalogMembers.Storage = "memory"
	}
	if !conf.DynamicZones.CatalogMembers.Allowed {
		// Default to true if not explicitly set
		conf.DynamicZones.CatalogMembers.Allowed = true
	}
	if conf.DynamicZones.CatalogMembers.Add == "" {
		conf.DynamicZones.CatalogMembers.Add = "manual"
	}
	if conf.DynamicZones.CatalogMembers.Remove == "" {
		conf.DynamicZones.CatalogMembers.Remove = "manual"
	}

	// Default: dynamic zones not allowed, memory storage
	if conf.DynamicZones.Dynamic.Storage == "" {
		conf.DynamicZones.Dynamic.Storage = "memory"
	}
	// Dynamic zones default to not allowed (false is correct default)
}

// migrateCatalogPolicyToDynamicZones handles backward compatibility by migrating
// catalog.policy.zones.add/remove to dynamiczones.catalog-members.add/remove
func (conf *Config) migrateCatalogPolicyToDynamicZones() {
	if conf.Catalog == nil {
		return
	}
	// If catalog.policy.zones.add is set but dynamiczones.catalog-members.add is not,
	// migrate the value
	if conf.Catalog.Policy.Zones.Add != "" && conf.DynamicZones.CatalogMembers.Add == "" {
		conf.DynamicZones.CatalogMembers.Add = conf.Catalog.Policy.Zones.Add
		lgConfig.Warn("catalog.policy.zones.add is deprecated, use dynamiczones.catalog-members.add instead", "migratedValue", conf.Catalog.Policy.Zones.Add)
	}

	// If catalog.policy.zones.remove is set but dynamiczones.catalog-members.remove is not,
	// migrate the value
	if conf.Catalog.Policy.Zones.Remove != "" && conf.DynamicZones.CatalogMembers.Remove == "" {
		conf.DynamicZones.CatalogMembers.Remove = conf.Catalog.Policy.Zones.Remove
		lgConfig.Warn("catalog.policy.zones.remove is deprecated, use dynamiczones.catalog-members.remove instead", "migratedValue", conf.Catalog.Policy.Zones.Remove)
	}
}

// migrateMetaGroupsToConfigGroups handles backward compatibility by migrating
// catalog.meta-groups to catalog.config-groups
func (conf *Config) migrateMetaGroupsToConfigGroups() {
	if conf.Catalog == nil {
		return
	}
	// If meta-groups is set but config-groups is empty, migrate
	if len(conf.Catalog.MetaGroups) > 0 && len(conf.Catalog.ConfigGroups) == 0 {
		conf.Catalog.ConfigGroups = conf.Catalog.MetaGroups
		lgConfig.Warn("catalog.meta-groups is deprecated, use catalog.config-groups instead", "migratedGroups", len(conf.Catalog.MetaGroups))
		// Clear meta-groups after migration
		conf.Catalog.MetaGroups = nil
	}
}

// validateDynamicZonesConfig validates dynamiczones configuration
// Checks if configfile is included in the include list (warns if not)
func (conf *Config) validateDynamicZonesConfig(includedFiles []string) {
	if conf.DynamicZones.ConfigFile == "" {
		return // No dynamic config file configured, nothing to validate
	}

	// Check if configfile path is absolute
	if !filepath.IsAbs(conf.DynamicZones.ConfigFile) {
		lgConfig.Warn("dynamiczones.configfile must be an absolute path", "path", conf.DynamicZones.ConfigFile)
		return
	}

	// Check if zone directory path is absolute
	if conf.DynamicZones.ZoneDirectory != "" && !filepath.IsAbs(conf.DynamicZones.ZoneDirectory) {
		lgConfig.Warn("dynamiczones.zonedirectory must be an absolute path", "path", conf.DynamicZones.ZoneDirectory)
	}

	// Check if the configfile is in the include list
	conf.CheckDynamicConfigFileIncluded(includedFiles)
}

// validateGroupPrefixes validates catalog.group-prefixes configuration
func (conf *Config) validateGroupPrefixes() error {
	if conf.Catalog == nil {
		return nil
	}
	// Check if config-groups or signing-groups are defined
	hasConfigGroups := len(conf.Catalog.ConfigGroups) > 0
	hasSigningGroups := len(conf.Catalog.SigningGroups) > 0

	if !hasConfigGroups && !hasSigningGroups {
		// No groups defined, no need to validate prefixes
		return nil
	}

	// If groups are defined, group-prefixes is REQUIRED
	if conf.Catalog.GroupPrefixes.Config == "" || conf.Catalog.GroupPrefixes.Signing == "" {
		return fmt.Errorf("catalog.group-prefixes is REQUIRED when catalog.config-groups or catalog.signing-groups are configured.\n" +
			"Please add:\n" +
			"  catalog:\n" +
			"    group-prefixes:\n" +
			"      config: \"config\"    # or \"config_\" or \"none\"\n" +
			"      signing: \"sign\"     # or \"sign_\" or \"none\"")
	}

	// Validate config prefix
	if conf.Catalog.GroupPrefixes.Config != "none" {
		if err := validateGroupPrefix(conf.Catalog.GroupPrefixes.Config, "config"); err != nil {
			return fmt.Errorf("invalid catalog.group-prefixes.config: %w", err)
		}
	}

	// Validate signing prefix
	if conf.Catalog.GroupPrefixes.Signing != "none" {
		if err := validateGroupPrefix(conf.Catalog.GroupPrefixes.Signing, "signing"); err != nil {
			return fmt.Errorf("invalid catalog.group-prefixes.signing: %w", err)
		}
	}

	// Check for prefix conflicts (if both are not "none")
	if conf.Catalog.GroupPrefixes.Config != "none" && conf.Catalog.GroupPrefixes.Signing != "none" {
		// Check for exact equality
		if conf.Catalog.GroupPrefixes.Config == conf.Catalog.GroupPrefixes.Signing {
			return fmt.Errorf("catalog.group-prefixes.config and catalog.group-prefixes.signing must be different (both are: %q)", conf.Catalog.GroupPrefixes.Config)
		}

		// Check for substring/prefix conflicts to prevent misclassification
		// e.g., "config" and "config_" would cause issues as one is a prefix of the other
		if strings.HasPrefix(conf.Catalog.GroupPrefixes.Config, conf.Catalog.GroupPrefixes.Signing) {
			return fmt.Errorf("catalog.group-prefixes.config (%q) cannot start with catalog.group-prefixes.signing (%q) - this would cause misclassification in group detection",
				conf.Catalog.GroupPrefixes.Config, conf.Catalog.GroupPrefixes.Signing)
		}
		if strings.HasPrefix(conf.Catalog.GroupPrefixes.Signing, conf.Catalog.GroupPrefixes.Config) {
			return fmt.Errorf("catalog.group-prefixes.signing (%q) cannot start with catalog.group-prefixes.config (%q) - this would cause misclassification in group detection",
				conf.Catalog.GroupPrefixes.Signing, conf.Catalog.GroupPrefixes.Config)
		}
	}

	return nil
}

// validateGroupPrefix validates a single group prefix value
func validateGroupPrefix(prefix string, prefixType string) error {
	// Check length (must leave room for group name in DNS label - max 63 chars)
	if len(prefix) > 50 {
		return fmt.Errorf("%s prefix too long (%d chars), max 50 chars to leave room for group names", prefixType, len(prefix))
	}

	// Check for valid DNS label characters
	// Valid: letters, digits, hyphens (but not at start/end)
	for i, ch := range prefix {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			return fmt.Errorf("%s prefix contains invalid character at position %d: %q (only letters, digits, hyphens, and underscores allowed)", prefixType, i, ch)
		}
	}

	// Check prefix doesn't start or end with hyphen
	if len(prefix) > 0 && (prefix[0] == '-' || prefix[len(prefix)-1] == '-') {
		return fmt.Errorf("%s prefix cannot start or end with hyphen", prefixType)
	}

	return nil
}
