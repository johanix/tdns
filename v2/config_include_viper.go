/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Expanding include: for the tools that read a config through viper rather
 * than through processConfigFile.
 */

package tdns

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// MergeViperIncludes expands the top-level include: list of an already-read
// viper config, merging each included file in turn. cfgFile is the file the
// includes are relative to.
//
// One implementation because there were three, and all three were wrong the
// same way: tdns-cli, tdns-debug and `cert init` each read the list with
// GetStringSlice, which understands only the bare-string form. Handed the map
// form -- {file: x, merge: true}, which is the only way to ask the daemon to
// combine two files' zones -- GetStringSlice yields an empty string per entry,
// so the path resolved to the config file's DIRECTORY and the operator was
// told "Unsupported Config Type" about a directory they never wrote in the
// config (#452). The daemon has parsed both forms since merging existed;
// sharing its parser is what stops the two drifting apart again.
//
// SCOPE: the tools' OWN configs. Anything reading a SERVER config should call
// LoadRawConfigMap instead and query the result -- that is the daemon's whole
// parser rather than its include-entry syntax, and it is what `config check`
// (loadConfigViper) and `cert init` do. The remaining callers read a small
// CLI-shaped config of their own, where viper IS the mechanism.
//
// That distinction is why what follows is acceptable rather than a hole.
// merge: true itself is not reproduced: viper deep-merges maps and REPLACES
// lists, while the daemon concatenates the allowlisted lists (zones:,
// templates:, dnssec.policies) for an include that asked for it. A config
// whose zones are split across two merge: true includes therefore reads
// differently here than in the daemon -- which no longer reaches any config
// that HAS a zone set, and is announced under --verbose regardless. Nested
// includes are likewise not followed, where the daemon recurses.
//
// A missing include is skipped rather than fatal: it is an optional overlay
// (a not-yet-installed algorithms.yaml is the case that shaped this), which is
// what all three copies did. A present-but-broken one is still an error.
func MergeViperIncludes(v *viper.Viper, cfgFile string) error {
	raw := v.Get("include")
	if raw == nil {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("%s: include: must be a list of paths or {file, merge} entries, got %T", cfgFile, raw)
	}

	// Merging moves viper's notion of "the config file" to whatever was
	// merged last, which would send a later ReadInConfig at an include.
	defer v.SetConfigFile(cfgFile)

	for _, inc := range list {
		entry, err := parseIncludeEntry(inc)
		if err != nil {
			return fmt.Errorf("%s: %v", cfgFile, err)
		}
		path := entry.File
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(cfgFile), path)
		}
		path = filepath.Clean(path)

		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				if Globals.Verbose {
					fmt.Fprintln(os.Stderr, "Skipping missing included config:", path)
				}
				continue
			}
			return fmt.Errorf("include %s: %v", path, err)
		}
		if entry.Merge && Globals.Verbose {
			fmt.Fprintf(os.Stderr,
				"Note: include %s asks for merge: true, which combines lists in the daemon only; this tool merges maps and replaces lists\n", path)
		}

		v.SetConfigFile(path)
		if err := v.MergeInConfig(); err != nil {
			return fmt.Errorf("merging included config %s: %v", path, err)
		}
		if Globals.Verbose {
			fmt.Fprintln(os.Stderr, "Merged included config:", path)
		}
	}
	return nil
}
