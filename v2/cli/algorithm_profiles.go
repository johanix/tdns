/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// algorithmProfile is CLI-side cost data for a DNSSEC/SIG(0) algorithm:
// relative signing and validation cost. It is the one piece of listing
// enrichment that is NOT server-reported, because cost is machine-
// dependent (it shifts across CPU architectures) — the static facts
// (sizes, NIST level, maturity, description) come from the server in
// AlgorithmInfo.Facts. Cost never feeds name<->codepoint resolution or
// what a server reports as supported (that stays server-authoritative).
type algorithmProfile struct {
	SigningCost    int // relative to ED25519 (= 1); 0 = unknown
	ValidationCost int
}

// costsYAML mirrors the multi-arch algorithm-costs.yaml produced by
// dnssec-algorithms/cmd/algbench:
//
//	costs:
//	   arm64:
//	      MLDSA44: { signing: 8.5, validation: 2.0 }
//	   amd64:
//	      MLDSA44: { signing: 5.9, validation: 2.1 }
type costsYAML struct {
	Costs map[string]map[string]struct {
		Signing    float64 `yaml:"signing"`
		Validation float64 `yaml:"validation"`
	} `yaml:"costs"`
}

// loadAlgorithmProfiles returns the per-algorithm cost map for the listing,
// keyed by the lower-cased algorithm name (viper lower-cases config keys,
// and callers look up with strings.ToLower(name)). Returns nil when no
// cost file is configured, when it cannot be read/parsed, or when it has
// no block for the selected architecture — in every such case the listing
// simply omits the SIGN/VRFY columns.
//
// Configuration:
//
//	algorithms.costsfile   path to algorithm-costs.yaml (from a
//	                       dnssec-algorithms checkout, or copied locally)
//	algorithms.costarch    which architecture's costs to show; defaults to
//	                       this host's runtime.GOARCH
//
// Costs are machine-dependent; the shown arch may differ from the server's
// arch, so the values are hints. Malformed input is non-fatal (warn +
// omit).
func loadAlgorithmProfiles() map[string]algorithmProfile {
	path := viper.GetString("algorithms.costsfile")
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot read algorithms.costsfile %q: %v\n", path, err)
		return nil
	}
	var cf costsYAML
	if err := yaml.Unmarshal(data, &cf); err != nil {
		fmt.Fprintf(os.Stderr, "warning: ignoring malformed algorithms.costsfile %q: %v\n", path, err)
		return nil
	}

	arch := viper.GetString("algorithms.costarch")
	if arch == "" {
		arch = runtime.GOARCH
	}
	block, ok := cf.Costs[arch]
	if !ok {
		// No costs for this arch: not an error, just no cost columns. Name
		// the arches that ARE present so the operator can set costarch.
		if len(cf.Costs) > 0 {
			avail := make([]string, 0, len(cf.Costs))
			for a := range cf.Costs {
				avail = append(avail, a)
			}
			sort.Strings(avail) // stable, greppable diagnostic output
			fmt.Fprintf(os.Stderr, "note: no costs for arch %q in %s (have: %s); set algorithms.costarch to pick one\n",
				arch, path, strings.Join(avail, ", "))
		}
		return nil
	}

	out := make(map[string]algorithmProfile, len(block))
	for name, c := range block {
		out[strings.ToLower(name)] = algorithmProfile{
			SigningCost:    roundCost(c.Signing),
			ValidationCost: roundCost(c.Validation),
		}
	}
	return out
}

// roundCost rounds a relative cost to the nearest integer for the listing.
// A positive-but-sub-1 cost (a fast algorithm, e.g. RSA verify at 0.8)
// rounds up to 1 rather than to 0, so it does not read as "unspecified".
func roundCost(f float64) int {
	if f <= 0 {
		return 0
	}
	if f < 1 {
		return 1
	}
	return int(f + 0.5)
}

// algIntCol renders an optional integer profile field for the listing:
// 0 (unset) becomes "-".
func algIntCol(n int) string {
	if n == 0 {
		return "-"
	}
	return strconv.Itoa(n)
}

// algStrCol renders an optional string profile field for the listing:
// "" (unset) becomes "-".
func algStrCol(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// algorithmFamily returns the family grouping key for an algorithm name:
// the leading run before the first digit or underscore (MAYO1 -> "MAYO",
// SNOVA24_5_4 -> "SNOVA", FALCON1024 -> "FALCON", QRUOV_Q31_L3 ->
// "QRUOV"). Used to sort the listing so related parameter sets group
// together; it is display-only and does not affect codepoints.
func algorithmFamily(name string) string {
	i := strings.IndexFunc(name, func(r rune) bool {
		return (r >= '0' && r <= '9') || r == '_'
	})
	if i <= 0 {
		return name
	}
	return name[:i]
}

// defaultDescWrapWidth bounds the DESCRIPTION column so a long note
// wraps onto continuation rows instead of stretching the whole table.
// Overridable via "algorithms.display.descriptionwidth" in the config.
const defaultDescWrapWidth = 50

// descWrapWidth returns the DESCRIPTION column wrap width from
// "algorithms.display.descriptionwidth", falling back to
// defaultDescWrapWidth when unset or non-positive.
func descWrapWidth() int {
	w := viper.GetInt("algorithms.display.descriptionwidth")
	if w <= 0 {
		return defaultDescWrapWidth
	}
	return w
}

// wrapText word-wraps s into lines no longer than width. A single word
// longer than width gets its own (overlong) line rather than being
// split. Returns nil for empty s.
func wrapText(s string, width int) []string {
	if s == "" {
		return nil
	}
	var lines []string
	var b strings.Builder
	for _, w := range strings.Fields(s) {
		switch {
		case b.Len() == 0:
			b.WriteString(w)
		case b.Len()+1+len(w) > width:
			lines = append(lines, b.String())
			b.Reset()
			b.WriteString(w)
		default:
			b.WriteByte(' ')
			b.WriteString(w)
		}
	}
	if b.Len() > 0 {
		lines = append(lines, b.String())
	}
	return lines
}
