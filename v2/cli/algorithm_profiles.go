/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// algorithmProfile is optional, CLI-side cost data for a DNSSEC/SIG(0)
// algorithm: relative signing and validation cost. It is the one piece of
// listing enrichment that is NOT server-reported, because cost is
// machine-dependent (it shifts across CPU architectures) — the static
// facts (sizes, NIST level, maturity, description) now come from the
// server in AlgorithmInfo.Facts. It never feeds name<->codepoint
// resolution or what a server reports as supported (that stays
// server-authoritative).
//
// Cost profiles are read from the optional "algorithms.profiles" map in
// the CLI config, keyed by algorithm name. The data is deliberately kept
// out of the (host-local, secret-bearing) main CLI config and pulled in
// from a shareable file via an "include:".
//
// Every field is optional. A zero value means "not provided" and is
// rendered as "-" in the listing; because no real cost is legitimately
// zero, that convention is unambiguous here.
//
// The remaining fields (Description, sizes, SecurityLevel, Maturity) are
// still accepted for backward compatibility with existing config files
// but are ignored — those values now come from the server. TODO: this
// struct will be replaced by a per-arch cost table
// (algorithm-costs.yaml) in a follow-up.
type algorithmProfile struct {
	SigningCost    int `mapstructure:"signingcost"`    // relative to ED25519 (= 1); 0 = unknown
	ValidationCost int `mapstructure:"validationcost"` // relative to ED25519 (= 1); 0 = unknown

	// Accepted-but-ignored (superseded by AlgorithmInfo.Facts). Retained
	// so existing algorithms.yaml files do not error on unmarshal.
	Description    string `mapstructure:"description"`
	PublicKeyBytes int    `mapstructure:"publickeybytes"`
	SignatureBytes int    `mapstructure:"signaturebytes"`
	SecretKeyBytes int    `mapstructure:"secretkeybytes"`
	SecurityLevel  int    `mapstructure:"securitylevel"`
	Maturity       string `mapstructure:"maturity"`
}

// loadAlgorithmProfiles returns the "algorithms.profiles" enrichment map
// from the (already include-expanded) CLI config, or nil if none is
// configured.
//
// viper lower-cases all config keys, so the returned map is keyed by the
// lower-cased algorithm name; callers must look up with
// strings.ToLower(name). Malformed config is non-fatal — enrichment is
// optional, so we warn and fall back to the bare listing.
func loadAlgorithmProfiles() map[string]algorithmProfile {
	if !viper.IsSet("algorithms.profiles") {
		return nil
	}
	var profiles map[string]algorithmProfile
	if err := viper.UnmarshalKey("algorithms.profiles", &profiles); err != nil {
		fmt.Fprintf(os.Stderr, "warning: ignoring malformed 'algorithms.profiles' config section: %v\n", err)
		return nil
	}
	return profiles
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
