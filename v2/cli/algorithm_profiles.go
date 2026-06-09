/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/viper"
)

// algorithmProfile is optional, CLI-side descriptive metadata about a
// DNSSEC/SIG(0) algorithm: key and signature sizes, relative cost,
// maturity, and a free-form note. It exists purely to *annotate* the
// `keystore ... algorithms` listing during PQ algorithm experimentation
// — it never feeds name<->codepoint resolution or what a server reports
// as supported (that stays server-authoritative).
//
// Profiles are read from the optional "algorithms" map in the CLI
// config, keyed by algorithm name. The data is deliberately kept out of
// the (host-local, secret-bearing) main CLI config and pulled in from a
// shareable file such as /etc/tdns/algorithms.yaml via an "include:".
//
// Every field is optional. A zero value means "not provided" and is
// rendered as "-" in the listing; because no real key/signature size or
// cost is legitimately zero, that convention is unambiguous here.
type algorithmProfile struct {
	Description    string `mapstructure:"description"`
	PublicKeyBytes int    `mapstructure:"publickeybytes"`
	SignatureBytes int    `mapstructure:"signaturebytes"`
	SecretKeyBytes int    `mapstructure:"secretkeybytes"`
	SecurityLevel  int    `mapstructure:"securitylevel"` // NIST PQ level 1/3/5; 0 = unspecified
	Maturity       string `mapstructure:"maturity"`      // final | draft | candidate | builtin
	SigningCost    int    `mapstructure:"signingcost"`    // relative to ED25519 (= 1); 0 = unknown
	ValidationCost int    `mapstructure:"validationcost"` // relative to ED25519 (= 1); 0 = unknown
}

// loadAlgorithmProfiles returns the "algorithms" enrichment map from the
// (already include-expanded) CLI config, or nil if none is configured.
//
// viper lower-cases all config keys, so the returned map is keyed by the
// lower-cased algorithm name; callers must look up with
// strings.ToLower(name). Malformed config is non-fatal — enrichment is
// optional, so we warn and fall back to the bare listing.
func loadAlgorithmProfiles() map[string]algorithmProfile {
	if !viper.IsSet("algorithms") {
		return nil
	}
	var profiles map[string]algorithmProfile
	if err := viper.UnmarshalKey("algorithms", &profiles); err != nil {
		fmt.Fprintf(os.Stderr, "warning: ignoring malformed 'algorithms' config section: %v\n", err)
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
