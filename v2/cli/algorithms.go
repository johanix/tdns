/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	tdns "github.com/johanix/tdns/v2"
	algregistry "github.com/johanix/tdns/v2/algorithms"
)

// --- Local registry helpers --------------------------------------------
//
// These resolve algorithm names against the CLI's own in-process
// registry (populated by RegisterMetadata in the cli main package).
// They back the *local* code paths that have no server to ask:
//   - `debug sig0 generate`, which generates a key in-process, and
//   - exported-key parsing, which reads an algorithm name out of a key
//     blob.
// Remote generate commands use the server-sourced helpers below
// instead, so the CLI never decides a name<->codepoint mapping that
// the server might disagree with.

// isKnownAlgorithm reports whether name (already upper-cased) matches
// an algorithm in the CLI's local registry.
func isKnownAlgorithm(name string) bool {
	_, ok := algregistry.AlgorithmNumber(name)
	return ok
}

// AlgorithmNumber returns the DNSSEC algorithm number for name from the
// local registry, or 0, false if unknown.
func AlgorithmNumber(name string) (uint8, bool) {
	return algregistry.AlgorithmNumber(name)
}

// MustAlgorithmNumber is the AlgorithmNumber variant for call sites
// that have already validated name. Returns 0 for unknown names.
func MustAlgorithmNumber(name string) uint8 {
	num, _ := algregistry.AlgorithmNumber(name)
	return num
}

// --- Server-sourced helpers --------------------------------------------

// serverAlgCache memoizes the per-role algorithm list for the lifetime
// of the process, so bare "-a" listing and codepoint resolution don't
// each trigger a separate server round-trip.
var serverAlgCache = map[string][]algregistry.AlgorithmInfo{}

// fetchServerAlgorithms returns the algorithm registry of the server
// for role (e.g. "auth", "agent"). It hard-fails — returns an error —
// when the server is unreachable; there is no local fallback, because
// these commands send their generate request to the same server
// anyway, so resolving the algorithm offline would only defer the
// failure by one step. The result is cached per role.
func fetchServerAlgorithms(role string) ([]algregistry.AlgorithmInfo, error) {
	if cached, ok := serverAlgCache[role]; ok {
		return cached, nil
	}
	api, err := GetApiClient(role, false)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s server to determine supported algorithms: %v", role, err)
	}
	resp, err := SendKeystoreCmd(api, tdns.KeystorePost{Command: "list-algorithms"})
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s server to determine supported algorithms: %v", role, err)
	}
	serverAlgCache[role] = resp.Algorithms
	return resp.Algorithms, nil
}

// algUse selects which capability a command cares about.
type algUse int

const (
	useSIG0 algUse = iota
	useDNSSEC
)

func (u algUse) permits(a algregistry.AlgorithmInfo) bool {
	switch u {
	case useDNSSEC:
		return a.ForDNSSEC
	default:
		return a.ForSIG0
	}
}

// resolveServerAlgorithm validates name against role's server registry
// and returns its codepoint. name is upper-cased by the caller. On an
// unknown name it returns an error listing the server's valid choices
// for the given use.
func resolveServerAlgorithm(role, name string, use algUse) (uint8, error) {
	algs, err := fetchServerAlgorithms(role)
	if err != nil {
		return 0, err
	}
	for _, a := range algs {
		if a.Name == name && use.permits(a) {
			return a.Number, nil
		}
	}
	return 0, fmt.Errorf("algorithm %q is not supported by the %s server. Supported: %s",
		name, role, strings.Join(serverAlgNames(algs, use), ", "))
}

// printServerAlgorithms lists the algorithms role's server supports for
// the given use. The set of algorithms is server-authoritative; if the
// CLI config carries an "algorithms" enrichment map (see
// [algorithmProfile]), each entry is annotated with key/signature sizes,
// relative cost, etc. With no enrichment configured it falls back to the
// original compact "NAME codepoint" listing.
func printServerAlgorithms(role string, use algUse) error {
	algs, err := fetchServerAlgorithms(role)
	if err != nil {
		return err
	}
	profiles := loadAlgorithmProfiles()
	fmt.Printf("Algorithms supported by the %s server:\n", role)

	if len(profiles) == 0 {
		for _, a := range algs {
			if use.permits(a) {
				fmt.Printf("  %-16s %d\n", a.Name, a.Number)
			}
		}
		return nil
	}

	// Enriched table. Sizes are in bytes; SIGN/VRFY are signing/
	// validation cost relative to ED25519 (= 1); "-" means the profile
	// did not specify the field.
	fmt.Println("  (sizes in bytes; SIGN/VRFY = signing/validation cost relative to ED25519=1; '-' = unspecified)")
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tCP\tPUBKEY\tSIG\tSECKEY\tLVL\tSIGN\tVRFY\tMATURITY\tDESCRIPTION")
	for _, a := range algs {
		if !use.permits(a) {
			continue
		}
		// viper lower-cases config keys, so the profile map is keyed by
		// the lower-cased algorithm name.
		p := profiles[strings.ToLower(a.Name)]
		fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.Name, a.Number,
			algIntCol(p.PublicKeyBytes), algIntCol(p.SignatureBytes), algIntCol(p.SecretKeyBytes),
			algIntCol(p.SecurityLevel), algIntCol(p.SigningCost), algIntCol(p.ValidationCost),
			algStrCol(p.Maturity), algStrCol(p.Description))
	}
	return tw.Flush()
}

func serverAlgNames(algs []algregistry.AlgorithmInfo, use algUse) []string {
	var names []string
	for _, a := range algs {
		if use.permits(a) {
			names = append(names, a.Name)
		}
	}
	sort.Strings(names)
	return names
}

// ResolveAlgorithm turns the user's --algorithm input into a codepoint,
// using role's server as the source of truth. It upper-cases the name,
// resolves it against role's server registry, and returns the
// codepoint. On any error (algorithm not given, unreachable server,
// unknown name) it prints the error — including the server's supported
// list where relevant — and exits 1.
//
// To discover the supported set without generating a key, use the
// sibling "algorithms" subcommand.
func ResolveAlgorithm(role string, use algUse) uint8 {
	raw := tdns.Globals.Algorithm
	if raw == "" {
		algs, err := fetchServerAlgorithms(role)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Error: no algorithm given (-a). Algorithms supported by the %s server: %s\n",
			role, strings.Join(serverAlgNames(algs, use), ", "))
		os.Exit(1)
	}
	num, err := resolveServerAlgorithm(role, strings.ToUpper(raw), use)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return num
}

// sig0AlgorithmsHelp / dnssecAlgorithmsHelp build the --algorithm flag
// help text. The supported set is per-server and only knowable at
// invocation time, so the help no longer enumerates algorithms; it
// points the user at the live query (bare "-a").
func sig0AlgorithmsHelp(prefix string) string {
	return prefix + " (use the 'algorithms' subcommand to list what the server supports)"
}

func dnssecAlgorithmsHelp(prefix string) string {
	return prefix + " (use the 'algorithms' subcommand to list what the server supports)"
}
