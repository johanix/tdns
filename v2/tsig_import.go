/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

var (
	bindTsigKeyStartRe = regexp.MustCompile(`(?m)^\s*key\s+"([^"]+)"\s*\{`)
	bindTsigAlgoRe     = regexp.MustCompile(`(?is)\balgorithm\s+([A-Za-z0-9._-]+)\s*;`)
	bindTsigSecretRe   = regexp.MustCompile(`(?is)\bsecret\s+"([^"]*)"\s*;`)
)

// extractTsigImportKeys scans file data for TSIG key declarations (not a full
// config parser — include/macro expansion is out of scope).
func extractTsigImportKeys(data, format string) ([]TsigDetails, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "bind":
		return extractBindTsigKeys(data)
	case "nsd":
		return extractNsdTsigKeys(data)
	default:
		return nil, fmt.Errorf("unknown tsig import format %q (use bind or nsd)", format)
	}
}

func extractBindTsigKeys(data string) ([]TsigDetails, error) {
	var out []TsigDetails
	seen := map[string]bool{}
	loc := bindTsigKeyStartRe.FindStringSubmatchIndex(data)
	for loc != nil {
		name := data[loc[2]:loc[3]]
		rest := data[loc[1]:]
		closeRel := strings.Index(rest, "}")
		if closeRel < 0 {
			return nil, fmt.Errorf("bind key %q: unclosed block", name)
		}
		block := rest[:closeRel]
		algoM := bindTsigAlgoRe.FindStringSubmatch(block)
		secM := bindTsigSecretRe.FindStringSubmatch(block)
		if algoM == nil || secM == nil {
			return nil, fmt.Errorf("bind key %q: missing algorithm or secret", name)
		}
		key, err := normalizeImportedTsigKey(name, algoM[1], secM[1], seen)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
		data = data[loc[1]+closeRel+1:]
		loc = bindTsigKeyStartRe.FindStringSubmatchIndex(data)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no TSIG keys found in bind-format input")
	}
	return out, nil
}

func extractNsdTsigKeys(data string) ([]TsigDetails, error) {
	lines := strings.Split(data, "\n")
	var out []TsigDetails
	seen := map[string]bool{}
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "key:" {
			continue
		}
		var name, algo, secret string
		for j := i + 1; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			if trimmed == "" {
				continue
			}
			if !strings.HasPrefix(lines[j], " ") && !strings.HasPrefix(lines[j], "\t") {
				i = j - 1
				break
			}
			if after, ok := strings.CutPrefix(trimmed, "name:"); ok {
				name = unquoteNsdValue(after)
				continue
			}
			if after, ok := strings.CutPrefix(trimmed, "algorithm:"); ok {
				algo = unquoteNsdValue(after)
				continue
			}
			if after, ok := strings.CutPrefix(trimmed, "secret:"); ok {
				secret = unquoteNsdValue(after)
				continue
			}
			i = j - 1
			break
		}
		if name == "" || algo == "" || secret == "" {
			return nil, fmt.Errorf("nsd key block at line %d: incomplete (need name, algorithm, secret)", i+1)
		}
		key, err := normalizeImportedTsigKey(name, algo, secret, seen)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no TSIG keys found in nsd-format input")
	}
	return out, nil
}

func unquoteNsdValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func normalizeImportedTsigKey(name, algo, secret string, seen map[string]bool) (TsigDetails, error) {
	name = dns.CanonicalName(strings.TrimSpace(name))
	algo = strings.TrimSpace(algo)
	secret = strings.TrimSpace(secret)
	if err := validateTsigKeySpec(name, algo, secret); err != nil {
		return TsigDetails{}, fmt.Errorf("key %q: %w", name, err)
	}
	if seen[name] {
		return TsigDetails{}, fmt.Errorf("duplicate key name %q in import file", name)
	}
	seen[name] = true
	return TsigDetails{Name: name, Algorithm: algo, Secret: secret}, nil
}
