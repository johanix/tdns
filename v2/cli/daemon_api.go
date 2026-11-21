/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Reading a DAEMON's config to learn how to reach its management API, for
 * `tdns-ncli config add`.
 */
package cli

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
)

// DaemonApi is what a daemon's own config says about how to reach it.
type DaemonApi struct {
	// ConfigFile is the absolute path of the daemon config that was read.
	ConfigFile string
	// Role is the daemon type: auth, agent or imr.
	Role string
	// Addresses are apiserver.addresses, verbatim.
	Addresses []string
	// ApiKey is apiserver.apikey.
	ApiKey string
	// Socket is apiserver.socket, the daemon's local admin socket, or "".
	Socket string
	// UseTLS is apiserver.usetls, which the daemon defaults to true when the
	// key is absent (v2/parseconfig.go), so absent must read as true here too.
	UseTLS bool
	// Warnings are things worth telling the operator that did not stop the
	// read.
	Warnings []string
}

// ReadDaemonApi reads the apiserver: block, and works out which kind of daemon
// the config belongs to, from a daemon config file.
//
// It reads the file the way the daemon's own loader does -- viper plus
// include: expansion -- so an apiserver: block that lives in an included file
// is found. If an include cannot be processed the main file alone is used and
// a warning says so: the daemon would refuse to start with that include, but
// that is the daemon's complaint to make, and the apiserver: block is very
// rarely in an include.
//
// roleOverride, when non-empty, replaces the detection (and skips the check
// that refuses tdns-mp daemons).
func ReadDaemonApi(path, roleOverride string) (*DaemonApi, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	out := &DaemonApi{ConfigFile: abs}

	// fail returns err with the warnings collected so far attached. After a
	// failed include they are the likeliest reason a key reads as unset (the
	// addresses may live only in the include that did not load), and on an
	// error return they would otherwise be lost with the result.
	fail := func(err error) (*DaemonApi, error) {
		if len(out.Warnings) == 0 {
			return nil, err
		}
		return nil, fmt.Errorf("%w (%s)", err, strings.Join(out.Warnings, "; "))
	}

	v, err := readDaemonViper(abs)
	if err != nil {
		return nil, err
	}
	if err := tdns.MergeViperIncludes(v, abs); err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"include: processing failed (%v); read the apiserver: block from the main file only", err))
		if v, err = readDaemonViper(abs); err != nil {
			return fail(err)
		}
	}

	out.Addresses = v.GetStringSlice("apiserver.addresses")
	out.Socket = v.GetString("apiserver.socket")
	if out.Socket != "" {
		// The daemon serves no socket on a path it refuses, so there is
		// nothing there to address.
		if err := tdns.CheckApiSocketPath(out.Socket); err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"%v: the daemon does not serve it, so it is not used here", err))
			out.Socket = ""
		}
	}
	if len(out.Addresses) == 0 && out.Socket == "" {
		return fail(fmt.Errorf("%s: neither apiserver.addresses nor apiserver.socket is set, so this daemon has no management API to address", abs))
	}
	// The key is what a TCP entry sends; a socket entry sends none.
	out.ApiKey = v.GetString("apiserver.apikey")
	if out.ApiKey == "" && out.Socket == "" {
		return fail(fmt.Errorf("%s: apiserver.apikey is not set", abs))
	}
	out.UseTLS = true
	if v.IsSet("apiserver.usetls") {
		out.UseTLS = v.GetBool("apiserver.usetls")
	}

	if roleOverride != "" {
		out.Role = roleOverride
		return out, nil
	}
	role, warn, err := detectDaemonRole(
		v.GetString("service.name"), v.IsSet("service"), v.IsSet("imrengine"), abs)
	if err != nil {
		return fail(err)
	}
	if warn != "" {
		out.Warnings = append(out.Warnings, warn)
	}
	out.Role = role
	return out, nil
}

func readDaemonViper(abs string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigFile(abs)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", abs, err)
	}
	return v, nil
}

// detectDaemonRole decides which daemon a config is for.
//
// Nothing in a daemon config states its type outright (the binary decides),
// so this goes by evidence, strongest first:
//
//  1. service.name, which every sample config sets to TDNS-AUTH or TDNS-AGENT
//     (the digits some operators append, TDNS-AUTH2, are ignored).
//  2. No service: block at all but an imrengine: block: that is tdns-imr,
//     whose config has no service: section.
//  3. The file name (tdns-auth2.yaml, sec-tdns-auth.yaml).
//
// Words are matched whole, so TDNS-MPAGENT is not an agent. A tdns-mp daemon
// is refused outright: tdns-ncli drives the tdns daemons only, and a wrong
// guess here would file an mp daemon's API under the wrong command tree. That
// covers the glued names (TDNS-MPAGENT, the samples' form) and the word "mp"
// on its own, because the split on hyphens turns TDNS-MP-AGENT and
// tdns-mp-agent.yaml into "tdns", "mp", "agent", which would otherwise read as
// an agent.
//
// When the evidence does not settle it the answer is an error asking for
// --role, never a guess: a daemon filed under the wrong role gets the wrong
// command tree pointed at it.
func detectDaemonRole(serviceName string, hasService, hasImrEngine bool, path string) (role, warning string, err error) {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	for _, w := range append(splitWords(serviceName), splitWords(base)...) {
		switch strings.TrimRight(w, "0123456789") {
		case "mp", "mpagent", "mpsigner", "mpcombiner", "mpauditor":
			return "", "", fmt.Errorf("%s looks like a tdns-mp daemon (%q); tdns-ncli drives the tdns daemons (auth, agent, imr) only -- use --role to override", path, w)
		}
	}

	fromName := roleFromWords(serviceName)
	fromFile := roleFromWords(base)
	switch {
	case fromName != "":
		if fromFile != "" && fromFile != fromName {
			warning = fmt.Sprintf("service.name says %s but the file name suggests %s; using %s", fromName, fromFile, fromName)
		}
		return fromName, warning, nil
	case !hasService && hasImrEngine:
		return "imr", "", nil
	case fromFile != "":
		return fromFile, "", nil
	}
	return "", "", fmt.Errorf(
		"cannot tell which daemon %s is for (service.name %q, file name %q); use --role auth|agent|imr",
		path, serviceName, filepath.Base(path))
}

// splitWords lower-cases s and splits it into runs of letters and digits.
func splitWords(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
}

// roleFromWords returns the daemon role named by a whole word of s, ignoring
// trailing digits (auth2), or "".
func roleFromWords(s string) string {
	for _, w := range splitWords(s) {
		switch strings.TrimRight(w, "0123456789") {
		case "auth":
			return "auth"
		case "agent":
			return "agent"
		case "imr":
			return "imr"
		}
	}
	return ""
}

// apiBaseURL turns one apiserver.addresses entry into the base URL the CLI
// uses.
//
// A wildcard listen address (0.0.0.0, ::, or no host) is where the daemon
// listens, not where a client connects, so it becomes loopback: the CLI and
// the daemon run on the same host. Anything else is used as written.
func apiBaseURL(addr string, useTLS bool) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("apiserver.addresses entry %q is not host:port: %w", addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("apiserver.addresses entry %q has no port", addr)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	scheme := "https"
	if !useTLS {
		scheme = "http"
	}
	return scheme + "://" + net.JoinHostPort(host, port) + "/api/v1", nil
}

// deriveInstanceName proposes a command word for a daemon config from its file
// name: tdns-auth2.yaml gives "auth2", sec-tdns-auth.yaml "sec-tdns-auth". The
// result is a valid instance name, or "" if the file name has nothing usable.
func deriveInstanceName(path string) string {
	b := strings.ToLower(filepath.Base(path))
	b = strings.TrimSuffix(b, filepath.Ext(b))
	b = strings.TrimPrefix(b, "tdns-")
	var sb strings.Builder
	for _, r := range b {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	name := strings.Trim(sb.String(), "-")
	if !validInstanceName(name) {
		return ""
	}
	return name
}

// validInstanceName reports whether s can be a command word: lower-case
// letters, digits and hyphens, starting with a letter, at most 32 characters.
func validInstanceName(s string) bool {
	if s == "" || len(s) > 32 || s[0] < 'a' || s[0] > 'z' || strings.HasSuffix(s, "-") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// freeName returns base if taken(base) is false, else base with a number
// appended (auth -> auth2 -> auth3). A base that already ends in digits is
// stripped of them first, so auth2 becomes auth3, not auth22.
func freeName(base string, taken func(string) bool) string {
	if !taken(base) {
		return base
	}
	stem := strings.TrimRight(base, "0123456789")
	if stem == "" {
		stem = base
	}
	for i := 2; ; i++ {
		if cand := fmt.Sprintf("%s%d", stem, i); cand != base && !taken(cand) {
			return cand
		}
	}
}
