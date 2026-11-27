/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * `tdns-ncli config check`: whether every apiservers: entry of the CLI
 * config can be used, and the command that fixes each one that cannot.
 */
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

func newConfigCheckCliCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check that every entry of the CLI config can be used",
		Long: `Checks every apiservers: entry of the CLI config without asking any
daemon: its name (an old name such as tdns-auth must be renamed: an
entry's name is now its command word), its role, its address (https, or
the local socket through config-file:) and its pins. Each problem comes
with the command that fixes it. The exit status is non-zero if there is
any. config list --check asks the daemons as well.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cliConfigPath(cmd)
			entries, err := ReadApiServers(cfg)
			if errors.Is(err, os.ErrNotExist) {
				fatalf("no CLI config %s. This writes one:\n%s", cfg,
					commandLines(ConfigAddHint(cfg)+" "+defaultDaemonConfig("auth"), 3))
			}
			if err != nil {
				fatalf("%v", err)
			}
			if n := CheckCliConfig(os.Stdout, cmd.Root(), cfg, entries, obsoleteEntryKeysIn(cfg)); n > 0 {
				os.Exit(1)
			}
		},
	}
}

// CheckCliConfig writes the verdict on entries, the apiservers: list of
// the CLI config cfg, to w, verdict first, and returns the number of
// problems. obsolete holds, per entry name, the keys of the API key era
// the entry still has (obsoleteEntryKeysIn): notes, not problems, as the
// CLI ignores them.
func CheckCliConfig(w io.Writer, root *cobra.Command, cfg string, entries []ApiDetails, obsolete map[string][]string) int {
	verdicts := checkInstanceEntries(commandsWithoutInstances(root), entries, builtinRoles())
	type problem struct{ what, fix string }
	var problems []problem
	var notes []string
	for i, e := range entries {
		v := verdicts[i]
		_, fix := entryFix(cfg, e)
		lower := strings.ToLower(e.BaseURL)
		switch {
		case v.Rename != "":
			problems = append(problems, problem{fmt.Sprintf("%s: the old name of the %s entry; an entry's name is\nnow its command word. Rename it:", e.Name, v.Rename), fix})
		case !v.Canonical && !v.Wire:
			problems = append(problems, problem{trimEntryPrefixKeep(v.Why), ""})
		case strings.HasPrefix(lower, "http://"):
			problems = append(problems, problem{fmt.Sprintf("%s: plain http, and the management API is TLS only.\nAs root on the daemon's host:", e.Name), fix})
		case strings.HasPrefix(lower, "https://") && len(e.Pins) == 0:
			problems = append(problems, problem{fmt.Sprintf("%s: no pin of its daemon's certificate. As root on\nthe daemon's host:", e.Name), fix})
		case v.Canonical && v.RoleEntry == "" && e.Role == "":
			notes = append(notes, fmt.Sprintf("%s has no role: and no command tree in this CLI reaches it", e.Name))
		}
		if keys := obsolete[e.Name]; len(keys) > 0 {
			notes = append(notes, fmt.Sprintf("%s has %s: lines of the API key era, which the CLI ignores; the next config update of %s drops them",
				e.Name, strings.Join(keys, ":, "), e.Name))
		}
	}

	switch n := len(problems); {
	case n == 0:
		fmt.Fprintf(w, "CLI config %s: ok, %d entr%s.\n", cfg, len(entries), plural(len(entries), "y", "ies"))
	default:
		fmt.Fprintf(w, "CLI config %s: %d problem%s.\n", cfg, n, plural(n, "", "s"))
	}
	for _, p := range problems {
		fmt.Fprintf(w, "\n%s\n", p.what)
		if p.fix != "" {
			fmt.Fprintln(w, commandLines(p.fix, 3))
		}
	}
	for _, n := range notes {
		fmt.Fprintf(w, "\nNote: %s\n", strings.Join(wrapText(n, 66), "\n      "))
	}
	for _, d := range duplicatePins(entries) {
		fmt.Fprintf(w, "\nWarning: %s\n", d)
	}
	return len(problems)
}

// trimEntryPrefixKeep is an instance refusal as config check prints it: the
// entry's name first, without the quotes and the "apiservers entry" lead.
func trimEntryPrefixKeep(why string) string {
	const lead = `apiservers entry "`
	if strings.HasPrefix(why, lead) {
		if i := strings.Index(why[len(lead):], `": `); i >= 0 {
			name := why[len(lead) : len(lead)+i]
			return name + ": " + why[len(lead)+i+3:]
		}
	}
	return why
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// obsoleteEntryKeysIn reads the CLI config cfg's apiservers: list raw, and
// returns, per entry name, which of ObsoleteEntryKeys it has. Best effort:
// a config that does not load has none.
func obsoleteEntryKeysIn(cfg string) map[string][]string {
	v, _, err := loadCliViper(cfg, nil)
	if err != nil {
		return nil
	}
	list, _ := v.Get("apiservers").([]interface{})
	out := map[string][]string{}
	for _, it := range list {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		for _, k := range ObsoleteEntryKeys {
			if _, has := m[k]; has && !slices.Contains(out[name], k) {
				out[name] = append(out[name], k)
			}
		}
	}
	return out
}
