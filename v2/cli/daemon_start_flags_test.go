package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// `imr2 daemon start` (or auth2's) must start the daemon on the instance's own
// config-file:, not on the daemon's compiled-in default, which is the
// canonical daemon's file. The CLI's own --config names the CLI config, so it
// is not passed to that daemon at all.
func TestDaemonStartFlagsCarryTheInstanceConfig(t *testing.T) {
	newTree := func() (*cobra.Command, *cobra.Command) {
		root := &cobra.Command{Use: "tdns-ncli"}
		root.PersistentFlags().String("config", "", "")
		root.PersistentFlags().Bool("debug", false, "")
		start := &cobra.Command{Use: "start"}
		root.AddCommand(start)
		return root, start
	}
	inst := &ApiDetails{Name: "imr2", Role: "imr", ConfigFile: "/etc/tdns/tdns-imr2.yaml"}
	flags := func(start *cobra.Command, ad *ApiDetails) []string {
		t.Helper()
		f, err := daemonStartFlags(start, ad)
		if err != nil {
			t.Fatalf("daemonStartFlags(%+v): %v", ad, err)
		}
		return f
	}

	_, start := newTree()
	if got, want := flags(start, inst), []string{"--config", "/etc/tdns/tdns-imr2.yaml"}; !reflect.DeepEqual(got, want) {
		t.Errorf("instance: %q, want %q", got, want)
	}

	root, start := newTree()
	root.PersistentFlags().Set("debug", "true")
	if got, want := flags(start, inst), []string{"--config", "/etc/tdns/tdns-imr2.yaml", "--debug"}; !reflect.DeepEqual(got, want) {
		t.Errorf("instance with --debug: %q, want %q", got, want)
	}

	// tdns-ncli --config /etc/tdns/tdns-ncli.yaml imr2 daemon start: that
	// --config is the CLI's config, not the daemon's.
	root, start = newTree()
	root.PersistentFlags().Set("config", "/etc/tdns/tdns-ncli.yaml")
	root.PersistentFlags().Set("debug", "true")
	if got, want := flags(start, inst), []string{"--config", "/etc/tdns/tdns-imr2.yaml", "--debug"}; !reflect.DeepEqual(got, want) {
		t.Errorf("with the CLI's --config: %q, want %q", got, want)
	}

	// An entry with no config-file: gets the flags as before, --config
	// included.
	root, start = newTree()
	root.PersistentFlags().Set("config", "/tmp/explicit.yaml")
	if got, want := flags(start, &ApiDetails{Name: "tdns-imr"}), []string{"--config", "/tmp/explicit.yaml"}; !reflect.DeepEqual(got, want) {
		t.Errorf("entry with no config-file: and --config: %q, want %q", got, want)
	}

	_, start = newTree()
	if got := flags(start, &ApiDetails{Name: "tdns-imr"}); len(got) != 0 {
		t.Errorf("entry with no config-file: %q, want none", got)
	}
	if got := flags(start, nil); len(got) != 0 {
		t.Errorf("no entry: %q, want none", got)
	}

	// A named instance with no config-file: has nothing right to start on:
	// the compiled-in default is the canonical daemon's config, and the
	// CLI's --config is the CLI's. Refused, with or without --config.
	for _, cfg := range []string{"", "/etc/tdns/tdns-ncli.yaml"} {
		root, start = newTree()
		if cfg != "" {
			root.PersistentFlags().Set("config", cfg)
		}
		got, err := daemonStartFlags(start, &ApiDetails{Name: "imr2", Role: "imr"})
		if err == nil || !strings.Contains(err.Error(), `"imr2" has no config-file:`) {
			t.Errorf("instance with no config-file: (--config %q): %q, %v; want a refusal", cfg, got, err)
		}
	}
}

// What `imr2 config mwe` tells the operator: an entry whose config-file: is
// the file it wrote and the start command uses (the .mwe when the config was
// already there), and a check through imr2's own entry.
func TestImrConfigMweOutputForAnInstance(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-imr2.yaml")
	if err := os.WriteFile(cfg, []byte("# the existing config\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { runImrConfigMwe("imr2", cfg) })

	mwe := cfg + ".mwe"
	if !strings.Contains(out, "config-file: "+mwe+"\n") {
		t.Errorf("the entry's config-file: is not the written %s:\n%s", mwe, out)
	}
	if !strings.Contains(out, "tdns-imr --config "+mwe) {
		t.Errorf("the start command does not use %s:\n%s", mwe, out)
	}
	if !strings.Contains(out, "tdns-ncli imr2 config check --serverconfig "+mwe) {
		t.Errorf("the check does not go through imr2's entry:\n%s", out)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "# the existing config\n" {
		t.Error("the existing config was changed")
	}
}

// command: may carry arguments, as an operator writes it: split as a shell
// would, and a --config in it agreeing with config-file: passed once.
func TestDaemonCommandLine(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		flags         []string
		bin           string
		args          []string
		err           string
	}{
		{"binary only", "/usr/local/libexec/tdns-auth", []string{"--config", "/etc/tdns-enc/tdns-auth.yaml"},
			"/usr/local/libexec/tdns-auth", []string{"--config", "/etc/tdns-enc/tdns-auth.yaml"}, ""},
		{"testor's auth2", "/usr/local/libexec/tdns-auth --config /etc/tdns-enc/tdns-auth.yaml", []string{"--config", "/etc/tdns-enc/tdns-auth.yaml", "--debug"},
			"/usr/local/libexec/tdns-auth", []string{"--config", "/etc/tdns-enc/tdns-auth.yaml", "--debug"}, ""},
		{"--config= spelling", "/usr/local/libexec/tdns-auth --config=/etc/tdns-enc/tdns-auth.yaml", []string{"--config", "/etc/tdns-enc/tdns-auth.yaml"},
			"/usr/local/libexec/tdns-auth", []string{"--config=/etc/tdns-enc/tdns-auth.yaml"}, ""},
		{"no config-file", "/usr/local/libexec/tdns-auth --config /etc/tdns-enc/tdns-auth.yaml", nil,
			"/usr/local/libexec/tdns-auth", []string{"--config", "/etc/tdns-enc/tdns-auth.yaml"}, ""},
		{"disagreeing --config", "/usr/local/libexec/tdns-auth --config /etc/tdns-site/tdns-auth.yaml", []string{"--config", "/etc/tdns-enc/tdns-auth.yaml"},
			"", nil, "make them the same"},
		{"quoted", `'/opt/my tdns/tdns-auth' -v "--config" /etc/a\ b.yaml`, nil,
			"/opt/my tdns/tdns-auth", []string{"-v", "--config", "/etc/a b.yaml"}, ""},
		{"unclosed quote", `/usr/local/libexec/tdns-auth 'x`, nil, "", nil, "not closed"},
		{"empty", "", []string{"--debug"}, "", []string{"--debug"}, ""},
	} {
		bin, args, err := daemonCommandLine(tc.command, tc.flags)
		switch {
		case tc.err != "":
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err = %v, want %q", tc.name, err, tc.err)
			}
		case err != nil || bin != tc.bin || !reflect.DeepEqual(args, tc.args):
			t.Errorf("%s: %q %q %v, want %q %q", tc.name, bin, args, err, tc.bin, tc.args)
		}
	}
}
