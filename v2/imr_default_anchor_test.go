/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// A block scalar reaches the field intact through viper, the daemons' path,
// and both its records load.
func TestViperTrustAnchorDSBlockScalar(t *testing.T) {
	doc := "imrengine:\n   trust-anchor-ds: |\n      " + rootDS20326 + "\n      " + rootDS38696 + "\n"
	f := filepath.Join(t.TempDir(), "imr.yaml")
	if err := os.WriteFile(f, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	v.SetConfigFile(f)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}
	var c Config
	if err := v.Unmarshal(&c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	dss, err := parseInlineDSAnchors(c.Imr.TrustAnchorDS)
	if err != nil {
		t.Fatalf("parseInlineDSAnchors(%q): %v", c.Imr.TrustAnchorDS, err)
	}
	if got, want := dsKeyTags(dss), []uint16{20326, 38696}; !slices.Equal(got, want) {
		t.Errorf("key tags = %v, want %v", got, want)
	}
}

// dog reads the IMR config the way the IMR does: two DS records in
// trust-anchor-ds are two anchors, and a value the IMR refuses is ignored
// whole.
func TestImrConfigAnchorsReadsSeveralDS(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return f
	}

	f := write("two.yaml", "imrengine:\n   trust-anchor-ds: |\n      "+rootDS20326+"\n      "+rootDS38696+"\n")
	ds, keys, src := imrConfigAnchors(f, func(string, ...any) {})
	if got, want := dsKeyTags(ds), []uint16{20326, 38696}; !slices.Equal(got, want) || len(keys) != 0 {
		t.Fatalf("got DS key tags %v and %d DNSKEY, want %v and none", got, len(keys), want)
	}
	if !strings.Contains(src, "trust-anchor-ds") {
		t.Errorf("source %q does not name trust-anchor-ds", src)
	}

	f = write("bad.yaml", "imrengine:\n   trust-anchor-ds: |\n      "+rootDS20326+"\n      www.example. IN A 192.0.2.1\n")
	var logged []string
	ds, keys, src = imrConfigAnchors(f, func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	})
	if len(ds) != 0 || len(keys) != 0 || src != "" {
		t.Errorf("a trust-anchor-ds with a non-DS in it: got %d DS, %d DNSKEY, source %q; want it ignored", len(ds), len(keys), src)
	}
	if !strings.Contains(strings.Join(logged, "\n"), "trust-anchor-ds") {
		t.Errorf("the ignored setting was not reported: %v", logged)
	}
}
