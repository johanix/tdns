/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
)

// asProcess makes the test run as appType, with or without a live cache.
func asProcess(t *testing.T, appType tdns.AppType, withCache bool) {
	t.Helper()
	savedType, savedCache := tdns.Globals.App.Type, Conf.Internal.RRsetCache
	t.Cleanup(func() { tdns.Globals.App.Type, Conf.Internal.RRsetCache = savedType, savedCache })
	tdns.Globals.App.Type = appType
	Conf.Internal.RRsetCache = nil
	if withCache {
		Conf.Internal.RRsetCache = cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	}
}

func TestInProcessOnlyRefusesInTdnsCli(t *testing.T) {
	asProcess(t, tdns.AppTypeCli, false)
	var buf bytes.Buffer
	if !inProcessOnly(&buf, "imr show config", `"tdns-cli imr config status"`) {
		t.Fatal("tdns-cli with no cache was allowed to report its own state as the resolver's")
	}
	if !strings.Contains(buf.String(), "imr config status") {
		t.Errorf("the refusal does not name the alternative: %q", buf.String())
	}
}

func TestInProcessOnlyAllowsTheResolversShell(t *testing.T) {
	asProcess(t, tdns.AppTypeCli, true)
	if inProcessOnly(io.Discard, "imr show config", "") {
		t.Error("refused in a process that holds the live cache")
	}
}

// Through the command itself: "imr show config" in tdns-cli used to print
// tdns-cli's empty configuration -- "Listening addresses: (none configured)",
// "Cache primed: false" -- about a daemon that was up and serving.
func TestShowConfigInTdnsCliDoesNotDescribeTdnsCli(t *testing.T) {
	asProcess(t, tdns.AppTypeCli, false)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedOut, savedErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	imrShowConfigCmd.Run(imrShowConfigCmd, nil)
	os.Stdout, os.Stderr = savedOut, savedErr
	w.Close()
	out, _ := io.ReadAll(r)

	if strings.Contains(string(out), "Listening addresses") || strings.Contains(string(out), "Cache primed") {
		t.Fatalf("show config described tdns-cli's own state:\n%s", out)
	}
	if !strings.Contains(string(out), "tdns-imr --cli") {
		t.Errorf("show config did not say where it works:\n%s", out)
	}
}
