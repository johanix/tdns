/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"strings"
	"testing"

	"github.com/johanix/tdns/v2"
)

// `config check` says which trust anchor the resolver will use: the compiled-in
// IANA root anchor when none is configured and the root hints are the
// compiled-in ones, and none -- a failure, with validation on -- when the root
// may be a private one.
func TestConfigCheckImrTrustAnchors(t *testing.T) {
	const g = "Trust anchors"
	off := false
	for _, tc := range []struct {
		name      string
		set       func(*tdns.Config)
		want      ccLevel
		wantInMsg string
	}{
		{"anchor configured", func(c *tdns.Config) {
			c.Imr.TrustAnchorDS = ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
		}, ccPASS, "is configured"},
		{"nothing set", func(*tdns.Config) {}, ccPASS, "compiled-in IANA root anchor is used"},
		{"root-hints file", func(c *tdns.Config) { c.Imr.RootHints = "/etc/tdns/root.hints" }, ccFAIL, "root-hints is set"},
		{"forwarded root", func(c *tdns.Config) {
			c.Imr.Forward = []tdns.ImrForwardConf{{Zone: ".", Upstreams: []tdns.ImrUpstreamConf{{Addr: "192.0.2.53"}}}}
		}, ccFAIL, "root is forwarded"},
		{"root-hints file, validation not enforced", func(c *tdns.Config) {
			c.Imr.RootHints = "/etc/tdns/root.hints"
			c.Imr.RequireDnssecValidation = &off
		}, ccINFO, "root-hints is set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			tc.set(cfg)
			rep := newCCReport()
			checkImrTrustAnchors(cfg, rep)
			if !hasLevel(rep, g, "anchor", tc.want) {
				t.Fatalf("want %s, got %+v", tc.want.label(), rep.byGroup[g])
			}
			for _, r := range rep.byGroup[g] {
				if r.check == "anchor" && !strings.Contains(r.msg, tc.wantInMsg) {
					t.Errorf("message %q does not mention %q", r.msg, tc.wantInMsg)
				}
			}
		})
	}
}
