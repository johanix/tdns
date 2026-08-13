/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package tdns

import "testing"

// TestTransferSrcFor pins the family matching. Binding a v4 source before
// dialling a v6 upstream fails at connect time, so picking the wrong entry
// would turn "bind a source address" into "this zone no longer transfers".
func TestTransferSrcFor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream string
		srcs     []string
		want     string // "" == dial unbound
	}{
		{"v4 upstream, v4 source", "10.25.0.4:53", []string{"172.16.0.53"}, "172.16.0.53"},
		{"v6 upstream, v6 source", "[2a01:bad:cafe:f::5]:53", []string{"2a01:bad:cafe:f::53"}, "2a01:bad:cafe:f::53"},
		{
			// The mixed case: both families configured, each upstream gets its own.
			name:     "mixed list picks the matching family",
			upstream: "10.25.0.4:53",
			srcs:     []string{"2a01:bad:cafe:f::53", "172.16.0.53"},
			want:     "172.16.0.53",
		},
		{
			name:     "mixed list, v6 upstream",
			upstream: "[2a01:bad:cafe:f::5]:53",
			srcs:     []string{"172.16.0.53", "2a01:bad:cafe:f::53"},
			want:     "2a01:bad:cafe:f::53",
		},
		{
			// Deliberately forgiving: naming only a v4 source must not break
			// every v6 upstream, so an unmatched family dials unbound.
			name:     "v6 upstream, only v4 source configured -> unbound",
			upstream: "[2a01:bad:cafe:f::5]:53",
			srcs:     []string{"172.16.0.53"},
			want:     "",
		},
		{"no sources", "10.25.0.4:53", nil, ""},
		{"garbage entries skipped", "10.25.0.4:53", []string{"not-an-ip", "172.16.0.53"}, "172.16.0.53"},
		{"all garbage", "10.25.0.4:53", []string{"not-an-ip"}, ""},
		{"upstream without port still works", "10.25.0.4", []string{"172.16.0.53"}, "172.16.0.53"},
		{"whitespace tolerated", "10.25.0.4:53", []string{"  172.16.0.53 "}, "172.16.0.53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := transferSrcFor(tc.upstream, tc.srcs)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("transferSrcFor(%q, %v) = %v, want nil", tc.upstream, tc.srcs, got)
				}
				return
			}
			if got == nil || got.String() != tc.want {
				t.Fatalf("transferSrcFor(%q, %v) = %v, want %s", tc.upstream, tc.srcs, got, tc.want)
			}
		})
	}
}

// TestEffectiveTransferSrc pins the zone-over-global precedence and the
// "unset means unbound" default, which is what every zone did before this.
func TestEffectiveTransferSrc(t *testing.T) {
	for _, tc := range []struct {
		name       string
		zone       []string
		global     []string
		wantSrcs   []string
		wantSource string
	}{
		{"unset everywhere", nil, nil, nil, "default"},
		{"global only", nil, []string{"172.16.0.53"}, []string{"172.16.0.53"}, "global"},
		{"zone only", []string{"10.0.0.1"}, nil, []string{"10.0.0.1"}, "zone"},
		{"zone overrides global", []string{"10.0.0.1"}, []string{"172.16.0.53"}, []string{"10.0.0.1"}, "zone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := &ZoneData{TransferSrc: tc.zone}
			if tc.global != nil {
				zd.KeyDB = &KeyDB{TransferSrc: tc.global}
			}
			srcs, source := zd.EffectiveTransferSrcWithSource()
			if source != tc.wantSource {
				t.Errorf("source = %q, want %q", source, tc.wantSource)
			}
			if len(srcs) != len(tc.wantSrcs) {
				t.Fatalf("srcs = %v, want %v", srcs, tc.wantSrcs)
			}
			for i := range srcs {
				if srcs[i] != tc.wantSrcs[i] {
					t.Errorf("srcs[%d] = %q, want %q", i, srcs[i], tc.wantSrcs[i])
				}
			}
		})
	}
}
