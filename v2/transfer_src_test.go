/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

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
			got, network := pickTransferSrc(context.Background(), nil, tc.upstream, tc.srcs)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("pickTransferSrc(%q, %v) = %v, want nil", tc.upstream, tc.srcs, got)
				}
				if network != "" {
					t.Fatalf("no source picked but network = %q", network)
				}
				return
			}
			if got == nil || got.String() != tc.want {
				t.Fatalf("pickTransferSrc(%q, %v) = %v, want %s", tc.upstream, tc.srcs, got, tc.want)
			}
			// The dial network must match the bound source's family, or the
			// destination can land in the other family and the dial fails.
			wantNet := "tcp6"
			if got.To4() != nil {
				wantNet = "tcp4"
			}
			if network != wantNet {
				t.Fatalf("source %v bound but network = %q, want %q", got, network, wantNet)
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
				kdb := &KeyDB{}
				kdb.SetTransferSrc(tc.global)
				zd.KeyDB = kdb
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

// TestPickTransferSrcHostnameUpstream covers the bug this fix exists for. The
// first version read the family off net.ParseIP(host), which is nil for a
// hostname -- so want4 was false and a hostname upstream got an IPv6 source
// bound, whatever the name actually resolved to, and the dial then failed.
//
// The resolver is stubbed: a real "localhost" is usually dual-stack, which
// would make binding v6 look legitimate and hide exactly the regression this
// test is for.
func TestPickTransferSrcHostnameUpstream(t *testing.T) {
	v4 := []net.IPAddr{{IP: net.ParseIP("10.25.0.4")}}
	v6 := []net.IPAddr{{IP: net.ParseIP("2a01:bad:cafe:f::5")}}
	both := append(append([]net.IPAddr{}, v4...), v6...)

	stub := func(addrs []net.IPAddr) func(context.Context, string) ([]net.IPAddr, error) {
		return func(context.Context, string) ([]net.IPAddr, error) { return addrs, nil }
	}

	for _, tc := range []struct {
		name        string
		resolves    []net.IPAddr
		srcs        []string
		wantIP      string
		wantNetwork string
	}{
		{
			// THE REGRESSION. v6 source listed first; the name is v4-only.
			// The old code bound the v6 source here and the transfer failed.
			name:     "v4-only hostname must not get the v6 source",
			resolves: v4, srcs: []string{"2a01:bad:cafe:f::53", "172.16.0.53"},
			wantIP: "172.16.0.53", wantNetwork: "tcp4",
		},
		{
			name:     "v6-only hostname must not get the v4 source",
			resolves: v6, srcs: []string{"172.16.0.53", "2a01:bad:cafe:f::53"},
			wantIP: "2a01:bad:cafe:f::53", wantNetwork: "tcp6",
		},
		{
			// Dual-stack: configured order decides, so the ACL-visible
			// address stays predictable.
			name:     "dual-stack hostname follows configured order",
			resolves: both, srcs: []string{"2a01:bad:cafe:f::53", "172.16.0.53"},
			wantIP: "2a01:bad:cafe:f::53", wantNetwork: "tcp6",
		},
		{
			name:     "dual-stack, only v4 configured",
			resolves: both, srcs: []string{"172.16.0.53"},
			wantIP: "172.16.0.53", wantNetwork: "tcp4",
		},
		{
			// No source for the family the name has -> unbound, not a guess.
			name:     "v4-only hostname, only v6 source -> unbound",
			resolves: v4, srcs: []string{"2a01:bad:cafe:f::53"},
			wantIP: "", wantNetwork: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, network := pickTransferSrc(context.Background(), stub(tc.resolves),
				"ns.example.com:53", tc.srcs)
			if tc.wantIP == "" {
				if ip != nil || network != "" {
					t.Fatalf("got (%v, %q), want (nil, \"\")", ip, network)
				}
				return
			}
			if ip == nil || ip.String() != tc.wantIP {
				t.Fatalf("got IP %v, want %s", ip, tc.wantIP)
			}
			if network != tc.wantNetwork {
				t.Fatalf("got network %q, want %q", network, tc.wantNetwork)
			}
		})
	}
}

// TestPickTransferSrcUnresolvableHostname: a name we cannot resolve must fall
// back to unbound rather than to a guess. Binding the wrong family would fail a
// transfer that would otherwise have worked.
func TestPickTransferSrcUnresolvableHostname(t *testing.T) {
	failing := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("no such host")
	}
	ip, network := pickTransferSrc(context.Background(), failing,
		"no-such-host.invalid.:53", []string{"127.0.0.1", "::1"})
	if ip != nil || network != "" {
		t.Fatalf("unresolvable upstream: got (%v, %q), want (nil, \"\")", ip, network)
	}
}

// TestValidateTransferSrc is the other half of the fix. A bad entry used to be
// skipped silently, which meant the transfer went out UNBOUND -- the exact bug
// transfer-src exists to fix, hidden behind a config that looked correct.
func TestValidateTransferSrc(t *testing.T) {
	for _, tc := range []struct {
		name    string
		srcs    []string
		wantErr string // substring; "" means must pass
	}{
		{"empty list", nil, ""},
		{"v4", []string{"172.16.0.53"}, ""},
		{"v6", []string{"2a01:bad:cafe:f::53"}, ""},
		{"both", []string{"172.16.0.53", "2a01:bad:cafe:f::53"}, ""},
		{"whitespace tolerated", []string{"  172.16.0.53  "}, ""},

		// The mistake actually worth catching: it looks like every other
		// address:port in the config file.
		{"addr:port", []string{"172.16.0.53:53"}, "includes a port"},
		{"v6 addr:port", []string{"[2a01:bad:cafe:f::53]:53"}, "includes a port"},
		{"hostname", []string{"ns1.example.com"}, "not an IP address"},
		{"garbage", []string{"not-an-ip"}, "not an IP address"},
		{"empty entry", []string{""}, "empty entry"},
		{"good then bad still fails", []string{"172.16.0.53", "oops"}, "not an IP address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTransferSrc("dnsengine.transfer_src", tc.srcs)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateTransferSrc(%v) = %v, want nil", tc.srcs, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateTransferSrc(%v) = nil, want error containing %q", tc.srcs, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
			// The offending value must be named, or an operator cannot find it.
			if tc.srcs[len(tc.srcs)-1] != "" && !strings.Contains(err.Error(), strings.TrimSpace(tc.srcs[len(tc.srcs)-1])) {
				t.Errorf("error %q does not name the offending entry", err)
			}
		})
	}
}

// TestResolveTransferSrcUpdate pins the modify semantics. The distinction that
// matters is nil vs empty: without it a per-zone transfer-src could be set but
// never removed except by deleting and re-adding the zone, which for a
// secondary means dropping and re-pulling it.
func TestResolveTransferSrcUpdate(t *testing.T) {
	old := []string{"172.16.0.53"}

	if got := resolveTransferSrcUpdate(old, nil); len(got) != 1 || got[0] != "172.16.0.53" {
		t.Errorf("nil input should keep the stored value, got %v", got)
	}
	if got := resolveTransferSrcUpdate(old, []string{}); len(got) != 0 {
		t.Errorf("empty (non-nil) input should clear, got %v", got)
	}
	if got := resolveTransferSrcUpdate(old, []string{"10.0.0.9"}); len(got) != 1 || got[0] != "10.0.0.9" {
		t.Errorf("non-empty input should replace, got %v", got)
	}
	if got := resolveTransferSrcUpdate(nil, []string{"10.0.0.9"}); len(got) != 1 {
		t.Errorf("setting on a zone that had none should work, got %v", got)
	}
	// A zone with no value and a caller saying nothing stays with no value.
	if got := resolveTransferSrcUpdate(nil, nil); got != nil {
		t.Errorf("nil/nil should stay nil, got %v", got)
	}
}

// TestTransferScratchZoneCarriesTransferSrc is the regression test for the bug
// that made transfer-src inert in practice.
//
// An inbound AXFR is not received into the live zone; FetchFromUpstream builds a
// throwaway ZoneData and calls ZoneTransferIn on THAT. The copy lists its fields
// explicitly, and transfer-src was missing from the list -- so the config was
// accepted, persisted, reloaded and displayed correctly, and every transfer
// still went out from whatever source the kernel picked. The only visible
// evidence was in the far end's ACL log.
func TestTransferScratchZoneCarriesTransferSrc(t *testing.T) {
	live := &ZoneData{
		ZoneName:    "yankee.dnslab.",
		ZoneType:    Secondary,
		TransferSrc: []string{"172.16.0.53"},
	}
	got := newTransferScratchZone(live)

	if len(got.TransferSrc) != 1 || got.TransferSrc[0] != "172.16.0.53" {
		t.Fatalf("scratch zone dropped transfer-src: got %v, want [172.16.0.53]", got.TransferSrc)
	}
	// It must resolve the same way on the copy as on the live zone, because the
	// copy is what ZoneTransferIn asks.
	if src := (&got).EffectiveTransferSrc(); len(src) != 1 || src[0] != "172.16.0.53" {
		t.Errorf("EffectiveTransferSrc on the scratch zone = %v, want [172.16.0.53]", src)
	}
	// The fields the transfer itself depends on must survive too.
	if got.ZoneName != live.ZoneName || got.ZoneType != live.ZoneType {
		t.Errorf("scratch zone lost identity: name=%q type=%v", got.ZoneName, got.ZoneType)
	}
	// A zone with no per-zone value must not invent one.
	empty := newTransferScratchZone(&ZoneData{ZoneName: "x."})
	if src := (&empty).EffectiveTransferSrc(); len(src) != 0 {
		t.Errorf("unset zone should resolve to no source, got %v", src)
	}
}

// TestValidateAllTransferSrc covers the CodeRabbit finding on #352: the first
// cut validated the global list in both the daemon loader and `config check`,
// but per-zone overrides only in the loader -- so `config check` passed configs
// that startup then refused, which defeats having a check command.
//
// Templates were missed by both, and matter as much as zones: a template is a
// ZoneConf and ExpandTemplate gap-fills its transfer-src onto every primary
// expanded from it, so a bad value there reaches real zones.
func TestValidateAllTransferSrc(t *testing.T) {
	for _, tc := range []struct {
		name    string
		conf    *Config
		wantErr string
	}{
		{"all empty", &Config{}, ""},
		{
			name: "valid everywhere",
			conf: &Config{
				DnsEngine: DnsEngineConf{TransferSrc: []string{"172.16.0.53"}},
				Zones:     []ZoneConf{{Name: "a.example.", TransferSrc: []string{"10.0.0.1"}}},
				Templates: []ZoneConf{{Name: "tmpl", TransferSrc: []string{"10.0.0.2"}}},
			},
		},
		{
			name:    "bad global",
			conf:    &Config{DnsEngine: DnsEngineConf{TransferSrc: []string{"172.16.0.53:53"}}},
			wantErr: "dnsengine.transfer_src",
		},
		{
			name:    "bad zone override is caught here too",
			conf:    &Config{Zones: []ZoneConf{{Name: "a.example.", TransferSrc: []string{"nope"}}}},
			wantErr: "zone a.example.",
		},
		{
			name:    "bad template override",
			conf:    &Config{Templates: []ZoneConf{{Name: "tmpl", TransferSrc: []string{"ns.example.com"}}}},
			wantErr: "template tmpl",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAllTransferSrc(tc.conf)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateAllTransferSrc = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateAllTransferSrc = nil, want error naming %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not name %q", err, tc.wantErr)
			}
		})
	}
}

// TestKeyDBGlobalsNoRace exercises the reload-vs-serve race CodeRabbit flagged
// on #352: config reload replaces the server-global transfer-src and outbound
// serial mode while serving goroutines read them through the Effective*
// resolvers. Both were plain struct fields, so the write and the read were an
// unsynchronised slice-header / string-header access.
//
// Only meaningful under -race; without it a torn read is simply unlikely rather
// than impossible, which is what makes this class of bug survive review.
func TestKeyDBGlobalsNoRace(t *testing.T) {
	kdb := &KeyDB{}
	kdb.SetTransferSrc([]string{"172.16.0.53"})
	kdb.SetOutboundSoaSerial(OutboundSoaSerialKeep)

	// A zone with no per-zone value, so both resolvers fall through to the
	// global tier -- the tier the reload is rewriting.
	zd := &ZoneData{ZoneName: "example.", KeyDB: kdb}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Reloader.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				kdb.SetTransferSrc([]string{"172.16.0.53"})
				kdb.SetOutboundSoaSerial(OutboundSoaSerialUnixtime)
			} else {
				kdb.SetTransferSrc([]string{"10.0.0.1", "2a01:bad:cafe:f::53"})
				kdb.SetOutboundSoaSerial(OutboundSoaSerialKeep)
			}
		}
	}()

	// Readers, as the transfer and serial paths do.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, s := range zd.EffectiveTransferSrc() {
					if s == "" {
						t.Error("observed an empty entry in the global transfer-src")
					}
				}
				_ = zd.EffectiveOutboundSoaSerial()
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestTransferSrcListIsACopy: a caller must not be able to mutate what other
// goroutines observe, nor be mutated under by the next reload.
func TestTransferSrcListIsACopy(t *testing.T) {
	kdb := &KeyDB{}
	orig := []string{"172.16.0.53"}
	kdb.SetTransferSrc(orig)

	// Mutating the slice we passed in must not change the stored value.
	orig[0] = "10.0.0.99"
	if got := kdb.TransferSrcList(); len(got) != 1 || got[0] != "172.16.0.53" {
		t.Errorf("stored value followed the caller's slice: %v", got)
	}
	// Mutating what we got back must not change the stored value either.
	got := kdb.TransferSrcList()
	got[0] = "10.0.0.98"
	if again := kdb.TransferSrcList(); again[0] != "172.16.0.53" {
		t.Errorf("returned slice aliases the stored value: %v", again)
	}
}
