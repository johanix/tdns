/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"strings"
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// +PR used to set a flag bit and could only ever say "yes". It now carries a
// level, and a bare +PR has to keep meaning what the bit meant -- strict --
// so that an existing command line does not silently become more permissive.
func TestProcessOptionsPrivacyLevels(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		want edns0.PrivacyLevel
	}{
		{"+pr", edns0.PrivacyStrict},
		{"+privacy", edns0.PrivacyStrict},
		{"+pr=strict", edns0.PrivacyStrict},
		{"+pr=2", edns0.PrivacyStrict},
		{"+pr=opportunistic", edns0.PrivacyOpportunistic},
		{"+pr=1", edns0.PrivacyOpportunistic},
		{"+privacy=none", edns0.PrivacyNone},
		{"+pr=0", edns0.PrivacyNone},
	} {
		options, err := ProcessOptions(nil, strings.ToUpper(tc.arg), tc.arg)
		if err != nil {
			t.Errorf("%s: %v", tc.arg, err)
			continue
		}
		got, ok := privacyLevel(options)
		if !ok {
			t.Errorf("%s: no privacy level recorded", tc.arg)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.arg, got, tc.want)
		}
	}
}

func TestProcessOptionsPrivacyRejectsGarbage(t *testing.T) {
	if _, err := ProcessOptions(nil, "+PR=MAYBE", "+pr=maybe"); err == nil {
		t.Error("+pr=maybe: want an error, got nil")
	}
}

// Absent +PR, no option is added: dog must not start announcing an opinion on
// privacy in every query it sends.
func TestPrivacyLevelAbsent(t *testing.T) {
	options, err := ProcessOptions(nil, "+DNSSEC", "+dnssec")
	if err != nil {
		t.Fatalf("ProcessOptions: %v", err)
	}
	if _, ok := privacyLevel(options); ok {
		t.Error("privacy level reported for a command line that never asked for one")
	}
}

// What dog puts on the wire has to be what the resolver reads back off it.
func TestPrivacyOptionOnTheWire(t *testing.T) {
	options, err := ProcessOptions(nil, "+PR=OPPORTUNISTIC", "+pr=opportunistic")
	if err != nil {
		t.Fatalf("ProcessOptions: %v", err)
	}
	level, ok := privacyLevel(options)
	if !ok {
		t.Fatal("no privacy level recorded")
	}

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}}
	if err := edns0.AddPrivacyOption(opt, uint8(level)); err != nil {
		t.Fatalf("AddPrivacyOption: %v", err)
	}
	m.Extra = append(m.Extra, opt)

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	var got dns.Msg
	if err := got.Unpack(wire); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(&got)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	if !msgoptions.HasPrivacy || msgoptions.Privacy != edns0.PrivacyOpportunistic {
		t.Errorf("resolver read HasPrivacy=%v Privacy=%s, want true/%s",
			msgoptions.HasPrivacy, msgoptions.Privacy, edns0.PrivacyOpportunistic)
	}
}
