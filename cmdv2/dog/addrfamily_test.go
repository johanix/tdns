/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

func TestAddrFamilyFromFlags(t *testing.T) {
	for _, tc := range []struct {
		v4, v6  bool
		want    core.AddrFamily
		wantErr bool
	}{
		{false, false, core.FamilyAny, false},
		{true, false, core.FamilyIPv4, false},
		{false, true, core.FamilyIPv6, false},
		// dig refuses both ("only one of -4 and -6 allowed"); so does dog.
		{true, true, core.FamilyAny, true},
	} {
		got, err := addrFamilyFromFlags(tc.v4, tc.v6)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("addrFamilyFromFlags(%v, %v) = %v, %v; want %v, err=%v",
				tc.v4, tc.v6, got, err, tc.want, tc.wantErr)
		}
	}
	if _, err := addrFamilyFromFlags(true, true); err == nil || !strings.Contains(err.Error(), "only one of -4 and -6") {
		t.Errorf("both flags: error %v, want dig's wording", err)
	}
}

// -4 and -6 must be real flags of the command, and cobra must take them
// anywhere among dog's other arguments, including ahead of "+options", which
// it must leave alone.
func TestDashFourAndSixAreFlags(t *testing.T) {
	fs := rootCmd.PersistentFlags()
	for _, sh := range []string{"4", "6"} {
		if fs.ShorthandLookup(sh) == nil {
			t.Fatalf("no -%s flag registered", sh)
		}
	}
	t.Cleanup(func() { ipv4Only, ipv6Only = false, false })

	for _, tc := range []struct {
		args       []string
		v4, v6     bool
		wantRemain []string
	}{
		{[]string{"-4", "@192.0.2.1", "example.com", "+dnssec"}, true, false, []string{"@192.0.2.1", "example.com", "+dnssec"}},
		{[]string{"example.com", "-6", "+tcp"}, false, true, []string{"example.com", "+tcp"}},
		{[]string{"-4", "-6"}, true, true, nil},
		{[]string{"--ipv4", "example.com"}, true, false, []string{"example.com"}},
		{[]string{"--ipv6", "example.com"}, false, true, []string{"example.com"}},
	} {
		ipv4Only, ipv6Only = false, false
		if err := fs.Parse(tc.args); err != nil {
			t.Errorf("Parse(%v): %v", tc.args, err)
			continue
		}
		if ipv4Only != tc.v4 || ipv6Only != tc.v6 {
			t.Errorf("Parse(%v): ipv4Only=%v ipv6Only=%v, want %v %v", tc.args, ipv4Only, ipv6Only, tc.v4, tc.v6)
		}
		if got := fs.Args(); strings.Join(got, " ") != strings.Join(tc.wantRemain, " ") {
			t.Errorf("Parse(%v): remaining args %v, want %v", tc.args, got, tc.wantRemain)
		}
	}
}

func TestHelpDocumentsDashFourAndSix(t *testing.T) {
	for _, want := range []string{"-4, --ipv4", "-6, --ipv6", "Address family:"} {
		if !strings.Contains(rootCmd.Long, want) {
			t.Errorf("dog -h does not mention %q", want)
		}
	}
}

func TestCheckServerFamily(t *testing.T) {
	for _, tc := range []struct {
		fam     core.AddrFamily
		host    string
		wantErr string // substring; "" means no error
	}{
		{core.FamilyAny, "2001:db8::53", ""},
		{core.FamilyIPv4, "192.0.2.53", ""},
		{core.FamilyIPv6, "2001:db8::53", ""},
		{core.FamilyIPv4, "2001:db8::53", "-4 given, but server 2001:db8::53 is an IPv6 address"},
		{core.FamilyIPv6, "192.0.2.53", "-6 given, but server 192.0.2.53 is an IPv4 address"},
		// A name is resolved for the family when dialled, so it passes here.
		{core.FamilyIPv4, "ns1.example.com", ""},
		{core.FamilyIPv6, "ns1.example.com", ""},
	} {
		err := checkServerFamily(tc.fam, tc.host)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("checkServerFamily(%v, %q) = %v, want nil", tc.fam, tc.host, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("checkServerFamily(%v, %q) = %v, want %q", tc.fam, tc.host, err, tc.wantErr)
		}
	}
}

const resolvBoth = `# generated
search example.org
nameserver 2001:db8::53
nameserver 192.0.2.53
nameserver 198.51.100.53
`

func TestPickNameserver(t *testing.T) {
	for _, tc := range []struct {
		name    string
		conf    string
		fam     core.AddrFamily
		want    string
		wantErr string
	}{
		// Unchanged for no flag: the first nameserver, whatever its family.
		{"any takes the first", resolvBoth, core.FamilyAny, "2001:db8::53", ""},
		{"-4 skips the IPv6 one", resolvBoth, core.FamilyIPv4, "192.0.2.53", ""},
		{"-6 takes the IPv6 one", resolvBoth, core.FamilyIPv6, "2001:db8::53", ""},
		{"-6 skips IPv4 listed first", "nameserver 192.0.2.53\nnameserver 2001:db8::53\n", core.FamilyIPv6, "2001:db8::53", ""},
		{"scoped link-local is IPv6", "nameserver fe80::1%en0\n", core.FamilyIPv6, "fe80::1%en0", ""},
		{"indented and tabbed", "\tnameserver\t192.0.2.7\n", core.FamilyIPv4, "192.0.2.7", ""},
		// None of the family: an error that names the flag and the way out,
		// not the other family's server quietly used instead.
		{"-4 with only IPv6", "nameserver 2001:db8::53\n", core.FamilyIPv4, "", "no IPv4 nameserver"},
		{"-6 with only IPv4", "nameserver 192.0.2.53\n", core.FamilyIPv6, "", "no IPv6 nameserver"},
		{"error names the flag", "nameserver 192.0.2.53\n", core.FamilyIPv6, "", "-6"},
		{"error names the way out", "nameserver 192.0.2.53\n", core.FamilyIPv6, "", "@server"},
		// No nameserver at all keeps its existing message under every flag.
		{"empty, any", "search example.org\n", core.FamilyAny, "", "no nameserver entry found"},
		{"empty, -4", "search example.org\n", core.FamilyIPv4, "", "no nameserver entry found"},
		// A name where an address belongs cannot be placed in a family.
		{"name is skipped under -6", "nameserver ns.example.org\nnameserver 2001:db8::53\n", core.FamilyIPv6, "2001:db8::53", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pickNameserver(tc.conf, tc.fam)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("pickNameserver = %q, %v; want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("pickNameserver = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestFamilyOptionsFromMap(t *testing.T) {
	if got := familyOptions(map[string]string{}); got != nil {
		t.Errorf("no family in the map gave %d client options, want none", len(got))
	}
	for _, v := range []string{"4", "6"} {
		opts := familyOptions(map[string]string{core.OptionAddrFamily: v})
		if len(opts) != 1 {
			t.Fatalf("family %q gave %d client options, want 1", v, len(opts))
		}
		want := "udp" + v
		c := core.NewDNSClient(core.TransportDo53, "53", nil, opts...)
		if c.DNSClientUDP.Net != want {
			t.Errorf("family %q: UDP client net %q, want %q", v, c.DNSClientUDP.Net, want)
		}
	}
	if got := addrFamilyFromOptions(map[string]string{core.OptionAddrFamily: "6"}); got != core.FamilyIPv6 {
		t.Errorf("addrFamilyFromOptions(6) = %v", got)
	}
}
