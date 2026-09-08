/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Provisioning for the relay family.
//
// Much thinner than the churn family's: the SUT is a SECONDARY, so it needs no
// zone file (the zone arrives from the rig's upstream over AXFR) and no SIG(0)
// key (the rig drives it entirely over DNS, never through the mgmt API). What
// is left is a config block the operator pastes in, and the reason each line
// of it is there.

// RelayProvisionInput is what the emitted config has to be built from.
type RelayProvisionInput struct {
	Zone       string
	Profile    string
	Upstream   string // where the rig's upstream peer will listen
	Downstream string // where the rig's downstream peer will listen
	Policy     string // DNSSEC policy name for the signing profile
}

// RelayConfigSnippet renders the SUT's zone (and, for the signing profile, its
// DNSSEC policy) plus the operator's to-do list.
func RelayConfigSnippet(in RelayProvisionInput) (string, []string, error) {
	zone := dns.Fqdn(in.Zone)
	if in.Profile == "" {
		in.Profile = ProfileSigning
	}
	if in.Profile != ProfileSigning && in.Profile != ProfileMirror {
		return "", nil, fmt.Errorf("unknown profile %q (want %q or %q)", in.Profile, ProfileSigning, ProfileMirror)
	}
	if in.Policy == "" {
		in.Policy = "relay"
	}
	upPrefix, err := hostPrefix(in.Upstream)
	if err != nil {
		return "", nil, fmt.Errorf("upstream listen address: %w", err)
	}
	downPrefix, err := hostPrefix(in.Downstream)
	if err != nil {
		return "", nil, fmt.Errorf("downstream listen address: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# tdns-debug relay rig -- SUT config for %s (profile: %s)\n", zone, in.Profile)
	fmt.Fprintf(&b, "#\n")
	fmt.Fprintf(&b, "# The rig is BOTH sides of this server: it is the primary this zone\n")
	fmt.Fprintf(&b, "# transfers from (%s) and the only downstream it announces to (%s).\n", in.Upstream, in.Downstream)
	fmt.Fprintf(&b, "# Nothing else may notify or transfer this zone, or the counts the rig\n")
	fmt.Fprintf(&b, "# is built to make will include somebody else's traffic.\n\n")

	if in.Profile == ProfileSigning {
		fmt.Fprintf(&b, "dnssec:\n")
		fmt.Fprintf(&b, "   policies:\n")
		fmt.Fprintf(&b, "      %s:\n", in.Policy)
		fmt.Fprintf(&b, "         algorithm:  ED25519\n")
		fmt.Fprintf(&b, "         ksk:\n            lifetime:  forever\n")
		fmt.Fprintf(&b, "         zsk:\n            lifetime:  forever\n")
		fmt.Fprintf(&b, "         csk:\n            lifetime:  none\n")
		fmt.Fprintf(&b, "         sigvalidity:\n            default:  14d\n            dnskey:   30d\n            ds:       14d\n\n")
	}

	fmt.Fprintf(&b, "zones:\n")
	fmt.Fprintf(&b, "   - name:      %s\n", zone)
	fmt.Fprintf(&b, "     type:      secondary\n")
	fmt.Fprintf(&b, "     store:     map\n")
	if in.Profile == ProfileSigning {
		// inline-signing is what puts the zone on the may-originate side of
		// zoneMayOriginateContent, which is the whole regime under test.
		fmt.Fprintf(&b, "     options:   [ inline-signing ]\n")
		fmt.Fprintf(&b, "     dnssecpolicy: %s\n", in.Policy)
	}
	fmt.Fprintf(&b, "     primaries:\n        - addr: %q\n          key:  NOKEY\n", in.Upstream)
	fmt.Fprintf(&b, "     allow-notify:\n        - prefix: %q\n          key:    NOKEY\n", upPrefix)
	fmt.Fprintf(&b, "     notify:\n        - addr: %q\n          key:  NOKEY\n", in.Downstream)
	fmt.Fprintf(&b, "     downstreams:\n        - prefix: %q\n          key:    NOKEY\n", downPrefix)

	todo := []string{
		fmt.Sprintf("paste the block above into the SUT's config (zone %s)", zone),
		"reload or restart the SUT, and confirm the zone is listed (`tdns-cli auth zone list`)",
		fmt.Sprintf("start the rig: tdns-debug test relay --zone %s --sut <addr:port> --profile %s", zone, in.Profile),
	}
	if in.Profile == ProfileSigning {
		todo = append(todo,
			"the zone stays unloaded until the rig runs -- the rig's upstream is its only primary, and it does not exist until then")
	} else {
		todo = append(todo,
			"do NOT give this zone inline-signing or a dnssecpolicy: the mirror profile checks that the SUT changes nothing, serial included")
	}
	return b.String(), todo, nil
}

// hostPrefix turns a listen address into the single-host ACL prefix that
// matches it, so allow-notify and downstreams admit the rig and nothing else.
func hostPrefix(addrPort string) (string, error) {
	host, _, err := net.SplitHostPort(addrPort)
	if err != nil {
		return "", fmt.Errorf("%q is not addr:port: %w", addrPort, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("%q is not an IP address; the ACL needs one", host)
	}
	if ip.To4() != nil {
		return ip.String() + "/32", nil
	}
	return ip.String() + "/128", nil
}
