/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The bridge from synthesized to provisioned transport signals. A server
// synthesizes a signal only for its identities (rule 2 of the maintainer's
// ruling on plan step S2, 2026-11-15); the direction is signals provisioned
// in the zones. tdns-cli's "config transport-signal" asks the daemon for
// what synthesis writes at _dns.<name> from the current service.transport,
// for every identity or for one name, so an operator can paste the records
// into the zone. Synthesis then stops there: it never writes where records
// exist.

// TransportSignalPreview is the signal service.transport gives one name,
// and where things stand at that name on this server.
type TransportSignalPreview struct {
	Name     string   // the nameserver name
	Owner    string   // _dns.<name>
	Records  []string // zone-file lines, exactly what synthesis writes
	Identity bool     // the name is in service.identities
	Home     string   `json:",omitempty"` // the name's home zone, "" when none is served here
	// State at the owner in the home zone:
	//   synthesized: the start-up pass's own signal is there
	//   provisioned: records the pass did not store are there; it does not synthesize
	//   none:        nothing is there
	//   not-hosted:  no zone served here holds the name
	State string
	// Matches: the provisioned SVCB RRset is the one in Records (TTL aside).
	Matches bool `json:",omitempty"`
}

const (
	SignalStateSynthesized = "synthesized"
	SignalStateProvisioned = "provisioned"
	SignalStateNone        = "none"
	SignalStateNotHosted   = "not-hosted"
)

// transportSignalPreview builds the previews for name, or for every name in
// service.identities when name is empty.
func transportSignalPreview(conf *Config, name string) ([]TransportSignalPreview, error) {
	t := conf.Service.Transport
	if t.Type != "svcb" {
		return nil, fmt.Errorf("service.transport.type is %q; only svcb gives an SVCB signal", t.Type)
	}
	names := conf.Service.Identities
	if strings.TrimSpace(name) != "" {
		names = []string{name}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("service.identities is empty; give a name")
	}
	var out []TransportSignalPreview
	for _, n := range names {
		n = core.CanonicalizeName(dns.Fqdn(strings.TrimSpace(n)))
		if _, ok := dns.IsDomainName(n); !ok || n == "." || strings.Contains(n, "..") {
			return nil, fmt.Errorf("%q is not a nameserver name", n)
		}
		rs, err := signalRRsetFor(t, n)
		if err != nil {
			return nil, fmt.Errorf("service.transport: %w", err)
		}
		p := TransportSignalPreview{
			Name:     n,
			Owner:    rs.Name,
			Identity: CaseFoldContains(conf.Service.Identities, n),
			State:    SignalStateNotHosted,
		}
		for _, rr := range rs.RRs {
			p.Records = append(p.Records, rr.String())
		}
		if home := FindZone(n); home != nil {
			p.Home = home.ZoneName
			p.State, p.Matches = home.signalStateAt(p.Owner, rs.RRs)
		}
		out = append(out, p)
	}
	return out, nil
}

// signalStateAt reads the owner in the zone's published snapshot: the pass's
// own signal, provisioned records, or nothing. matches says whether the SVCB
// RRset there is want, TTL aside.
func (zd *ZoneData) signalStateAt(owner string, want []dns.RR) (state string, matches bool) {
	od := getOwnerFrom(zd.publishedSnapshot(), owner)
	if od == nil || ownerRRsetCount(od) == 0 {
		return SignalStateNone, false
	}
	svcb := od.RRtypes.GetOnlyRRSet(dns.TypeSVCB)
	if zd.ownerHoldsOnlyPassSignal(owner, od) {
		return SignalStateSynthesized, false
	}
	return SignalStateProvisioned, len(svcb.RRs) > 0 && signalDigest(svcb.RRs) == signalDigest(want)
}
