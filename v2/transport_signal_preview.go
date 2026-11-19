/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"slices"
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
// into the zone. Where the pass has synthesized a signal already, the
// operator then releases the name ("config transport-signal --release"),
// and the RRset there is the operator's: synthesis never writes where the
// operator's records are.

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
	if err := checkSignalTransportType(t); err != nil {
		return nil, err
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
		n, err := signalNameserverName(n)
		if err != nil {
			return nil, err
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

// checkSignalTransportType refuses a service.transport that gives no SVCB
// signal: the bridge is about SVCB signals only.
func checkSignalTransportType(t TransportConf) error {
	if t.Type != "svcb" {
		return fmt.Errorf("service.transport.type is %q; only svcb gives an SVCB signal", t.Type)
	}
	return nil
}

// signalNameserverName is name canonical and fully qualified, or an error
// when it is not a nameserver name.
func signalNameserverName(name string) (string, error) {
	n := core.CanonicalizeName(dns.Fqdn(strings.TrimSpace(name)))
	if _, ok := dns.IsDomainName(n); !ok || n == "." || strings.Contains(n, "..") {
		return "", fmt.Errorf("%q is not a nameserver name", n)
	}
	return n, nil
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
	own, err := zd.ownerHoldsOnlyPassSignal(owner, od)
	if err != nil {
		lgDns.Warn("transport signal preview: could not read the record of what the pass stored at the owner; shown as provisioned",
			"zone", zd.ZoneName, "owner", owner, "error", err)
	}
	if own {
		return SignalStateSynthesized, false
	}
	return SignalStateProvisioned, len(svcb.RRs) > 0 && signalDigest(svcb.RRs) == signalDigest(want)
}

// The release. An operator who pastes what the bridge printed over a signal
// the pass synthesized puts the pass's own bytes at the owner, and the
// pass's record of what it stored (signalDigest, TTL aside) still matches:
// the pass would go on taking the RRset for its own, rewrite it when
// service.transport changes, and withdraw it once the name leaves
// service.identities. Nothing in the zone tells the two apart: a zone write
// leaves the pass's signal in the zone file too. Only the operator can say,
// and the release is how. It drops the record, in memory and in the KeyDB,
// and from then on the pass treats whatever RRset is at the owner as the
// operator's: it leaves it alone, never rewrites it and never withdraws it.

// transportSignalRelease releases _dns.<name> in the name's home zone. It
// returns the state there after the release, and a line saying what it did.
func transportSignalRelease(conf *Config, name string) ([]TransportSignalPreview, string, error) {
	if err := checkSignalTransportType(conf.Service.Transport); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(name) == "" {
		return nil, "", fmt.Errorf("give the name to release")
	}
	n, err := signalNameserverName(name)
	if err != nil {
		return nil, "", err
	}
	home := FindZone(n)
	if home == nil {
		return nil, "", fmt.Errorf("no zone served here holds %s; nothing to release", n)
	}
	owner := "_dns." + n
	released, err := home.releaseSignal(owner)
	if err != nil {
		return nil, "", err
	}
	after, err := transportSignalPreview(conf, n)
	if err != nil {
		return nil, "", err
	}
	msg := fmt.Sprintf("released %s in %s: the RRset there is the operator's from now on", owner, home.ZoneName)
	if !released {
		msg = fmt.Sprintf("%s in %s was not the transport signal pass's; nothing to release", owner, home.ZoneName)
	}
	return after, msg, nil
}

// releaseSignal drops the pass's record of what it stored at owner. It runs
// under zd.mu, which the pass holds from its first look at an owner to its
// record of what it stored, so a pass in progress cannot record the owner
// again after the release. It refuses an owner that holds nothing: a release
// then would only let synthesis start over. released is false when the pass
// had no record of the owner. A failed KeyDB delete is an error: the
// revocation holds in this process (forgetSignalStored), but the KeyDB's
// record would outlive a restart, and the pass would take the records for
// its own again. A release run again tries the delete again, since the
// pending revocation keeps the owner in signalStoredOwners.
//
// It also refuses while a change to the SVCB RRset at owner is staged and
// not published (stagedSignalChangeLocked): its guards read the published
// zone, and the staged change publishes after the release all the same. A
// withdrawal the pass staged would then remove the RRset the release just
// handed to the operator.
//
// It refuses in a zone whose removal has started (signalPassRetired, which
// RemoveDynamicZone sets under zd.mu before it takes the KeyDB's record). A
// removal whose config rewrite fails puts that record back, and would undo
// a release made in between.
func (zd *ZoneData) releaseSignal(owner string) (released bool, err error) {
	owner = core.CanonicalizeName(owner)
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.signalPassRetired {
		return false, fmt.Errorf("zone %s is being removed, so %s cannot be released: a removal that fails puts the record of what the pass stored back", zd.ZoneName, owner)
	}
	if zd.stagedSignalChangeLocked(owner) {
		return false, fmt.Errorf("%s in %s has a change staged that is not published yet (the publish cadence holds it back, or the publish was refused); run the release again after the next publish", owner, zd.ZoneName)
	}
	if od := getOwnerFrom(zd.publishedSnapshot(), owner); od == nil || ownerRRsetCount(od) == 0 {
		return false, fmt.Errorf("%s holds nothing in %s; put the records there first (a release with nothing there would only let synthesis start over)", owner, zd.ZoneName)
	}
	if !slices.Contains(zd.signalStoredOwners(), owner) {
		return false, nil
	}
	if err := zd.forgetSignalStored(owner); err != nil {
		return false, fmt.Errorf("%s: the KeyDB could not drop the stored-signal record, so the release holds only until a restart; run it again: %w", owner, err)
	}
	lgDns.Info("transport signal released: the RRset at the owner is the operator's from now on",
		"zone", zd.ZoneName, "owner", owner)
	return true, nil
}

// stagedSignalChangeLocked reports whether the working set holds a change to
// the SVCB RRset at owner that is not published: the RRset or the whole
// owner deleted (a withdrawal), or other records put there. A working set
// that only re-stages the published records, as every pass with an identity
// does, holds no change. Caller holds zd.mu.
func (zd *ZoneData) stagedSignalChangeLocked(owner string) bool {
	if zd.workingSet == nil {
		return false
	}
	svcbStrings := func(od *OwnerData) []string {
		if od == nil {
			return nil
		}
		var out []string
		for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypeSVCB).RRs {
			out = append(out, rr.String())
		}
		slices.Sort(out)
		return out
	}
	return !slices.Equal(svcbStrings(zd.workingSet[owner]), svcbStrings(getOwnerFrom(zd.publishedSnapshot(), owner)))
}
