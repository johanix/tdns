/*
 * Transport signal synthesis (SVCB / TSYNC)
 */
package tdns

import (
	"fmt"
	"net"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// matchesConfiguredAddrs returns true if any RR in rrset matches a configured address.
// Note that the hostports are expected to be in the format "address:port".
func matchesConfiguredAddrs(hostports []string, rrset *core.RRset) bool {
	if rrset == nil {
		return false
	}
	for _, rr := range rrset.RRs {
		var ip string
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A.String()
		case *dns.AAAA:
			ip = r.AAAA.String()
		}
		for _, hp := range hostports {
			// (b) wildcard checks: if hp is "0.0.0.0" or "0.0.0.0:port" or "[::]" or "[::]:port", always match
			if hp == "0.0.0.0" || hp == "[::]" {
				return true
			}
			if strings.HasPrefix(hp, "0.0.0.0:") || strings.HasPrefix(hp, "[::]:") {
				return true
			}

			// (a) relax: accept host or host:port in hp
			addr, _, err := net.SplitHostPort(hp)
			if err != nil {
				// Not host:port, match against whole hp
				if ip == hp {
					return true
				}
			} else {
				if ip == addr {
					return true
				}
			}
		}
	}
	return false
}

// CreateTransportSignalRRs orchestrates construction of a transport signal RRset
// for this zone. It delegates to the chosen mechanism (svcb|tsync). In-bailiwick
// signals are synthesized, SIGNED, and stored as real "_dns.<ns>" owner RRsets
// (the resigner keeps their signatures fresh); they are served on direct query
// and injected opportunistically at query time. The only materialized state is
// the per-snapshot signalSynth fallback for an out-of-bailiwick identity NS whose
// own zone this server does not host (Case A).
func (zd *ZoneData) CreateTransportSignalRRs(conf *Config) error {
	// Resolve DNSSEC keys BEFORE taking zd.mu: signing the transport signal with
	// a nil dak can reach PublishDnskeyRRs, which locks zd.mu, so signing under
	// the lock with an unresolved dak self-deadlocks during key bootstrap.
	var dak *DnssecKeys
	if zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] {
		var err error
		if dak, err = zd.EnsureActiveDnssecKeys(zd.KeyDB, false); err != nil {
			return err
		}
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()

	switch conf.Service.Transport.Type {
	case "none", "":
		lgDns.Debug("CreateTransportSignalRRs: service.transport.type=none; skipping transport signal synthesis for zone",
			"zone", zd.ZoneName)
		return nil
	case "svcb":
		return zd.createTransportSignalSVCB(conf, dak)
	case "tsync":
		return zd.createTransportSignalTSYNC(conf, dak)
	default:
		lgDns.Debug("CreateTransportSignalRRs: unknown transport type, skipping",
			"type", conf.Service.Transport.Type,
			"zone", zd.ZoneName)
		return nil
	}
}

// commitTransportSignalLocked stages a signal owner RRset and/or records a
// synthesized fallback, then publishes.
//
//	storedOwner: "_dns.<ns>" owner to stage `stored` under ("" stages nothing)
//	stored:      the already-signed SVCB/TSYNC RRset for storedOwner
//	synthName:   "_dns.<ns>" name for a synthesized fallback signal ("" = none)
//	synth:       the synthesized (unsigned) RRset for synthName (Case A only)
func (zd *ZoneData) commitTransportSignalLocked(storedOwner string, stored core.RRset, synthName string, synth *core.RRset) {
	if storedOwner != "" && len(stored.RRs) > 0 {
		zd.stageRRsetLocked(storedOwner, stored)
	}
	if synthName != "" && synth != nil {
		if zd.wsSignalSynth == nil {
			zd.wsSignalSynth = map[string]*core.RRset{}
		}
		zd.wsSignalSynth[synthName] = synth
	}
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
}

// svcbHasAlias reports whether the RRset contains an AliasMode SVCB (non-terminal
// Target) — i.e. an operator-authored bridge rather than a synthesized server SVCB.
func svcbHasAlias(rrset core.RRset) bool {
	for _, rr := range rrset.RRs {
		if svcb, ok := rr.(*dns.SVCB); ok {
			if svcb.Target != "." && svcb.Target != "" {
				return true
			}
		}
	}
	return false
}

// tsyncHasAlias reports whether the RRset contains an aliased TSYNC — an
// operator-authored bridge to another nameserver's signal.
func tsyncHasAlias(rrset core.RRset) bool {
	for _, rr := range rrset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if ts, ok2 := prr.Data.(*core.TSYNC); ok2 && ts != nil && ts.Alias != "" && ts.Alias != "." {
				return true
			}
		}
	}
	return false
}

// buildServerSVCB constructs a synthesized ServiceMode "_dns.<ns> SVCB" RRset
// carrying the registered oots SvcParam (draft-johani-dnsop-svcb-oots / -03).
// Address hints and the private tlsa SvcParam are not included on the OOTS
// record (-03 does not use them).
func (zd *ZoneData) buildServerSVCB(conf *Config, nsName string, ipv4s, ipv6s []net.IP) (*core.RRset, error) {
	_ = ipv4s
	_ = ipv6s
	if Globals.ServerSVCB == nil {
		return nil, fmt.Errorf("buildServerSVCB: no server SVCB configured")
	}
	// -03 OOTS record carries only the oots SvcParam (no inherited alpn/hints/tlsa).
	values := make([]dns.SVCBKeyValue, 0, 1)
	if sig := conf.Service.Transport.Signal; sig != "" {
		oots, err := transportSignalToSVCBOots(sig)
		if err != nil {
			return nil, fmt.Errorf("buildServerSVCB: %w", err)
		}
		if oots != nil {
			values = append(values, oots)
		}
	}

	owner := "_dns." + nsName
	svcb := &dns.SVCB{
		Hdr:      dns.RR_Header{Name: owner, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 10800},
		Priority: 1,
		Target:   ".",
		Value:    values,
	}
	return &core.RRset{Name: owner, RRtype: dns.TypeSVCB, RRs: []dns.RR{svcb}}, nil
}

// transportSignalToSVCBOots builds a dns.SVCBOots from a config signal string.
// Zero-weight entries other than do53 are omitted (absence means 0); do53:0 is
// kept so "no Do53" is expressible on the wire.
func transportSignalToSVCBOots(sig string) (*dns.SVCBOots, error) {
	m, err := core.ParseTransportString(sig)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var entries []dns.SVCBOotsEntry
	for _, k := range keys {
		v := m[k]
		if v == 0 && k != "do53" {
			continue
		}
		entries = append(entries, dns.SVCBOotsEntry{Proto: k, Weight: v})
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return &dns.SVCBOots{Oots: entries}, nil
}

// SVCB path. See CreateTransportSignalRRs for the storage/injection model.
func (zd *ZoneData) createTransportSignalSVCB(conf *Config, dak *DnssecKeys) error {
	apex := zd.stagedOwner(zd.ZoneName)
	if apex == nil {
		return fmt.Errorf("zone apex not found")
	}
	nsRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
	if len(nsRRset.RRs) == 0 {
		return fmt.Errorf("no NS records found at zone apex")
	}

	for _, rr := range nsRRset.RRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		nsName := ns.Ns
		ownerName := "_dns." + nsName

		if !dns.IsSubDomain(zd.ZoneName, nsName) {
			// Out-of-bailiwick nameserver. Only advertise a signal for one of
			// THIS server's own identities (Case A). If we also host the
			// nameserver's own zone, its authoritative _dns.<ns> signal is
			// injected directly at query time via FindZone — nothing to store
			// here. Otherwise synthesize an (unsigned) fallback hint from the
			// server's SVCB config; it can never be a signed owner RRset in this
			// zone because _dns.<ns> is out of bailiwick.
			if !CaseFoldContains(conf.Service.Identities, nsName) || Globals.ServerSVCB == nil {
				continue
			}
			if tz, _ := FindZone(ownerName); tz != nil {
				lgDns.Debug("createTransportSignalSVCB: identity NS zone is co-hosted; will inject its authoritative signal",
					"zone", zd.ZoneName, "ns", nsName)
				return nil
			}
			synth, err := zd.buildServerSVCB(conf, nsName, nil, nil)
			if err != nil {
				return err
			}
			lgDns.Debug("createTransportSignalSVCB: synthesized fallback signal for out-of-bailiwick identity NS",
				"zone", zd.ZoneName, "ns", nsName, "owner", ownerName)
			zd.commitTransportSignalLocked("", core.RRset{}, ownerName, synth)
			return nil
		}

		// In-bailiwick nameserver.
		nsData := zd.stagedOwner(nsName)
		if nsData == nil {
			continue
		}
		// An operator-authored AliasMode SVCB at _dns.<ns> is a bridge to another
		// nameserver's signal — leave it untouched; it is served on direct query
		// and its target is chased at injection time.
		if ownerData := zd.stagedOwner(ownerName); ownerData != nil {
			if svcbHasAlias(ownerData.RRtypes.GetOnlyRRSet(dns.TypeSVCB)) {
				lgDns.Debug("createTransportSignalSVCB: keeping operator SVCB alias", "owner", ownerName, "zone", zd.ZoneName)
				return nil
			}
		}

		aRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeA)
		aaaaRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeAAAA)
		if !matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aRRset) && !matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aaaaRRset) {
			lgDns.Debug("createTransportSignalSVCB: NS addresses do not match configured; skipping",
				"zone", zd.ZoneName, "ns", nsName)
			continue
		}
		var ipv4s, ipv6s []net.IP
		for _, rr := range aRRset.RRs {
			if a, ok := rr.(*dns.A); ok {
				ipv4s = append(ipv4s, a.A)
			}
		}
		for _, rr := range aaaaRRset.RRs {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				ipv6s = append(ipv6s, aaaa.AAAA)
			}
		}
		stored, err := zd.buildServerSVCB(conf, nsName, ipv4s, ipv6s)
		if err != nil {
			return err
		}
		// Sign BEFORE staging so the snapshot freezes a signed signal; the
		// resigner keeps its signature fresh thereafter. Store as a real
		// _dns.<ns> owner RRset (replacing any prior synthesized server SVCB),
		// so it is directly queryable and injected from the stored copy.
		if _, err := zd.SignRRset(stored, "", dak, false, nil); err != nil {
			lgDns.Error("createTransportSignalSVCB: error signing SVCB; not staging unsigned signal",
				"owner", ownerName, "err", err)
			return fmt.Errorf("createTransportSignalSVCB: failed to sign SVCB for %q: %w", ownerName, err)
		}
		lgDns.Debug("createTransportSignalSVCB: stored synthesized server SVCB",
			"zone", zd.ZoneName, "ns", nsName, "owner", ownerName)
		zd.commitTransportSignalLocked(ownerName, *stored, "", nil)
		return nil
	}
	return nil
}

// TSYNC path. See CreateTransportSignalRRs for the storage/injection model.
func (zd *ZoneData) createTransportSignalTSYNC(conf *Config, dak *DnssecKeys) error {
	apex := zd.stagedOwner(zd.ZoneName)
	if apex == nil {
		return fmt.Errorf("zone apex not found")
	}
	nsRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
	if len(nsRRset.RRs) == 0 {
		return fmt.Errorf("no NS records found at zone apex")
	}

	// TSYNC is only synthesized for in-bailiwick nameservers.
	for _, rr := range nsRRset.RRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		nsName := ns.Ns
		ownerName := "_dns." + nsName
		if !dns.IsSubDomain(zd.ZoneName, nsName) {
			continue
		}
		nsData := zd.stagedOwner(nsName)
		if nsData == nil {
			continue
		}
		// Operator-authored aliased TSYNC at _dns.<ns>: leave it; served on
		// direct query and its target is chased at injection time.
		if ownerData := zd.stagedOwner(ownerName); ownerData != nil {
			if tsyncHasAlias(ownerData.RRtypes.GetOnlyRRSet(core.TypeTSYNC)) {
				lgDns.Debug("createTransportSignalTSYNC: keeping operator TSYNC alias", "owner", ownerName, "zone", zd.ZoneName)
				return nil
			}
		}

		aRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeA)
		aaaaRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeAAAA)
		if !(matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aRRset) || matchesConfiguredAddrs(conf.DnsEngine.Addresses, &aaaaRRset)) {
			continue
		}
		var ipv4s, ipv6s []string
		for _, rr := range aRRset.RRs {
			if a, ok := rr.(*dns.A); ok {
				ipv4s = append(ipv4s, a.A.String())
			}
		}
		for _, rr := range aaaaRRset.RRs {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				ipv6s = append(ipv6s, aaaa.AAAA.String())
			}
		}
		tsyncStr := fmt.Sprintf("_dns.%s 10800 IN TSYNC . %q %q %q",
			nsName,
			fmt.Sprintf("transport=%s", conf.Service.Transport.Signal),
			fmt.Sprintf("v4=%s", strings.Join(ipv4s, ",")),
			fmt.Sprintf("v6=%s", strings.Join(ipv6s, ",")),
		)
		trr, err := dns.NewRR(tsyncStr)
		if err != nil {
			lgDns.Error("createTransportSignalTSYNC: failed to build TSYNC", "err", err)
			continue
		}
		stored := core.RRset{Name: ownerName, RRtype: core.TypeTSYNC, RRs: []dns.RR{trr}}
		// Sign BEFORE staging (fixes the prior sign-after-commit ordering that
		// froze an unsigned TSYNC into the snapshot).
		if _, err := zd.SignRRset(&stored, "", dak, false, nil); err != nil {
			lgDns.Error("createTransportSignalTSYNC: error signing TSYNC; not staging unsigned signal",
				"owner", ownerName, "err", err)
			return fmt.Errorf("createTransportSignalTSYNC: failed to sign TSYNC for %q: %w", ownerName, err)
		}
		lgDns.Debug("createTransportSignalTSYNC: stored synthesized TSYNC",
			"zone", zd.ZoneName, "ns", nsName, "owner", ownerName, "rr", trr.String())
		zd.commitTransportSignalLocked(ownerName, stored, "", nil)
		return nil
	}
	return nil
}
