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
	// Bare: no working set before this pass, so the one seeded below holds
	// nothing but what the pass stages, and its publish can stay serial-less.
	// A working set that already exists carries another writer's change,
	// which the gate has not published yet (see commitTransportSignalLocked).
	bare := zd.workingSet == nil
	zd.ensureWorkingSet()

	switch conf.Service.Transport.Type {
	case "none", "":
		lgDns.Debug("CreateTransportSignalRRs: service.transport.type=none; skipping transport signal synthesis for zone",
			"zone", zd.ZoneName)
		return nil
	case "svcb":
		return zd.createTransportSignalSVCB(conf, dak, bare)
	case "tsync":
		return zd.createTransportSignalTSYNC(conf, dak, bare)
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
//	bare:        the working set was seeded by this pass (CreateTransportSignalRRs)
//	storedOwner: "_dns.<ns>" owner to stage `stored` under ("" stages nothing)
//	stored:      the already-signed SVCB/TSYNC RRset for storedOwner
//	synthName:   "_dns.<ns>" name for a synthesized fallback signal ("" = none)
//	synth:       the synthesized (unsigned) RRset for synthName (Case A only)
//
// The signal is derived state, recomputed at every start, so its publish is
// serial-less: bumping for it would make every restart a new serial, a NOTIFY
// round and a transfer for content that is not zone data. That holds only
// when the working set is bare. One that already existed carries another
// writer's change the gate has not published (docs/2026-09-17-publish-gate-
// and-transactions.md, Amendment 5), and a serial-less publish would install
// that change at the served serial -- refused by the journal and dropped, or
// installed where no secondary transfers it. Then the signal is staged like
// any other change and asks the gate: it rides with the carrying publish, at
// that publish's serial.
func (zd *ZoneData) commitTransportSignalLocked(bare bool, storedOwner string, stored core.RRset, synthName string, synth *core.RRset) {
	if storedOwner != "" && len(stored.RRs) > 0 {
		zd.stageRRsetLocked(storedOwner, stored)
	}
	var m map[string]*core.RRset
	if synthName != "" && synth != nil {
		m = map[string]*core.RRset{synthName: synth}
	}
	zd.publishTransportSignalLocked(bare, m)
}

// publishTransportSignalLocked records the synthesized fallbacks for the next
// snapshot and publishes what the pass staged: serial-less on a bare working
// set, through the gate otherwise (see commitTransportSignalLocked).
func (zd *ZoneData) publishTransportSignalLocked(bare bool, synth map[string]*core.RRset) {
	for name, s := range synth {
		if zd.wsSignalSynth == nil {
			zd.wsSignalSynth = map[string]*core.RRset{}
		}
		zd.wsSignalSynth[name] = s
	}
	if !bare {
		zd.publishOrQueueLocked(zd.generation.Load(), false)
		return
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

// SVCB path. See CreateTransportSignalRRs for the storage/injection model and
// docs/2026-10-04-transport-signal-publication-and-serving.md for the rules:
// the server speaks only about itself, zone content is signed by whoever signs
// the zone, every NS name is visited, and nothing is ever looked up
// recursively.
func (zd *ZoneData) createTransportSignalSVCB(conf *Config, dak *DnssecKeys, bare bool) error {
	apex := zd.stagedOwner(zd.ZoneName)
	if apex == nil {
		return fmt.Errorf("zone apex not found")
	}
	nsRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
	if len(nsRRset.RRs) == 0 {
		return fmt.Errorf("no NS records found at zone apex")
	}

	// Where nothing may be stored: a secondary that may not originate content
	// (docs/2026-07-25-secondary-zones-immutable.md: it serves what it received,
	// unmodified), and a zone that is signed but not by this server (an
	// unsigned owner under a signed apex is bogus to a validator, and the
	// signer's chain denies the name; dak == nil says only that THIS server
	// does not sign, the apex says whether someone does). Such a server keeps
	// its signal as an unsigned fallback beside the snapshot, injected only.
	storeForbidden := !zoneMayOriginateContent(zd) || (dak == nil && apexIsSigned(apex))

	staged, aliases := 0, 0
	synth := map[string]*core.RRset{}
	for _, rr := range nsRRset.RRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		nsName := ns.Ns
		ownerName := "_dns." + nsName

		if !dns.IsSubDomain(zd.ZoneName, nsName) {
			// Out of bailiwick: the signal's home is the name's own zone.
			// Only one of this server's identities is spoken for (Case A).
			// Co-hosted, that zone's authoritative signal is injected at
			// query time; otherwise an unsigned fallback is kept beside the
			// snapshot, never as content of this zone.
			if !CaseFoldContains(conf.Service.Identities, nsName) || Globals.ServerSVCB == nil {
				continue
			}
			if tz := FindZone(ownerName); tz != nil {
				lgDns.Debug("createTransportSignalSVCB: identity NS zone is co-hosted; will inject its authoritative signal",
					"zone", zd.ZoneName, "ns", nsName)
				continue
			}
			s, err := zd.buildServerSVCB(conf, nsName, nil, nil)
			if err != nil {
				return err
			}
			lgDns.Debug("createTransportSignalSVCB: synthesized fallback signal for out-of-bailiwick identity NS",
				"zone", zd.ZoneName, "ns", nsName, "owner", ownerName)
			synth[ownerName] = s
			continue
		}

		// In bailiwick.
		nsData := zd.stagedOwner(nsName)
		if nsData == nil {
			continue
		}
		// An operator-authored AliasMode SVCB at _dns.<ns> is the operator's
		// statement: left as it is, served on direct query, chased literally
		// at injection time (RFC 9460 section 3). A target that is one of
		// this server's identities whose zone is not hosted here gets the
		// fallback an out-of-bailiwick NS name gets. The walk goes on: an
		// alias at one name says nothing about the server's other names.
		if od := zd.stagedOwner(ownerName); od != nil {
			if rs := od.RRtypes.GetOnlyRRSet(dns.TypeSVCB); svcbHasAlias(rs) {
				lgDns.Debug("createTransportSignalSVCB: keeping operator SVCB alias", "owner", ownerName, "zone", zd.ZoneName)
				aliases++
				for _, tgt := range signalChaseTargets(rs) {
					id := strings.TrimPrefix(tgt, "_dns.")
					if !CaseFoldContains(conf.Service.Identities, id) || Globals.ServerSVCB == nil || FindZone(tgt) != nil {
						continue
					}
					s, err := zd.buildServerSVCB(conf, id, nil, nil)
					if err != nil {
						return err
					}
					synth[tgt] = s
				}
				continue
			}
		}

		aRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeA)
		aaaaRRset := nsData.RRtypes.GetOnlyRRSet(dns.TypeAAAA)
		if !matchesConfiguredAddrs(conf.Listeners.Addresses, &aRRset) && !matchesConfiguredAddrs(conf.Listeners.Addresses, &aaaaRRset) {
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
		switch {
		case storeForbidden:
			lgDns.Info("createTransportSignalSVCB: this server stores no signal into this zone (a secondary that may not originate content, or a zone signed by someone else); the signal is kept as an unsigned fallback beside the snapshot, injected only",
				"zone", zd.ZoneName, "owner", ownerName)
			synth[ownerName] = stored
			continue
		case dak != nil:
			// Sign BEFORE staging so the snapshot freezes a signed signal; the
			// resigner keeps its signature fresh thereafter. dak is resolved by
			// CreateTransportSignalRRs, outside zd.mu, and for a zone this
			// server signs it is never nil here (EnsureActiveDnssecKeys returns
			// keys or an error), which is what keeps a nil dak out of
			// SignRRset under zd.mu (the PublishDnskeyRRs re-lock).
			if _, err := zd.SignRRset(stored, "", dak, false, nil); err != nil {
				lgDns.Error("createTransportSignalSVCB: error signing SVCB; not staging unsigned signal",
					"owner", ownerName, "err", err)
				return fmt.Errorf("createTransportSignalSVCB: failed to sign SVCB for %q: %w", ownerName, err)
			}
		}
		lgDns.Debug("createTransportSignalSVCB: stored synthesized server SVCB",
			"zone", zd.ZoneName, "ns", nsName, "owner", ownerName)
		zd.stageRRsetLocked(ownerName, *stored)
		staged++
	}
	if staged == 0 && len(synth) == 0 {
		if aliases == 0 {
			lgDns.Warn("createTransportSignalSVCB: add-transport-signal is set, but no NS name of the zone resolves to this server's listeners and none is one of its identities; nothing to publish (a hidden primary should not carry the option)",
				"zone", zd.ZoneName)
		}
		return nil
	}
	zd.publishTransportSignalLocked(bare, synth)
	return nil
}

// addsTransportSignal reports whether this zone publishes and injects transport
// signals. Today that is the zone's own option; a server-wide default would
// be resolved here, at the point of use, not into zd.Options (the option
// finalization sites are many, and the option is persisted with dynamic
// zones). Every reader of the option goes through this.
func (zd *ZoneData) addsTransportSignal() bool {
	return zd.Options[OptAddTransportSignal]
}

// apexIsSigned reports whether the zone is signed by anyone: it serves a
// DNSKEY RRset, or its SOA carries a signature.
func apexIsSigned(apex *OwnerData) bool {
	if apex == nil {
		return false
	}
	if rs, ok := apex.RRtypes.Get(dns.TypeDNSKEY); ok && len(rs.RRs) > 0 {
		return true
	}
	return len(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRSIGs) > 0
}

// svcbMixesModes reports an SVCB RRset holding both an AliasMode record
// (SvcPriority 0) and ServiceMode records. RFC 9460 section 2.4.1: all RRs of
// an RRset should have the same mode, and a recipient MUST ignore the
// ServiceMode records beside an AliasMode one. tdns refuses such a set rather
// than serve records a client discards.
func svcbMixesModes(rs core.RRset) bool {
	alias, service := false, false
	for _, rr := range rs.RRs {
		if svcb, ok := rr.(*dns.SVCB); ok {
			if svcb.Priority == 0 {
				alias = true
			} else {
				service = true
			}
		}
	}
	return alias && service
}

// refuseMixedSvcbUpdateLocked applies an update's SVCB actions to a copy of
// each owner's staged SVCB RRset, in order and with the applier's own rules
// (RFC 2136: class ANY deletes the RRset, class NONE one record, class IN
// adds one; owners by canonical name; a record matches regardless of TTL, as
// the applier's IsDuplicate does), and refuses the update if any owner would
// end up mixing AliasMode and ServiceMode records. Nothing is staged by this;
// the caller holds zd.mu.
func (zd *ZoneData) refuseMixedSvcbUpdateLocked(actions []dns.RR) error {
	sets := map[string][]dns.RR{}
	load := func(owner string) []dns.RR {
		if rrs, ok := sets[owner]; ok {
			return rrs
		}
		var rrs []dns.RR
		if od := zd.stagedOwner(owner); od != nil {
			rrs = append(rrs, od.RRtypes.GetOnlyRRSet(dns.TypeSVCB).RRs...)
		}
		sets[owner] = rrs
		return rrs
	}
	for _, rr := range actions {
		h := rr.Header()
		owner := core.CanonicalizeName(h.Name)
		switch {
		case h.Class == dns.ClassANY && (h.Rrtype == dns.TypeANY || h.Rrtype == dns.TypeSVCB):
			sets[owner] = nil
		case h.Rrtype != dns.TypeSVCB:
			continue
		case h.Class == dns.ClassNONE:
			// As the applier compares: the record brought to class IN, the
			// TTL ignored by IsDuplicate.
			want := dns.Copy(rr)
			want.Header().Class = dns.ClassINET
			kept := load(owner)[:0:0]
			for _, have := range load(owner) {
				if !dns.IsDuplicate(have, want) {
					kept = append(kept, have)
				}
			}
			sets[owner] = kept
		case h.Class == dns.ClassINET:
			sets[owner] = append(load(owner), rr)
		}
	}
	for owner, rrs := range sets {
		if svcbMixesModes(core.RRset{Name: owner, RRtype: dns.TypeSVCB, RRs: rrs}) {
			return fmt.Errorf("zone %s: update refused: %s would hold an SVCB RRset mixing AliasMode and ServiceMode records, which a client ignores (RFC 9460 section 2.4.1)", zd.ZoneName, owner)
		}
	}
	return nil
}

// TSYNC path. See CreateTransportSignalRRs for the storage/injection model.
func (zd *ZoneData) createTransportSignalTSYNC(conf *Config, dak *DnssecKeys, bare bool) error {
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
		if !(matchesConfiguredAddrs(conf.Listeners.Addresses, &aRRset) || matchesConfiguredAddrs(conf.Listeners.Addresses, &aaaaRRset)) {
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
		// froze an unsigned TSYNC into the snapshot). Gate on dak, not the static
		// signing options: CreateTransportSignalRRs resolves dak via
		// EnsureActiveDnssecKeys, which for a signing zone returns non-nil keys or
		// an error — never (nil, nil) — so a transiently-keyless signing zone
		// (bootstrap / policy-reset) errors out upstream and never reaches here
		// with a nil dak; dak == nil is exactly "the zone doesn't sign." Gating on
		// dak also keeps nil out of SignRRset, which under zd.mu self-deadlocks
		// via PublishDnskeyRRs. An unsigned zone gets an unsigned signal, not a
		// hard failure. (Revisit if EnsureActiveDnssecKeys ever returns a nil dak
		// for a signing zone.)
		if dak != nil {
			if _, err := zd.SignRRset(&stored, "", dak, false, nil); err != nil {
				lgDns.Error("createTransportSignalTSYNC: error signing TSYNC; not staging unsigned signal",
					"owner", ownerName, "err", err)
				return fmt.Errorf("createTransportSignalTSYNC: failed to sign TSYNC for %q: %w", ownerName, err)
			}
		}
		lgDns.Debug("createTransportSignalTSYNC: stored synthesized TSYNC",
			"zone", zd.ZoneName, "ns", nsName, "owner", ownerName, "rr", trr.String())
		zd.commitTransportSignalLocked(bare, ownerName, stored, "", nil)
		return nil
	}
	return nil
}
