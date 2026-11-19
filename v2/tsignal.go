/*
 * Transport signal synthesis (SVCB / TSYNC)
 */
package tdns

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// matchesConfiguredAddrs reports whether any A or AAAA in rrset is an address
// this server listens on. hostports are listener addresses, "host:port" or a
// bare host.
//
// A listener address names itself. A wildcard listener ("0.0.0.0" or "[::]",
// with or without a port) names every address of THIS HOST, not every address
// there is. It used to match anything, so a server listening on a wildcard
// took every in-bailiwick NS name as its own and, in a zone it shares with
// another provider, published its own transports under the other provider's
// nameserver. The server-wide add-transport-signal made that every zone. The
// host's addresses are its interface addresses (localAddrs).
func matchesConfiguredAddrs(hostports []string, rrset *core.RRset) bool {
	if rrset == nil {
		return false
	}
	var wildcard bool
	var listeners []string
	for _, hp := range hostports {
		host := hp
		if h, _, err := net.SplitHostPort(hp); err == nil {
			host = h
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			wildcard = true
			continue
		}
		listeners = append(listeners, host)
	}
	for _, rr := range rrset.RRs {
		var ip net.IP
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A
		case *dns.AAAA:
			ip = r.AAAA
		default:
			continue
		}
		for _, l := range listeners {
			if lip := net.ParseIP(l); (lip != nil && lip.Equal(ip)) || l == ip.String() {
				return true
			}
		}
		if wildcard {
			for _, local := range localAddrs() {
				if local.Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}

// interfaceAddrs is where localAddrs reads the host's addresses; tests replace it.
var interfaceAddrs = net.InterfaceAddrs

// localAddrsMaxAge is how long localAddrs trusts what it last read.
const localAddrsMaxAge = time.Minute

type localAddrSnapshot struct {
	ips []net.IP
	at  time.Time
}

var localAddrSnap atomic.Pointer[localAddrSnapshot]

// localAddrs returns this host's interface addresses: what a wildcard listener
// listens on. They are read from the system at most once a minute, because the
// responder's injection asks per response. A failed read keeps the last good
// answer; with none, the host has no known address and a wildcard matches
// nothing, which is the safe side: no signal rather than a wrong one.
func localAddrs() []net.IP {
	if s := localAddrSnap.Load(); s != nil && time.Since(s.at) < localAddrsMaxAge {
		return s.ips
	}
	addrs, err := interfaceAddrs()
	if err != nil {
		lgDns.Warn("transport signal: cannot read this host's interface addresses; a wildcard listener matches the last known ones", "err", err)
		if s := localAddrSnap.Load(); s != nil {
			return s.ips
		}
		return nil
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ips = append(ips, v.IP)
		case *net.IPAddr:
			ips = append(ips, v.IP)
		}
	}
	localAddrSnap.Store(&localAddrSnapshot{ips: ips, at: time.Now()})
	return ips
}

// CreateTransportSignalRRs orchestrates construction of a transport signal RRset
// for this zone. It delegates to the chosen mechanism (svcb|tsync). An SVCB
// signal is synthesized only at _dns.<identity> in the identity's home zone,
// SIGNED where this server signs, and stored as a real owner RRset (the
// resigner keeps its signature fresh); it is served on direct query and
// injected at query time like any signal provisioned in a zone. See
// createTransportSignalSVCB for the rules.
func (zd *ZoneData) CreateTransportSignalRRs(conf *Config) error {
	// Resolve DNSSEC keys BEFORE taking zd.mu: signing the transport signal with
	// a nil dak can reach PublishDnskeyRRs, which locks zd.mu, so signing under
	// the lock with an unresolved dak self-deadlocks during key bootstrap.
	var dak *DnssecKeys
	if zd.Option(OptOnlineSigning) || zd.Option(OptInlineSigning) {
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
		// Nothing is synthesized. What the pass stored under a type that
		// did synthesize is withdrawn, as for a name no longer an identity:
		// left in place, rule 1 would serve it as provisioned, and a refresh
		// would carry it.
		lgDns.Debug("CreateTransportSignalRRs: service.transport.type=none; skipping transport signal synthesis for zone",
			"zone", zd.ZoneName)
		if apex := zd.stagedOwner(zd.ZoneName); apex != nil && zd.signalMayWrite(apex, dak) {
			if withdrawn, unpublished := zd.withdrawStaleSignalsLocked(nil); withdrawn+unpublished > 0 {
				zd.publishTransportSignalLocked(bare, nil)
			}
		}
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

// svcbHasAlias reports whether the RRset contains an AliasMode SVCB
// (SvcPriority 0, RFC 9460 section 2.4.2): an operator's bridge to another
// name's signal. The mode is the priority, not the target: a ServiceMode
// record with a TargetName names an endpoint host, not a signal to chase.
func svcbHasAlias(rrset core.RRset) bool {
	for _, rr := range rrset.RRs {
		if svcb, ok := rr.(*dns.SVCB); ok && svcb.Priority == 0 {
			return true
		}
	}
	return false
}

// svcbSignalWarnings checks an SVCB RRset as an operator wrote it and
// returns what the zone loader should warn about (it refuses nothing):
//   - an oots weight above 100: resolvers read it as 100 (design 2026-11-14
//     section 8; the codec keeps the octet as written);
//   - a transport named in two ServiceMode records of the set: one endpoint
//     per transport, so a resolver uses it from one record only (the lowest
//     SvcPriority, then the lowest RDATA) and ignores it in the others
//     (design 2026-11-14 section 2).
//
// AliasMode records carry no signal and are not counted.
func svcbSignalWarnings(rs core.RRset) []string {
	var warns []string
	named := map[string]int{}
	var order []string
	for _, rr := range rs.RRs {
		svcb, ok := rr.(*dns.SVCB)
		if !ok || svcb.Priority == 0 {
			continue
		}
		inRecord := map[string]bool{}
		for _, kv := range svcb.Value {
			oots, ok := kv.(*dns.SVCBOots)
			if !ok {
				continue
			}
			for _, e := range oots.Oots {
				proto := strings.ToLower(e.Proto)
				if e.Weight > 100 {
					warns = append(warns, fmt.Sprintf("oots weight %d for %q is above 100; resolvers read it as 100", e.Weight, proto))
				}
				if inRecord[proto] {
					continue
				}
				inRecord[proto] = true
				if named[proto] == 0 {
					order = append(order, proto)
				}
				named[proto]++
			}
		}
	}
	for _, proto := range order {
		if n := named[proto]; n > 1 {
			warns = append(warns, fmt.Sprintf("transport %q is named in %d records of the RRset; a resolver uses it from one record only (the lowest SvcPriority, then the lowest RDATA) and ignores it in the others", proto, n))
		}
	}
	return warns
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
// carrying the registered oots SvcParam (draft-johani-dnsop-svcb-oots / -03)
// and, on the record of a transport the operator gave a port, the standard
// SVCB port key. Address hints and the private tlsa SvcParam are not
// included. transportSignalLayout decides the records (signalRRsetFor).
// Publishing a port does not open the listen socket.
func (zd *ZoneData) buildServerSVCB(conf *Config, nsName string, ipv4s, ipv6s []net.IP) (*core.RRset, error) {
	_ = ipv4s
	_ = ipv6s
	if Globals.ServerSVCB == nil {
		return nil, fmt.Errorf("buildServerSVCB: no server SVCB configured")
	}
	rs, err := signalRRsetFor(conf.Service.Transport, nsName)
	if err != nil {
		return nil, fmt.Errorf("buildServerSVCB: %w", err)
	}
	return rs, nil
}

// signalRRsetFor is the SVCB RRset at _dns.<name> that service.transport
// gives: what the start-up pass writes, and what tdns-cli's "config
// transport-signal" prints for an operator to provision instead.
func signalRRsetFor(t TransportConf, nsName string) (*core.RRset, error) {
	recs, err := transportSignalLayout(t)
	if err != nil {
		return nil, err
	}
	owner := "_dns." + nsName
	rrs := make([]dns.RR, 0, len(recs))
	for _, rec := range recs {
		rrs = append(rrs, &dns.SVCB{
			Hdr:      dns.RR_Header{Name: owner, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 10800},
			Priority: 1,
			Target:   rec.targetName(),
			Value:    svcbValuesForSignal(rec.weights, rec.port),
		})
	}
	return &core.RRset{Name: owner, RRtype: dns.TypeSVCB, RRs: rrs}, nil
}

// signalRecord is one SVCB of the published signal: the weights it states,
// its port key (0 for none) and its TargetName ("" for the nameserver
// itself, ".").
type signalRecord struct {
	weights map[string]uint8
	port    uint16
	target  string
}

// targetName is the record's TargetName on the wire.
func (r signalRecord) targetName() string {
	if r.target == "" {
		return "."
	}
	return r.target
}

// publishedSignalTarget is the TargetName published for transport t: the
// configured name, fully qualified, or "" when there is none or it is "."
// (the nameserver itself).
func publishedSignalTarget(targets map[string]string, t string) string {
	v := strings.TrimSpace(targets[t])
	if v == "" || v == "." {
		return ""
	}
	return dns.Fqdn(v)
}

// svcbHasTarget reports whether an SVCB RRset has a ServiceMode record whose
// TargetName is not the owner's own nameserver ("."): an alternative host.
func svcbHasTarget(rs *core.RRset) bool {
	if rs == nil {
		return false
	}
	for _, rr := range rs.RRs {
		if svcb, ok := rr.(*dns.SVCB); ok && svcb.Priority != 0 && svcb.Target != "." && svcb.Target != "" {
			return true
		}
	}
	return false
}

// signalStandardPorts is the standard port of each transport that can take a
// port in service.transport.ports. A configured port equal to it counts as
// absent. udp and tcp are cleartext DNS on port 53; do53 is not a key, since
// it is the shorthand for the two on their default port.
var signalStandardPorts = map[string]uint16{"udp": 53, "tcp": 53, "dot": 853, "doq": 853, "doh": 443}

// signalPortOrder is the order the records with a port go out in, after the
// record without one. RRset order means nothing on the wire; a fixed order
// keeps zone diffs and tests stable.
var signalPortOrder = []string{"udp", "tcp", "dot", "doq", "doh"}

// cleartextSignalToken reports whether tok is udp or tcp. Absent, each weighs
// 100, so a stated 0 means something, and a port for one is never published
// for nothing: cleartext is the last resort whatever its weight, and forced
// TCP goes to the tcp endpoint whatever tcp's weight.
func cleartextSignalToken(tok string) bool {
	return tok == "udp" || tok == "tcp"
}

// publishedSignalPort is the port published for transport t: the configured
// one, or 0 when there is none or it is t's standard port.
func publishedSignalPort(ports map[string]uint16, t string) uint16 {
	p := ports[t]
	if p == signalStandardPorts[t] {
		return 0
	}
	return p
}

// transportSignalLayout lays out the published SVCB RRset from
// service.transport:
//   - No signal and no published port or target: one record with no weights
//     and no port, an empty SVCB, as before. No signal with a udp or tcp port
//     or target: the records below, each at the default 100
//     (validateTransportSignal refuses an encrypted port or target without a
//     weight).
//   - No published port or target: one record with the signal's weights as
//     published (publishedSignalWeights): do53 is emitted as udp and tcp, and
//     nothing the operator did not name is written out.
//   - Published ports or targets: one record per transport with a port or a
//     target that carries that transport alone, its target as TargetName and
//     its port beside it, in the order udp, tcp, dot, doq, doh, after one
//     record at the nameserver itself (TargetName ".") without a port that
//     carries every other transport named. That record is left out when
//     nothing is left for it. A udp or tcp with a port or a target that the
//     signal does not name is stated at its default, 100, since a record's
//     endpoint applies only to the transports it names. Every transport is in
//     at most one record, so a resolver never meets one named twice, and a
//     record's endpoint applies to every transport it names (design
//     2026-11-14 section 2).
func transportSignalLayout(t TransportConf) ([]signalRecord, error) {
	weights := map[string]uint8{}
	if t.Signal != "" {
		var err error
		if weights, err = publishedSignalWeights(t.Signal); err != nil {
			return nil, err
		}
	}
	var ported []signalRecord
	for _, tr := range signalPortOrder {
		p := publishedSignalPort(t.Ports, tr)
		tg := publishedSignalTarget(t.Targets, tr)
		if p == 0 && tg == "" {
			continue
		}
		w, named := weights[tr]
		switch {
		case cleartextSignalToken(tr) && !named:
			w = 100
		case !cleartextSignalToken(tr) && w == 0:
			continue
		}
		ported = append(ported, signalRecord{weights: map[string]uint8{tr: w}, port: p, target: tg})
		delete(weights, tr)
	}
	if t.Signal == "" && len(ported) == 0 {
		return []signalRecord{{}}, nil
	}
	if len(ported) > 0 && svcbOotsFromWeights(weights) == nil {
		return ported, nil
	}
	return append([]signalRecord{{weights: weights}}, ported...), nil
}

// svcbValuesForSignal is the SvcParams of one published record, in key order:
// port (3) then oots (12). A zero port is omitted, and so is oots when no
// weight is left to state. Hints, alpn and tlsa are not added.
func svcbValuesForSignal(weights map[string]uint8, port uint16) []dns.SVCBKeyValue {
	var values []dns.SVCBKeyValue
	if port != 0 {
		values = append(values, &dns.SVCBPort{Port: port})
	}
	if oots := svcbOotsFromWeights(weights); oots != nil {
		values = append(values, oots)
	}
	return values
}

// transportSignalToSVCBOots builds a dns.SVCBOots from a config signal string,
// as published (publishedSignalWeights, svcbOotsFromWeights).
func transportSignalToSVCBOots(sig string) (*dns.SVCBOots, error) {
	m, err := publishedSignalWeights(sig)
	if err != nil {
		return nil, err
	}
	return svcbOotsFromWeights(m), nil
}

// publishedSignalWeights is a configured signal as tdns-auth publishes it: the
// weights the operator named, with do53 emitted as udp and tcp, an explicit
// udp or tcp winning over it (core.ExpandDo53Shorthand). do53 is never
// emitted, beside udp and tcp or alone. No absence default is written out: an
// absent udp or tcp means 100, and an absent encrypted transport 0 (the
// alternative-endpoint design, sections 2 and 8). A publisher emits udp and
// tcp only where every tdns node that can re-pack the record keeps them,
// which a deployment of this version ensures (gate G1 of the plan).
func publishedSignalWeights(sig string) (map[string]uint8, error) {
	m, err := core.ParseTransportStringRaw(sig)
	if err != nil {
		return nil, err
	}
	core.ExpandDo53Shorthand(m)
	return m, nil
}

// publishedTSYNCSignal is the transport= value of a published TSYNC: the
// configured signal as written, or, when it names do53, the signal as
// publishedSignalWeights emits it, so that do53 is never published.
func publishedTSYNCSignal(sig string) string {
	raw, err := core.ParseTransportStringRaw(sig)
	if _, named := raw["do53"]; err != nil || !named {
		return sig
	}
	core.ExpandDo53Shorthand(raw)
	return MarshalTransport(raw)
}

// svcbOotsFromWeights builds a dns.SVCBOots from a weight map, entries in
// key order. A zero-weight encrypted transport is omitted (absence means 0);
// udp:0 and tcp:0 are kept, since an absent udp or tcp means 100. nil when no
// entry is left.
func svcbOotsFromWeights(m map[string]uint8) *dns.SVCBOots {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var entries []dns.SVCBOotsEntry
	for _, k := range keys {
		v := m[k]
		if v == 0 && !cleartextSignalToken(k) {
			continue
		}
		entries = append(entries, dns.SVCBOotsEntry{Proto: k, Weight: v})
	}
	if len(entries) == 0 {
		return nil
	}
	return &dns.SVCBOots{Oots: entries}
}

// SVCB path. See CreateTransportSignalRRs for the storage model. The rules
// are the maintainer's ruling on plan step S2 (2026-11-15):
//
//  1. Records provisioned in a zone, by an operator or a customer, in either
//     mode, are included by zone data alone (collectSignalRRsets). This
//     pass leaves them as they are.
//  2. Synthesis from service.transport is the only place identity applies.
//     The pass synthesizes at _dns.<name> only for a name in
//     service.identities, only in the zone that is that name's home (the
//     most specific zone hosted here that holds it), only where this server
//     is that zone's primary and signer, and only where nothing is at that
//     owner but what the pass itself stored there.
//  3. It never writes into a customer zone, whatever is or is not there.
//     Rule 2 implies this: the only owners it writes are _dns.<identity> in
//     the identity's home zone, and listing a name in service.identities
//     says that its home is this server's own zone. A customer zone whose NS
//     is one of those names gets the signal by rule 1, from the home zone.
//
// Nothing is ever looked up recursively.
func (zd *ZoneData) createTransportSignalSVCB(conf *Config, dak *DnssecKeys, bare bool) error {
	apex := zd.stagedOwner(zd.ZoneName)
	if apex == nil {
		return fmt.Errorf("zone apex not found")
	}

	// The identities whose home is this zone. One below a zone cut here is
	// the child's, a child not served here (a co-hosted child would be its
	// home): nothing is written for it, since this zone holds only glue and
	// occluded data there, which is never served.
	var homeOf []string
	for _, id := range conf.Service.Identities {
		id = core.CanonicalizeName(dns.Fqdn(strings.TrimSpace(id)))
		if id == "." || !zd.isHomeOf(id) || slices.Contains(homeOf, id) {
			continue
		}
		if zd.stagedBelowCut("_dns." + id) {
			lgDns.Warn("createTransportSignalSVCB: an identity is below a zone cut to a child not served here; no signal is synthesized for it (service.identities should name only names whose home zone is served here)",
				"zone", zd.ZoneName, "identity", id)
			continue
		}
		homeOf = append(homeOf, id)
	}

	// Primary and signer: the zone's content originates here (not a
	// secondary that serves what it received,
	// docs/2026-07-25-secondary-zones-immutable.md) and no one else signs it
	// (an unsigned owner under a signed apex is bogus to a validator; dak ==
	// nil says only that THIS server does not sign, the apex says whether
	// someone does). An unsigned zone of this server's own counts. Anywhere
	// else nothing is synthesized: a signal there is provisioned in the zone
	// and served as it is (rule 1), or there is none.
	mayWrite := zd.signalMayWrite(apex, dak)
	if len(homeOf) > 0 && !mayWrite {
		lgDns.Info("createTransportSignalSVCB: this zone is the home of identities, but this server is not its primary and signer; no signal is synthesized, and one provisioned in the zone is served as it is",
			"zone", zd.ZoneName, "identities", homeOf)
		homeOf = nil
	}

	changed, kept := 0, 0
	unsignedTarget := false // a signal with a target stored unsigned
	want := map[string]bool{}
	for _, id := range homeOf {
		owner := "_dns." + id
		want[owner] = true
		// Records at the owner that are not the pass's own are provisioned,
		// whatever their type and mode: left as they are, and the transport
		// configuration does not apply to that name. The pass's own stored
		// signal is zone content too, which is why it is told apart by the
		// record of what the pass stored there (signalStoredByPass), not by
		// its presence and not by matching what the configuration gives: an
		// operator may write exactly that, and a later configuration must
		// not replace it.
		if od := zd.stagedOwner(owner); od != nil && ownerRRsetCount(od) > 0 {
			own, err := zd.ownerHoldsOnlyPassSignal(owner, od)
			if err != nil {
				zd.warnSignalRecordUnreadable(owner, err)
				kept++
				continue
			}
			if !own {
				lgDns.Info("createTransportSignalSVCB: leaving the operator's records at the signal owner alone; the transport configuration does not apply to this name",
					"zone", zd.ZoneName, "owner", owner, "alias", svcbHasAlias(od.RRtypes.GetOnlyRRSet(dns.TypeSVCB)), "rrsets", ownerRRsetCount(od))
				kept++
				if err := zd.forgetSignalStored(owner); err != nil {
					zd.warnSignalForgetFailed(owner, err)
				}
				continue
			}
		}
		stored, err := zd.buildServerSVCB(conf, id, nil, nil)
		if err != nil {
			return err
		}
		if dak != nil {
			// Sign BEFORE staging so the snapshot freezes a signed signal; the
			// resigner keeps its signature fresh thereafter. dak is resolved by
			// CreateTransportSignalRRs, outside zd.mu, and for a zone this
			// server signs it is never nil here (EnsureActiveDnssecKeys returns
			// keys or an error), which is what keeps a nil dak out of
			// SignRRset under zd.mu (the PublishDnskeyRRs re-lock).
			if _, err := zd.SignRRset(stored, "", dak, false, nil); err != nil {
				lgDns.Error("createTransportSignalSVCB: error signing SVCB; not staging unsigned signal",
					"owner", owner, "err", err)
				return fmt.Errorf("createTransportSignalSVCB: failed to sign SVCB for %q: %w", owner, err)
			}
		}
		lgDns.Debug("createTransportSignalSVCB: stored synthesized server SVCB",
			"zone", zd.ZoneName, "identity", id, "owner", owner)
		zd.stageRRsetLocked(owner, *stored)
		zd.noteSignalStored(owner, stored.RRs)
		unsignedTarget = unsignedTarget || (dak == nil && svcbHasTarget(stored))
		changed++
	}

	if mayWrite {
		withdrawn, unpublished := zd.withdrawStaleSignalsLocked(want)
		changed += withdrawn + unpublished
	}

	if changed == 0 {
		// A warning only when the zone set the option itself and nothing
		// can come of it: then it is a stray option, say on a hidden
		// primary. Under the server-wide option such a zone is ordinary and
		// says so at debug level, or a server whose zones mostly name other
		// servers would warn once per zone.
		if kept == 0 && len(homeOf) == 0 && zd.nsNamesWithASignalHere(conf, apex) == 0 {
			if zd.transportSignalSource() == "zone" {
				lgDns.Warn("createTransportSignalSVCB: add-transport-signal is set, but no NS name of the zone has a signal in a zone served here and none is an identity of this server whose home is served here; nothing to publish (a hidden primary should not carry the option)",
					"zone", zd.ZoneName)
			} else {
				lgDns.Debug("createTransportSignalSVCB: no NS name of the zone has a signal here; nothing to publish under the server-wide add-transport-signal",
					"zone", zd.ZoneName)
			}
		}
		return nil
	}
	if unsignedTarget {
		// A resolver honours a target only after a Secure verdict for the
		// whole path (design 2026-11-14 section 4, R1), so in an unsigned
		// signal the targets are dead weight: the transports they move stay
		// on the nameserver for every resolver that follows the rule.
		lgDns.Warn("createTransportSignalSVCB: service.transport.targets names a target, but the signal in this zone is not signed; resolvers honour a target only from a validated signal, so the transports it moves are not offered there",
			"zone", zd.ZoneName)
	}
	zd.publishTransportSignalLocked(bare, nil)
	return nil
}

// signalMayWrite reports whether the signal pass may write this zone:
// primary and signer. The zone's content originates here (not a secondary
// that serves what it received, docs/2026-07-25-secondary-zones-immutable.md)
// and no one else signs it (an unsigned owner under a signed apex is bogus to
// a validator; dak == nil says only that THIS server does not sign, the apex
// says whether someone does). An unsigned zone of this server's own counts.
func (zd *ZoneData) signalMayWrite(apex *OwnerData, dak *DnssecKeys) bool {
	return zoneMayOriginateContent(zd) && (dak != nil || !apexIsSigned(apex))
}

// withdrawStaleSignalsLocked withdraws what the pass stored at an owner that
// is no longer an identity at home here (not in want): one dropped from
// service.identities, say, across a restart, or every one once
// service.transport.type is none. Left in place, rule 1 would serve it as if
// it were provisioned. Only the pass's own unchanged signal goes; an RRset
// the operator has since replaced is theirs, and only the record goes. A
// withdrawal writes the zone, so the caller runs this only where this server
// is primary and signer (signalMayWrite). A former primary that restarts as
// a secondary changes nothing and keeps its record: should the zone be its
// own again, the pass withdraws then.
//
// After a withdrawal, or with nothing at the owner, the record stays. The
// withdrawal reaches the zone file only when the zone is next written, and a
// restart before then loads the signal again; with the record kept, the pass
// knows it and withdraws it again. Only records that are not the pass's end
// the record. A revocation whose KeyDB delete failed earlier in this process
// is tried again, whatever is at the owner now.
//
// A withdrawal staged by an earlier run whose publish was refused (signing
// or the NSEC repair failed) is published again. The publisher keeps the
// working set and drops the queue flag, so the owner is gone from the
// working set while the published snapshot still serves the pass's signal
// there, and nothing else would publish it.
//
// It returns the number of owners withdrawn now, and the number whose
// earlier withdrawal is still unpublished; either calls for a publish.
// Caller holds zd.mu.
func (zd *ZoneData) withdrawStaleSignalsLocked(want map[string]bool) (withdrawn, unpublished int) {
	for _, owner := range zd.signalStoredOwners() {
		if want[owner] {
			continue
		}
		if zd.signalRevocationPending(owner) {
			if err := zd.forgetSignalStored(owner); err != nil {
				zd.warnSignalForgetFailed(owner, err)
			}
			continue
		}
		od := zd.stagedOwner(owner)
		if od == nil || ownerRRsetCount(od) == 0 {
			if po := getOwnerFrom(zd.publishedSnapshot(), owner); po != nil {
				if rs := po.RRtypes.GetOnlyRRSet(dns.TypeSVCB); len(rs.RRs) > 0 {
					own, err := zd.signalStoredByPass(owner, rs.RRs)
					if err != nil {
						zd.warnSignalRecordUnreadable(owner, err)
						continue
					}
					if own {
						lgDns.Info("transport signal pass: a withdrawal staged earlier is not published yet; publishing it again",
							"zone", zd.ZoneName, "owner", owner)
						unpublished++
					}
				}
			}
			continue
		}
		if rs := od.RRtypes.GetOnlyRRSet(dns.TypeSVCB); len(rs.RRs) > 0 {
			own, err := zd.signalStoredByPass(owner, rs.RRs)
			if err != nil {
				zd.warnSignalRecordUnreadable(owner, err)
				continue
			}
			if own {
				zd.stageDeleteLocked(owner, dns.TypeSVCB)
				if o := zd.stagedOwner(owner); o != nil && o.RRtypes.Count() == 0 {
					zd.stageOwnerDeleteLocked(owner)
				}
				lgDns.Info("transport signal pass: withdrew the signal the pass had stored for a name that is no longer an identity at home in this zone",
					"zone", zd.ZoneName, "owner", owner)
				withdrawn++
				continue
			}
		}
		if err := zd.forgetSignalStored(owner); err != nil {
			zd.warnSignalForgetFailed(owner, err)
		}
	}
	return withdrawn, unpublished
}

// stagedBelowCut reports whether name is at or below a zone cut in this
// zone's working set: an owner from name up to the apex, the apex not
// included, that holds an NS RRset.
func (zd *ZoneData) stagedBelowCut(name string) bool {
	n := core.CanonicalizeName(name)
	for dns.IsSubDomain(zd.ZoneName, n) && !core.EqualNames(n, zd.ZoneName) {
		if od := zd.stagedOwner(n); od != nil && len(od.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs) > 0 {
			return true
		}
		i, end := dns.NextLabel(n, 0)
		if end {
			break
		}
		n = n[i:]
	}
	return false
}

// ownerRRsetCount is the number of non-empty RRsets at an owner. NSEC is a
// property of the owner, not an RRset, and RRSIGs ride with their RRsets.
func ownerRRsetCount(od *OwnerData) int {
	n := 0
	for _, t := range od.RRtypes.Keys() {
		if rs, ok := od.RRtypes.Get(t); ok && len(rs.RRs) > 0 {
			n++
		}
	}
	return n
}

// ownerHoldsOnlyPassSignal reports whether the only records at owner are the
// SVCB RRset the signal pass last stored there. Other records at the owner
// answer no without the record being read; otherwise an error when it cannot
// be read (signalStoredByPass).
func (zd *ZoneData) ownerHoldsOnlyPassSignal(owner string, od *OwnerData) (bool, error) {
	rs := od.RRtypes.GetOnlyRRSet(dns.TypeSVCB)
	if ownerRRsetCount(od) != 1 || len(rs.RRs) == 0 {
		return false, nil
	}
	return zd.signalStoredByPass(owner, rs.RRs)
}

// nsNamesWithASignalHere counts the zone's NS names whose signal a response
// can carry by rule 1: one at _dns.<ns> in a zone served here, or an
// identity whose home is served here (its own pass synthesizes it there, in
// whatever order the passes run).
func (zd *ZoneData) nsNamesWithASignalHere(conf *Config, apex *OwnerData) int {
	n := 0
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := "_dns." + ns.Ns
		var od *OwnerData
		if zd.isHomeOf(owner) {
			od = zd.stagedOwner(owner)
		} else if home := FindZone(owner); home != nil {
			od = getOwnerFrom(home.publishedSnapshot(), owner)
		}
		if len(signalRRsetsFromOwner(od)) > 0 ||
			(CaseFoldContains(conf.Service.Identities, ns.Ns) && (zd.isHomeOf(ns.Ns) || FindZone(ns.Ns) != nil)) {
			n++
		}
	}
	return n
}

// addsTransportSignal reports whether this zone publishes and injects transport
// signals: the zone's own option, or the server-wide authengine option. Every
// reader of the option goes through this.
func (zd *ZoneData) addsTransportSignal() bool {
	return zd.transportSignalSource() != ""
}

// transportSignalSource says where this zone's add-transport-signal comes
// from: "zone" (the zone's own option, possibly via its template), "global"
// (authengine.options, every zone the server serves), or "" when it is off.
// The words are the ones EffectiveOutboundSoaSerialWithSource uses.
//
// The server-wide option is resolved here, at the point of use, never into
// zd.Options: the option finalization sites are many, and zd.Options is
// persisted with dynamic zones, which would turn a server default into each
// zone's own setting. A zone that sets the option itself reports "zone" even
// when the server sets it too: that is what an operator chose for this zone,
// and what the start-up pass's warning is about.
func (zd *ZoneData) transportSignalSource() string {
	if zd.Option(OptAddTransportSignal) {
		return "zone"
	}
	if zd.KeyDB != nil {
		if v, ok := zd.KeyDB.AuthOption(AuthOptAddTransportSignal); ok && v == "true" {
			return "global"
		}
	}
	return ""
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
			fmt.Sprintf("transport=%s", publishedTSYNCSignal(conf.Service.Transport.Signal)),
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
