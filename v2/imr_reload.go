/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Reloading the imrengine: stub and forward zones without a restart (#436).
 *
 * Before this, both were read exactly once: AddStub ran only inside the
 * !IsPrimed() branch of InitImrEngine and the forward table was built once
 * and never touched again, so adding an upstream -- or removing a stub that
 * pointed at a decommissioned server -- meant restarting the resolver and
 * throwing away its whole cache.
 *
 * Two properties make that safe to change:
 *
 *   - The table is IMMUTABLE once published. A reload validates and builds a
 *     complete new table and swaps one pointer; readers hold a snapshot for
 *     the duration of a query. Nothing mutates under a query in flight.
 *
 *   - Live state survives what did not change. A forward upstream whose
 *     configuration is untouched keeps its object -- its reachability
 *     counters, its unreachable flag, its DNS client -- and an untouched stub
 *     keeps its AuthServers, and with them their transport counters and
 *     address backoffs. Rebuilding everything on every reload would silently
 *     clear a DEGRADED that is still true, which teaches operators to
 *     distrust the flag.
 */
package tdns

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// imrZoneTable is the resolver's configured zone routing: the forward table
// and the configured stub zones, swapped as a unit.
//
// stubFP records, per stub zone, a fingerprint of the server list that was
// actually applied to the cache — which is what lets the next reload tell an
// edited stub from an untouched one.
type imrZoneTable struct {
	forwards []*ForwardZone    // most-specific first (BuildImrForwards sorts)
	stubs    []string          // canonical FQDNs, config order
	stubFP   map[string]string // stub zone -> fingerprint of the applied config
	// loadedAt is when this table was published. Reported by config status,
	// so "did my reload actually reach this daemon" is a question the
	// operator can answer without reading the log.
	loadedAt time.Time
}

var emptyZoneTable = &imrZoneTable{}

// zoneTable returns the currently published table, never nil. Nil-safe on the
// receiver so status/API readers can call it on an app with no resolver.
func (imr *Imr) zoneTable() *imrZoneTable {
	if imr == nil {
		return emptyZoneTable
	}
	if t := imr.zones.Load(); t != nil {
		return t
	}
	return emptyZoneTable
}

// ForwardZones returns the live forward table, most-specific first.
//
// Read-only, for the caller and for everything it hands the result to: the
// slice and the *ForwardZone values in it are shared with every other reader
// and with the next reload. (Per-upstream reachability state is mutated, but
// through ForwardUpstream's own mutex.)
func (imr *Imr) ForwardZones() []*ForwardZone { return imr.zoneTable().forwards }

// StubZones returns the CONFIGURED stub zones (canonical FQDNs). Deliberately
// not derived from the cache's ServerMap, which also accumulates zone cuts
// learned from referrals — those must not override a configured forward.
func (imr *Imr) StubZones() []string { return imr.zoneTable().stubs }

// setZoneTable publishes a table directly. Init and tests only; a reload goes
// through ReloadZones, which reconciles rather than replaces.
func (imr *Imr) setZoneTable(forwards []*ForwardZone, stubs []string, stubFP map[string]string) {
	imr.zones.Store(&imrZoneTable{
		forwards: forwards, stubs: stubs, stubFP: stubFP, loadedAt: time.Now(),
	})
}

// ImrZoneReloadResult reports what an imrengine: reload actually changed, so
// the operator sees the effect rather than a bare "reloaded".
type ImrZoneReloadResult struct {
	ForwardsAdded   []string `json:"forwards_added,omitempty"`
	ForwardsRemoved []string `json:"forwards_removed,omitempty"`
	ForwardsChanged []string `json:"forwards_changed,omitempty"`
	StubsAdded      []string `json:"stubs_added,omitempty"`
	StubsRemoved    []string `json:"stubs_removed,omitempty"`
	StubsChanged    []string `json:"stubs_changed,omitempty"`
	// RestartRequired names imrengine: keys that changed in the config file
	// but are NOT reloadable — trust anchors, tuning, options. Reporting them
	// is the whole point: silently ignoring an edit is how an operator ends up
	// debugging a resolver that is not running the config they are reading.
	RestartRequired []string `json:"restart_required,omitempty"`
}

// Changed reports whether the reload altered the running zone routing.
func (r ImrZoneReloadResult) Changed() bool {
	return len(r.ForwardsAdded)+len(r.ForwardsRemoved)+len(r.ForwardsChanged)+
		len(r.StubsAdded)+len(r.StubsRemoved)+len(r.StubsChanged) > 0
}

// Summary renders the result as one operator-facing line, or "" when nothing
// changed and nothing needs a restart.
func (r ImrZoneReloadResult) Summary() string {
	var parts []string
	add := func(label string, zones []string) {
		if len(zones) > 0 {
			parts = append(parts, fmt.Sprintf("%s %s", label, strings.Join(zones, ", ")))
		}
	}
	add("forward +", r.ForwardsAdded)
	add("forward -", r.ForwardsRemoved)
	add("forward ~", r.ForwardsChanged)
	add("stub +", r.StubsAdded)
	add("stub -", r.StubsRemoved)
	add("stub ~", r.StubsChanged)
	add("restart required for", r.RestartRequired)
	if len(parts) == 0 {
		return ""
	}
	return "IMR zones: " + strings.Join(parts, "; ")
}

// ReloadZones swaps the resolver's stub and forward zones to match the
// supplied config, and reports the diff.
//
// Atomic on failure: the new forward table is built and validated before
// anything live is touched, so a config that BuildImrForwards rejects (an
// unparseable upstream, trust-ad over a plaintext upstream) leaves the
// running resolver exactly as it was — the same "refuse whole, change
// nothing" contract as the DNSSEC policy guardrail on the zone-reload path.
//
// Nil-safe: an application with no resolver reloads nothing and reports no
// error.
func (imr *Imr) ReloadZones(stubconf []ImrStubConf, fwdconf []ImrForwardConf) (ImrZoneReloadResult, error) {
	var res ImrZoneReloadResult
	if imr == nil {
		return res, nil
	}

	newForwards, err := BuildImrForwards(fwdconf)
	if err != nil {
		return res, fmt.Errorf("imrengine.forward: %v", err)
	}
	newStubs, newFP, newServers := canonicalStubs(stubconf)

	// One reload at a time: two concurrent reloads would each diff against
	// the table the other is replacing, and the loser's cache-side stub work
	// would outlive the table that describes it.
	if imr.Cache == nil {
		return res, fmt.Errorf("IMR has no cache; cannot reload stub and forward zones")
	}

	imr.reloadMu.Lock()
	defer imr.reloadMu.Unlock()

	old := imr.zoneTable()
	diffForwardZones(old.forwards, newForwards, &res)
	carryForwardUpstreams(old.forwards, newForwards)

	// Stubs the cache must gain or re-learn, applied BEFORE the swap so a
	// query that sees a new stub zone in the table already finds its servers.
	appliedFP := make(map[string]string, len(newFP))
	for _, zone := range newStubs {
		fp := newFP[zone]
		appliedFP[zone] = fp
		if prev, existed := old.stubFP[zone]; existed && prev == fp {
			continue // untouched: keep its AuthServers, counters and backoffs
		}
		if err := imr.Cache.AddStub(zone, newServers[zone]); err != nil {
			// A rejected stub is not a reason to abandon the rest of the
			// reload; report it and leave that zone's old servers in place.
			lgImr.Error("stub zone reload failed, keeping previous servers", "zone", zone, "err", err)
			appliedFP[zone] = old.stubFP[zone]
			continue
		}
		if _, existed := old.stubFP[zone]; existed {
			res.StubsChanged = append(res.StubsChanged, zone)
		} else {
			res.StubsAdded = append(res.StubsAdded, zone)
		}
	}

	imr.setZoneTable(newForwards, newStubs, appliedFP)

	// Removals AFTER the swap, so no query can route to a stub zone whose
	// servers have already been dropped. Dropping the ServerMap entry is not
	// destructive: it is cache, and ordinary iteration re-learns the
	// delegation on the next query — which is exactly what should happen once
	// the zone is no longer stubbed.
	for zone := range old.stubFP {
		if _, kept := appliedFP[zone]; kept {
			continue
		}
		res.StubsRemoved = append(res.StubsRemoved, zone)
		if zone == "." {
			// The root's server map is the priming state, not a delegation
			// the resolver can re-learn: removing it leaves a resolver that
			// cannot start a walk.
			lgImr.Warn("stub zone for the root removed from config; keeping its server map (re-priming needs a restart)")
			continue
		}
		imr.Cache.ServerMap.Remove(zone)
	}

	sort.Strings(res.StubsRemoved)
	// A dropped upstream must not keep an aggregate DEGRADED alive, and a
	// newly configured one starts unprobed rather than failing.
	imr.updateForwardUpstreamError()

	if res.Changed() {
		lgImr.Info("imrengine zones reloaded", "summary", res.Summary())
	}
	return res, nil
}

// canonicalStubs canonicalises the configured stub zones and fingerprints
// each one's server list. Lenient by design — the same config that booted
// must keep booting — so a duplicate zone (last wins) or an empty server list
// is a WARN, not an error.
func canonicalStubs(stubs []ImrStubConf) ([]string, map[string]string, map[string][]cache.AuthServer) {
	zones := make([]string, 0, len(stubs))
	fps := make(map[string]string, len(stubs))
	servers := make(map[string][]cache.AuthServer, len(stubs))
	for _, sc := range stubs {
		if sc.Zone == "" {
			lgImr.Warn("stub zone without a zone name, ignored")
			continue
		}
		zone := dns.Fqdn(core.CanonicalizeName(sc.Zone))
		if _, ok := dns.IsDomainName(zone); !ok {
			lgImr.Warn("stub zone is not a valid domain name, ignored", "zone", sc.Zone)
			continue
		}
		if len(sc.Servers) == 0 {
			lgImr.Warn("stub zone has no servers; it will resolve nothing", "zone", zone)
		}
		if _, dup := fps[zone]; dup {
			lgImr.Warn("stub zone is configured more than once; the last entry wins", "zone", zone)
			zones = dropZone(zones, zone)
		}
		zones = append(zones, zone)
		fps[zone] = stubFingerprint(sc)
		servers[zone] = sc.Servers
	}
	return zones, fps, servers
}

// dropZone removes zone from the list, in place. Used only for the
// duplicate-stub case, where the later entry replaces the earlier one.
func dropZone(zones []string, zone string) []string {
	out := zones[:0]
	for _, z := range zones {
		if z != zone {
			out = append(out, z)
		}
	}
	return out
}

// stubFingerprint renders a stub zone's configured servers as a stable
// string. Only CONFIG fields go in: the point is to answer "did the operator
// edit this stub", not "has its runtime state moved".
func stubFingerprint(sc ImrStubConf) string {
	parts := make([]string, 0, len(sc.Servers))
	for i := range sc.Servers {
		s := &sc.Servers[i]
		addrs := append([]string(nil), s.Addrs...)
		sort.Strings(addrs)
		alpn := append([]string(nil), s.Alpn...)
		sort.Strings(alpn)
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%s|%v",
			core.CanonicalizeName(s.Name), strings.Join(addrs, ","),
			strings.Join(alpn, ","), s.TransportSignal, s.ConnMode))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// upstreamKey is the CONFIGURATION identity of a forward upstream: two
// upstreams with the same key dial the same server the same way, so a reload
// can carry the live one across instead of building a replacement.
type upstreamKey struct {
	Addr          string
	Port          string
	TLSServerName string
	Transport     core.Transport
	Insecure      bool
}

func (up *ForwardUpstream) key() upstreamKey {
	return upstreamKey{
		Addr:          up.Addr,
		Port:          up.Port,
		TLSServerName: up.TLSServerName,
		Transport:     up.Transport,
		Insecure:      up.Insecure,
	}
}

// forwardZoneSignature is a zone's configuration in one string: what has to
// differ for the zone to count as CHANGED rather than untouched.
func forwardZoneSignature(fz *ForwardZone) string {
	keys := make([]string, 0, len(fz.Upstreams))
	for _, up := range fz.Upstreams {
		keys = append(keys, fmt.Sprintf("%v", up.key()))
	}
	return fmt.Sprintf("trust-ad=%v|%s", fz.TrustAD, strings.Join(keys, ";"))
}

// diffForwardZones records which forward zones were added, removed or edited.
func diffForwardZones(old, new []*ForwardZone, res *ImrZoneReloadResult) {
	oldSig := make(map[string]string, len(old))
	for _, fz := range old {
		oldSig[fz.Zone] = forwardZoneSignature(fz)
	}
	newSeen := make(map[string]bool, len(new))
	for _, fz := range new {
		newSeen[fz.Zone] = true
		sig, existed := oldSig[fz.Zone]
		switch {
		case !existed:
			res.ForwardsAdded = append(res.ForwardsAdded, fz.Zone)
		case sig != forwardZoneSignature(fz):
			res.ForwardsChanged = append(res.ForwardsChanged, fz.Zone)
		}
	}
	for _, fz := range old {
		if !newSeen[fz.Zone] {
			res.ForwardsRemoved = append(res.ForwardsRemoved, fz.Zone)
		}
	}
	sort.Strings(res.ForwardsRemoved)
}

// carryForwardUpstreams substitutes the LIVE upstream object wherever the new
// table configures one identically, so an untouched upstream keeps its
// reachability counters, its unreachable flag and its DNS client across a
// reload of an unrelated zone. Per zone, not global: the same resolver
// forwarded for two zones keeps two independent sets of counters, and this
// must not merge them.
func carryForwardUpstreams(old, new []*ForwardZone) {
	live := map[string]map[upstreamKey]*ForwardUpstream{}
	for _, fz := range old {
		byKey := make(map[upstreamKey]*ForwardUpstream, len(fz.Upstreams))
		for _, up := range fz.Upstreams {
			byKey[up.key()] = up
		}
		live[fz.Zone] = byKey
	}
	for _, fz := range new {
		byKey, ok := live[fz.Zone]
		if !ok {
			continue
		}
		for i, up := range fz.Upstreams {
			if prev, ok := byKey[up.key()]; ok {
				fz.Upstreams[i] = prev
			}
		}
	}
}

// --- config-side plumbing --------------------------------------------------

// applyImrEngineReload hands the configured imrengine: stub and forward zones
// to the running resolver and reports the diff, including which edited keys
// are NOT reloadable.
//
// It re-reads and strictly validates the imrengine: block itself rather than
// trusting what the caller left in conf.Imr, so that BOTH reload paths get
// the same gate. That is load-bearing on the full-config path: ParseConfig
// reports an unknown key as a WARNING, so a misspelled `forwrd:` decodes to
// an empty list, and applying that would delete every forward zone the
// resolver is running on -- the very wipe reloadImrEngineFromFile refuses on
// the SIGHUP path. Same reasoning for a mistyped `stubs:`, which would drop
// the stub zones and, with them, their veto over a `zone: .` forward.
//
// Nil-safe on every axis: an app with no resolver (or one that never got
// past InitImrEngine) reloads nothing and reports nothing.
func (conf *Config) applyImrEngineReload() (ImrZoneReloadResult, error) {
	imr := conf.Internal.ImrEngine
	if imr == nil {
		return ImrZoneReloadResult{}, nil
	}
	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		return ImrZoneReloadResult{}, err
	}
	if block == nil {
		// No config file to re-read (embedded use): take what is in memory.
		block = &conf.Imr
	}
	res, err := imr.ReloadZones(block.Stubs, block.Forward)
	if err != nil {
		return res, err
	}
	// Diffed against the block just read from the FILE, not conf.Imr: on the
	// zone-reload path conf.Imr still holds the boot values for everything
	// except stubs and forwards, so that comparison would compare the boot
	// config with itself and never report anything.
	res.RestartRequired = imrRestartRequiredKeys(imr.bootConf, *block)
	if len(res.RestartRequired) > 0 {
		lgImr.Warn("imrengine keys changed but are not reloadable; the resolver keeps running on the values it started with",
			"keys", strings.Join(res.RestartRequired, ", "))
	}
	return res, nil
}

// imrRestartRequiredKeys names the imrengine: keys that differ between the
// config the resolver was BUILT from and the config just parsed, and that a
// reload cannot apply.
//
// Everything the resolver snapshots at init belongs here: the tuning knobs
// are copied into Imr.Tuning and into the process-wide backoff policy, the
// trust anchors are consumed once by initializeImrTrustAnchors, root-hints
// priming has already happened, and the debug log file handle is open. Stubs
// and forwards are absent on purpose — those are what the reload DOES apply.
func imrRestartRequiredKeys(boot, current ImrEngineConf) []string {
	var keys []string
	check := func(key string, same bool) {
		if !same {
			keys = append(keys, "imrengine."+key)
		}
	}
	bothNil := func(a, b *bool) bool {
		if a == nil || b == nil {
			return a == b
		}
		return *a == *b
	}
	check("active", bothNil(boot.Active, current.Active))
	check("root-hints", boot.RootHints == current.RootHints)
	check("options", slices.Equal(boot.OptionsStrs, current.OptionsStrs))
	check("trust-anchor-ds", boot.TrustAnchorDS == current.TrustAnchorDS)
	check("trust-anchor-dnskey", boot.TrustAnchorDNSKEY == current.TrustAnchorDNSKEY)
	check("trust-anchor-file", boot.TrustAnchorFile == current.TrustAnchorFile)
	check("require-dnssec-validation", bothNil(boot.RequireDnssecValidation, current.RequireDnssecValidation))
	check("verbose", boot.Verbose == current.Verbose)
	check("debug", boot.Debug == current.Debug)
	check("logging", boot.Logging == current.Logging)
	check("tuning", imrTuningEqual(boot.Tuning, current.Tuning))
	return keys
}

// imrTuningEqual compares two tuning blocks by value. Written out rather than
// reflect.DeepEqual'd so that adding a knob to ImrTuningConf without teaching
// this function about it is a compile error, not a silently missed report.
func imrTuningEqual(a, b ImrTuningConf) bool {
	if a.Backoff != b.Backoff || a.AddressFamily != b.AddressFamily ||
		a.Discovery != b.Discovery || a.QueryBudget != b.QueryBudget {
		return false
	}
	x, y := a.UpgradeIndirectCacheHits, b.UpgradeIndirectCacheHits
	if x == nil || y == nil {
		return x == y
	}
	return *x == *y
}
