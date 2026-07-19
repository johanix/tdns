/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// The policy-reload family validates the transactional DNSSEC policy-reload
// "no re-sign / backfill" guarantee (test A2). tdns records a per-zone
// "last-applied DNSSEC policy" in the keystore; the first time the server binds
// a signed, config-only zone that has no applied record it must backfill
// applied = intent WITHOUT re-signing (the zone is already correctly signed).
// The failure mode this test hunts is treating "applied missing" as "needs
// apply" → SignZone(force=true) on every zone at once — a thundering herd
// across the whole (PQ-signed) zone set.
//
// A2 proves: N zones get backfilled, and ZERO get re-signed. There is no
// server-side sign counter, so "did a re-sign happen?" is inferred from the
// only load-bearing signal available on the wire: RRSIG inception. A re-sign
// stamps a fresh inception; a backfill leaves the served RRSIG untouched.
//
// The trigger is a driven `reload-zones` (POST /config Command=reload-zones):
// that is the reload path that re-runs the per-zone DNSSEC-policy sync — where
// the first-bind backfill (or the herd re-sign, if broken) happens. The tool
// snapshots apex RRSIG inceptions immediately before and after that one reload
// and compares per keytag. It is deliberately single-mode: a daemon RESTART
// cannot validate A2, because an online/inline-signed zone is re-signed at
// every load (inception is stamped time.Now() and RRSIGs are in-memory only),
// so a restart advances inception for every zone regardless of backfill — a
// systematic false positive — and the backfill is a reload-path property that
// is not observable across a process restart at all.
//
// This is a pure DNS + mgmt-API client (design doc §3): the applied-policy
// readback and the reload drive are OPTIONAL capabilities; an absent one is a
// SKIP, never a failure — which also lets the inception-only check run
// differentially against BIND/NSD.

// PolicyReloadConfig parameterizes an A2 run.
type PolicyReloadConfig struct {
	DnsServer string          // addr:port for the DNS observations
	Api       *tdns.ApiClient // enumerate zones + applied readback + reload drive; nil disables the verdict
	Target    string          // target name (informational, for the report)

	// Zones is the zone set to test. Empty means the caller wants enumeration
	// (EnumerateSignedZones).
	Zones []string

	Tolerance int // allowed count of coincidentally-advanced zones (background resigner ticks)

	AppliedCapable bool // CapAppliedRead probed → applied_* readback enabled
	ReloadCapable  bool // mgmt API reachable → `reload-zones` can be driven

	ReadyTimeout time.Duration // budget to wait for all zones to answer SOA again after the trigger

	Tool string
}

// AppliedRec is the per-zone last-applied DNSSEC-policy record read back from
// the mgmt API (scoped list-zones / `zone desc`, #301). Present is false when
// the keystore holds no applied record for the zone (armed → NULL, or never
// applied). Err carries the server's AppliedError when the keystore read
// itself failed (distinct from a genuinely absent record).
type AppliedRec struct {
	Present bool   `json:"present"`
	Policy  string `json:"policy,omitempty"`
	Source  string `json:"source,omitempty"`
	At      string `json:"at,omitempty"`
	Err     string `json:"err,omitempty"`
}

// ZoneSnapshot is one zone's observable state at one instant: enough to decide,
// against a later snapshot, whether it was re-signed and whether it dropped
// unsigned. RRSIGs are the apex SOA + DNSKEY signatures (keyed by keytag).
type ZoneSnapshot struct {
	Zone   string `json:"zone"`
	OK     bool   `json:"ok"` // the SOA query answered (server authoritative for the zone)
	ErrMsg string `json:"err,omitempty"`
	Serial uint32 `json:"serial"`
	Signed bool   `json:"signed"` // an RRSIG(SOA) accompanied the apex SOA (+dnssec)
	// RRSIGErr is set when the apex-RRSIG probe itself failed (SOA answered but
	// the SOA/DNSKEY +dnssec queries errored). It makes a probe failure
	// distinguishable from a genuinely unsigned zone: Signed=false with a
	// non-empty RRSIGErr is "unknown", not "confirmed unsigned", so the compare
	// must not read it as a signedness drop or a cleared signature.
	RRSIGErr string     `json:"rrsig_err,omitempty"`
	RRSIGs   []RRSIGObs `json:"rrsigs,omitempty"`
	Applied  AppliedRec `json:"applied"`
}

// RunPolicyReload executes an A2 run and returns the report. It is single-mode:
// snapshot every zone → drive one `reload-zones` → wait for all zones Ready →
// snapshot again → Compare. A returned error is a setup error (exit 2):
// unreachable target, no zones. A recorded violation drives the report's exit
// code (1). Driving the reload needs the mgmt API; without it the trigger cannot
// fire, so the verdict is SKIPPED (never a failure) — this also lets the tool
// run harmlessly against a non-tdns target.
func RunPolicyReload(ctx context.Context, cfg PolicyReloadConfig) (*Report, error) {
	if cfg.DnsServer == "" {
		return nil, fmt.Errorf("no DNS server: pass --dns")
	}
	if len(cfg.Zones) == 0 {
		return nil, fmt.Errorf("no zones to test: pass --zones or ensure the mgmt API lists signed zones")
	}
	if cfg.ReadyTimeout <= 0 {
		cfg.ReadyTimeout = 60 * time.Second
	}
	rep := NewReport(cfg.Tool, "policy-reload")

	if cfg.Api == nil || !cfg.ReloadCapable {
		rep.Skip("reload-drive", "mgmt API unavailable — cannot drive `reload-zones`; the A2 backfill verdict needs the reload trigger")
		rep.Skip("A2 verdict", "no reload trigger fired")
		return rep, nil
	}

	before := snapshotZones(ctx, cfg, cfg.Zones)
	rep.Stat("zones.snapshotted", int64(len(before)))
	rep.Stat("zones.signed", int64(countSigned(before)))

	if err := driveReloadZones(ctx, cfg.Api); err != nil {
		return nil, fmt.Errorf("driving reload-zones: %w", err)
	}
	rep.Stat("reload.issued", 1)
	waitZonesReady(ctx, cfg, cfg.Zones, rep)
	after := snapshotZones(ctx, cfg, cfg.Zones)

	chk := &PolicyReloadChecker{
		report:         rep,
		tolerance:      cfg.Tolerance,
		appliedCapable: cfg.AppliedCapable,
	}
	chk.Compare(before, after)
	return rep, nil
}

// snapshotZones captures every zone's SOA serial, apex RRSIG inceptions,
// query-signedness, and (when capable) the applied-policy record. A zone that
// fails its SOA query is recorded OK=false so the comparison can flag a
// post-trigger drop to SERVFAIL.
func snapshotZones(ctx context.Context, cfg PolicyReloadConfig, zones []string) map[string]ZoneSnapshot {
	out := make(map[string]ZoneSnapshot, len(zones))
	for _, z := range zones {
		fqdn := dns.Fqdn(z)
		zs := ZoneSnapshot{Zone: fqdn}
		serial, err := querySOASerial(ctx, cfg.DnsServer, fqdn)
		if err != nil {
			zs.OK = false
			zs.ErrMsg = err.Error()
			out[fqdn] = zs
			continue
		}
		zs.OK = true
		zs.Serial = serial
		rrsigs, rerr := queryApexRRSIGs(ctx, cfg.DnsServer, fqdn)
		if rerr != nil {
			// SOA answered but the RRSIG probe failed: record it so the compare
			// treats Signed=false as "unknown", not "confirmed unsigned".
			zs.RRSIGErr = rerr.Error()
		} else {
			zs.RRSIGs = rrsigs
			for _, o := range rrsigs {
				if o.CoveredType == dns.TypeSOA {
					zs.Signed = true
				}
			}
		}
		if cfg.AppliedCapable && cfg.Api != nil {
			zs.Applied = fetchAppliedPolicy(ctx, cfg.Api, fqdn)
		}
		out[fqdn] = zs
	}
	return out
}

// --- the verdict ------------------------------------------------------------

type advancedZone struct {
	zone   string
	detail string
}

// PolicyReloadChecker compares a before/after pair of per-zone snapshots and
// records the A2 verdict on the report. It is the unit-tested core: Compare is a
// pure function of the two maps.
type PolicyReloadChecker struct {
	report         *Report
	tolerance      int
	appliedCapable bool

	advanced     []advancedZone // zones whose apex RRSIG inception advanced (a re-sign)
	beforeAbsent int            // compared zones with no applied record in the before snapshot
}

// Compare evaluates A2 over the before/after snapshots. Only zones present in
// BOTH are compared (a zone that appeared or vanished across the trigger is a
// config change, not a re-sign, and is Stat'd, not asserted). It records:
//   - a re-sign (inception advance on a shared keytag) → A2 violation once the
//     count exceeds --tolerance, naming every advanced zone;
//   - a drop to unsigned/SERVFAIL after the trigger → A2-signed violation
//     (via the reused SignednessChecker latch), naming the zone;
//   - the applied absent→config backfill transition → Stat (or a one-time Skip
//     when the applied-readback capability is absent).
func (c *PolicyReloadChecker) Compare(before, after map[string]ZoneSnapshot) {
	if !c.appliedCapable {
		c.report.Skip("applied-policy readback",
			"the mgmt-API applied_* fields are unavailable (older tdns or non-tdns target) — the absent→config backfill confirmation is skipped; the inception no-re-sign check still runs")
	}

	// Zone-set bookkeeping: only the intersection is comparable.
	for name := range before {
		if _, ok := after[name]; !ok {
			c.report.Stat("zones.vanished", 1)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			c.report.Stat("zones.appeared", 1)
		}
	}

	for _, name := range sortedKeys(before) {
		b := before[name]
		a, ok := after[name]
		if !ok {
			continue // vanished; already counted
		}
		c.report.Stat("zones.compared", 1)
		c.checkSignedness(name, b, a)
		c.checkInception(name, b, a)
		if c.appliedCapable {
			c.checkApplied(b, a)
		}
	}

	// Coverage guard: A2 asserts "no zone was re-signed", but that is only
	// meaningful if the backfill path actually ran — i.e. some zone had an absent
	// applied record when the reload fired. If every zone already had `applied`
	// present (operator forgot to arm applied_*→NULL), the sync takes the
	// same-name None branch: no backfill, no re-sign, a clean-but-vacuous result.
	// Surface that so a green run can't be mistaken for proof of the guarantee.
	if c.appliedCapable && c.beforeAbsent == 0 {
		c.report.Skip("A2 backfill coverage",
			"no zone had an absent applied record before the reload — clear applied_* (→ NULL) under the running server BEFORE running so reload-zones actually backfills; otherwise this only proves 'no re-sign of already-recorded zones', not the backfill guarantee")
	}

	// Apply the re-sign verdict with the tolerance for coincidental background
	// resigner ticks. Any advance beyond the tolerance breaks the guarantee.
	switch {
	case len(c.advanced) > c.tolerance:
		c.report.Stat("a2.resigned", int64(len(c.advanced)))
		for _, az := range c.advanced {
			c.report.Violate("A2",
				fmt.Sprintf("zone %s was RE-SIGNED across the policy reload (apex RRSIG inception advanced) — the backfill path must record applied=intent WITHOUT re-signing an already-correct zone", az.zone),
				az.detail)
		}
	case len(c.advanced) > 0:
		// Within tolerance: surfaced, not a failure (a background resigner may
		// legitimately have re-signed a zone that was near RRSIG expiry).
		c.report.Stat("a2.resigned-within-tolerance", int64(len(c.advanced)))
		for _, az := range c.advanced {
			c.report.Skip("A2 inception advance (within --tolerance)",
				fmt.Sprintf("zone %s: %s", az.zone, az.detail))
		}
	default:
		c.report.Stat("a2.no-resign", int64(c.report.Stats["zones.compared"]))
	}
}

// checkSignedness reuses SignednessChecker's latch rule per zone: a zone
// observed signed in `before` (the latch) that comes back unsigned in `after` is
// a drop the reload must never cause. The checker runs against a throwaway
// sub-report so the generic I10 text can be re-emitted named for this zone and
// this test. A zone that stops answering entirely (SERVFAIL / no SOA) is the
// same failure surfaced directly.
func (c *PolicyReloadChecker) checkSignedness(zone string, b, a ZoneSnapshot) {
	if !a.OK {
		if b.Signed {
			c.report.Violate("A2-signed",
				fmt.Sprintf("zone %s stopped answering authoritatively (SERVFAIL / no SOA) after the reload trigger", zone),
				a.ErrMsg)
		}
		return
	}
	// If the after-snapshot RRSIG probe itself failed, a.Signed=false is a probe
	// artifact (SOA answered, the +dnssec queries errored), not a confirmed drop
	// to unsigned — asserting here would be a false positive. Surface it as
	// inconclusive instead. (A before-probe failure only ever suppresses the
	// latch → a missed detection, never a false alarm, so it needs no guard.)
	if a.RRSIGErr != "" {
		if b.Signed {
			c.report.Stat("signedness.inconclusive", 1)
		}
		return
	}
	sub := NewReport("", "")
	sc := &SignednessChecker{report: sub}
	// Feed the crisp query-signed boolean into both fields: SignednessChecker
	// counts a sample as signed only when HasDNSKEY && HasRRSIG, so mirroring the
	// single boolean into both makes it latch iff the zone was query-signed.
	sc.Observe(SignednessObs{Serial: b.Serial, HasDNSKEY: b.Signed, HasRRSIG: b.Signed})
	sc.Observe(SignednessObs{Serial: a.Serial, HasDNSKEY: a.Signed, HasRRSIG: a.Signed})
	for _, v := range sub.Violations {
		c.report.Violate("A2-signed",
			fmt.Sprintf("zone %s dropped from signed to unsigned across the reload trigger", zone),
			v.Context)
	}
}

// checkInception diffs apex RRSIG inceptions per (covered-type, keytag). A key
// present in both snapshots whose inception advanced (RFC 1982 serial
// arithmetic) is a re-sign. Keys only in one snapshot are a key change
// (rollover), not a re-sign of existing content, and are ignored here.
func (c *PolicyReloadChecker) checkInception(zone string, b, a ZoneSnapshot) {
	type key struct {
		covered uint16
		keytag  uint16
	}
	bm := make(map[key]RRSIGObs, len(b.RRSIGs))
	for _, o := range b.RRSIGs {
		bm[key{o.CoveredType, o.KeyTag}] = o
	}
	var details []string
	for _, ao := range a.RRSIGs {
		bo, ok := bm[key{ao.CoveredType, ao.KeyTag}]
		if !ok {
			continue // new key (rollover), not a re-sign of an existing signature
		}
		if serialLT(bo.Inception, ao.Inception) {
			details = append(details, fmt.Sprintf("%s keytag=%d alg=%d inception %d→%d",
				dns.TypeToString[ao.CoveredType], ao.KeyTag, ao.Algorithm, bo.Inception, ao.Inception))
		}
	}
	if len(details) > 0 {
		c.advanced = append(c.advanced, advancedZone{zone: zone, detail: strings.Join(details, "; ")})
	}
}

// checkApplied records the applied-policy backfill transition as counters. The
// clean A2 signal is absent(before)→config(after): the first bind backfilled
// applied=intent with source=config. This is confirmation, not a pass/fail gate
// — the load-bearing invariant is the inception no-re-sign check above.
func (c *PolicyReloadChecker) checkApplied(b, a ZoneSnapshot) {
	if !b.Applied.Present {
		c.beforeAbsent++
		c.report.Stat("applied.before-absent", 1)
	}
	if a.Applied.Err != "" {
		c.report.Stat("applied.read-errors", 1)
	}
	switch {
	case !a.Applied.Present:
		c.report.Stat("applied.after-absent", 1)
	case a.Applied.Source == "config":
		c.report.Stat("applied.after-config", 1)
		if !b.Applied.Present {
			c.report.Stat("applied.backfilled", 1)
		}
	default:
		c.report.Stat("applied.after-nonconfig", 1)
	}
}

// --- mgmt-API helpers -------------------------------------------------------

// zoneConfView mirrors just the ZoneConf fields the policy-reload test reads
// (design doc §3 mirror-type strategy — decode into our own type so the tool
// tolerates servers that predate the typed applied_* fields). The applied_*
// fields are pointers so their ABSENCE (older tdns / non-tdns, field missing
// from the JSON → nil) is distinguishable from a present-but-empty value
// (#301+ server with no applied record → non-nil, "").
type zoneConfView struct {
	Name                  string  `json:"Name"`
	EffectiveDnssecPolicy string  `json:"EffectiveDnssecPolicy"`
	AppliedPolicy         *string `json:"AppliedPolicy"`
	AppliedSource         *string `json:"AppliedSource"`
	AppliedAt             *string `json:"AppliedAt"`
	AppliedError          *string `json:"AppliedError"`
}

type listZonesResp struct {
	Error    bool
	ErrorMsg string
	Zones    map[string]zoneConfView
}

// listZones posts a list-zones command (bulk when zone=="", scoped to one zone
// otherwise) and decodes the mirror response.
func listZones(ctx context.Context, api *tdns.ApiClient, zone string) (*listZonesResp, error) {
	status, buf, err := api.RequestNGWithContext(ctx, "POST", "/zone",
		tdns.ZonePost{Command: "list-zones", Zone: zone}, false)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("list-zones: http status %d", status)
	}
	var lr listZonesResp
	if err := json.Unmarshal(buf, &lr); err != nil {
		return nil, fmt.Errorf("list-zones: bad response: %w", err)
	}
	if lr.Error {
		return nil, fmt.Errorf("list-zones: %s", lr.ErrorMsg)
	}
	return &lr, nil
}

// EnumerateSignedZones returns the target's signed zones (EffectiveDnssecPolicy
// non-empty), sorted. Used when the operator does not pass an explicit --zones
// set.
func EnumerateSignedZones(ctx context.Context, api *tdns.ApiClient) ([]string, error) {
	if api == nil {
		return nil, fmt.Errorf("no mgmt API configured — pass --zones to name the signed zones explicitly")
	}
	lr, err := listZones(ctx, api, "")
	if err != nil {
		return nil, err
	}
	var zones []string
	for name, zc := range lr.Zones {
		if strings.TrimSpace(zc.EffectiveDnssecPolicy) != "" {
			zones = append(zones, dns.Fqdn(name))
		}
	}
	sort.Strings(zones)
	return zones, nil
}

// fetchAppliedPolicy reads one zone's last-applied policy record via a scoped
// list-zones. A missing zone or a nil AppliedPolicy field (older server) yields
// an absent record rather than an error — the capability gate decides whether to
// count it.
func fetchAppliedPolicy(ctx context.Context, api *tdns.ApiClient, zone string) AppliedRec {
	lr, err := listZones(ctx, api, zone)
	if err != nil {
		return AppliedRec{Err: err.Error()}
	}
	zc, ok := lr.Zones[dns.Fqdn(zone)]
	if !ok {
		return AppliedRec{}
	}
	rec := AppliedRec{}
	if zc.AppliedError != nil && *zc.AppliedError != "" {
		rec.Err = *zc.AppliedError
	}
	if zc.AppliedPolicy != nil && *zc.AppliedPolicy != "" {
		rec.Present = true
		rec.Policy = *zc.AppliedPolicy
		if zc.AppliedSource != nil {
			rec.Source = *zc.AppliedSource
		}
		if zc.AppliedAt != nil {
			rec.At = *zc.AppliedAt
		}
	}
	return rec
}

// ProbeAppliedPolicy sets CapAppliedRead on the matrix by checking whether a
// SCOPED list-zones for a real zone returns the typed applied_* fields. A
// pre-#301 server (or a non-tdns target) omits them entirely → the mirror's
// AppliedPolicy pointer is nil → capability absent. The bulk list-zones path
// never populates them, so this must probe the scoped path against a zone that
// actually exists.
func ProbeAppliedPolicy(ctx context.Context, m *CapabilityMatrix, api *tdns.ApiClient, zone string) {
	if api == nil {
		m.set(CapAppliedRead, CapAbsent, "no mgmt API")
		return
	}
	if zone == "" {
		m.set(CapAppliedRead, CapUnknown, "no sample zone to probe the applied_* fields")
		return
	}
	lr, err := listZones(ctx, api, zone)
	if err != nil {
		m.set(CapAppliedRead, CapAbsent, err.Error())
		return
	}
	zc, ok := lr.Zones[dns.Fqdn(zone)]
	if !ok {
		m.set(CapAppliedRead, CapUnknown, fmt.Sprintf("sample zone %s not listed", zone))
		return
	}
	if zc.AppliedPolicy == nil {
		m.set(CapAppliedRead, CapAbsent, "server does not return the typed applied_* fields (pre-#301 or non-tdns)")
		return
	}
	m.set(CapAppliedRead, CapAvailable, "scoped list-zones returns applied_* fields")
}

// driveReloadZones issues one `reload-zones` (POST /config Command=reload-zones)
// — the reload path that re-parses the zone config and enqueues the ConfigUpdate
// refreshers that carry the per-zone DNSSEC-policy sync (syncZoneDnssecPolicyFromConfig),
// where the first-bind backfill (or the herd re-sign, if broken) happens. NOT
// `config reload` (Command=reload): that path re-reads only the main config and
// never calls ParseZones, so the per-zone sync — the whole point of A2 — never
// runs and the "no inception change" result would be vacuous.
func driveReloadZones(ctx context.Context, api *tdns.ApiClient) error {
	status, buf, err := api.RequestNGWithContext(ctx, "POST", "/config",
		tdns.ConfigPost{Command: "reload-zones"}, false)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("reload-zones: http status %d", status)
	}
	var cr struct {
		Error    bool
		ErrorMsg string
	}
	if err := json.Unmarshal(buf, &cr); err == nil && cr.Error {
		return fmt.Errorf("reload-zones: %s", cr.ErrorMsg)
	}
	return nil
}

// waitZonesReady polls each zone's SOA until all answer or the ReadyTimeout
// budget elapses. It never fails the run — a zone still not answering at the
// deadline is left for the after-snapshot to record as a drop.
func waitZonesReady(ctx context.Context, cfg PolicyReloadConfig, zones []string, rep *Report) {
	deadline := time.Now().Add(cfg.ReadyTimeout)
	pending := append([]string(nil), zones...)
	for len(pending) > 0 && time.Now().Before(deadline) {
		var still []string
		for _, z := range pending {
			if _, err := querySOASerial(ctx, cfg.DnsServer, z); err != nil {
				still = append(still, z)
			}
		}
		pending = still
		if len(pending) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	if len(pending) > 0 {
		rep.Stat("zones.not-ready", int64(len(pending)))
	}
}

// --- small helpers ----------------------------------------------------------

func sortedKeys(m map[string]ZoneSnapshot) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func countSigned(m map[string]ZoneSnapshot) int {
	n := 0
	for _, zs := range m {
		if zs.Signed {
			n++
		}
	}
	return n
}
