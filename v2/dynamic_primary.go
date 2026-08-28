/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Dynamic PRIMARY zones: API-provisioned, template-constrained primaries
 * (docs/2026-07-13-dynamic-primary-zones.md). The template is the security
 * envelope: an API client cannot express an update policy at all, it can only
 * pick among operator-blessed configurations.
 */

package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	core "github.com/johanix/tdns/v2/core"
)

// dynamicPrimarySpec is the validated result of expanding a dynamic-primary
// zone config against its template: everything the add path (and the boot
// re-expansion in LoadDynamicZoneFiles) needs to build the zone.
type dynamicPrimarySpec struct {
	Zconf          ZoneConf            // fully expanded + validated config
	Options        map[ZoneOption]bool // parsed zone options (policy-adjusted)
	Policy         UpdatePolicy        // activated update policy
	PublishCadence time.Duration       // parsed publish-cadence (0 = default)
}

// dynamicPrimaryDisallowedOptions are template options that name machinery a
// dynamic primary must not participate in (v1): catalogs have their own
// provisioning paths and multi-provider zones their own signing model.
var dynamicPrimaryDisallowedOptions = map[ZoneOption]bool{
	OptCatalogZone:             true,
	OptCatalogMemberAutoCreate: true,
	OptCatalogMemberAutoDelete: true,
	OptMultiProvider:           true,
}

// lookupZoneTemplate copies a template out of the global Templates map under
// confMu (the map is wholesale-replaced by template reload while holding the
// write lock; entries are never mutated in place, so the copy is safe to use
// after release).
func lookupZoneTemplate(name string) (ZoneConf, bool) {
	confMu.RLock()
	defer confMu.RUnlock()
	tmpl, ok := Templates[name]
	return tmpl, ok
}

// prepareDynamicPrimary expands zconf (Name + Template, plus any persisted
// fields, which win over the template by gap-fill) against its template and
// runs the same validation/activation sequence ParseZones applies to static
// zones. staged, when non-nil, is an inline TSIG key being added with the
// zone: keyless (""/NOKEY) downstreams entries are rewired to it (BLOCKED and
// explicitly-keyed entries are never touched) BEFORE ACL validation, and the
// ACL check accepts the staged name. fromAPI enforces the per-template
// dynamiczones: blessing (gate 2) — the boot path only warns, mirroring how
// dynamiczones.dynamic.allowed gates new adds but not already-persisted zones.
//
// A non-nil error means the config is invalid: the add path refuses the
// request, the boot path registers an error-state zone.
func (conf *Config) prepareDynamicPrimary(zconf ZoneConf, staged *TsigDetails, fromAPI bool) (*dynamicPrimarySpec, error) {
	zconf.Name = dns.Fqdn(zconf.Name)
	zconf.Type = "primary"

	if zconf.Template == "" {
		return nil, fmt.Errorf("dynamic primary zone requires a template")
	}
	tmpl, ok := lookupZoneTemplate(zconf.Template)
	if !ok {
		return nil, fmt.Errorf("template %q does not exist", zconf.Template)
	}
	if fromAPI && !tmpl.DynamicZones {
		return nil, fmt.Errorf("template %q is not blessed for dynamic zones (set dynamiczones: true on the template)", zconf.Template)
	}
	if !fromAPI && !tmpl.DynamicZones {
		lg.Warn("dynamic primary: template no longer blessed for dynamic zones; loading persisted zone anyway (blessing gates new adds)", "zone", zconf.Name, "template", zconf.Template)
	}
	if tmpl.Type != "" && strings.ToLower(tmpl.Type) != "primary" {
		return nil, fmt.Errorf("template %q is type %s, not primary", zconf.Template, tmpl.Type)
	}

	// A conflicted template (primaries:+upstreams: etc.) would silently hand
	// the zone its broader canonical ACL — same quarantine rule as ParseZones.
	if conflict := zoneOrTemplateAliasConflict(conf.Internal.XfrAliasConflicts, zconf.Name, zconf.Template); conflict != "" {
		return nil, fmt.Errorf("conflicting transfer-list spellings: %s", conflict)
	}

	expanded, err := ExpandTemplate(zconf, &tmpl, Globals.App.Type)
	if err != nil {
		return nil, fmt.Errorf("template expansion error: %q: %v", zconf.Template, err)
	}

	// Expand `- peers: [ id, ... ]` references into concrete entries.
	if err := conf.expandPeerRefs(&expanded, conf.Internal.BrokenPeers); err != nil {
		return nil, fmt.Errorf("peers: %v", err)
	}

	// A primary is file-backed: the template must yield a zonefile (its %s
	// pattern) unless the persisted entry already carries one.
	if expanded.Zonefile == "" {
		return nil, fmt.Errorf("template %q yields no zonefile for the zone (a dynamic primary requires a zonefile pattern)", zconf.Template)
	}

	// Dynamic zones are map-only (the same chokepoint the secondary add
	// enforces); a template asking for another store is refused loudly.
	if store := parseZoneStore(expanded.Store); store != MapZone {
		return nil, fmt.Errorf("dynamic zones are map-only (template %q sets store: %s)", zconf.Template, expanded.Store)
	}

	// Inline TSIG: rewire keyless (""/NOKEY) downstreams entries to the staged
	// key — gating outbound transfers by it, the mirror image of the secondary
	// case. BLOCKED and explicitly-keyed entries are never rewired (rewiring
	// only ever tightens access). Done before ACL validation so the validation
	// sees the final ACL.
	if staged != nil {
		for i := range expanded.Downstreams {
			if expanded.Downstreams[i].Key == "" || expanded.Downstreams[i].Key == NOKEY {
				expanded.Downstreams[i].Key = staged.Name
			}
		}
	}

	// The same per-list validation ParseZones applies. The ACL key check
	// accepts the staged inline key (it is committed with the zone).
	keyOK := func(name string) bool { return conf.tsigKeyAcceptable(name, staged) }
	if err := validateDownstreamAuth(expanded.DownstreamAuth); err != nil {
		return nil, fmt.Errorf("downstream-auth: %v", err)
	}
	crossCheckDownstreamAuth(expanded.Name, expanded.DownstreamAuth, expanded.Downstreams, conf.Internal.ImrEngine != nil)
	for _, n := range expanded.Notify {
		if n.Legacy != "" {
			return nil, fmt.Errorf("notify now requires {addr, key} (got bare string %q)", n.Legacy)
		}
		if n.Transport != "" || n.TLSAuth != "" || n.TLSName != "" || len(n.Pins) > 0 || n.CAFile != "" {
			return nil, fmt.Errorf("notify %s: transport/tls-* not supported for notify targets", n.Addr)
		}
		if n.Key != "" && n.Key != NOKEY && !keyOK(n.Key) {
			return nil, fmt.Errorf("notify %s references unknown key %q", n.Addr, n.Key)
		}
	}
	if err := ValidateACL(expanded.AllowNotify, keyOK); err != nil {
		return nil, fmt.Errorf("allow-notify: %v", err)
	}
	if err := ValidateACL(expanded.Downstreams, keyOK); err != nil {
		return nil, fmt.Errorf("downstreams: %v", err)
	}

	publishCadence, err := parsePublishCadence(expanded.PublishCadence)
	if err != nil {
		return nil, fmt.Errorf("publish-cadence: %v", err)
	}

	// DNSSEC policy: "none" means unsigned; an unusable policy reference is a
	// refusal here (ParseZones quarantines instead — for an API request the
	// refusal IS the quarantine-equivalent, and fail-loud beats silently
	// minting an unsigned zone).
	if expanded.DnssecPolicy == "none" {
		expanded.DnssecPolicy = ""
	}
	if expanded.DnssecPolicy != "" {
		if _, errMsg := resolveZonePolicyRef(expanded.DnssecPolicy, conf.Internal.DnssecPolicies); errMsg != "" {
			return nil, fmt.Errorf("dnssecpolicy %q: %s", expanded.DnssecPolicy, errMsg)
		}
	}

	// Option pre-scan: parseZoneOptions (shared below) logs-and-drops what it
	// dislikes; for a template-driven zone every such case must refuse loudly
	// instead — a blessed template that silently loses an option is exactly
	// the drift the envelope is supposed to prevent.
	for _, o := range expanded.OptionsStrs {
		o = strings.ToLower(strings.TrimSpace(o))
		if o == "" {
			continue
		}
		opt, known := StringToZoneOption[o]
		if !known {
			return nil, fmt.Errorf("unknown config option: %q", o)
		}
		if dynamicPrimaryDisallowedOptions[opt] {
			return nil, fmt.Errorf("option %q is not supported for dynamic primary zones", o)
		}
		if (opt == OptOnlineSigning || opt == OptInlineSigning) && expanded.DnssecPolicy == "" {
			return nil, fmt.Errorf("%s requires the template to set a dnssecpolicy", o)
		}
	}
	options := parseZoneOptions(conf, expanded.Name, &expanded, nil)

	policy, err := activateUpdatePolicy(&expanded, options)
	if err != nil {
		return nil, err
	}
	// v1: no child-update policies on dynamic primaries. The delegation
	// backend is wired in ParseZones only, so an API-added (or dynamically
	// re-loaded) zone would carry the option with a nil backend — the exact
	// silently-misbehaving-scanner state the static path refuses to start.
	if options[OptAllowChildUpdates] {
		return nil, fmt.Errorf("allow-child-updates is not supported for dynamic primary zones (use a static zone)")
	}

	return &dynamicPrimarySpec{
		Zconf:          expanded,
		Options:        options,
		Policy:         policy,
		PublishCadence: publishCadence,
	}, nil
}

// bootstrapApexRecords synthesizes the minimal apex content for a freshly
// provisioned dynamic primary: SOA, apex NS (ns.<zone>) and A/AAAA glue built
// from the server's own listen addresses (ports stripped, deduplicated,
// wildcard listeners skipped with a WARN — predictable beats clever). Returns
// zone-file lines. With zero usable addresses the zone is still created (NS
// without address records) with a WARN; once live it is reshaped via DNS
// UPDATE as the template's policy allows.
func bootstrapApexRecords(zone string, listenAddrs []string) []string {
	zone = dns.Fqdn(zone)
	nsName := "ns." + zone

	lines := []string{
		fmt.Sprintf("%s\t3600\tIN\tSOA\t%s hostmaster.%s 1 3600 600 604800 300", zone, nsName, zone),
		fmt.Sprintf("%s\t3600\tIN\tNS\t%s", zone, nsName),
	}

	seen := map[string]bool{}
	glue := 0
	for _, la := range listenAddrs {
		host, _, err := net.SplitHostPort(la)
		if err != nil {
			host = la // address without port
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			lg.Warn("bootstrap apex: unparsable listen address, skipping", "zone", zone, "address", la)
			continue
		}
		if addr.IsUnspecified() {
			lg.Warn("bootstrap apex: skipping wildcard listener (list concrete addresses in dnsengine.addresses to have them in synthesized apexes)", "zone", zone, "address", la)
			continue
		}
		key := addr.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		if addr.Is4() {
			lines = append(lines, fmt.Sprintf("%s\t3600\tIN\tA\t%s", nsName, key))
		} else {
			lines = append(lines, fmt.Sprintf("%s\t3600\tIN\tAAAA\t%s", nsName, key))
		}
		glue++
	}
	if glue == 0 {
		lg.Warn("bootstrap apex: no usable listen address; zone created with NS but no address records", "zone", zone)
	}
	return lines
}

// synthesizeBootstrapZonefile writes the bootstrap apex for zone to path
// (atomically: temp + rename, directory created as needed). The caller has
// already established that no file exists at path.
func (conf *Config) synthesizeBootstrapZonefile(zone, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create zone file directory %s: %v", dir, err)
	}
	content := strings.Join(bootstrapApexRecords(zone, conf.DnsEngine.Addresses), "\n") + "\n"

	tempFile, err := os.CreateTemp(dir, fmt.Sprintf(".%s.bootstrap.tmp", filepath.Base(path)))
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	tempFilePath := tempFile.Name()
	if _, err := tempFile.WriteString(content); err != nil {
		tempFile.Close()
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to write temp file: %v", err)
	}
	// Fsync before rename: without it a crash can leave a correctly-named but
	// empty zonefile, which the boot path would load as an empty primary.
	if err := tempFile.Sync(); err != nil {
		tempFile.Close()
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to sync temp file: %v", err)
	}
	// os.CreateTemp yields 0600; the UPDATE write-back (WriteZone → WriteFile
	// → os.Create) produces 0644, so set 0644 up front rather than having the
	// mode flip on the first update.
	if err := tempFile.Chmod(0644); err != nil {
		tempFile.Close()
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to chmod temp file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to close temp file: %v", err)
	}
	if err := os.Rename(tempFilePath, path); err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to rename temp file to zone file: %v", err)
	}
	lg.Info("synthesized bootstrap apex for dynamic primary", "zone", zone, "path", path)
	return nil
}

// provisionDynamicPrimary is the primary branch of ProvisionDynamicZone: the
// common gates (allowed-list, template-required, name validity, duplicate)
// have already passed. It expands + validates against the template, bootstraps
// the zone file if absent, registers a pre-configured first-load stub in the
// Zones map (the same shape ParseZones leaves for static zones, so the
// RefreshEngine runs the full first-bind sequence: FetchFromFile → initial
// snapshot install → policy sync → OnFirstLoad signing), persists with
// rollback, and enqueues the file-load refresh.
func (conf *Config) provisionDynamicPrimary(ctx context.Context, in DynamicZoneInput, fromAPI bool) (string, error) {
	name := dns.Fqdn(in.Name)

	// The template is the whole configuration envelope: caller-supplied
	// options would extend it outside operator control, so they are refused
	// rather than silently ignored.
	if len(in.Options) > 0 {
		return "", fmt.Errorf("zone %s: a primary zone takes its options from the template; per-zone options are not accepted", name)
	}
	if len(in.Primaries) > 0 {
		return "", fmt.Errorf("zone %s: a primary zone has no upstream primaries; the primaries list is not accepted", name)
	}

	// Stage the inline TSIG key (validate + collision-check only; in.Primaries
	// is empty so no rewiring happens here — prepareDynamicPrimary rewires the
	// expanded downstreams instead). Committed only after persistence.
	staged, serr := conf.stageInlineTsigKey(&in)
	if serr != nil {
		return "", fmt.Errorf("zone %s: %w", name, serr)
	}

	spec, perr := conf.prepareDynamicPrimary(ZoneConf{Name: name, Template: in.Template}, staged, fromAPI)
	if perr != nil {
		return "", fmt.Errorf("zone %s: %w", name, perr)
	}

	options := spec.Options
	if fromAPI {
		options[OptApiManagedZone] = true
	}

	// Bootstrap the zone file if absent; an existing file (e.g. re-add after
	// a delete that failed to remove it, or operator-provided content) is
	// used as-is.
	createdFile := false
	if _, err := os.Stat(spec.Zconf.Zonefile); err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("zone %s: cannot stat zonefile %s: %v", name, spec.Zconf.Zonefile, err)
		}
		if err := conf.synthesizeBootstrapZonefile(name, spec.Zconf.Zonefile); err != nil {
			return "", fmt.Errorf("zone %s: %w", name, err)
		}
		createdFile = true
	} else {
		lg.Info("dynamic primary: zone file already exists, using as-is", "zone", name, "path", spec.Zconf.Zonefile)
	}
	cleanupFile := func() {
		if createdFile {
			if err := os.Remove(spec.Zconf.Zonefile); err != nil && !os.IsNotExist(err) {
				lg.Warn("dynamic primary: failed to remove bootstrap zone file on rollback", "zone", name, "path", spec.Zconf.Zonefile, "error", err)
			}
		}
	}

	// Build the fully-configured first-load stub. FirstZoneLoad routes the
	// enqueued refresher down the RefreshEngine's pre-registered-stub branch
	// (the static-primary first-bind path); ZoneType being set skips the
	// engine's config merge, so everything must be carried here.
	msc := ConfLive().MultiSigner[spec.Zconf.MultiSigner]
	zd := &ZoneData{
		ZoneName: core.CanonicalizeName(name),
		ZoneType: Primary,
		// Set directly, like every other field here: this ZoneData is
		// pre-registered with ZoneType already Primary, and the RefreshEngine
		// merge block that would otherwise copy it off the ZoneRefresher is
		// gated on `zd.ZoneType == 0`. Relying on the zr path alone would
		// silently drop a template's outbound-soa-serial and leave the zone on
		// the server-global default.
		OutboundSoaSerial: spec.Zconf.OutboundSoaSerial,
		TransferSrc:       spec.Zconf.TransferSrc,
		ZoneStore:         MapZone,
		Zonefile:          spec.Zconf.Zonefile,
		Template:          in.Template,
		Notify:            normalizePeerAddrs(spec.Zconf.Notify),
		AllowNotify:       spec.Zconf.AllowNotify,
		Downstreams:       spec.Zconf.Downstreams,
		DownstreamAuth:    spec.Zconf.DownstreamAuth,
		Logger:            log.Default(),
		Options:           options,
		UpdatePolicy:      spec.Policy,
		DnssecPolicyName:  spec.Zconf.DnssecPolicy, // config-base name; struct bound post-Ready
		MultiSigner:       &msc,
		DelegationSyncQ:   conf.Internal.DelegationSyncQ,
		Status:            ZoneStatusPending,
		Data:              core.NewNameMap[OwnerData](),
		KeyDB:             conf.Internal.KeyDB,
		FirstZoneLoad:     true,
		publishCadence:    spec.PublishCadence,
	}

	// First-load callbacks, mirroring what ParseZones registers for static
	// zones (the engine's stub branch drains OnFirstLoad post-Ready).
	if options[OptOnlineSigning] || options[OptInlineSigning] {
		resignQ := conf.Internal.ResignQ
		zd.OnFirstLoad = append(zd.OnFirstLoad, func(z *ZoneData) {
			if err := z.SetupZoneSigning(resignQ); err != nil {
				lg.Error("SetupZoneSigning failed in OnFirstLoad", "zone", z.ZoneName, "error", err)
			}
		})
	}
	// SetupZoneSync's delegation-sync-child path does an unbounded send to
	// DelegationSyncQ, and OnFirstLoad callbacks run inside the RefreshEngine
	// loop — dispatch async so a full/stopped consumer cannot stall it.
	if options[OptDelSyncParent] || options[OptDelSyncChild] {
		delegationSyncQ := conf.Internal.DelegationSyncQ
		zd.OnFirstLoad = append(zd.OnFirstLoad, func(z *ZoneData) {
			if delegationSyncQ == nil {
				lg.Error("DelegationSyncQ not available", "zone", z.ZoneName)
				return
			}
			go func() {
				if err := z.SetupZoneSync(delegationSyncQ); err != nil {
					lg.Error("SetupZoneSync failed", "zone", z.ZoneName, "error", err)
				}
			}()
		})
	}

	// Commit the staged inline key just before registration/persistence (so
	// the keystore holds it when the zone goes live), then register and
	// persist. On persist failure roll back registration, key, and a
	// freshly-synthesized bootstrap file — a failed add leaves nothing behind.
	rollbackKey, cerr := conf.commitStagedTsigKey(staged)
	if cerr != nil {
		cleanupFile()
		return "", fmt.Errorf("zone %s: %w", name, cerr)
	}
	Zones.Set(name, zd)
	if err := conf.AddDynamicZoneToConfig(zd); err != nil {
		zd.stopPublisher()
		Zones.Remove(name)
		rollbackKey()
		cleanupFile()
		return "", fmt.Errorf("failed to persist dynamic zone %s: %w", name, err)
	}

	zr := ZoneRefresher{
		Name:           name,
		ZoneType:       Primary,
		ZoneStore:      MapZone,
		Zonefile:       spec.Zconf.Zonefile,
		Template:       in.Template,
		PublishCadence: spec.PublishCadence,
		Notify:         zd.Notify,
		AllowNotify:    spec.Zconf.AllowNotify,
		Downstreams:    spec.Zconf.Downstreams,
		DownstreamAuth: spec.Zconf.DownstreamAuth,
		Options:        options,
		UpdatePolicy:   spec.Policy,
		DnssecPolicy:   spec.Zconf.DnssecPolicy,
		Force:          true, // load from file regardless of serial

		// Template-expanded: a template carrying outbound-soa-serial gives
		// every zone stamped from it that serial policy (the intended
		// granularity — see the per-zone config model in the design doc).
		OutboundSoaSerial: spec.Zconf.OutboundSoaSerial,
		TransferSrc:       spec.Zconf.TransferSrc,
	}
	if err := conf.enqueueRefresh(ctx, zr); err != nil {
		// Mark the registered-but-unscheduled zone so list-dynamic shows a
		// visible error instead of an indefinite "provisioning" (the boot
		// path registers an error state for its analogous failure).
		// RefreshError is deliberately not service-impacting.
		zd.SetError(RefreshError, "initial load not scheduled: %v", err)
		return "", fmt.Errorf("zone %s registered but failed to schedule initial load: %w", name, err)
	}

	return fmt.Sprintf("zone %s provisioning (primary from template %s); poll list-dynamic for state", name, in.Template), nil
}
