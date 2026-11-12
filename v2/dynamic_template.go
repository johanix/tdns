/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Templates for API zones of both types: the template owns a zone's
 * outbound settings (docs/2026-11-12-dynamic-zone-templates.md).
 *
 * An API zone names a template (or gets the operator's default for its type).
 * For a secondary the template supplies only the outbound side: who may
 * transfer the zone from this server, how they must authenticate, who is told
 * of a change, who may tell us, and the NOTIFY resend settings. Its
 * primaries, TSIG key, options and transfer source stay the caller's. For a
 * primary the template supplies the whole configuration
 * (dynamic_primary.go), and the outbound side follows the same rules as here.
 *
 * The outbound settings are never persisted for such a zone. They are
 * expanded from the template when the zone is added, at every boot and on
 * every config reload, so a change to the template -- a downstream added or
 * removed -- reaches every zone stamped from it.
 */

package tdns

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// templateOutbound is the outbound half of a zone's configuration, the part
// a dynamic zone's template owns.
type templateOutbound struct {
	Notify              []PeerConf
	AllowNotify         []AclEntry
	Downstreams         []AclEntry
	DownstreamAuth      []string
	NotifyRetries       *int
	NotifyRetryInterval time.Duration
}

// outboundFromConf takes the outbound settings of an expanded, validated zone
// config, in the form the ZoneData holds them.
func outboundFromConf(zname string, zc *ZoneConf) templateOutbound {
	retries, interval := zoneNotifyRetrySettings(zname, zc)
	return templateOutbound{
		Notify:              normalizePeerAddrs(zc.Notify),
		AllowNotify:         zc.AllowNotify,
		Downstreams:         zc.Downstreams,
		DownstreamAuth:      zc.DownstreamAuth,
		NotifyRetries:       retries,
		NotifyRetryInterval: interval,
	}
}

// clearTemplateOwned drops the fields a template owns from a zone config, so
// an expansion takes them from the template whatever the entry carried
// (ExpandTemplate fills only what the zone left unset).
func clearTemplateOwned(zc *ZoneConf) {
	zc.Notify = nil
	zc.AllowNotify = nil
	zc.Downstreams = nil
	zc.DownstreamAuth = nil
	zc.NotifyRetries = nil
	zc.NotifyRetryInterval = ""
}

// hasTemplateOwned reports whether a zone config carries any field a template
// owns.
func hasTemplateOwned(zc *ZoneConf) bool {
	return len(zc.Notify) > 0 || len(zc.AllowNotify) > 0 || len(zc.Downstreams) > 0 ||
		len(zc.DownstreamAuth) > 0 || zc.NotifyRetries != nil || zc.NotifyRetryInterval != ""
}

// outboundLocked reads a zone's current outbound settings. The caller holds
// zd.mu.
func (zd *ZoneData) outboundLocked() templateOutbound {
	return templateOutbound{
		Notify:              zd.Notify,
		AllowNotify:         zd.AllowNotify,
		Downstreams:         zd.Downstreams,
		DownstreamAuth:      zd.DownstreamAuth,
		NotifyRetries:       zd.notifyRetries,
		NotifyRetryInterval: zd.notifyRetryInterval,
	}
}

// setOutboundLocked installs outbound settings on a zone, replacing all of
// them (an empty list clears: no downstreams means no transfers out). The
// caller holds zd.mu. The transfer and NOTIFY paths read these fields per
// request, so the new settings apply from the next one.
func (zd *ZoneData) setOutboundLocked(out templateOutbound) {
	zd.Notify = out.Notify
	zd.AllowNotify = out.AllowNotify
	zd.Downstreams = out.Downstreams
	zd.DownstreamAuth = out.DownstreamAuth
	zd.notifyRetries = out.NotifyRetries
	zd.notifyRetryInterval = out.NotifyRetryInterval
}

// dynamicTemplateGate is what a template must be to drive a dynamic zone of
// type zt. fromAPI enforces the blessing (dynamiczones: true): a new add or
// an explicit template change needs it, a zone that already has the template
// keeps loading if the blessing is withdrawn (the caller warns), the way
// dynamiczones.dynamic.allowed gates new adds but not persisted zones.
//
// A primary's template may leave its type unset; a secondary's must say
// type: secondary. Most of a template is meaningless for an API secondary
// (only the outbound side is used), so the type is how the operator says the
// template is meant for one.
func dynamicTemplateGate(name string, tmpl *ZoneConf, zt ZoneType, fromAPI bool) error {
	if fromAPI && !tmpl.DynamicZones {
		return fmt.Errorf("template %q is not blessed for dynamic zones (set dynamiczones: true on the template)", name)
	}
	tt := strings.ToLower(strings.TrimSpace(tmpl.Type))
	switch zt {
	case Primary:
		if tt != "" && tt != "primary" {
			return fmt.Errorf("template %q is type %s, not primary", name, tmpl.Type)
		}
	case Secondary:
		if tt == "" {
			return fmt.Errorf("template %q has no type; a template for dynamic secondaries must say type: secondary", name)
		}
		if tt != "secondary" {
			return fmt.Errorf("template %q is type %s, not secondary", name, tmpl.Type)
		}
	default:
		return fmt.Errorf("templates drive primary and secondary zones only (got %s)", ZoneTypeToString[zt])
	}
	return nil
}

// validateTemplateOutbound runs the per-list checks ParseZones applies to a
// static zone over the outbound lists of an expanded dynamic zone. keyOK
// decides which TSIG key names are acceptable.
func (conf *Config) validateTemplateOutbound(expanded *ZoneConf, keyOK func(string) bool) error {
	if err := validateDownstreamAuth(expanded.DownstreamAuth); err != nil {
		return fmt.Errorf("downstream-auth: %v", err)
	}
	crossCheckDownstreamAuth(expanded.Name, expanded.DownstreamAuth, expanded.Downstreams, conf.Internal.ImrEngine != nil)
	for _, n := range expanded.Notify {
		if n.Legacy != "" {
			return fmt.Errorf("notify now requires {addr, key} (got bare string %q)", n.Legacy)
		}
		if n.Transport != "" || n.TLSAuth != "" || n.TLSName != "" || len(n.Pins) > 0 || n.CAFile != "" {
			return fmt.Errorf("notify %s: transport/tls-* not supported for notify targets", n.Addr)
		}
		if n.Key != "" && n.Key != NOKEY && !keyOK(n.Key) {
			return fmt.Errorf("notify %s references unknown key %q", n.Addr, n.Key)
		}
	}
	if err := ValidateACL(expanded.AllowNotify, keyOK); err != nil {
		return fmt.Errorf("allow-notify: %v", err)
	}
	if err := ValidateACL(expanded.Downstreams, keyOK); err != nil {
		return fmt.Errorf("downstreams: %v", err)
	}
	return nil
}

// prepareSecondaryTemplate expands template for the API secondary zname and
// returns the outbound settings it gives the zone. Nothing else is taken from
// the template: the zone's primaries, TSIG key, options and transfer source
// are the caller's, so a template cannot redirect where a zone comes from.
//
// The secondary's own inline TSIG key is not acceptable here: it
// authenticates the zone's primaries, and a template is shared by every zone
// stamped from it. Every key the template names must be in the keystore.
func (conf *Config) prepareSecondaryTemplate(zname, template string, fromAPI bool) (templateOutbound, error) {
	zname = dns.Fqdn(zname)
	tmpl, ok := lookupZoneTemplate(template)
	if !ok {
		return templateOutbound{}, fmt.Errorf("template %q does not exist", template)
	}
	if err := dynamicTemplateGate(template, &tmpl, Secondary, fromAPI); err != nil {
		return templateOutbound{}, err
	}
	if !fromAPI && !tmpl.DynamicZones {
		lg.Warn("dynamic secondary: template no longer blessed for dynamic zones; using it anyway (blessing gates new adds)", "zone", zname, "template", template)
	}
	// A conflicted template (downstreams: plus provide-xfr: etc.) would hand
	// the zone the surviving broad list -- same quarantine rule as ParseZones.
	if conflict := zoneOrTemplateAliasConflict(conf.Internal.XfrAliasConflicts, zname, template); conflict != "" {
		return templateOutbound{}, fmt.Errorf("conflicting transfer-list spellings: %s", conflict)
	}

	zc := ZoneConf{
		Name:                zname,
		Type:                "secondary",
		Notify:              clonePeerConfs(tmpl.Notify),
		AllowNotify:         append([]AclEntry(nil), tmpl.AllowNotify...),
		Downstreams:         append([]AclEntry(nil), tmpl.Downstreams...),
		DownstreamAuth:      append([]string(nil), tmpl.DownstreamAuth...),
		NotifyRetryInterval: tmpl.NotifyRetryInterval,
	}
	if tmpl.NotifyRetries != nil {
		v := *tmpl.NotifyRetries
		zc.NotifyRetries = &v
	}
	if err := conf.expandPeerRefs(&zc, conf.Internal.BrokenPeers); err != nil {
		return templateOutbound{}, fmt.Errorf("peers: %v", err)
	}
	if err := conf.validateTemplateOutbound(&zc, conf.tsigKeyDefined); err != nil {
		return templateOutbound{}, err
	}
	return outboundFromConf(zname, &zc), nil
}

// expandTemplateOutbound re-expands the template of a live template-driven
// API zone and returns the outbound settings it gives the zone now. For a
// primary it runs the whole primary expansion (prepareDynamicPrimary), so a
// template that no longer validates is reported here too; only the outbound
// side of the result is used.
func (conf *Config) expandTemplateOutbound(zname string, zt ZoneType, template, zonefile, inlineKey string) (templateOutbound, error) {
	switch zt {
	case Secondary:
		return conf.prepareSecondaryTemplate(zname, template, false)
	case Primary:
		spec, err := conf.prepareDynamicPrimary(ZoneConf{
			Name:          zname,
			Template:      template,
			Zonefile:      zonefile,
			InlineTsigKey: inlineKey,
		}, nil, false)
		if err != nil {
			return templateOutbound{}, err
		}
		return outboundFromConf(dns.Fqdn(zname), &spec.Zconf), nil
	default:
		return templateOutbound{}, fmt.Errorf("zone type %s takes no template", ZoneTypeToString[zt])
	}
}

// legacyInlineTsigKey recovers the inline key of a dynamic primary persisted
// before the template owned the outbound settings. Such an entry carries the
// downstreams as they were materialized at add time, with every keyless
// (""/NOKEY) entry of the template bound to the inline key. So the inline key
// is the key that the persisted entries use for the prefixes the template
// leaves keyless.
//
// No keyless template prefix, or none of them keyed in the entry: no inline
// key. More than one key: the template changed since and the key cannot be
// told; the caller refuses the zone rather than guess, because a lost
// binding would open the zone to keyless transfers.
func legacyInlineTsigKey(templateDownstreams, persisted []AclEntry) (string, error) {
	keyless := map[string]bool{}
	for _, e := range templateDownstreams {
		if e.Key == "" || e.Key == NOKEY {
			keyless[strings.TrimSpace(e.Prefix)] = true
		}
	}
	found := map[string]string{} // canonical key -> key as written
	for _, e := range persisted {
		if !keyless[strings.TrimSpace(e.Prefix)] {
			continue
		}
		if e.Key == "" || tsigNameIsReserved(e.Key) {
			continue
		}
		found[tsigKeyKey(e.Key)] = e.Key
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		for _, k := range found {
			return k, nil
		}
	}
	keys := make([]string, 0, len(found))
	for _, k := range found {
		keys = append(keys, k)
	}
	return "", fmt.Errorf("cannot tell which inline TSIG key this zone was added with (the persisted downstreams bind the template's keyless entries to %v); "+
		"set inline-tsig-key on the zone's entry in the dynamic config, or delete and re-add the zone", keys)
}

// outboundEqual compares two outbound settings, an empty list equal to an
// absent one.
func outboundEqual(a, b templateOutbound) bool {
	norm := func(o templateOutbound) templateOutbound {
		if len(o.Notify) == 0 {
			o.Notify = nil
		}
		if len(o.AllowNotify) == 0 {
			o.AllowNotify = nil
		}
		if len(o.Downstreams) == 0 {
			o.Downstreams = nil
		}
		if len(o.DownstreamAuth) == 0 {
			o.DownstreamAuth = nil
		}
		return o
	}
	return reflect.DeepEqual(norm(a), norm(b))
}

// reapplyResult counts what ReapplyDynamicZoneTemplates did.
type reapplyResult struct {
	Zones, Changed, Failed int
}

func (r reapplyResult) summary() string {
	if r.Zones == 0 {
		return ""
	}
	return fmt.Sprintf(" Template-driven dynamic zones: %d re-expanded (%d changed, %d failed).", r.Zones, r.Changed, r.Failed)
}

// ReapplyDynamicZoneTemplates re-expands the template of every
// template-driven API zone and installs the outbound settings it now gives
// on the live zone. Called once a reload has rebuilt the template map, so an
// edited template reaches the zones stamped from it without a restart.
//
// A zone whose template no longer expands keeps the outbound settings it
// had and carries a TemplateWarning until an expansion succeeds: a reload
// with a broken template must not cut a live zone off from its downstreams.
// (At boot there is nothing to keep, so such a zone loads without them.)
//
// Must be called WITHOUT confMu held: the template lookup takes it.
func (conf *Config) ReapplyDynamicZoneTemplates() reapplyResult {
	var res reapplyResult
	for item := range Zones.IterBuffered() {
		zd := item.Val
		if zd == nil {
			continue
		}
		zd.mu.Lock()
		apiManaged := zd.Options[OptApiManagedZone]
		template, zt, zonefile, inlineKey := zd.Template, zd.ZoneType, zd.Zonefile, zd.InlineTsigKey
		zd.mu.Unlock()
		if !apiManaged || template == "" {
			continue
		}
		res.Zones++
		out, err := conf.expandTemplateOutbound(item.Key, zt, template, zonefile, inlineKey)
		zd.mu.Lock()
		if cur, live := Zones.Get(item.Key); !live || cur != zd {
			// Deleted or replaced while we expanded: the replacement got
			// its settings from its own expansion.
			zd.mu.Unlock()
			res.Zones--
			continue
		}
		if err != nil {
			res.Failed++
			lg.Error("dynamic zone: template did not expand on reload; keeping the zone's outbound settings", "zone", item.Key, "template", template, "err", err)
			zd.setErrorLocked(TemplateWarning, "template %q: %v; keeping the zone's previous outbound settings", template, err)
			zd.mu.Unlock()
			continue
		}
		if !outboundEqual(zd.outboundLocked(), out) {
			res.Changed++
			lg.Info("dynamic zone: outbound settings follow the template", "zone", item.Key, "template", template,
				"notify", peerAddrs(out.Notify), "downstreams", len(out.Downstreams))
		}
		zd.setOutboundLocked(out)
		if _, had := zd.Errors[TemplateWarning]; had {
			zd.clearErrorLocked(TemplateWarning)
		}
		zd.mu.Unlock()
	}
	return res
}
