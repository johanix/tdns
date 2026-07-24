/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The peers: block (docs/2026-07-21-peers-xfr-auth-design.md): one
 * declaration per remote server, referenced from the four peer/ACL lists as
 * `- peers: [ id, ... ]` entries. Everything here is parse-time — references
 * expand into the existing PeerConf/AclEntry structures, so the runtime
 * (resolvePrimaries, refresh engine, ACL matcher) is untouched. This file
 * also implements the transfer-terminology alias normalization
 * (upstreams:/request-xfr: -> primaries; secondaries:/provide-xfr: ->
 * downstreams).
 */
package tdns

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strings"
)

// TLSIdentity describes how WE verify a peer's CLIENT certificate when it
// connects to us (the downstream role). Data-driven: whichever credentials
// are present determine which downstream-auth mechanisms this peer CAN
// satisfy (pins -> tls-pin, ca-file -> tls-pkix, dane -> tls-dane); which of
// those SUFFICE is the zone's downstream-auth decision.
type TLSIdentity struct {
	// Name is the identity pin: the tls-pkix mechanism requires the client
	// leaf to carry this DNS SAN, and tls-dane uses it as the TLSA base.
	// Defaults to the host part of the peer's addr. Chain-only semantics
	// (any member of the CA) apply only when no name exists at all.
	Name string `yaml:"name" mapstructure:"name"`
	// Pins are base64 SPKI SHA-256 digests (any match satisfies tls-pin).
	Pins []string `yaml:"pins" mapstructure:"pins"`
	// CAFile holds TRUST ANCHORS ONLY — root cert(s), concatenated PEM;
	// never intermediates (those arrive in the client's presented chain),
	// never the leaf.
	CAFile string `yaml:"ca-file" mapstructure:"ca-file"`
	// Dane enables the tls-dane mechanism: the presented client cert must
	// match Name's DNSSEC-validated TLSA RRset.
	Dane bool `yaml:"dane" mapstructure:"dane"`
}

// PeerDef is one entry in the top-level peers: block: one declaration per
// remote server, carrying both directions. The TLS identity/trust material
// (tls-name/pins/ca-file/dane) is SHARED — the same fields describe how we
// verify the peer's SERVER cert when we dial it (outbound, per tls-auth) and
// its CLIENT cert when it dials us (inbound, per the zone's downstream-auth).
type PeerDef struct {
	Addr string   `yaml:"addr" mapstructure:"addr"`
	Key  string   `yaml:"key" mapstructure:"key"`   // sugar for keys: [x]
	Keys []string `yaml:"keys" mapstructure:"keys"` // sign with FIRST, accept ANY inbound

	// Outbound-only mode selectors (require addr; tls-auth requires transport: dot).
	Transport string `yaml:"transport" mapstructure:"transport"` // "" | do53 | dot
	TLSAuth   string `yaml:"tls-auth" mapstructure:"tls-auth"`   // pin | pkix | dane

	// Shared TLS identity + trust material (used in BOTH directions).
	TLSName string   `yaml:"tls-name" mapstructure:"tls-name"` // SNI + required SAN + TLSA base; defaults to addr's host
	Pins    []string `yaml:"pins" mapstructure:"pins"`         // base64 SPKI SHA-256 pins (pin)
	CAFile  string   `yaml:"ca-file" mapstructure:"ca-file"`   // trust-anchor PEM (pkix)
	Dane    bool     `yaml:"dane" mapstructure:"dane"`         // inbound tls-dane capability (outbound dane is tls-auth: dane)

	// Inbound source addresses (default: addr's host as /32 or /128).
	Prefixes []string `yaml:"prefixes" mapstructure:"prefixes"`
}

// peerAddrHost returns the host part of the peer's addr ("" if unset).
func (p *PeerDef) addrHost() string {
	if p.Addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(p.Addr); err == nil {
		return h
	}
	return p.Addr
}

// ValidatePeers validates and normalizes the peers: block in place:
// key/keys sugar resolution, NOKEY-alone rule, prefix and tls-identity name
// defaulting, outbound validation via validatePeerXoT, inbound credential
// validation. A broken peer definition does NOT abort the config — it is
// recorded and every zone referencing it is quarantined at expansion time
// (matching the quarantine-zones-not-abort house rule; one typo must not
// take the whole server down). Returns the broken map (peer id -> reason).
func (conf *Config) ValidatePeers() map[string]string {
	broken := map[string]string{}
	for id, p := range conf.Peers {
		if err := validatePeerDef(&p); err != nil {
			lgConfig.Error("peers: invalid peer definition; zones referencing it will be quarantined", "peer", id, "err", err)
			broken[id] = err.Error()
			continue
		}
		conf.Peers[id] = p // store the normalized copy
	}
	return broken
}

func validatePeerDef(p *PeerDef) error {
	// key: is sugar for keys: [x]; both set is ambiguous.
	if p.Key != "" && len(p.Keys) > 0 {
		return fmt.Errorf("both key and keys set (key: %q is sugar for keys: [%q]; use one)", p.Key, p.Key)
	}
	if p.Key != "" {
		p.Keys = []string{p.Key}
		p.Key = ""
	}
	if len(p.Keys) == 0 {
		return fmt.Errorf("no TSIG key (use keys: [NOKEY] for no TSIG)")
	}
	// NOKEY only alone: mixing it with named keys would recreate the
	// NOKEY-shadows-TSIG footgun inside a single object.
	for _, k := range p.Keys {
		if k == NOKEY && len(p.Keys) > 1 {
			return fmt.Errorf("NOKEY must be the only entry in keys (mixing it with named keys disables TSIG for this peer)")
		}
		if k == "" {
			return fmt.Errorf("empty key name in keys")
		}
	}

	// transport/tls-auth are outbound-only mode selectors; they need a dial
	// target. The identity/trust material (tls-name/pins/ca-file/dane) is
	// shared with the inbound side and is validated below, independent of addr.
	p.Transport = strings.ToLower(strings.TrimSpace(p.Transport))
	p.TLSAuth = strings.ToLower(strings.TrimSpace(p.TLSAuth))
	if (p.Transport != "" || p.TLSAuth != "") && p.Addr == "" {
		return fmt.Errorf("transport/tls-auth require addr (an outbound dial target)")
	}
	// When we dial the peer over DoT, validate the outbound tls-auth mode and
	// the material it needs — the same check an inline upstream entry gets.
	if p.Addr != "" && (p.Transport == TransportDoT || p.TLSAuth != "") {
		pc := PeerConf{
			Addr:      p.Addr,
			Key:       p.Keys[0],
			Transport: p.Transport,
			TLSAuth:   p.TLSAuth,
			TLSName:   p.TLSName,
			Pins:      p.Pins,
			CAFile:    p.CAFile,
		}
		if err := validatePeerXoT(&pc); err != nil {
			return err
		}
		p.Transport, p.TLSAuth = pc.Transport, pc.TLSAuth
	}

	// Inbound prefixes: default from addr's host as an explicit single-host
	// mask (/32 or /128). A bare IP is not a valid ip-spec (parseIPSpec rejects
	// it), so the auto-generated default must carry the boundary too.
	if len(p.Prefixes) == 0 {
		if host := p.addrHost(); host != "" {
			if ip := net.ParseIP(host); ip != nil {
				// Use the canonical IPv4 form for a v4 (or v4-mapped) address, so
				// we never emit "::ffff:a.b.c.d/32" — which parseIPSpec would read
				// as a v6 /32 (a huge block), not the intended single host.
				if v4 := ip.To4(); v4 != nil {
					p.Prefixes = []string{v4.String() + "/32"}
				} else {
					p.Prefixes = []string{host + "/128"}
				}
			}
		}
		// A hostname addr yields no prefix default — inbound use then
		// requires explicit prefixes (checked at reference time).
	}

	// Shared TLS identity/trust material: default the name from the addr
	// hostname, then validate whatever material is present. It is consumed
	// inbound (per the zone's downstream-auth policy) and outbound (tls-auth
	// above). A peer with no material is fine — a do53-only or plain peer.
	if p.TLSName == "" {
		if host := p.addrHost(); host != "" && net.ParseIP(host) == nil {
			p.TLSName = host
		}
	}
	for _, pin := range p.Pins {
		raw, err := base64.StdEncoding.DecodeString(pin)
		if err != nil || len(raw) != sha256.Size {
			return fmt.Errorf("pin %q is not a base64 SHA-256 SPKI digest", pin)
		}
	}
	if p.CAFile != "" {
		if err := checkPEMCertFile(p.CAFile); err != nil {
			return fmt.Errorf("ca-file %q: %v", p.CAFile, err)
		}
	}
	if p.Dane && p.TLSName == "" {
		return fmt.Errorf("dane requires tls-name (none given, and addr provides no hostname)")
	}
	return nil
}

// expandPeerRefs replaces every `- peers: [ id, ... ]` reference entry in the
// zone's four lists with the expansion of the named peers. Called after
// template expansion (so templates may carry references) and before the
// per-zone validation that consumes the lists. An error quarantines the zone.
func (conf *Config) expandPeerRefs(zconf *ZoneConf, brokenPeers map[string]string) error {
	var err error
	if zconf.Primaries, err = conf.expandPeerList(zconf.Primaries, "upstreams", brokenPeers); err != nil {
		return err
	}
	if zconf.Notify, err = conf.expandPeerList(zconf.Notify, "notify", brokenPeers); err != nil {
		return err
	}
	if zconf.Downstreams, err = conf.expandAclList(zconf.Downstreams, "downstreams", true, brokenPeers); err != nil {
		return err
	}
	if zconf.AllowNotify, err = conf.expandAclList(zconf.AllowNotify, "allow-notify", false, brokenPeers); err != nil {
		return err
	}
	return nil
}

// lookupPeer resolves one reference id, distinguishing unknown ids (with a
// hint about the legacy bare-string shape) from known-but-broken peers.
func (conf *Config) lookupPeer(id, where string, brokenPeers map[string]string) (PeerDef, error) {
	if reason, bad := brokenPeers[id]; bad {
		return PeerDef{}, fmt.Errorf("%s: peer %q is invalid: %s", where, id, reason)
	}
	p, ok := conf.Peers[id]
	if !ok {
		return PeerDef{}, fmt.Errorf("%s: unknown peer %q (not in the peers: block)", where, id)
	}
	return p, nil
}

// expandPeerList expands references inside an upstreams:/notify: list into
// outbound PeerConf entries (signing key = keys[0]).
func (conf *Config) expandPeerList(in []PeerConf, where string, brokenPeers map[string]string) ([]PeerConf, error) {
	out := make([]PeerConf, 0, len(in))
	for _, e := range in {
		if len(e.PeersRef) == 0 {
			out = append(out, e)
			continue
		}
		// A reference entry carries ONLY peers:. Inline fields — the dial
		// target (addr/key) or any TLS knob (transport/tls-auth/pins/ca-file/
		// tls-name) — belong on the peer definition, not the reference; if we
		// silently ignored them the operator would believe they configured
		// pin/DoT on the zone while the pull actually used the peer's (maybe
		// plaintext) settings. Reject rather than downgrade.
		if e.Addr != "" || e.Key != "" {
			return nil, fmt.Errorf("%s: an entry may be a reference (peers:) or inline (addr/key), not both", where)
		}
		if e.Transport != "" || e.TLSAuth != "" || e.TLSName != "" || len(e.Pins) > 0 || e.CAFile != "" {
			return nil, fmt.Errorf("%s: TLS fields (transport/tls-auth/pins/ca-file/tls-name) must be set on the peer definition, not on a peers: reference entry", where)
		}
		for _, id := range e.PeersRef {
			p, err := conf.lookupPeer(id, where, brokenPeers)
			if err != nil {
				return nil, err
			}
			if p.Addr == "" {
				return nil, fmt.Errorf("%s: peer %q has no addr and cannot be dialed", where, id)
			}
			out = append(out, PeerConf{
				Addr:      p.Addr,
				Key:       p.Keys[0],
				Transport: p.Transport,
				TLSAuth:   p.TLSAuth,
				TLSName:   p.TLSName,
				Pins:      p.Pins,
				CAFile:    p.CAFile,
			})
		}
	}
	return out, nil
}

// expandAclList expands references inside a downstreams:/allow-notify: list
// into the prefix x key cross-product of AclEntries — the same shape the
// hand-written TSIG-rollover pattern produces, so the ACL matcher is
// untouched. Only downstreams entries carry the peer's tls-identity
// (allow-notify is Do53 NOTIFY; certificates play no role there).
func (conf *Config) expandAclList(in []AclEntry, where string, withIdentity bool, brokenPeers map[string]string) ([]AclEntry, error) {
	out := make([]AclEntry, 0, len(in))
	for _, e := range in {
		if len(e.PeersRef) == 0 {
			out = append(out, e)
			continue
		}
		if e.Prefix != "" || e.Key != "" {
			return nil, fmt.Errorf("%s: an entry may be a reference (peers:) or inline (prefix/key), not both", where)
		}
		for _, id := range e.PeersRef {
			p, err := conf.lookupPeer(id, where, brokenPeers)
			if err != nil {
				return nil, err
			}
			if len(p.Prefixes) == 0 {
				return nil, fmt.Errorf("%s: peer %q has no prefixes (and addr provides no IP) — cannot be matched as a source", where, id)
			}
			for _, prefix := range p.Prefixes {
				for _, key := range p.Keys {
					ae := AclEntry{Prefix: prefix, Key: key, PeerName: id}
					// Build the runtime tls-identity from the peer's shared
					// TLS material. Attach it only when the peer actually
					// carries a credential (name alone can't prove anything).
					if withIdentity && (len(p.Pins) > 0 || p.CAFile != "" || p.Dane) {
						ae.TLSIdentity = &TLSIdentity{Name: p.TLSName, Pins: p.Pins, CAFile: p.CAFile, Dane: p.Dane}
					}
					out = append(out, ae)
				}
			}
		}
	}
	return out, nil
}

// --- transfer-terminology aliases -------------------------------------------

// xfrKeyAliases maps every accepted spelling to the canonical (internal) key.
// BIND9: primaries/secondaries. tdns (canonical in docs): upstreams/
// downstreams. NSD: request-xfr/provide-xfr.
var xfrKeyAliases = map[string]string{
	"upstreams":   "primaries",
	"request-xfr": "primaries",
	"secondaries": "downstreams",
	"provide-xfr": "downstreams",
}

// NormalizeXfrAliases rewrites alias spellings in every zones:/templates:
// entry of the raw config map to the canonical keys, BEFORE mapstructure
// decoding (so aliases neither fail to decode nor show up as unknown keys).
// Two spellings of the same field in one entry is a conflict: never a silent
// preference — the entry's name is recorded and the zone is quarantined by
// ParseZones. Returns conflicts as map[zone-or-template name]description.
func NormalizeXfrAliases(configMap map[string]interface{}) map[string]string {
	conflicts := map[string]string{}
	for _, section := range []string{"zones", "templates"} {
		list, ok := configMap[section].([]interface{})
		if !ok {
			continue
		}
		for _, item := range list {
			entry := asStringMap(item)
			if entry == nil {
				continue
			}
			name, _ := entry["name"].(string)
			for _, alias := range aliasKeysSorted() {
				canonical := xfrKeyAliases[alias]
				val, present := entry[alias]
				if !present {
					continue
				}
				if _, clash := entry[canonical]; clash {
					conflicts[name] = fmt.Sprintf("%s: both %q and %q given — use one spelling", section, alias, canonical)
					continue
				}
				entry[canonical] = val
				delete(entry, alias)
			}
		}
	}
	return conflicts
}

// MiscasedXfrKey names a transfer-list key whose lower-cased form is an
// accepted spelling (alias or canonical) but whose actual case differs. The
// daemon decodes YAML case-sensitively, so such a key is unknown to it and
// silently dropped — `config check` surfaces these so an operator does not
// believe a transfer list is configured when the daemon will ignore it.
type MiscasedXfrKey struct {
	Zone      string // zone or template name (from the entry's name:)
	Key       string // the key exactly as written
	Canonical string // the spelling the daemon accepts
}

// FindMiscasedXfrKeys scans zones: and templates: for transfer-list keys that
// are correct except for letter case. This mirrors NormalizeXfrAliases' key
// set (aliases + their canonical targets) but reports the near-misses the
// daemon drops rather than normalizing them.
func FindMiscasedXfrKeys(configMap map[string]interface{}) []MiscasedXfrKey {
	// lower-cased accepted spelling -> canonical spelling to suggest.
	accepted := map[string]string{
		"primaries":   "primaries",
		"downstreams": "downstreams",
	}
	for alias, canonical := range xfrKeyAliases {
		accepted[alias] = canonical
	}

	var out []MiscasedXfrKey
	for _, section := range []string{"zones", "templates"} {
		list, ok := configMap[section].([]interface{})
		if !ok {
			continue
		}
		for _, item := range list {
			entry := asStringMap(item)
			if entry == nil {
				continue
			}
			name, _ := entry["name"].(string)
			for k := range entry {
				lower := strings.ToLower(k)
				if canonical, known := accepted[lower]; known && k != lower {
					out = append(out, MiscasedXfrKey{Zone: name, Key: k, Canonical: canonical})
				}
			}
		}
	}
	return out
}

// CheckPeerRefs validates the peers: block and every zone's `- peers:`
// references the same way ParseZones does at load, WITHOUT mutating conf.Zones,
// so `config check` reports exactly the peer problems that would quarantine a
// zone in the daemon. It returns the broken peer definitions (id -> reason) and
// the zones whose references fail to expand (zone name -> reason).
func (conf *Config) CheckPeerRefs() (brokenPeers, zoneErrors map[string]string) {
	brokenPeers = conf.ValidatePeers()
	zoneErrors = map[string]string{}
	for i := range conf.Zones {
		zc := conf.Zones[i] // copy: expandPeerRefs replaces the list fields
		if err := conf.expandPeerRefs(&zc, brokenPeers); err != nil {
			zoneErrors[conf.Zones[i].Name] = err.Error()
		}
	}
	return brokenPeers, zoneErrors
}

// aliasKeysSorted returns the alias spellings in deterministic order so a
// double-alias conflict (e.g. upstreams + request-xfr) reports stably.
func aliasKeysSorted() []string {
	keys := make([]string, 0, len(xfrKeyAliases))
	for k := range xfrKeyAliases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// asStringMap normalizes the two map shapes YAML decoding can produce.
func asStringMap(v interface{}) map[string]interface{} {
	switch m := v.(type) {
	case map[string]interface{}:
		return m
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			if ks, ok := k.(string); ok {
				out[ks] = val
			}
		}
		return out
	default:
		return nil
	}
}

// aliasConflictFor returns the recorded alias conflict for a zone or
// template name ("" if none). Case: zone names in config may lack the
// trailing dot; check both forms.
func aliasConflictFor(conflicts map[string]string, name string) string {
	if c, ok := conflicts[name]; ok {
		return c
	}
	if c, ok := conflicts[strings.TrimSuffix(name, ".")]; ok {
		return c
	}
	return ""
}

// zoneOrTemplateAliasConflict returns the transfer-list spelling conflict that
// must quarantine a zone: one recorded directly on the zone, or (failing that)
// on the template it uses. NormalizeXfrAliases keys a template conflict by the
// TEMPLATE name, so a zone that only inherits the conflict through its template
// would otherwise load with the surviving broad canonical ACL. Consulting both
// is what keeps a conflicted template from silently widening a dependent zone.
func zoneOrTemplateAliasConflict(conflicts map[string]string, zoneName, template string) string {
	if c := aliasConflictFor(conflicts, zoneName); c != "" {
		return c
	}
	if template != "" {
		return aliasConflictFor(conflicts, template)
	}
	return ""
}
